use anyhow::{Context, Result, anyhow};
use clap::ValueEnum;
use log::info;
use smoltcp::wire::EthernetAddress;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::str::FromStr;
use std::sync::mpsc::{SyncSender, sync_channel};
use vmnet::mode::Mode;
use vmnet::parameters::{Parameter, ParameterKind};
use vmnet::port_forwarding::{AddressFamily, Protocol};
use vmnet::{Batch, Events, Options};

#[derive(ValueEnum, Clone, Debug)]
pub enum NetType {
    /// Shared network
    ///
    /// Uses NAT-translation to give guests access to the global network
    Nat,
    /// Host network
    ///
    /// Guests will be able to talk only to the host without access to global network
    Host,
}

pub struct Host {
    interface: vmnet::Interface,
    new_packets_rx: UnixDatagram,
    callback_can_continue_tx: SyncSender<()>,
    pub gateway_ip: smoltcp::wire::Ipv4Address,
    pub gateway_mac: EthernetAddress,
    pub max_packet_size: u64,
    pub read_max_packets: u64,
    finalized: bool,
}

impl Host {
    pub fn new(vm_net_type: NetType, enable_isolation: bool) -> Result<Host> {
        // Initialize a vmnet.framework NAT or Host interface with isolation enabled
        let mut interface = vmnet::Interface::new(
            match vm_net_type {
                NetType::Nat => Mode::Shared(Default::default()),
                NetType::Host => Mode::Host(Default::default()),
            },
            Options {
                enable_isolation: Some(enable_isolation),
                ..Default::default()
            },
        )
        .context("failed to initialize vmnet interface")?;

        // Retrieve first IP (gateway) used for this interface
        let Some(Parameter::StartAddress(start_address)) =
            interface.parameters().get(ParameterKind::StartAddress)
        else {
            return Err(anyhow!(
                "failed to retrieve vmnet's interface start address"
            ));
        };
        let start_address = Ipv4Addr::from_str(&start_address)
            .context("failed to parse vmnet's interface start address")?;

        // Retrieve last IP used for this interface and calculate the prefix
        let Some(Parameter::EndAddress(end_address)) =
            interface.parameters().get(ParameterKind::EndAddress)
        else {
            return Err(anyhow!("failed to retrieve vmnet's interface end address"));
        };
        let end_address = Ipv4Addr::from_str(&end_address)
            .context("failed to parse vmnet's interface end address")?;

        let Some(prefix) = Self::ipv4_range_prefix(start_address, end_address) else {
            return Err(anyhow!(
                "failed to resolve vmnet's interface: prefix ambiguity for {}–{}",
                start_address,
                end_address
            ));
        };

        // Figure out the gateway's interface MAC address
        let Some(gateway_mac) = Self::interface_mac_for_ip(start_address, prefix) else {
            return Err(anyhow!(
                "failed to resolve vmnet's interface: no interface found with {}/{} CIDR",
                start_address,
                prefix
            ));
        };
        let gateway_mac = EthernetAddress(gateway_mac.octets());

        // Retrieve max packet size for this interface
        let Some(Parameter::MaxPacketSize(max_packet_size)) =
            interface.parameters().get(ParameterKind::MaxPacketSize)
        else {
            return Err(anyhow!(
                "failed to retrieve vmnet's interface max packet size"
            ));
        };

        // Retrieve read max packets for this interface
        let Some(Parameter::ReadMaxPackets(read_max_packets)) =
            interface.parameters().get(ParameterKind::ReadMaxPackets)
        else {
            return Err(anyhow!(
                "failed to retrieve vmnet's interface read max packets"
            ));
        };

        // Set up a socketpair() to emulate polling of the vmnet interface
        let (new_packets_tx, new_packets_rx) = UnixDatagram::pair()?;
        new_packets_rx.set_nonblocking(true)?;

        let (callback_can_continue_tx, callback_can_continue_rx) = sync_channel(0);

        interface
            .set_event_callback(Events::PACKETS_AVAILABLE, move |_mask, _params| {
                // Send a dummy datagram to make the other end of socketpair() readable
                // and ignore the error as this merely a signalling channel to wake up
                // the poller
                new_packets_tx.send(&[0; 1]).ok();

                // Wait for the permission to continue to avoid
                // wasting CPU cycles or in case of termination,
                // to unblock this Block[1] and allow
                // vmnet.framework to terminate
                //
                // [1]: https://en.wikipedia.org/wiki/Blocks_(C_language_extension)
                callback_can_continue_rx.recv().unwrap();
            })
            .context("failed to set vmnet interface's event callback")?;

        Ok(Host {
            interface,
            new_packets_rx,
            callback_can_continue_tx,
            gateway_ip: start_address,
            gateway_mac,
            max_packet_size,
            read_max_packets,
            finalized: false,
        })
    }

    fn interface_mac_for_ip(ip: Ipv4Addr, prefix: u8) -> Option<pnet_datalink::MacAddr> {
        for iface in pnet_datalink::interfaces() {
            if iface
                .ips
                .iter()
                .any(|network| network.ip() == IpAddr::V4(ip) && network.prefix() == prefix)
                && let Some(mac) = iface.mac
            {
                return Some(mac);
            }
        }

        None
    }

    fn ipv4_range_prefix(start_address: Ipv4Addr, end_address: Ipv4Addr) -> Option<u8> {
        let start_address = start_address.to_bits();
        let end_address = end_address.to_bits();

        if start_address > end_address {
            return None;
        }

        Some((start_address ^ end_address).leading_zeros() as u8)
    }
}

impl Host {
    pub fn port_forwarding_add_rule(
        &mut self,
        external_port: u16,
        internal_addr: Ipv4Addr,
        internal_port: u16,
    ) -> Result<()> {
        let details = format!(
            "external_port={external_port}, internal_addr={internal_addr}, internal_port={internal_port}"
        );

        self.interface
            .port_forwarding_rule_add(
                AddressFamily::Ipv4,
                Protocol::Tcp,
                external_port,
                internal_addr.into(),
                internal_port,
            )
            .map(|_| info!("added port forwarding rule {details}"))
            .map_err(|err| anyhow!("failed to add port forwarding rule {details}: {err}"))
    }

    pub fn port_forwarding_remove_rule(&mut self, external_port: u16) -> Result<()> {
        let details = format!("external_port={external_port}");

        self.interface
            .port_forwarding_rule_remove(AddressFamily::Ipv4, Protocol::Tcp, external_port)
            .map(|_| info!("removed port forwarding rule {details}"))
            .map_err(|err| anyhow!("failed to remove port forwarding rule {details}: {err}"))
    }

    pub fn read(&mut self, batch: &mut Batch, bufs: &mut [Vec<u8>]) -> vmnet::Result<usize> {
        // Dequeue dummy datagram from the socket (if any)
        // to free up buffer space and reduce false-positives
        // when polling
        let mut buf_to_be_discarded: [u8; 1] = [0; 1];
        let _ = self.new_packets_rx.recv(&mut buf_to_be_discarded);

        let result = self.interface.read_batch(batch, bufs);

        if let Err(vmnet::Error::VmnetReadNothing) = result {
            // We've emptied everything, unlock the callback
            // so that it will be able to pick up new events
            let _ = self.callback_can_continue_tx.send(());
        }

        result
    }

    pub fn write(&mut self, buf: &[u8]) -> vmnet::Result<usize> {
        self.interface.write(buf)
    }

    pub fn finalize(&mut self) -> Result<()> {
        // First make sure our callback won't be scheduled again after it finishes
        self.interface
            .clear_event_callback()
            .context("failed to clear vmnet interface's event callback")?;

        // Now let the callback finish
        let _ = self.callback_can_continue_tx.send(());

        self.interface
            .finalize()
            .context("failed to finalize vmnet's interface")?;

        self.finalized = true;

        Ok(())
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        if !self.finalized {
            let _ = self.finalize();
        }
    }
}

impl AsRawFd for Host {
    fn as_raw_fd(&self) -> RawFd {
        self.new_packets_rx.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::Host;
    use std::net::Ipv4Addr;

    #[test]
    fn ipv4_range_prefix_for_class_c_subnet() {
        assert_eq!(
            Host::ipv4_range_prefix(
                Ipv4Addr::new(192, 168, 64, 0),
                Ipv4Addr::new(192, 168, 64, 255),
            ),
            Some(24)
        );
    }

    #[test]
    fn ipv4_range_prefix_for_single_address() {
        assert_eq!(
            Host::ipv4_range_prefix(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 1)),
            Some(32)
        );
    }

    #[test]
    fn ipv4_range_prefix_for_class_c_usable_range() {
        assert_eq!(
            Host::ipv4_range_prefix(
                Ipv4Addr::new(192, 168, 64, 1),
                Ipv4Addr::new(192, 168, 64, 254),
            ),
            Some(24)
        );
    }

    #[test]
    fn ipv4_range_prefix_for_containing_class_c_subnet() {
        assert_eq!(
            Host::ipv4_range_prefix(
                Ipv4Addr::new(192, 168, 64, 2),
                Ipv4Addr::new(192, 168, 64, 254),
            ),
            Some(24)
        );
    }

    #[test]
    fn ipv4_range_prefix_rejects_inverted_range() {
        assert_eq!(
            Host::ipv4_range_prefix(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1)),
            None
        );
    }
}
