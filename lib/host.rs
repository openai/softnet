use crate::subnet_finder;
use anyhow::{Context, Result, anyhow};
use clap::ValueEnum;
use log::info;
use smoltcp::wire::EthernetAddress;
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::sync::mpsc::{SyncSender, sync_channel};
use vmnet::network::Mode;
use vmnet::parameters::{Parameter, ParameterKind};
use vmnet::port_forwarding::{AddressFamily, Protocol};
use vmnet::{Batch, Events, Network, NetworkConfiguration, Options};

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
    pub vm_ip: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub gateway_ip: smoltcp::wire::Ipv4Address,
    pub max_packet_size: u64,
    pub read_max_packets: u64,
    finalized: bool,
}

impl Host {
    pub fn new(
        vm_net_type: NetType,
        vm_mac: EthernetAddress,
        enable_isolation: bool,
    ) -> Result<Host> {
        // Find an unused /30 subnet for the gateway and VM
        let (gateway_ip, vm_ip, subnet) = subnet_finder::find_available_subnet(30)?;

        // Create vmnet's network configuration
        let mut configuration = NetworkConfiguration::new(match vm_net_type {
            NetType::Nat => Mode::Shared,
            NetType::Host => Mode::Host,
        })
        .context("failed to create vmnet network configuration")?;

        // Configure the gateway address and subnet mask
        let subnet_mask = subnet.netmask();
        configuration
            .set_ipv4_subnet(gateway_ip, subnet_mask)
            .context("failed to configure IPv4 subnet")?;

        // Reserve the VM's address for its MAC
        configuration
            .add_dhcp_reservation(vm_mac.0, vm_ip)
            .context("failed to add DHCP address reservation")?;

        // Create vmnet's network
        let network = Network::new(&configuration)
            .with_context(|| format!("failed to create vmnet network {subnet}"))?;

        // Instantiate vmnet's interface
        //
        // The interface retains the network reservation until it is stopped
        let mut interface = vmnet::Interface::with_network(
            &network,
            Options {
                allocate_mac_address: Some(false),
                enable_isolation: Some(enable_isolation),
                ..Default::default()
            },
        )
        .context("failed to initialize vmnet interface")?;

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
            vm_ip,
            subnet_mask,
            gateway_ip,
            max_packet_size,
            read_max_packets,
            finalized: false,
        })
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
