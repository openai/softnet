use crate::subnet_finder;
use anyhow::{Context, Result, anyhow};
use clap::ValueEnum;
use log::info;
use smoltcp::wire::EthernetAddress;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::mpsc::{SyncSender, sync_channel};
use tokio::sync::Notify;
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
    ready: Arc<Notify>,
    draining: bool,
    callback_can_continue_tx: Option<SyncSender<()>>,
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
        // Find an unused /29 subnet for the gateway and VM
        let (gateway_ip, vm_ip, subnet) = subnet_finder::find_available_subnet(29)?;

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

        // Coordinate packet readiness and callback acknowledgments
        let ready = Arc::new(Notify::new());
        let ready_for_callback = Arc::clone(&ready);
        let (callback_can_continue_tx, callback_can_continue_rx) = sync_channel(1);

        interface
            .set_event_callback(Events::PACKETS_AVAILABLE, move |_mask, _params| {
                // Wake the Tokio reader to drain the available packets
                ready_for_callback.notify_one();

                // Park this GCD worker until drained; returning early makes vmnet repeat callbacks
                let _ = callback_can_continue_rx.recv();
            })
            .context("failed to set vmnet interface's event callback")?;

        Ok(Host {
            interface,
            ready,
            draining: false,
            callback_can_continue_tx: Some(callback_can_continue_tx),
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

    pub async fn read(&mut self, batch: &mut Batch, bufs: &mut [Vec<u8>]) -> vmnet::Result<usize> {
        loop {
            // One callback can cover several batches; stay ready until an empty read
            if !self.draining {
                self.ready.notified().await;
                self.draining = true;
            }

            match self.interface.read_batch(batch, bufs) {
                Err(vmnet::Error::VmnetReadNothing) => {
                    self.draining = false;

                    if let Some(tx) = &self.callback_can_continue_tx {
                        // Buffer the acknowledgment so the reader never waits for the callback
                        let _ = tx.try_send(());
                    }
                }
                result => return result,
            }
        }
    }

    pub fn write(&mut self, buf: &[u8]) -> vmnet::Result<usize> {
        self.interface.write(buf)
    }

    pub fn finalize(&mut self) -> Result<()> {
        if self.finalized {
            return Ok(());
        }

        // First make sure our callback won't be scheduled again after it finishes
        let clear_result = self.interface.clear_event_callback();

        // Disconnecting releases the callback during shutdown without waiting for a receiver
        self.callback_can_continue_tx.take();

        let stop_result = self.interface.finalize();
        self.finalized = stop_result.is_ok();

        clear_result.context("failed to clear vmnet interface's event callback")?;
        stop_result.context("failed to finalize vmnet's interface")
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        if !self.finalized {
            let _ = self.finalize();
        }
    }
}
