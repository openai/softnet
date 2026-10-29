use crate::network::Network;
use anyhow::{Context, Result, anyhow};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::mpsc::{SyncSender, sync_channel};
use tokio::sync::Notify;
use vmnet::parameters::{Parameter, ParameterKind};
use vmnet::{Batch, Events, Options};

pub struct Host {
    interface: vmnet::Interface,
    ready: Arc<Notify>,
    draining: bool,
    callback_can_continue_tx: Option<SyncSender<()>>,
    pub vm_ip: Ipv4Addr,
    pub gateway_ip: smoltcp::wire::Ipv4Address,
    pub max_packet_size: u64,
    pub read_max_packets: u64,
    finalized: bool,
}

impl Host {
    pub fn new(network: &Network, vm_ip: Ipv4Addr, enable_isolation: bool) -> Result<Host> {
        // Instantiate vmnet's interface
        //
        // The interface retains the network reservation until it is stopped
        let mut interface = vmnet::Interface::with_network(
            &network.handle,
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
            gateway_ip: network.gateway_ip,
            max_packet_size,
            read_max_packets,
            finalized: false,
        })
    }
}

impl Host {
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
