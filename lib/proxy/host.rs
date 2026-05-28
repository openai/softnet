use crate::proxy::Proxy;
use crate::proxy::udp_packet_helper::UdpPacketHelper;
use anyhow::{Context, Result};
use smoltcp::wire::{EthernetFrame, EthernetProtocol, Ipv4Packet, UdpPacket};

impl Proxy<'_> {
    pub(crate) fn process_frame_from_host(&mut self, frame: &EthernetFrame<&[u8]>) -> Result<()> {
        if self.allowed_from_host(frame).is_none() {
            // Block packet by not forwarding it to the VM
            return Ok(());
        }

        match self.vm.write(frame.as_ref()) {
            Ok(_) => Ok(()),
            Err(err) => {
                if let Some(libc::ENOBUFS) = err.raw_os_error() {
                    if !self.enobufs_encountered {
                        sentry::capture_message(
                            "No buffer space available in VM's socket",
                            sentry::Level::Warning,
                        );
                        self.enobufs_encountered = true;
                    }

                    return Ok(());
                }

                Err(err).context("failed to write to the VM")
            }
        }
    }

    fn allowed_from_host(&mut self, frame: &EthernetFrame<&[u8]>) -> Option<()> {
        if self.peer_mac_addresses.is_empty() {
            // Peers unset → isolation between VMs is enabled → all frames are from gateway
            return self.allowed_from_gateway(frame);
        }

        // Peers set → isolation between VMs is disabled → can receive a frame from any VM
        let from_gateway = Some(frame.src_addr()) == self.host.gateway_mac;
        if from_gateway {
            return self.allowed_from_gateway(frame);
        }

        let from_peer = self.peer_mac_addresses.contains(&frame.src_addr());
        if from_peer {
            return self.allowed_from_peer(frame);
        }

        None
    }

    fn allowed_from_gateway(&mut self, frame: &EthernetFrame<&[u8]>) -> Option<()> {
        let decision = match frame.ethertype() {
            EthernetProtocol::Arp => Some(()),
            EthernetProtocol::Ipv4 => Some(()),
            _ => None,
        };

        if decision.is_some() {
            // Snoop bootpd(8) replies from the gateway to
            // figure out the IP assigned to the VM
            if frame.dst_addr() == self.vm_mac_address {
                self.snoop(frame);
            }
        }

        decision
    }

    fn allowed_from_peer(&mut self, frame: &EthernetFrame<&[u8]>) -> Option<()> {
        if frame.dst_addr() != self.vm_mac_address
            && !frame.dst_addr().is_broadcast()
            && !frame.dst_addr().is_multicast()
        {
            return None;
        }

        match frame.ethertype() {
            EthernetProtocol::Arp => Some(()),
            EthernetProtocol::Ipv4 => Some(()),
            _ => None,
        }
    }

    fn snoop(&mut self, frame: &EthernetFrame<&[u8]>) {
        if frame.ethertype() != EthernetProtocol::Ipv4 {
            return;
        }

        let ipv4_pkt = match Ipv4Packet::new_checked(frame.payload()) {
            Ok(ipv4_pkt) => ipv4_pkt,
            _ => return,
        };

        if ipv4_pkt.src_addr() != self.host.gateway_ip {
            return;
        }

        if ipv4_pkt.next_header() != smoltcp::wire::IpProtocol::Udp {
            return;
        }

        let udp_pkt = match UdpPacket::new_checked(ipv4_pkt.payload()) {
            Ok(udp_pkt) => udp_pkt,
            Err(_) => return,
        };

        if !udp_pkt.is_dhcp_response() {
            return;
        }

        self.dhcp_snooper.register_dhcp_reply(udp_pkt.payload());
    }
}
