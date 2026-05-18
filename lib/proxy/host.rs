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

        // Snoop bootpd(8) replies from the host to
        // figure out the IP assigned to the VM
        if frame.dst_addr() == self.vm_mac_address {
            self.snoop(frame);
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
        let from_gateway = frame.src_addr() == self.host.gateway_mac;
        let peer_action = self.rules_mac.get(frame.src_addr().as_bytes());
        let from_allowed_peer = peer_action == Some(&crate::proxy::Action::Allow);

        if !from_gateway && !from_allowed_peer {
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
