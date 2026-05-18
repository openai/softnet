use crate::proxy::udp_packet_helper::UdpPacketHelper;
use crate::proxy::{Action, Proxy};
use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use smoltcp::wire::{ArpPacket, EthernetFrame, EthernetProtocol, Ipv4Packet, UdpPacket};
use std::net::Ipv4Addr;

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

    pub(crate) fn allowed_from_host(&self, frame: &EthernetFrame<&[u8]>) -> Option<()> {
        if frame.src_addr() == self.host.gateway_mac {
            return allowed_host_ethertype(frame);
        }

        match self.rules_mac.get(frame.src_addr().as_bytes()) {
            Some(Action::Block) => return None,
            Some(Action::Allow) => return allowed_host_ethertype(frame),
            None => {}
        }

        match frame.ethertype() {
            EthernetProtocol::Arp => {
                let arp_pkt = ArpPacket::new_checked(frame.payload()).ok()?;
                let source_protocol_addr: [u8; 4] =
                    arp_pkt.source_protocol_addr().try_into().ok()?;

                self.allowed_peer_ip_from_host(Ipv4Addr::from(source_protocol_addr))
            }
            EthernetProtocol::Ipv4 => {
                let ipv4_pkt = Ipv4Packet::new_checked(frame.payload()).ok()?;
                self.allowed_peer_ip_from_host(ipv4_pkt.src_addr())
            }
            _ => None,
        }
    }

    fn allowed_peer_ip_from_host(&self, peer_ip: Ipv4Addr) -> Option<()> {
        let peer_net = Ipv4Net::from(peer_ip);

        match self.rules.get_lpm(&peer_net).map(|(_, action)| action) {
            Some(Action::Allow) => Some(()),
            Some(Action::Block) | None => None,
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

fn allowed_host_ethertype(frame: &EthernetFrame<&[u8]>) -> Option<()> {
    match frame.ethertype() {
        EthernetProtocol::Arp | EthernetProtocol::Ipv4 => Some(()),
        _ => None,
    }
}
