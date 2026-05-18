use crate::proxy::udp_packet_helper::UdpPacketHelper;
use crate::proxy::{Action, Proxy};
use anyhow::Context;
use anyhow::Result;
use ipnet::Ipv4Net;
use smoltcp::wire::{
    ArpPacket, EthernetFrame, EthernetProtocol, IpProtocol, Ipv4Packet, UdpPacket,
};
use std::net::Ipv4Addr;

impl Proxy<'_> {
    pub(crate) fn process_frame_from_vm(&mut self, frame: EthernetFrame<&[u8]>) -> Result<()> {
        if self.allowed_from_vm(&frame).is_none() {
            // Block packet by not forwarding it to the host
            return Ok(());
        }

        self.host
            .write(frame.as_ref())
            .map(|_| ())
            .context("failed to write to the host")
    }

    pub(crate) fn allowed_from_vm(&self, frame: &EthernetFrame<&[u8]>) -> Option<()> {
        if frame.src_addr() != self.vm_mac_address {
            return None;
        }

        let dst_mac_allowed = match self.rules_mac.get(frame.dst_addr().as_bytes()) {
            Some(Action::Block) => return None,
            Some(Action::Allow) => true,
            None => false,
        };

        match frame.ethertype() {
            EthernetProtocol::Arp => {
                let arp_pkt = ArpPacket::new_checked(frame.payload()).ok()?;
                self.allowed_from_vm_arp(arp_pkt)
            }
            EthernetProtocol::Ipv4 => {
                let ipv4_pkt = Ipv4Packet::new_checked(frame.payload()).ok()?;
                self.allowed_from_vm_ipv4(ipv4_pkt, dst_mac_allowed)
            }
            _ => None,
        }
    }

    fn allowed_from_vm_arp(&self, arp_pkt: ArpPacket<&[u8]>) -> Option<()> {
        if arp_pkt.source_hardware_addr() != self.vm_mac_address.0 {
            return None;
        }

        let source_protocol_addr: [u8; 4] = arp_pkt.source_protocol_addr().try_into().unwrap();
        let source_protocol_addr = Ipv4Addr::from(source_protocol_addr);

        if let Some(lease) = self.dhcp_snooper.lease() {
            if lease.valid_ip_source(source_protocol_addr) {
                return Some(());
            }
        } else if source_protocol_addr.is_unspecified() {
            return Some(());
        }

        None
    }

    pub(crate) fn allowed_from_vm_ipv4(
        &self,
        ipv4_pkt: Ipv4Packet<&[u8]>,
        dst_mac_allowed: bool,
    ) -> Option<()> {
        // Is this packet coming from VM's IP address that we've learned from DHCP snooping?
        if let Some(lease) = &self.dhcp_snooper.lease()
            && lease.valid_ip_source(ipv4_pkt.src_addr())
        {
            let dst_addr = ipv4_pkt.dst_addr();

            if dst_mac_allowed {
                return Some(());
            }

            // Filter traffic based on user-specified rules first
            if !self.rules.is_empty() {
                let dst_net = Ipv4Net::from(dst_addr);

                if let Some((_, action)) = self.rules.get_lpm(&dst_net) {
                    return match action {
                        Action::Allow => Some(()),
                        Action::Block => None,
                    };
                }
            }

            // When no user-specified rules matched, simply allow all global traffic
            if ip_network::IpNetwork::from(dst_addr).is_global() {
                return Some(());
            }

            // Additionally, allow communication with the host,
            // otherwise things like SSH to a VM won't work
            if ipv4_pkt.dst_addr() == self.host.gateway_ip {
                return Some(());
            }

            // Additionally, allow DNS requests to DNS-servers
            // provided to a VM by the host's DHCP server
            if ipv4_pkt.next_header() == IpProtocol::Udp {
                let udp_pkt = UdpPacket::new_checked(ipv4_pkt.payload()).ok()?;

                if udp_pkt.is_dns_request()
                    && self.dhcp_snooper.valid_dns_target(&ipv4_pkt.dst_addr())
                {
                    return Some(());
                }
            }
        }

        // Allow outgoing DHCP requests to broadcast addresses,
        // otherwise DHCP snooper will never be populated
        if ipv4_pkt.next_header() == IpProtocol::Udp {
            let udp_pkt = UdpPacket::new_checked(ipv4_pkt.payload()).ok()?;

            // Allow DHCP communication with the bootpd(8) on host via broadcast address
            if udp_pkt.is_dhcp_request() && ipv4_pkt.dst_addr().is_broadcast() {
                return Some(());
            }
        }

        None
    }
}
