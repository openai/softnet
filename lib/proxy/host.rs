use crate::proxy::conntrack::ConntrackResult;
use crate::proxy::udp_packet_helper::UdpPacketHelper;
use crate::proxy::{Action, Direction, Proxy, Rule, select_rules};
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
        match frame.ethertype() {
            EthernetProtocol::Arp => Some(()),
            EthernetProtocol::Ipv4 => {
                let ipv4_pkt = Ipv4Packet::new_checked(frame.payload()).ok()?;
                self.allowed_from_host_ipv4(&ipv4_pkt)
            }
            _ => None,
        }
    }

    fn allowed_from_host_ipv4(&mut self, ipv4_pkt: &Ipv4Packet<&[u8]>) -> Option<()> {
        if !self.stateful_policy {
            return Some(());
        }

        if let Some(rules) = select_rules(&self.rules, ipv4_pkt.src_addr(), Direction::In) {
            // DHCP is required to maintain the VM's lease and must bypass user-specified rules
            if self.is_allowed_dhcp_response(ipv4_pkt) {
                return Some(());
            }

            // Only process packets addressed to the VM's current IP
            let Some(lease) = self.dhcp_snooper.lease() else {
                return None;
            };
            if !lease.is_valid_for(ipv4_pkt.dst_addr()) {
                return None;
            }

            // Stateless rules decide each packet immediately, without consulting the conntrack
            if let Some((action, _)) = rules
                .iter()
                .find(|(_, rule)| matches!(rule, Rule::Stateless(_)))
            {
                return (*action == Action::Allow).then_some(());
            }

            // Existing connections follow conntrack; new ones require an inbound stateful allow rule
            return match self.conntrack.inspect_from_host(ipv4_pkt) {
                ConntrackResult::Allowed => Some(()),
                ConntrackResult::Denied => None,
                ConntrackResult::New(pending) => {
                    let allow_new = rules.iter().any(|(action, rule)| {
                        *action == Action::Allow
                            && matches!(
                                rule,
                                Rule::Stateful {
                                    direction: Direction::In,
                                    ..
                                }
                            )
                    });

                    if !allow_new {
                        return None;
                    }

                    self.conntrack.commit(pending).then_some(())
                }
            };
        }

        Some(())
    }

    fn snoop(&mut self, frame: &EthernetFrame<&[u8]>) {
        if frame.ethertype() != EthernetProtocol::Ipv4 {
            return;
        }

        let ipv4_pkt = match Ipv4Packet::new_checked(frame.payload()) {
            Ok(ipv4_pkt) => ipv4_pkt,
            _ => return,
        };

        if !self.is_allowed_dhcp_response(&ipv4_pkt) {
            return;
        }

        let udp_pkt = match UdpPacket::new_checked(ipv4_pkt.payload()) {
            Ok(udp_pkt) => udp_pkt,
            Err(_) => return,
        };

        self.dhcp_snooper.register_dhcp_reply(udp_pkt.payload());
    }

    fn is_allowed_dhcp_response(&self, ipv4_pkt: &Ipv4Packet<&[u8]>) -> bool {
        if ipv4_pkt.src_addr() != self.host.gateway_ip
            || ipv4_pkt.next_header() != smoltcp::wire::IpProtocol::Udp
        {
            return false;
        }

        UdpPacket::new_checked(ipv4_pkt.payload())
            .map(|udp_pkt| udp_pkt.is_dhcp_response())
            .unwrap_or(false)
    }
}
