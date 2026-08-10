use dhcproto::Decodable;
use dhcproto::v4::{DhcpOption, HType, Message, MessageType, Opcode, OptionCode};
use smoltcp::wire::Ipv4Address;
use std::collections::HashSet;
use std::time::Duration;

#[derive(Default)]
pub struct DhcpSnooper {
    vm_mac_address: [u8; 6],
    vm_lease: Option<Lease>,
    uncertainty_duration: Duration,
}

impl DhcpSnooper {
    pub fn new(uncertainty_duration: Duration, vm_mac_address: [u8; 6]) -> Self {
        DhcpSnooper {
            vm_mac_address,
            uncertainty_duration,
            ..Default::default()
        }
    }

    pub fn register_dhcp_reply(&mut self, dhcp_packet: &[u8]) {
        let mut decoder = dhcproto::v4::Decoder::new(dhcp_packet);

        let message = match dhcproto::v4::Message::decode(&mut decoder) {
            Ok(message) => message,
            Err(_) => return,
        };

        // Decoded DHCP replies may be broadcast[1], so additionally validate the BOOTP client
        // hardware address to avoid acting on another VM's lease transition
        //
        // [1]: https://datatracker.ietf.org/doc/html/rfc2131#section-4.1
        if !message_matches_bootp_client(&message, Opcode::BootReply, self.vm_mac_address) {
            return;
        }

        match message.opts().msg_type() {
            Some(MessageType::Ack) => {
                let lease_time = match message.opts().get(OptionCode::AddressLeaseTime) {
                    Some(DhcpOption::AddressLeaseTime(lease_time)) => lease_time,
                    _ => return,
                };

                let dns_ips = match message.opts().get(OptionCode::DomainNameServer) {
                    Some(DhcpOption::DomainNameServer(dns_ips)) => {
                        HashSet::from_iter(dns_ips.iter().cloned())
                    }
                    _ => HashSet::new(),
                };

                let mut lease_duration = Duration::from_secs(*lease_time as u64);

                // Adjust for uncertainty caused by using a coarse clock
                lease_duration = lease_duration.saturating_sub(self.uncertainty_duration);

                self.vm_lease = Some(Lease::new(message.yiaddr(), lease_duration, dns_ips))
            }
            Some(MessageType::Nak) => {
                self.vm_lease = None;
            }
            _ => {}
        };
    }

    #[cfg(test)]
    pub(crate) fn set_lease(&mut self, vm_lease: Option<Lease>) {
        self.vm_lease = vm_lease
    }

    pub fn lease(&self) -> &Option<Lease> {
        &self.vm_lease
    }

    pub(crate) fn address_and_dns_ips(&self) -> Option<(Ipv4Address, HashSet<Ipv4Address>)> {
        let lease = self.vm_lease.as_ref().filter(|lease| lease.valid())?;
        Some((lease.address(), lease.dns_ips.clone()))
    }

    pub fn valid_dns_target(&self, addr: &Ipv4Address) -> bool {
        if let Some(lease) = &self.vm_lease {
            return lease.dns_ips.contains(addr);
        }

        false
    }
}

#[derive(Debug)]
pub struct Lease {
    address: Ipv4Address,
    valid_until: coarsetime::Instant,
    dns_ips: HashSet<Ipv4Address>,
}

impl Lease {
    pub fn new(address: Ipv4Address, lease_time: Duration, dns_ips: HashSet<Ipv4Address>) -> Lease {
        Lease {
            address,
            valid_until: coarsetime::Instant::recent() + lease_time.into(),
            dns_ips,
        }
    }

    pub fn address(&self) -> Ipv4Address {
        self.address
    }

    pub fn valid(&self) -> bool {
        coarsetime::Instant::recent() < self.valid_until
    }

    pub fn is_valid_for(&self, address: Ipv4Address) -> bool {
        self.address == address && self.valid()
    }
}

pub(crate) fn message_matches_bootp_client(
    message: &Message,
    opcode: Opcode,
    mac: [u8; 6],
) -> bool {
    message.opcode() == opcode
        && message.htype() == HType::Eth
        && message.hlen() == mac.len() as u8
        && message.chaddr() == mac
}

#[cfg(test)]
mod tests {
    use super::{DhcpSnooper, Lease};
    use dhcproto::v4::{DhcpOption, Message, MessageType, Opcode};
    use dhcproto::{Encodable, Encoder};
    use smoltcp::wire::Ipv4Address;
    use std::collections::HashSet;
    use std::time::Duration;

    const VM_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const OTHER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    const OLD_ADDRESS: Ipv4Address = Ipv4Address::new(192, 168, 64, 2);

    #[test]
    fn processes_replies_only_for_matching_client() {
        // Start with an active lease
        let mut snooper = DhcpSnooper::new(Duration::ZERO, VM_MAC);
        snooper.set_lease(Some(Lease::new(
            OLD_ADDRESS,
            Duration::from_secs(600),
            HashSet::new(),
        )));

        // Ignore a NAK for another client
        let mut message = Message::new(
            Ipv4Address::UNSPECIFIED,
            Ipv4Address::UNSPECIFIED,
            Ipv4Address::UNSPECIFIED,
            Ipv4Address::UNSPECIFIED,
            &OTHER_MAC,
        );
        message.set_opcode(Opcode::BootReply);
        message
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Nak));

        let mut encoded = Vec::new();
        message.encode(&mut Encoder::new(&mut encoded)).unwrap();

        snooper.register_dhcp_reply(&encoded);

        assert_eq!(snooper.lease().as_ref().unwrap().address(), OLD_ADDRESS);

        // Process a NAK for the matching client
        message.set_chaddr(&VM_MAC);
        encoded.clear();
        message.encode(&mut Encoder::new(&mut encoded)).unwrap();

        snooper.register_dhcp_reply(&encoded);

        assert!(snooper.lease().is_none());
    }
}
