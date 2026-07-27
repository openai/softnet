use dhcproto::Decodable;
use dhcproto::v4::{DhcpOption, MessageType, OptionCode};
use smoltcp::wire::Ipv4Address;
use std::collections::HashSet;
use std::time::Duration;

#[derive(Default)]
pub struct DhcpSnooper {
    vm_lease: Option<Lease>,
    uncertainty_duration: Duration,
}

impl DhcpSnooper {
    pub fn new(uncertainty_duration: Duration) -> Self {
        DhcpSnooper {
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
