mod exposed_port;
mod host;
mod port_forwarder;
mod udp_packet_helper;
mod vm;

use crate::dhcp_snooper::DhcpSnooper;
use crate::host::Host;
use crate::host::NetType;
use crate::poller::Poller;
use crate::vm::VM;
use anyhow::Result;
pub use exposed_port::ExposedPort;
use ipnet::Ipv4Net;
use mac_address::MacAddress;
use port_forwarder::PortForwarder;
use prefix_trie::{Prefix, PrefixMap};
use smoltcp::wire::EthernetFrame;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::os::unix::io::{AsRawFd, RawFd};
use std::str::FromStr;
use std::time::Duration;
use vmnet::Batch;

pub struct Proxy<'proxy> {
    vm: VM,
    host: Host,
    poller: Poller<'proxy>,
    vm_mac_address: smoltcp::wire::EthernetAddress,
    dhcp_snooper: DhcpSnooper,
    rules: PrefixMap<Ipv4Net, Action>,
    rules_mac: HashMap<[u8; 6], Action>,
    enobufs_encountered: bool,
    port_forwarder: PortForwarder,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Prefix(Ipv4Net),
    MacAddress(MacAddress),
    Host,
}

impl Target {
    pub fn is_ipv4_default_route(&self) -> bool {
        matches!(self, Target::Prefix(prefix) if *prefix == Ipv4Net::zero())
    }

    pub fn is_mac_address(&self) -> bool {
        matches!(self, Target::MacAddress(_))
    }
}

impl FromStr for Target {
    type Err = ipnet::AddrParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s == "@host" {
            return Ok(Target::Host);
        }

        if let Ok(mac_address) = MacAddress::from_str(s) {
            return Ok(Target::MacAddress(mac_address));
        }

        Ipv4Net::from_str(s).map(Target::Prefix)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Action {
    Block,
    Allow,
}

impl Proxy<'_> {
    pub fn new<'proxy>(
        vm_fd: RawFd,
        vm_mac_address: MacAddress,
        vm_net_type: NetType,
        enable_isolation: bool,
        allow: Vec<Target>,
        block: Vec<Target>,
        exposed_ports: Vec<ExposedPort>,
    ) -> Result<Proxy<'proxy>> {
        let vm = VM::new(vm_fd)?;
        let host = Host::new(vm_net_type, enable_isolation)?;
        let poller_timeout = Duration::from_millis(100);
        let poller = Poller::new(vm.as_raw_fd(), host.as_raw_fd(), poller_timeout)?;

        // Craft packet filter rules
        //
        // SECURITY: blocking rules must always take precedence
        // over allowing rules when prefixes are identical.
        let mut rules = PrefixMap::new();
        let mut rules_mac = HashMap::new();

        for allow_target in allow {
            let allow_prefix = match allow_target {
                Target::Prefix(prefix) => prefix,
                Target::Host => host.gateway_ip.into(),
                Target::MacAddress(mac_address) => {
                    rules_mac.insert(mac_address.bytes(), Action::Allow);

                    continue;
                }
            };

            rules.insert(allow_prefix, Action::Allow);
        }

        for block_target in block {
            let block_prefix = match block_target {
                Target::Prefix(prefix) => prefix,
                Target::Host => host.gateway_ip.into(),
                Target::MacAddress(mac_address) => {
                    rules_mac.insert(mac_address.bytes(), Action::Block);

                    continue;
                }
            };

            rules.insert(block_prefix, Action::Block);
        }

        Ok(Proxy {
            vm,
            host,
            poller,
            vm_mac_address: smoltcp::wire::EthernetAddress(vm_mac_address.bytes()),
            dhcp_snooper: DhcpSnooper::new(poller_timeout),
            rules,
            rules_mac,
            enobufs_encountered: false,
            port_forwarder: PortForwarder::new(exposed_ports),
        })
    }

    pub fn run(&mut self) -> Result<()> {
        // Create a single buffer from reading from the VM
        let mut buf: Vec<u8> = vec![0; self.host.max_packet_size as usize];

        // Create multiple buffers and a batch for reading from the host
        let mut bufs = vec![
            vec![0u8; self.host.max_packet_size as usize];
            self.host.read_max_packets as usize
        ];
        let mut batch = Batch::preallocate(bufs.len());

        self.poller.arm()?;

        loop {
            let (vm_readable, host_readable, interrupt) = self.poller.wait()?;

            // Update coarse time for the DHCP snooper
            coarsetime::Instant::update();

            if vm_readable {
                self.read_from_vm(buf.as_mut_slice())?;
            }

            if host_readable {
                self.read_from_host(&mut batch, &mut bufs)?;
            }

            // Graceful termination
            if interrupt {
                return Ok(());
            }

            // Timeout
            if !vm_readable && !host_readable && !interrupt {
                self.port_forwarder
                    .tick(&mut self.host, self.dhcp_snooper.lease());
            }

            self.poller.rearm();
        }
    }

    fn read_from_vm(&mut self, buf: &mut [u8]) -> Result<()> {
        loop {
            match self.vm.read(buf) {
                Ok(n) => {
                    // Update coarse time for the DHCP snooper
                    coarsetime::Instant::update();

                    if let Ok(frame) = EthernetFrame::new_checked(&buf[..n]) {
                        self.process_frame_from_vm(frame)?;
                    }
                }
                Err(err) => {
                    if err.kind() == ErrorKind::WouldBlock {
                        return Ok(());
                    }

                    return Err(err.into());
                }
            }
        }
    }

    fn read_from_host(&mut self, batch: &mut Batch, bufs: &mut [Vec<u8>]) -> Result<()> {
        loop {
            match self.host.read(batch, bufs) {
                Ok(pktcnt) => {
                    // Update coarse time for the DHCP snooper
                    coarsetime::Instant::update();

                    for buf in batch.packet_sized_bufs(bufs).take(pktcnt) {
                        if let Ok(pkt) = EthernetFrame::new_checked(buf) {
                            self.process_frame_from_host(&pkt)?;
                        }
                    }
                }
                Err(err) => {
                    if let vmnet::Error::VmnetReadNothing = err {
                        return Ok(());
                    }

                    return Err(err.into());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::NetType;
    use crate::dhcp_snooper::Lease;
    use crate::proxy::{Action, Proxy, Target};
    use ipnet::Ipv4Net;
    use mac_address::MacAddress;
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
    use prefix_trie::PrefixMap;
    use serial_test::serial;
    use smoltcp::wire::{EthernetAddress, Ipv4Address, Ipv4Packet};
    use std::collections::HashSet;
    use std::os::fd::AsRawFd;
    use std::str::FromStr;
    use std::time::Duration;

    #[test]
    #[serial]
    fn test_blocking_takes_precedence() {
        let vm_ip = Ipv4Address::from_str("192.168.0.2").unwrap();
        let proxy = create_proxy(vm_ip, vec!["66.66.0.0/16"], vec!["66.66.0.0/16"]);

        assert_eq!(
            proxy.rules,
            PrefixMap::<Ipv4Net, Action>::from_iter(vec![(
                Ipv4Net::from_str("66.66.0.0/16").unwrap(),
                Action::Block
            ),])
        );

        assert!(allowed_from_vm_ipv4(&proxy, vm_ip, "66.66.66.66").is_none());
    }

    #[test]
    #[serial]
    fn test_longest_prefix_match_wins() {
        let vm_ip = Ipv4Address::from_str("192.168.0.2").unwrap();
        let proxy = create_proxy(vm_ip, vec!["33.33.33.33/32"], vec!["33.33.33.0/24"]);

        assert_eq!(
            proxy.rules,
            PrefixMap::<Ipv4Net, Action>::from_iter(vec![
                (Ipv4Net::from_str("33.33.33.33/32").unwrap(), Action::Allow),
                (Ipv4Net::from_str("33.33.33.0/24").unwrap(), Action::Block),
            ])
        );

        assert!(allowed_from_vm_ipv4(&proxy, vm_ip, "33.33.33.32").is_none());
        assert!(allowed_from_vm_ipv4(&proxy, vm_ip, "33.33.33.33").is_some());
        assert!(allowed_from_vm_ipv4(&proxy, vm_ip, "33.33.33.34").is_none());
    }

    #[test]
    #[serial]
    fn test_allow_host() {
        let vm_ip = Ipv4Address::from_str("192.168.0.2").unwrap();
        let proxy = create_proxy(vm_ip, vec!["@host"], vec!["0.0.0.0/0"]);

        assert_eq!(
            proxy.rules,
            PrefixMap::from_iter(vec![
                (proxy.host.gateway_ip.into(), Action::Allow),
                (Ipv4Net::from_str("0.0.0.0/0").unwrap(), Action::Block),
            ])
        );

        // Access to global IPs should be disallowed because of --block=0.0.0.0/0
        assert!(allowed_from_vm_ipv4(&proxy, vm_ip, "8.8.8.8").is_none());

        // Despite the above, access to host IP address should be possible because of --allow=@host
        assert!(allowed_from_vm_ipv4(&proxy, vm_ip, &proxy.host.gateway_ip.to_string()).is_some());
    }

    #[test]
    #[serial]
    fn test_allow_mac_takes_precedence_over_blocked_prefix() {
        let vm_ip = Ipv4Address::from_str("192.168.0.2").unwrap();
        let peer_mac = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);
        let proxy = create_proxy(vm_ip, vec!["02:00:00:00:00:02"], vec!["0.0.0.0/0"]);

        assert!(allowed_from_vm_ipv4_to_mac(&proxy, vm_ip, "192.168.0.3", peer_mac).is_some());
    }

    #[test]
    #[serial]
    fn test_block_mac_takes_precedence_over_allowed_prefix() {
        let vm_ip = Ipv4Address::from_str("192.168.0.2").unwrap();
        let peer_mac = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);
        let proxy = create_proxy(
            vm_ip,
            vec!["192.168.0.0/24", "02:00:00:00:00:02"],
            vec!["02:00:00:00:00:02"],
        );

        assert!(allowed_from_vm_ipv4_to_mac(&proxy, vm_ip, "192.168.0.3", peer_mac).is_none());
    }

    fn create_proxy<'test>(vm_ip: Ipv4Address, allow: Vec<&str>, block: Vec<&str>) -> Proxy<'test> {
        let (vm_fd, _) = socketpair(
            AddressFamily::Unix,
            SockType::Datagram,
            None,
            SockFlag::empty(),
        )
        .unwrap();
        let vm_fd = Box::leak(Box::new(vm_fd));

        let allow: Vec<Target> = allow
            .into_iter()
            .map(|cidr| cidr.parse().unwrap())
            .collect();
        let block: Vec<Target> = block
            .into_iter()
            .map(|cidr| cidr.parse().unwrap())
            .collect();
        let enable_isolation = !allow.iter().any(Target::is_ipv4_default_route)
            && !allow.iter().chain(block.iter()).any(Target::is_mac_address);

        let mut proxy = Proxy::new(
            vm_fd.as_raw_fd(),
            MacAddress::from_str("02:00:00:00:00:01").unwrap(),
            NetType::Nat,
            enable_isolation,
            allow,
            block,
            Vec::default(),
        )
        .unwrap();

        proxy.dhcp_snooper.set_lease(Some(Lease::new(
            vm_ip,
            Duration::from_secs(600),
            HashSet::new(),
        )));

        proxy
    }

    fn allowed_from_vm_ipv4(proxy: &Proxy, src: Ipv4Address, dst: &str) -> Option<()> {
        allowed_from_vm_ipv4_to_mac(proxy, src, dst, EthernetAddress([0x02, 0, 0, 0, 0, 0x03]))
    }

    fn allowed_from_vm_ipv4_to_mac(
        proxy: &Proxy,
        src: Ipv4Address,
        dst: &str,
        dst_mac: EthernetAddress,
    ) -> Option<()> {
        let mut buf = vec![0; 1500];

        let mut ipv4_pkt_mut = Ipv4Packet::new_unchecked(&mut buf[..]);
        ipv4_pkt_mut.set_src_addr(src);
        ipv4_pkt_mut.set_dst_addr(Ipv4Address::from_str(dst).unwrap());

        let ipv4_pkt = Ipv4Packet::new_unchecked(buf.as_slice());

        proxy.allowed_from_vm_ipv4(ipv4_pkt, dst_mac)
    }
}
