mod control;
mod exposed_port;
mod host;
mod port_forwarder;
mod rule;
mod udp_packet_helper;
mod vm;

use crate::dhcp_snooper::DhcpSnooper;
use crate::host::Host;
use crate::host::NetType;
use crate::poller::Poller;
use crate::vm::VM;
use anyhow::Result;
use control::Control;
pub use exposed_port::ExposedPort;
use ipnet::Ipv4Net;
use mac_address::MacAddress;
use port_forwarder::PortForwarder;
use prefix_trie::PrefixMap;
pub use rule::{Direction, Rule, Target};
use smoltcp::wire::EthernetFrame;
use std::io::ErrorKind;
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;
use vmnet::Batch;

pub struct Proxy<'proxy> {
    vm: VM,
    host: Host,
    poller: Poller<'proxy>,
    vm_mac_address: smoltcp::wire::EthernetAddress,
    dhcp_snooper: DhcpSnooper,
    rules: PrefixMap<Ipv4Net, Action>,
    control: Option<Control>,
    enobufs_encountered: bool,
    port_forwarder: PortForwarder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Block,
    Allow,
}

impl Proxy<'_> {
    pub fn new<'proxy>(
        vm_fd: RawFd,
        vm_mac_address: MacAddress,
        vm_net_type: NetType,
        allow: Vec<Rule>,
        block: Vec<Rule>,
        exposed_ports: Vec<ExposedPort>,
        control_fd: Option<RawFd>,
    ) -> Result<Proxy<'proxy>> {
        // Stateful rules are not supported yet
        let allow = stateless_targets(allow);
        let block = stateless_targets(block);

        let vm = VM::new(vm_fd)?;
        let host = Host::new(
            vm_net_type,
            !allow.contains(&Target::Prefix(Ipv4Net::default())),
        )?;
        let poller_timeout = Duration::from_millis(100);
        let control = control_fd
            .map(|control_fd| {
                Control::new(control_fd, host.gateway_ip, allow.clone(), block.clone())
            })
            .transpose()?;
        let poller = Poller::new(
            vm.as_raw_fd(),
            host.as_raw_fd(),
            control.as_ref().map(AsRawFd::as_raw_fd),
            poller_timeout,
        )?;

        // Craft packet filter rules
        //
        // SECURITY: blocking rules must always take precedence
        // over allowing rules when prefixes are identical.
        let mut rules = PrefixMap::new();

        for allow_target in allow {
            let allow_prefix = match allow_target {
                Target::Prefix(prefix) => prefix,
                Target::Host => host.gateway_ip.into(),
            };

            rules.insert(allow_prefix, Action::Allow);
        }

        for block_target in block {
            let block_prefix = match block_target {
                Target::Prefix(prefix) => prefix,
                Target::Host => host.gateway_ip.into(),
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
            control,
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

            // Service control on every wake (including timeouts) so a bounded read or a pending
            // response continues making progress even when no new edge is generated.
            self.service_control();

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
        let mut packets_read = 0;

        loop {
            match self.vm.read(buf) {
                Ok(n) => {
                    // Update coarse time for the DHCP snooper
                    coarsetime::Instant::update();

                    if let Ok(frame) = EthernetFrame::new_checked(&buf[..n]) {
                        self.process_frame_from_vm(frame)?;
                    }

                    packets_read += 1;
                    if packets_read == 128 {
                        self.service_control();
                        packets_read = 0;
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

                    self.service_control();
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

    fn service_control(&mut self) {
        let Some(control) = self.control.as_mut() else {
            return;
        };

        let keep_open = match control.service(&mut self.rules) {
            Ok(keep_open) => keep_open,
            Err(err) => {
                log::warn!("disabling Softnet control socket: {err:#}");
                false
            }
        };

        if keep_open {
            return;
        }

        if let Err(err) = self.poller.remove_control() {
            log::warn!("failed to remove Softnet control socket from the poller: {err:#}");
        }

        if let Some(control) = self.control.take()
            && let Err(err) = control.shutdown()
        {
            log::warn!("failed to shut down Softnet control socket: {err:#}");
        }
    }
}

fn stateless_targets(rules: Vec<Rule>) -> Vec<Target> {
    rules
        .into_iter()
        .map(|rule| match rule {
            Rule::Stateless(target) => target,
            Rule::Stateful { .. } => unreachable!("stateful rules were rejected before conversion"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::NetType;
    use crate::dhcp_snooper::Lease;
    use crate::proxy::{Action, Proxy};
    use ipnet::Ipv4Net;
    use mac_address::MacAddress;
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
    use prefix_trie::PrefixMap;
    use serial_test::serial;
    use smoltcp::wire::{Ipv4Address, Ipv4Packet};
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

    fn create_proxy<'test>(vm_ip: Ipv4Address, allow: Vec<&str>, block: Vec<&str>) -> Proxy<'test> {
        let (vm_fd, _) = socketpair(
            AddressFamily::Unix,
            SockType::Datagram,
            None,
            SockFlag::empty(),
        )
        .unwrap();
        let vm_fd = Box::leak(Box::new(vm_fd));

        let mut proxy = Proxy::new(
            vm_fd.as_raw_fd(),
            MacAddress::from_str("02:00:00:00:00:01").unwrap(),
            NetType::Nat,
            allow
                .into_iter()
                .map(|value| value.parse().unwrap())
                .collect(),
            block
                .into_iter()
                .map(|value| value.parse().unwrap())
                .collect(),
            Vec::default(),
            None,
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
        let mut buf = vec![0; 1500];

        let mut ipv4_pkt_mut = Ipv4Packet::new_unchecked(&mut buf[..]);
        ipv4_pkt_mut.set_src_addr(src);
        ipv4_pkt_mut.set_dst_addr(Ipv4Address::from_str(dst).unwrap());

        let ipv4_pkt = Ipv4Packet::new_unchecked(buf.as_slice());

        proxy.allowed_from_vm_ipv4(ipv4_pkt)
    }
}
