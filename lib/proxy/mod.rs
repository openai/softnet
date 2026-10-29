mod exposed_port;
mod flows;
mod host;
mod rule;
mod rules;
mod vm;

use crate::dhcp_server::DhcpServer;
use crate::host::Host;
use crate::network::Network;
use crate::vm::VM;
use anyhow::Result;
pub use exposed_port::ExposedPort;
use flows::{FlowTable, PendingFlow};
use ipnet::Ipv4Net;
use mac_address::MacAddress;
pub use rule::{Direction, Rule, Target};
pub(crate) use rules::{PolicyDecision, Rules};
use smoltcp::wire::{EthernetAddress, EthernetFrame, Ipv4Address};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{MissedTickBehavior, interval};
use vmnet::Batch;

pub(crate) enum Command {
    PolicyGet {
        reply: oneshot::Sender<Policy>,
    },
    PolicySet {
        allow: Vec<Rule>,
        block: Vec<Rule>,
        reply: oneshot::Sender<Policy>,
    },
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Policy {
    pub(crate) allow: Vec<Rule>,
    pub(crate) block: Vec<Rule>,
    pub(crate) rule_count: usize,
}

pub struct Proxy {
    vm: VM,
    host: Host,
    vm_mac_address: smoltcp::wire::EthernetAddress,
    dhcp_server: DhcpServer,
    rules: Rules,
    allow: Vec<Rule>,
    block: Vec<Rule>,
    flows: Option<FlowTable>,
    enobufs_encountered: bool,
}

impl Proxy {
    /// Creates the VM interface and packet policy using the entered Tokio runtime.
    pub(crate) fn new(
        vm: VM,
        vm_mac_address: MacAddress,
        vm_ip: Ipv4Addr,
        network: &Network,
        allow: Vec<Rule>,
        block: Vec<Rule>,
    ) -> Result<Proxy> {
        let vm_mac_address = EthernetAddress(vm_mac_address.bytes());
        let allow = normalize_rules(allow);
        let block = normalize_rules(block);

        // Create this VM's vmnet interface on the shared network
        let host = Host::new(
            network,
            vm_ip,
            !allow.contains(&Rule::Stateless(Target::Prefix(Ipv4Net::default()))),
        )?;

        let rules = Rules::new(host.gateway_ip, &allow, &block);

        // Any stateful rule enables flow inspection for the whole VM, including
        // traffic admitted through implicit global and gateway fallbacks
        let flows = rules.has_stateful().then(FlowTable::new);

        // Serve the VM's reserved address over DHCP
        let dhcp_server = DhcpServer::new(
            vm_mac_address,
            host.vm_ip,
            network.subnet.netmask(),
            host.gateway_ip,
        );

        Ok(Proxy {
            vm,
            host,
            vm_mac_address,
            dhcp_server,
            rules,
            allow,
            block,
            flows,
            enobufs_encountered: false,
        })
    }

    pub(crate) async fn run(&mut self, mut commands_rx: mpsc::Receiver<Command>) -> Result<()> {
        // Create a single buffer from reading from the VM
        let mut buf: Vec<u8> = vec![0; self.host.max_packet_size as usize];

        // Create multiple buffers and a batch for reading from the host
        let mut bufs = vec![
            vec![0u8; self.host.max_packet_size as usize];
            self.host.read_max_packets as usize
        ];
        let mut batch = Batch::preallocate(bufs.len());

        // Check VM connectivity periodically, skipping missed ticks
        let mut maintenance = interval(Duration::from_millis(100));
        maintenance.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // Service packet I/O, policy changes, and maintenance on the same runtime
        loop {
            tokio::select! {
                result = self.vm.read(&mut buf) => {
                    let n = match result {
                        Ok(n) => n,
                        Err(error) => {
                            // Treat peer closure as normal VM shutdown
                            if self.vm.is_disconnect(&error)? {
                                return Ok(());
                            }

                            return Err(error.into());
                        }
                    };

                    // Update the coarse time once the packet arrives
                    coarsetime::Instant::update();

                    if let Ok(frame) = EthernetFrame::new_checked(&buf[..n]) {
                        self.process_frame_from_vm(frame)?;
                    }

                    // Limit VM bursts to 128 packets (including the one we read above),
                    // so that other select branches will have a chance to run
                    for _ in 0..127 {
                        match self.vm.try_read(&mut buf) {
                            Ok(n) => {
                                coarsetime::Instant::update();

                                if let Ok(frame) = EthernetFrame::new_checked(&buf[..n]) {
                                    self.process_frame_from_vm(frame)?;
                                }

                                tokio::task::consume_budget().await;
                            }
                            Err(err) => {
                                // End this burst once all queued packets have been drained
                                if err.kind() == std::io::ErrorKind::WouldBlock {
                                    break;
                                }

                                // Treat peer closure as normal VM shutdown
                                if self.vm.is_disconnect(&err)? {
                                    return Ok(());
                                }

                                return Err(err.into());
                            }
                        }
                    }
                }

                result = self.host.read(&mut batch, &mut bufs) => {
                    let pktcnt = result?;

                    // Update the coarse time once the packet arrives
                    coarsetime::Instant::update();

                    for buf in batch.packet_sized_bufs(&bufs).take(pktcnt) {
                        if let Ok(pkt) = EthernetFrame::new_checked(buf)
                            && let Err(error) = self.process_frame_from_host(&pkt) {
                                // Treat peer closure as normal VM shutdown
                                if let Some(io_error) = error.downcast_ref::<std::io::Error>()
                                    && self.vm.is_disconnect(io_error)?
                                {
                                    return Ok(());
                                }

                                return Err(error);
                            }

                        tokio::task::consume_budget().await;
                    }
                }

                command = commands_rx.recv() => {
                    match command {
                        Some(Command::PolicyGet { reply }) => {
                            let _ = reply.send(self.policy_get());
                        }
                        Some(Command::PolicySet { allow, block, reply }) => {
                            let _ = reply.send(self.policy_set(allow, block));
                        }
                        None => return Ok(()),
                    }
                }

                _ = maintenance.tick() => {
                    // Unix datagram sockets do not report peer closure as readable
                    if !self.vm.is_connected()? {
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Commits the pending flow, rejecting the packet if the table cannot store it.
    fn admit_with_tracking(&mut self, pending: PendingFlow) -> Option<()> {
        self.flows.as_mut()?.commit(pending).then_some(())
    }

    /// Commits a pending flow for trackable packets; untracked packets proceed without one.
    fn admit_with_tracking_if_trackable(&mut self, pending: Option<PendingFlow>) -> Option<()> {
        match pending {
            Some(pending) => self.admit_with_tracking(pending),
            None => Some(()),
        }
    }

    /// Commits a pending flow when the return-direction rule is stateful.
    fn admit_with_tracking_if_stateful(
        &mut self,
        pending: Option<PendingFlow>,
        peer_addr: Ipv4Address,
        return_direction: Direction,
    ) -> Option<()> {
        if self.rules.is_stateful(peer_addr, return_direction) {
            self.admit_with_tracking_if_trackable(pending)
        } else {
            Some(())
        }
    }

    pub(crate) fn policy_get(&self) -> Policy {
        Policy {
            allow: self.allow.clone(),
            block: self.block.clone(),
            rule_count: self.rules.len(),
        }
    }

    pub(crate) fn policy_set(&mut self, allow: Vec<Rule>, block: Vec<Rule>) -> Policy {
        let allow = normalize_rules(allow);
        let block = normalize_rules(block);

        // Keep existing tracked flows when the normalized policy is unchanged
        if self.allow != allow || self.block != block {
            self.rules = Rules::new(self.host.gateway_ip, &allow, &block);
            self.allow = allow;
            self.block = block;
            self.flows = self.rules.has_stateful().then(FlowTable::new);
        }

        self.policy_get()
    }

    pub(crate) fn finalize(&mut self) -> Result<()> {
        self.host.finalize()
    }
}

fn normalize_rules(mut rules: Vec<Rule>) -> Vec<Rule> {
    rules.iter_mut().for_each(|rule| *rule = rule.normalized());
    rules.sort_by_key(ToString::to_string);
    rules.dedup();

    rules
}

#[cfg(test)]
mod tests {
    use crate::NetType;
    use crate::proxy::{Policy, Proxy};
    use crate::vm::VM;
    use mac_address::MacAddress;
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
    use serial_test::serial;
    use smoltcp::wire::{IpProtocol, Ipv4Address, Ipv4Packet, UdpPacket};
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::str::FromStr;

    #[tokio::test]
    #[serial]
    async fn test_blocking_takes_precedence() {
        let (mut proxy, _peer) = create_proxy(vec!["66.66.0.0/16"], vec!["66.66.0.0/16"]);
        let vm_ip = proxy.host.vm_ip;

        assert_eq!(proxy.rules.len(), 1);

        assert!(allowed_from_vm_ipv4(&mut proxy, vm_ip, "66.66.66.66").is_none());
    }

    #[tokio::test]
    #[serial]
    async fn test_longest_prefix_match_wins() {
        let (mut proxy, _peer) = create_proxy(vec!["33.33.33.33/32"], vec!["33.33.33.0/24"]);
        let vm_ip = proxy.host.vm_ip;

        assert_eq!(proxy.rules.len(), 2);

        assert!(allowed_from_vm_ipv4(&mut proxy, vm_ip, "33.33.33.32").is_none());
        assert!(allowed_from_vm_ipv4(&mut proxy, vm_ip, "33.33.33.33").is_some());
        assert!(allowed_from_vm_ipv4(&mut proxy, vm_ip, "33.33.33.34").is_none());
    }

    #[tokio::test]
    #[serial]
    async fn test_allow_host() {
        let (mut proxy, _peer) = create_proxy(vec!["@host"], vec!["0.0.0.0/0"]);
        let vm_ip = proxy.host.vm_ip;

        assert_eq!(proxy.rules.len(), 2);

        // Access to global IPs should be disallowed because of --block=0.0.0.0/0
        assert!(allowed_from_vm_ipv4(&mut proxy, vm_ip, "8.8.8.8").is_none());

        // Despite the above, access to host IP address should be possible because of --allow=@host
        let gateway_ip = proxy.host.gateway_ip.to_string();
        assert!(allowed_from_vm_ipv4(&mut proxy, vm_ip, &gateway_ip).is_some());
    }

    #[tokio::test]
    #[serial]
    async fn test_bare_default_block_applies_in_both_directions_in_stateful_mode() {
        let (mut proxy, _peer) = create_proxy(vec!["in 192.0.2.0/24"], vec!["0.0.0.0/0"]);
        let vm_ip = proxy.host.vm_ip;
        let fallback_peer = Ipv4Address::new(203, 0, 113, 1);
        let explicitly_allowed_peer = Ipv4Address::new(192, 0, 2, 1);

        let fallback_request = udp_packet(fallback_peer, 40_000, vm_ip, 1_234);
        let fallback_request = Ipv4Packet::new_checked(fallback_request.as_slice()).unwrap();
        assert!(proxy.allowed_from_host_ipv4(&fallback_request).is_none());

        let fallback_reply = udp_packet(vm_ip, 1_234, fallback_peer, 40_000);
        let fallback_reply = Ipv4Packet::new_checked(fallback_reply.as_slice()).unwrap();
        assert!(proxy.allowed_from_vm_ipv4(fallback_reply).is_none());

        let allowed_request = udp_packet(explicitly_allowed_peer, 40_000, vm_ip, 1_234);
        let allowed_request = Ipv4Packet::new_checked(allowed_request.as_slice()).unwrap();
        assert!(proxy.allowed_from_host_ipv4(&allowed_request).is_some());

        let allowed_reply = udp_packet(vm_ip, 1_234, explicitly_allowed_peer, 40_000);
        let allowed_reply = Ipv4Packet::new_checked(allowed_reply.as_slice()).unwrap();
        assert!(proxy.allowed_from_vm_ipv4(allowed_reply).is_some());
    }

    #[tokio::test]
    #[serial]
    async fn test_directional_egress_block_does_not_block_reply_to_unmatched_inbound_flow() {
        let (mut proxy, _peer) = create_proxy(vec![], vec!["out 203.0.113.0/24"]);
        let vm_ip = proxy.host.vm_ip;
        let peer = Ipv4Address::new(203, 0, 113, 1);

        let request = udp_packet(peer, 40_000, vm_ip, 1_234);
        let request = Ipv4Packet::new_checked(request.as_slice()).unwrap();
        assert!(proxy.allowed_from_host_ipv4(&request).is_some());

        let reply = udp_packet(vm_ip, 1_234, peer, 40_000);
        let reply = Ipv4Packet::new_checked(reply.as_slice()).unwrap();
        assert!(proxy.allowed_from_vm_ipv4(reply).is_some());
    }

    #[tokio::test]
    #[serial]
    async fn test_directional_ingress_block_does_not_block_reply_to_bare_outbound_allow() {
        let (mut proxy, _peer) = create_proxy(vec!["203.0.113.0/24"], vec!["in 203.0.113.0/24"]);
        let vm_ip = proxy.host.vm_ip;
        let peer = Ipv4Address::new(203, 0, 113, 1);

        let request = udp_packet(vm_ip, 1_234, peer, 40_000);
        let request = Ipv4Packet::new_checked(request.as_slice()).unwrap();
        assert!(proxy.allowed_from_vm_ipv4(request).is_some());

        let reply = udp_packet(peer, 40_000, vm_ip, 1_234);
        let reply = Ipv4Packet::new_checked(reply.as_slice()).unwrap();
        assert!(proxy.allowed_from_host_ipv4(&reply).is_some());
    }

    #[tokio::test]
    #[serial]
    async fn policy_replacement_normalizes_rules_and_preserves_flows_on_retry() {
        let (mut proxy, _peer) = create_proxy(
            vec!["out 10.1.2.3/8", "out 10.0.0.0/8"],
            vec!["in 0.0.0.0/0"],
        );
        let vm_ip = proxy.host.vm_ip;
        let peer = Ipv4Address::new(10, 1, 2, 3);
        let request = udp_packet(vm_ip, 40_000, peer, 1_234);
        let request = Ipv4Packet::new_checked(request.as_slice()).unwrap();
        assert!(proxy.allowed_from_vm_ipv4(request).is_some());

        // An equivalent policy must preserve the tracked permission for this reply
        let policy = proxy.policy_set(
            vec!["out 10.0.0.0/8".parse().unwrap()],
            vec!["in 0.0.0.0/0".parse().unwrap()],
        );
        assert_eq!(
            policy,
            Policy {
                allow: vec!["out 10.0.0.0/8".parse().unwrap()],
                block: vec!["in 0.0.0.0/0".parse().unwrap()],
                rule_count: 2,
            }
        );

        let reply = udp_packet(peer, 1_234, vm_ip, 40_000);
        let reply = Ipv4Packet::new_checked(reply.as_slice()).unwrap();
        assert!(proxy.allowed_from_host_ipv4(&reply).is_some());

        // A changed policy clears tracked flows, so the inbound block applies again
        proxy.policy_set(
            vec!["out 10.1.0.0/16".parse().unwrap()],
            vec!["in 0.0.0.0/0".parse().unwrap()],
        );
        assert!(proxy.allowed_from_host_ipv4(&reply).is_none());
    }

    fn create_proxy(allow: Vec<&str>, block: Vec<&str>) -> (Proxy, OwnedFd) {
        let (vm_fd, peer) = socketpair(
            AddressFamily::Unix,
            SockType::Datagram,
            None,
            SockFlag::empty(),
        )
        .unwrap();
        let (_, vm_ip, subnet) = crate::subnet_finder::find_available_subnet(29).unwrap();
        let vm_mac_address = MacAddress::from_str("02:00:00:00:00:02").unwrap();
        let network =
            crate::network::Network::new(NetType::Nat, subnet, &[(vm_mac_address, vm_ip)], &[])
                .unwrap();
        let proxy = Proxy::new(
            VM::new(vm_fd.as_raw_fd()).unwrap(),
            vm_mac_address,
            vm_ip,
            &network,
            allow
                .into_iter()
                .map(|value| value.parse().unwrap())
                .collect(),
            block
                .into_iter()
                .map(|value| value.parse().unwrap())
                .collect(),
        )
        .unwrap();

        (proxy, peer)
    }

    fn allowed_from_vm_ipv4(proxy: &mut Proxy, src: Ipv4Address, dst: &str) -> Option<()> {
        let mut buf = vec![0; 1500];

        let mut ipv4_pkt_mut = Ipv4Packet::new_unchecked(&mut buf[..]);
        ipv4_pkt_mut.set_src_addr(src);
        ipv4_pkt_mut.set_dst_addr(Ipv4Address::from_str(dst).unwrap());

        let ipv4_pkt = Ipv4Packet::new_unchecked(buf.as_slice());

        proxy.allowed_from_vm_ipv4(ipv4_pkt)
    }

    fn udp_packet(
        src_addr: Ipv4Address,
        src_port: u16,
        dst_addr: Ipv4Address,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut bytes = vec![0; 28];
        let mut ipv4 = Ipv4Packet::new_unchecked(bytes.as_mut_slice());
        ipv4.set_version(4);
        ipv4.set_header_len(20);
        ipv4.set_total_len(28);
        ipv4.set_next_header(IpProtocol::Udp);
        ipv4.set_src_addr(src_addr);
        ipv4.set_dst_addr(dst_addr);

        let mut udp = UdpPacket::new_unchecked(ipv4.payload_mut());
        udp.set_src_port(src_port);
        udp.set_dst_port(dst_port);
        udp.set_len(8);
        bytes
    }
}
