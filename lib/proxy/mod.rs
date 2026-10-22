mod control;
mod exposed_port;
mod flows;
mod host;
mod rule;
mod rules;
mod vm;

use crate::dhcp_server::{DHCP_SERVER_MAC, DhcpServer};
use crate::host::Host;
use crate::host::NetType;
use crate::vm::VM;
use anyhow::{Context, Result, bail};
use control::{Control, normalize_rules};
pub use exposed_port::ExposedPort;
use flows::{FlowTable, PendingFlow};
use futures_util::future::OptionFuture;
use ipnet::Ipv4Net;
use mac_address::MacAddress;
pub use rule::{Direction, Rule, Target};
pub(crate) use rules::{PolicyDecision, Rules};
use smoltcp::wire::{EthernetAddress, EthernetFrame, Ipv4Address};
use std::os::unix::io::RawFd;
use std::time::Duration;
use tokio::time::{MissedTickBehavior, interval};
use vmnet::Batch;

pub struct Proxy {
    vm: VM,
    host: Host,
    vm_mac_address: smoltcp::wire::EthernetAddress,
    dhcp_server: DhcpServer,
    rules: Rules,
    control: Option<Control>,
    flows: Option<FlowTable>,
    enobufs_encountered: bool,
}

impl Proxy {
    /// Requires an entered Tokio runtime during construction.
    pub fn new(
        vm_fd: RawFd,
        vm_mac_address: MacAddress,
        vm_net_type: NetType,
        allow: Vec<Rule>,
        block: Vec<Rule>,
        exposed_ports: Vec<ExposedPort>,
        control_fd: Option<RawFd>,
    ) -> Result<Proxy> {
        // Ensure that VM's MAC address won't conflict with our DHCP server's MAC address
        let vm_mac_address = EthernetAddress(vm_mac_address.bytes());
        if vm_mac_address == DHCP_SERVER_MAC {
            bail!("VM MAC address {vm_mac_address} is reserved for the DHCP server");
        }

        let allow = normalize_rules(allow);
        let block = normalize_rules(block);

        let vm = VM::new(vm_fd)?;
        let mut host = Host::new(
            vm_net_type,
            vm_mac_address,
            !allow.contains(&Rule::Stateless(Target::Prefix(Ipv4Net::default()))),
        )?;
        let control = control_fd
            .map(|control_fd| {
                Control::new(control_fd, host.gateway_ip, allow.clone(), block.clone())
            })
            .transpose()?;

        let rules = Rules::new(host.gateway_ip, &allow, &block);

        // Any stateful rule enables flow inspection for the whole VM, including
        // traffic admitted through implicit global and gateway fallbacks
        let flows = rules.has_stateful().then(FlowTable::new);

        // vmnet owns the gateway (including ARP and DNS); the VM address is
        // reserved for this MAC for the lifetime of the attached interface.
        let dhcp_server = DhcpServer::new(
            vm_mac_address,
            host.vm_ip,
            host.subnet_mask,
            host.gateway_ip,
        );

        // Install port forwardings for the reserved VM's IP address
        for port in exposed_ports {
            host.port_forwarding_add_rule(port.external_port, host.vm_ip, port.internal_port)
                .context("failed to configure port forwarding")?;
        }

        Ok(Proxy {
            vm,
            host,
            vm_mac_address,
            dhcp_server,
            rules,
            control,
            flows,
            enobufs_encountered: false,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
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
                    let n = result?;

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
                            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(err) => return Err(err.into()),
                        }
                    }
                }

                result = self.host.read(&mut batch, &mut bufs) => {
                    let pktcnt = result?;

                    // Update the coarse time once the packet arrives
                    coarsetime::Instant::update();

                    for buf in batch.packet_sized_bufs(&bufs).take(pktcnt) {
                        if let Ok(pkt) = EthernetFrame::new_checked(buf) {
                            self.process_frame_from_host(&pkt)?;
                        }

                        tokio::task::consume_budget().await;
                    }
                }

                // Skip this branch when no control socket is present
                Some(result) = OptionFuture::from(
                    self.control
                        .as_mut()
                        .map(|control| control.service(&mut self.rules))
                ) => {
                    match result {
                        Ok(Some(true)) => {
                            // Invalidate tracked flows whenever the policy changes
                            self.flows = self.rules.has_stateful().then(FlowTable::new);
                        }
                        Ok(Some(false)) => {
                            // Policy unchanged; keep tracked flows intact
                        }
                        Ok(None) => {
                            // Control stream reached EOF; stop polling it
                            self.control = None;
                        }
                        Err(err) => {
                            // Control service failed; stop polling it
                            self.control = None;

                            log::warn!("disabling Softnet control socket: {err:#}");
                        }
                    }

                    coarsetime::Instant::update();
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
}

#[cfg(test)]
mod tests {
    use crate::NetType;
    use crate::proxy::Proxy;
    use mac_address::MacAddress;
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
    use serial_test::serial;
    use smoltcp::wire::{IpProtocol, Ipv4Address, Ipv4Packet, UdpPacket};
    use std::os::fd::AsRawFd;
    use std::str::FromStr;

    #[tokio::test]
    #[serial]
    async fn test_blocking_takes_precedence() {
        let mut proxy = create_proxy(vec!["66.66.0.0/16"], vec!["66.66.0.0/16"]);
        let vm_ip = proxy.host.vm_ip;

        assert_eq!(proxy.rules.len(), 1);

        assert!(allowed_from_vm_ipv4(&mut proxy, vm_ip, "66.66.66.66").is_none());
    }

    #[tokio::test]
    #[serial]
    async fn test_longest_prefix_match_wins() {
        let mut proxy = create_proxy(vec!["33.33.33.33/32"], vec!["33.33.33.0/24"]);
        let vm_ip = proxy.host.vm_ip;

        assert_eq!(proxy.rules.len(), 2);

        assert!(allowed_from_vm_ipv4(&mut proxy, vm_ip, "33.33.33.32").is_none());
        assert!(allowed_from_vm_ipv4(&mut proxy, vm_ip, "33.33.33.33").is_some());
        assert!(allowed_from_vm_ipv4(&mut proxy, vm_ip, "33.33.33.34").is_none());
    }

    #[tokio::test]
    #[serial]
    async fn test_allow_host() {
        let mut proxy = create_proxy(vec!["@host"], vec!["0.0.0.0/0"]);
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
        let mut proxy = create_proxy(vec!["in 192.0.2.0/24"], vec!["0.0.0.0/0"]);
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
        let mut proxy = create_proxy(vec![], vec!["out 203.0.113.0/24"]);
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
        let mut proxy = create_proxy(vec!["203.0.113.0/24"], vec!["in 203.0.113.0/24"]);
        let vm_ip = proxy.host.vm_ip;
        let peer = Ipv4Address::new(203, 0, 113, 1);

        let request = udp_packet(vm_ip, 1_234, peer, 40_000);
        let request = Ipv4Packet::new_checked(request.as_slice()).unwrap();
        assert!(proxy.allowed_from_vm_ipv4(request).is_some());

        let reply = udp_packet(peer, 40_000, vm_ip, 1_234);
        let reply = Ipv4Packet::new_checked(reply.as_slice()).unwrap();
        assert!(proxy.allowed_from_host_ipv4(&reply).is_some());
    }

    fn create_proxy(allow: Vec<&str>, block: Vec<&str>) -> Proxy {
        let (vm_fd, _) = socketpair(
            AddressFamily::Unix,
            SockType::Datagram,
            None,
            SockFlag::empty(),
        )
        .unwrap();
        let vm_fd = Box::leak(Box::new(vm_fd));

        Proxy::new(
            vm_fd.as_raw_fd(),
            MacAddress::from_str("02:00:00:00:00:02").unwrap(),
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
        .unwrap()
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
