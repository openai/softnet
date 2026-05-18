use crate::dhcp_snooper::Lease;
use anyhow::{Context, Result, anyhow};
use dhcproto::Decodable;
use dhcproto::v4::{DhcpOption, MessageType, Opcode, OptionCode};
use smoltcp::wire::{
    EthernetFrame, EthernetProtocol, IpProtocol, Ipv4Address, Ipv4Packet, UdpPacket,
};
use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::time::{Duration, Instant};

const TABLE_PRINT_INTERVAL: Duration = Duration::from_secs(5);

unsafe extern "C" {
    fn pcap_get_selectable_fd(pcap: *mut libc::c_void) -> libc::c_int;
}

#[derive(Default)]
pub struct DhcpSnooperGlobal {
    pcap_capture: Option<pcap::Capture<pcap::Active>>,
    pcap_fd: Option<RawFd>,
    leases_by_mac: HashMap<[u8; 6], Lease>,
    uncertainty_duration: Duration,
    last_table_print: Option<Instant>,
}

impl DhcpSnooperGlobal {
    pub fn new(gateway_interface_name: &str, uncertainty_duration: Duration) -> Result<Self> {
        // Start capturing packets on bridge interface in promiscuous mode.
        let mut pcap_capture = pcap::Capture::from_device(gateway_interface_name)?
            .promisc(true)
            .timeout(1)
            .immediate_mode(true)
            .open()?;

        // Capture packets using a filter to avoid wasting CPU cycles in user-space.
        pcap_capture
            .filter("udp and (port 67 or port 68)", true)
            .context("failed to install DHCP pcap filter")?;

        // Prepare packet capture for event-driven consumption.
        let pcap_capture = pcap_capture.setnonblock()?;
        let pcap_fd = unsafe { pcap_get_selectable_fd(pcap_capture.as_ptr().cast()) };
        if pcap_fd == -1 {
            return Err(anyhow!("failed to call pcap_get_selectable_fd(3)"));
        }

        Ok(DhcpSnooperGlobal {
            pcap_capture: Some(pcap_capture),
            pcap_fd: Some(pcap_fd),
            uncertainty_duration,
            ..Default::default()
        })
    }

    pub fn disabled(uncertainty_duration: Duration) -> Self {
        DhcpSnooperGlobal {
            uncertainty_duration,
            ..Default::default()
        }
    }

    pub fn pcap_raw_fd(&self) -> Option<RawFd> {
        self.pcap_fd
    }

    pub fn read_pcap(&mut self, mut handle_packet: impl FnMut(&mut Self, &[u8])) -> Result<()> {
        let Some(mut pcap_capture) = self.pcap_capture.take() else {
            return Ok(());
        };

        let result = loop {
            match pcap_capture.next_packet() {
                Ok(packet) => handle_packet(self, packet.data),
                Err(pcap::Error::TimeoutExpired) => break Ok(()),
                Err(err) => break Err(err.into()),
            }
        };

        self.pcap_capture = Some(pcap_capture);
        result
    }

    pub fn register_ethernet_packet(&mut self, packet: &[u8]) {
        Self::register_ethernet_packet_with(
            &mut self.leases_by_mac,
            self.uncertainty_duration,
            packet,
        );
    }

    fn register_ethernet_packet_with(
        leases_by_mac: &mut HashMap<[u8; 6], Lease>,
        uncertainty_duration: Duration,
        packet: &[u8],
    ) {
        let Some(dhcp_packet) = Self::dhcp_payload(packet) else {
            return;
        };

        let mut decoder = dhcproto::v4::Decoder::new(dhcp_packet);
        let message = match dhcproto::v4::Message::decode(&mut decoder) {
            Ok(message) => message,
            Err(_) => return,
        };

        println!("{message}");

        let Some(mac) = Self::message_mac(&message) else {
            return;
        };

        match message.opts().msg_type() {
            Some(MessageType::Ack) => {
                let lease_time = match message.opts().get(OptionCode::AddressLeaseTime) {
                    Some(DhcpOption::AddressLeaseTime(lease_time)) => *lease_time,
                    _ => 600,
                };
                let mut lease_duration = Duration::from_secs(lease_time as u64);
                lease_duration = lease_duration.saturating_sub(uncertainty_duration);

                leases_by_mac.insert(
                    mac,
                    Lease::new(message.yiaddr(), lease_duration, Default::default()),
                );

                println!(
                    "DHCP global lease learned: {} -> {}",
                    Self::format_mac(&mac),
                    message.yiaddr()
                );
            }
            Some(MessageType::Nak) => {
                leases_by_mac.remove(&mac);
                println!("DHCP global lease removed: {}", Self::format_mac(&mac));
            }
            _ => {}
        }
    }

    pub fn print_table_periodically(&mut self) {
        let now = Instant::now();
        if self
            .last_table_print
            .is_some_and(|last_print| now.duration_since(last_print) < TABLE_PRINT_INTERVAL)
        {
            return;
        }
        self.last_table_print = Some(now);

        self.print_table();
    }

    pub fn valid_ip_for_mac(&self, mac: &[u8; 6], ip: Ipv4Address) -> bool {
        self.leases_by_mac
            .get(mac)
            .is_some_and(|lease| lease.valid_ip_source(ip))
    }

    fn print_table(&self) {
        if self.leases_by_mac.is_empty() {
            println!("DHCP global leases: <empty>");
            return;
        }

        println!("DHCP global leases:");
        for (mac, lease) in &self.leases_by_mac {
            let state = if lease.valid() { "valid" } else { "expired" };
            println!(
                "  {} -> {} ({state})",
                Self::format_mac(mac),
                lease.address()
            );
        }
    }

    fn dhcp_payload(packet: &[u8]) -> Option<&[u8]> {
        let frame = EthernetFrame::new_checked(packet).ok()?;
        if frame.ethertype() != EthernetProtocol::Ipv4 {
            return None;
        }

        let ipv4_packet = Ipv4Packet::new_checked(frame.payload()).ok()?;
        if ipv4_packet.next_header() != IpProtocol::Udp {
            return None;
        }

        let udp_packet = UdpPacket::new_checked(ipv4_packet.payload()).ok()?;
        if !matches!(udp_packet.src_port(), 67 | 68) && !matches!(udp_packet.dst_port(), 67 | 68) {
            return None;
        }

        Some(udp_packet.payload())
    }

    fn message_mac(message: &dhcproto::v4::Message) -> Option<[u8; 6]> {
        if message.opcode() != Opcode::BootReply {
            return None;
        }

        message.chaddr().try_into().ok()
    }

    fn format_mac(mac: &[u8; 6]) -> String {
        mac.iter()
            .map(|octet| format!("{octet:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}
