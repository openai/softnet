use smoltcp::wire::UdpPacket;

pub(crate) trait UdpPacketHelper {
    const DNS_PORT: u16 = 53;
    const BOOTPS_PORT: u16 = 67;
    const BOOTPC_PORT: u16 = 68;

    fn is_dns_request(&self) -> bool;

    fn is_dhcp_request(&self) -> bool;
    fn is_dhcp_response(&self) -> bool;
}

impl UdpPacketHelper for UdpPacket<&[u8]> {
    fn is_dns_request(&self) -> bool {
        self.dst_port() == Self::DNS_PORT
    }

    fn is_dhcp_request(&self) -> bool {
        self.src_port() == Self::BOOTPC_PORT && self.dst_port() == Self::BOOTPS_PORT
    }

    fn is_dhcp_response(&self) -> bool {
        self.src_port() == Self::BOOTPS_PORT && self.dst_port() == Self::BOOTPC_PORT
    }
}

#[cfg(test)]
mod tests {
    use super::UdpPacketHelper;
    use smoltcp::wire::UdpPacket;

    #[test]
    fn test_is_dhcp_request_requires_both_standard_ports() {
        assert!(is_dhcp_request(68, 67));
        assert!(!is_dhcp_request(68, 9999));
        assert!(!is_dhcp_request(9999, 67));
    }

    #[test]
    fn test_is_dhcp_response_requires_both_standard_ports() {
        assert!(is_dhcp_response(67, 68));
        assert!(!is_dhcp_response(67, 9999));
        assert!(!is_dhcp_response(9999, 68));
    }

    fn is_dhcp_request(src_port: u16, dst_port: u16) -> bool {
        let buffer = udp_packet_buffer(src_port, dst_port);
        let udp_pkt = UdpPacket::new_unchecked(&buffer[..]);
        udp_pkt.is_dhcp_request()
    }

    fn is_dhcp_response(src_port: u16, dst_port: u16) -> bool {
        let buffer = udp_packet_buffer(src_port, dst_port);
        let udp_pkt = UdpPacket::new_unchecked(&buffer[..]);
        udp_pkt.is_dhcp_response()
    }

    fn udp_packet_buffer(src_port: u16, dst_port: u16) -> [u8; 8] {
        let mut buffer = [0; 8];
        let mut udp_pkt = UdpPacket::new_unchecked(&mut buffer[..]);
        udp_pkt.set_src_port(src_port);
        udp_pkt.set_dst_port(dst_port);
        buffer
    }
}
