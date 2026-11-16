use dhcproto::v4::{CLIENT_PORT, SERVER_PORT};
use smoltcp::wire::{Icmpv4Message, Icmpv4Packet, IpProtocol, Ipv4Packet, TcpPacket, UdpPacket};
use std::net::Ipv4Addr;

pub(super) enum Translation {
    FromVm { source: Ipv4Addr },
    ToVm { destination: Ipv4Addr },
}

/// Translates one complete IP datagram and returns its length without link-layer padding.
pub(super) fn translate(bytes: &mut [u8], translation: Translation) -> Option<usize> {
    let mut ip = Ipv4Packet::new_checked(bytes).ok()?;
    if ip.version() != 4
        || ip.header_len() != 20
        || ip.hop_limit() == 0
        || ip.as_ref()[6] & 0x80 != 0 // reserved IPv4 flag
        || ip.more_frags()
        || ip.frag_offset() != 0
    {
        return None;
    }

    let src = ip.src_addr();
    let dst = ip.dst_addr();
    let (translated_src, translated_dst, verify) = match translation {
        Translation::FromVm { source } => (source, dst, false),
        Translation::ToVm { destination } => (src, destination, true),
    };

    // The VM may leave partial checksums for its NIC, while tunneled packets are already on the wire
    if verify && !ip.verify_checksum() {
        return None;
    }

    let len = usize::from(ip.total_len());
    let protocol = ip.next_header();
    let payload = ip.payload_mut();
    match protocol {
        IpProtocol::Tcp => {
            let mut tcp = TcpPacket::new_checked(payload).ok()?;
            if tcp.src_port() == 0
                || tcp.dst_port() == 0
                || (verify && !tcp.verify_checksum(&src.into(), &dst.into()))
            {
                return None;
            }
            tcp.fill_checksum(&translated_src.into(), &translated_dst.into());
        }
        IpProtocol::Udp => {
            let payload_len = payload.len();
            let mut udp = UdpPacket::new_checked(payload).ok()?;

            // Keep DHCP requests local and reject remote DHCP server replies
            let dhcp = match translation {
                Translation::FromVm { .. } => udp.dst_port() == SERVER_PORT,
                Translation::ToVm { .. } => {
                    udp.src_port() == SERVER_PORT && udp.dst_port() == CLIENT_PORT
                }
            };

            if usize::from(udp.len()) != payload_len
                || udp.src_port() == 0
                || udp.dst_port() == 0
                || dhcp
                || (verify && !udp.verify_checksum(&src.into(), &dst.into()))
            {
                return None;
            }
            // A zero IPv4 UDP checksum explicitly omits transport integrity
            if udp.checksum() != 0 {
                udp.fill_checksum(&translated_src.into(), &translated_dst.into());
            }
        }
        IpProtocol::Icmp => {
            let mut icmp = Icmpv4Packet::new_checked(payload).ok()?;
            if !matches!(
                icmp.msg_type(),
                Icmpv4Message::EchoRequest | Icmpv4Message::EchoReply
            ) || icmp.msg_code() != 0
                || (verify && !icmp.verify_checksum())
            {
                return None;
            }
            if !verify {
                icmp.fill_checksum();
            }
        }
        _ => return None,
    }

    ip.set_src_addr(translated_src);
    ip.set_dst_addr(translated_dst);
    ip.fill_checksum();
    Some(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;

    const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 168, 64, 2);
    const OVERLAY: Ipv4Addr = Ipv4Addr::new(10, 77, 1, 2);
    const PEER: Ipv4Addr = Ipv4Addr::new(10, 77, 2, 2);
    const PAYLOAD: &[u8] = b"hello";

    fn datagram(src: Ipv4Addr, dst: Ipv4Addr, protocol: IpProtocol) -> Vec<u8> {
        let builder = PacketBuilder::ipv4(src.octets(), dst.octets(), 64);
        let mut bytes = Vec::new();
        match protocol {
            IpProtocol::Tcp => builder.tcp(9234, 8080, 1, 1024).write(&mut bytes, PAYLOAD),
            IpProtocol::Udp => builder.udp(9234, 8080).write(&mut bytes, PAYLOAD),
            IpProtocol::Icmp => builder.icmpv4_echo_request(7, 1).write(&mut bytes, PAYLOAD),
            _ => unreachable!(),
        }
        .unwrap();
        bytes
    }

    #[test]
    fn translates_complete_packets_in_both_directions() {
        for protocol in [IpProtocol::Tcp, IpProtocol::Udp, IpProtocol::Icmp] {
            let mut outbound = datagram(LOCAL, PEER, protocol);
            let len = outbound.len();
            outbound.extend_from_slice(&[0xcc; 8]);
            assert_eq!(
                translate(&mut outbound, Translation::FromVm { source: OVERLAY }),
                Some(len)
            );
            assert_eq!(&outbound[..len], datagram(OVERLAY, PEER, protocol));
            assert_eq!(&outbound[len..], &[0xcc; 8]);

            let mut inbound = datagram(PEER, OVERLAY, protocol);
            assert_eq!(
                translate(&mut inbound, Translation::ToVm { destination: LOCAL }),
                Some(len)
            );
            assert_eq!(inbound, datagram(PEER, LOCAL, protocol));
        }
    }

    #[test]
    fn completes_guest_checksums_and_rejects_damaged_tunneled_packets() {
        for (protocol, checksum_offset) in [
            (IpProtocol::Tcp, 16),
            (IpProtocol::Udp, 6),
            (IpProtocol::Icmp, 2),
        ] {
            let mut outbound = datagram(LOCAL, PEER, protocol);
            outbound[10..12].fill(0);
            outbound[20 + checksum_offset..22 + checksum_offset].copy_from_slice(&[0x12, 0x34]);
            assert!(translate(&mut outbound, Translation::FromVm { source: OVERLAY }).is_some());
            assert_eq!(outbound, datagram(OVERLAY, PEER, protocol));

            let mut inbound = datagram(PEER, OVERLAY, protocol);
            *inbound.last_mut().unwrap() ^= 1;
            assert!(translate(&mut inbound, Translation::ToVm { destination: LOCAL }).is_none());
        }
    }

    #[test]
    fn keeps_dhcp_on_the_local_network() {
        for (source, destination, outbound, inbound) in [
            (68, 67, false, true),
            (8080, 67, false, true),
            (67, 68, true, false),
            (67, 8080, true, true),
            (8080, 68, true, true),
        ] {
            let mut bytes = Vec::new();
            PacketBuilder::ipv4(PEER.octets(), OVERLAY.octets(), 64)
                .udp(source, destination)
                .write(&mut bytes, PAYLOAD)
                .unwrap();

            assert_eq!(
                translate(&mut bytes.clone(), Translation::FromVm { source: LOCAL }).is_some(),
                outbound,
            );
            assert_eq!(
                translate(&mut bytes, Translation::ToVm { destination: LOCAL }).is_some(),
                inbound,
            );
        }
    }

    #[test]
    fn preserves_the_optional_zero_udp_checksum() {
        let mut bytes = datagram(PEER, OVERLAY, IpProtocol::Udp);
        bytes[26..28].fill(0);
        assert!(translate(&mut bytes, Translation::ToVm { destination: LOCAL }).is_some());
        assert_eq!(UdpPacket::new_checked(&bytes[20..]).unwrap().checksum(), 0);
    }

    #[test]
    fn rejects_malformed_or_unsupported_datagrams() {
        // These single-byte mutations exercise the boundaries used by port filtering and rewriting
        for (protocol, offset, value) in [
            (IpProtocol::Tcp, 0, 0x65), // wrong IP version
            (IpProtocol::Tcp, 0, 0x46), // IP options
            (IpProtocol::Tcp, 6, 0x80), // reserved IPv4 flag
            (IpProtocol::Tcp, 8, 0),    // invalid TTL
            (IpProtocol::Tcp, 6, 0x20), // first fragment
            (IpProtocol::Tcp, 7, 1),    // subsequent fragment
            (IpProtocol::Tcp, 32, 0),   // invalid TCP header length
            (IpProtocol::Tcp, 9, 47),   // unsupported IP protocol
            (IpProtocol::Udp, 25, 8),   // unexpected trailing UDP payload
            (IpProtocol::Icmp, 20, 3),  // ICMP error with embedded original addresses
            (IpProtocol::Icmp, 21, 1),  // invalid echo code
        ] {
            let mut bytes = datagram(LOCAL, PEER, protocol);
            bytes[offset] = value;
            assert!(translate(&mut bytes, Translation::FromVm { source: OVERLAY }).is_none());
        }
        let mut bytes = datagram(LOCAL, PEER, IpProtocol::Udp);
        bytes.pop();
        assert!(translate(&mut bytes, Translation::FromVm { source: OVERLAY }).is_none());
    }
}
