use anyhow::Result;
use dhcproto::v4::{
    CLIENT_PORT, DhcpOption, Flags, HType, Message, MessageType, Opcode, OptionCode, SERVER_PORT,
};
use dhcproto::{Decodable, Encodable};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    ETHERNET_HEADER_LEN, EthernetAddress, EthernetFrame, EthernetProtocol, IpAddress, IpProtocol,
    Ipv4Address, Ipv4Packet, Ipv4Repr, UDP_HEADER_LEN, UdpPacket, UdpRepr,
};

pub(crate) const DHCP_SERVER_MAC: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 1]);

pub(crate) struct DhcpServer {
    vm_mac: EthernetAddress,
    vm_ip: Ipv4Address,
    subnet_mask: Ipv4Address,
    gateway_ip: Ipv4Address,
}

impl DhcpServer {
    /// Creates a DHCP server for the VM's reserved IPv4 configuration.
    pub fn new(
        vm_mac: EthernetAddress,
        vm_ip: Ipv4Address,
        subnet_mask: Ipv4Address,
        gateway_ip: Ipv4Address,
    ) -> Self {
        Self {
            vm_mac,
            vm_ip,
            subnet_mask,
            gateway_ip,
        }
    }

    /// Returns a reply for a request sent to the DHCP server port.
    pub fn receive_vm(
        &self,
        ip: &Ipv4Packet<&[u8]>,
        udp: &UdpPacket<&[u8]>,
    ) -> Result<Option<Vec<u8>>> {
        // Accept only intact DHCP client datagrams with valid checksums
        if udp.src_port() != CLIENT_PORT
            || !ip.verify_checksum()
            || ip.more_frags()
            || ip.frag_offset() != 0
            || UdpRepr::parse(
                udp,
                &IpAddress::Ipv4(ip.src_addr()),
                &IpAddress::Ipv4(ip.dst_addr()),
                &ChecksumCapabilities::default(),
            )
            .is_err()
        {
            return Ok(None);
        }

        // Only accept broadcasts or requests addressed to our gateway
        if !(ip.dst_addr().is_broadcast() || ip.dst_addr() == self.gateway_ip) {
            return Ok(None);
        }

        // Decode the DHCP request
        let Ok(request) = Message::from_bytes(udp.payload()) else {
            return Ok(None);
        };

        // Allow REQUESTs from an obsolete address so the VM can receive a NAK
        if request.opts().msg_type() != Some(MessageType::Request)
            && !ip.src_addr().is_unspecified()
            && self.vm_ip != ip.src_addr()
        {
            return Ok(None);
        }

        // Build a reply if the request is supported
        if let Some(reply) = self.receive(&request) {
            // Broadcast NAKs and requested broadcasts; otherwise unicast to the VM
            let (destination_mac, destination_ip) =
                if reply.opts().msg_type() == Some(MessageType::Nak) || request.flags().broadcast()
                {
                    (EthernetAddress::BROADCAST, Ipv4Address::BROADCAST)
                } else if !request.ciaddr().is_unspecified() {
                    (self.vm_mac, request.ciaddr())
                } else {
                    (self.vm_mac, reply.yiaddr())
                };

            // Encode the reply for delivery to the VM
            let packet = encode_packet(
                &reply,
                DHCP_SERVER_MAC,
                destination_mac,
                self.gateway_ip,
                destination_ip,
                SERVER_PORT,
                CLIENT_PORT,
            )?;
            return Ok(Some(packet));
        }

        Ok(None)
    }

    /// Handles a DHCP request from the attached VM.
    fn receive(&self, request: &Message) -> Option<Message> {
        // Only accept direct Ethernet requests from the attached VM
        if request.opcode() != Opcode::BootRequest
            || request.htype() != HType::Eth
            || request.hlen() != self.vm_mac.0.len() as u8
            || request.chaddr() != self.vm_mac.0
            || !request.giaddr().is_unspecified()
        {
            return None;
        }

        // Ignore requests that select another DHCP server
        let server_id = match request.opts().get(OptionCode::ServerIdentifier) {
            Some(DhcpOption::ServerIdentifier(address)) => Some(*address),
            _ => None,
        };
        if server_id.is_some_and(|address| address != self.gateway_ip) {
            return None;
        }

        // Read the requested address, if supplied
        let requested_ip = match request.opts().get(OptionCode::RequestedIpAddress) {
            Some(DhcpOption::RequestedIpAddress(address)) => Some(*address),
            _ => None,
        };

        // Offer the reserved address or validate a request for it
        match request.opts().msg_type()? {
            MessageType::Discover if request.ciaddr().is_unspecified() && server_id.is_none() => {
                Some(self.address_reply(request, MessageType::Offer))
            }
            MessageType::Request => {
                // Use option 50 for SELECTING/INIT-REBOOT and ciaddr for RENEWING/REBINDING
                let address = match (server_id, requested_ip, request.ciaddr().is_unspecified()) {
                    (_, Some(address), true) => address,
                    (None, None, false) => request.ciaddr(),
                    _ => return None,
                };

                // Reject requests for any address other than the VM's reservation
                if address != self.vm_ip {
                    return Some(self.reply(request, MessageType::Nak));
                }

                // Acknowledge the reserved address
                Some(self.address_reply(request, MessageType::Ack))
            }
            _ => None,
        }
    }

    /// Builds an OFFER or ACK with the VM's reserved address and network configuration.
    fn address_reply(&self, request: &Message, message_type: MessageType) -> Message {
        // Include the reserved address and network configuration with an infinite lease
        let mut reply = self.reply(request, message_type);
        reply.set_yiaddr(self.vm_ip);
        let options = reply.opts_mut();
        options.insert(DhcpOption::SubnetMask(self.subnet_mask));
        options.insert(DhcpOption::Router(vec![self.gateway_ip]));
        options.insert(DhcpOption::DomainNameServer(vec![self.gateway_ip]));
        options.insert(DhcpOption::AddressLeaseTime(u32::MAX));

        reply
    }

    /// Builds a DHCP reply with the request's transaction and client identifiers.
    fn reply(&self, request: &Message, message_type: MessageType) -> Message {
        // Create a reply for the same client and transaction
        let nak = message_type == MessageType::Nak;
        let mut reply = Message::default();
        reply
            .set_xid(request.xid())
            .set_chaddr(request.chaddr())
            .set_opcode(Opcode::BootReply);

        // Broadcast NAKs; otherwise retain the client's address and flags
        if nak {
            reply.set_flags(Flags::default().set_broadcast());
        } else {
            reply
                .set_ciaddr(request.ciaddr())
                .set_flags(request.flags());
        }

        // Identify the reply type and this DHCP server
        let options = reply.opts_mut();
        options.insert(DhcpOption::MessageType(message_type));
        options.insert(DhcpOption::ServerIdentifier(self.gateway_ip));

        // RFC 6842 requires echoing the client's identifier in every reply
        if let Some(identifier) = request.opts().get(OptionCode::ClientIdentifier) {
            options.insert(identifier.clone());
        }

        reply
    }
}

/// Encodes a DHCP message in an Ethernet frame with IPv4 and UDP headers.
fn encode_packet(
    message: &Message,
    source_mac: EthernetAddress,
    destination_mac: EthernetAddress,
    source_ip: Ipv4Address,
    destination_ip: Ipv4Address,
    source_port: u16,
    destination_port: u16,
) -> Result<Vec<u8>> {
    // Pad the encoded message to the minimum BOOTP size, including short NAKs
    let mut payload = message.to_vec()?;
    payload.resize(payload.len().max(dhcproto::v4::MIN_PACKET_SIZE), 0);

    // Allocate space for Ethernet, IPv4, UDP, and the DHCP payload
    let ip_repr = Ipv4Repr {
        src_addr: source_ip,
        dst_addr: destination_ip,
        next_header: IpProtocol::Udp,
        payload_len: UDP_HEADER_LEN + payload.len(),
        hop_limit: 64,
    };
    let mut bytes = vec![0; ETHERNET_HEADER_LEN + ip_repr.buffer_len() + ip_repr.payload_len];

    // Write the Ethernet header
    let mut ethernet = EthernetFrame::new_unchecked(bytes.as_mut_slice());
    ethernet.set_src_addr(source_mac);
    ethernet.set_dst_addr(destination_mac);
    ethernet.set_ethertype(EthernetProtocol::Ipv4);

    // Write the IPv4 header and checksum
    let mut ip = Ipv4Packet::new_unchecked(ethernet.payload_mut());
    ip_repr.emit(&mut ip, &ChecksumCapabilities::default());

    // Write the UDP header, DHCP payload, and checksum
    let mut udp = UdpPacket::new_unchecked(ip.payload_mut());
    UdpRepr {
        src_port: source_port,
        dst_port: destination_port,
    }
    .emit(
        &mut udp,
        &IpAddress::Ipv4(source_ip),
        &IpAddress::Ipv4(destination_ip),
        payload.len(),
        |buffer| buffer.copy_from_slice(&payload),
        &ChecksumCapabilities::default(),
    );

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{DHCP_SERVER_MAC, DhcpServer, encode_packet};
    use dhcproto::Decodable;
    use dhcproto::v4::{
        CLIENT_PORT, DhcpOption, Message, MessageType, Opcode, OptionCode, SERVER_PORT,
    };
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{
        EthernetAddress, EthernetFrame, Ipv4Address, Ipv4Packet, Ipv4Repr, UdpPacket, UdpRepr,
    };

    const VM: EthernetAddress = EthernetAddress([2, 0, 0, 0, 0, 2]);
    const ADDRESS: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const GATEWAY: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const MASK: Ipv4Address = Ipv4Address::new(255, 255, 255, 252);
    const CLIENT_ID: &[u8] = &[1, 2, 0, 0, 0, 0, 2];

    #[test]
    fn assigns_reserved_address() {
        // Create a server and a client request
        let dhcp = DhcpServer::new(VM, ADDRESS, MASK, GATEWAY);
        let mut message = request(MessageType::Discover);

        // Discover the reserved address
        let (offer, destination) = exchange(&dhcp, &message, Ipv4Address::BROADCAST);
        assert_eq!(offer.opts().msg_type(), Some(MessageType::Offer));
        assert_eq!(offer.yiaddr(), ADDRESS);
        assert_eq!(destination, ADDRESS);

        // Request the offered address
        message
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Request));
        message
            .opts_mut()
            .insert(DhcpOption::RequestedIpAddress(offer.yiaddr()));
        message
            .opts_mut()
            .insert(DhcpOption::ServerIdentifier(GATEWAY));
        let (ack, destination) = exchange(&dhcp, &message, Ipv4Address::BROADCAST);

        // Check the address and configuration in the acknowledgement
        assert_eq!(ack.opcode(), Opcode::BootReply);
        assert_eq!(ack.opts().msg_type(), Some(MessageType::Ack));
        assert_eq!(ack.xid(), message.xid());
        assert_eq!(ack.chaddr(), VM.0);
        assert_eq!(ack.yiaddr(), ADDRESS);
        assert_eq!(destination, ADDRESS);
        for option in [
            DhcpOption::ServerIdentifier(GATEWAY),
            DhcpOption::SubnetMask(MASK),
            DhcpOption::Router(vec![GATEWAY]),
            DhcpOption::DomainNameServer(vec![GATEWAY]),
            DhcpOption::AddressLeaseTime(u32::MAX),
            DhcpOption::ClientIdentifier(CLIENT_ID.to_vec()),
        ] {
            assert_eq!(ack.opts().get(OptionCode::from(&option)), Some(&option));
        }
    }

    #[test]
    fn renews_reserved_address_and_rejects_stale_address() {
        // Renew the reserved address
        let dhcp = DhcpServer::new(VM, ADDRESS, MASK, GATEWAY);
        let mut message = request(MessageType::Request);
        message.set_ciaddr(ADDRESS);
        let (ack, destination) = exchange(&dhcp, &message, GATEWAY);
        assert_eq!(ack.opts().msg_type(), Some(MessageType::Ack));
        assert_eq!(ack.yiaddr(), ADDRESS);
        assert_eq!(destination, ADDRESS);

        // Broadcast a NAK when the client renews an old address
        message.set_ciaddr(Ipv4Address::new(192, 168, 2, 2));
        let (nak, destination) = exchange(&dhcp, &message, GATEWAY);
        assert_eq!(nak.opts().msg_type(), Some(MessageType::Nak));
        assert!(nak.yiaddr().is_unspecified());
        assert_eq!(destination, Ipv4Address::BROADCAST);
    }

    fn request(kind: MessageType) -> Message {
        let mut message = Message::default();
        message.set_xid(42).set_chaddr(&VM.0);
        message.opts_mut().insert(DhcpOption::MessageType(kind));
        message
            .opts_mut()
            .insert(DhcpOption::ClientIdentifier(CLIENT_ID.to_vec()));
        message
    }

    fn exchange(
        dhcp: &DhcpServer,
        request: &Message,
        destination: Ipv4Address,
    ) -> (Message, Ipv4Address) {
        // Encode the client request
        let frame = encode_packet(
            request,
            VM,
            EthernetAddress::BROADCAST,
            request.ciaddr(),
            destination,
            CLIENT_PORT,
            SERVER_PORT,
        )
        .unwrap();

        // Pass the packet to the DHCP server
        let ethernet = EthernetFrame::new_checked(frame.as_slice()).unwrap();
        let ip = Ipv4Packet::new_checked(ethernet.payload()).unwrap();
        let udp = UdpPacket::new_unchecked(ip.payload());
        let frame = dhcp
            .receive_vm(&ip, &udp)
            .unwrap()
            .expect("expected a DHCP reply");

        // Decode and validate the reply
        let ethernet = EthernetFrame::new_checked(frame.as_slice()).unwrap();
        let ip = Ipv4Packet::new_unchecked(ethernet.payload());
        Ipv4Repr::parse(&ip, &ChecksumCapabilities::default()).unwrap();
        let udp = UdpPacket::new_unchecked(ip.payload());
        UdpRepr::parse(
            &udp,
            &ip.src_addr().into(),
            &ip.dst_addr().into(),
            &ChecksumCapabilities::default(),
        )
        .unwrap();
        assert_eq!(ethernet.src_addr(), DHCP_SERVER_MAC);
        assert_eq!(ip.src_addr(), GATEWAY);
        (Message::from_bytes(udp.payload()).unwrap(), ip.dst_addr())
    }
}
