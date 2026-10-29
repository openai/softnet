use anyhow::{Context, Result, bail, ensure};
use etherparse::PacketBuilder;
use hickory_server::net::{NetError, runtime::TokioTime, xfer::Protocol};
use hickory_server::proto::op::{DEFAULT_MAX_PAYLOAD_LEN, Header, MessageType, OpCode};
use hickory_server::proto::rr::{
    Name, RData, Record,
    rdata::{A, SOA},
};
use hickory_server::proto::serialize::binary::{BinEncoder, EncodedSize};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::store::in_memory::InMemoryZoneHandler;
use hickory_server::zone_handler::{AxfrPolicy, Catalog, MessageResponse, ZoneType};
use smoltcp::wire::{
    ETHERNET_HEADER_LEN, EthernetAddress, IPV4_HEADER_LEN, Ipv4Packet, UDP_HEADER_LEN, UdpPacket,
};
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};

/// DNS domain for VM names.
pub(crate) const DNS_DOMAIN: &str = "internal";

/// Standard DNS server port.
pub(crate) const DNS_PORT: u16 = 53;

pub(crate) struct DnsServer {
    domain: Name,
    catalog: Catalog,
}

#[derive(Clone)]
struct Response {
    bytes: Arc<OnceLock<Vec<u8>>>,
    max_payload: u16,
}

impl DnsServer {
    pub(crate) fn new(records: Vec<(Name, Ipv4Addr)>) -> Result<Self> {
        // Initialize the DNS zone
        let mut domain = Name::from_ascii(DNS_DOMAIN).expect("valid VM DNS domain");
        domain.set_fqdn(true);
        let mut zone: InMemoryZoneHandler =
            InMemoryZoneHandler::empty(domain.clone(), ZoneType::Primary, AxfrPolicy::Deny);
        ensure!(
            zone.upsert_mut(
                Record::from_rdata(
                    domain.clone(),
                    0,
                    RData::SOA(SOA::new(domain.clone(), domain.clone(), 0, 0, 0, 0, 0)),
                ),
                0,
            ),
            "failed to initialize the VM DNS zone"
        );

        let mut names = BTreeSet::new();

        for (name, address) in records {
            // Validate single-label VM names before checking for duplicates
            if name.is_fqdn() || name.num_labels() != 1 || name.is_wildcard() {
                bail!("invalid VM name {name}: expected a single DNS label");
            }

            if !names.insert(name.clone()) {
                bail!("VM name {name} is already in use");
            }

            // Register the VM name in the DNS zone without caching its address
            let name = name.append_domain(&domain).expect("valid VM DNS name");

            ensure!(
                zone.upsert_mut(Record::from_rdata(name, 0, RData::A(A(address))), 0),
                "failed to register a VM DNS name"
            );
        }

        let mut catalog = Catalog::new();
        catalog.upsert(domain.clone().into(), vec![Arc::new(zone)]);

        Ok(Self { domain, catalog })
    }

    /// Returns a copy of the served DNS domain.
    pub(crate) fn domain(&self) -> Name {
        self.domain.clone()
    }

    /// Answers queries for Softnet's DNS zone from a validated IPv4 UDP datagram.
    pub(crate) async fn respond(
        &self,
        source_mac: EthernetAddress,
        destination_mac: EthernetAddress,
        ip: &Ipv4Packet<&[u8]>,
        udp: &UdpPacket<&[u8]>,
        max_packet_size: usize,
    ) -> Result<Option<Vec<u8>>> {
        // Only inspect standard DNS queries
        let source = SocketAddr::from((ip.src_addr(), udp.src_port()));
        let Ok(request) = Request::from_bytes(udp.payload().to_vec(), source, Protocol::Udp) else {
            return Ok(None);
        };

        if request.metadata.message_type != MessageType::Query
            || request.metadata.op_code != OpCode::Query
        {
            return Ok(None);
        }

        // Handle only names within the DNS zone
        let Ok(info) = request.request_info() else {
            return Ok(None);
        };

        if self.catalog.find(info.query.name()).is_none() {
            return Ok(None);
        }

        // Keep replies within the client's limit and the VM's available frame size
        let Some(available) =
            max_packet_size.checked_sub(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN)
        else {
            return Ok(None);
        };
        let max_payload = usize::from(request.max_payload())
            .min(usize::from(DEFAULT_MAX_PAYLOAD_LEN))
            .min(available);

        if max_payload < Header::LEN {
            return Ok(None);
        }

        let response = Response {
            bytes: Arc::new(OnceLock::new()),
            max_payload: max_payload as u16,
        };

        // Resolve without opening a listener or sending the reply through the host network
        self.catalog
            .handle_request::<_, TokioTime>(&request, response.clone())
            .await;
        let payload = response
            .bytes
            .get()
            .context("failed to encode DNS response")?;

        // Swap the request's addresses and emit fresh IPv4 and UDP checksums
        let builder = PacketBuilder::ethernet2(destination_mac.0, source_mac.0)
            .ipv4(ip.dst_addr().octets(), ip.src_addr().octets(), 64)
            .udp(DNS_PORT, udp.src_port());

        let mut bytes = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut bytes, payload)?;

        Ok(Some(bytes))
    }
}

#[async_trait::async_trait]
impl ResponseHandler for Response {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError> {
        // Hickory truncates whole records and sets TC when the datagram limit is reached
        let mut bytes = Vec::new();
        let mut encoder = BinEncoder::new(&mut bytes);
        encoder.set_max_size(self.max_payload);
        let info = response.destructive_emit(&mut encoder)?;

        self.bytes
            .set(bytes)
            .map_err(|_| NetError::from("DNS response already encoded"))?;

        Ok(info)
    }
}
