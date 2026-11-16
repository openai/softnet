mod config;
mod nat;

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use boringtun::{
    noise::{Tunn, TunnResult, errors::WireGuardError},
    x25519::{PublicKey, StaticSecret},
};
pub(crate) use config::Config;
use ipnet::Ipv4Net;
use nat::{Translation, translate};
use serde::Serialize;
use smoltcp::wire::Ipv4Packet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::{
    net::UdpSocket,
    time::{Duration, Interval, MissedTickBehavior, interval},
};

// Leave room for the WireGuard transport header and authentication tag
const MAX_UDP_PAYLOAD: usize = 65_507;
const MAX_INNER_PACKET: usize = MAX_UDP_PAYLOAD - 32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    pub public_key: String,
    pub listen_port: u16,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Peer {
    public_key: String,
    endpoint: SocketAddrV4,
    persistent_keepalive_seconds: u16,
}

struct ActivePeer {
    config: Peer,
    tunnel: Tunn,
}

/// One VM's WireGuard identity, reserved route and tunnel address.
pub(crate) struct WireGuard {
    address: Ipv4Addr,
    route: Ipv4Net,
    mtu: Option<u16>,
    peer: Option<ActivePeer>,
    bound_port: u16,
    public_key: String,
    private_key: StaticSecret,
    socket: UdpSocket,
    timer: Interval,
    incoming: Vec<u8>,
    outbound: Vec<u8>,
    scratch: Vec<u8>,
}

impl WireGuard {
    pub(crate) async fn new(desired: Config) -> Result<Self> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .context("binding WireGuard UDP socket")?;
        let private_key = StaticSecret::from(rand::random::<[u8; 32]>());
        let peer = build_peer(&private_key, desired.peer)?;

        // Keep the protocol timer across receive cancellations
        let mut timer = interval(Duration::from_millis(250));
        timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

        Ok(Self {
            address: desired.address,
            route: desired.route,
            mtu: desired.mtu,
            peer,
            bound_port: socket.local_addr()?.port(),
            public_key: STANDARD.encode(PublicKey::from(&private_key).as_bytes()),
            private_key,
            socket,
            timer,
            incoming: vec![0; u16::MAX as usize],
            outbound: Vec::new(),
            scratch: vec![0; u16::MAX as usize + 32],
        })
    }

    pub(crate) fn status(&self) -> Status {
        Status {
            public_key: self.public_key.clone(),
            listen_port: self.bound_port,
        }
    }

    pub(crate) fn reserves(&self, address: Ipv4Addr) -> bool {
        self.route.contains(&address)
    }

    /// Translates the source address of a VM packet and attempts to send it through the tunnel.
    ///
    /// For an oversized DF packet, returns the MTU to advertise to the guest instead.
    pub(crate) async fn send_vm_ipv4(
        &mut self,
        ip: &Ipv4Packet<&[u8]>,
        vm_ip: Ipv4Addr,
    ) -> Option<u16> {
        if ip.src_addr() != vm_ip || self.peer.is_none() || ip.dst_addr() == self.address {
            return None;
        }

        // Own the reusable buffer while sending through the mutable tunnel
        let mut packet = std::mem::take(&mut self.outbound);
        packet.clear();
        packet.extend_from_slice(&ip.as_ref()[..usize::from(ip.total_len())]);

        // Validate and translate the datagram before handing it to the authenticated peer
        let mut fragmentation_needed = None;

        if let Some(length) = translate(
            &mut packet,
            Translation::FromVm {
                source: self.address,
            },
        ) {
            if let Some(mtu) = self.mtu
                && ip.dont_frag()
                && length > usize::from(mtu)
            {
                fragmentation_needed = Some(mtu);
            } else {
                self.send_ipv4(&packet[..length]).await;
            }
        }

        self.outbound = packet;

        fragmentation_needed
    }

    /// Receives one tunnel packet, returning `None` if it cannot be delivered to the VM.
    pub(crate) async fn receive_vm_ipv4(
        &mut self,
        output: &mut [u8],
        vm_ip: Ipv4Addr,
    ) -> Result<Option<usize>> {
        let length = self.receive_ipv4(output).await?;
        let packet = &mut output[..length];

        // The receive path already validated the IPv4 header
        if Ipv4Packet::new_unchecked(&*packet).dst_addr() != self.address {
            return Ok(None);
        }

        Ok(translate(packet, Translation::ToVm { destination: vm_ip }))
    }

    /// Applies a configuration change, discarding the previous peer session
    /// and any queued packets.
    pub(crate) fn apply(&mut self, desired: Config) -> Result<()> {
        if self.address == desired.address
            && self.route == desired.route
            && self.mtu == desired.mtu
            && self.peer.as_ref().map(|peer| &peer.config) == desired.peer.as_ref()
        {
            return Ok(());
        }

        // Revoke queued plaintext on any configuration change and retain a valid snapshot on error
        self.peer = build_peer(&self.private_key, desired.peer)?;
        self.address = desired.address;
        self.route = desired.route;
        self.mtu = desired.mtu;

        Ok(())
    }

    pub(crate) async fn send_ipv4(&mut self, packet: &[u8]) {
        let Ok(ip) = Ipv4Packet::new_checked(packet) else {
            return;
        };
        if ip.version() != 4
            || usize::from(ip.total_len()) != packet.len()
            || packet.len() > MAX_INNER_PACKET
        {
            return;
        }
        if ip.dst_addr() == self.address || !self.route.contains(&ip.dst_addr()) {
            return;
        }

        if let Some(peer) = &mut self.peer
            && let TunnResult::WriteToNetwork(datagram) =
                peer.tunnel.encapsulate(packet, &mut self.scratch)
        {
            transmit(&self.socket, peer.config.endpoint, datagram).await;
        }
    }

    /// Services the tunnel until an authorized IPv4 packet fits in the output buffer.
    pub(crate) async fn receive_ipv4(&mut self, output: &mut [u8]) -> Result<usize> {
        loop {
            // Maintain the protocol even when no datagrams arrive
            let received = tokio::select! {
                received = self.socket.recv_from(&mut self.incoming) => received,
                _ = self.timer.tick() => {
                    self.tick().await?;
                    continue;
                }
            };
            let (length, source) = received.context("reading WireGuard UDP socket")?;
            let SocketAddr::V4(source) = source else {
                continue;
            };
            let Some(peer) = self
                .peer
                .as_mut()
                .filter(|peer| peer.config.endpoint == source)
            else {
                continue;
            };

            // An empty input to BoringTun drains locally queued packets and must never come from UDP
            if length == 0 {
                continue;
            }
            let mut input = &self.incoming[..length];
            loop {
                match peer
                    .tunnel
                    .decapsulate(Some((*source.ip()).into()), input, &mut self.scratch)
                {
                    TunnResult::WriteToNetwork(datagram) => {
                        // Drain queued packets without cancellation points, as with timer sends
                        if let Err(error) = self.socket.try_send_to(datagram, source.into()) {
                            log::debug!("WireGuard send to {source} failed: {error}");
                        }

                        input = &[];
                    }
                    TunnResult::WriteToTunnelV4(data, address) => {
                        // Validate the packet and authorize the source returned by BoringTun
                        if Ipv4Packet::new_checked(&*data).is_err() {
                            break;
                        }

                        if address == self.address
                            || !self.route.contains(&address)
                            || data.len() > output.len()
                        {
                            break;
                        }

                        output[..data.len()].copy_from_slice(data);
                        return Ok(data.len());
                    }
                    _ => break,
                }
            }
        }
    }

    async fn tick(&mut self) -> Result<()> {
        self.socket
            .writable()
            .await
            .context("waiting to send WireGuard timers")?;

        // Keep timer updates and their best-effort sends together across receive cancellation
        if let Some(peer) = &mut self.peer {
            match peer.tunnel.update_timers(&mut self.scratch) {
                TunnResult::WriteToNetwork(datagram) => {
                    let endpoint = peer.config.endpoint;
                    if let Err(error) = self.socket.try_send_to(datagram, endpoint.into()) {
                        log::debug!("WireGuard send to {endpoint} failed: {error}");
                    }
                }
                TunnResult::Err(WireGuardError::ConnectionExpired)
                    if peer.tunnel.persistent_keepalive().is_some() =>
                {
                    // Let BoringTun send the next handshake on its retry timer
                    let _ = peer
                        .tunnel
                        .format_handshake_initiation(&mut self.scratch, false);
                }
                _ => {}
            }
        }

        Ok(())
    }
}

fn build_peer(private_key: &StaticSecret, peer: Option<Peer>) -> Result<Option<ActivePeer>> {
    let Some(config) = peer else {
        return Ok(None);
    };

    let key = PublicKey::from(decode_key(&config.public_key)?);
    ensure!(
        key != PublicKey::from(private_key) && private_key.diffie_hellman(&key).was_contributory(),
        "invalid remote WireGuard public key"
    );
    let keepalive = config.persistent_keepalive_seconds;
    let tunnel = Tunn::new(
        private_key.clone(),
        key,
        None,
        (keepalive != 0).then_some(keepalive),
        rand::random::<u32>() >> 8,
        None,
    );

    Ok(Some(ActivePeer { config, tunnel }))
}

async fn transmit(socket: &UdpSocket, endpoint: SocketAddrV4, datagram: &[u8]) {
    // Losing a peer or datagram must not stop the rest of the VM's networking
    if let Err(error) = socket.send_to(datagram, endpoint).await {
        log::debug!("WireGuard send to {endpoint} failed: {error}");
    }
}

fn unicast(address: Ipv4Addr) -> bool {
    !address.is_unspecified() && !address.is_broadcast() && !address.is_multicast()
}

fn usable_prefix(prefix: Ipv4Net) -> bool {
    const RESERVED: [Ipv4Net; 4] = [
        Ipv4Net::new_assert(Ipv4Addr::UNSPECIFIED, 8),
        Ipv4Net::new_assert(Ipv4Addr::new(127, 0, 0, 0), 8),
        Ipv4Net::new_assert(Ipv4Addr::new(169, 254, 0, 0), 16),
        Ipv4Net::new_assert(Ipv4Addr::new(224, 0, 0, 0), 3),
    ];

    !RESERVED
        .iter()
        .any(|reserved| prefix.contains(reserved) || reserved.contains(&prefix))
}

fn decode_key(value: &str) -> Result<[u8; 32]> {
    STANDARD
        .decode(value)
        .context("invalid base64 WireGuard public key")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("WireGuard public key must be 32 bytes"))
}

#[cfg(test)]
#[path = "tests.rs"]
mod routing_tests;
