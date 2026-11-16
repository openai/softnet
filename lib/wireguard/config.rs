use super::{MAX_INNER_PACKET, Peer, unicast, usable_prefix};
use anyhow::{Result, ensure};
use ipnet::Ipv4Net;
use std::net::{Ipv4Addr, SocketAddrV4};

#[derive(Debug)]
pub(crate) struct Config {
    /// Local tunnel address used in place of the VM's IP inside the tunnel.
    pub address: Ipv4Addr,

    /// Reserved tunnel prefix that serves as the peer's `AllowedIPs` when configured.
    pub route: Ipv4Net,

    /// Inner IPv4 path MTU, if known.
    pub mtu: Option<u16>,

    /// Remote WireGuard peer. With `None`, traffic to the reserved prefix is dropped.
    pub peer: Option<Peer>,
}

impl Config {
    pub(crate) fn new(address: Ipv4Addr, route: &str, mtu: Option<u16>) -> Result<Self> {
        let prefix = route.parse::<Ipv4Net>()?;
        ensure!(
            prefix.to_string() == route && prefix.trunc() == prefix && usable_prefix(prefix),
            "expected a canonical usable IPv4 prefix"
        );
        ensure!(
            usable_prefix(address.into()) && prefix != Ipv4Net::from(address),
            "invalid WireGuard address"
        );

        ensure!(
            mtu.is_none_or(|mtu| (68..=MAX_INNER_PACKET).contains(&usize::from(mtu))),
            "invalid WireGuard IPv4 MTU"
        );

        Ok(Self {
            address,
            route: prefix,
            mtu,
            peer: None,
        })
    }

    pub(crate) fn validate(&self, subnet: Ipv4Net) -> Result<()> {
        // Guest-subnet destinations use ARP and cannot be intercepted by this IP router
        ensure!(
            !self.route.contains(&subnet) && !subnet.contains(&self.route),
            "WireGuard route must be disjoint from the VM subnet"
        );

        Ok(())
    }
}

impl Peer {
    pub(crate) fn new(
        public_key: String,
        endpoint: SocketAddrV4,
        persistent_keepalive_seconds: u16,
    ) -> Result<Self> {
        ensure!(
            unicast(*endpoint.ip()) && endpoint.port() != 0,
            "invalid WireGuard UDP endpoint"
        );

        Ok(Self {
            public_key,
            endpoint,
            persistent_keepalive_seconds,
        })
    }
}
