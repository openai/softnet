use anyhow::{Context, Result};
use clap::ValueEnum;
use ipnet::Ipv4Net;
use mac_address::MacAddress;
use std::net::Ipv4Addr;
use vmnet::NetworkConfiguration;
use vmnet::network::Mode;

// A /29 has six usable addresses, including the gateway
pub(crate) const MAX_VMS: usize = 5;

// Prefix length of a subnet used by one or more VMs
pub(crate) const SUBNET_PREFIX_LEN: u8 = 29;

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum NetType {
    /// Shared network
    ///
    /// Uses NAT-translation to give guests access to the global network
    Nat,
    /// Host network
    ///
    /// Guests will be able to talk only to the host without access to global network
    Host,
}

pub(crate) struct Network {
    pub(crate) handle: vmnet::Network,
    pub(crate) subnet: Ipv4Net,
    pub(crate) gateway_ip: Ipv4Addr,
}

impl Network {
    pub(crate) fn new(
        net_type: NetType,
        subnet: Ipv4Net,
        reservations: &[(MacAddress, Ipv4Addr)],
    ) -> Result<Self> {
        // Create vmnet's network configuration
        let mut configuration = NetworkConfiguration::new(match net_type {
            NetType::Nat => Mode::Shared,
            NetType::Host => Mode::Host,
        })
        .context("failed to create vmnet network configuration")?;

        // Configure the gateway address and subnet mask
        let gateway_ip = subnet
            .hosts()
            .next()
            .context("shared VM subnet has no gateway address")?;
        let subnet_mask = subnet.netmask();
        configuration
            .set_ipv4_subnet(gateway_ip, subnet_mask)
            .context("failed to configure IPv4 subnet")?;

        // Publish every VM's reservation before the network starts
        for (vm_mac, vm_ip) in reservations {
            configuration
                .add_dhcp_reservation(vm_mac.bytes(), *vm_ip)
                .with_context(|| {
                    format!("failed to reserve {vm_ip} for VM MAC address {vm_mac}")
                })?;
        }

        // Create vmnet's network
        let handle = vmnet::Network::new(&configuration)
            .with_context(|| format!("failed to create vmnet network {subnet}"))?;

        Ok(Self {
            handle,
            subnet,
            gateway_ip,
        })
    }
}
