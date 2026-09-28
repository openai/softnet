use anyhow::{Context, Result};
use ipnet::{Ipv4AddrRange, Ipv4Net};
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use rand::seq::{IndexedRandom, IteratorRandom};
use std::net::Ipv4Addr;

const MAX_ATTEMPTS: usize = 128;

/// Find an available private subnet and its first two usable host addresses
pub(crate) fn find_available_subnet(prefix_len: u8) -> Result<(Ipv4Addr, Ipv4Addr, Ipv4Net)> {
    // Add private address space (as defined in RFC 1918[1])
    //
    // [1]: https://datatracker.ietf.org/doc/html/rfc1918#section-3
    let private_subnets: Vec<Ipv4Net> = vec![
        "10.0.0.0/8".parse()?,
        "172.16.0.0/12".parse()?,
        "192.168.0.0/16".parse()?,
    ];

    // Figure out which address space is already utilized on the host
    let mut used_subnets = Vec::new();

    for interface in NetworkInterface::show()? {
        for addr in interface.addr {
            // We only support IPv4 for now
            if let Addr::V4(addr) = addr {
                let mask = addr.netmask.context("IPv4 interface has no netmask")?;
                used_subnets.push(Ipv4Net::with_netmask(addr.ip, mask)?);
            }
        }
    }

    // Try up to MAX_ATTEMPTS random subnets until we're able to
    // get an available subnet of the desired length
    for _ in 0..MAX_ATTEMPTS {
        // Give each private range an equal chance, even if a larger one is occupied
        let private_subnet = private_subnets.choose(&mut rand::rng()).unwrap();

        // Skip private ranges too small to contain the requested subnet
        if prefix_len < private_subnet.prefix_len() {
            continue;
        }

        // Pick a subnet of the desired length within this private range
        let address = Ipv4AddrRange::new(private_subnet.network(), private_subnet.broadcast())
            .choose(&mut rand::rng())
            .unwrap();
        let candidate = Ipv4Net::new(address, prefix_len)?.trunc();

        // Only use the subnet if it doesn't overlap address space
        // that is already utilized on the host
        let overlaps = used_subnets
            .iter()
            .any(|used_subnet| candidate.contains(used_subnet) || used_subnet.contains(&candidate));
        if overlaps {
            continue;
        }

        // Take the first two hosts from the subnet
        let mut hosts = candidate.hosts();
        if let (Some(first_host), Some(second_host)) = (hosts.next(), hosts.next()) {
            return Ok((first_host, second_host, candidate));
        }
    }

    anyhow::bail!(
        "failed to find an unused private IPv4 /{prefix_len} subnet after {MAX_ATTEMPTS} attempts"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[serial_test::serial]
    fn finds_two_usable_addresses() {
        // Find a subnet on the current host
        let (gateway_ip, vm_ip, subnet) = find_available_subnet(30).unwrap();

        // Check the subnet and its two usable addresses
        assert_eq!(subnet.prefix_len(), 30);
        assert!(subnet.network().is_private());
        assert_eq!(subnet.hosts().collect::<Vec<_>>(), [gateway_ip, vm_ip]);
    }
}
