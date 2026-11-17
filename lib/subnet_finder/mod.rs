use anyhow::{Context, Result};
use ipnet::{Ipv4AddrRange, Ipv4Net};
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use rand::seq::{IndexedRandom, IteratorRandom};
use std::net::Ipv4Addr;

const MAX_ATTEMPTS: usize = 128;

/// Find an available private subnet and its first two usable host addresses
pub(crate) fn find_available_subnet(prefix_len: u8) -> Result<(Ipv4Addr, Ipv4Addr, Ipv4Net)> {
    find_available_subnet_in(prefix_len, &default_subnet_pool()?)
}

/// Find an available subnet within the supplied allocation pool.
pub(crate) fn find_available_subnet_in(
    prefix_len: u8,
    subnet_pool: &[Ipv4Net],
) -> Result<(Ipv4Addr, Ipv4Addr, Ipv4Net)> {
    anyhow::ensure!(!subnet_pool.is_empty(), "subnet pool must not be empty");

    let used_subnets = used_subnets()?;

    // Try up to MAX_ATTEMPTS random subnets until we're able to
    // get an available subnet of the desired length
    for _ in 0..MAX_ATTEMPTS {
        let candidate = random_candidate(prefix_len, subnet_pool)?;

        if !is_vmnet_compatible(&candidate) {
            continue;
        }

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
        "failed to find an unused IPv4 /{prefix_len} subnet in the configured pool after {MAX_ATTEMPTS} attempts"
    )
}

fn is_vmnet_compatible(subnet: &Ipv4Net) -> bool {
    // Keep 192.168 subnet strings short enough for macOS firewall generation.
    let octets = subnet.network().octets();
    octets[..2] != [192, 168] || octets[2] < 100
}

fn default_subnet_pool() -> Result<Vec<Ipv4Net>> {
    // Add private address space (as defined in RFC 1918[1]) with one exception
    //
    // We narrow the 192.168.0.0/16 allocation pool to work around a macOS bug
    // where long subnet address strings lose their CIDR prefix in the generated
    // firewall rules, causing connection issues.
    //
    // [1]: https://datatracker.ietf.org/doc/html/rfc1918#section-3
    Ok(vec![
        "10.0.0.0/8".parse()?,
        "172.16.0.0/12".parse()?,
        "192.168.0.0/18".parse()?,  // third octet 0–63
        "192.168.64.0/19".parse()?, // third octet 64–95
        "192.168.96.0/22".parse()?, // third octet 96–99
    ])
}

fn used_subnets() -> Result<Vec<Ipv4Net>> {
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

    Ok(used_subnets)
}

fn random_candidate(prefix_len: u8, subnet_pool: &[Ipv4Net]) -> Result<Ipv4Net> {
    let eligible_subnets = subnet_pool
        .iter()
        .filter(|subnet| prefix_len >= subnet.prefix_len());
    let pool = eligible_subnets
        .choose(&mut rand::rng())
        .context("subnet pool contains no range large enough for the requested subnet")?;

    let address = Ipv4AddrRange::new(pool.network(), pool.broadcast())
        .choose(&mut rand::rng())
        .unwrap();
    Ok(Ipv4Net::new(address, prefix_len)?.trunc())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[serial_test::serial]
    fn finds_two_usable_addresses() {
        // Find a subnet on the current host
        let (gateway_ip, vm_ip, subnet) = find_available_subnet(29).unwrap();

        // Check the subnet and its first two usable addresses
        assert_eq!(subnet.prefix_len(), 29);
        assert!(subnet.network().is_private());
        assert_eq!(subnet.hosts().collect::<Vec<_>>()[..2], [gateway_ip, vm_ip]);
    }

    #[test]
    fn candidates_stay_within_the_configured_pool() {
        let pool = "172.20.16.0/20".parse::<Ipv4Net>().unwrap();

        for _ in 0..128 {
            let candidate = random_candidate(29, &[pool]).unwrap();
            assert!(pool.contains(&candidate.network()));
            assert!(pool.contains(&candidate.broadcast()));
        }
    }

    #[test]
    fn rejects_pools_smaller_than_the_requested_subnet() {
        let error = random_candidate(29, &["172.20.16.0/30".parse().unwrap()]).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("no range large enough for the requested subnet")
        );
    }

    #[test]
    fn rejects_vmnet_incompatible_custom_pool() {
        let error =
            find_available_subnet_in(29, &["192.168.200.200/29".parse().unwrap()]).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("failed to find an unused IPv4 /29 subnet")
        );
    }

    #[test]
    fn vmnet_compatibility_applies_to_all_pools() {
        assert!(is_vmnet_compatible(&"192.168.99.248/29".parse().unwrap()));
        assert!(!is_vmnet_compatible(&"192.168.100.0/29".parse().unwrap()));
        assert!(is_vmnet_compatible(&"10.200.0.0/29".parse().unwrap()));
        assert!(is_vmnet_compatible(&"172.20.0.0/29".parse().unwrap()));
    }
}
