use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Represents an IPv4 or IPv6 CIDR subnet block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CidrBlock {
    V4 { network: u32, mask: u32 },
    V6 { network: u128, mask: u128 },
}

impl CidrBlock {
    /// Parses a CIDR notation string (e.g. "192.168.1.0/24", "10.0.0.1", "::1", "2001:db8::/32").
    /// An omitted prefix length defaults to /32 (IPv4) or /128 (IPv6).
    pub fn parse(s: &str) -> Result<Self> {
        let trimmed = s.trim();
        if trimmed == "*" || trimmed == "all" || trimmed == "0.0.0.0/0" {
            return Ok(CidrBlock::V4 {
                network: 0,
                mask: 0,
            });
        }
        if trimmed == "::/0" {
            return Ok(CidrBlock::V6 {
                network: 0,
                mask: 0,
            });
        }

        if let Some((ip_str, prefix_str)) = trimmed.split_once('/') {
            let prefix: u32 = prefix_str
                .parse()
                .map_err(|_| anyhow!("Invalid CIDR prefix length in '{}'", s))?;

            if let Ok(ipv4) = ip_str.parse::<Ipv4Addr>() {
                if prefix > 32 {
                    return Err(anyhow!("IPv4 CIDR prefix must be between 0 and 32: '{}'", s));
                }
                let mask = if prefix == 0 {
                    0u32
                } else {
                    !0u32 << (32 - prefix)
                };
                let network = u32::from(ipv4) & mask;
                Ok(CidrBlock::V4 { network, mask })
            } else if let Ok(ipv6) = ip_str.parse::<Ipv6Addr>() {
                if prefix > 128 {
                    return Err(anyhow!(
                        "IPv6 CIDR prefix must be between 0 and 128: '{}'",
                        s
                    ));
                }
                let mask = if prefix == 0 {
                    0u128
                } else {
                    !0u128 << (128 - prefix)
                };
                let network = u128::from(ipv6) & mask;
                Ok(CidrBlock::V6 { network, mask })
            } else {
                Err(anyhow!("Invalid IP address in CIDR '{}'", s))
            }
        } else if let Ok(ipv4) = trimmed.parse::<Ipv4Addr>() {
            let mask = !0u32;
            let network = u32::from(ipv4);
            Ok(CidrBlock::V4 { network, mask })
        } else if let Ok(ipv6) = trimmed.parse::<Ipv6Addr>() {
            let mask = !0u128;
            let network = u128::from(ipv6);
            Ok(CidrBlock::V6 { network, mask })
        } else {
            Err(anyhow!("Invalid IP or CIDR block: '{}'", s))
        }
    }

    /// Checks if a given IP address falls within this CIDR block.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        let normalized = normalize_ip(ip);
        match (self, normalized) {
            (CidrBlock::V4 { network, mask }, IpAddr::V4(v4)) => {
                (u32::from(v4) & *mask) == *network
            }
            (CidrBlock::V6 { network, mask }, IpAddr::V6(v6)) => {
                (u128::from(v6) & *mask) == *network
            }
            _ => false,
        }
    }
}

/// Normalizes IPv4-mapped IPv6 addresses (`::ffff:192.0.2.128`) to native `IpAddr::V4`.
fn normalize_ip(ip: &IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            // Check for IPv4-mapped IPv6 address (0:0:0:0:0:ffff:d.d.d.d)
            if octets[0..10] == [0; 10] && octets[10] == 0xff && octets[11] == 0xff {
                IpAddr::V4(Ipv4Addr::new(
                    octets[12], octets[13], octets[14], octets[15],
                ))
            } else {
                IpAddr::V6(*v6)
            }
        }
        IpAddr::V4(v4) => IpAddr::V4(*v4),
    }
}

/// A collection of CIDR blocks representing an IP filter (allow-list).
#[derive(Debug, Clone)]
pub struct IpFilter {
    pub allow_all: bool,
    pub blocks: Vec<CidrBlock>,
}

impl Default for IpFilter {
    fn default() -> Self {
        Self {
            allow_all: true,
            blocks: Vec::new(),
        }
    }
}

impl IpFilter {
    /// Compiles a list of CIDR block strings into an `IpFilter`.
    /// If empty, or contains "0.0.0.0/0", "::/0", "*", or "all", `allow_all` is enabled.
    pub fn new(cidrs: &[String]) -> Result<Self> {
        if cidrs.is_empty() {
            return Ok(Self::default());
        }

        let mut blocks = Vec::new();
        let mut allow_all = false;

        for entry in cidrs {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            if entry == "*" || entry == "all" {
                allow_all = true;
                break;
            }
            let block = CidrBlock::parse(entry)?;
            if let CidrBlock::V4 { mask: 0, .. } = block {
                // Check if there is also an IPv6 allow-all or if this is the only entry
                if cidrs.iter().any(|c| c.trim() == "::/0" || c.trim() == "*") {
                    allow_all = true;
                }
            }
            blocks.push(block);
        }

        Ok(Self { allow_all, blocks })
    }

    /// Checks if a client IP is allowed by this filter.
    pub fn is_allowed(&self, ip: &IpAddr) -> bool {
        if self.allow_all {
            return true;
        }
        self.blocks.iter().any(|block| block.contains(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_v4_parsing_and_matching() {
        let block = CidrBlock::parse("192.168.1.0/24").unwrap();
        assert!(block.contains(&"192.168.1.1".parse().unwrap()));
        assert!(block.contains(&"192.168.1.254".parse().unwrap()));
        assert!(!block.contains(&"192.168.2.1".parse().unwrap()));
        assert!(!block.contains(&"10.0.0.1".parse().unwrap()));

        // Single host
        let host = CidrBlock::parse("10.0.0.5").unwrap();
        assert!(host.contains(&"10.0.0.5".parse().unwrap()));
        assert!(!host.contains(&"10.0.0.6".parse().unwrap()));
    }

    #[test]
    fn test_ipv4_mapped_ipv6_matching() {
        let block = CidrBlock::parse("192.168.1.0/24").unwrap();
        // ::ffff:192.168.1.50
        let mapped: IpAddr = "::ffff:192.168.1.50".parse().unwrap();
        assert!(block.contains(&mapped));
    }

    #[test]
    fn test_cidr_v6_parsing_and_matching() {
        let block = CidrBlock::parse("2001:db8::/32").unwrap();
        assert!(block.contains(&"2001:db8:ffff::1".parse().unwrap()));
        assert!(!block.contains(&"2001:db9::1".parse().unwrap()));

        let localhost = CidrBlock::parse("::1").unwrap();
        assert!(localhost.contains(&"::1".parse().unwrap()));
        assert!(!localhost.contains(&"::2".parse().unwrap()));
    }

    #[test]
    fn test_ip_filter_allow_all() {
        let filter = IpFilter::new(&["0.0.0.0/0".to_string(), "::/0".to_string()]).unwrap();
        assert!(filter.is_allowed(&"1.2.3.4".parse().unwrap()));
        assert!(filter.is_allowed(&"2607:f8b0::1".parse().unwrap()));

        let wildcard = IpFilter::new(&["*".to_string()]).unwrap();
        assert!(wildcard.is_allowed(&"8.8.8.8".parse().unwrap()));

        let empty = IpFilter::new(&[]).unwrap();
        assert!(empty.is_allowed(&"127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_ip_filter_restricted() {
        let filter = IpFilter::new(&[
            "192.168.1.0/24".to_string(),
            "10.0.0.1".to_string(),
        ])
        .unwrap();

        assert!(filter.is_allowed(&"192.168.1.50".parse().unwrap()));
        assert!(filter.is_allowed(&"10.0.0.1".parse().unwrap()));
        assert!(!filter.is_allowed(&"10.0.0.2".parse().unwrap()));
        assert!(!filter.is_allowed(&"172.16.0.1".parse().unwrap()));
    }
}

