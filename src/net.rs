use ipv4::Ipv4Cidr;
use ipv4::Ipv4CidrError;
use std::fmt::Debug;
use std::fmt::Display;
use std::net::IpAddr;
use std::ops::BitAnd;
use std::ops::BitOr;
use std::str::FromStr;
use thiserror::Error;

use crate::net::ipv6::Ipv6Cidr;
use crate::net::ipv6::Ipv6CidrError;

pub mod dto;
pub mod ipv4;
pub mod ipv6;

#[derive(Debug, Error)]
pub enum CidrParseError {
    #[error("Invalid CIDR.\n IPv4: {v4}\n IPv6: {v6} ")]
    Neither {
        v4: Ipv4CidrError,
        v6: Ipv6CidrError,
    },
}

/// General IpNetwork trait
pub trait IpNetwork {
    type Addr: Copy + PartialEq + PartialOrd + Debug + Display;
    type Bits: BitAnd + BitOr;

    /// Address
    fn addr(&self) -> Self::Addr;

    /// Prefix length
    fn prefix_len(&self) -> u8;

    /// Network mask bits
    fn netmask_bits(&self) -> Self::Bits;

    /// Network mask address
    fn netmask(&self) -> Self::Addr;

    /// Host mask bits
    fn hostmask_bits(&self) -> Self::Bits;

    /// Host mask address
    fn hostmask(&self) -> Self::Addr;

    /// First arithmetical address in a range
    fn first_address(&self) -> Self::Addr;

    /// Last arithmetical address in a range
    fn last_address(&self) -> Self::Addr;
}

/// Enum containing IPv4 and IPv6 variants
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Cidr {
    V4(Ipv4Cidr),
    V6(Ipv6Cidr),
}

impl FromStr for Cidr {
    type Err = CidrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v4_err = match s.parse::<Ipv4Cidr>() {
            Ok(v4) => return Ok(Cidr::V4(v4)),
            Err(e) => e,
        };

        let v6_err = match s.parse::<Ipv6Cidr>() {
            Ok(v6) => return Ok(Cidr::V6(v6)),
            Err(e) => e,
        };

        Err(CidrParseError::Neither {
            v4: v4_err,
            v6: v6_err,
        })
    }
}

impl Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cidr::V4(v4_cidr) => {
                write!(f, "{}", v4_cidr)
            }
            Cidr::V6(v6_cidr) => {
                write!(f, "{}", v6_cidr)
            }
        }
    }
}

impl IpNetwork for Cidr {
    type Addr = IpAddr;
    type Bits = u128;

    fn addr(&self) -> IpAddr {
        match self {
            Cidr::V4(ipv4_cidr) => IpAddr::V4(ipv4_cidr.addr()),
            Cidr::V6(ipv6_cidr) => IpAddr::V6(ipv6_cidr.addr()),
        }
    }

    fn prefix_len(&self) -> u8 {
        match self {
            Cidr::V4(ipv4_cidr) => ipv4_cidr.prefix_len(),
            Cidr::V6(ipv6_cidr) => ipv6_cidr.prefix_len(),
        }
    }

    fn netmask(&self) -> IpAddr {
        match self {
            Cidr::V4(ipv4_cidr) => IpAddr::V4(ipv4_cidr.netmask()),
            Cidr::V6(ipv6_cidr) => IpAddr::V6(ipv6_cidr.netmask()),
        }
    }

    fn hostmask(&self) -> IpAddr {
        match self {
            Cidr::V4(ipv4_cidr) => IpAddr::V4(ipv4_cidr.hostmask()),
            Cidr::V6(ipv6_cidr) => IpAddr::V6(ipv6_cidr.hostmask()),
        }
    }

    fn first_address(&self) -> IpAddr {
        match self {
            Cidr::V4(ipv4_cidr) => IpAddr::V4(ipv4_cidr.first_address()),
            Cidr::V6(ipv6_cidr) => IpAddr::V6(ipv6_cidr.first_address()),
        }
    }

    fn last_address(&self) -> IpAddr {
        match self {
            Cidr::V4(ipv4_cidr) => IpAddr::V4(ipv4_cidr.last_address()),
            Cidr::V6(ipv6_cidr) => IpAddr::V6(ipv6_cidr.last_address()),
        }
    }

    fn netmask_bits(&self) -> Self::Bits {
        match self {
            Cidr::V4(ipv4_cidr) => ipv4_cidr.netmask_bits() as u128,
            Cidr::V6(ipv6_cidr) => ipv6_cidr.netmask_bits(),
        }
    }

    fn hostmask_bits(&self) -> Self::Bits {
        match self {
            Cidr::V4(ipv4_cidr) => ipv4_cidr.hostmask_bits() as u128,
            Cidr::V6(ipv6_cidr) => ipv6_cidr.hostmask_bits(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED_IPV4_PREFIX: u8 = 24;
    const EXPECTED_IPV6_PREFIX: u8 = 24;

    const EXPECTED_IPV4_STR: &str = "10.22.135.144";
    const EXPECTED_IPV6_STR: &str = "2001:db8:1::ab9:c0a8:102";

    #[test]
    fn test_parse_ipv4_cidr() {
        // Arrange
        let expected_ipv4_cidr_str: String = format!("{EXPECTED_IPV4_STR}/{EXPECTED_IPV4_PREFIX}");

        // Act
        let actual_net: Cidr = expected_ipv4_cidr_str.parse().unwrap();

        // Assert
        match actual_net {
            Cidr::V4(cidr) => {
                assert_eq!(cidr.prefix_len(), EXPECTED_IPV4_PREFIX);
                assert_eq!(cidr.addr().to_string(), EXPECTED_IPV4_STR);
            }
            _ => panic!("Expected Cidr::V4"),
        }
    }

    #[test]
    fn test_parse_ipv6_cidr() {
        // Arrange
        let expected_ipv6_cidr_str: String = format!("{EXPECTED_IPV6_STR}/{EXPECTED_IPV6_PREFIX}");

        // Act
        let actual_net: Cidr = expected_ipv6_cidr_str.parse().unwrap();

        // Assert
        match actual_net {
            Cidr::V6(cidr) => {
                assert_eq!(cidr.prefix_len(), EXPECTED_IPV6_PREFIX);
                assert_eq!(cidr.addr().to_string(), EXPECTED_IPV6_STR);
            }
            _ => panic!("Expected Cidr::V6"),
        }
    }

    #[test]
    fn test_parse_invalid_string() {
        // Arrange
        let expected_invalid_string: &str = "some-invalid-string";

        // Act
        let actual_err = expected_invalid_string.parse::<Cidr>();

        // Assert
        assert!(actual_err.is_err());
    }
}
