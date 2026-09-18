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

///  General operations over IP network
pub trait IpNetwork {
    type Addr: Copy + PartialEq + PartialOrd + Debug + Display;
    type Bits: BitAnd + BitOr;

    /// Get address part
    ///
    /// # Example
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use std::str::FromStr;
    ///
    /// use cidit::Ipv4Cidr;
    /// use cidit::IpNetwork;
    ///
    /// let ipv4_addr = Ipv4Addr::from_str("10.22.135.144").unwrap();
    /// let ipv4_cidr: Ipv4Cidr = "10.22.135.144/24".parse().unwrap();
    ///
    /// assert_eq!(ipv4_cidr.address(), ipv4_addr);
    /// ```
    fn address(&self) -> Self::Addr;

    /// Get prefix length
    ///
    /// # Example
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    ///
    /// use cidit::Ipv4Cidr;
    /// use cidit::IpNetwork;
    ///
    /// let prefix: u8 = 24;
    /// let ipv4_cidr: Ipv4Cidr = "10.22.135.144/24".parse().unwrap();
    ///
    /// assert_eq!(ipv4_cidr.prefix_len(), prefix);
    /// ```
    fn prefix_len(&self) -> u8;

    /// Get network mask as bits
    ///
    /// # Example
    ///
    /// ```
    /// use cidit::Ipv4Cidr;
    /// use cidit::IpNetwork;
    ///
    /// let ipv4_cidr: Ipv4Cidr = "10.22.135.144/24".parse().unwrap();
    ///
    /// assert_eq!(ipv4_cidr.netmask_bits(), 0b11111111_11111111_11111111_00000000);
    /// ```
    fn netmask_bits(&self) -> Self::Bits;

    /// Get network mask as IP address
    ///
    /// # Example
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use std::str::FromStr;
    ///
    /// use cidit::Ipv4Cidr;
    /// use cidit::IpNetwork;
    ///
    /// let ipv4_cidr: Ipv4Cidr = "10.22.135.144/24".parse().unwrap();
    ///
    /// assert_eq!(ipv4_cidr.netmask(), Ipv4Addr::from_str("255.255.255.0").unwrap());
    /// ```
    fn netmask(&self) -> Self::Addr;

    /// Get host mask as bits
    ///
    /// # Example
    ///
    /// ```
    /// use cidit::Ipv4Cidr;
    /// use cidit::IpNetwork;
    ///
    /// let ipv4_cidr: Ipv4Cidr = "10.22.135.144/24".parse().unwrap();
    ///
    /// assert_eq!(ipv4_cidr.hostmask_bits(), 0b00000000_00000000_00000000_11111111);
    /// ```
    fn hostmask_bits(&self) -> Self::Bits;

    /// Get host mask as IP address
    ///
    /// # Example
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use std::str::FromStr;
    ///
    /// use cidit::Ipv4Cidr;
    /// use cidit::IpNetwork;
    ///
    /// let ipv4_cidr: Ipv4Cidr = "10.22.135.144/24".parse().unwrap();
    ///
    /// assert_eq!(ipv4_cidr.hostmask(), Ipv4Addr::from_str("0.0.0.255").unwrap());
    /// ```
    fn hostmask(&self) -> Self::Addr;

    /// First arithmetical IP address in a range
    ///
    /// # Example
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use std::str::FromStr;
    ///
    /// use cidit::Ipv4Cidr;
    /// use cidit::IpNetwork;
    ///
    /// let ipv4_cidr: Ipv4Cidr = "10.22.135.144/24".parse().unwrap();
    ///
    /// assert_eq!(ipv4_cidr.first_address(), Ipv4Addr::from_str("10.22.135.0").unwrap());
    /// ```
    fn first_address(&self) -> Self::Addr;

    /// Last arithmetical IP address in a range
    ///
    /// # Example
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use std::str::FromStr;
    ///
    /// use cidit::Ipv4Cidr;
    /// use cidit::IpNetwork;
    ///
    /// let ipv4_cidr: Ipv4Cidr = "10.22.135.144/24".parse().unwrap();
    ///
    /// assert_eq!(ipv4_cidr.last_address(), Ipv4Addr::from_str("10.22.135.255").unwrap());
    /// ```
    fn last_address(&self) -> Self::Addr;
}

/// Enum representing genetic CIDR block.
/// Contains IPv4 and IPv6 variants
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

    fn address(&self) -> IpAddr {
        match self {
            Cidr::V4(ipv4_cidr) => IpAddr::V4(ipv4_cidr.address()),
            Cidr::V6(ipv6_cidr) => IpAddr::V6(ipv6_cidr.address()),
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
    use crate::test_helpers;

    use super::*;

    const EXPECTED_IPV4_PREFIX: u8 = 24;
    const EXPECTED_IPV6_PREFIX: u8 = 24;

    const EXPECTED_IPV4_STR: &str = "10.22.135.144";
    const EXPECTED_IPV6_STR: &str = "2001:db8:1::ab9:c0a8:102";

    #[test]
    fn test_cidr_parse_error_type() {
        // Arrange
        // Act
        // Assert
        test_helpers::assert_error::<CidrParseError>();
    }

    #[test]
    fn test_cidr_type() {
        // Arrange
        // Act
        // Assert
        test_helpers::assert_normal_type::<Cidr>();
    }

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
                assert_eq!(cidr.address().to_string(), EXPECTED_IPV4_STR);
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
                assert_eq!(cidr.address().to_string(), EXPECTED_IPV6_STR);
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
