use std::{
    net::{AddrParseError, Ipv6Addr},
    str::FromStr,
};

use thiserror::Error;

use crate::net::IpNetwork;

const MAX_IPV6_CIDR_PREFIX_LEN: u8 = 128;
const POINT_TO_POINT_CIDR_PREFIX_LEN: u8 = 127;
const MIN_REASONABLE_PREFIX_LEN: u8 = 96;

#[derive(Debug, Error, PartialEq)]
pub enum Ipv6CidrError {
    #[error("Invalid CIDR format (expected: ::/x)")]
    Format,
    #[error("Failed to parse address: {0}")]
    IpParse(AddrParseError),
    #[error("Prefix is not a number")]
    PrefixNan,
    #[error("Invalid CIDR prefix: {0} (expected <= {max} )", max = MAX_IPV6_CIDR_PREFIX_LEN)]
    PrefixLen(u8),
}

/// Internal representation of IPv6 CIDR
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Ipv6Cidr {
    ip: Ipv6Addr,
    prefix: u8,
}

impl Ipv6Cidr {
    pub fn new(address: Ipv6Addr, prefix: u8) -> Result<Self, Ipv6CidrError> {
        if prefix > MAX_IPV6_CIDR_PREFIX_LEN {
            return Err(Ipv6CidrError::PrefixLen(prefix));
        }
        Ok(Self {
            ip: address,
            prefix,
        })
    }
}

impl FromStr for Ipv6Cidr {
    type Err = Ipv6CidrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ip, prefix) = s.split_once('/').ok_or(Ipv6CidrError::Format)?;
        let ip: Ipv6Addr = ip.parse().map_err(Ipv6CidrError::IpParse)?;
        let prefix: u8 = prefix.parse().map_err(|_| Ipv6CidrError::PrefixNan)?;
        Self::new(ip, prefix)
    }
}

/// IPv6 Network
pub trait Ipv6Network: IpNetwork {
    /// Number of available IPs in a range
    fn subnet_size(&self) -> String;

    /// Gets network address for IPv6.
    /// Returns None for network masks
    /// /127 for point-to-point connections
    /// ([RFC 6164](https://datatracker.ietf.org/doc/html/rfc6164))
    /// and /128 for single host
    fn network_address(&self) -> Option<Ipv6Addr>;
}

impl Ipv6Network for Ipv6Cidr {
    fn subnet_size(&self) -> String {
        let prefix_len: u8 = self.prefix;
        let power: u8 = MAX_IPV6_CIDR_PREFIX_LEN - prefix_len;
        if prefix_len < MIN_REASONABLE_PREFIX_LEN {
            format!("2^{}", power)
        } else {
            format!("{}", 1u128 << power)
        }
    }

    fn network_address(&self) -> Option<Ipv6Addr> {
        if self.prefix < POINT_TO_POINT_CIDR_PREFIX_LEN {
            Some(self.first_address())
        } else {
            None
        }
    }
}

impl IpNetwork for Ipv6Cidr {
    type Addr = Ipv6Addr;
    type Bits = u128;

    fn addr(&self) -> Ipv6Addr {
        self.ip
    }

    fn prefix_len(&self) -> u8 {
        self.prefix
    }

    fn netmask_bits(&self) -> Self::Bits {
        if self.prefix == 0 {
            0
        } else {
            !0u128 << (MAX_IPV6_CIDR_PREFIX_LEN - self.prefix)
        }
    }

    fn netmask(&self) -> Ipv6Addr {
        Ipv6Addr::from_bits(self.netmask_bits())
    }

    fn hostmask_bits(&self) -> Self::Bits {
        if self.prefix == MAX_IPV6_CIDR_PREFIX_LEN {
            0
        } else {
            !0u128 >> self.prefix
        }
    }

    fn hostmask(&self) -> Ipv6Addr {
        Ipv6Addr::from_bits(self.hostmask_bits())
    }

    fn first_address(&self) -> Ipv6Addr {
        Ipv6Addr::from_bits(self.ip.to_bits() & self.netmask_bits())
    }

    fn last_address(&self) -> Ipv6Addr {
        Ipv6Addr::from_bits(self.first_address().to_bits() | self.hostmask_bits())
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::test_helpers;

    use super::*;

    const EXPECTED_IPV6_STR: &str = "2001:db8:1::ab9:c0a8:102";

    #[test]
    fn test_cidr_parse_error_type() {
        // Arrange
        // Act
        // Assert
        test_helpers::assert_error::<Ipv6CidrError>();
    }

    #[test]
    fn test_ipv6_cidr_type() {
        // Arrange
        // Act
        // Assert
        test_helpers::assert_normal_type::<Ipv6Cidr>();
    }

    #[test]
    fn test_construct_ipv6_cidr() {
        // Arrange
        let expected_prefix: u8 = 64;
        let expected_address = Ipv6Addr::from_str(EXPECTED_IPV6_STR).unwrap();

        // Act
        let actual_cidr: Ipv6Cidr = Ipv6Cidr::new(expected_address, expected_prefix).unwrap();

        // Assert
        assert_eq!(actual_cidr.ip, expected_address);
        assert_eq!(actual_cidr.prefix, expected_prefix);
    }

    #[test]
    fn test_construct_ipv6_cidr_wrong_prefix() {
        // Arrange
        let expected_prefix: u8 = 129;
        let expected_address = Ipv6Addr::from_str(EXPECTED_IPV6_STR).unwrap();

        // Act
        let actual_result = Ipv6Cidr::new(expected_address, expected_prefix);

        // Assert
        assert!(matches!(actual_result, Err(Ipv6CidrError::PrefixLen(_))));
    }

    #[test]
    fn test_parse_ipv6_cidr_success() {
        // Arrange
        let expected_prefix: u8 = 64;
        let expected_cidr_string: String = format!("{EXPECTED_IPV6_STR}/{expected_prefix}");
        let expected_binary_address: u128 =
            Ipv6Addr::from_str(EXPECTED_IPV6_STR).unwrap().to_bits();
        let expected_cidr = Ipv6Cidr {
            ip: Ipv6Addr::from_bits(expected_binary_address),
            prefix: expected_prefix,
        };

        // Act
        let actual_cidr: Ipv6Cidr = expected_cidr_string.parse().unwrap();

        // Assert
        assert_eq!(actual_cidr, expected_cidr);
    }

    #[test]
    fn test_parse_ipv6_cidr_invalid_format() {
        // Arrange

        // Act
        let actual_result: Result<Ipv6Cidr, Ipv6CidrError> = EXPECTED_IPV6_STR.parse();

        // Assert
        assert_eq!(actual_result, Err(Ipv6CidrError::Format));
    }

    #[test]
    fn test_parse_ipv6_cidr_invalid_cidr_invalid_ip() {
        // Arrange
        let expected_prefix: u8 = 24;
        let expected_invalid_ip = "2001:db8:1::not_a_number";
        let expected_cidr_string: String = format!("{expected_invalid_ip}/{expected_prefix}");

        // Act
        let actual_result: Result<Ipv6Cidr, Ipv6CidrError> = expected_cidr_string.parse();

        // Assert
        assert!(matches!(actual_result, Err(Ipv6CidrError::IpParse(_))));
    }

    #[test]
    fn test_parse_ipv6_cidr_prefix_nan() {
        // Arrange
        let expected_cidr_string: String = format!("{EXPECTED_IPV6_STR}/not_a_number");

        // Act
        let actual_result: Result<Ipv6Cidr, Ipv6CidrError> = expected_cidr_string.parse();

        // Assert
        assert!(matches!(actual_result, Err(Ipv6CidrError::PrefixNan)));
    }

    #[test]
    fn test_addr() {
        // Arrange
        let expected_prefix_len: u8 = 64;
        let expected_address = Ipv6Addr::from_str(EXPECTED_IPV6_STR).unwrap();
        let expected_ipv6_cidr = Ipv6Cidr::new(
            EXPECTED_IPV6_STR.parse::<Ipv6Addr>().unwrap(),
            expected_prefix_len,
        )
        .unwrap();

        // Act
        let actual_addr = expected_ipv6_cidr.addr();

        // Assert
        assert_eq!(actual_addr, expected_address);
    }

    #[test]
    fn test_netmask() {
        // Arrange
        let expected_prefix_len: u8 = 64;
        let expected_netmask = Ipv6Addr::from_str("ffff:ffff:ffff:ffff::").unwrap();
        let expected_ipv6_cidr = Ipv6Cidr::new(
            EXPECTED_IPV6_STR.parse::<Ipv6Addr>().unwrap(),
            expected_prefix_len,
        )
        .unwrap();

        // Act
        let actual_netmask = expected_ipv6_cidr.netmask();

        // Assert
        assert_eq!(actual_netmask, expected_netmask);
    }

    #[test]
    fn test_netmask_entire_network() {
        // Arrange
        let expected_prefix_len: u8 = 0;
        let expected_netmask = Ipv6Addr::from_str("::").unwrap();
        let expected_ipv6_cidr = Ipv6Cidr::new(
            EXPECTED_IPV6_STR.parse::<Ipv6Addr>().unwrap(),
            expected_prefix_len,
        )
        .unwrap();

        // Act
        let actual_netmask = expected_ipv6_cidr.netmask();

        // Assert
        assert_eq!(actual_netmask, expected_netmask);
    }

    #[test]
    fn test_netmask_single_ip() {
        // Arrange
        let expected_prefix_len: u8 = 128;
        let expected_netmask =
            Ipv6Addr::from_str("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").unwrap();
        let expected_ipv6_cidr = Ipv6Cidr::new(
            EXPECTED_IPV6_STR.parse::<Ipv6Addr>().unwrap(),
            expected_prefix_len,
        )
        .unwrap();

        // Act
        let actual_netmask = expected_ipv6_cidr.netmask();

        // Assert
        assert_eq!(actual_netmask, expected_netmask);
    }

    #[test]
    fn test_hostmask() {
        // Arrange
        let expected_prefix_len: u8 = 64;
        let expected_hostmask = Ipv6Addr::from_str("::ffff:ffff:ffff:ffff").unwrap();
        let expected_ipv6_cidr = Ipv6Cidr::new(
            EXPECTED_IPV6_STR.parse::<Ipv6Addr>().unwrap(),
            expected_prefix_len,
        )
        .unwrap();

        // Act
        let actual_hostmask = expected_ipv6_cidr.hostmask();

        // Assert
        assert_eq!(actual_hostmask, expected_hostmask);
    }

    #[test]
    fn test_hostmask_entire_network() {
        // Arrange
        let expected_prefix_len: u8 = 0;
        let expected_hostmask =
            Ipv6Addr::from_str("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").unwrap();
        let expected_ipv6_cidr = Ipv6Cidr::new(
            EXPECTED_IPV6_STR.parse::<Ipv6Addr>().unwrap(),
            expected_prefix_len,
        )
        .unwrap();

        // Act
        let actual_hostmask = expected_ipv6_cidr.hostmask();

        // Assert
        assert_eq!(actual_hostmask, expected_hostmask);
    }

    #[test]
    fn test_hostmask_single_ip() {
        // Arrange
        let expected_prefix_len: u8 = 128;
        let expected_hostmask = Ipv6Addr::from_str("::").unwrap();
        let expected_ipv6_cidr = Ipv6Cidr::new(
            EXPECTED_IPV6_STR.parse::<Ipv6Addr>().unwrap(),
            expected_prefix_len,
        )
        .unwrap();

        // Act
        let actual_hostmask = expected_ipv6_cidr.hostmask();

        // Assert
        assert_eq!(actual_hostmask, expected_hostmask);
    }

    #[test]
    fn test_network_address() {
        // Arrange
        let expected_prefix_len: u8 = 64;
        let expected_network_address = Ipv6Addr::from_str("2001:db8:1::").unwrap();
        let expected_ipv6_cidr = Ipv6Cidr::new(
            EXPECTED_IPV6_STR.parse::<Ipv6Addr>().unwrap(),
            expected_prefix_len,
        )
        .unwrap();

        // Act
        let actual_network_address = expected_ipv6_cidr.first_address();

        // Assert
        assert_eq!(actual_network_address, expected_network_address);
    }

    #[test]
    fn test_last_address() {
        // Arrange
        let expected_prefix_len: u8 = 64;
        let expected_last_address = Ipv6Addr::from_str("2001:db8:1::ffff:ffff:ffff:ffff").unwrap();
        let expected_ipv6_cidr = Ipv6Cidr::new(
            EXPECTED_IPV6_STR.parse::<Ipv6Addr>().unwrap(),
            expected_prefix_len,
        )
        .unwrap();

        // Act
        let actual_last_address = expected_ipv6_cidr.last_address();

        // Assert
        assert_eq!(actual_last_address, expected_last_address);
    }

    #[test]
    fn test_subnet_size_prefix_gt_96() {
        // Arrange
        let expected_prefix_len: u8 = 97;
        let expected_subnet_size: &str = "2147483648";
        let expected_ipv6_cidr = Ipv6Cidr::new(
            EXPECTED_IPV6_STR.parse::<Ipv6Addr>().unwrap(),
            expected_prefix_len,
        )
        .unwrap();

        // Act
        let actual_subnet_size: String = expected_ipv6_cidr.subnet_size();

        // Assert
        assert_eq!(actual_subnet_size, expected_subnet_size);
    }

    #[test]
    fn test_subnet_size_prefix_lte_96() {
        // Arrange
        let expected_prefix_len: u8 = 8;
        let expected_subnet_size: &str = "2^120";
        let expected_ipv6_cidr = Ipv6Cidr::new(
            EXPECTED_IPV6_STR.parse::<Ipv6Addr>().unwrap(),
            expected_prefix_len,
        )
        .unwrap();

        // Act
        let actual_subnet_size: String = expected_ipv6_cidr.subnet_size();

        // Assert
        assert_eq!(actual_subnet_size, expected_subnet_size);
    }
}
