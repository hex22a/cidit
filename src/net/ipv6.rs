use std::{net::Ipv6Addr, str::FromStr};

use thiserror::Error;

const MAX_IPV6_CIDR_PREFIX_LEN: u8 = 128;
const MIN_REASONABLE_PREFIX_LEN: u8 = 96;

/// Error parsing IPv4 CIDR
#[derive(Debug, Error, PartialEq)]
pub enum Ipv6CidrError {
    #[error("Invalid CIDR format")]
    InvalidFormat,
    #[error("Invalid CIDR")]
    InvalidCidr,
    #[error("Invalid CIDR prefix: {0} (expected <= {max} )", max = MAX_IPV6_CIDR_PREFIX_LEN)]
    InvalidPrefix(u8),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Ipv6Cidr {
    ip: Ipv6Addr,
    prefix: u8,
}

impl Ipv6Cidr {
    pub fn new(address: u128, prefix: u8) -> Result<Self, Ipv6CidrError> {
        if prefix > MAX_IPV6_CIDR_PREFIX_LEN {
            return Err(Ipv6CidrError::InvalidPrefix(prefix));
        }
        Ok(Self {
            ip: Ipv6Addr::from_bits(address),
            prefix,
        })
    }
}

impl FromStr for Ipv6Cidr {
    type Err = Ipv6CidrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ip, prefix) = s.split_once('/').ok_or(Ipv6CidrError::InvalidFormat)?;
        let ip: Ipv6Addr = ip.parse().map_err(|_| Ipv6CidrError::InvalidCidr)?;
        let prefix: u8 = prefix.parse().map_err(|_| Ipv6CidrError::InvalidCidr)?;
        Self::new(ip.to_bits(), prefix)
    }
}

pub trait SubnetSize {
    fn subnet_size(&self) -> String;
}

impl SubnetSize for Ipv6Cidr {
    fn subnet_size(&self) -> String {
        let prefix_len: u8 = self.prefix;
        let power: u8 = MAX_IPV6_CIDR_PREFIX_LEN - prefix_len;
        if prefix_len < MIN_REASONABLE_PREFIX_LEN {
            format!("2^{}", power)
        } else {
            format!("{}", 1u128 << power)
        }
    }
}

/// IPv6 Network
pub trait Ipv6Network {
    /// Get address part
    fn addr(&self) -> Ipv6Addr;

    /// Get prefix length
    fn prefix_len(&self) -> u8;

    /// Gets network mask address
    fn netmask(&self) -> Ipv6Addr;

    /// Gets network mask address
    fn hostmask(&self) -> Ipv6Addr;

    /// Gets arithmetical network address
    fn network_address(&self) -> u128;

    /// Gets last available address
    fn last_address(&self) -> u128;
}

impl Ipv6Network for Ipv6Cidr {
    fn addr(&self) -> Ipv6Addr {
        self.ip
    }

    fn prefix_len(&self) -> u8 {
        self.prefix
    }

    fn netmask(&self) -> Ipv6Addr {
        let mask = if self.prefix == 0 {
            0
        } else {
            !0u128 << (MAX_IPV6_CIDR_PREFIX_LEN - self.prefix)
        };
        Ipv6Addr::from_bits(mask)
    }

    fn network_address(&self) -> u128 {
        self.ip.to_bits() & self.netmask().to_bits()
    }

    fn last_address(&self) -> u128 {
        self.network_address() + self.hostmask().to_bits()
    }

    fn hostmask(&self) -> Ipv6Addr {
        let mask = if self.prefix == MAX_IPV6_CIDR_PREFIX_LEN {
            0
        } else {
            !0u128 >> self.prefix
        };
        Ipv6Addr::from_bits(mask)
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
        let expected_binary_address: u128 =
            Ipv6Addr::from_str(EXPECTED_IPV6_STR).unwrap().to_bits();

        // Act
        let actual_cidr: Ipv6Cidr =
            Ipv6Cidr::new(expected_binary_address, expected_prefix).unwrap();

        // Assert
        assert_eq!(actual_cidr.ip.to_bits(), expected_binary_address);
        assert_eq!(actual_cidr.prefix, expected_prefix);
    }

    #[test]
    fn test_construct_ipv6_cidr_wrong_prefix() {
        // Arrange
        let expected_prefix: u8 = 129;
        let expected_binary_address: u128 =
            Ipv6Addr::from_str(EXPECTED_IPV6_STR).unwrap().to_bits();

        // Act
        let actual_result = Ipv6Cidr::new(expected_binary_address, expected_prefix);

        // Assert
        assert!(matches!(
            actual_result,
            Err(Ipv6CidrError::InvalidPrefix(_))
        ));
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
        assert_eq!(actual_result, Err(Ipv6CidrError::InvalidFormat));
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
        assert_eq!(actual_result, Err(Ipv6CidrError::InvalidCidr));
    }

    #[test]
    fn test_addr() {
        // Arrange
        let expected_prefix_len: u8 = 64;
        let expected_address = Ipv6Addr::from_str(EXPECTED_IPV6_STR).unwrap();
        let expected_ipv6_cidr = Ipv6Cidr::new(
            EXPECTED_IPV6_STR.parse::<Ipv6Addr>().unwrap().to_bits(),
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
            EXPECTED_IPV6_STR.parse::<Ipv6Addr>().unwrap().to_bits(),
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
            EXPECTED_IPV6_STR.parse::<Ipv6Addr>().unwrap().to_bits(),
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
            EXPECTED_IPV6_STR.parse::<Ipv6Addr>().unwrap().to_bits(),
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
            EXPECTED_IPV6_STR.parse::<Ipv6Addr>().unwrap().to_bits(),
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
            EXPECTED_IPV6_STR.parse::<Ipv6Addr>().unwrap().to_bits(),
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
            EXPECTED_IPV6_STR.parse::<Ipv6Addr>().unwrap().to_bits(),
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
        let expected_network_address = Ipv6Addr::from_str("2001:db8:1::").unwrap().to_bits();
        let expected_ipv6_cidr = Ipv6Cidr::new(
            EXPECTED_IPV6_STR.parse::<Ipv6Addr>().unwrap().to_bits(),
            expected_prefix_len,
        )
        .unwrap();

        // Act
        let actual_network_address = expected_ipv6_cidr.network_address();

        // Assert
        assert_eq!(actual_network_address, expected_network_address);
    }

    #[test]
    fn test_last_address() {
        // Arrange
        let expected_prefix_len: u8 = 64;
        let expected_last_address = Ipv6Addr::from_str("2001:db8:1::ffff:ffff:ffff:ffff")
            .unwrap()
            .to_bits();
        let expected_ipv6_cidr = Ipv6Cidr::new(
            EXPECTED_IPV6_STR.parse::<Ipv6Addr>().unwrap().to_bits(),
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
            EXPECTED_IPV6_STR.parse::<Ipv6Addr>().unwrap().to_bits(),
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
            EXPECTED_IPV6_STR.parse::<Ipv6Addr>().unwrap().to_bits(),
            expected_prefix_len,
        )
        .unwrap();

        // Act
        let actual_subnet_size: String = expected_ipv6_cidr.subnet_size();

        // Assert
        assert_eq!(actual_subnet_size, expected_subnet_size);
    }
}
