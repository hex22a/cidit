use std::{net::Ipv4Addr, str::FromStr};
use thiserror::Error;

const MAX_IPV4_CIDR_PREFIX_LEN: u8 = 32;
pub const POINT_TO_POINT_CIDR_PREFIX_LEN: u8 = 31;

/// Error parsing IPv4 CIDR
#[derive(Debug, Error, PartialEq)]
pub enum Ipv4CidrError {
    #[error("Invalid CIDR format (expected x.x.x.x/x)")]
    InvalidFormat,
    #[error("Invalid CIDR")]
    InvalidCidr,
    #[error("Invalid CIDR prefix: {0} (expected <= {max} )", max = MAX_IPV4_CIDR_PREFIX_LEN)]
    InvalidPrefix(u8),
}

/// Internal representation of IPv4 CIDR
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Ipv4Cidr {
    ip: Ipv4Addr,
    prefix: u8,
}

impl Ipv4Cidr {
    pub fn new(address: u32, prefix: u8) -> Result<Self, Ipv4CidrError> {
        if prefix > MAX_IPV4_CIDR_PREFIX_LEN {
            return Err(Ipv4CidrError::InvalidPrefix(prefix));
        }
        Ok(Self {
            ip: Ipv4Addr::from_bits(address),
            prefix,
        })
    }
}

/// IPv4 Network
pub trait Ipv4Network {
    /// Get address part
    fn addr(&self) -> Ipv4Addr;

    /// Get prefix length
    fn prefix_len(&self) -> u8;

    /// Gets network mask address
    fn netmask(&self) -> Ipv4Addr;

    /// Gets arithmetical network address for all network masks
    /// including /31 for point-to-point connections and /32 for single host.
    /// [RFC 3021](https://datatracker.ietf.org/doc/html/rfc3021)
    fn network_address(&self) -> u32;

    /// Gets arithmetical broadcast address for all network masks
    /// including /31 for point-to-point connections and /32 for single host.
    /// [RFC 3021](https://datatracker.ietf.org/doc/html/rfc3021)
    fn broadcast_address(&self) -> u32;

    /// Gets first usable IP address.
    /// For /31 network mask is the same as arithmetical network address
    fn first_usable(&self) -> u32;

    /// Gets last usable IP address.
    /// For /31 network mask is the same as arithmetical broadcast address
    fn last_usable(&self) -> u32;
}

impl FromStr for Ipv4Cidr {
    type Err = Ipv4CidrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ip_str, prefix) = s.split_once('/').ok_or(Ipv4CidrError::InvalidFormat)?;
        let ip: Ipv4Addr = ip_str.parse().map_err(|_| Ipv4CidrError::InvalidCidr)?;
        let prefix: u8 = prefix.parse().map_err(|_| Ipv4CidrError::InvalidCidr)?;
        Self::new(ip.to_bits(), prefix)
    }
}

impl Ipv4Network for Ipv4Cidr {
    fn prefix_len(&self) -> u8 {
        self.prefix
    }

    fn addr(&self) -> Ipv4Addr {
        self.ip
    }

    fn netmask(&self) -> Ipv4Addr {
        let mask = if self.prefix == 0 {
            0
        } else {
            !0u32 << (MAX_IPV4_CIDR_PREFIX_LEN - self.prefix)
        };
        Ipv4Addr::from_bits(mask)
    }

    fn network_address(&self) -> u32 {
        self.ip.to_bits() & self.netmask().to_bits()
    }

    fn broadcast_address(&self) -> u32 {
        if self.prefix == MAX_IPV4_CIDR_PREFIX_LEN {
            self.network_address()
        } else {
            self.network_address() + (!0u32 >> self.prefix)
        }
    }

    fn first_usable(&self) -> u32 {
        let network_address = self.network_address();
        if self.prefix >= POINT_TO_POINT_CIDR_PREFIX_LEN {
            network_address
        } else {
            network_address + 1
        }
    }

    fn last_usable(&self) -> u32 {
        let broadcast_address = self.broadcast_address();
        if self.prefix >= POINT_TO_POINT_CIDR_PREFIX_LEN {
            broadcast_address
        } else {
            broadcast_address - 1
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_helpers;

    const EXPECTED_BINARY_ADDRESS: u32 = 0b00001010_00010110_10000111_10010000;
    const EXPECTED_IPV4_STR: &str = "10.22.135.144";

    #[test]
    fn test_cidr_parse_error_type() {
        // Arrange
        // Act
        // Assert
        test_helpers::assert_error::<Ipv4CidrError>();
    }

    #[test]
    fn test_ipv4_cidr_type() {
        // Arrange
        // Act
        // Assert
        test_helpers::assert_normal_type::<Ipv4Cidr>();
    }

    #[test]
    fn test_construct_ipv4_cidr() {
        // Arrange
        let expected_prefix: u8 = 24;

        // Act
        let actual_cidr: Ipv4Cidr =
            Ipv4Cidr::new(EXPECTED_BINARY_ADDRESS, expected_prefix).unwrap();

        // Assert
        assert_eq!(actual_cidr.ip.to_bits(), EXPECTED_BINARY_ADDRESS);
        assert_eq!(actual_cidr.prefix, expected_prefix);
    }

    #[test]
    fn test_construct_ipv4_cidr_wrong_prefix() {
        // Arrange
        let expected_prefix: u8 = 33;

        // Act
        let actual_result = Ipv4Cidr::new(EXPECTED_BINARY_ADDRESS, expected_prefix);

        // Assert
        assert!(matches!(
            actual_result,
            Err(Ipv4CidrError::InvalidPrefix(_))
        ));
    }

    #[test]
    fn test_parse_ipv4_cidr_success() {
        // Arrange
        let expected_prefix: u8 = 24;
        let expected_cidr_string: String = format!("{EXPECTED_IPV4_STR}/{expected_prefix}");
        let expected_cidr = Ipv4Cidr {
            ip: Ipv4Addr::from_bits(EXPECTED_BINARY_ADDRESS),
            prefix: expected_prefix,
        };

        // Act
        let actual_cidr: Ipv4Cidr = expected_cidr_string.parse().unwrap();

        // Assert
        assert_eq!(actual_cidr, expected_cidr);
    }

    #[test]
    fn test_parse_ipv4_cidr_invalid_format() {
        // Arrange

        // Act
        let actual_result: Result<Ipv4Cidr, Ipv4CidrError> = EXPECTED_IPV4_STR.parse();

        // Assert
        assert_eq!(actual_result, Err(Ipv4CidrError::InvalidFormat));
    }

    #[test]
    fn test_parse_ipv4_cidr_invalid_cidr_invalid_ip() {
        // Arrange
        let expected_prefix: u8 = 24;
        let expected_invalid_ip = "192.168.not_a_number.1";
        let expected_cidr_string: String = format!("{expected_invalid_ip}/{expected_prefix}");

        // Act
        let actual_result: Result<Ipv4Cidr, Ipv4CidrError> = expected_cidr_string.parse();

        // Assert
        assert_eq!(actual_result, Err(Ipv4CidrError::InvalidCidr));
    }

    #[test]
    fn test_netmask() {
        // Arrange
        let expected_prefix: u8 = 24;
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_binary_netmask: u32 = 0b11111111_11111111_11111111_00000000;
        let expected_netmask = Ipv4Addr::from_bits(expected_binary_netmask);
        let cidr = Ipv4Cidr {
            ip: Ipv4Addr::from_bits(expected_binary_address),
            prefix: expected_prefix,
        };

        // Act
        let actual_netmask = cidr.netmask();

        // Assert
        assert_eq!(actual_netmask, expected_netmask);
    }

    #[test]
    fn test_netmask_entire_network() {
        // Arrange
        let expected_prefix: u8 = 0;
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_binary_netmask: u32 = 0b00000000_00000000_00000000_00000000;
        let expected_netmask = Ipv4Addr::from_bits(expected_binary_netmask);
        let cidr = Ipv4Cidr {
            ip: Ipv4Addr::from_bits(expected_binary_address),
            prefix: expected_prefix,
        };

        // Act
        let actual_netmask = cidr.netmask();

        // Assert
        assert_eq!(actual_netmask, expected_netmask);
    }

    #[test]
    fn test_netmask_single_ip() {
        // Arrange
        let expected_prefix: u8 = 32;
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_binary_netmask: u32 = 0b11111111_11111111_11111111_11111111;
        let expected_netmask = Ipv4Addr::from_bits(expected_binary_netmask);
        let cidr = Ipv4Cidr {
            ip: Ipv4Addr::from_bits(expected_binary_address),
            prefix: expected_prefix,
        };

        // Act
        let actual_netmask = cidr.netmask();

        // Assert
        assert_eq!(actual_netmask, expected_netmask);
    }

    #[test]
    fn test_network_address() {
        // Arrange
        let expected_prefix: u8 = 24;
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_network_address: u32 = 0b00001010_01011000_10000111_00000000;
        let expected_cidr = Ipv4Cidr {
            ip: Ipv4Addr::from_bits(expected_binary_address),
            prefix: expected_prefix,
        };

        // Act
        let actual_network_address: u32 = expected_cidr.network_address();

        // Assert
        assert_eq!(actual_network_address, expected_network_address);
    }

    #[test]
    fn test_broadcast_address() {
        // Arrange
        let expected_prefix: u8 = 24;
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_broadcast_address: u32 = 0b00001010_01011000_10000111_11111111;
        let expected_cidr = Ipv4Cidr {
            ip: Ipv4Addr::from_bits(expected_binary_address),
            prefix: expected_prefix,
        };

        // Act
        let actual_broadcast_address: u32 = expected_cidr.broadcast_address();

        // Assert
        assert_eq!(actual_broadcast_address, expected_broadcast_address);
    }

    #[test]
    fn test_broadcast_address_entire_network() {
        // Arrange
        let expected_prefix: u8 = 0;
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_broadcast_address: u32 = 0b11111111_11111111_11111111_11111111;
        let expected_cidr = Ipv4Cidr {
            ip: Ipv4Addr::from_bits(expected_binary_address),
            prefix: expected_prefix,
        };

        // Act
        let actual_broadcast_address: u32 = expected_cidr.broadcast_address();

        // Assert
        assert_eq!(actual_broadcast_address, expected_broadcast_address);
    }

    #[test]
    fn test_broadcast_address_single_ip() {
        // Arrange
        let expected_prefix: u8 = 32;
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_broadcast_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_cidr = Ipv4Cidr {
            ip: Ipv4Addr::from_bits(expected_binary_address),
            prefix: expected_prefix,
        };

        // Act
        let actual_broadcast_address: u32 = expected_cidr.broadcast_address();

        // Assert
        assert_eq!(actual_broadcast_address, expected_broadcast_address);
    }

    #[test]
    fn test_first_usable() {
        // Arrange
        let expected_prefix: u8 = 24;
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_first_usable: u32 = 0b00001010_01011000_10000111_00000001;
        let expected_cidr = Ipv4Cidr {
            ip: Ipv4Addr::from_bits(expected_binary_address),
            prefix: expected_prefix,
        };

        // Act
        let actual_first_usable = expected_cidr.first_usable();

        // Assert
        assert_eq!(actual_first_usable, expected_first_usable);
    }

    #[test]
    fn test_first_usable_rfc_3021() {
        // Arrange
        let expected_prefix: u8 = 31;
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_first_usable: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_cidr = Ipv4Cidr {
            ip: Ipv4Addr::from_bits(expected_binary_address),
            prefix: expected_prefix,
        };

        // Act
        let actual_first_usable = expected_cidr.first_usable();

        // Assert
        assert_eq!(actual_first_usable, expected_first_usable);
    }

    #[test]
    fn test_first_usable_single_ip() {
        // Arrange
        let expected_prefix: u8 = 32;
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_first_usable: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_cidr = Ipv4Cidr {
            ip: Ipv4Addr::from_bits(expected_binary_address),
            prefix: expected_prefix,
        };

        // Act
        let actual_first_usable = expected_cidr.first_usable();

        // Assert
        assert_eq!(actual_first_usable, expected_first_usable);
    }

    #[test]
    fn test_last_usable() {
        // Arrange
        let expected_prefix: u8 = 24;
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_last_usable: u32 = 0b00001010_01011000_10000111_11111110;
        let expected_cidr = Ipv4Cidr {
            ip: Ipv4Addr::from_bits(expected_binary_address),
            prefix: expected_prefix,
        };

        // Act
        let actual_last_usable = expected_cidr.last_usable();

        // Assert
        assert_eq!(actual_last_usable, expected_last_usable);
    }

    #[test]
    fn test_last_usable_rfc_3021() {
        // Arrange
        let expected_prefix: u8 = 31;
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_last_usable: u32 = 0b00001010_01011000_10000111_10010001;
        let expected_cidr = Ipv4Cidr {
            ip: Ipv4Addr::from_bits(expected_binary_address),
            prefix: expected_prefix,
        };

        // Act
        let actual_last_usable = expected_cidr.last_usable();

        // Assert
        assert_eq!(actual_last_usable, expected_last_usable);
    }

    #[test]
    fn test_last_usable_single_ip() {
        // Arrange
        let expected_prefix: u8 = 32;
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_last_usable: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_cidr = Ipv4Cidr {
            ip: Ipv4Addr::from_bits(expected_binary_address),
            prefix: expected_prefix,
        };

        // Act
        let actual_last_usable = expected_cidr.last_usable();

        // Assert
        assert_eq!(actual_last_usable, expected_last_usable);
    }
}
