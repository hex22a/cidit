use crate::inspector::Inspectable;
use crate::inspector::InspectionResult;
use crate::inspector::ipv4::Ipv4InspectionResult;
use crate::ip::ipv4::Address;
use crate::ip::ipv4::IPv4;
use std::str::FromStr;
use thiserror::Error;

const MAX_IPV4_CIDR_PREFIX_LEN: u8 = 32;
const POINT_TO_POINT_CIDR_PREFIX_LEN: u8 = 31;

/// Error parsing IPv4 CIDR
#[derive(Debug, Error, PartialEq)]
pub enum Ipv4CidrParseError {
    #[error("Invalid CIDR format (expected x.x.x.x/x)")]
    InvalidFormat,
    #[error("Invalid CIDR")]
    InvalidCidr,
}

#[derive(Debug, Error, PartialEq)]
pub(crate) enum Ipv4CidrPartsError {
    #[error("Invalid CIDR prefix: {0} (expected <= {max} )", max = MAX_IPV4_CIDR_PREFIX_LEN)]
    InvalidPrefix(u8),
}

/// An internal representation of IPv4 CIDR
#[derive(Debug, PartialEq, Eq)]
pub struct Ipv4Cidr {
    ip: IPv4,
    mask: IPv4,
    prefix: u8,
}

pub(crate) struct Ipv4CidrParts {
    address: u32,
    prefix: u8,
}

/// IPv4 Network
trait Ipv4Network {
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

impl TryFrom<Ipv4CidrParts> for Ipv4Cidr {
    type Error = Ipv4CidrPartsError;

    fn try_from(value: Ipv4CidrParts) -> Result<Self, Self::Error> {
        if value.prefix > MAX_IPV4_CIDR_PREFIX_LEN {
            return Err(Ipv4CidrPartsError::InvalidPrefix(value.prefix));
        }
        let mask = if value.prefix == 0 {
            IPv4::from(0)
        } else {
            IPv4::from(!0u32 << (MAX_IPV4_CIDR_PREFIX_LEN - value.prefix))
        };
        Ok(Self {
            ip: IPv4::from(value.address),
            mask,
            prefix: value.prefix,
        })
    }
}

impl FromStr for Ipv4Cidr {
    type Err = Ipv4CidrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ip_str, prefix) = s.split_once('/').ok_or(Ipv4CidrParseError::InvalidFormat)?;
        let ip: IPv4 = ip_str
            .parse::<IPv4>()
            .map_err(|_| Ipv4CidrParseError::InvalidCidr)?;
        let prefix: u8 = prefix
            .parse::<u8>()
            .map_err(|_| Ipv4CidrParseError::InvalidCidr)?;
        let cidr_parts: Ipv4CidrParts = Ipv4CidrParts {
            address: ip.addr(),
            prefix,
        };
        Self::try_from(cidr_parts).map_err(|_| Ipv4CidrParseError::InvalidCidr)
    }
}

impl Ipv4Network for Ipv4Cidr {
    fn network_address(&self) -> u32 {
        self.ip.addr() & self.mask.addr()
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

impl Ipv4Cidr {
    pub(crate) fn prefix_len(&self) -> u8 {
        self.prefix
    }

    pub(crate) fn addr(&self) -> IPv4 {
        self.ip
    }
}

impl Inspectable for Ipv4Cidr {
    fn inspect(&self) -> InspectionResult {
        let prefix_len = self.prefix_len();
        let human_readable_ip_part = self.addr().to_string();
        let network = if prefix_len >= POINT_TO_POINT_CIDR_PREFIX_LEN {
            String::from("")
        } else {
            IPv4::from(self.network_address()).to_string()
        };
        let first_usable_ip = self.first_usable();
        let broadcast = if prefix_len >= POINT_TO_POINT_CIDR_PREFIX_LEN {
            String::from("")
        } else {
            IPv4::from(self.broadcast_address()).to_string()
        };
        let last_usable_ip = self.last_usable();
        InspectionResult::V4(Ipv4InspectionResult {
            cidr: format!("{human_readable_ip_part}/{prefix_len}"),
            first_usable: IPv4::from(first_usable_ip).to_string(),
            last_usable: IPv4::from(last_usable_ip).to_string(),
            network,
            broadcast,
            address: human_readable_ip_part,
            prefix_length: prefix_len,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::inspector::Inspectable;
    use crate::inspector::InspectionResult;
    use crate::inspector::ipv4::Ipv4InspectionResult;
    use crate::ip::ipv4::{Address, IPv4};
    use crate::test_helpers;

    const EXPECTED_BINARY_ADDRESS: u32 = 0b00001010_00010110_10000111_10010000;
    const EXPECTED_IPV4_STR: &str = "10.22.135.144";

    #[test]
    fn test_cidr_parse_error_type() {
        // Arrange
        // Act
        // Assert
        test_helpers::assert_error::<Ipv4CidrParseError>();
    }

    #[test]
    fn test_cidr_parts_error_type() {
        // Arrange
        // Act
        // Assert
        test_helpers::assert_error::<Ipv4CidrPartsError>();
    }

    #[test]
    fn test_ipv4_cidr_type() {
        // Arrange
        // Act
        // Assert
        test_helpers::assert_normal_type::<Ipv4Cidr>();
    }

    #[test]
    fn test_ipv4cidr_try_from_success() {
        // Arrange
        let expected_prefix: u8 = 24;
        let expected_cidr_parts: Ipv4CidrParts = Ipv4CidrParts {
            address: EXPECTED_BINARY_ADDRESS,
            prefix: expected_prefix,
        };

        let expected_binary_mask: u32 = 0b11111111_11111111_11111111_00000000;

        // Act
        let actual_cidr: Ipv4Cidr = Ipv4Cidr::try_from(expected_cidr_parts).unwrap();

        // Assert
        assert_eq!(actual_cidr.ip.addr(), EXPECTED_BINARY_ADDRESS);
        assert_eq!(actual_cidr.mask.addr(), expected_binary_mask);
        assert_eq!(actual_cidr.prefix, expected_prefix);
    }

    #[test]
    fn test_ipv4cidr_try_from_single_ip() {
        // Arrange
        let expected_prefix: u8 = 32;
        let expected_cidr_parts: Ipv4CidrParts = Ipv4CidrParts {
            address: EXPECTED_BINARY_ADDRESS,
            prefix: expected_prefix,
        };

        let expected_binary_mask: u32 = 0b11111111_11111111_11111111_11111111;

        // Act
        let actual_cidr: Ipv4Cidr = Ipv4Cidr::try_from(expected_cidr_parts).unwrap();

        // Assert
        assert_eq!(actual_cidr.ip.addr(), EXPECTED_BINARY_ADDRESS);
        assert_eq!(actual_cidr.mask.addr(), expected_binary_mask);
        assert_eq!(actual_cidr.prefix, expected_prefix);
    }

    #[test]
    fn test_ipv4cidr_try_from_entire_network() {
        // Arrange
        let expected_prefix: u8 = 0;
        let expected_cidr_parts: Ipv4CidrParts = Ipv4CidrParts {
            address: EXPECTED_BINARY_ADDRESS,
            prefix: expected_prefix,
        };

        let expected_binary_mask: u32 = 0b00000000_00000000_00000000_00000000;

        // Act
        let actual_cidr: Ipv4Cidr = Ipv4Cidr::try_from(expected_cidr_parts).unwrap();

        // Assert
        assert_eq!(actual_cidr.ip.addr(), EXPECTED_BINARY_ADDRESS);
        assert_eq!(actual_cidr.mask.addr(), expected_binary_mask);
        assert_eq!(actual_cidr.prefix, expected_prefix);
    }

    #[test]
    fn test_ipv4cidr_try_from_wrong_prefix() {
        // Arrange
        let expected_prefix: u8 = 33;
        let expected_cidr_parts: Ipv4CidrParts = Ipv4CidrParts {
            address: EXPECTED_BINARY_ADDRESS,
            prefix: expected_prefix,
        };

        // Act
        let actual_result: Result<Ipv4Cidr, Ipv4CidrPartsError> =
            Ipv4Cidr::try_from(expected_cidr_parts);

        // Assert
        assert_eq!(
            actual_result,
            Err(Ipv4CidrPartsError::InvalidPrefix(expected_prefix))
        );
    }

    #[test]
    fn test_parse_ipv4_cidr_success() {
        // Arrange
        let expected_prefix: u8 = 24;
        let expected_binary_mask: u32 = 0b11111111_11111111_11111111_00000000;
        let expected_cidr_string: String = format!("{EXPECTED_IPV4_STR}/{expected_prefix}");
        let expected_cidr = Ipv4Cidr {
            ip: IPv4::from(EXPECTED_BINARY_ADDRESS),
            mask: IPv4::from(expected_binary_mask),
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
        let actual_result: Result<Ipv4Cidr, Ipv4CidrParseError> = EXPECTED_IPV4_STR.parse();

        // Assert
        assert_eq!(actual_result, Err(Ipv4CidrParseError::InvalidFormat));
    }

    #[test]
    fn test_parse_ipv4_cidr_invalid_cidr_invalid_ip() {
        // Arrange
        let expected_prefix: u8 = 24;
        let expected_invalid_ip = "192.168.not_a_number.1";
        let expected_cidr_string: String = format!("{expected_invalid_ip}/{expected_prefix}");

        // Act
        let actual_result: Result<Ipv4Cidr, Ipv4CidrParseError> = expected_cidr_string.parse();

        // Assert
        assert_eq!(actual_result, Err(Ipv4CidrParseError::InvalidCidr));
    }

    #[test]
    fn test_network_address() {
        // Arrange
        let expected_prefix: u8 = 24;
        let expected_binary_mask: u32 = 0b11111111_11111111_11111111_00000000;
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_network_address: u32 = 0b00001010_01011000_10000111_00000000;
        let expected_cidr = Ipv4Cidr {
            ip: IPv4::from(expected_binary_address),
            mask: IPv4::from(expected_binary_mask),
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
        let expected_binary_mask: u32 = 0b11111111_11111111_11111111_00000000;
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_broadcast_address: u32 = 0b00001010_01011000_10000111_11111111;
        let expected_cidr = Ipv4Cidr {
            ip: IPv4::from(expected_binary_address),
            mask: IPv4::from(expected_binary_mask),
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
        let expected_binary_mask: u32 = 0b00000000_00000000_00000000_00000000;
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_broadcast_address: u32 = 0b11111111_11111111_11111111_11111111;
        let expected_cidr = Ipv4Cidr {
            ip: IPv4::from(expected_binary_address),
            mask: IPv4::from(expected_binary_mask),
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
        let expected_binary_mask: u32 = 0b11111111_11111111_11111111_11111111;
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_broadcast_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_cidr = Ipv4Cidr {
            ip: IPv4::from(expected_binary_address),
            mask: IPv4::from(expected_binary_mask),
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
        let expected_binary_mask: u32 = 0b11111111_11111111_11111111_00000000;
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_first_usable: u32 = 0b00001010_01011000_10000111_00000001;
        let expected_cidr = Ipv4Cidr {
            ip: IPv4::from(expected_binary_address),
            mask: IPv4::from(expected_binary_mask),
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
        let expected_binary_mask: u32 = 0b11111111_11111111_11111111_11111110;
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_first_usable: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_cidr = Ipv4Cidr {
            ip: IPv4::from(expected_binary_address),
            mask: IPv4::from(expected_binary_mask),
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
        let expected_binary_mask: u32 = 0b11111111_11111111_11111111_11111111;
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_first_usable: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_cidr = Ipv4Cidr {
            ip: IPv4::from(expected_binary_address),
            mask: IPv4::from(expected_binary_mask),
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
        let expected_binary_mask: u32 = 0b11111111_11111111_11111111_00000000;
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_last_usable: u32 = 0b00001010_01011000_10000111_11111110;
        let expected_cidr = Ipv4Cidr {
            ip: IPv4::from(expected_binary_address),
            mask: IPv4::from(expected_binary_mask),
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
        let expected_binary_mask: u32 = 0b11111111_11111111_11111111_11111110;
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_last_usable: u32 = 0b00001010_01011000_10000111_10010001;
        let expected_cidr = Ipv4Cidr {
            ip: IPv4::from(expected_binary_address),
            mask: IPv4::from(expected_binary_mask),
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
        let expected_binary_mask: u32 = 0b11111111_11111111_11111111_11111111;
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_last_usable: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_cidr = Ipv4Cidr {
            ip: IPv4::from(expected_binary_address),
            mask: IPv4::from(expected_binary_mask),
            prefix: expected_prefix,
        };

        // Act
        let actual_last_usable = expected_cidr.last_usable();

        // Assert
        assert_eq!(actual_last_usable, expected_last_usable);
    }

    #[test]
    fn test_inspect() {
        // Arrange
        let expected_prefix: u8 = 24;
        let expected_binary_mask: u32 = 0b11111111_11111111_11111111_00000000;
        let expected_cidr_string: String = format!("{EXPECTED_IPV4_STR}/{expected_prefix}");
        let expected_subnet_address: String = String::from("10.22.135.0");
        let expected_first_usable_ip: String = String::from("10.22.135.1");
        let expected_last_usable_ip: String = String::from("10.22.135.254");
        let expected_broadcast_ip: String = String::from("10.22.135.255");
        let expected_inspection_result: InspectionResult =
            InspectionResult::V4(Ipv4InspectionResult {
                cidr: expected_cidr_string,
                first_usable: expected_first_usable_ip,
                last_usable: expected_last_usable_ip,
                broadcast: expected_broadcast_ip,
                network: expected_subnet_address,
                address: EXPECTED_IPV4_STR.to_string(),
                prefix_length: expected_prefix,
            });
        let expected_cidr = Ipv4Cidr {
            ip: IPv4::from(EXPECTED_BINARY_ADDRESS),
            mask: IPv4::from(expected_binary_mask),
            prefix: expected_prefix,
        };

        // Act
        let actual_inspection_result: InspectionResult = expected_cidr.inspect();

        // Assert
        assert_eq!(actual_inspection_result, expected_inspection_result);
    }

    #[test]
    fn test_inspect_rfc_3021() {
        // Arrange
        let expected_prefix: u8 = 31;
        let expected_binary_mask: u32 = 0b11111111_11111111_11111111_11111110;
        let expected_cidr_string: String = format!("{EXPECTED_IPV4_STR}/{expected_prefix}");
        let expected_subnet_address: String = String::from("");
        let expected_first_usable_ip: String = String::from(EXPECTED_IPV4_STR);
        let expected_last_usable_ip: String = String::from("10.22.135.145");
        let expected_broadcast_ip: String = String::from("");
        let expected_inspection_result: InspectionResult =
            InspectionResult::V4(Ipv4InspectionResult {
                cidr: expected_cidr_string,
                first_usable: expected_first_usable_ip,
                last_usable: expected_last_usable_ip,
                broadcast: expected_broadcast_ip,
                network: expected_subnet_address,
                address: String::from(EXPECTED_IPV4_STR),
                prefix_length: expected_prefix,
            });
        let expected_cidr = Ipv4Cidr {
            ip: IPv4::from(EXPECTED_BINARY_ADDRESS),
            mask: IPv4::from(expected_binary_mask),
            prefix: expected_prefix,
        };

        // Act
        let actual_inspection_result: InspectionResult = expected_cidr.inspect();

        // Assert
        assert_eq!(actual_inspection_result, expected_inspection_result);
    }

    #[test]
    fn test_inspect_single_ip() {
        // Arrange
        let expected_prefix: u8 = 32;
        let expected_binary_mask: u32 = 0b11111111_11111111_11111111_11111111;
        let expected_cidr_string: String = format!("{EXPECTED_IPV4_STR}/{expected_prefix}");
        let expected_subnet_address: String = String::from("");
        let expected_first_usable_ip: String = String::from(EXPECTED_IPV4_STR);
        let expected_last_usable_ip: String = String::from(EXPECTED_IPV4_STR);
        let expected_broadcast_ip: String = String::from("");
        let expected_inspection_result: InspectionResult =
            InspectionResult::V4(Ipv4InspectionResult {
                cidr: expected_cidr_string,
                first_usable: expected_first_usable_ip,
                last_usable: expected_last_usable_ip,
                broadcast: expected_broadcast_ip,
                network: expected_subnet_address,
                address: String::from(EXPECTED_IPV4_STR),
                prefix_length: expected_prefix,
            });
        let expected_cidr = Ipv4Cidr {
            ip: IPv4::from(EXPECTED_BINARY_ADDRESS),
            mask: IPv4::from(expected_binary_mask),
            prefix: expected_prefix,
        };

        // Act
        let actual_inspection_result: InspectionResult = expected_cidr.inspect();

        // Assert
        assert_eq!(actual_inspection_result, expected_inspection_result);
    }
}
