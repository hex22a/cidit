use std::str::FromStr;
use thiserror::Error;
use crate::inspector::InspectionResult;
use crate::inspector::Inspectable;
use crate::inspector::ipv4::Ipv4InspectionResult;
use crate::ip::ipv4::IPv4;

const MAX_IPV4_CIDR_PREFIX_LEN: u8 = 32;

#[derive(Debug, Error, PartialEq)]
pub enum Ipv4CidrParseError {
    #[error("Invalid CIDR format (expected x.x.x.x/x)")]
    InvalidFormat,
    #[error("Invalid CIDR")]
    InvalidCidr,
}

#[derive(Debug, Error, PartialEq)]
pub enum Ipv4CidrPartsError {
    #[error("Invalid CIDR prefix: {0} (expected <= {max} )", max = MAX_IPV4_CIDR_PREFIX_LEN)]
    InvalidPrefix(u8),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ipv4Cidr {
    ip: IPv4,
    mask: IPv4,
    prefix: u8,
}

pub struct Ipv4CidrParts {
    address: u32,
    prefix: u8,
}

trait Subnet {
    fn get_subnet_address(&self) -> u32;
}

impl TryFrom<Ipv4CidrParts> for Ipv4Cidr {
    type Error = Ipv4CidrPartsError;

    fn try_from(value: Ipv4CidrParts) -> Result<Self, Self::Error> {
        if value.prefix > MAX_IPV4_CIDR_PREFIX_LEN {
            return Err(Ipv4CidrPartsError::InvalidPrefix(value.prefix))
        }
        Ok( Self {
            ip: IPv4::from(value.address),
            mask: IPv4::from(!0u32 << (MAX_IPV4_CIDR_PREFIX_LEN - value.prefix)),
            prefix: value.prefix,
        })
    }
}

impl FromStr for Ipv4Cidr {
    type Err = Ipv4CidrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ip_str, prefix) = s.split_once('/').ok_or(Ipv4CidrParseError::InvalidFormat)?;
        let ip: IPv4 = ip_str.parse::<IPv4>().map_err(|_| Ipv4CidrParseError::InvalidCidr)?;
        let prefix: u8 = prefix.parse::<u8>().map_err(|_| Ipv4CidrParseError::InvalidCidr)?;
        let cidr_parts: Ipv4CidrParts = Ipv4CidrParts {
            address: ip.address,
            prefix,
        };
        Ok(Self::try_from(cidr_parts).map_err(|_| Ipv4CidrParseError::InvalidCidr)?)
    }
}

impl Subnet for Ipv4Cidr {
    fn get_subnet_address(&self) -> u32 {
        self.ip.address & self.mask.address
    }
}

impl Ipv4Cidr {
    pub(crate) fn prefix_len(&self) -> u8 {
        self.prefix.clone()
    }

    pub(crate) fn addr(&self) -> IPv4 {
        self.ip
    }
}

impl Inspectable for Ipv4Cidr {
    fn inspect(&self) -> InspectionResult {
        let subnet_address = self.get_subnet_address();
        let first_usable_ip = subnet_address + 1;
        let broadcast_address = subnet_address + (!0u32 >> self.prefix);
        let last_usable_ip = broadcast_address - 1;
        let human_readable_ip_part = self.ip.to_string();
        let prefix = self.prefix;
        InspectionResult::V4(Ipv4InspectionResult {
            cidr: format!("{human_readable_ip_part}/{prefix}"),
            first_usable: IPv4::from(first_usable_ip).to_string(),
            last_usable: IPv4::from(last_usable_ip).to_string(),
            subnet: IPv4::from(subnet_address).to_string(),
            broadcast: IPv4::from(broadcast_address).to_string(),
            address: human_readable_ip_part,
            prefix_len: prefix,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::inspector::InspectionResult;
    use crate::inspector::ipv4::Ipv4InspectionResult;
    use crate::inspector::Inspectable;
    use crate::ip::ipv4::IPv4;
    use super::{Ipv4CidrParseError, Ipv4CidrPartsError, Ipv4Cidr, Ipv4CidrParts};
    use super::Ipv4CidrParseError::InvalidCidr;
    use super::Subnet;

    const EXPECTED_BINARY_ADDRESS: u32 = 0b00001010_00010110_10000111_10010000;
    const EXPECTED_IPV4_STR: &str = "10.22.135.144";

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
        assert_eq!(actual_cidr.ip.address, EXPECTED_BINARY_ADDRESS);
        assert_eq!(actual_cidr.mask.address, expected_binary_mask);
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
        let actual_result: Result<Ipv4Cidr, Ipv4CidrPartsError> = Ipv4Cidr::try_from(expected_cidr_parts);

        // Assert
        assert_eq!(actual_result, Err(Ipv4CidrPartsError::InvalidPrefix(expected_prefix)));
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
        assert_eq!(actual_result, Err(InvalidCidr));
    }

    #[test]
    fn test_get_subnet_address() {
        // Arrange
        let expected_prefix: u8 = 24;
        let expected_binary_mask: u32 = 0b11111111_11111111_11111111_00000000;
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_subnet_address: u32 = 0b00001010_01011000_10000111_00000000;
        let expected_cidr = Ipv4Cidr {
            ip: IPv4::from(expected_binary_address),
            mask: IPv4::from(expected_binary_mask),
            prefix: expected_prefix,
        };

        // Act
        let actual_subnet_address: u32 = expected_cidr.get_subnet_address();

        // Assert
        assert_eq!(actual_subnet_address, expected_subnet_address);
    }

    #[test]
    fn test_inspect(){
        // Arrange
        let expected_prefix: u8 = 24;
        let expected_binary_mask: u32 = 0b11111111_11111111_11111111_00000000;
        let expected_cidr_string: String = format!("{EXPECTED_IPV4_STR}/{expected_prefix}");
        let expected_subnet_address: String = "10.22.135.0".to_string();
        let expected_first_usable_ip: String = "10.22.135.1".to_string();
        let expected_last_usable_ip: String = "10.22.135.254".to_string();
        let expected_broadcast_ip: String = "10.22.135.255".to_string();
        let expected_inspection_result: InspectionResult = InspectionResult::V4(Ipv4InspectionResult {
            cidr: expected_cidr_string,
            first_usable: expected_first_usable_ip,
            last_usable: expected_last_usable_ip,
            broadcast: expected_broadcast_ip,
            subnet: expected_subnet_address,
            address: EXPECTED_IPV4_STR.to_string(),
            prefix_len: expected_prefix,
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
