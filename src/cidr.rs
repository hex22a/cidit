use std::str::FromStr;
use thiserror::Error;
use ipnet::{Ipv6Net, AddrParseError};
use crate::cidr::ipv4::Ipv4Cidr;
use crate::cidr::ipv4::Ipv4CidrParseError;

pub mod ipv4;
pub mod ipv6;

#[derive(Debug, Error)]
pub(crate) enum CidrParseError {
    #[error("Not a valid CIDR (v4 or v6)")]
    Neither {
        v4: Ipv4CidrParseError,
        v6: AddrParseError,
    }
}

pub(crate) enum Cidr {
    V4(Ipv4Cidr),
    V6(Ipv6Net),
}

impl FromStr for Cidr {
    type Err = CidrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v4_err = match s.parse::<Ipv4Cidr>() {
            Ok(v4) => return Ok(Cidr::V4(v4)),
            Err(e) => e,
        };

        let v6_err = match s.parse::<Ipv6Net>() {
            Ok(v6) => return Ok(Cidr::V6(v6)),
            Err(e) => e,
        };

        Err(CidrParseError::Neither {
            v4: v4_err,
            v6: v6_err,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Cidr;

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
            },
            _ => panic!("Expected Cidr::V4")
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
            },
            _ => panic!("Expected Cidr::V6")
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
