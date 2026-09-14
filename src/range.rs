use std::{
    net::{AddrParseError, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use thiserror::Error;

use crate::{
    Cidr,
    range::{ipv4::Ipv4Range, ipv6::Ipv6Range},
};

mod ipv4;
mod ipv6;

#[derive(Debug, Error)]
pub enum RangeError {
    #[error("One or both provided IPs are invalid: {0}")]
    IpParse(AddrParseError),
    #[error("Invalid range format. Supported formats: ip..ip, ip-ip, \"ip ip\"")]
    Format,
    #[error("Inconsistent IP versions. Both IPs in range should be either v4 or v6")]
    Inconsistent,
}

pub trait AddressRange {
    fn smallest_common_cidr(&self) -> Cidr;
    fn exact_fit(&self) -> Vec<Cidr>;
}

pub enum IpRange {
    V4(Ipv4Range),
    V6(Ipv6Range),
}

impl IpRange {
    fn parse_ranges(start: &str, end: &str) -> Result<Self, RangeError> {
        match start.parse::<Ipv4Addr>() {
            Ok(ipv4_start) => match end.parse::<Ipv4Addr>() {
                Ok(ipv4_end) => return Ok(IpRange::V4(Ipv4Range::new(ipv4_start, ipv4_end))),
                Err(ipv4_end_err) => match end.parse::<Ipv6Addr>() {
                    Ok(_) => return Err(RangeError::Inconsistent),
                    Err(_) => {
                        return Err(RangeError::IpParse(ipv4_end_err));
                    }
                },
            },
            Err(_) => match start.parse::<Ipv6Addr>() {
                Ok(ipv6_start) => match end.parse::<Ipv6Addr>() {
                    Ok(ipv6_end) => {
                        return Ok(IpRange::V6(Ipv6Range::new(ipv6_start, ipv6_end)));
                    }
                    Err(ipv6_end_err) => match end.parse::<Ipv4Addr>() {
                        Ok(_) => return Err(RangeError::Inconsistent),
                        Err(_) => {
                            return Err(RangeError::IpParse(ipv6_end_err));
                        }
                    },
                },
                Err(ipv6_start_err) => {
                    return Err(RangeError::IpParse(ipv6_start_err));
                }
            },
        }
    }
}

impl FromStr for IpRange {
    type Err = RangeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((start, end)) = s.split_once("..") {
            Self::parse_ranges(start, end)
        } else if let Some((start, end)) = s.split_once('-') {
            Self::parse_ranges(start, end)
        } else if let Some((start, end)) = s.split_once(' ') {
            Self::parse_ranges(start, end)
        } else {
            Err(RangeError::Format)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED_IPV4_START_STR: &str = "10.22.135.144";
    const EXPECTED_IPV4_END_STR: &str = "10.22.135.255";
    const EXPECTED_IPV6_START_STR: &str = "2001:db8:1::ab9:c0a8:102";
    const EXPECTED_IPV6_END_STR: &str = "2001:db8:1::ab9:c0a8:ffff";

    #[test]
    fn test_parse_ipv4_dots() {
        // Arrange
        let expected_ipv4_range_string =
            format!("{EXPECTED_IPV4_START_STR}..{EXPECTED_IPV4_END_STR}");

        // Act
        let actual_range: IpRange = expected_ipv4_range_string.parse().unwrap();

        // Assert
        match actual_range {
            IpRange::V4(range) => {
                assert_eq!(range.start().to_string(), EXPECTED_IPV4_START_STR);
                assert_eq!(range.end().to_string(), EXPECTED_IPV4_END_STR);
            }
            _ => panic!("Expected IpRange::V4"),
        }
    }

    #[test]
    fn test_parse_ipv4_dash() {
        // Arrange
        let expected_ipv4_range_string =
            format!("{EXPECTED_IPV4_START_STR}-{EXPECTED_IPV4_END_STR}");

        // Act
        let actual_range: IpRange = expected_ipv4_range_string.parse().unwrap();

        // Assert
        match actual_range {
            IpRange::V4(range) => {
                assert_eq!(range.start().to_string(), EXPECTED_IPV4_START_STR);
                assert_eq!(range.end().to_string(), EXPECTED_IPV4_END_STR);
            }
            _ => panic!("Expected IpRange::V4"),
        }
    }

    #[test]
    fn test_parse_ipv4_space() {
        // Arrange
        let expected_ipv4_range_string =
            format!("{EXPECTED_IPV4_START_STR} {EXPECTED_IPV4_END_STR}");

        // Act
        let actual_range: IpRange = expected_ipv4_range_string.parse().unwrap();

        // Assert
        match actual_range {
            IpRange::V4(range) => {
                assert_eq!(range.start().to_string(), EXPECTED_IPV4_START_STR);
                assert_eq!(range.end().to_string(), EXPECTED_IPV4_END_STR);
            }
            _ => panic!("Expected IpRange::V4"),
        }
    }

    #[test]
    fn test_parse_ipv6_dots() {
        // Arrange
        let expected_ipv6_range_string =
            format!("{EXPECTED_IPV6_START_STR}..{EXPECTED_IPV6_END_STR}");

        // Act
        let actual_range: IpRange = expected_ipv6_range_string.parse().unwrap();

        // Assert
        match actual_range {
            IpRange::V6(range) => {
                assert_eq!(range.start().to_string(), EXPECTED_IPV6_START_STR);
                assert_eq!(range.end().to_string(), EXPECTED_IPV6_END_STR);
            }
            _ => panic!("Expected IpRange::V6"),
        }
    }

    #[test]
    fn test_parse_ipv6_dash() {
        // Arrange
        let expected_ipv6_range_string =
            format!("{EXPECTED_IPV6_START_STR}-{EXPECTED_IPV6_END_STR}");

        // Act
        let actual_range: IpRange = expected_ipv6_range_string.parse().unwrap();

        // Assert
        match actual_range {
            IpRange::V6(range) => {
                assert_eq!(range.start().to_string(), EXPECTED_IPV6_START_STR);
                assert_eq!(range.end().to_string(), EXPECTED_IPV6_END_STR);
            }
            _ => panic!("Expected IpRange::V6"),
        }
    }

    #[test]
    fn test_parse_ipv6_space() {
        // Arrange
        let expected_ipv6_range_string =
            format!("{EXPECTED_IPV6_START_STR} {EXPECTED_IPV6_END_STR}");

        // Act
        let actual_range: IpRange = expected_ipv6_range_string.parse().unwrap();

        // Assert
        match actual_range {
            IpRange::V6(range) => {
                assert_eq!(range.start().to_string(), EXPECTED_IPV6_START_STR);
                assert_eq!(range.end().to_string(), EXPECTED_IPV6_END_STR);
            }
            _ => panic!("Expected IpRange::V6"),
        }
    }

    #[test]
    fn test_parse_invalid_string() {
        // Arrange
        let expected_invalid_string: &str = "some_invalid_string";

        // Act
        let actual_result = expected_invalid_string.parse::<IpRange>();

        // Assert
        assert!(matches!(actual_result, Err(RangeError::Format)));
    }

    #[test]
    fn test_parse_inconsistent_v4_v6() {
        // Arrange
        let expected_invalid_string = format!("{EXPECTED_IPV4_START_STR}..{EXPECTED_IPV6_END_STR}");

        // Act
        let actual_result = expected_invalid_string.parse::<IpRange>();

        // Assert
        assert!(matches!(actual_result, Err(RangeError::Inconsistent)));
    }

    #[test]
    fn test_parse_inconsistent_v6_v4() {
        // Arrange
        let expected_invalid_string = format!("{EXPECTED_IPV6_START_STR}..{EXPECTED_IPV4_END_STR}");

        // Act
        let actual_result = expected_invalid_string.parse::<IpRange>();

        // Assert
        assert!(matches!(actual_result, Err(RangeError::Inconsistent)));
    }

    #[test]
    fn test_parse_invalid_ip_dots() {
        // Arrange
        let expected_invalid_string: &str = "some..10.0.0.10";

        // Act
        let actual_result = expected_invalid_string.parse::<IpRange>();

        // Assert
        assert!(matches!(actual_result, Err(RangeError::IpParse(_))));
    }

    #[test]
    fn test_parse_invalid_ip_dash() {
        // Arrange
        let expected_invalid_string: &str = "some-10.0.0.10";

        // Act
        let actual_result = expected_invalid_string.parse::<IpRange>();

        // Assert
        assert!(matches!(actual_result, Err(RangeError::IpParse(_))));
    }

    #[test]
    fn test_parse_invalid_ip_space() {
        // Arrange
        let expected_invalid_string: &str = "some 10.0.0.10";

        // Act
        let actual_result = expected_invalid_string.parse::<IpRange>();

        // Assert
        assert!(matches!(actual_result, Err(RangeError::IpParse(_))));
    }
}
