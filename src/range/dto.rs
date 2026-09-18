use serde::Serialize;
use tabled::Tabled;

use crate::{AddressRange, IpNetwork, IpRange};

#[derive(Debug, Tabled, PartialEq)]
pub struct RangeCombinedInfo {
    ip_ver: &'static str,
    start: String,
    end: String,
    cidr: String,
    cidr_start: String,
    cidr_end: String,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct RangeInfo {
    ip_version: &'static str,
    start: String,
    end: String,
    cidr: String,
    cidr_start: String,
    cidr_end: String,
}

impl From<IpRange> for Vec<RangeCombinedInfo> {
    fn from(value: IpRange) -> Self {
        match value {
            IpRange::V4(range) => range
                .cidrs()
                .into_iter()
                .flatten()
                .map(|cidr| RangeCombinedInfo {
                    ip_ver: "v4",
                    start: range.start().to_string(),
                    end: range.end().to_string(),
                    cidr: cidr.to_string(),
                    cidr_start: cidr.first_address().to_string(),
                    cidr_end: cidr.last_address().to_string(),
                })
                .collect(),

            IpRange::V6(range) => range
                .cidrs()
                .into_iter()
                .flatten()
                .map(|cidr| RangeCombinedInfo {
                    ip_ver: "v6",
                    start: range.start().to_string(),
                    end: range.end().to_string(),
                    cidr: cidr.to_string(),
                    cidr_start: cidr.first_address().to_string(),
                    cidr_end: cidr.last_address().to_string(),
                })
                .collect(),
        }
    }
}

impl From<IpRange> for Vec<RangeInfo> {
    fn from(value: IpRange) -> Self {
        match value {
            IpRange::V4(range) => range
                .cidrs()
                .into_iter()
                .flatten()
                .map(|cidr| RangeInfo {
                    ip_version: "v4",
                    start: range.start().to_string(),
                    end: range.end().to_string(),
                    cidr: cidr.to_string(),
                    cidr_start: cidr.first_address().to_string(),
                    cidr_end: cidr.last_address().to_string(),
                })
                .collect(),

            IpRange::V6(range) => range
                .cidrs()
                .into_iter()
                .flatten()
                .map(|cidr| RangeInfo {
                    ip_version: "v6",
                    start: range.start().to_string(),
                    end: range.end().to_string(),
                    cidr: cidr.to_string(),
                    cidr_start: cidr.first_address().to_string(),
                    cidr_end: cidr.last_address().to_string(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::{Ipv4Range, Ipv6Range, range::RangeMode};

    use super::*;

    const EXPECTED_IPV4_STR: &str = "10.0.0.0";
    const EXPECTED_IPV6_STR: &str = "2001:db8::";

    #[test]
    fn test_cidrs_v4() {
        // Arrange
        let expected_start = String::from("10.0.0.10").parse().unwrap();
        let expected_end = String::from("10.0.0.20").parse().unwrap();
        let expected_common_cidr = String::from("10.0.0.0/27").parse().unwrap();
        let expected_cidrs = Some(vec![expected_common_cidr]);
        let mut range = IpRange::V4(Ipv4Range::new(expected_start, expected_end));
        range.find_cidr(RangeMode::SmallestCommon);

        // Act
        let actual_cidrs = range.cidrs();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs.as_deref());
    }

    #[test]
    fn test_cidrs_v4_no_find_called() {
        // Arrange
        let expected_start = String::from("10.0.0.10").parse().unwrap();
        let expected_end = String::from("10.0.0.20").parse().unwrap();
        let expected_cidrs = None;
        let range = IpRange::V4(Ipv4Range::new(expected_start, expected_end));

        // Act
        let actual_cidrs = range.cidrs();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs);
    }

    #[test]
    fn test_cidrs_v6() {
        // Arrange
        let expected_start = String::from("2001:db8::10").parse().unwrap();
        let expected_end = String::from("2001:db8::20").parse().unwrap();
        let expected_common_cidr = String::from("2001:db8::/122").parse().unwrap();
        let expected_cidrs = Some(vec![expected_common_cidr]);
        let mut range = IpRange::V6(Ipv6Range::new(expected_start, expected_end));
        range.find_cidr(RangeMode::SmallestCommon);

        // Act
        let actual_cidrs = range.cidrs();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs.as_deref());
    }

    #[test]
    fn test_cidrs_v6_no_find_called() {
        // Arrange
        let expected_start = String::from("2001:db8::10").parse().unwrap();
        let expected_end = String::from("2001:db8::20").parse().unwrap();
        let expected_cidrs = None;
        let range = IpRange::V6(Ipv6Range::new(expected_start, expected_end));

        // Act
        let actual_cidrs = range.cidrs();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs);
    }

    #[test]
    fn test_range_tabled_info_from_range_v4() {
        // Arrange
        let expected_range_start_string = String::from("10.0.0.10");
        let expected_range_end_string = String::from("10.0.0.20");
        let expected_range_start: Ipv4Addr = expected_range_start_string.parse().unwrap();
        let expected_range_end: Ipv4Addr = expected_range_end_string.parse().unwrap();
        let expected_prefix: u8 = 27;
        let expected_cidr_string: String = format!("{EXPECTED_IPV4_STR}/{expected_prefix}");
        let expected_cidr_start: String = String::from("10.0.0.0");
        let expected_cidr_end: String = String::from("10.0.0.31");
        let expected_range_info = vec![RangeCombinedInfo {
            ip_ver: "v4",
            start: expected_range_start_string,
            end: expected_range_end_string,
            cidr: expected_cidr_string,
            cidr_start: expected_cidr_start,
            cidr_end: expected_cidr_end,
        }];

        let mut range = IpRange::V4(Ipv4Range::new(expected_range_start, expected_range_end));
        range.find_cidr(RangeMode::SmallestCommon);

        // Act
        let actual_range_info: Vec<RangeCombinedInfo> = range.into();

        // Assert
        assert_eq!(actual_range_info, expected_range_info);
    }

    #[test]
    fn test_range_tabled_info_from_cidr_v6() {
        // Arrange
        let expected_range_start_string = String::from("2001:db8::10");
        let expected_range_end_string = String::from("2001:db8::20");
        let expected_range_start: Ipv6Addr = expected_range_start_string.parse().unwrap();
        let expected_range_end: Ipv6Addr = expected_range_end_string.parse().unwrap();
        let expected_cidr_start: String = String::from("2001:db8::");
        let expected_cidr_end: String = String::from("2001:db8::3f");
        let expected_prefix_len: u8 = 122;
        let expected_cidr_str: String = format!("{EXPECTED_IPV6_STR}/{expected_prefix_len}");
        let expected_range_info = vec![RangeCombinedInfo {
            ip_ver: "v6",
            start: expected_range_start_string,
            end: expected_range_end_string,
            cidr: expected_cidr_str,
            cidr_start: expected_cidr_start,
            cidr_end: expected_cidr_end,
        }];

        let mut range = IpRange::V6(Ipv6Range::new(expected_range_start, expected_range_end));
        range.find_cidr(RangeMode::SmallestCommon);

        // Act
        let actual_range_info: Vec<RangeCombinedInfo> = range.into();

        // Assert
        assert_eq!(actual_range_info, expected_range_info);
    }

    #[test]
    fn test_range_json_info_from_range_v4() {
        // Arrange
        let expected_range_start_string = String::from("10.0.0.10");
        let expected_range_end_string = String::from("10.0.0.20");
        let expected_range_start: Ipv4Addr = expected_range_start_string.parse().unwrap();
        let expected_range_end: Ipv4Addr = expected_range_end_string.parse().unwrap();
        let expected_prefix: u8 = 27;
        let expected_cidr_string: String = format!("{EXPECTED_IPV4_STR}/{expected_prefix}");
        let expected_cidr_start: String = String::from("10.0.0.0");
        let expected_cidr_end: String = String::from("10.0.0.31");
        let expected_range_info = vec![RangeInfo {
            ip_version: "v4",
            start: expected_range_start_string,
            end: expected_range_end_string,
            cidr: expected_cidr_string,
            cidr_start: expected_cidr_start,
            cidr_end: expected_cidr_end,
        }];

        let mut range = IpRange::V4(Ipv4Range::new(expected_range_start, expected_range_end));
        range.find_cidr(RangeMode::SmallestCommon);

        // Act
        let actual_range_info: Vec<RangeInfo> = range.into();

        // Assert
        assert_eq!(actual_range_info, expected_range_info);
    }

    #[test]
    fn test_range_json_info_from_cidr_v6() {
        // Arrange
        let expected_range_start_string = String::from("2001:db8::10");
        let expected_range_end_string = String::from("2001:db8::20");
        let expected_range_start: Ipv6Addr = expected_range_start_string.parse().unwrap();
        let expected_range_end: Ipv6Addr = expected_range_end_string.parse().unwrap();
        let expected_cidr_start: String = String::from("2001:db8::");
        let expected_cidr_end: String = String::from("2001:db8::3f");
        let expected_prefix_len: u8 = 122;
        let expected_cidr_str: String = format!("{EXPECTED_IPV6_STR}/{expected_prefix_len}");
        let expected_range_info = vec![RangeInfo {
            ip_version: "v6",
            start: expected_range_start_string,
            end: expected_range_end_string,
            cidr: expected_cidr_str,
            cidr_start: expected_cidr_start,
            cidr_end: expected_cidr_end,
        }];

        let mut range = IpRange::V6(Ipv6Range::new(expected_range_start, expected_range_end));
        range.find_cidr(RangeMode::SmallestCommon);

        // Act
        let actual_range_info: Vec<RangeInfo> = range.into();

        // Assert
        assert_eq!(actual_range_info, expected_range_info);
    }
}
