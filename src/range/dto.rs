use serde::Serialize;
use tabled::Tabled;

use crate::{Cidr, IpNetwork, Ipv4Network};

#[derive(Debug, Tabled, PartialEq)]
pub struct RangeCombinedInfo {
    ip_ver: &'static str,
    cidr: String,
    start: String,
    end: String,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct RangeInfo {
    ip_version: &'static str,
    cidr: String,
    start: String,
    end: String,
}

impl From<Cidr> for RangeCombinedInfo {
    fn from(value: Cidr) -> Self {
        match value {
            Cidr::V4(v4) => Self {
                ip_ver: "v4",
                cidr: format!("{}/{}", v4.addr(), v4.prefix_len()),
                start: Ipv4Network::network_address(&v4).to_string(),
                end: v4.broadcast_address().to_string(),
            },
            Cidr::V6(v6) => Self {
                ip_ver: "v6",
                cidr: format!("{}/{}", v6.addr(), v6.prefix_len()),
                start: v6.network_address().to_string(),
                end: v6.last_address().to_string(),
            },
        }
    }
}

impl From<Cidr> for RangeInfo {
    fn from(value: Cidr) -> Self {
        match value {
            Cidr::V4(v4) => Self {
                ip_version: "v4",
                cidr: format!("{}/{}", v4.addr(), v4.prefix_len()),
                start: Ipv4Network::network_address(&v4).to_string(),
                end: v4.broadcast_address().to_string(),
            },
            Cidr::V6(v6) => Self {
                ip_version: "v6",
                cidr: format!("{}/{}", v6.addr(), v6.prefix_len()),
                start: v6.network_address().to_string(),
                end: v6.last_address().to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::{Ipv4Cidr, Ipv6Cidr};

    use super::*;

    const EXPECTED_IPV4_STR: &str = "10.22.135.144";
    const EXPECTED_IPV6_STR: &str = "2001:db8:1::ab9:c0a8:102";

    #[test]
    fn test_range_tabled_info_from_cidr_v4() {
        // Arrange
        let expected_address: Ipv4Addr = EXPECTED_IPV4_STR.parse().unwrap();
        let expected_prefix: u8 = 24;
        let expected_cidr_string: String = format!("{EXPECTED_IPV4_STR}/{expected_prefix}");
        let expected_subnet_address: String = String::from("10.22.135.0");
        let expected_broadcast_ip: String = String::from("10.22.135.255");
        let expected_cidr_info = RangeCombinedInfo {
            ip_ver: "v4",
            cidr: expected_cidr_string,
            start: expected_subnet_address,
            end: expected_broadcast_ip,
        };

        let expected_cidr = Ipv4Cidr::new(expected_address, expected_prefix).unwrap();

        // Act
        let actual_cidr_info = RangeCombinedInfo::from(Cidr::V4(expected_cidr));

        // Assert
        assert_eq!(actual_cidr_info, expected_cidr_info);
    }

    #[test]
    fn test_range_tabled_info_from_cidr_v6() {
        // Arrange
        let expected_address: Ipv6Addr = EXPECTED_IPV6_STR.parse().unwrap();
        let expected_prefix_len: u8 = 64;
        let expected_cidr_str: String = format!("{EXPECTED_IPV6_STR}/{expected_prefix_len}");
        let expected_cidr_info = RangeCombinedInfo {
            ip_ver: "v6",
            cidr: expected_cidr_str,
            start: String::from("2001:db8:1::"),
            end: String::from("2001:db8:1:0:ffff:ffff:ffff:ffff"),
        };

        let expected_cidr = Ipv6Cidr::new(expected_address, expected_prefix_len).unwrap();

        // Act
        let actual_cidr_info = RangeCombinedInfo::from(Cidr::V6(expected_cidr));

        // Assert
        assert_eq!(actual_cidr_info, expected_cidr_info);
    }

    #[test]
    fn test_range_json_info_from_cidr_v4() {
        // Arrange
        let expected_address: Ipv4Addr = EXPECTED_IPV4_STR.parse().unwrap();
        let expected_prefix: u8 = 24;
        let expected_cidr_string: String = format!("{EXPECTED_IPV4_STR}/{expected_prefix}");
        let expected_subnet_address: String = String::from("10.22.135.0");
        let expected_broadcast_ip: String = String::from("10.22.135.255");
        let expected_cidr_info = RangeInfo {
            ip_version: "v4",
            cidr: expected_cidr_string,
            start: expected_subnet_address,
            end: expected_broadcast_ip,
        };

        let expected_cidr = Ipv4Cidr::new(expected_address, expected_prefix).unwrap();

        // Act
        let actual_cidr_info = RangeInfo::from(Cidr::V4(expected_cidr));

        // Assert
        assert_eq!(actual_cidr_info, expected_cidr_info);
    }

    #[test]
    fn test_range_json_info_from_cidr_v6() {
        // Arrange
        let expected_address: Ipv6Addr = EXPECTED_IPV6_STR.parse().unwrap();
        let expected_prefix_len: u8 = 64;
        let expected_cidr_str: String = format!("{EXPECTED_IPV6_STR}/{expected_prefix_len}");
        let expected_cidr_info = RangeInfo {
            ip_version: "v6",
            cidr: expected_cidr_str,
            start: String::from("2001:db8:1::"),
            end: String::from("2001:db8:1:0:ffff:ffff:ffff:ffff"),
        };

        let expected_cidr = Ipv6Cidr::new(expected_address, expected_prefix_len).unwrap();

        // Act
        let actual_cidr_info = RangeInfo::from(Cidr::V6(expected_cidr));

        // Assert
        assert_eq!(actual_cidr_info, expected_cidr_info);
    }
}
