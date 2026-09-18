use serde::Serialize;
use tabled::Tabled;

use crate::{Cidr, IpNetwork, Ipv4Network, Ipv6Network};

/// Combined CIDR inspection result.
/// Represents details about both IPv4 and IPv6 CIDR blocks
#[derive(Debug, Tabled, Default, PartialEq)]
#[tabled(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct CidrCombinedInfo {
    ip_ver: &'static str,
    cidr: String,
    address: String,
    prefix: u8,
    network: String,
    first_usable: String,
    last_usable: String,
    broadcast: String,
    available: String,
    netmask: String,
    hostmask: String,
}

/// CIDR inspection result specific to IPv4
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Ipv4CidrInfo {
    pub cidr: String,
    pub address: String,
    pub prefix_length: u8,
    pub first_usable: String,
    pub last_usable: String,
    pub network: String,
    pub broadcast: String,
}

/// CIDR inspection result specific to IPv6
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Ipv6CidrInfo {
    pub cidr: String,
    pub address: String,
    pub prefix_length: u8,
    pub netmask: String,
    pub hostmask: String,
    pub network: String,
    pub subnet_size: String,
}

/// Enum containing variants to represent either
/// IPv4 or IPv6 CIDR inspection result
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "ip_version", rename_all = "lowercase")]
pub enum CidrInfo {
    V4(Ipv4CidrInfo),
    V6(Ipv6CidrInfo),
}

impl From<Cidr> for CidrCombinedInfo {
    fn from(value: Cidr) -> Self {
        match value {
            Cidr::V4(v4) => CidrCombinedInfo {
                ip_ver: "v4",
                cidr: v4.to_string(),
                address: v4.address().to_string(),
                prefix: v4.prefix_len(),
                first_usable: v4.first_usable().to_string(),
                last_usable: v4.last_usable().to_string(),
                network: v4
                    .network_address()
                    .map(|n| n.to_string())
                    .unwrap_or_default(),
                broadcast: v4
                    .broadcast_address()
                    .map(|b| b.to_string())
                    .unwrap_or_default(),
                ..Default::default()
            },
            Cidr::V6(v6) => CidrCombinedInfo {
                ip_ver: "v6",
                cidr: v6.to_string(),
                address: v6.address().to_string(),
                prefix: v6.prefix_len(),
                netmask: v6.netmask().to_string(),
                hostmask: v6.hostmask().to_string(),
                network: v6.first_address().to_string(),
                available: v6.subnet_size(),
                ..Default::default()
            },
        }
    }
}

impl From<Cidr> for CidrInfo {
    fn from(value: Cidr) -> Self {
        match value {
            Cidr::V4(v4) => CidrInfo::V4(Ipv4CidrInfo {
                cidr: v4.to_string(),
                address: v4.address().to_string(),
                prefix_length: v4.prefix_len(),
                first_usable: v4.first_usable().to_string(),
                last_usable: v4.last_usable().to_string(),
                network: v4
                    .network_address()
                    .map(|n| n.to_string())
                    .unwrap_or_default(),
                broadcast: v4
                    .broadcast_address()
                    .map(|b| b.to_string())
                    .unwrap_or_default(),
            }),
            Cidr::V6(v6) => CidrInfo::V6(Ipv6CidrInfo {
                cidr: v6.to_string(),
                address: v6.address().to_string(),
                prefix_length: v6.prefix_len(),
                netmask: v6.netmask().to_string(),
                hostmask: v6.hostmask().to_string(),
                network: v6.first_address().to_string(),
                subnet_size: v6.subnet_size(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::{Ipv4Cidr, Ipv6Cidr, test_helpers};

    use super::*;

    const EXPECTED_IPV4_STR: &str = "10.22.135.144";
    const EXPECTED_IPV6_STR: &str = "2001:db8:1::ab9:c0a8:102";

    #[test]
    fn test_cidr_combined_info_type() {
        // Arrange
        // Act
        // Assert
        test_helpers::assert_normal_type::<CidrCombinedInfo>();
    }

    #[test]
    fn test_ipv4_cidr_info_type() {
        // Arrange
        // Act
        // Assert
        test_helpers::assert_normal_type::<Ipv4CidrInfo>();
    }

    #[test]
    fn test_ipv6_cidr_info_type() {
        // Arrange
        // Act
        // Assert
        test_helpers::assert_normal_type::<Ipv6CidrInfo>();
    }

    #[test]
    fn test_cidr_info_type() {
        // Arrange
        // Act
        // Assert
        test_helpers::assert_normal_type::<Ipv6CidrInfo>();
    }

    #[test]
    fn test_cidr_info_from_cidr_v4() {
        // Arrange
        let expected_address: Ipv4Addr = EXPECTED_IPV4_STR.parse().unwrap();
        let expected_prefix: u8 = 24;
        let expected_cidr_string: String = format!("{EXPECTED_IPV4_STR}/{expected_prefix}");
        let expected_subnet_address: String = String::from("10.22.135.0");
        let expected_first_usable_ip: String = String::from("10.22.135.1");
        let expected_last_usable_ip: String = String::from("10.22.135.254");
        let expected_broadcast_ip: String = String::from("10.22.135.255");
        let expected_cidr_info = CidrInfo::V4(Ipv4CidrInfo {
            cidr: expected_cidr_string,
            address: expected_address.to_string(),
            prefix_length: expected_prefix,
            network: expected_subnet_address,
            first_usable: expected_first_usable_ip,
            last_usable: expected_last_usable_ip,
            broadcast: expected_broadcast_ip,
        });

        let expected_cidr = Ipv4Cidr::new(expected_address, expected_prefix).unwrap();

        // Act
        let actual_cidr_info = CidrInfo::from(Cidr::V4(expected_cidr));

        // Assert
        assert_eq!(actual_cidr_info, expected_cidr_info);
    }

    #[test]
    fn test_cidr_info_from_cidr_v4_point_to_point() {
        // Arrange
        let expected_address: Ipv4Addr = EXPECTED_IPV4_STR.parse().unwrap();
        let expected_prefix: u8 = 31;
        let expected_cidr_string: String = format!("{EXPECTED_IPV4_STR}/{expected_prefix}");
        let expected_subnet_address: String = String::from("");
        let expected_first_usable_ip: String = String::from(EXPECTED_IPV4_STR);
        let expected_last_usable_ip: String = String::from("10.22.135.145");
        let expected_broadcast_ip: String = String::from("");
        let expected_cidr_info = CidrInfo::V4(Ipv4CidrInfo {
            cidr: expected_cidr_string,
            address: expected_address.to_string(),
            prefix_length: expected_prefix,
            network: expected_subnet_address,
            first_usable: expected_first_usable_ip,
            last_usable: expected_last_usable_ip,
            broadcast: expected_broadcast_ip,
        });

        let expected_cidr = Ipv4Cidr::new(expected_address, expected_prefix).unwrap();

        // Act
        let actual_cidr_info = CidrInfo::from(Cidr::V4(expected_cidr));

        // Assert
        assert_eq!(actual_cidr_info, expected_cidr_info);
    }

    #[test]
    fn test_cidr_info_from_cidr_v4_single_ip() {
        // Arrange
        let expected_address: Ipv4Addr = EXPECTED_IPV4_STR.parse().unwrap();
        let expected_prefix: u8 = 32;
        let expected_cidr_string: String = format!("{EXPECTED_IPV4_STR}/{expected_prefix}");
        let expected_subnet_address: String = String::from("");
        let expected_first_usable_ip: String = String::from(EXPECTED_IPV4_STR);
        let expected_last_usable_ip: String = String::from(EXPECTED_IPV4_STR);
        let expected_broadcast_ip: String = String::from("");
        let expected_cidr_info = CidrInfo::V4(Ipv4CidrInfo {
            cidr: expected_cidr_string,
            address: expected_address.to_string(),
            prefix_length: expected_prefix,
            network: expected_subnet_address,
            first_usable: expected_first_usable_ip,
            last_usable: expected_last_usable_ip,
            broadcast: expected_broadcast_ip,
        });

        let expected_cidr = Ipv4Cidr::new(expected_address, expected_prefix).unwrap();

        // Act
        let actual_cidr_info = CidrInfo::from(Cidr::V4(expected_cidr));

        // Assert
        assert_eq!(actual_cidr_info, expected_cidr_info);
    }

    #[test]
    fn test_cidr_info_from_cidr_v6() {
        // Arrange
        let expected_address: Ipv6Addr = EXPECTED_IPV6_STR.parse().unwrap();
        let expected_prefix_len: u8 = 64;
        let expected_cidr_str: String = format!("{EXPECTED_IPV6_STR}/{expected_prefix_len}");
        let expected_subnet_size: String = "2^64".to_string();
        let expected_netmask: String = "ffff:ffff:ffff:ffff::".to_string();
        let expected_hostmask: String = "::ffff:ffff:ffff:ffff".to_string();
        let expected_network: String = "2001:db8:1::".to_string();
        let expected_ipv6_cidr = Ipv6Cidr::new(expected_address, expected_prefix_len).unwrap();
        let expected_cidr_info = CidrInfo::V6(Ipv6CidrInfo {
            cidr: expected_cidr_str,
            address: expected_address.to_string(),
            prefix_length: expected_prefix_len,
            netmask: expected_netmask,
            hostmask: expected_hostmask,
            network: expected_network,
            subnet_size: expected_subnet_size,
        });

        // Act
        let actual_cidr_info = CidrInfo::from(Cidr::V6(expected_ipv6_cidr));

        // Assert
        assert_eq!(actual_cidr_info, expected_cidr_info);
    }

    #[test]
    fn test_cidr_info_from_cidr_v6_point_to_point() {
        // Arrange
        let expected_address: Ipv6Addr = EXPECTED_IPV6_STR.parse().unwrap();
        let expected_prefix_len: u8 = 127;
        let expected_cidr_str: String = format!("{EXPECTED_IPV6_STR}/{expected_prefix_len}");
        let expected_subnet_size: String = "2".to_string();
        let expected_netmask: String = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe".to_string();
        let expected_hostmask: String = "::1".to_string();
        let expected_network: String = EXPECTED_IPV6_STR.to_string();
        let expected_ipv6_cidr = Ipv6Cidr::new(expected_address, expected_prefix_len).unwrap();
        let expected_cidr_info = CidrInfo::V6(Ipv6CidrInfo {
            cidr: expected_cidr_str,
            address: expected_address.to_string(),
            prefix_length: expected_prefix_len,
            netmask: expected_netmask,
            hostmask: expected_hostmask,
            network: expected_network,
            subnet_size: expected_subnet_size,
        });

        // Act
        let actual_cidr_info = CidrInfo::from(Cidr::V6(expected_ipv6_cidr));

        // Assert
        assert_eq!(actual_cidr_info, expected_cidr_info);
    }

    #[test]
    fn test_cidr_info_from_cidr_v6_single_ip() {
        // Arrange
        let expected_address: Ipv6Addr = EXPECTED_IPV6_STR.parse().unwrap();
        let expected_prefix_len: u8 = 128;
        let expected_cidr_str: String = format!("{EXPECTED_IPV6_STR}/{expected_prefix_len}");
        let expected_subnet_size: String = "1".to_string();
        let expected_netmask: String = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".to_string();
        let expected_hostmask: String = "::".to_string();
        let expected_network: String = EXPECTED_IPV6_STR.to_string();
        let expected_ipv6_cidr = Ipv6Cidr::new(expected_address, expected_prefix_len).unwrap();
        let expected_cidr_info = CidrInfo::V6(Ipv6CidrInfo {
            cidr: expected_cidr_str,
            address: expected_address.to_string(),
            prefix_length: expected_prefix_len,
            netmask: expected_netmask,
            hostmask: expected_hostmask,
            network: expected_network,
            subnet_size: expected_subnet_size,
        });

        // Act
        let actual_cidr_info = CidrInfo::from(Cidr::V6(expected_ipv6_cidr));

        // Assert
        assert_eq!(actual_cidr_info, expected_cidr_info);
    }

    #[test]
    fn test_cidr_combined_info_from_cidr_v4() {
        // Arrange
        let expected_address: Ipv4Addr = EXPECTED_IPV4_STR.parse().unwrap();
        let expected_prefix: u8 = 24;
        let expected_cidr_string: String = format!("{EXPECTED_IPV4_STR}/{expected_prefix}");
        let expected_subnet_address: String = String::from("10.22.135.0");
        let expected_first_usable_ip: String = String::from("10.22.135.1");
        let expected_last_usable_ip: String = String::from("10.22.135.254");
        let expected_broadcast_ip: String = String::from("10.22.135.255");
        let expected_cidr_info = CidrCombinedInfo {
            ip_ver: "v4",
            cidr: expected_cidr_string,
            address: expected_address.to_string(),
            prefix: expected_prefix,
            network: expected_subnet_address,
            first_usable: expected_first_usable_ip,
            last_usable: expected_last_usable_ip,
            broadcast: expected_broadcast_ip,
            available: String::from(""),
            netmask: String::from(""),
            hostmask: String::from(""),
        };

        let expected_cidr = Ipv4Cidr::new(expected_address, expected_prefix).unwrap();

        // Act
        let actual_cidr_info = CidrCombinedInfo::from(Cidr::V4(expected_cidr));

        // Assert
        assert_eq!(actual_cidr_info, expected_cidr_info);
    }

    #[test]
    fn test_cidr_combined_info_from_cidr_v4_point_to_point() {
        // Arrange
        let expected_address: Ipv4Addr = EXPECTED_IPV4_STR.parse().unwrap();
        let expected_prefix: u8 = 31;
        let expected_cidr_string: String = format!("{EXPECTED_IPV4_STR}/{expected_prefix}");
        let expected_subnet_address: String = String::from("");
        let expected_first_usable_ip: String = String::from(EXPECTED_IPV4_STR);
        let expected_last_usable_ip: String = String::from("10.22.135.145");
        let expected_broadcast_ip: String = String::from("");
        let expected_cidr_info = CidrCombinedInfo {
            ip_ver: "v4",
            cidr: expected_cidr_string,
            address: expected_address.to_string(),
            prefix: expected_prefix,
            network: expected_subnet_address,
            first_usable: expected_first_usable_ip,
            last_usable: expected_last_usable_ip,
            broadcast: expected_broadcast_ip,
            available: String::from(""),
            netmask: String::from(""),
            hostmask: String::from(""),
        };

        let expected_cidr = Ipv4Cidr::new(expected_address, expected_prefix).unwrap();

        // Act
        let actual_cidr_info = CidrCombinedInfo::from(Cidr::V4(expected_cidr));

        // Assert
        assert_eq!(actual_cidr_info, expected_cidr_info);
    }

    #[test]
    fn test_cidr_combined_info_from_cidr_v4_single_ip() {
        // Arrange
        let expected_address: Ipv4Addr = EXPECTED_IPV4_STR.parse().unwrap();
        let expected_prefix: u8 = 32;
        let expected_cidr_string: String = format!("{EXPECTED_IPV4_STR}/{expected_prefix}");
        let expected_subnet_address: String = String::from("");
        let expected_first_usable_ip: String = String::from(EXPECTED_IPV4_STR);
        let expected_last_usable_ip: String = String::from(EXPECTED_IPV4_STR);
        let expected_broadcast_ip: String = String::from("");
        let expected_cidr_info = CidrCombinedInfo {
            ip_ver: "v4",
            cidr: expected_cidr_string,
            address: expected_address.to_string(),
            prefix: expected_prefix,
            network: expected_subnet_address,
            first_usable: expected_first_usable_ip,
            last_usable: expected_last_usable_ip,
            broadcast: expected_broadcast_ip,
            available: String::from(""),
            netmask: String::from(""),
            hostmask: String::from(""),
        };

        let expected_cidr = Ipv4Cidr::new(expected_address, expected_prefix).unwrap();

        // Act
        let actual_cidr_info = CidrCombinedInfo::from(Cidr::V4(expected_cidr));

        // Assert
        assert_eq!(actual_cidr_info, expected_cidr_info);
    }

    #[test]
    fn test_cidr_combined_info_from_cidr_v6() {
        // Arrange
        let expected_address: Ipv6Addr = EXPECTED_IPV6_STR.parse().unwrap();
        let expected_prefix_len: u8 = 64;
        let expected_cidr_str: String = format!("{EXPECTED_IPV6_STR}/{expected_prefix_len}");
        let expected_subnet_size: String = "2^64".to_string();
        let expected_netmask: String = "ffff:ffff:ffff:ffff::".to_string();
        let expected_hostmask: String = "::ffff:ffff:ffff:ffff".to_string();
        let expected_network: String = "2001:db8:1::".to_string();
        let expected_ipv6_cidr = Ipv6Cidr::new(expected_address, expected_prefix_len).unwrap();
        let expected_cidr_info = CidrCombinedInfo {
            ip_ver: "v6",
            cidr: expected_cidr_str,
            address: expected_address.to_string(),
            prefix: expected_prefix_len,
            netmask: expected_netmask,
            hostmask: expected_hostmask,
            network: expected_network,
            available: expected_subnet_size,
            first_usable: String::from(""),
            last_usable: String::from(""),
            broadcast: String::from(""),
        };

        // Act
        let actual_cidr_info = CidrCombinedInfo::from(Cidr::V6(expected_ipv6_cidr));

        // Assert
        assert_eq!(actual_cidr_info, expected_cidr_info);
    }

    #[test]
    fn test_cidr_combined_info_from_cidr_v6_point_to_point() {
        // Arrange
        let expected_address: Ipv6Addr = EXPECTED_IPV6_STR.parse().unwrap();
        let expected_prefix_len: u8 = 127;
        let expected_cidr_str: String = format!("{EXPECTED_IPV6_STR}/{expected_prefix_len}");
        let expected_subnet_size: String = "2".to_string();
        let expected_netmask: String = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe".to_string();
        let expected_hostmask: String = "::1".to_string();
        let expected_network: String = EXPECTED_IPV6_STR.to_string();
        let expected_ipv6_cidr = Ipv6Cidr::new(expected_address, expected_prefix_len).unwrap();
        let expected_cidr_info = CidrCombinedInfo {
            ip_ver: "v6",
            cidr: expected_cidr_str,
            address: expected_address.to_string(),
            prefix: expected_prefix_len,
            netmask: expected_netmask,
            hostmask: expected_hostmask,
            network: expected_network,
            available: expected_subnet_size,
            first_usable: String::from(""),
            last_usable: String::from(""),
            broadcast: String::from(""),
        };

        // Act
        let actual_cidr_info = CidrCombinedInfo::from(Cidr::V6(expected_ipv6_cidr));

        // Assert
        assert_eq!(actual_cidr_info, expected_cidr_info);
    }

    #[test]
    fn test_cidr_combined_info_from_cidr_v6_single_ip() {
        // Arrange
        let expected_address: Ipv6Addr = EXPECTED_IPV6_STR.parse().unwrap();
        let expected_prefix_len: u8 = 128;
        let expected_cidr_str: String = format!("{EXPECTED_IPV6_STR}/{expected_prefix_len}");
        let expected_subnet_size: String = "1".to_string();
        let expected_netmask: String = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".to_string();
        let expected_hostmask: String = "::".to_string();
        let expected_network: String = EXPECTED_IPV6_STR.to_string();
        let expected_ipv6_cidr = Ipv6Cidr::new(expected_address, expected_prefix_len).unwrap();
        let expected_cidr_info = CidrCombinedInfo {
            ip_ver: "v6",
            cidr: expected_cidr_str,
            address: expected_address.to_string(),
            prefix: expected_prefix_len,
            netmask: expected_netmask,
            hostmask: expected_hostmask,
            network: expected_network,
            available: expected_subnet_size,
            first_usable: String::from(""),
            last_usable: String::from(""),
            broadcast: String::from(""),
        };

        // Act
        let actual_cidr_info = CidrCombinedInfo::from(Cidr::V6(expected_ipv6_cidr));

        // Assert
        assert_eq!(actual_cidr_info, expected_cidr_info);
    }
}
