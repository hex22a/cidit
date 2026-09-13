use std::net::Ipv4Addr;

use cidit::{Cidr, Ipv4Network, POINT_TO_POINT_CIDR_PREFIX_LEN, SubnetSize};
use serde::Serialize;
use tabled::{
    Table, Tabled,
    settings::{Remove, Style, object::Rows},
};

const JSON_OUTPUT_VERSION: u8 = 2;

#[derive(Debug, Tabled, Default, PartialEq)]
pub(crate) struct CidrTabledInfo {
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

#[derive(Debug, Tabled, PartialEq)]
pub(crate) struct RangeTabledInfo {
    ip_ver: &'static str,
    cidr: String,
    start: String,
    end: String,
}

/// Inspection result for IPv4
#[derive(Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Ipv4CidrJsonInfo {
    pub cidr: String,
    pub address: String,
    pub prefix_length: u8,
    pub first_usable: String,
    pub last_usable: String,
    pub network: String,
    pub broadcast: String,
}

/// Inspection result for IPv6
#[derive(Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Ipv6CidrJsonInfo {
    pub cidr: String,
    pub address: String,
    pub prefix_length: u8,
    pub netmask: String,
    pub hostmask: String,
    pub network: String,
    pub subnet_size: String,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "ip_version", rename_all = "lowercase")]
pub(crate) enum CidrJsonInfo {
    V4(Ipv4CidrJsonInfo),
    V6(Ipv6CidrJsonInfo),
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub(crate) struct RangeJsonInfo {
    ip_version: &'static str,
    cidr: String,
    start: String,
    end: String,
}

#[derive(Serialize)]
struct JsonOutput<T> {
    version: u8,
    data: Vec<T>,
}

impl From<Cidr> for CidrTabledInfo {
    fn from(value: Cidr) -> Self {
        match value {
            Cidr::V4(v4) => {
                let network = if v4.prefix_len() >= POINT_TO_POINT_CIDR_PREFIX_LEN {
                    String::from("")
                } else {
                    Ipv4Addr::from_bits(v4.network_address()).to_string()
                };
                let broadcast = if v4.prefix_len() >= POINT_TO_POINT_CIDR_PREFIX_LEN {
                    String::from("")
                } else {
                    Ipv4Addr::from_bits(v4.broadcast_address()).to_string()
                };
                CidrTabledInfo {
                    ip_ver: "v4",
                    cidr: format!("{}/{}", v4.addr(), v4.prefix_len()),
                    address: v4.addr().to_string(),
                    prefix: v4.prefix_len(),
                    first_usable: Ipv4Addr::from_bits(v4.first_usable()).to_string(),
                    last_usable: Ipv4Addr::from_bits(v4.last_usable()).to_string(),
                    network,
                    broadcast,
                    ..Default::default()
                }
            }
            Cidr::V6(v6) => CidrTabledInfo {
                ip_ver: "v6",
                cidr: format!("{}/{}", v6.addr(), v6.prefix_len()),
                address: v6.addr().to_string(),
                prefix: v6.prefix_len(),
                netmask: v6.netmask().to_string(),
                hostmask: v6.hostmask().to_string(),
                network: v6.network().to_string(),
                available: v6.subnet_size(),
                ..Default::default()
            },
        }
    }
}

impl From<Cidr> for CidrJsonInfo {
    fn from(value: Cidr) -> Self {
        match value {
            Cidr::V4(v4) => {
                let network = if v4.prefix_len() >= POINT_TO_POINT_CIDR_PREFIX_LEN {
                    String::from("")
                } else {
                    Ipv4Addr::from_bits(v4.network_address()).to_string()
                };
                let broadcast = if v4.prefix_len() >= POINT_TO_POINT_CIDR_PREFIX_LEN {
                    String::from("")
                } else {
                    Ipv4Addr::from_bits(v4.broadcast_address()).to_string()
                };
                CidrJsonInfo::V4(Ipv4CidrJsonInfo {
                    cidr: format!("{}/{}", v4.addr(), v4.prefix_len()),
                    address: v4.addr().to_string(),
                    prefix_length: v4.prefix_len(),
                    first_usable: Ipv4Addr::from_bits(v4.first_usable()).to_string(),
                    last_usable: Ipv4Addr::from_bits(v4.last_usable()).to_string(),
                    network,
                    broadcast,
                })
            }
            Cidr::V6(v6) => CidrJsonInfo::V6(Ipv6CidrJsonInfo {
                cidr: format!("{}/{}", v6.addr(), v6.prefix_len()),
                address: v6.addr().to_string(),
                prefix_length: v6.prefix_len(),
                netmask: v6.netmask().to_string(),
                hostmask: v6.hostmask().to_string(),
                network: v6.network().to_string(),
                subnet_size: v6.subnet_size(),
            }),
        }
    }
}

impl From<Cidr> for RangeTabledInfo {
    fn from(value: Cidr) -> Self {
        match value {
            Cidr::V4(v4) => Self {
                ip_ver: "v4",
                cidr: format!("{}/{}", v4.addr(), v4.prefix_len()),
                start: Ipv4Addr::from_bits(v4.network_address()).to_string(),
                end: Ipv4Addr::from_bits(v4.broadcast_address()).to_string(),
            },
            Cidr::V6(v6) => Self {
                ip_ver: "v6",
                cidr: format!("{}/{}", v6.addr(), v6.prefix_len()),
                start: v6.network().to_string(),
                end: v6.broadcast().to_string(),
            },
        }
    }
}

impl From<Cidr> for RangeJsonInfo {
    fn from(value: Cidr) -> Self {
        match value {
            Cidr::V4(v4) => Self {
                ip_version: "v4",
                cidr: format!("{}/{}", v4.addr(), v4.prefix_len()),
                start: Ipv4Addr::from_bits(v4.network_address()).to_string(),
                end: Ipv4Addr::from_bits(v4.broadcast_address()).to_string(),
            },
            Cidr::V6(v6) => Self {
                ip_version: "v6",
                cidr: format!("{}/{}", v6.addr(), v6.prefix_len()),
                start: v6.network().to_string(),
                end: v6.broadcast().to_string(),
            },
        }
    }
}

pub fn print_json<T>(cidrs: Vec<Cidr>, pretty: bool)
where
    T: Serialize + From<Cidr>,
{
    let data = cidrs.into_iter().map(T::from).collect();
    let json_output = JsonOutput {
        version: JSON_OUTPUT_VERSION,
        data,
    };
    match pretty {
        true => println!("{}", serde_json::to_string_pretty(&json_output).unwrap()),
        false => println!("{}", serde_json::to_string(&json_output).unwrap()),
    }
}

pub fn print_ndjson<T>(cidrs: Vec<Cidr>)
where
    T: Serialize + From<Cidr>,
{
    cidrs
        .into_iter()
        .map(T::from)
        .for_each(|item| println!("{}", serde_json::to_string(&item).unwrap()));
}

pub fn print_table<T>(results: Vec<Cidr>, headless: bool)
where
    T: Tabled + From<Cidr>,
{
    let rows: Vec<T> = results.into_iter().map(T::from).collect();
    let mut table = Table::new(rows);
    table.with(Style::blank());
    if headless {
        table.with(Remove::row(Rows::first()));
    }

    println!("{table}");
}

#[cfg(test)]
mod tests {
    use cidit::Ipv4Cidr;
    use ipnet::Ipv6Net;

    use super::*;

    const EXPECTED_BINARY_ADDRESS: u32 = 0b00001010_00010110_10000111_10010000;
    const EXPECTED_IPV4_STR: &str = "10.22.135.144";
    const EXPECTED_IPV6_STR: &str = "2001:db8:1::ab9:c0a8:102";

    #[test]
    fn test_cidr_info_from_cidr_v4() {
        // Arrange
        let expected_prefix: u8 = 24;
        let expected_cidr_string: String = format!("{EXPECTED_IPV4_STR}/{expected_prefix}");
        let expected_subnet_address: String = String::from("10.22.135.0");
        let expected_first_usable_ip: String = String::from("10.22.135.1");
        let expected_last_usable_ip: String = String::from("10.22.135.254");
        let expected_broadcast_ip: String = String::from("10.22.135.255");
        let expected_cidr_info = CidrTabledInfo {
            ip_ver: "v4",
            cidr: expected_cidr_string,
            address: String::from(EXPECTED_IPV4_STR),
            prefix: expected_prefix,
            network: expected_subnet_address,
            first_usable: expected_first_usable_ip,
            last_usable: expected_last_usable_ip,
            broadcast: expected_broadcast_ip,
            available: String::from(""),
            netmask: String::from(""),
            hostmask: String::from(""),
        };

        let expected_cidr = Ipv4Cidr::new(EXPECTED_BINARY_ADDRESS, expected_prefix).unwrap();

        // Act
        let actual_cidr_info = CidrTabledInfo::from(Cidr::V4(expected_cidr));

        // Assert
        assert_eq!(actual_cidr_info, expected_cidr_info);
    }

    #[test]
    fn test_cidr_info_from_cidr_v4_point_to_point() {
        // Arrange
        let expected_prefix: u8 = 31;
        let expected_cidr_string: String = format!("{EXPECTED_IPV4_STR}/{expected_prefix}");
        let expected_subnet_address: String = String::from("");
        let expected_first_usable_ip: String = String::from(EXPECTED_IPV4_STR);
        let expected_last_usable_ip: String = String::from("10.22.135.145");
        let expected_broadcast_ip: String = String::from("");
        let expected_cidr_info = CidrTabledInfo {
            ip_ver: "v4",
            cidr: expected_cidr_string,
            address: String::from(EXPECTED_IPV4_STR),
            prefix: expected_prefix,
            network: expected_subnet_address,
            first_usable: expected_first_usable_ip,
            last_usable: expected_last_usable_ip,
            broadcast: expected_broadcast_ip,
            available: String::from(""),
            netmask: String::from(""),
            hostmask: String::from(""),
        };

        let expected_cidr = Ipv4Cidr::new(EXPECTED_BINARY_ADDRESS, expected_prefix).unwrap();

        // Act
        let actual_cidr_info = CidrTabledInfo::from(Cidr::V4(expected_cidr));

        // Assert
        assert_eq!(actual_cidr_info, expected_cidr_info);
    }

    #[test]
    fn test_cidr_info_from_cidr_v4_single_ip() {
        // Arrange
        let expected_prefix: u8 = 32;
        let expected_cidr_string: String = format!("{EXPECTED_IPV4_STR}/{expected_prefix}");
        let expected_subnet_address: String = String::from("");
        let expected_first_usable_ip: String = String::from(EXPECTED_IPV4_STR);
        let expected_last_usable_ip: String = String::from(EXPECTED_IPV4_STR);
        let expected_broadcast_ip: String = String::from("");
        let expected_cidr_info = CidrTabledInfo {
            ip_ver: "v4",
            cidr: expected_cidr_string,
            address: String::from(EXPECTED_IPV4_STR),
            prefix: expected_prefix,
            network: expected_subnet_address,
            first_usable: expected_first_usable_ip,
            last_usable: expected_last_usable_ip,
            broadcast: expected_broadcast_ip,
            available: String::from(""),
            netmask: String::from(""),
            hostmask: String::from(""),
        };

        let expected_cidr = Ipv4Cidr::new(EXPECTED_BINARY_ADDRESS, expected_prefix).unwrap();

        // Act
        let actual_cidr_info = CidrTabledInfo::from(Cidr::V4(expected_cidr));

        // Assert
        assert_eq!(actual_cidr_info, expected_cidr_info);
    }

    #[test]
    fn test_cidr_info_from_cidr_v6() {
        // Arrange
        let expected_prefix_len: u8 = 64;
        let expected_cidr_str: String = format!("{EXPECTED_IPV6_STR}/{expected_prefix_len}");
        let expected_subnet_size: String = "2^64".to_string();
        let expected_netmask: String = "ffff:ffff:ffff:ffff::".to_string();
        let expected_hostmask: String = "::ffff:ffff:ffff:ffff".to_string();
        let expected_network: String = "2001:db8:1::".to_string();
        let expected_ipv6_cidr: Ipv6Net =
            Ipv6Net::new(EXPECTED_IPV6_STR.parse().unwrap(), expected_prefix_len).unwrap();
        let expected_cidr_info = CidrTabledInfo {
            ip_ver: "v6",
            cidr: expected_cidr_str,
            address: EXPECTED_IPV6_STR.to_string(),
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
        let actual_cidr_info = CidrTabledInfo::from(Cidr::V6(expected_ipv6_cidr));

        // Assert
        assert_eq!(actual_cidr_info, expected_cidr_info);
    }

    #[test]
    fn test_range_tabled_info_from_cidr_v4() {
        // Arrange
        let expected_prefix: u8 = 24;
        let expected_cidr_string: String = format!("{EXPECTED_IPV4_STR}/{expected_prefix}");
        let expected_subnet_address: String = String::from("10.22.135.0");
        let expected_broadcast_ip: String = String::from("10.22.135.255");
        let expected_cidr_info = RangeTabledInfo {
            ip_ver: "v4",
            cidr: expected_cidr_string,
            start: expected_subnet_address,
            end: expected_broadcast_ip,
        };

        let expected_cidr = Ipv4Cidr::new(EXPECTED_BINARY_ADDRESS, expected_prefix).unwrap();

        // Act
        let actual_cidr_info = RangeTabledInfo::from(Cidr::V4(expected_cidr));

        // Assert
        assert_eq!(actual_cidr_info, expected_cidr_info);
    }

    #[test]
    fn test_range_tabled_info_from_cidr_v6() {
        // Arrange
        let expected_prefix_len: u8 = 64;
        let expected_cidr_str: String = format!("{EXPECTED_IPV6_STR}/{expected_prefix_len}");
        let expected_cidr_info = RangeTabledInfo {
            ip_ver: "v6",
            cidr: expected_cidr_str,
            start: String::from("2001:db8:1::"),
            end: String::from("2001:db8:1:0:ffff:ffff:ffff:ffff"),
        };

        let expected_cidr: Ipv6Net =
            Ipv6Net::new(EXPECTED_IPV6_STR.parse().unwrap(), expected_prefix_len).unwrap();

        // Act
        let actual_cidr_info = RangeTabledInfo::from(Cidr::V6(expected_cidr));

        // Assert
        assert_eq!(actual_cidr_info, expected_cidr_info);
    }

    #[test]
    fn test_range_json_info_from_cidr_v4() {
        // Arrange
        let expected_prefix: u8 = 24;
        let expected_cidr_string: String = format!("{EXPECTED_IPV4_STR}/{expected_prefix}");
        let expected_subnet_address: String = String::from("10.22.135.0");
        let expected_broadcast_ip: String = String::from("10.22.135.255");
        let expected_cidr_info = RangeJsonInfo {
            ip_version: "v4",
            cidr: expected_cidr_string,
            start: expected_subnet_address,
            end: expected_broadcast_ip,
        };

        let expected_cidr = Ipv4Cidr::new(EXPECTED_BINARY_ADDRESS, expected_prefix).unwrap();

        // Act
        let actual_cidr_info = RangeJsonInfo::from(Cidr::V4(expected_cidr));

        // Assert
        assert_eq!(actual_cidr_info, expected_cidr_info);
    }

    #[test]
    fn test_range_json_info_from_cidr_v6() {
        // Arrange
        let expected_prefix_len: u8 = 64;
        let expected_cidr_str: String = format!("{EXPECTED_IPV6_STR}/{expected_prefix_len}");
        let expected_cidr_info = RangeJsonInfo {
            ip_version: "v6",
            cidr: expected_cidr_str,
            start: String::from("2001:db8:1::"),
            end: String::from("2001:db8:1:0:ffff:ffff:ffff:ffff"),
        };

        let expected_cidr: Ipv6Net =
            Ipv6Net::new(EXPECTED_IPV6_STR.parse().unwrap(), expected_prefix_len).unwrap();

        // Act
        let actual_cidr_info = RangeJsonInfo::from(Cidr::V6(expected_cidr));

        // Assert
        assert_eq!(actual_cidr_info, expected_cidr_info);
    }
}
