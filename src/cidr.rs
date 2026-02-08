use std::str::FromStr;
use ipnet::Ipv6Net;
use crate::cidr::ipv4::Ipv4Cidr;

pub mod ipv4;

pub(crate) enum Cidr {
    V4(Ipv4Cidr),
    V6(Ipv6Net),
}

impl FromStr for Cidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(v4) = s.parse::<Ipv4Cidr>() {
            return Ok(Cidr::V4(v4));
        }

        if let Ok(v6) = s.parse::<Ipv6Net>() {
            return Ok(Cidr::V6(v6));
        }

        Err("Invalid IP network".into())
    }
}

#[cfg(test)]
mod tests {
    use super::Cidr;
    use crate::inspector::ipv4::HumanReadable;

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
                assert_eq!(cidr.prefix(), EXPECTED_IPV4_PREFIX);
                assert_eq!(cidr.network().human_readable(), EXPECTED_IPV4_STR);
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
}
