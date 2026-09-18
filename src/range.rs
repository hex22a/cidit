use std::{
    fmt::Debug,
    fmt::Display,
    net::{AddrParseError, IpAddr},
    ops::{BitAnd, BitXor, Not},
    str::FromStr,
};

use thiserror::Error;

use crate::{
    Cidr,
    ip::{Incrementable, IpBits},
    net::IpNetwork,
    range::{ipv4::Ipv4Range, ipv6::Ipv6Range},
};

pub mod dto;
pub mod ipv4;
pub mod ipv6;

#[derive(Debug, Error)]
pub enum RangeParseError {
    #[error("One or both provided IPs are invalid: {0}")]
    IpParse(AddrParseError),
    #[error("Invalid range format. Supported formats: ip..ip, ip-ip, \"ip ip\"")]
    Format,
    #[error("Inconsistent IP versions. Both IPs in range should be either v4 or v6")]
    Inconsistent,
}

pub enum RangeMode {
    ExactFit,
    SmallestCommon,
}

pub trait AddressRange {
    type Addr: Debug + Display + PartialEq + PartialOrd;

    fn start(&self) -> Self::Addr;
    fn end(&self) -> Self::Addr;
    fn cidrs(&self) -> Option<&[Cidr]>;
    fn find_cidr(&mut self, mode: RangeMode) -> &mut Self;
}

pub enum IpRange {
    V4(Ipv4Range),
    V6(Ipv6Range),
}

impl IpRange {
    fn parse_ranges(start: &str, end: &str) -> Result<Self, RangeParseError> {
        let start = start.parse::<IpAddr>().map_err(RangeParseError::IpParse)?;
        let end = end.parse::<IpAddr>().map_err(RangeParseError::IpParse)?;
        match (start, end) {
            (IpAddr::V4(ipv4_start), IpAddr::V4(ipv4_end)) => {
                Ok(IpRange::V4(Ipv4Range::new(ipv4_start, ipv4_end)))
            }
            (IpAddr::V6(ipv6_start), IpAddr::V6(ipv6_end)) => {
                Ok(IpRange::V6(Ipv6Range::new(ipv6_start, ipv6_end)))
            }
            _ => Err(RangeParseError::Inconsistent),
        }
    }
}

impl FromStr for IpRange {
    type Err = RangeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((start, end)) = s.split_once("..") {
            Self::parse_ranges(start, end)
        } else if let Some((start, end)) = s.split_once('-') {
            Self::parse_ranges(start, end)
        } else if let Some((start, end)) = s.split_once(' ') {
            Self::parse_ranges(start, end)
        } else {
            Err(RangeParseError::Format)
        }
    }
}

fn smallest_common_cidr<T, N, F>(start: T, end: T, make_cidr: F) -> N
where
    T: IpBits + BitXor<Output = T> + BitAnd<Output = T> + Not<Output = T> + Copy,
    N: IpNetwork,
    F: FnOnce(T, u8) -> N,
{
    let diff = start ^ end;
    let prefix = diff.leading_zeros();
    make_cidr(start & !diff, prefix)
}

fn exact_fit<T, F>(start: T::Addr, end: T::Addr, max_prefix: u8, make_cidr: F) -> Vec<T>
where
    T: IpNetwork + Copy,
    T::Addr: Incrementable,
    F: Fn(T::Addr, u8) -> T,
{
    let mut result: Vec<T> = Vec::new();
    let mut start_addr = start;
    let end_addr = end;

    while start_addr <= end_addr {
        let mut prefix = max_prefix;
        let mut guess_cidr = make_cidr(start_addr, prefix);
        let mut next_guess_cidr = guess_cidr;

        while next_guess_cidr.first_address() == start_addr
            && next_guess_cidr.last_address() <= end_addr
        {
            guess_cidr = next_guess_cidr;

            if prefix == 0 {
                break;
            }

            prefix -= 1;
            next_guess_cidr = make_cidr(start_addr, prefix);
        }

        result.push(guess_cidr);

        if prefix == 0 {
            break;
        }

        start_addr = guess_cidr
            .last_address()
            .checked_add_one()
            .expect("CIDR is less than maximum IP address if prefix > 0")
    }

    result
}

impl AddressRange for IpRange {
    type Addr = IpAddr;

    fn start(&self) -> IpAddr {
        match self {
            IpRange::V4(range) => IpAddr::V4(range.start()),
            IpRange::V6(range) => IpAddr::V6(range.start()),
        }
    }

    fn end(&self) -> IpAddr {
        match self {
            IpRange::V4(range) => IpAddr::V4(range.end()),
            IpRange::V6(range) => IpAddr::V6(range.end()),
        }
    }

    fn cidrs(&self) -> Option<&[Cidr]> {
        match self {
            IpRange::V4(range) => range.cidrs(),
            IpRange::V6(range) => range.cidrs(),
        }
    }

    fn find_cidr(&mut self, mode: RangeMode) -> &mut Self {
        match self {
            IpRange::V4(range) => {
                range.find_cidr(mode);
            }
            IpRange::V6(range) => {
                range.find_cidr(mode);
            }
        }
        self
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
        assert!(matches!(actual_result, Err(RangeParseError::Format)));
    }

    #[test]
    fn test_parse_inconsistent_v4_v6() {
        // Arrange
        let expected_invalid_string = format!("{EXPECTED_IPV4_START_STR}..{EXPECTED_IPV6_END_STR}");

        // Act
        let actual_result = expected_invalid_string.parse::<IpRange>();

        // Assert
        assert!(matches!(actual_result, Err(RangeParseError::Inconsistent)));
    }

    #[test]
    fn test_parse_inconsistent_v6_v4() {
        // Arrange
        let expected_invalid_string = format!("{EXPECTED_IPV6_START_STR}..{EXPECTED_IPV4_END_STR}");

        // Act
        let actual_result = expected_invalid_string.parse::<IpRange>();

        // Assert
        assert!(matches!(actual_result, Err(RangeParseError::Inconsistent)));
    }

    #[test]
    fn test_parse_invalid_start_ip_dots() {
        // Arrange
        let expected_invalid_string: &str = "some..10.0.0.10";

        // Act
        let actual_result = expected_invalid_string.parse::<IpRange>();

        // Assert
        assert!(matches!(actual_result, Err(RangeParseError::IpParse(_))));
    }

    #[test]
    fn test_parse_invalid_start_ip_dash() {
        // Arrange
        let expected_invalid_string: &str = "some-10.0.0.10";

        // Act
        let actual_result = expected_invalid_string.parse::<IpRange>();

        // Assert
        assert!(matches!(actual_result, Err(RangeParseError::IpParse(_))));
    }

    #[test]
    fn test_parse_invalid_start_ip_space() {
        // Arrange
        let expected_invalid_string: &str = "some 10.0.0.10";

        // Act
        let actual_result = expected_invalid_string.parse::<IpRange>();

        // Assert
        assert!(matches!(actual_result, Err(RangeParseError::IpParse(_))));
    }

    #[test]
    fn test_parse_invalid_end_ip_dots() {
        // Arrange
        let expected_invalid_string: &str = "10.0.0.10..some";

        // Act
        let actual_result = expected_invalid_string.parse::<IpRange>();

        // Assert
        assert!(matches!(actual_result, Err(RangeParseError::IpParse(_))));
    }

    #[test]
    fn test_parse_invalid_end_ip_dash() {
        // Arrange
        let expected_invalid_string: &str = "10.0.0.10-some";

        // Act
        let actual_result = expected_invalid_string.parse::<IpRange>();

        // Assert
        assert!(matches!(actual_result, Err(RangeParseError::IpParse(_))));
    }

    #[test]
    fn test_parse_invalid_end_ip_space() {
        // Arrange
        let expected_invalid_string: &str = "10.0.0.10 some";

        // Act
        let actual_result = expected_invalid_string.parse::<IpRange>();

        // Assert
        assert!(matches!(actual_result, Err(RangeParseError::IpParse(_))));
    }

    #[test]
    fn test_start_v4() {
        // Arrange
        let expected_start = String::from("10.0.0.10").parse().unwrap();
        let expected_end = String::from("10.0.0.20").parse().unwrap();
        let range = IpRange::V4(Ipv4Range::new(expected_start, expected_end));

        // Act
        let actual_start = range.start();

        // Assert
        assert_eq!(actual_start, expected_start)
    }

    #[test]
    fn test_end_v4() {
        // Arrange
        let expected_start = String::from("10.0.0.10").parse().unwrap();
        let expected_end = String::from("10.0.0.20").parse().unwrap();
        let range = IpRange::V4(Ipv4Range::new(expected_start, expected_end));

        // Act
        let actual_end = range.end();

        // Assert
        assert_eq!(actual_end, expected_end)
    }

    #[test]
    fn test_start_v6() {
        // Arrange
        let expected_start = String::from("2001:db8::10").parse().unwrap();
        let expected_end = String::from("2001:db8::20").parse().unwrap();
        let range = IpRange::V6(Ipv6Range::new(expected_start, expected_end));

        // Act
        let actual_start = range.start();

        // Assert
        assert_eq!(actual_start, expected_start)
    }

    #[test]
    fn test_end_v6() {
        // Arrange
        let expected_start = String::from("2001:db8::10").parse().unwrap();
        let expected_end = String::from("2001:db8::20").parse().unwrap();
        let range = IpRange::V6(Ipv6Range::new(expected_start, expected_end));

        // Act
        let actual_end = range.end();

        // Assert
        assert_eq!(actual_end, expected_end)
    }

    #[test]
    fn test_find_smallest_common_cidr_v4() {
        // Arrange
        let expected_start = String::from("10.0.0.10").parse().unwrap();
        let expected_end = String::from("10.0.0.20").parse().unwrap();
        let expected_ipv4_cidr = String::from("10.0.0.0/27").parse().unwrap();
        let expected_common_cidr = Cidr::V4(expected_ipv4_cidr);
        let expected_cidrs = Some(vec![expected_common_cidr]);
        let mut range = IpRange::V4(Ipv4Range::new(expected_start, expected_end));

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::SmallestCommon);

        // Assert
        match actual_updated_range {
            IpRange::V4(range) => {
                assert_eq!(range.cidrs(), expected_cidrs.as_deref());
            }
            _ => panic!("Expected IpRange::V4"),
        }
    }

    #[test]
    fn test_find_smallest_common_cidr_v4_reverse_order() {
        // Arrange
        let expected_start = String::from("10.0.0.20").parse().unwrap();
        let expected_end = String::from("10.0.0.10").parse().unwrap();
        let expected_ipv4_cidr = String::from("10.0.0.0/27").parse().unwrap();
        let expected_common_cidr = Cidr::V4(expected_ipv4_cidr);
        let expected_cidrs = Some(vec![expected_common_cidr]);
        let mut range = IpRange::V4(Ipv4Range::new(expected_start, expected_end));

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::SmallestCommon);

        // Assert
        match actual_updated_range {
            IpRange::V4(range) => {
                assert_eq!(range.cidrs(), expected_cidrs.as_deref());
            }
            _ => panic!("Expected IpRange::V4"),
        }
    }

    #[test]
    fn test_find_smallest_common_cidr_v4_one_ip() {
        // Arrange
        let expected_start = String::from("10.0.0.10").parse().unwrap();
        let expected_end = String::from("10.0.0.10").parse().unwrap();
        let expected_ipv4_cidr = String::from("10.0.0.10/32").parse().unwrap();
        let expected_common_cidr = Cidr::V4(expected_ipv4_cidr);
        let expected_cidrs = Some(vec![expected_common_cidr]);
        let mut range = IpRange::V4(Ipv4Range::new(expected_start, expected_end));

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::SmallestCommon);

        // Assert
        match actual_updated_range {
            IpRange::V4(range) => {
                assert_eq!(range.cidrs(), expected_cidrs.as_deref());
            }
            _ => panic!("Expected IpRange::V4"),
        }
    }

    #[test]
    fn test_find_smallest_common_cidr_v6() {
        // Arrange
        let expected_start = String::from("2001:db8::10").parse().unwrap();
        let expected_end = String::from("2001:db8::20").parse().unwrap();
        let expected_ipv6_cidr = String::from("2001:db8::/122").parse().unwrap();
        let expected_common_cidr = Cidr::V6(expected_ipv6_cidr);
        let expected_cidrs = Some(vec![expected_common_cidr]);
        let mut range = IpRange::V6(Ipv6Range::new(expected_start, expected_end));

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::SmallestCommon);

        // Assert
        match actual_updated_range {
            IpRange::V6(range) => {
                assert_eq!(range.cidrs(), expected_cidrs.as_deref());
            }
            _ => panic!("Expected IpRange::V6"),
        }
    }

    #[test]
    fn test_find_smallest_common_cidr_v6_one_ip() {
        // Arrange
        let expected_start = String::from("2001:db8::10").parse().unwrap();
        let expected_end = String::from("2001:db8::10").parse().unwrap();
        let expected_ipv6_cidr = String::from("2001:db8::10/128").parse().unwrap();
        let expected_common_cidr = Cidr::V6(expected_ipv6_cidr);
        let expected_cidrs = Some(vec![expected_common_cidr]);
        let mut range = IpRange::V6(Ipv6Range::new(expected_start, expected_end));

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::SmallestCommon);

        // Assert
        match actual_updated_range {
            IpRange::V6(range) => {
                assert_eq!(range.cidrs(), expected_cidrs.as_deref());
            }
            _ => panic!("Expected IpRange::V6"),
        }
    }

    #[test]
    fn test_find_exact_fit_v4() {
        // Arrange
        let expected_start = String::from("10.0.0.10").parse().unwrap();
        let expected_end = String::from("10.0.0.20").parse().unwrap();
        let expected_ipv4_cidr1 = String::from("10.0.0.10/31").parse().unwrap();
        let expected_ipv4_cidr2 = String::from("10.0.0.12/30").parse().unwrap();
        let expected_ipv4_cidr3 = String::from("10.0.0.16/30").parse().unwrap();
        let expected_ipv4_cidr4 = String::from("10.0.0.20/32").parse().unwrap();
        let expected_cidrs = Some(vec![
            Cidr::V4(expected_ipv4_cidr1),
            Cidr::V4(expected_ipv4_cidr2),
            Cidr::V4(expected_ipv4_cidr3),
            Cidr::V4(expected_ipv4_cidr4),
        ]);
        let mut range = IpRange::V4(Ipv4Range::new(expected_start, expected_end));

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        match actual_updated_range {
            IpRange::V4(range) => {
                assert_eq!(range.cidrs(), expected_cidrs.as_deref());
            }
            _ => panic!("Expected IpRange::V4"),
        }
    }

    #[test]
    fn test_find_exact_fit_v4_unaligned_start() {
        // Arrange
        let expected_start = String::from("10.0.0.5").parse().unwrap();
        let expected_end = String::from("10.0.0.10").parse().unwrap();
        let expected_ipv4_cidr1 = String::from("10.0.0.5/32").parse().unwrap();
        let expected_ipv4_cidr2 = String::from("10.0.0.6/31").parse().unwrap();
        let expected_ipv4_cidr3 = String::from("10.0.0.8/31").parse().unwrap();
        let expected_ipv4_cidr4 = String::from("10.0.0.10/32").parse().unwrap();
        let expected_cidrs = Some(vec![
            Cidr::V4(expected_ipv4_cidr1),
            Cidr::V4(expected_ipv4_cidr2),
            Cidr::V4(expected_ipv4_cidr3),
            Cidr::V4(expected_ipv4_cidr4),
        ]);
        let mut range = IpRange::V4(Ipv4Range::new(expected_start, expected_end));

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        match actual_updated_range {
            IpRange::V4(range) => {
                assert_eq!(range.cidrs(), expected_cidrs.as_deref());
            }
            _ => panic!("Expected IpRange::V4"),
        }
    }

    #[test]
    fn test_find_exact_fit_v4_single_address() {
        // Arrange
        let expected_start = String::from("10.0.0.10").parse().unwrap();
        let expected_end = String::from("10.0.0.10").parse().unwrap();
        let expected_ipv4_cidr1 = String::from("10.0.0.10/32").parse().unwrap();
        let expected_cidrs = Some(vec![Cidr::V4(expected_ipv4_cidr1)]);
        let mut range = IpRange::V4(Ipv4Range::new(expected_start, expected_end));

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        match actual_updated_range {
            IpRange::V4(range) => {
                assert_eq!(range.cidrs(), expected_cidrs.as_deref());
            }
            _ => panic!("Expected IpRange::V4"),
        }
    }

    #[test]
    fn test_find_exact_fit_v4_single_octet() {
        // Arrange
        let expected_start = String::from("10.0.0.0").parse().unwrap();
        let expected_end = String::from("10.0.0.255").parse().unwrap();
        let expected_ipv4_cidr1 = String::from("10.0.0.0/24").parse().unwrap();
        let expected_cidrs = Some(vec![Cidr::V4(expected_ipv4_cidr1)]);
        let mut range = IpRange::V4(Ipv4Range::new(expected_start, expected_end));

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        match actual_updated_range {
            IpRange::V4(range) => {
                assert_eq!(range.cidrs(), expected_cidrs.as_deref());
            }
            _ => panic!("Expected IpRange::V4"),
        }
    }

    #[test]
    fn test_find_exact_fit_v4_entire_network() {
        // Arrange
        let expected_start = String::from("0.0.0.0").parse().unwrap();
        let expected_end = String::from("255.255.255.255").parse().unwrap();
        let expected_ipv4_cidr1 = String::from("0.0.0.0/0").parse().unwrap();
        let expected_cidrs = Some(vec![Cidr::V4(expected_ipv4_cidr1)]);
        let mut range = IpRange::V4(Ipv4Range::new(expected_start, expected_end));

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        match actual_updated_range {
            IpRange::V4(range) => {
                assert_eq!(range.cidrs(), expected_cidrs.as_deref());
            }
            _ => panic!("Expected IpRange::V4"),
        }
    }

    #[test]
    fn test_find_exact_fit_v4_aligned_block() {
        // Arrange
        let expected_start = String::from("10.0.0.16").parse().unwrap();
        let expected_end = String::from("10.0.0.31").parse().unwrap();
        let expected_ipv4_cidr1 = String::from("10.0.0.16/28").parse().unwrap();
        let expected_cidrs = Some(vec![Cidr::V4(expected_ipv4_cidr1)]);
        let mut range = IpRange::V4(Ipv4Range::new(expected_start, expected_end));

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        match actual_updated_range {
            IpRange::V4(range) => {
                assert_eq!(range.cidrs(), expected_cidrs.as_deref());
            }
            _ => panic!("Expected IpRange::V4"),
        }
    }

    #[test]
    fn test_find_exact_fit_v4_grows_block() {
        // Arrange
        let expected_start = String::from("10.0.0.8").parse().unwrap();
        let expected_end = String::from("10.0.0.11").parse().unwrap();
        let expected_ipv4_cidr1 = String::from("10.0.0.8/30").parse().unwrap();
        let expected_cidrs = Some(vec![Cidr::V4(expected_ipv4_cidr1)]);
        let mut range = IpRange::V4(Ipv4Range::new(expected_start, expected_end));

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        match actual_updated_range {
            IpRange::V4(range) => {
                assert_eq!(range.cidrs(), expected_cidrs.as_deref());
            }
            _ => panic!("Expected IpRange::V4"),
        }
    }

    #[test]
    fn test_find_exact_fit_v4_crosses_octet_boundary() {
        // Arrange
        let expected_start = String::from("10.0.0.254").parse().unwrap();
        let expected_end = String::from("10.0.1.1").parse().unwrap();
        let expected_ipv4_cidr1 = String::from("10.0.0.254/31").parse().unwrap();
        let expected_ipv4_cidr2 = String::from("10.0.1.0/31").parse().unwrap();
        let expected_cidrs = Some(vec![
            Cidr::V4(expected_ipv4_cidr1),
            Cidr::V4(expected_ipv4_cidr2),
        ]);
        let mut range = IpRange::V4(Ipv4Range::new(expected_start, expected_end));

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        match actual_updated_range {
            IpRange::V4(range) => {
                assert_eq!(range.cidrs(), expected_cidrs.as_deref());
            }
            _ => panic!("Expected IpRange::V4"),
        }
    }

    #[test]
    fn test_find_exact_fit_v6() {
        // Arrange
        let expected_start = String::from("2001:db8::10").parse().unwrap();
        let expected_end = String::from("2001:db8::20").parse().unwrap();
        let expected_ipv6_cidr1 = String::from("2001:db8::10/124").parse().unwrap();
        let expected_ipv6_cidr2 = String::from("2001:db8::20/128").parse().unwrap();
        let expected_cidrs = Some(vec![
            Cidr::V6(expected_ipv6_cidr1),
            Cidr::V6(expected_ipv6_cidr2),
        ]);
        let mut range = IpRange::V6(Ipv6Range::new(expected_start, expected_end));

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        match actual_updated_range {
            IpRange::V6(range) => {
                assert_eq!(range.cidrs(), expected_cidrs.as_deref());
            }
            _ => panic!("Expected IpRange::V6"),
        }
    }

    #[test]
    fn test_find_exact_fit_v6_unaligned_start() {
        // Arrange
        let expected_start = String::from("2001:db8::5").parse().unwrap();
        let expected_end = String::from("2001:db8::a").parse().unwrap();
        let expected_ipv6_cidr1 = String::from("2001:db8::5/128").parse().unwrap();
        let expected_ipv6_cidr2 = String::from("2001:db8::6/127").parse().unwrap();
        let expected_ipv6_cidr3 = String::from("2001:db8::8/127").parse().unwrap();
        let expected_ipv6_cidr4 = String::from("2001:db8::a/128").parse().unwrap();
        let expected_cidrs = Some(vec![
            Cidr::V6(expected_ipv6_cidr1),
            Cidr::V6(expected_ipv6_cidr2),
            Cidr::V6(expected_ipv6_cidr3),
            Cidr::V6(expected_ipv6_cidr4),
        ]);
        let mut range = IpRange::V6(Ipv6Range::new(expected_start, expected_end));

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        match actual_updated_range {
            IpRange::V6(range) => {
                assert_eq!(range.cidrs(), expected_cidrs.as_deref());
            }
            _ => panic!("Expected IpRange::V6"),
        }
    }

    #[test]
    fn test_find_exact_fit_v6_single_address() {
        // Arrange
        let expected_start = String::from("2001:db8::10").parse().unwrap();
        let expected_end = String::from("2001:db8::10").parse().unwrap();
        let expected_ipv6_cidr1 = String::from("2001:db8::10/128").parse().unwrap();
        let expected_cidrs = Some(vec![Cidr::V6(expected_ipv6_cidr1)]);
        let mut range = IpRange::V6(Ipv6Range::new(expected_start, expected_end));

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        match actual_updated_range {
            IpRange::V6(range) => {
                assert_eq!(range.cidrs(), expected_cidrs.as_deref());
            }
            _ => panic!("Expected IpRange::V6"),
        }
    }

    #[test]
    fn test_find_exact_fit_v6_single_octet() {
        // Arrange
        let expected_start = String::from("2001:db8::").parse().unwrap();
        let expected_end = String::from("2001:db8::ff").parse().unwrap();
        let expected_ipv6_cidr1 = String::from("2001:db8::/120").parse().unwrap();
        let expected_cidrs = Some(vec![Cidr::V6(expected_ipv6_cidr1)]);
        let mut range = IpRange::V6(Ipv6Range::new(expected_start, expected_end));

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        match actual_updated_range {
            IpRange::V6(range) => {
                assert_eq!(range.cidrs(), expected_cidrs.as_deref());
            }
            _ => panic!("Expected IpRange::V6"),
        }
    }

    #[test]
    fn test_find_exact_fit_v6_entire_network() {
        // Arrange
        let expected_start = String::from("::").parse().unwrap();
        let expected_end = String::from("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
            .parse()
            .unwrap();
        let expected_ipv6_cidr1 = String::from("::/0").parse().unwrap();
        let expected_cidrs = Some(vec![Cidr::V6(expected_ipv6_cidr1)]);
        let mut range = IpRange::V6(Ipv6Range::new(expected_start, expected_end));

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        match actual_updated_range {
            IpRange::V6(range) => {
                assert_eq!(range.cidrs(), expected_cidrs.as_deref());
            }
            _ => panic!("Expected IpRange::V6"),
        }
    }

    #[test]
    fn test_find_exact_fit_v6_aligned_block() {
        // Arrange
        let expected_start = String::from("2001:db8::10").parse().unwrap();
        let expected_end = String::from("2001:db8::1f").parse().unwrap();
        let expected_ipv6_cidr1 = String::from("2001:db8::10/124").parse().unwrap();
        let expected_cidrs = Some(vec![Cidr::V6(expected_ipv6_cidr1)]);
        let mut range = IpRange::V6(Ipv6Range::new(expected_start, expected_end));

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        match actual_updated_range {
            IpRange::V6(range) => {
                assert_eq!(range.cidrs(), expected_cidrs.as_deref());
            }
            _ => panic!("Expected IpRange::V6"),
        }
    }

    #[test]
    fn test_find_exact_fit_v6_grows_block() {
        // Arrange
        let expected_start = String::from("2001:db8::8").parse().unwrap();
        let expected_end = String::from("2001:db8::b").parse().unwrap();
        let expected_ipv6_cidr1 = String::from("2001:db8::8/126").parse().unwrap();
        let expected_cidrs = Some(vec![Cidr::V6(expected_ipv6_cidr1)]);
        let mut range = IpRange::V6(Ipv6Range::new(expected_start, expected_end));

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        match actual_updated_range {
            IpRange::V6(range) => {
                assert_eq!(range.cidrs(), expected_cidrs.as_deref());
            }
            _ => panic!("Expected IpRange::V6"),
        }
    }

    #[test]
    fn test_find_exact_fit_v6_crosses_octet_boundary() {
        // Arrange
        let expected_start = String::from("2001:db8::fffe").parse().unwrap();
        let expected_end = String::from("2001:db8::1:1").parse().unwrap();
        let expected_ipv6_cidr1 = String::from("2001:db8::fffe/127").parse().unwrap();
        let expected_ipv6_cidr2 = String::from("2001:db8::1:0/127").parse().unwrap();
        let expected_cidrs = Some(vec![
            Cidr::V6(expected_ipv6_cidr1),
            Cidr::V6(expected_ipv6_cidr2),
        ]);
        let mut range = IpRange::V6(Ipv6Range::new(expected_start, expected_end));

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        match actual_updated_range {
            IpRange::V6(range) => {
                assert_eq!(range.cidrs(), expected_cidrs.as_deref());
            }
            _ => panic!("Expected IpRange::V6"),
        }
    }
}
