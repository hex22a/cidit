use std::net::Ipv6Addr;

use crate::{net::ipv6::Ipv6Cidr, range::AddressRange};

pub struct Ipv6Range {
    start: Ipv6Addr,
    end: Ipv6Addr,
}

impl Ipv6Range {
    pub fn new(start: Ipv6Addr, end: Ipv6Addr) -> Self {
        Self { start, end }
    }
}

impl AddressRange for Ipv6Range {
    type Addr = Ipv6Addr;
    type Net = Ipv6Cidr;

    fn start(&self) -> Ipv6Addr {
        self.start
    }

    fn end(&self) -> Ipv6Addr {
        self.end
    }

    fn smallest_common_cidr(&self) -> Ipv6Cidr {
        let start = self.start.to_bits();
        let end = self.end.to_bits();
        super::smallest_common_cidr(start, end, |addr, prefix| {
            Ipv6Cidr::new(Ipv6Addr::from_bits(addr), prefix)
                .expect("prefix is always less or equal to 128")
        })
    }

    fn exact_fit(&self) -> Vec<Ipv6Cidr> {
        super::exact_fit(self.start(), self.end(), 128u8, |addr, prefix| {
            Ipv6Cidr::new(addr, prefix).expect("prefix is always less or equal to 128")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smallest_common_cidr() {
        // Arrange
        let expected_start = String::from("2001:db8::10").parse().unwrap();
        let expected_end = String::from("2001:db8::20").parse().unwrap();
        let expected_common_cidr = String::from("2001:db8::/122").parse().unwrap();
        let range = Ipv6Range::new(expected_start, expected_end);

        // Act
        let actual_common_cidr = range.smallest_common_cidr();

        // Assert
        assert_eq!(actual_common_cidr, expected_common_cidr);
    }

    #[test]
    fn test_smallest_common_cidr_one_ip() {
        // Arrange
        let expected_start = String::from("2001:db8::10").parse().unwrap();
        let expected_end = String::from("2001:db8::10").parse().unwrap();
        let expected_common_cidr = String::from("2001:db8::10/128").parse().unwrap();
        let range = Ipv6Range::new(expected_start, expected_end);

        // Act
        let actual_common_cidr = range.smallest_common_cidr();

        // Assert
        assert_eq!(actual_common_cidr, expected_common_cidr);
    }

    #[test]
    fn test_exact_fit() {
        // Arrange
        let expected_start = String::from("2001:db8::10").parse().unwrap();
        let expected_end = String::from("2001:db8::20").parse().unwrap();
        let expected_ipv6_cidr1 = String::from("2001:db8::10/124").parse().unwrap();
        let expected_ipv6_cidr2 = String::from("2001:db8::20/128").parse().unwrap();
        let expected_cidrs = vec![expected_ipv6_cidr1, expected_ipv6_cidr2];
        let range = Ipv6Range::new(expected_start, expected_end);

        // Act
        let actual_cidrs = range.exact_fit();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs);
    }

    #[test]
    fn test_exact_fit_unaligned_start() {
        // Arrange
        let expected_start = String::from("2001:db8::5").parse().unwrap();
        let expected_end = String::from("2001:db8::a").parse().unwrap();
        let expected_ipv6_cidr1 = String::from("2001:db8::5/128").parse().unwrap();
        let expected_ipv6_cidr2 = String::from("2001:db8::6/127").parse().unwrap();
        let expected_ipv6_cidr3 = String::from("2001:db8::8/127").parse().unwrap();
        let expected_ipv6_cidr4 = String::from("2001:db8::a/128").parse().unwrap();
        let expected_cidrs = vec![
            expected_ipv6_cidr1,
            expected_ipv6_cidr2,
            expected_ipv6_cidr3,
            expected_ipv6_cidr4,
        ];
        let range = Ipv6Range::new(expected_start, expected_end);

        // Act
        let actual_cidrs = range.exact_fit();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs);
    }

    #[test]
    fn test_exact_fit_single_address() {
        // Arrange
        let expected_start = String::from("2001:db8::10").parse().unwrap();
        let expected_end = String::from("2001:db8::10").parse().unwrap();
        let expected_ipv6_cidr1 = String::from("2001:db8::10/128").parse().unwrap();
        let expected_cidrs = vec![expected_ipv6_cidr1];
        let range = Ipv6Range::new(expected_start, expected_end);

        // Act
        let actual_cidrs = range.exact_fit();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs);
    }

    #[test]
    fn test_exact_fit_single_octet() {
        // Arrange
        let expected_start = String::from("2001:db8::").parse().unwrap();
        let expected_end = String::from("2001:db8::ff").parse().unwrap();
        let expected_ipv6_cidr1 = String::from("2001:db8::/120").parse().unwrap();
        let expected_cidrs = vec![expected_ipv6_cidr1];
        let range = Ipv6Range::new(expected_start, expected_end);

        // Act
        let actual_cidrs = range.exact_fit();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs);
    }

    #[test]
    fn test_exact_fit_entire_network() {
        // Arrange
        let expected_start = String::from("::").parse().unwrap();
        let expected_end = String::from("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
            .parse()
            .unwrap();
        let expected_ipv6_cidr1 = String::from("::/0").parse().unwrap();
        let expected_cidrs = vec![expected_ipv6_cidr1];
        let range = Ipv6Range::new(expected_start, expected_end);

        // Act
        let actual_cidrs = range.exact_fit();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs);
    }

    #[test]
    fn test_exact_fit_aligned_block() {
        // Arrange
        let expected_start = String::from("2001:db8::10").parse().unwrap();
        let expected_end = String::from("2001:db8::1f").parse().unwrap();
        let expected_ipv6_cidr1 = String::from("2001:db8::10/124").parse().unwrap();
        let expected_cidrs = vec![expected_ipv6_cidr1];
        let range = Ipv6Range::new(expected_start, expected_end);

        // Act
        let actual_cidrs = range.exact_fit();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs);
    }

    #[test]
    fn test_exact_fit_grows_block() {
        // Arrange
        let expected_start = String::from("2001:db8::8").parse().unwrap();
        let expected_end = String::from("2001:db8::b").parse().unwrap();
        let expected_ipv6_cidr1 = String::from("2001:db8::8/126").parse().unwrap();
        let expected_cidrs = vec![expected_ipv6_cidr1];
        let range = Ipv6Range::new(expected_start, expected_end);

        // Act
        let actual_cidrs = range.exact_fit();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs);
    }

    #[test]
    fn test_exact_fit_crosses_octet_boundary() {
        // Arrange
        let expected_start = String::from("2001:db8::fffe").parse().unwrap();
        let expected_end = String::from("2001:db8::1:1").parse().unwrap();
        let expected_ipv6_cidr1 = String::from("2001:db8::fffe/127").parse().unwrap();
        let expected_ipv6_cidr2 = String::from("2001:db8::1:0/127").parse().unwrap();
        let expected_cidrs = vec![expected_ipv6_cidr1, expected_ipv6_cidr2];
        let range = Ipv6Range::new(expected_start, expected_end);

        // Act
        let actual_cidrs = range.exact_fit();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs);
    }
}
