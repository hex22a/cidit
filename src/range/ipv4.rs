use std::net::Ipv4Addr;

use crate::{Ipv4Cidr, range::AddressRange};

pub struct Ipv4Range {
    start: Ipv4Addr,
    end: Ipv4Addr,
}

impl Ipv4Range {
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        Self { start, end }
    }
}

impl AddressRange for Ipv4Range {
    type Addr = Ipv4Addr;
    type Net = Ipv4Cidr;

    fn start(&self) -> Ipv4Addr {
        self.start
    }

    fn end(&self) -> Ipv4Addr {
        self.end
    }

    fn smallest_common_cidr(&self) -> Ipv4Cidr {
        let start = self.start.to_bits();
        let end = self.end.to_bits();
        super::smallest_common_cidr(start, end, |addr, prefix| {
            Ipv4Cidr::new(Ipv4Addr::from_bits(addr), prefix)
                .expect("prefix is always less or equal to 32")
        })
    }

    fn exact_fit(&self) -> Vec<Ipv4Cidr> {
        super::exact_fit(self.start(), self.end(), 32u8, |addr, prefix| {
            Ipv4Cidr::new(addr, prefix).expect("prefix is always less or equal to 32")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smallest_common_cidr() {
        // Arrange
        let expected_start = String::from("10.0.0.10").parse().unwrap();
        let expected_end = String::from("10.0.0.20").parse().unwrap();
        let expected_common_cidr = String::from("10.0.0.0/27").parse().unwrap();
        let range = Ipv4Range::new(expected_start, expected_end);

        // Act
        let actual_common_cidr = range.smallest_common_cidr();

        // Assert
        assert_eq!(actual_common_cidr, expected_common_cidr);
    }

    #[test]
    fn test_smallest_common_cidr_reverse_order() {
        // Arrange
        let expected_start = String::from("10.0.0.20").parse().unwrap();
        let expected_end = String::from("10.0.0.10").parse().unwrap();
        let expected_common_cidr = String::from("10.0.0.0/27").parse().unwrap();
        let range = Ipv4Range::new(expected_start, expected_end);

        // Act
        let actual_common_cidr = range.smallest_common_cidr();

        // Assert
        assert_eq!(actual_common_cidr, expected_common_cidr);
    }

    #[test]
    fn test_smallest_common_cidr_one_ip() {
        // Arrange
        let expected_start = String::from("10.0.0.10").parse().unwrap();
        let expected_end = String::from("10.0.0.10").parse().unwrap();
        let expected_common_cidr = String::from("10.0.0.10/32").parse().unwrap();
        let range = Ipv4Range::new(expected_start, expected_end);

        // Act
        let actual_common_cidr = range.smallest_common_cidr();

        // Assert
        assert_eq!(actual_common_cidr, expected_common_cidr);
    }

    #[test]
    fn test_exact_fit() {
        // Arrange
        let expected_start = String::from("10.0.0.10").parse().unwrap();
        let expected_end = String::from("10.0.0.20").parse().unwrap();
        let expected_ipv4_cidr1 = String::from("10.0.0.10/31").parse().unwrap();
        let expected_ipv4_cidr2 = String::from("10.0.0.12/30").parse().unwrap();
        let expected_ipv4_cidr3 = String::from("10.0.0.16/30").parse().unwrap();
        let expected_ipv4_cidr4 = String::from("10.0.0.20/32").parse().unwrap();
        let expected_cidrs = vec![
            expected_ipv4_cidr1,
            expected_ipv4_cidr2,
            expected_ipv4_cidr3,
            expected_ipv4_cidr4,
        ];
        let range = Ipv4Range::new(expected_start, expected_end);

        // Act
        let actual_cidrs = range.exact_fit();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs);
    }

    #[test]
    fn test_exact_fit_unaligned_start() {
        // Arrange
        let expected_start = String::from("10.0.0.5").parse().unwrap();
        let expected_end = String::from("10.0.0.10").parse().unwrap();
        let expected_ipv4_cidr1 = String::from("10.0.0.5/32").parse().unwrap();
        let expected_ipv4_cidr2 = String::from("10.0.0.6/31").parse().unwrap();
        let expected_ipv4_cidr3 = String::from("10.0.0.8/31").parse().unwrap();
        let expected_ipv4_cidr4 = String::from("10.0.0.10/32").parse().unwrap();
        let expected_cidrs = vec![
            expected_ipv4_cidr1,
            expected_ipv4_cidr2,
            expected_ipv4_cidr3,
            expected_ipv4_cidr4,
        ];
        let range = Ipv4Range::new(expected_start, expected_end);

        // Act
        let actual_cidrs = range.exact_fit();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs);
    }

    #[test]
    fn test_exact_fit_single_address() {
        // Arrange
        let expected_start = String::from("10.0.0.10").parse().unwrap();
        let expected_end = String::from("10.0.0.10").parse().unwrap();
        let expected_ipv4_cidr1 = String::from("10.0.0.10/32").parse().unwrap();
        let expected_cidrs = vec![expected_ipv4_cidr1];
        let range = Ipv4Range::new(expected_start, expected_end);

        // Act
        let actual_cidrs = range.exact_fit();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs);
    }

    #[test]
    fn test_exact_fit_single_octet() {
        // Arrange
        let expected_start = String::from("10.0.0.0").parse().unwrap();
        let expected_end = String::from("10.0.0.255").parse().unwrap();
        let expected_ipv4_cidr1 = String::from("10.0.0.0/24").parse().unwrap();
        let expected_cidrs = vec![expected_ipv4_cidr1];
        let range = Ipv4Range::new(expected_start, expected_end);

        // Act
        let actual_cidrs = range.exact_fit();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs);
    }

    #[test]
    fn test_exact_fit_entire_network() {
        // Arrange
        let expected_start = String::from("0.0.0.0").parse().unwrap();
        let expected_end = String::from("255.255.255.255").parse().unwrap();
        let expected_ipv4_cidr1 = String::from("0.0.0.0/0").parse().unwrap();
        let expected_cidrs = vec![expected_ipv4_cidr1];
        let range = Ipv4Range::new(expected_start, expected_end);

        // Act
        let actual_cidrs = range.exact_fit();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs);
    }

    #[test]
    fn test_exact_fit_aligned_block() {
        // Arrange
        let expected_start = String::from("10.0.0.16").parse().unwrap();
        let expected_end = String::from("10.0.0.31").parse().unwrap();
        let expected_ipv4_cidr1 = String::from("10.0.0.16/28").parse().unwrap();
        let expected_cidrs = vec![expected_ipv4_cidr1];
        let range = Ipv4Range::new(expected_start, expected_end);

        // Act
        let actual_cidrs = range.exact_fit();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs);
    }

    #[test]
    fn test_exact_fit_grows_block() {
        // Arrange
        let expected_start = String::from("10.0.0.8").parse().unwrap();
        let expected_end = String::from("10.0.0.11").parse().unwrap();
        let expected_ipv4_cidr1 = String::from("10.0.0.8/30").parse().unwrap();
        let expected_cidrs = vec![expected_ipv4_cidr1];
        let range = Ipv4Range::new(expected_start, expected_end);

        // Act
        let actual_cidrs = range.exact_fit();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs);
    }

    #[test]
    fn test_exact_fit_crosses_octet_boundary() {
        // Arrange
        let expected_start = String::from("10.0.0.254").parse().unwrap();
        let expected_end = String::from("10.0.1.1").parse().unwrap();
        let expected_ipv4_cidr1 = String::from("10.0.0.254/31").parse().unwrap();
        let expected_ipv4_cidr2 = String::from("10.0.1.0/31").parse().unwrap();
        let expected_cidrs = vec![expected_ipv4_cidr1, expected_ipv4_cidr2];
        let range = Ipv4Range::new(expected_start, expected_end);

        // Act
        let actual_cidrs = range.exact_fit();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs);
    }
}
