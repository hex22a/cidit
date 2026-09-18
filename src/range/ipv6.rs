use std::net::Ipv6Addr;

use crate::{
    Cidr,
    net::ipv6::Ipv6Cidr,
    range::{AddressRange, RangeMode},
};

/// Internal representation of IPv6 range
pub struct Ipv6Range {
    start: Ipv6Addr,
    end: Ipv6Addr,
    cidrs: Option<Vec<Cidr>>,
}

impl Ipv6Range {
    pub fn new(start: Ipv6Addr, end: Ipv6Addr) -> Self {
        Self {
            start,
            end,
            cidrs: None,
        }
    }
}

impl AddressRange for Ipv6Range {
    type Addr = Ipv6Addr;

    fn start(&self) -> Ipv6Addr {
        self.start
    }

    fn end(&self) -> Ipv6Addr {
        self.end
    }

    fn cidrs(&self) -> Option<&[Cidr]> {
        self.cidrs.as_deref()
    }

    fn find_cidr(&mut self, mode: RangeMode) -> &mut Self {
        match mode {
            RangeMode::ExactFit => {
                self.cidrs = Some(
                    super::exact_fit(self.start(), self.end(), 128u8, |addr, prefix| {
                        Ipv6Cidr::new(addr, prefix).expect("prefix is always less or equal to 128")
                    })
                    .into_iter()
                    .map(Cidr::V6)
                    .collect(),
                );
            }
            RangeMode::SmallestCommon => {
                let start = self.start.to_bits();
                let end = self.end.to_bits();
                self.cidrs = Some(vec![super::smallest_common_cidr(
                    start,
                    end,
                    |addr, prefix| {
                        Cidr::V6(
                            Ipv6Cidr::new(Ipv6Addr::from_bits(addr), prefix)
                                .expect("prefix is always less or equal to 128"),
                        )
                    },
                )])
            }
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::test_helpers;

    use super::*;

    #[test]
    fn test_ipv6_range_type() {
        // Arrange
        // Act
        // Assert
        test_helpers::assert_normal_type::<Ipv6Range>();
    }

    #[test]
    fn test_cidrs() {
        // Arrange
        let expected_start = String::from("2001:db8::10").parse().unwrap();
        let expected_end = String::from("2001:db8::20").parse().unwrap();
        let expected_common_cidr = String::from("2001:db8::/122").parse().unwrap();
        let expected_cidrs = Some(vec![expected_common_cidr]);
        let mut range = Ipv6Range::new(expected_start, expected_end);
        range.find_cidr(RangeMode::SmallestCommon);

        // Act
        let actual_cidrs = range.cidrs();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs.as_deref());
    }

    #[test]
    fn test_cidrs_no_find_called() {
        // Arrange
        let expected_start = String::from("2001:db8::10").parse().unwrap();
        let expected_end = String::from("2001:db8::20").parse().unwrap();
        let expected_cidrs = None;
        let range = Ipv6Range::new(expected_start, expected_end);

        // Act
        let actual_cidrs = range.cidrs();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs);
    }

    #[test]
    fn test_find_smallest_common_cidr() {
        // Arrange
        let expected_start = String::from("2001:db8::10").parse().unwrap();
        let expected_end = String::from("2001:db8::20").parse().unwrap();
        let expected_common_cidr = String::from("2001:db8::/122").parse().unwrap();
        let expected_cidrs = Some(vec![expected_common_cidr]);
        let mut range = Ipv6Range::new(expected_start, expected_end);

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::SmallestCommon);

        // Assert
        assert_eq!(actual_updated_range.cidrs, expected_cidrs);
    }

    #[test]
    fn test_find_smallest_common_cidr_one_ip() {
        // Arrange
        let expected_start = String::from("2001:db8::10").parse().unwrap();
        let expected_end = String::from("2001:db8::10").parse().unwrap();
        let expected_common_cidr = String::from("2001:db8::10/128").parse().unwrap();
        let expected_cidrs = Some(vec![expected_common_cidr]);
        let mut range = Ipv6Range::new(expected_start, expected_end);

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::SmallestCommon);

        // Assert
        assert_eq!(actual_updated_range.cidrs, expected_cidrs);
    }

    #[test]
    fn test_find_exact_fit() {
        // Arrange
        let expected_start = String::from("2001:db8::10").parse().unwrap();
        let expected_end = String::from("2001:db8::20").parse().unwrap();
        let expected_ipv6_cidr1 = String::from("2001:db8::10/124").parse().unwrap();
        let expected_ipv6_cidr2 = String::from("2001:db8::20/128").parse().unwrap();
        let expected_cidrs = Some(vec![expected_ipv6_cidr1, expected_ipv6_cidr2]);
        let mut range = Ipv6Range::new(expected_start, expected_end);

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        assert_eq!(actual_updated_range.cidrs, expected_cidrs);
    }

    #[test]
    fn test_find_exact_fit_unaligned_start() {
        // Arrange
        let expected_start = String::from("2001:db8::5").parse().unwrap();
        let expected_end = String::from("2001:db8::a").parse().unwrap();
        let expected_ipv6_cidr1 = String::from("2001:db8::5/128").parse().unwrap();
        let expected_ipv6_cidr2 = String::from("2001:db8::6/127").parse().unwrap();
        let expected_ipv6_cidr3 = String::from("2001:db8::8/127").parse().unwrap();
        let expected_ipv6_cidr4 = String::from("2001:db8::a/128").parse().unwrap();
        let expected_cidrs = Some(vec![
            expected_ipv6_cidr1,
            expected_ipv6_cidr2,
            expected_ipv6_cidr3,
            expected_ipv6_cidr4,
        ]);
        let mut range = Ipv6Range::new(expected_start, expected_end);

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        assert_eq!(actual_updated_range.cidrs, expected_cidrs);
    }

    #[test]
    fn test_find_exact_fit_single_address() {
        // Arrange
        let expected_start = String::from("2001:db8::10").parse().unwrap();
        let expected_end = String::from("2001:db8::10").parse().unwrap();
        let expected_ipv6_cidr1 = String::from("2001:db8::10/128").parse().unwrap();
        let expected_cidrs = Some(vec![expected_ipv6_cidr1]);
        let mut range = Ipv6Range::new(expected_start, expected_end);

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        assert_eq!(actual_updated_range.cidrs, expected_cidrs);
    }

    #[test]
    fn test_find_exact_fit_single_octet() {
        // Arrange
        let expected_start = String::from("2001:db8::").parse().unwrap();
        let expected_end = String::from("2001:db8::ff").parse().unwrap();
        let expected_ipv6_cidr1 = String::from("2001:db8::/120").parse().unwrap();
        let expected_cidrs = Some(vec![expected_ipv6_cidr1]);
        let mut range = Ipv6Range::new(expected_start, expected_end);

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        assert_eq!(actual_updated_range.cidrs, expected_cidrs);
    }

    #[test]
    fn test_find_exact_fit_entire_network() {
        // Arrange
        let expected_start = String::from("::").parse().unwrap();
        let expected_end = String::from("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
            .parse()
            .unwrap();
        let expected_ipv6_cidr1 = String::from("::/0").parse().unwrap();
        let expected_cidrs = Some(vec![expected_ipv6_cidr1]);
        let mut range = Ipv6Range::new(expected_start, expected_end);

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        assert_eq!(actual_updated_range.cidrs, expected_cidrs);
    }

    #[test]
    fn test_find_exact_fit_aligned_block() {
        // Arrange
        let expected_start = String::from("2001:db8::10").parse().unwrap();
        let expected_end = String::from("2001:db8::1f").parse().unwrap();
        let expected_ipv6_cidr1 = String::from("2001:db8::10/124").parse().unwrap();
        let expected_cidrs = Some(vec![expected_ipv6_cidr1]);
        let mut range = Ipv6Range::new(expected_start, expected_end);

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        assert_eq!(actual_updated_range.cidrs, expected_cidrs);
    }

    #[test]
    fn test_find_exact_fit_grows_block() {
        // Arrange
        let expected_start = String::from("2001:db8::8").parse().unwrap();
        let expected_end = String::from("2001:db8::b").parse().unwrap();
        let expected_ipv6_cidr1 = String::from("2001:db8::8/126").parse().unwrap();
        let expected_cidrs = Some(vec![expected_ipv6_cidr1]);
        let mut range = Ipv6Range::new(expected_start, expected_end);

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        assert_eq!(actual_updated_range.cidrs, expected_cidrs);
    }

    #[test]
    fn test_find_exact_fit_crosses_octet_boundary() {
        // Arrange
        let expected_start = String::from("2001:db8::fffe").parse().unwrap();
        let expected_end = String::from("2001:db8::1:1").parse().unwrap();
        let expected_ipv6_cidr1 = String::from("2001:db8::fffe/127").parse().unwrap();
        let expected_ipv6_cidr2 = String::from("2001:db8::1:0/127").parse().unwrap();
        let expected_cidrs = Some(vec![expected_ipv6_cidr1, expected_ipv6_cidr2]);
        let mut range = Ipv6Range::new(expected_start, expected_end);

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        assert_eq!(actual_updated_range.cidrs, expected_cidrs);
    }
}
