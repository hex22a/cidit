use std::net::Ipv4Addr;

use crate::{
    Cidr, Ipv4Cidr,
    range::{AddressRange, RangeMode},
};

pub struct Ipv4Range {
    start: Ipv4Addr,
    end: Ipv4Addr,
    cidrs: Option<Vec<Cidr>>,
}

impl Ipv4Range {
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        Self {
            start,
            end,
            cidrs: None,
        }
    }
}

impl AddressRange for Ipv4Range {
    type Addr = Ipv4Addr;

    fn start(&self) -> Ipv4Addr {
        self.start
    }

    fn end(&self) -> Ipv4Addr {
        self.end
    }

    fn cidrs(&self) -> Option<&[Cidr]> {
        self.cidrs.as_deref()
    }

    fn find_cidr(&mut self, mode: RangeMode) -> &mut Self {
        match mode {
            RangeMode::ExactFit => {
                self.cidrs = Some(
                    super::exact_fit(self.start(), self.end(), 32u8, |addr, prefix| {
                        Ipv4Cidr::new(addr, prefix).expect("prefix is always less or equal to 32")
                    })
                    .into_iter()
                    .map(Cidr::V4)
                    .collect(),
                )
            }
            RangeMode::SmallestCommon => {
                let start = self.start.to_bits();
                let end = self.end.to_bits();
                self.cidrs = Some(vec![super::smallest_common_cidr(
                    start,
                    end,
                    |addr, prefix| {
                        Cidr::V4(
                            Ipv4Cidr::new(Ipv4Addr::from_bits(addr), prefix)
                                .expect("prefix is always less or equal to 32"),
                        )
                    },
                )]);
            }
        };
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidrs() {
        // Arrange
        let expected_start = String::from("10.0.0.10").parse().unwrap();
        let expected_end = String::from("10.0.0.20").parse().unwrap();
        let expected_common_cidr = String::from("10.0.0.0/27").parse().unwrap();
        let expected_cidrs = Some(vec![expected_common_cidr]);
        let mut range = Ipv4Range::new(expected_start, expected_end);
        range.find_cidr(RangeMode::SmallestCommon);

        // Act
        let actual_cidrs = range.cidrs();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs.as_deref());
    }

    #[test]
    fn test_cidrs_no_find_called() {
        // Arrange
        let expected_start = String::from("10.0.0.10").parse().unwrap();
        let expected_end = String::from("10.0.0.20").parse().unwrap();
        let expected_cidrs = None;
        let range = Ipv4Range::new(expected_start, expected_end);

        // Act
        let actual_cidrs = range.cidrs();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs);
    }

    #[test]
    fn test_find_smallest_common_cidr() {
        // Arrange
        let expected_start = String::from("10.0.0.10").parse().unwrap();
        let expected_end = String::from("10.0.0.20").parse().unwrap();
        let expected_common_cidr = String::from("10.0.0.0/27").parse().unwrap();
        let expected_cidrs = Some(vec![expected_common_cidr]);
        let mut range = Ipv4Range::new(expected_start, expected_end);

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::SmallestCommon);

        // Assert
        assert_eq!(actual_updated_range.cidrs, expected_cidrs);
    }

    #[test]
    fn test_find_smallest_common_cidr_reverse_order() {
        // Arrange
        let expected_start = String::from("10.0.0.20").parse().unwrap();
        let expected_end = String::from("10.0.0.10").parse().unwrap();
        let expected_common_cidr = String::from("10.0.0.0/27").parse().unwrap();
        let expected_cidrs = Some(vec![expected_common_cidr]);
        let mut range = Ipv4Range::new(expected_start, expected_end);

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::SmallestCommon);

        // Assert
        assert_eq!(actual_updated_range.cidrs, expected_cidrs);
    }

    #[test]
    fn test_find_smallest_common_cidr_one_ip() {
        // Arrange
        let expected_start = String::from("10.0.0.10").parse().unwrap();
        let expected_end = String::from("10.0.0.10").parse().unwrap();
        let expected_common_cidr = String::from("10.0.0.10/32").parse().unwrap();
        let expected_cidrs = Some(vec![expected_common_cidr]);
        let mut range = Ipv4Range::new(expected_start, expected_end);

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::SmallestCommon);

        // Assert
        assert_eq!(actual_updated_range.cidrs, expected_cidrs);
    }

    #[test]
    fn test_find_exact_fit() {
        // Arrange
        let expected_start = String::from("10.0.0.10").parse().unwrap();
        let expected_end = String::from("10.0.0.20").parse().unwrap();
        let expected_ipv4_cidr1 = String::from("10.0.0.10/31").parse().unwrap();
        let expected_ipv4_cidr2 = String::from("10.0.0.12/30").parse().unwrap();
        let expected_ipv4_cidr3 = String::from("10.0.0.16/30").parse().unwrap();
        let expected_ipv4_cidr4 = String::from("10.0.0.20/32").parse().unwrap();
        let expected_cidrs = Some(vec![
            expected_ipv4_cidr1,
            expected_ipv4_cidr2,
            expected_ipv4_cidr3,
            expected_ipv4_cidr4,
        ]);
        let mut range = Ipv4Range::new(expected_start, expected_end);

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        assert_eq!(actual_updated_range.cidrs, expected_cidrs);
    }

    #[test]
    fn test_find_exact_fit_unaligned_start() {
        // Arrange
        let expected_start = String::from("10.0.0.5").parse().unwrap();
        let expected_end = String::from("10.0.0.10").parse().unwrap();
        let expected_ipv4_cidr1 = String::from("10.0.0.5/32").parse().unwrap();
        let expected_ipv4_cidr2 = String::from("10.0.0.6/31").parse().unwrap();
        let expected_ipv4_cidr3 = String::from("10.0.0.8/31").parse().unwrap();
        let expected_ipv4_cidr4 = String::from("10.0.0.10/32").parse().unwrap();
        let expected_cidrs = Some(vec![
            expected_ipv4_cidr1,
            expected_ipv4_cidr2,
            expected_ipv4_cidr3,
            expected_ipv4_cidr4,
        ]);
        let mut range = Ipv4Range::new(expected_start, expected_end);

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        assert_eq!(actual_updated_range.cidrs, expected_cidrs);
    }

    #[test]
    fn test_find_exact_fit_single_address() {
        // Arrange
        let expected_start = String::from("10.0.0.10").parse().unwrap();
        let expected_end = String::from("10.0.0.10").parse().unwrap();
        let expected_ipv4_cidr1 = String::from("10.0.0.10/32").parse().unwrap();
        let expected_cidrs = Some(vec![expected_ipv4_cidr1]);
        let mut range = Ipv4Range::new(expected_start, expected_end);

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        assert_eq!(actual_updated_range.cidrs, expected_cidrs);
    }

    #[test]
    fn test_find_exact_fit_single_octet() {
        // Arrange
        let expected_start = String::from("10.0.0.0").parse().unwrap();
        let expected_end = String::from("10.0.0.255").parse().unwrap();
        let expected_ipv4_cidr1 = String::from("10.0.0.0/24").parse().unwrap();
        let expected_cidrs = Some(vec![expected_ipv4_cidr1]);
        let mut range = Ipv4Range::new(expected_start, expected_end);

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        assert_eq!(actual_updated_range.cidrs, expected_cidrs);
    }

    #[test]
    fn test_find_exact_fit_entire_network() {
        // Arrange
        let expected_start = String::from("0.0.0.0").parse().unwrap();
        let expected_end = String::from("255.255.255.255").parse().unwrap();
        let expected_ipv4_cidr1 = String::from("0.0.0.0/0").parse().unwrap();
        let expected_cidrs = Some(vec![expected_ipv4_cidr1]);
        let mut range = Ipv4Range::new(expected_start, expected_end);

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        assert_eq!(actual_updated_range.cidrs, expected_cidrs);
    }

    #[test]
    fn test_find_exact_fit_aligned_block() {
        // Arrange
        let expected_start = String::from("10.0.0.16").parse().unwrap();
        let expected_end = String::from("10.0.0.31").parse().unwrap();
        let expected_ipv4_cidr1 = String::from("10.0.0.16/28").parse().unwrap();
        let expected_cidrs = Some(vec![expected_ipv4_cidr1]);
        let mut range = Ipv4Range::new(expected_start, expected_end);

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        assert_eq!(actual_updated_range.cidrs, expected_cidrs);
    }

    #[test]
    fn test_find_exact_fit_grows_block() {
        // Arrange
        let expected_start = String::from("10.0.0.8").parse().unwrap();
        let expected_end = String::from("10.0.0.11").parse().unwrap();
        let expected_ipv4_cidr1 = String::from("10.0.0.8/30").parse().unwrap();
        let expected_cidrs = Some(vec![expected_ipv4_cidr1]);
        let mut range = Ipv4Range::new(expected_start, expected_end);

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        assert_eq!(actual_updated_range.cidrs, expected_cidrs);
    }

    #[test]
    fn test_find_exact_fit_crosses_octet_boundary() {
        // Arrange
        let expected_start = String::from("10.0.0.254").parse().unwrap();
        let expected_end = String::from("10.0.1.1").parse().unwrap();
        let expected_ipv4_cidr1 = String::from("10.0.0.254/31").parse().unwrap();
        let expected_ipv4_cidr2 = String::from("10.0.1.0/31").parse().unwrap();
        let expected_cidrs = Some(vec![expected_ipv4_cidr1, expected_ipv4_cidr2]);
        let mut range = Ipv4Range::new(expected_start, expected_end);

        // Act
        let actual_updated_range = range.find_cidr(RangeMode::ExactFit);

        // Assert
        assert_eq!(actual_updated_range.cidrs, expected_cidrs);
    }
}
