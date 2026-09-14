use std::net::Ipv4Addr;

use crate::{Cidr, Ipv4Cidr, net::ipv4::Ipv4Network, range::AddressRange};

pub struct Ipv4Range {
    start: Ipv4Addr,
    end: Ipv4Addr,
}

impl Ipv4Range {
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        Self { start, end }
    }

    pub fn start(&self) -> Ipv4Addr {
        self.start
    }

    pub fn end(&self) -> Ipv4Addr {
        self.end
    }
}

impl AddressRange for Ipv4Range {
    fn smallest_common_cidr(&self) -> Cidr {
        let diff = self.start.to_bits() ^ self.end.to_bits();
        let prefix: u8 = diff.leading_zeros() as u8;
        Cidr::V4(
            Ipv4Cidr::new(self.start.to_bits() & !diff, prefix)
                .expect("prefix is always less or equal to 32"),
        )
    }

    fn exact_fit(&self) -> Vec<Cidr> {
        let mut result: Vec<Cidr> = Vec::new();
        let mut start_addr = self.start.to_bits();
        let end_addr = self.end.to_bits();

        while start_addr <= end_addr {
            let mut prefix = 32u8;
            let mut guess_cidr: Ipv4Cidr =
                Ipv4Cidr::new(start_addr, prefix).expect("prefix is always less or equal to 32");
            let mut next_guess_cidr = guess_cidr;

            while next_guess_cidr.network_address().to_bits() == start_addr
                && next_guess_cidr.broadcast_address().to_bits() <= end_addr
            {
                guess_cidr = next_guess_cidr;

                if prefix == 0 {
                    break;
                }

                prefix -= 1;
                next_guess_cidr = Ipv4Cidr::new(start_addr, prefix)
                    .expect("prefix is always less or equal to 32");
            }

            result.push(Cidr::V4(guess_cidr));

            if prefix == 0 {
                break;
            }

            start_addr = guess_cidr.broadcast_address().to_bits() + 1;
        }

        result
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
        let expected_ipv4_cidr = String::from("10.0.0.0/27").parse().unwrap();
        let expected_common_cidr = Cidr::V4(expected_ipv4_cidr);
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
        let expected_ipv4_cidr = String::from("10.0.0.0/27").parse().unwrap();
        let expected_common_cidr = Cidr::V4(expected_ipv4_cidr);
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
        let expected_ipv4_cidr = String::from("10.0.0.10/32").parse().unwrap();
        let expected_common_cidr = Cidr::V4(expected_ipv4_cidr);
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
            Cidr::V4(expected_ipv4_cidr1),
            Cidr::V4(expected_ipv4_cidr2),
            Cidr::V4(expected_ipv4_cidr3),
            Cidr::V4(expected_ipv4_cidr4),
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
            Cidr::V4(expected_ipv4_cidr1),
            Cidr::V4(expected_ipv4_cidr2),
            Cidr::V4(expected_ipv4_cidr3),
            Cidr::V4(expected_ipv4_cidr4),
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
        let expected_cidrs = vec![Cidr::V4(expected_ipv4_cidr1)];
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
        let expected_cidrs = vec![Cidr::V4(expected_ipv4_cidr1)];
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
        let expected_cidrs = vec![Cidr::V4(expected_ipv4_cidr1)];
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
        let expected_cidrs = vec![Cidr::V4(expected_ipv4_cidr1)];
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
        let expected_cidrs = vec![Cidr::V4(expected_ipv4_cidr1)];
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
        let expected_cidrs = vec![Cidr::V4(expected_ipv4_cidr1), Cidr::V4(expected_ipv4_cidr2)];
        let range = Ipv4Range::new(expected_start, expected_end);

        // Act
        let actual_cidrs = range.exact_fit();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs);
    }
}
