use std::net::Ipv6Addr;

use crate::{
    Cidr,
    net::ipv6::{Ipv6Cidr, Ipv6Network},
    range::AddressRange,
};

pub struct Ipv6Range {
    start: Ipv6Addr,
    end: Ipv6Addr,
}

impl Ipv6Range {
    pub fn new(start: Ipv6Addr, end: Ipv6Addr) -> Self {
        Self { start, end }
    }

    pub fn start(&self) -> Ipv6Addr {
        self.start
    }

    pub fn end(&self) -> Ipv6Addr {
        self.end
    }
}

impl AddressRange for Ipv6Range {
    fn smallest_common_cidr(&self) -> Cidr {
        let diff = self.start.to_bits() ^ self.end.to_bits();
        let prefix: u8 = diff.leading_zeros() as u8;
        Cidr::V6(
            Ipv6Cidr::new(self.start.to_bits() & !diff, prefix)
                .expect("prefix is always less or equal to 128"),
        )
    }

    fn exact_fit(&self) -> Vec<Cidr> {
        let mut result: Vec<Cidr> = Vec::new();
        let mut start_addr = self.start.to_bits();
        let end_addr = self.end.to_bits();

        while start_addr <= end_addr {
            let mut prefix = 128u8;
            let mut guess_cidr =
                Ipv6Cidr::new(start_addr, prefix).expect("prefix is always less or equal to 128");
            let mut next_guess_cidr = guess_cidr;

            while next_guess_cidr.network_address() == start_addr
                && next_guess_cidr.last_address() <= end_addr
            {
                guess_cidr = next_guess_cidr;

                if prefix == 0 {
                    break;
                }

                prefix -= 1;
                next_guess_cidr = Ipv6Cidr::new(start_addr, prefix)
                    .expect("prefix is always less or equal to 128");
            }

            result.push(Cidr::V6(guess_cidr));

            if prefix == 0 {
                break;
            }

            start_addr = guess_cidr.last_address() + 1;
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
        let expected_start = String::from("2001:db8::10").parse().unwrap();
        let expected_end = String::from("2001:db8::20").parse().unwrap();
        let expected_ipv6_cidr = String::from("2001:db8::/122").parse().unwrap();
        let expected_common_cidr = Cidr::V6(expected_ipv6_cidr);
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
        let expected_ipv6_cidr = String::from("2001:db8::10/128").parse().unwrap();
        let expected_common_cidr = Cidr::V6(expected_ipv6_cidr);
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
        let expected_cidrs = vec![Cidr::V6(expected_ipv6_cidr1), Cidr::V6(expected_ipv6_cidr2)];
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
            Cidr::V6(expected_ipv6_cidr1),
            Cidr::V6(expected_ipv6_cidr2),
            Cidr::V6(expected_ipv6_cidr3),
            Cidr::V6(expected_ipv6_cidr4),
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
        let expected_cidrs = vec![Cidr::V6(expected_ipv6_cidr1)];
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
        let expected_cidrs = vec![Cidr::V6(expected_ipv6_cidr1)];
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
        let expected_cidrs = vec![Cidr::V6(expected_ipv6_cidr1)];
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
        let expected_cidrs = vec![Cidr::V6(expected_ipv6_cidr1)];
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
        let expected_cidrs = vec![Cidr::V6(expected_ipv6_cidr1)];
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
        let expected_cidrs = vec![Cidr::V6(expected_ipv6_cidr1), Cidr::V6(expected_ipv6_cidr2)];
        let range = Ipv6Range::new(expected_start, expected_end);

        // Act
        let actual_cidrs = range.exact_fit();

        // Assert
        assert_eq!(actual_cidrs, expected_cidrs);
    }
}
