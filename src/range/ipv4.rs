use crate::{
    Cidr,
    cidr::ipv4::Ipv4CidrParts,
    ip::ipv4::{Address, IPv4},
    range::AddressRange,
};

pub struct Ipv4Range {
    start: IPv4,
    end: IPv4,
}

impl Ipv4Range {
    pub fn new(start: IPv4, end: IPv4) -> Self {
        Self { start, end }
    }
}

impl AddressRange for Ipv4Range {
    fn smallest_common_cidr(&self) -> Cidr {
        let diff = self.start.addr() ^ self.end.addr();
        let prefix: u8 = diff.leading_zeros() as u8;
        Cidr::V4(
            Ipv4CidrParts {
                address: self.start.addr() & !diff,
                prefix,
            }
            .try_into()
            .expect("prefix is always less or equal to 32"),
        )
    }

    fn exact_fit(&self) -> Vec<Cidr> {
        todo!()
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
}
