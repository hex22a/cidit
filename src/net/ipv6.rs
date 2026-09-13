use ipnet::Ipv6Net;

const MAX_IPV6_CIDR_PREFIX_LEN: u8 = 128;
const MIN_REASONABLE_PREFIX_LEN: u8 = 96;

pub trait SubnetSize {
    fn subnet_size(&self) -> String;
}

impl SubnetSize for Ipv6Net {
    fn subnet_size(&self) -> String {
        let prefix_len: u8 = self.prefix_len();
        let power: u8 = MAX_IPV6_CIDR_PREFIX_LEN - prefix_len;
        if prefix_len < MIN_REASONABLE_PREFIX_LEN {
            format!("2^{}", power)
        } else {
            format!("{}", 1u128 << power)
        }
    }
}

#[cfg(test)]
mod test {
    use ipnet::Ipv6Net;

    use super::*;

    const EXPECTED_IPV6_STR: &str = "2001:db8:1::ab9:c0a8:102";

    #[test]
    fn test_subnet_size_prefix_gt_96() {
        // Arrange
        let expected_prefix_len: u8 = 97;
        let expected_subnet_size: &str = "2147483648";
        let expected_ipv6_cidr: Ipv6Net =
            Ipv6Net::new(EXPECTED_IPV6_STR.parse().unwrap(), expected_prefix_len).unwrap();

        // Act
        let actual_subnet_size: String = expected_ipv6_cidr.subnet_size();

        // Assert
        assert_eq!(actual_subnet_size, expected_subnet_size);
    }

    #[test]
    fn test_subnet_size_prefix_lte_96() {
        // Arrange
        let expected_prefix_len: u8 = 8;
        let expected_subnet_size: &str = "2^120";
        let expected_ipv6_cidr: Ipv6Net =
            Ipv6Net::new(EXPECTED_IPV6_STR.parse().unwrap(), expected_prefix_len).unwrap();

        // Act
        let actual_subnet_size: String = expected_ipv6_cidr.subnet_size();

        // Assert
        assert_eq!(actual_subnet_size, expected_subnet_size);
    }
}
