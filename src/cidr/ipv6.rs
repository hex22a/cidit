use ipnet::Ipv6Net;

use crate::inspector::{InspectionResult, Inspectable, ipv6::Ipv6InspectionResult};

const MAX_IPV6_CIDR_PREFIX_LEN: u8 = 128;
const MIN_REASONABLE_PREFIX_LEN: u8 = 96;

pub(crate) trait SubnetSize {
    fn subnet_size(&self) -> String;
}

impl SubnetSize for Ipv6Net {
    fn subnet_size(&self) -> String {
        let prefix_len: u8 = self.prefix_len();
        let power: u8 = MAX_IPV6_CIDR_PREFIX_LEN - prefix_len;
        if prefix_len < MIN_REASONABLE_PREFIX_LEN {
            return format!("2^{}", power);
        } else {
            return format!("{}", 1u128 << power);
        }
    }
}

impl Inspectable for Ipv6Net {
    fn inspect(&self) -> InspectionResult {
        let cidr = format!("{}/{}", self.addr(), self.prefix_len());
        return InspectionResult::V6(Ipv6InspectionResult {
            cidr, 
            address: self.addr().to_string(),
            prefix_len: self.prefix_len(),
            netmask: self.netmask().to_string(),
            hostmask: self.hostmask().to_string(),
            network: self.network().to_string(),
            subnet_size: self.subnet_size()
        });
    }
}

#[cfg(test)]
mod test {
    use ipnet::Ipv6Net;
    use crate::inspector::{InspectionResult, Inspectable, ipv6::Ipv6InspectionResult};

    use super::SubnetSize;

    const EXPECTED_IPV6_STR: &str = "2001:db8:1::ab9:c0a8:102";

    #[test]
    fn test_subnet_size_prefix_gt_96() {
        // Arrange
        let expected_prefix_len: u8 = 97;
        let expected_subnet_size: &str = "2147483648";
        let expected_ipv6_cidr: Ipv6Net = Ipv6Net::new(EXPECTED_IPV6_STR.parse().unwrap(), expected_prefix_len).unwrap();

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
        let expected_ipv6_cidr: Ipv6Net = Ipv6Net::new(EXPECTED_IPV6_STR.parse().unwrap(), expected_prefix_len).unwrap();

        // Act
        let actual_subnet_size: String = expected_ipv6_cidr.subnet_size(); 

        // Assert
        assert_eq!(actual_subnet_size, expected_subnet_size);
    }

    #[test]
    fn test_inspect() {
        // Arrange
        let expected_prefix_len: u8 = 64;
        let expected_cidr_str: String = format!("{EXPECTED_IPV6_STR}/{expected_prefix_len}");
        let expected_subnet_size: String = "2^64".to_string();
        let expected_netmask: String = "ffff:ffff:ffff:ffff::".to_string();
        let expected_hostmask: String = "::ffff:ffff:ffff:ffff".to_string();
        let expected_network: String = "2001:db8:1::".to_string();
        let expected_ipv6_cidr: Ipv6Net = Ipv6Net::new(EXPECTED_IPV6_STR.parse().unwrap(), expected_prefix_len).unwrap();
        let expected_inspection_result: InspectionResult = InspectionResult::V6(Ipv6InspectionResult {
            cidr: expected_cidr_str,
            address: EXPECTED_IPV6_STR.to_string(),
            prefix_len: expected_prefix_len,
            netmask: expected_netmask,
            hostmask: expected_hostmask,
            network: expected_network,
            subnet_size: expected_subnet_size,
        });

        // Act
        let actual_inspection_result: InspectionResult = expected_ipv6_cidr.inspect();

        // Assert
        assert_eq!(actual_inspection_result, expected_inspection_result);
    }
}
