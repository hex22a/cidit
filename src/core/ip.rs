pub struct IPv4;

pub trait Address {
    fn get_ip_and_mask(string: String) -> (String, u8);
    fn split_into_octets(string: &str) -> Vec<u8>;
    fn get_binary_address(octets: Vec<u8>) -> u32;
    fn get_binary_mask(mask: u8) -> u32;
    fn get_subnet_address(address: u32, mask: u32) -> u32;
    fn get_ip_range_and_broadcast(subnet_address: u32, mask: u8) -> (u32, u32, u32);
    fn get_human_readable_address(address: u32) -> String;
}

impl Address for IPv4 {
    fn get_ip_and_mask(string: String) -> (String, u8) {
        let (ip, str_mask) = string.split_once("/").unwrap();
        (ip.to_string(), str_mask.parse::<u8>().unwrap())
    }

    fn split_into_octets(string: &str) -> Vec<u8> {
        string.split('.').map(|s| u8::from_str_radix(s, 10).unwrap()).collect()
    }

    fn get_binary_address(octets: Vec<u8>) -> u32 {
        u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]])
    }

    fn get_binary_mask(mask: u8) -> u32 {
        !0u32 << (32 - mask)
    }

    fn get_subnet_address(address: u32, mask: u32) -> u32 {
        address & mask
    }

    fn get_ip_range_and_broadcast(subnet_address: u32, mask: u8) -> (u32, u32, u32) {
        let first_usable_ip = subnet_address + 1;
        let broadcast_address = subnet_address + (!0u32 >> mask);
        let last_usable_ip = broadcast_address - 1;
        (first_usable_ip, last_usable_ip, broadcast_address)
    }

    fn get_human_readable_address(address: u32) -> String {
        address.to_be_bytes().iter().map(|byte| format!("{}", byte)).collect::<Vec<_>>().join(".")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::Address;

    #[test]
    fn test_get_ip_and_mask() {
        // Arrange
        let expected_ip: &str = "10.1.1.1";
        let expected_mask: u8 = 24;
        let expected_ip_and_mask = (expected_ip.to_string(), expected_mask);
        let expected_cidr: String = format!("{expected_ip}/{expected_mask}");

        // Act
        let actual_ip_and_mask = IPv4::get_ip_and_mask(expected_cidr);

        // Assert
        assert_eq!(actual_ip_and_mask, expected_ip_and_mask);
    }

    #[test]
    fn test_split_into_octets() {
        // Arrange
        let expected_octets: Vec<u8> = vec![10, 88, 135, 144];
        // Act
        let actual_octets: Vec<u8> = IPv4::split_into_octets("10.88.135.144");
        // Assert
        assert_eq!(actual_octets, expected_octets);
    }

    #[test]
    fn test_get_binary_address() {
        // Arrange
        let expected_octets: Vec<u8> = vec![10, 88, 135, 144];
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        // Act
        let actual_binary_address: u32 = IPv4::get_binary_address(expected_octets);
        // Assert
        assert_eq!(actual_binary_address, expected_binary_address);
    }

    #[test]
    fn test_get_binary_mask() {
        // Arrange
        let expected_mask: u8 = 24;
        let expected_binary_mask: u32 = 0b11111111_11111111_11111111_00000000;

        // Act
        let actual_binary_mask: u32 = IPv4::get_binary_mask(expected_mask);

        // Assert
        assert_eq!(actual_binary_mask, expected_binary_mask);
    }

    #[test]
    fn test_get_subnet_address() {
        // Arrange
        let expected_binary_mask: u32 = 0b11111111_11111111_11111111_00000000;
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_subnet_address: u32 = 0b00001010_01011000_10000111_00000000;

        // Act
        let actual_subnet_address: u32 = IPv4::get_subnet_address(expected_binary_address, expected_binary_mask);

        // Assert
        assert_eq!(actual_subnet_address, expected_subnet_address);
    }

    #[test]
    fn test_get_ip_range_and_broadcast() {
        // Arrange
        let expected_mask: u8 = 24;
        let expected_subnet_address: u32 = 0b00001010_01011000_10000111_00000000;
        let expected_first_usable_ip: u32 = 0b00001010_01011000_10000111_00000001;
        let expected_last_usable_ip: u32 = 0b00001010_01011000_10000111_11111110;
        let expected_broadcast_ip: u32 = 0b00001010_01011000_10000111_11111111;
        let expected_ip_range: (u32, u32, u32) = (expected_first_usable_ip, expected_last_usable_ip, expected_broadcast_ip);

        // Act
        let actual_ip_range: (u32, u32, u32) = IPv4::get_ip_range_and_broadcast(expected_subnet_address, expected_mask);

        // Assert
        assert_eq!(actual_ip_range, expected_ip_range);
    }

    #[test]
    fn test_get_human_readable_address() {
        // Arrange
        let expected_binary_address: u32 = 0b00001010_01011000_10000111_10010000;
        let expected_human_readable_address: String = "10.88.135.144".to_string();

        // Act
        let actual_human_readable_address = IPv4::get_human_readable_address(expected_binary_address);

        // Assert
        assert_eq!(actual_human_readable_address, expected_human_readable_address);
    }
}
