use std::str::FromStr;
use std::fmt::Display;

#[derive(Debug, PartialEq)]
pub(crate) enum IpParseError {
    InvalidFormat,
    InvalidIp,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct IPv4 {
    pub(crate) address: u32,
}

impl From<u32> for IPv4 {
    fn from(address: u32) -> IPv4 {
        IPv4 { address }
    }
}

impl FromStr for IPv4 {
    type Err = IpParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return Err(IpParseError::InvalidFormat);
        }
        let octets: Vec<u8> = parts.iter()
            .map(|s| s.parse::<u8>().map_err(|_| IpParseError::InvalidIp))
            .collect::<Result<_, _>>()?;

        let address: u32 = u32::from_be_bytes(octets.try_into().unwrap());
        Ok(Self { address })
    }
}

impl Display for IPv4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.address.to_be_bytes();
        write!(f, "{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

#[cfg(test)]
mod tests {
    use super::IpParseError;
    use super::IPv4;

    const EXPECTED_BINARY_ADDRESS: u32 = 0b00001010_00010110_10000111_10010000;
    const EXPECTED_IPV4_STR: &str = "10.22.135.144";

    #[test]
    fn test_ipv4_from() {
        // Arrange

        // Act
        let actual_ipv4: IPv4 = IPv4::from(EXPECTED_BINARY_ADDRESS);

        // Assert
        assert_eq!(actual_ipv4.address, EXPECTED_BINARY_ADDRESS);
    }

    #[test]
    fn test_parse_ipv4_happy_path() {
        // Arrange
        let expected_ipv4 = IPv4::from(EXPECTED_BINARY_ADDRESS);

        // Act
        let actual_ipv4: IPv4 = EXPECTED_IPV4_STR.parse().unwrap();

        // Assert
        assert_eq!(actual_ipv4, expected_ipv4)
    }

    #[test]
    fn test_parse_ipv4_invalid_format() {
        // Arrange
        let expected_ip_invalid_format = "192.168.1.1.1";

        // Act
        let actual_result: Result<IPv4, IpParseError> = expected_ip_invalid_format.parse();

        // Assert
        assert_eq!(actual_result, Err(IpParseError::InvalidFormat));
    }

    #[test]
    fn test_parse_ipv4_invalid_ip() {
        // Arrange
        let expected_invalid_ip = "192.168.not_a_number.1";

        // Act
        let actual_result: Result<IPv4, IpParseError> = expected_invalid_ip.parse();

        // Assert
        assert_eq!(actual_result, Err(IpParseError::InvalidIp));
    }

    #[test]
    fn test_human_readable() {
        // Arrange
        let expected_ipv4 = IPv4 {
            address: EXPECTED_BINARY_ADDRESS
        };

        // Act
        let actual_human_readable_address: String = expected_ipv4.to_string();

        // Assert
        assert_eq!(actual_human_readable_address, EXPECTED_IPV4_STR.to_string());
    }
}
