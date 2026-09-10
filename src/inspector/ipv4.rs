use serde::Serialize;

/// Inspection result for IPv4
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Ipv4InspectionResult {
    pub cidr: String,
    pub address: String,
    pub prefix_length: u8,
    pub first_usable: String,
    pub last_usable: String,
    pub network: String,
    pub broadcast: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers;

    #[test]
    fn test_ipv4_inspection_result_type() {
        // Arrange
        // Act
        // Assert
        test_helpers::assert_normal_type::<Ipv4InspectionResult>();
    }
}
