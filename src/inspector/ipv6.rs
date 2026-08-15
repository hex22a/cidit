use serde::Serialize;

/// Inspection result for IPv6
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Ipv6InspectionResult {
    pub cidr: String,
    pub address: String,
    pub prefix_length: u8,
    pub netmask: String,
    pub hostmask: String,
    pub network: String,
    pub subnet_size: String,
}
