use serde::Serialize;

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
