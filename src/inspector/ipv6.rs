use serde::Serialize;

#[derive(Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Ipv6InspectionResult {
    pub(crate) cidr: String,
    pub(crate) address: String,
    pub(crate) prefix_len: u8,
    pub(crate) netmask: String,
    pub(crate) hostmask: String,
    pub(crate) network: String,
    pub(crate) subnet_size: String,
}

