use serde::Serialize;

#[derive(Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Ipv4InspectionResult {
    pub(crate) cidr: String,
    pub(crate) address: String,
    pub(crate) prefix_len: u8,
    pub(crate) first_usable: String,
    pub(crate) last_usable: String,
    pub(crate) subnet: String,
    pub(crate) broadcast: String,
}

