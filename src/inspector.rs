use serde::Serialize;

pub mod ipv4;

#[derive(Debug, PartialEq, Eq, Serialize)]
pub(crate) struct InspectionResult {
    pub(crate) cidr: String,
    pub(crate) first_usable: String,
    pub(crate) last_usable: String,
    pub(crate) subnet: String,
    pub(crate) broadcast: String,
}