use crate::inspector::ipv4::Ipv4InspectionResult;
use crate::inspector::ipv6::Ipv6InspectionResult;
use serde::Serialize;

pub mod ipv4;
pub mod ipv6;

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "ip_version", rename_all = "lowercase")]
pub enum InspectionResult {
    V4(Ipv4InspectionResult),
    V6(Ipv6InspectionResult),
}

pub trait Inspectable {
    fn inspect(&self) -> InspectionResult;
}
