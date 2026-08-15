//! # cidit
//!
//! `cidit` (**CID**R **I**nspection **T**ool) is a tool for calculating and inspecting IP ranges

mod cidr;
mod inspector;
mod ip;

pub use cidr::Cidr;
pub use cidr::ipv4::Ipv4Cidr;
pub use inspector::Inspectable;
pub use inspector::InspectionResult;
pub use inspector::ipv4::Ipv4InspectionResult;
pub use inspector::ipv6::Ipv6InspectionResult;
pub use ipnet::Ipv6Net;
