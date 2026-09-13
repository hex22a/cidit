//! # cidit
//!
//! `cidit` (**CID**R **I**nspection **T**ool) is a tool for calculating and inspecting IP ranges

mod cidr;
mod ip;
mod range;

#[cfg(test)]
pub mod test_helpers;

pub use cidr::Cidr;
pub use cidr::ipv4::Ipv4Cidr;
pub use cidr::ipv4::Ipv4CidrError;
pub use cidr::ipv4::Ipv4Network;
pub use cidr::ipv4::POINT_TO_POINT_CIDR_PREFIX_LEN;
pub use cidr::ipv6::SubnetSize;
pub use ip::ipv4::IPv4;
pub use ipnet::Ipv6Net;
pub use range::AddressRange;
pub use range::IpRange;
