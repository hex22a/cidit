//! # cidit
//!
//! `cidit` (**CID**R **I**nspection **T**ool) is a tool for calculating and inspecting IP ranges

mod ip;
mod net;
mod range;

#[cfg(test)]
pub mod test_helpers;

pub use net::Cidr;
pub use net::CidrParseError;
pub use net::IpNetwork;
pub use net::dto::CidrCombinedInfo;
pub use net::dto::CidrInfo;
pub use net::dto::Ipv4CidrInfo;
pub use net::dto::Ipv6CidrInfo;
pub use net::ipv4::Ipv4Cidr;
pub use net::ipv4::Ipv4CidrError;
pub use net::ipv4::Ipv4Network;
pub use net::ipv6::Ipv6Cidr;
pub use net::ipv6::Ipv6CidrError;
pub use net::ipv6::Ipv6Network;
pub use range::AddressRange;
pub use range::IpRange;
pub use range::dto::RangeCombinedInfo;
pub use range::dto::RangeInfo;
pub use range::ipv4::Ipv4Range;
pub use range::ipv6::Ipv6Range;
