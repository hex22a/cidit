use std::net::AddrParseError;

use thiserror::Error;

use crate::ip::ipv4::Ipv4ParseError;

pub mod ipv4;

#[derive(Debug, Error)]
pub enum IpParseError {
    #[error("IPv4 parse error: {0}")]
    V4(Ipv4ParseError),
    #[error("IPv6 parse error: {0}")]
    V6(AddrParseError),
}
