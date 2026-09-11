use ipnet::Ipv6AddrRange;

use crate::{Cidr, range::ipv4::Ipv4Range};

mod ipv4;
mod ipv6;

pub trait AddressRange {
    fn smallest_common_cidr(&self) -> Cidr;
    fn exact_fit(&self) -> Vec<Cidr>;
}

pub enum IpRange {
    V4(Ipv4Range),
    V6(Ipv6AddrRange),
}
