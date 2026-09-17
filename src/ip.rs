use std::net::{Ipv4Addr, Ipv6Addr};

pub(crate) trait IpBits {
    fn leading_zeros(self) -> u8;
}

impl IpBits for u32 {
    fn leading_zeros(self) -> u8 {
        self.leading_zeros() as u8
    }
}

impl IpBits for u128 {
    fn leading_zeros(self) -> u8 {
        self.leading_zeros() as u8
    }
}

pub(crate) trait Incrementable: Sized {
    fn checked_add_one(self) -> Option<Self>;
}

impl Incrementable for Ipv4Addr {
    fn checked_add_one(self) -> Option<Self> {
        self.to_bits().checked_add(1).map(Ipv4Addr::from_bits)
    }
}

impl Incrementable for Ipv6Addr {
    fn checked_add_one(self) -> Option<Self> {
        self.to_bits().checked_add(1).map(Ipv6Addr::from_bits)
    }
}
