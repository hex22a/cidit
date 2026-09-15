use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub trait IpBits {
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

pub trait Incrementable: Sized {
    fn checked_add_one(self) -> Option<Self>;
}

impl Incrementable for IpAddr {
    fn checked_add_one(self) -> Option<Self> {
        match self {
            IpAddr::V4(ipv4_addr) => ipv4_addr
                .to_bits()
                .checked_add(1)
                .map(Ipv4Addr::from_bits)
                .map(IpAddr::V4),
            IpAddr::V6(ipv6_addr) => ipv6_addr
                .to_bits()
                .checked_add(1)
                .map(Ipv6Addr::from_bits)
                .map(IpAddr::V6),
        }
    }
}
