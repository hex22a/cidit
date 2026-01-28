mod core;

use clap::Parser;
use crate::core::ip::Address;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// CIDR e.g. 10.122.33.129/24
    cidr: String,
}

fn main() {
    let args = Args::parse();

    let (ip, mask) = core::ip::IPv4::get_ip_and_mask(args.cidr);
    let octets = core::ip::IPv4::split_into_octets(ip.as_str());
    let binary_ip = core::ip::IPv4::get_binary_address(octets);
    let binary_mask = core::ip::IPv4::get_binary_mask(mask);
    let subnet_address = core::ip::IPv4::get_subnet_address(binary_ip, binary_mask);
    let (first_usable_ip, last_usable_ip, broadcast_ip) = core::ip::IPv4::get_ip_range_and_broadcast(subnet_address, mask);

    println!("Subnet mask: {}", core::ip::IPv4::get_human_readable_address(binary_mask));
    println!("First usable IP: {}", core::ip::IPv4::get_human_readable_address(first_usable_ip));
    println!("Last usable IP: {}", core::ip::IPv4::get_human_readable_address(last_usable_ip));
    println!("Broadcast IP: {}", core::ip::IPv4::get_human_readable_address(broadcast_ip));
}
