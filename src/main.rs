mod ip;
mod inspector;

use clap::Parser;
use crate::inspector::ipv4::Inspectable;
use crate::ip::ipv4::Ipv4Cidr;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// CIDR e.g. 10.122.33.129/24
    cidr: String,
}

fn main() {
    let args = Args::parse();
    let inspection_result = args.cidr.parse::<Ipv4Cidr>().unwrap().inspect();
    println!("{}", serde_json::to_string(&inspection_result).unwrap());
}
