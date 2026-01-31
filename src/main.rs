mod ip;
mod inspector;

use clap::{Parser, ValueEnum};
use crate::inspector::ipv4::Inspectable;
use crate::ip::ipv4::Ipv4Cidr;

#[derive(ValueEnum, Clone, Debug)]
enum OutputFormat {
    Json,
    Table
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// CIDR e.g. 10.122.33.129/24
    cidr: String,

    #[arg (short, long, default_value = "table")]
    format: OutputFormat,
}

fn main() {
    let args = Args::parse();
    let cidr = match args.cidr.parse::<Ipv4Cidr>() {
        Ok(cidr) => cidr,
        Err(err) => {
            eprintln!("Invalid CIDR '{}': {:?}", args.cidr, err);
            std::process::exit(1);
        }
    };
    let inspection_result = cidr.inspect();
    match args.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string(&inspection_result).unwrap());
        },
        OutputFormat::Table => {
            inspector::print_table(&inspection_result);
        }
    }
}
