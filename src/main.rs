mod ip;
mod inspector;

use clap::{Parser, ValueEnum};
use crate::inspector::InspectionResult;
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
    /// One or more CIDRs e.g. 10.122.33.129/24
    cidrs: Vec<String>,

    #[arg (short, long, default_value = "table")]
    format: OutputFormat,

    /// Prettify the JSON output (only for --format=json)
    #[arg (short, long)]
    pretty: bool,

    /// Print table without header (only for --format=table)
    #[arg (short='H', long)]
    headless: bool,
}

fn main() {
    let args = Args::parse();

    let cidrs: Vec<Ipv4Cidr> = args.cidrs.iter().map(|cidr| {
        match cidr.parse::<Ipv4Cidr>() {
            Ok(cidr) => cidr,
            Err(err ) => {
                eprintln!("Invalid CIDR '{}': {:?}", cidr, err);
                std::process::exit(1);
            }
        }
    }).collect::<Vec<Ipv4Cidr>>();

    let inspection_results: Vec<InspectionResult> = cidrs.iter()
        .map(|cidr| cidr.inspect()).collect();

    match args.format {
        OutputFormat::Json => {
            inspector::print_json(&inspection_results, &args.pretty);
        },
        OutputFormat::Table => {
            inspector::print_table(&inspection_results, &args.headless);
        }
    }
}
