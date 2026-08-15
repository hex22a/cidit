mod print;

use cidit::{Cidr, Inspectable, InspectionResult};
use clap::{Parser, ValueEnum};

#[derive(ValueEnum, Clone, Debug)]
enum OutputFormat {
    Json,
    Table,
    Ndjson,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// One or more CIDRs e.g. 10.122.33.129/24
    cidrs: Vec<String>,

    #[arg(short, long, default_value = "table")]
    format: OutputFormat,

    /// Prettify the JSON output (only for --format=json)
    #[arg(short, long)]
    pretty: bool,

    /// Print table without header (only for --format=table)
    #[arg(short = 'H', long)]
    headless: bool,
}

fn main() {
    let args = Args::parse();

    let cidrs: Vec<Cidr> = args
        .cidrs
        .iter()
        .map(|cidr| match cidr.parse::<Cidr>() {
            Ok(cidr) => cidr,
            Err(err) => {
                eprintln!("Invalid CIDR '{}': {:?}", cidr, err);
                std::process::exit(1);
            }
        })
        .collect::<Vec<Cidr>>();

    let inspection_results: Vec<InspectionResult> = cidrs
        .iter()
        .map(|cidr| match cidr {
            Cidr::V4(v4) => v4.inspect(),
            Cidr::V6(v6) => v6.inspect(),
        })
        .collect();

    match args.format {
        OutputFormat::Json => {
            print::print_json(inspection_results, &args.pretty);
        }
        OutputFormat::Table => {
            print::print_table(inspection_results, &args.headless);
        }
        OutputFormat::Ndjson => {
            print::print_ndjson(inspection_results);
        }
    }
}
