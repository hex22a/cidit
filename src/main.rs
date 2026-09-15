mod print;

use cidit::{AddressRange, Cidr, IpRange};
use clap::{Parser, ValueEnum};

use crate::print::{CidrJsonInfo, CidrTabledInfo, RangeJsonInfo, RangeTabledInfo};

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

    /// Output format
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,

    /// Prettify the JSON output (only for --format=json)
    #[arg(short, long, requires = "format")]
    pretty: bool,

    /// Print table without header (only for --format=table)
    #[arg(short = 'H', long, requires = "format")]
    headless: bool,

    /// Get smallest CIDR that contains a given range
    #[arg(short, long)]
    range: Option<String>,

    /// Get one or more CIDR blocks to exactly match the provided range
    /// (only for --range)
    #[arg(short, long, requires = "range")]
    exact: bool,
}

fn main() {
    let args = Args::parse();

    match args.range {
        Some(range) => {
            let range: IpRange = range.parse::<IpRange>().unwrap_or_else(|e| {
                eprintln!("'{range}': {e}");
                std::process::exit(1);
            });

            let cidrs: Vec<Cidr> = if args.exact {
                range.exact_fit()
            } else {
                vec![range.smallest_common_cidr()]
            };

            match args.format {
                OutputFormat::Json => {
                    print::print_json::<RangeJsonInfo>(cidrs, args.pretty);
                }
                OutputFormat::Table => {
                    print::print_table::<RangeTabledInfo>(cidrs, args.headless);
                }
                OutputFormat::Ndjson => {
                    print::print_ndjson::<RangeJsonInfo>(cidrs);
                }
            }
        }
        None => {
            let cidrs: Vec<Cidr> = args
                .cidrs
                .iter()
                .map(|cidr| match cidr.parse::<Cidr>() {
                    Ok(cidr) => cidr,
                    Err(err) => {
                        eprintln!("'{}': {}", cidr, err);
                        std::process::exit(1);
                    }
                })
                .collect::<Vec<Cidr>>();

            match args.format {
                OutputFormat::Json => {
                    print::print_json::<CidrJsonInfo>(cidrs, args.pretty);
                }
                OutputFormat::Table => {
                    print::print_table::<CidrTabledInfo>(cidrs, args.headless);
                }
                OutputFormat::Ndjson => {
                    print::print_ndjson::<CidrJsonInfo>(cidrs);
                }
            }
        }
    }
}
