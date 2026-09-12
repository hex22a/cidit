mod print;

use cidit::{AddressRange, Cidr, Inspectable, InspectionResult, IpRange};
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
                eprintln!("{e}");
                std::process::exit(1);
            });

            let cidrs: Vec<Cidr> = match range {
                IpRange::V4(ipv4_range) => {
                    if args.exact {
                        ipv4_range.exact_fit()
                    } else {
                        vec![ipv4_range.smallest_common_cidr()]
                    }
                }
                IpRange::V6(ipv6_range) => {
                    if args.exact {
                        ipv6_range.exact_fit()
                    } else {
                        vec![ipv6_range.smallest_common_cidr()]
                    }
                }
            };

            for cidr in cidrs {
                println!("{}", cidr);
            }
        }
        None => {
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
                    print::print_json(inspection_results, args.pretty);
                }
                OutputFormat::Table => {
                    print::print_table(inspection_results, args.headless);
                }
                OutputFormat::Ndjson => {
                    print::print_ndjson(inspection_results);
                }
            }
        }
    }
}
