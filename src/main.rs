mod print;

use cidit::{
    AddressRange, Cidr, CidrCombinedInfo, CidrInfo, IpRange, RangeCombinedInfo, RangeInfo,
    RangeMode,
};
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
    #[arg(short, long, num_args=1..)]
    range: Option<Vec<String>>,

    /// Get one or more CIDR blocks to exactly match the provided range
    /// (only for --range)
    #[arg(short, long, requires = "range")]
    exact: bool,
}

fn main() {
    let args = Args::parse();

    match args.range {
        Some(ranges) => {
            let ranges = ranges.iter().map(|range| {
                let mut range = range.parse::<IpRange>().unwrap_or_else(|e| {
                    eprintln!("'{range}': {e}");
                    std::process::exit(1);
                });

                let mode = if args.exact {
                    RangeMode::ExactFit
                } else {
                    RangeMode::SmallestCommon
                };

                range.find_cidr(mode);
                range
            });

            match args.format {
                OutputFormat::Json => {
                    let info = ranges.map(|range| {
                        let info: Vec<RangeInfo> = range.into();
                        info
                    });
                    print::print_json(info, args.pretty);
                }
                OutputFormat::Table => {
                    let info = ranges.flat_map(|range| {
                        let info: Vec<RangeCombinedInfo> = range.into();
                        info
                    });
                    print::print_table(info, args.headless);
                }
                OutputFormat::Ndjson => {
                    let info = ranges.map(|range| {
                        let info: Vec<RangeInfo> = range.into();
                        info
                    });
                    print::print_ndjson(info);
                }
            }
        }
        None => {
            let cidrs = args.cidrs.iter().map(|cidr| match cidr.parse::<Cidr>() {
                Ok(cidr) => cidr,
                Err(err) => {
                    eprintln!("'{}': {}", cidr, err);
                    std::process::exit(1);
                }
            });

            match args.format {
                OutputFormat::Json => {
                    let info = cidrs.map(CidrInfo::from);
                    print::print_json(info, args.pretty);
                }
                OutputFormat::Table => {
                    let info = cidrs.map(CidrCombinedInfo::from);
                    print::print_table(info, args.headless);
                }
                OutputFormat::Ndjson => {
                    let info = cidrs.map(CidrInfo::from);
                    print::print_ndjson(info);
                }
            }
        }
    }
}
