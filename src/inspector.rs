use serde::Serialize;
use tabled::{Table, Tabled};
use tabled::settings::{Remove, Style};
use tabled::settings::object::Rows;
use crate::inspector::ipv4::Ipv4InspectionResult;
use crate::inspector::ipv6::Ipv6InspectionResult;

pub mod ipv4;
pub mod ipv6;

const JSON_OUTPUT_VERSION: u8 = 1;

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "ip_version", rename_all="lowercase")]
pub(crate) enum InspectionResult {
    V4(Ipv4InspectionResult),
    V6(Ipv6InspectionResult),
}

pub(crate) trait Inspectable {
    fn inspect(&self) -> InspectionResult;
}

#[derive(Tabled, Default)]
pub(crate) struct TableRow {
    ip_version: &'static str,
    cidr: String,
    address: String,
    prefix_len: u8,
    first_usable: String,
    last_usable: String,
    subnet: String,
    broadcast: String,
    netmask: String,
    hostmask: String,
    network: String,
    subnet_size: String,
}

#[derive(Serialize)]
struct JsonOutput {
    version: u8,
    data: Vec<InspectionResult>
}

impl From<InspectionResult> for TableRow {
    fn from(value: InspectionResult) -> Self {
        match value {
            InspectionResult::V4(v4) => TableRow {
                ip_version: "v4",
                cidr: v4.cidr,
                address: v4.address,
                prefix_len: v4.prefix_len,
                first_usable: v4.first_usable,
                last_usable: v4.last_usable,
                subnet: v4.subnet,
                broadcast: v4.broadcast,
                ..Default::default()
            },
            InspectionResult::V6(v6) => TableRow {
                ip_version: "v6",
                cidr: v6.cidr,
                address: v6.address,
                prefix_len: v6.prefix_len,
                netmask: v6.netmask,
                hostmask: v6.hostmask,
                network: v6.network,
                subnet_size: v6.subnet_size,
                ..Default::default()
            }
        }
    }
}

pub fn print_json(inspection_results: Vec<InspectionResult>, pretty: &bool) {
    let json_output = JsonOutput {
        version: JSON_OUTPUT_VERSION,
        data: inspection_results,
    };
    match pretty {
        true => println!("{}", serde_json::to_string_pretty(&json_output).unwrap()),
        false => println!("{}", serde_json::to_string(&json_output).unwrap()),
    }
}

pub fn print_table(results: Vec<InspectionResult>, headless: &bool) {
    let rows: Vec<TableRow> = results.into_iter().map(TableRow::from).collect();
    let mut table = Table::new(rows);
    (&mut table).with(Style::blank());
    if *headless {
        (&mut table).with(Remove::row(Rows::first()));
    }

    println!("{table}");
}
