use cidit::InspectionResult;
use serde::Serialize;
use tabled::{
    Table, Tabled,
    settings::{Remove, Style, object::Rows},
};

const JSON_OUTPUT_VERSION: u8 = 2;

#[derive(Tabled, Default)]
pub(crate) struct TableRow {
    ip_ver: &'static str,
    cidr: String,
    address: String,
    prefix: u8,
    network: String,
    first_usable: String,
    last_usable: String,
    broadcast: String,
    available: String,
    netmask: String,
    hostmask: String,
}

#[derive(Serialize)]
struct JsonOutput {
    version: u8,
    data: Vec<InspectionResult>,
}

impl From<InspectionResult> for TableRow {
    fn from(value: InspectionResult) -> Self {
        match value {
            InspectionResult::V4(v4) => TableRow {
                ip_ver: "v4",
                cidr: v4.cidr,
                address: v4.address,
                prefix: v4.prefix_length,
                first_usable: v4.first_usable,
                last_usable: v4.last_usable,
                network: v4.network,
                broadcast: v4.broadcast,
                ..Default::default()
            },
            InspectionResult::V6(v6) => TableRow {
                ip_ver: "v6",
                cidr: v6.cidr,
                address: v6.address,
                prefix: v6.prefix_length,
                netmask: v6.netmask,
                hostmask: v6.hostmask,
                network: v6.network,
                available: v6.subnet_size,
                ..Default::default()
            },
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

pub fn print_ndjson(inspection_results: Vec<InspectionResult>) {
    inspection_results
        .iter()
        .for_each(|item| println!("{}", serde_json::to_string(&item).unwrap()));
}

pub fn print_table(results: Vec<InspectionResult>, headless: &bool) {
    let rows: Vec<TableRow> = results.into_iter().map(TableRow::from).collect();
    let mut table = Table::new(rows);
    table.with(Style::blank());
    if *headless {
        table.with(Remove::row(Rows::first()));
    }

    println!("{table}");
}
