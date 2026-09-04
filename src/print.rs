use cidit::InspectionResult;
use comfy_table::{Table, presets::NOTHING};
use serde::Serialize;
const JSON_OUTPUT_VERSION: u8 = 2;

#[derive(Default)]
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

impl TableRow {
    fn table_row(self) -> Vec<String> {
        vec![
            self.ip_ver.to_string(),
            self.cidr,
            self.address,
            self.prefix.to_string(),
            self.network,
            self.first_usable,
            self.last_usable,
            self.broadcast,
            self.available,
            self.netmask,
            self.hostmask,
        ]
    }
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

pub fn print_json(inspection_results: Vec<InspectionResult>, pretty: bool) {
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

pub fn print_table(results: Vec<InspectionResult>, headless: bool) {
    let rows: Vec<Vec<String>> = results
        .into_iter()
        .map(TableRow::from)
        .map(TableRow::table_row)
        .collect();
    let mut table = Table::new();
    table.load_style(NOTHING);
    if !headless {
        table.set_header(vec![
            "ip_ver",
            "cidr",
            "address",
            "prefix",
            "network",
            "first_usable",
            "last_usable",
            "broadcast",
            "available",
            "netmask",
            "hostmask",
        ]);
    }
    table.add_rows(rows);

    println!("{table}");
}
