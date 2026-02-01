use serde::Serialize;
use tabled::{Table, Tabled};
use tabled::settings::{Remove, Style};
use tabled::settings::object::Rows;

pub mod ipv4;

const JSON_OUTPUT_VERSION: u8 = 1;

#[derive(Debug, PartialEq, Eq, Serialize, Tabled)]
pub(crate) struct InspectionResult {
    pub(crate) cidr: String,
    pub(crate) first_usable: String,
    pub(crate) last_usable: String,
    pub(crate) subnet: String,
    pub(crate) broadcast: String,
}

#[derive(Serialize)]
struct JsonOutput<'a> {
    version: u8,
    data: &'a Vec<InspectionResult>
}

pub fn print_json(inspection_results: &Vec<InspectionResult>, pretty: &bool) {
    let json_output = JsonOutput {
        version: JSON_OUTPUT_VERSION,
        data: inspection_results,
    };
    match pretty {
        true => println!("{}", serde_json::to_string_pretty(&json_output).unwrap()),
        false => println!("{}", serde_json::to_string(&json_output).unwrap()),
    }
}

pub fn print_table(results: &Vec<InspectionResult>, headless: &bool) {
    let mut table = Table::new(results);
    (&mut table).with(Style::blank());
    if *headless {
        (&mut table).with(Remove::row(Rows::first()));
    }

    println!("{table}");
}