use serde::Serialize;
use tabled::{Table, Tabled};
use tabled::settings::Style;

pub mod ipv4;

#[derive(Debug, PartialEq, Eq, Serialize, Tabled)]
pub(crate) struct InspectionResult {
    pub(crate) cidr: String,
    pub(crate) first_usable: String,
    pub(crate) last_usable: String,
    pub(crate) subnet: String,
    pub(crate) broadcast: String,
}

pub fn print_table(result: &InspectionResult) {
    let mut binding = Table::new(vec![result]);
    let table = binding
        .with(Style::blank());

    println!("{table}");
}