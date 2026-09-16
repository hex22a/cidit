use serde::Serialize;
use tabled::{
    Table, Tabled,
    settings::{Remove, Style, object::Rows},
};

const JSON_OUTPUT_VERSION: u8 = 2;

#[derive(Serialize)]
struct JsonOutput<T> {
    version: u8,
    data: Vec<T>,
}

pub fn print_json<T>(items: T, pretty: bool)
where
    T: Iterator,
    T::Item: Serialize,
{
    let data = items.collect();
    let json_output = JsonOutput {
        version: JSON_OUTPUT_VERSION,
        data,
    };
    match pretty {
        true => println!("{}", serde_json::to_string_pretty(&json_output).unwrap()),
        false => println!("{}", serde_json::to_string(&json_output).unwrap()),
    }
}

pub fn print_ndjson<T>(items: T)
where
    T: Iterator,
    T::Item: Serialize,
{
    for item in items {
        println!("{}", serde_json::to_string(&item).unwrap())
    }
}

pub fn print_table<T>(items: T, headless: bool)
where
    T: Iterator,
    T::Item: Tabled,
{
    let rows: Vec<T::Item> = items.collect();
    let mut table = Table::new(rows);
    table.with(Style::blank());
    if headless {
        table.with(Remove::row(Rows::first()));
    }

    println!("{table}");
}
