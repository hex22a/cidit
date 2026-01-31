use crate::inspector::InspectionResult;

pub trait Inspectable {
    fn get_subnet_address(&self) -> u32;
    fn inspect(&self) -> InspectionResult;
}

pub trait HumanReadable {
    fn human_readable(&self) -> String;
}

