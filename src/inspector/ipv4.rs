use crate::inspector::InspectionResult;

pub trait Inspectable {
    fn inspect(&self) -> InspectionResult;
}

pub trait HumanReadable {
    fn human_readable(&self) -> String;
}

