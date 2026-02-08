use crate::inspector::InspectionResult;

pub trait Inspectable {
    fn inspect(&self) -> InspectionResult;
}

