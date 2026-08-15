use ipv4::Ipv4InspectionResult;
use ipv6::Ipv6InspectionResult;
use serde::Serialize;

pub mod ipv4;
pub mod ipv6;

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "ip_version", rename_all = "lowercase")]
pub enum InspectionResult {
    V4(Ipv4InspectionResult),
    V6(Ipv6InspectionResult),
}

/// Trait that provides `inspect` function
///
/// Bring this trait into the scope to get an InspectionResult
///
/// # Example
/// ```
/// use cidit::InspectionResult;
/// use cidit::Ipv4InspectionResult;
/// use cidit::Ipv4Cidr;
///
/// use cidit::Inspectable;
///
/// let expected_ipv4_cidr_string = String::from("10.22.135.144/24");
/// let expected_inspection_result = InspectionResult::V4(Ipv4InspectionResult {
///                cidr: expected_ipv4_cidr_string.clone(),
///                first_usable: String::from("10.22.135.1"),
///                last_usable: String::from("10.22.135.254"),
///                broadcast: String::from("10.22.135.255"),
///                network: String::from("10.22.135.0"),
///                address: String::from("10.22.135.144"),
///                prefix_length: 24,
///                });
/// let expected_ipv4_cidr: Ipv4Cidr = expected_ipv4_cidr_string.parse().unwrap();
///
/// let actual_inspection_result: InspectionResult = expected_ipv4_cidr.inspect();
///
/// assert_eq!(actual_inspection_result, expected_inspection_result);
/// ```
pub trait Inspectable {
    fn inspect(&self) -> InspectionResult;
}
