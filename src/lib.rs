use crate::error::DumpError;

mod mrt;
mod table_dump;
mod bgp;
mod attributes;
mod utils;
mod error;

pub trait MrtDump {
    fn to_bytes(&self, subtype: u16) -> Result<Vec<u8>, DumpError>;
}