use mrt_dump::error::DumpError;

pub use crate::mrt_compose::*;

mod mrt_dump;
mod mrt_compose;

pub trait MrtDump {
    fn to_bytes(&self, subtype: u16) -> Result<Vec<u8>, DumpError>;
}