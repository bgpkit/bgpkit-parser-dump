use bgp_models::bgp::Attribute;
use crate::{DumpError, MrtDump};

impl MrtDump for Attribute {
    fn to_bytes(&self, subtype: u16) -> Result<Vec<u8>, DumpError> {
        todo!()
    }
}