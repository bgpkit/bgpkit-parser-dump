use bgp_models::mrt::{CommonHeader, MrtMessage, MrtRecord};
use num_traits::ToPrimitive;
use crate::{DumpError, MrtDump};
use crate::mrt_dump::utils::WriteUtils;

impl MrtDump for MrtRecord {
    fn to_bytes(&self, _subtype: u16) -> Result<Vec<u8>, DumpError> {
        let mut buffer: Vec<u8> = vec![];

        let bytes = self.message.to_bytes(self.common_header.entry_subtype)?;
        buffer.extend(self.common_header.to_bytes(bytes.len() as u16)?);
        buffer.extend(bytes.as_slice());

        Ok(buffer)
    }
}

impl MrtDump for CommonHeader {
    fn to_bytes(&self, size: u16) -> Result<Vec<u8>, DumpError> {
        let mut buffer: Vec<u8> = vec![];

        buffer.write_32b(self.timestamp)?;

        buffer.write_16b(self.entry_type.to_u16().unwrap())?;
        buffer.write_16b(self.entry_subtype)?;


        if let Some(mt) = self.microsecond_timestamp {
            buffer.write_32b((size + 4) as u32)?;
            buffer.write_32b(mt)?;
        } else {
            buffer.write_32b(size as u32)?;
        }
        Ok(buffer)
    }
}

impl MrtDump for MrtMessage {
    fn to_bytes(&self, subtype: u16) -> Result<Vec<u8>, DumpError> {
        Ok(
            match self {
                MrtMessage::TableDumpMessage(m) => m.to_bytes(subtype)?,
                MrtMessage::TableDumpV2Message(m) => m.to_bytes(subtype)?,
                MrtMessage::Bgp4Mp(m) => m.to_bytes(subtype)?,
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgp_models::prelude::*;
    use bgpkit_parser::parser::mrt::mrt_record::parse_common_header;

    #[test]
    fn test_common_header() {
        // test MRT header
        let header1 = CommonHeader{
            timestamp: 1,
            microsecond_timestamp: Some(100),
            entry_type: EntryType::BGP4MP_ET,
            entry_subtype: 15,
            length: 20
        };

        // turn it to raw bytes in MRT format
        let bytes = header1.to_bytes(20).unwrap();

        // parse it back to Rust structs
        let (_bytes, header2) = parse_common_header(&mut bytes.as_slice()).unwrap();

        // test equality!
        assert_eq!(header1, header2);
    }
}