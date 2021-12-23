use std::io::Write;
use bgp_models::mrt::{PeerIndexTable, RibAfiEntries, RibGenericEntries, TableDumpMessage, TableDumpV2Message, TableDumpV2Type};
use byteorder::WriteBytesExt;
use crate::{DumpError, MrtDump};
use crate::mrt_dump::utils::WriteUtils;
use num_traits::FromPrimitive;
use crate::mrt_dump::attributes::MrtAttrDump;

impl MrtDump for TableDumpMessage{
    fn to_bytes(&self, _subtype: u16) -> Result<Vec<u8>, DumpError> {
        todo!()
    }
}

impl MrtDump for TableDumpV2Message{
    fn to_bytes(&self, subtype: u16) -> Result<Vec<u8>, DumpError> {
        Ok(
            match self {
                TableDumpV2Message::PeerIndexTable(m) => {m.to_bytes(subtype)?}
                TableDumpV2Message::RibAfiEntries(m) => {m.to_bytes(subtype)?}
                TableDumpV2Message::RibGenericEntries(m) => {m.to_bytes(subtype)?}
            }
        )
    }
}

impl MrtDump for PeerIndexTable {
    fn to_bytes(&self, _: u16) -> Result<Vec<u8>, DumpError> {
        let mut buffer: Vec<u8> = vec![];

        // collector id as ip
        buffer.write_ip(&self.collector_bgp_id.into())?;

        // view name length
        buffer.write_16b(self.view_name_length)?;

        buffer.write_all(&vec![0; self.view_name_length as usize])?;

        // peer count
        buffer.write_16b(self.peer_count)?;

        for i in 0..self.peers_map.len() {
            let peer = self.peers_map.get(&(i as u32)).unwrap();
            buffer.write_u8(peer.peer_type)?;
            buffer.write_ip(&peer.peer_bgp_id.into())?;
            buffer.write_ip(&peer.peer_address)?;
            buffer.write_asn(&peer.peer_asn)?;
        }
        Ok(buffer)
    }
}

impl MrtDump for RibAfiEntries {
    fn to_bytes(&self, subtype: u16) -> Result<Vec<u8>, DumpError> {
        let rib_type: TableDumpV2Type = TableDumpV2Type::from_u16(subtype).unwrap();
        let add_path = match rib_type {
            TableDumpV2Type::RibIpv4UnicastAddPath | TableDumpV2Type::RibIpv4MulticastAddPath |
            TableDumpV2Type::RibIpv6UnicastAddPath | TableDumpV2Type::RibIpv6MulticastAddPath => {
                true
            }
            _ => {false}
        };

        let mut buffer: Vec<u8> = vec![];
        buffer.write_32b(self.sequence_number)?;

        buffer.write_nlri(&self.prefix, add_path)?;

        buffer.write_16b(self.rib_entries.len() as u16)?;

        for entry in &self.rib_entries {
            buffer.write_16b(entry.peer_index)?;
            buffer.write_32b(entry.originated_time)?;
            if add_path {
                // todo: currently the parser does not use this path id, so we also do not write it out
                buffer.write_32b(0)?;
            }

            let mut attr_buffer = vec![];
            for attribute in &entry.attributes {
                attr_buffer.extend(attribute.to_bytes(add_path, false, false, false)?);
            }

            buffer.write_16b(attr_buffer.len() as u16)?;
            buffer.write_all(&attr_buffer)?;

        }
        Ok(buffer)
    }
}

impl MrtDump for RibGenericEntries {
    fn to_bytes(&self, _subtype: u16) -> Result<Vec<u8>, DumpError> {
        todo!("parser has not supported yet, so haven't us.")
    }
}
