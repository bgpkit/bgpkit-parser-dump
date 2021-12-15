use bgp_models::mrt::{PeerIndexTable, RibAfiEntries, RibGenericEntries, TableDumpMessage, TableDumpV2Message, TableDumpV2Type};
use bgp_models::network::{Afi, AsnLength, Safi};
use byteorder::WriteBytesExt;
use crate::{DumpError, MrtDump};
use crate::utils::WriteUtils;
use num_traits::FromPrimitive;

impl MrtDump for TableDumpMessage{
    fn to_bytes(&self, subtype: u16) -> Result<Vec<u8>, DumpError> {
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
        // BigEndian::write_u32(&mut buffer, ipv4_to_u32(&self.collector_bgp_id));

        // view name length
        buffer.write_16b(self.view_name_length)?;

        // peer count
        buffer.write_16b(self.peer_count)?;

        for i in 0..self.peers_map.len() {
            let peer = self.peers_map.get(&(i as u32)).unwrap();

            let asn_len = match peer.peer_type & 2 {
                2 => AsnLength::Bits32,
                _ => AsnLength::Bits16,
            };

            buffer.write_u8(peer.peer_type)?;
            buffer.write_ip(&peer.peer_bgp_id.into())?;
            buffer.write_ip(&peer.peer_address)?;
            buffer.write_asn(peer.peer_asn)?;
        }
        Ok(buffer)
    }
}

impl MrtDump for RibAfiEntries {
    fn to_bytes(&self, subtype: u16) -> Result<Vec<u8>, DumpError> {
        let rib_type: TableDumpV2Type = TableDumpV2Type::from_u16(subtype).unwrap();
        let afi: Afi;
        let safi: Safi;
        match rib_type {
            TableDumpV2Type::RibIpv4Unicast | TableDumpV2Type::RibIpv4UnicastAddPath => {
                afi = Afi::Ipv4;
                safi = Safi::Unicast
            }
            TableDumpV2Type::RibIpv4Multicast | TableDumpV2Type::RibIpv4MulticastAddPath => {
                afi = Afi::Ipv4;
                safi = Safi::Multicast
            }
            TableDumpV2Type::RibIpv6Unicast | TableDumpV2Type::RibIpv6UnicastAddPath => {
                afi = Afi::Ipv6;
                safi = Safi::Unicast
            }
            TableDumpV2Type::RibIpv6Multicast | TableDumpV2Type::RibIpv6MulticastAddPath => {
                afi = Afi::Ipv6;
                safi = Safi::Multicast
            }
            _ => {
                ()
            }
        };

        let add_path = match rib_type {
            TableDumpV2Type::RibIpv4UnicastAddPath | TableDumpV2Type::RibIpv4MulticastAddPath |
            TableDumpV2Type::RibIpv6UnicastAddPath | TableDumpV2Type::RibIpv6MulticastAddPath => {
                true
            }
            _ => {false}
        };

        let mut buffer: Vec<u8> = vec![];
        buffer.write_32b(self.sequence_number)?;

        todo!("write nlri prefix");

        buffer.write_16b(self.rib_entries.len() as u16)?;

        for entry in self.rib_entries {
            buffer.write_16b(entry.peer_index)?;
            buffer.write_32b(entry.originated_time)?;
            todo!("add attribute_length to all relevant structs");
            todo!("add subtype (u16 or enum) to all relevant structs");
        }

        todo!("write entries");

        todo!()
    }
}

impl MrtDump for RibGenericEntries {
    fn to_bytes(&self, subtype: u16) -> Result<Vec<u8>, DumpError> {
        todo!()
    }
}
