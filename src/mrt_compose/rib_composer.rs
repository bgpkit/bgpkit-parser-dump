use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;

use bgp_models::prelude::*;
use ipnetwork::IpNetwork;
use num_traits::ToPrimitive;

use crate::{elem_to_attributes, MrtCompose, MrtDump};
use crate::mrt_compose::error::ComposeError;

pub struct TableDumpComposer {
    mrt_records: Option<Vec<MrtRecord>>,
    rib_entries: BTreeMap<IpNetwork, Vec<RibEntry>>,
    peers: BTreeMap<String, (usize, Peer)>,
    ts_sec: u32,
}

impl TableDumpComposer {
    pub fn new() -> Self {
        TableDumpComposer{ mrt_records: None , rib_entries: BTreeMap::new(), peers: BTreeMap::new(), ts_sec: 0 }
    }
}

impl MrtCompose for TableDumpComposer {
    fn add_elem(&mut self, elem: &BgpElem) -> Result<(), ComposeError> {
        // reset mrt records cache, force recompute new mrt records when exporting to bytes.
        self.mrt_records = None;

        if self.ts_sec == 0 {
            self.ts_sec = elem.timestamp as u32;
        }

        let attributes =  elem_to_attributes(elem);
        let peer_ip_str = elem.peer_ip.to_string();

        /*
        let peer_type = input.read_8b()?;
        let afi = match peer_type & 1 {
            1 => Afi::Ipv6,
            _ => Afi::Ipv4,
        };
        let asn_len = match peer_type & 2 {
            2 => AsnLength::Bits32,
            _ => AsnLength::Bits16,
        };
        */

        let peer_type: u8 = match elem.peer_ip.is_ipv4(){
            true => 2,   // ipv4, 32-bit asn
            false => 3,  // ipv6, 32-bit asn
        };

        let peers_len = self.peers.len();
        let (pid, _peer) = self.peers.entry(peer_ip_str)
            .or_insert((peers_len,
                        Peer {
                            peer_type,
                            peer_bgp_id: Ipv4Addr::from([0,0,0,0]),
                            peer_address: elem.peer_ip,
                            peer_asn: elem.peer_asn
                        }
            ));

        let entries = self.rib_entries.entry(elem.prefix.prefix).or_insert(vec![]);
        entries.push(
            RibEntry{
                peer_index: *pid as u16,
                originated_time: 0,
                attributes
            }
        );

        Ok(())
    }

    fn add_elems(&mut self, elems: &Vec<BgpElem>) -> Result<(), ComposeError> {
        for elem in elems {
            self.add_elem(elem)?;
        }
        Ok(())
    }

    fn export_bytes(&mut self) -> Result<Vec<u8>, ComposeError> {
        if let Some(records) = &self.mrt_records {
            let mut buffer = vec![];
            for msg in records {
                let bytes = msg.to_bytes(0)?;
                buffer.extend(bytes);
            }
            return Ok(buffer)
        }

        let mut mrt_records = vec![];

        // peer index table
        let mut peers_map: HashMap<u32, Peer> = HashMap::new();
        for (pid, peer) in self.peers.values() {
            peers_map.insert(*pid as u32, peer.clone());
        }
        let peer_count = peers_map.len() as u16;

        let header = CommonHeader{
            timestamp: self.ts_sec,
            microsecond_timestamp: None,
            entry_type: EntryType::TABLE_DUMP_V2,
            entry_subtype: TableDumpV2Type::PeerIndexTable.to_u16().unwrap(),
            length: 0
        };

        mrt_records.push(
            MrtRecord{
                common_header: header,
                message: MrtMessage::TableDumpV2Message(
                    TableDumpV2Message::PeerIndexTable(
                        PeerIndexTable{
                            collector_bgp_id: Ipv4Addr::from([0,0,0,0]),
                            view_name_length: 0,
                            view_name: "".to_string(),
                            peer_count,
                            peers_map
                        }
                    )
                )
            }
        );

        for (prefix, rib_entries) in &self.rib_entries {
            let rib_type = match prefix.is_ipv4() {
                true => TableDumpV2Type::RibIpv4Unicast,
                false => TableDumpV2Type:: RibIpv6Unicast
            };
            
            let header = CommonHeader{
                timestamp: self.ts_sec,
                microsecond_timestamp: None,
                entry_type: EntryType::TABLE_DUMP_V2,
                entry_subtype: rib_type.to_u16().unwrap(),
                length: 0
            };
            let new_rib_entries: Vec<RibEntry> = rib_entries.iter().map(|e| e.clone()).collect();

            mrt_records.push(
                MrtRecord{
                    common_header: header,
                    message: MrtMessage::TableDumpV2Message(
                        TableDumpV2Message::RibAfiEntries(
                            RibAfiEntries{
                                rib_type,
                                sequence_number: 0,
                                prefix: NetworkPrefix{
                                    prefix: prefix.clone(),
                                    path_id: 0
                                },
                                rib_entries: new_rib_entries
                            }
                        )
                    )
                }
            );
        }

        let mut buffer = vec![];
        for msg in &mrt_records {
            let bytes = msg.to_bytes(0)?;
            buffer.extend(bytes);
        }

        self.mrt_records = Some(mrt_records);
        return Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    use bgpkit_parser::parse_mrt_record;

    use super::*;

    #[test]
    fn test_compose_rib() {
        let aspath = AsPath{
            segments: vec![AsPathSegment::AsSequence([1,2,3,5].map(|i|{i.into()}).to_vec())]
        };

        let elem = BgpElem {
            timestamp: 12.1,
            elem_type: ElemType::ANNOUNCE,
            peer_ip: IpAddr::from(Ipv4Addr::from([1,2,3,4])),
            peer_asn: Asn { asn: 100, len: AsnLength::Bits32 },
            prefix: NetworkPrefix::from_str("10.2.2.0/24").unwrap(),
            next_hop: Some(IpAddr::from(Ipv4Addr::from([4,3,2,1]))),
            as_path: Some(aspath.clone()),
            origin_asns: None,
            origin: Some(Origin::EGP),
            local_pref: Some(250),
            med: Some(251),
            communities: None,
            atomic: Some(AtomicAggregate::AG),
            aggr_asn: Some(Asn::from(123)),
            aggr_ip: Some(IpAddr::from(Ipv4Addr::from([4,3,2,2])))
        };

        let elem2 = BgpElem {
            timestamp: 12.1,
            elem_type: ElemType::ANNOUNCE,
            peer_ip: IpAddr::from(Ipv4Addr::from([1,2,3,1])),
            peer_asn: Asn { asn: 100, len: AsnLength::Bits32 },
            prefix: NetworkPrefix::from_str("10.2.2.0/24").unwrap(),
            next_hop: Some(IpAddr::from(Ipv4Addr::from([4,3,2,1]))),
            as_path: Some(aspath),
            origin_asns: None,
            origin: Some(Origin::EGP),
            local_pref: Some(250),
            med: Some(251),
            communities: None,
            atomic: Some(AtomicAggregate::AG),
            aggr_asn: Some(Asn::from(123)),
            aggr_ip: Some(IpAddr::from(Ipv4Addr::from([4,3,2,2])))
        };

        let mut composer = TableDumpComposer::new();
        composer.add_elem(&elem).unwrap();
        composer.add_elem(&elem2).unwrap();

        let bytes = composer.export_bytes().unwrap();

        let record = parse_mrt_record(&mut bytes.as_slice()).unwrap();

        dbg!(&record);
    }
}
