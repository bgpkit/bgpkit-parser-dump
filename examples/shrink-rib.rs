use std::fs::File;
use std::io::Write;
use bgp_models::mrt::{MrtMessage, TableDumpV2Message};
use flate2::Compression;
use flate2::write::GzEncoder;
use bgpkit_parser_dump::MrtDump;

fn main() {
    let parser = bgpkit_parser::BgpkitParser::new("http://archive.routeviews.org/bgpdata/2021.12/RIBS/rib.20211201.0000.bz2").unwrap();
    let mut e = GzEncoder::new(File::create("/tmp/test.gz").unwrap(), Compression::default());

    let mut pid = None;
    for mut record in parser.into_record_iter() {
        if let MrtMessage::TableDumpV2Message(m) = &mut record.message {
            match m {
                TableDumpV2Message::PeerIndexTable(e) => {
                    for (i, peer) in &e.peers_map {
                        if peer.peer_asn.asn == 2497 {
                            pid = Some(*i)
                        }
                    }
                }
                TableDumpV2Message::RibAfiEntries(r) => {
                    assert!(pid.is_some());
                    let mut new_ribs = vec![];
                    for r in &r.rib_entries {
                        if r.peer_index == pid.unwrap() as u16 {
                            new_ribs.push(r.clone());
                        }
                    }
                    if new_ribs.is_empty() {
                        continue
                    }
                    r.rib_entries = new_ribs;
                }
                TableDumpV2Message::RibGenericEntries(_) => {}
            }
        }
        let bytes = record.to_bytes(0).unwrap();
        e.write_all(bytes.as_slice()).unwrap();
    }
}