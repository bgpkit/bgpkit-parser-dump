use std::fs::File;
use std::io::Write;
use bgp_models::bgp::BgpElem;
use bgpkit_parser::BgpkitParser;
use bgpkit_parser::parser::mrt::mrt_record::parse_mrt_record;
use flate2::write::GzEncoder;
use flate2::Compression;
use bgpkit_parser_dump::{BgpUpdatesComposer, MrtCompose, MrtDump, TableDumpComposer};

#[test]
fn test_updates() {
    let url = "http://data.ris.ripe.net/rrc23/2021.12/updates.20211205.0450.gz";
    let parser = BgpkitParser::new(url).unwrap();
    let mut count = 0;
    for record in parser.into_record_iter() {
        let bytes = record.to_bytes(0).unwrap();
        let record2 = match parse_mrt_record(&mut bytes.as_slice()) {
            Ok(r) => {r}
            Err(e) => {
                println!("{:?}", &record);
                println!("{:?}", &count);
                panic!("{}",e);
            }
        };
        count+=1;
        assert_eq!(record.message, record2.message);
    }
}

#[test]
fn test_rib_v2() {
    let url = "http://archive.routeviews.org/route-views.sg/bgpdata/2018.07/RIBS/rib.20180701.0000.bz2";
    let parser = BgpkitParser::new(url).unwrap();
    for record in parser.into_record_iter() {
        let bytes = record.to_bytes(0).unwrap();
        let record2 = parse_mrt_record(&mut bytes.as_slice()).unwrap();
        // NOTE: number of bytes are different, thus only comparing the parsed messages.
        assert_eq!(record.message, record2.message);
    }
}

#[test]
fn test_filtered_updates() {
    let url = "http://data.ris.ripe.net/rrc23/2021.12/updates.20211205.0450.gz";
    let parser = BgpkitParser::new(url).unwrap().add_filter("origin_asn", "43766").unwrap();
    let elems = parser.into_elem_iter().collect::<Vec<BgpElem>>();

    let mut composer = BgpUpdatesComposer::new();
    for elem in &elems {
        composer.add_elem(elem).unwrap();
    }

    let bytes = composer.export_bytes().unwrap();
    let mut e = GzEncoder::new(File::create("/tmp/test-filtered-updates.gz").unwrap(), Compression::default());
    e.write_all(bytes.as_slice()).unwrap();
    e.finish().unwrap();


    let parser = BgpkitParser::new("/tmp/test-filtered-updates.gz").unwrap();
    let elem_count = parser.into_elem_iter().count();
    assert_eq!(elem_count, 118);
    // 43766
}

#[test]
fn test_filtered_rib() {
    let url = "https://spaces.bgpkit.org/parser/rib-example.bz2";
    let parser = BgpkitParser::new(url).unwrap().add_filter("origin_asn", "15169").unwrap();
    let elems = parser.into_elem_iter().collect::<Vec<BgpElem>>();

    let mut composer = TableDumpComposer::new();
    for elem in &elems {
        composer.add_elem(elem).unwrap();
    }

    let bytes = composer.export_bytes().unwrap();
    let mut e = GzEncoder::new(File::create("/tmp/test-filtered-rib.gz").unwrap(), Compression::default());
    e.write_all(bytes.as_slice()).unwrap();
    e.finish().unwrap();


    let parser = BgpkitParser::new("/tmp/test-filtered-rib.gz").unwrap();
    let elem_count = parser.into_elem_iter().count();
    assert_eq!(elem_count, 2507);
}
