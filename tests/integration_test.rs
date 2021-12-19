use bgpkit_parser::BgpkitParser;
use bgpkit_parser::parser::mrt::mrt_record::parse_mrt_record;
use bgpkit_parser_dump::MrtDump;

#[test]
fn test_updates() {
    let url = "http://data.ris.ripe.net/rrc23/2021.12/updates.20211205.0450.gz";
    let parser = BgpkitParser::new(url).unwrap();
    for record in parser.into_record_iter() {
        let bytes = record.to_bytes(0).unwrap();
        let record2 = parse_mrt_record(&mut bytes.as_slice()).unwrap();
        assert_eq!(record, record2);
    }
}

#[test]
fn test_rib_v2() {
    let url = "http://archive.routeviews.org/route-views.sg/bgpdata/2018.07/RIBS/rib.20180701.0000.bz2";
    let parser = BgpkitParser::new(url).unwrap();
    for record in parser.into_record_iter() {
        let bytes = record.to_bytes(0).unwrap();
        let record2 = parse_mrt_record(&mut bytes.as_slice()).unwrap();
        assert_eq!(record, record2);
    }
}
