/// Shrink a 110MB rib dump file from RouteViews2 into a 10MB smaller RIB dump
/// with only updates from route collector peers from AS2497 (IIJ).
///
/// The output file is packaged into a new MRT file.
use std::fs::File;
use std::io::Write;

use bgp_models::bgp::BgpElem;
use flate2::Compression;
use flate2::write::GzEncoder;

use bgpkit_parser_dump::{MrtCompose, TableDumpComposer};

fn main() {
    let parser = bgpkit_parser::BgpkitParser::new("http://archive.routeviews.org/bgpdata/2021.12/RIBS/rib.20211201.0000.bz2").unwrap()
        .add_filter("peer_asn", "2497").unwrap();
    let mut e = GzEncoder::new(File::create("/tmp/test-shrink-rib-composer.gz").unwrap(), Compression::default());

    let elems = parser.into_iter().collect::<Vec<BgpElem>>();
    let mut composer = TableDumpComposer::new();

    for elem in &elems {
        composer.add_elem(elem).unwrap();
    }

    e.write_all(composer.export_bytes().unwrap().as_slice()).unwrap();
}