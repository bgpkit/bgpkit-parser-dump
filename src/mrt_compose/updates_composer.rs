use std::net::IpAddr;
use std::str::FromStr;

use bgp_models::prelude::*;
use num_traits::ToPrimitive;

use crate::{elem_to_attributes, MrtCompose, MrtDump};
use crate::mrt_compose::error::ComposeError;

pub struct BgpUpdatesComposer {
    mrt_records: Vec<MrtRecord>,
}

impl BgpUpdatesComposer {
    pub fn new() -> Self {
        BgpUpdatesComposer{ mrt_records: vec![] }
    }
}

impl MrtCompose for BgpUpdatesComposer {
    /// add single [BgpElem] as a BGP message entry
    fn add_elem(&mut self, elem: &BgpElem) -> Result<(), ComposeError> {

        let t = elem.timestamp;
        let t_str= format!("{:.6}", t);
        let fields = t_str.split(".").collect::<Vec<&str>>();
        let msec = u32::from_str(fields.get(1).unwrap()).unwrap();

        let header = CommonHeader{
            timestamp: t as u32,
            microsecond_timestamp: Some(msec),
            entry_type: EntryType::BGP4MP_ET,
            entry_subtype: Bgp4MpType::Bgp4MpMessageAs4.to_u16().unwrap(),
            length: 0
        };

        let (a,w) = match elem.elem_type{
            ElemType::ANNOUNCE => {(vec![elem.prefix], vec![])}
            ElemType::WITHDRAW => {(vec![], vec![elem.prefix])}
        };

        let msg = BgpUpdateMessage{
            withdrawn_prefixes: w,
            attributes: elem_to_attributes(elem),
            announced_prefixes: a
        };

        let afi = match elem.prefix.prefix.is_ipv4() {
            true => Afi::Ipv4,
            false => Afi::Ipv6,
        };

        let local_ip = match elem.peer_ip.is_ipv4(){
            true => IpAddr::from([0,0,0,0]),
            false => IpAddr::from([ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 ])
        };

        self.mrt_records.push (
            MrtRecord{
                common_header: header,
                message: MrtMessage::Bgp4Mp(
                    Bgp4Mp::Bgp4MpMessageAs4(
                        Bgp4MpMessage{
                            msg_type: Bgp4MpType::Bgp4MpMessageAs4,
                            peer_asn: elem.peer_asn,
                            local_asn: Asn{ asn: 0, len: elem.peer_asn.len },
                            interface_index: 0,
                            afi,
                            peer_ip: elem.peer_ip,
                            local_ip,
                            bgp_message: BgpMessage::Update(msg)
                        }
                    )
                )
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
        let mut buffer = vec![];
        for msg in &self.mrt_records {
            let bytes = msg.to_bytes(0)?;
            buffer.extend(bytes);
        }
        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use bgpkit_parser::parse_mrt_record;

    use super::*;

    #[test]
    fn test_compose() {
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

        let mut composer = BgpUpdatesComposer::new();
        composer.add_elem(&elem).unwrap();

        dbg!(&composer.mrt_records);

        let bytes = composer.export_bytes().unwrap();

        let record = parse_mrt_record(&mut bytes.as_slice()).unwrap();

        dbg!(&record);
    }
}