use std::net::IpAddr;
use std::str::FromStr;
use num_traits::ToPrimitive;
use bgp_models::prelude::*;
use crate::mrt_compose::error::ComposeError;
use crate::MrtDump;

pub trait MrtCompose {
    fn add_elem(&mut self, elem: &BgpElem) -> Result<(), ComposeError>;
    fn add_elems(&mut self, elems: &Vec<BgpElem>) -> Result<(), ComposeError>;
    fn export_bytes(&mut self) -> Result<Vec<u8>, ComposeError>;
}

#[allow(dead_code)]
pub struct TableDumpComposer {

}

pub struct BgpUpdatesComposer {
    mrt_messages: Vec<MrtRecord>,
}

fn elem_to_attributes(elem: &BgpElem) -> Vec<Attribute> {
    let mut attrs = vec![];

    if let Some(next_hop) = &elem.next_hop {
        attrs.push(
            Attribute {
                attr_type: AttrType::NEXT_HOP,
                value: AttributeValue::NextHop(*next_hop),
                flag: 64, // transitive
            }
        );
    }

    if let Some(comms) = &elem.communities{
        let mut reg_comms = vec![];
        let mut ext_comms = vec![];
        let mut lrg_comms = vec![];

        for comm in comms {
            match comm {
                MetaCommunity::Community(c) => {
                    reg_comms.push (*c);
                }
                MetaCommunity::ExtendedCommunity(c) => {
                    ext_comms.push (*c);
                }
                MetaCommunity::LargeCommunity(c) => {
                    lrg_comms.push (*c);
                }
            }
        }

        if !reg_comms.is_empty() {
            attrs.push(
                Attribute {
                    attr_type: AttrType::COMMUNITIES,
                    value: AttributeValue::Communities(reg_comms),
                    flag: 64, // transitive
                }
            );
        }
        if !ext_comms.is_empty() {
            attrs.push(
                Attribute {
                    attr_type: AttrType::EXTENDED_COMMUNITIES,
                    value: AttributeValue::ExtendedCommunities(ext_comms),
                    flag: 64, // transitive
                }
            );
        }
        if !lrg_comms.is_empty() {
            attrs.push(
                Attribute {
                    attr_type: AttrType::LARGE_COMMUNITIES,
                    value: AttributeValue::LargeCommunities(lrg_comms),
                    flag: 64, // transitive
                }
            );
        }
    }

    if let Some(aggr_asn) = &elem.aggr_asn{
        let aggr_ip = &elem.aggr_ip.unwrap();
        attrs.push(
            Attribute {
                attr_type: AttrType::AGGREGATOR,
                value: AttributeValue::Aggregator(*aggr_asn, *aggr_ip ),
                flag: 64, // transitive
            }
        );
    }

    if let Some(as_path) = &elem.as_path {
        attrs.push(
            Attribute {
                attr_type: AttrType::AS4_PATH,
                value: AttributeValue::As4Path(as_path.clone()),
                flag: 64, // transitive
            }
        );
    }

    if let Some(atomic) = &elem.atomic {
        match atomic {
            AtomicAggregate::NAG => {
                attrs.push(
                    Attribute {
                        attr_type: AttrType::ATOMIC_AGGREGATE,
                        value: AttributeValue::AtomicAggregate(AtomicAggregate::NAG),
                        flag: 64, // transitive
                    }
                );
            }
            AtomicAggregate::AG => {
                attrs.push(
                    Attribute {
                        attr_type: AttrType::ATOMIC_AGGREGATE,
                        value: AttributeValue::AtomicAggregate(AtomicAggregate::AG),
                        flag: 64, // transitive
                    }
                );
            }
        }
    }

    if let Some(med) = &elem.med {
        attrs.push(
            Attribute {
                attr_type: AttrType::MULTI_EXIT_DISCRIMINATOR,
                value: AttributeValue::MultiExitDiscriminator(*med),
                flag: 64, // transitive
            }
        );
    }

    if let Some(origin) = &elem.origin {
        attrs.push(
            Attribute {
                attr_type: AttrType::ORIGIN,
                value: AttributeValue::Origin(*origin),
                flag: 64, // transitive
            }
        );
    }

    attrs
}

impl BgpUpdatesComposer {
    pub fn new() -> Self {
        BgpUpdatesComposer{ mrt_messages: vec![] }
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

        self.mrt_messages.push (
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
                            local_ip: IpAddr::from([0,0,0,0]),
                            bgp_message: BgpMessage::Update(msg)
                        }
                    )
                )
            }
        );
        Ok(())
    }

    /// add a group of [BgpElem]s as a BGP message entry
    fn add_elems(&mut self, _elems: &Vec<BgpElem>) -> Result<(), ComposeError> {
        todo!()
    }

    fn export_bytes(&mut self) -> Result<Vec<u8>, ComposeError> {
        let mut buffer = vec![];
        for msg in &self.mrt_messages {
            let bytes = msg.to_bytes(0)?;
            buffer.extend(bytes);
        }
        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Take;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use bgpkit_parser::parse_mrt_record;
    use bgpkit_parser::parser::utils::DataBytes;
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
        composer.add_elem(&elem);

        dbg!(&composer.mrt_messages);

        let mut bytes = composer.export_bytes().unwrap();

        let record = parse_mrt_record(&mut bytes.as_slice()).unwrap();

        dbg!(&record);
    }
}