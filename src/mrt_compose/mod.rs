mod updates_composer;
mod rib_composer;
mod error;

use bgp_models::prelude::*;

pub use updates_composer::BgpUpdatesComposer;
pub use rib_composer::TableDumpComposer;
use crate::mrt_compose::error::ComposeError;

pub trait MrtCompose {
    fn add_elem(&mut self, elem: &BgpElem) -> Result<(), ComposeError>;
    fn export_bytes(&mut self) -> Result<Vec<u8>, ComposeError>;
}

pub(crate) fn elem_to_attributes(elem: &BgpElem) -> Vec<Attribute> {
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
                // Non-Atomic-Aggregate does not show up as an attribute;
                // i.e. the lack of AttrType::ATOMIC_AGGREGATE means NAG.
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

