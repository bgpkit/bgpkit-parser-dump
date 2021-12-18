use std::io::Write;
use std::net::IpAddr;
use bgp_models::bgp::{AsPathSegment, Attribute, AttributeFlagsBit, Community, ExtendedCommunity};
use bgp_models::network::{AsnLength, NextHopAddress};
use bgp_models::prelude::AttributeValue;
use byteorder::WriteBytesExt;
use num_traits::ToPrimitive;
use crate::{DumpError, MrtDump};
use crate::utils::WriteUtils;

pub trait MrtAttrDump {
    fn to_bytes(&self, add_path: bool, write_afi: bool, write_safi: bool, write_prefixes: bool)-> Result<Vec<u8>, DumpError>;
}

impl MrtAttrDump for Attribute {
    fn to_bytes(&self, add_path: bool, write_afi: bool, write_safi: bool, write_prefixes: bool) -> Result<Vec<u8>, DumpError> {
        let mut buffer: Vec<u8> = vec![];
        buffer.write_u8(self.flag)?;
        buffer.write_u8(self.attr_type.to_u8().unwrap())?;

        let mut attr_buf: Vec<u8> = vec![];
        match &self.value {
            AttributeValue::Origin(v) => {
                attr_buf.write_u8(v.to_u8().unwrap())?;
            }
            AttributeValue::AsPath(v) | AttributeValue::As4Path(v) => {
                for seg in &v.segments {
                    // https://datatracker.ietf.org/doc/html/rfc5065#section-3
                    let (seg_type, asns) = match seg {
                        AsPathSegment::AsSet(v) => {
                            (1, v)
                        }
                        AsPathSegment::AsSequence(v) => {
                            (2, v)
                        }
                        AsPathSegment::ConfedSequence(v) => {
                            (3, v)
                        }
                        AsPathSegment::ConfedSet(v) => {
                            (4, v)
                        }
                    };
                    attr_buf.write_u8(seg_type as u8)?;
                    attr_buf.write_u8(asns.len() as u8)?;
                    for asn in asns {
                        match asn.len {
                            AsnLength::Bits16 => {
                                attr_buf.write_16b(asn.asn as u16)?
                            }
                            AsnLength::Bits32 => {
                                attr_buf.write_32b(asn.asn as u32)?
                            }
                        }
                    }
                }
            }
            AttributeValue::NextHop(v) => {
                attr_buf.write_ip(v)?
            }
            AttributeValue::MultiExitDiscriminator(v) => {
                attr_buf.write_32b(*v)?;
            }
            AttributeValue::LocalPreference(v) => {
                attr_buf.write_32b(*v)?;
            }
            AttributeValue::AtomicAggregate(_v) => {
                // do nothing here. the value type is enough.
            }
            AttributeValue::Aggregator(asn, ip) => {
                attr_buf.write_asn(asn)?;
                attr_buf.write_ip(ip)?;
            }
            AttributeValue::Communities(v) => {
                const COMMUNITY_NO_EXPORT: u32 = 0xFFFFFF01;
                const COMMUNITY_NO_ADVERTISE: u32 = 0xFFFFFF02;
                const COMMUNITY_NO_EXPORT_SUBCONFED: u32 = 0xFFFFFF03;
                for comm in v {
                    match comm {
                        Community::NoExport => {
                            attr_buf.write_32b(COMMUNITY_NO_EXPORT)?;
                        }
                        Community::NoAdvertise => {
                            attr_buf.write_32b(COMMUNITY_NO_ADVERTISE)?;
                        }
                        Community::NoExportSubConfed => {

                            attr_buf.write_32b(COMMUNITY_NO_EXPORT_SUBCONFED)?;
                        }
                        Community::Custom(asn, value) => {
                            attr_buf.write_16b(asn.asn as u16)?;
                            attr_buf.write_16b(*value)?;
                        }
                    }

                }
            }
            AttributeValue::ExtendedCommunities(v) => {
                for comm in v {
                    match comm {
                        ExtendedCommunity::TransitiveTwoOctetAsSpecific(c) |
                            ExtendedCommunity::NonTransitiveTwoOctetAsSpecific(c) => {
                            attr_buf.write_u8(c.ec_type)?;
                            attr_buf.write_u8(c.ec_subtype)?;
                            attr_buf.write_16b(c.global_administrator.asn as u16)?;
                            attr_buf.write_all(&c.local_administrator)?;
                        }
                        ExtendedCommunity::TransitiveFourOctetAsSpecific(c) |
                        ExtendedCommunity::NonTransitiveFourOctetAsSpecific(c) => {
                            attr_buf.write_u8(c.ec_type)?;
                            attr_buf.write_u8(c.ec_subtype)?;
                            attr_buf.write_32b(c.global_administrator.asn as u32)?;
                            attr_buf.write_all(&c.local_administrator)?;

                        }
                        ExtendedCommunity::TransitiveIpv4AddressSpecific(c) |
                        ExtendedCommunity::NonTransitiveIpv4AddressSpecific(c) => {
                            attr_buf.write_u8(c.ec_type)?;
                            attr_buf.write_u8(c.ec_subtype)?;
                            attr_buf.write_all(&c.global_administrator.octets())?;
                            attr_buf.write_all(&c.local_administrator)?;
                        }
                        ExtendedCommunity::TransitiveOpaque(c) |
                        ExtendedCommunity::NonTransitiveOpaque(c) => {
                            attr_buf.write_u8(c.ec_type)?;
                            attr_buf.write_u8(c.ec_subtype)?;
                            attr_buf.write_all(&c.value)?;
                        }
                        ExtendedCommunity::Ipv6AddressSpecific(c) => {
                            attr_buf.write_u8(c.ec_type)?;
                            attr_buf.write_u8(c.ec_subtype)?;
                            attr_buf.write_all(&c.global_administrator.octets())?;
                            attr_buf.write_all(&c.local_administrator)?;
                        }
                        ExtendedCommunity::Raw(c) => {
                            attr_buf.write_all(c)?;
                        }
                    }
                }
            }
            AttributeValue::LargeCommunities(v) => {
                for comm in v {
                    attr_buf.write_32b(comm.global_administrator)?;
                    assert_eq!(comm.local_data.len(), 2);
                    attr_buf.write_32b(comm.local_data[0])?;
                    attr_buf.write_32b(comm.local_data[1])?;
                }
            }
            AttributeValue::OriginatorId(v) => {
                attr_buf.write_ip(v)?;
            }
            AttributeValue::Clusters(v) => {
                for ip in v {
                    attr_buf.write_ip(ip);
                }
            }
            AttributeValue::MpReachNlri(v) => {
                /*
                    +---------------------------------------------------------+
                    | Address Family Identifier (2 octets)                    |
                    +---------------------------------------------------------+
                    | Subsequent Address Family Identifier (1 octet)          |
                    +---------------------------------------------------------+
                    | Length of Next Hop Network Address (1 octet)            |
                    +---------------------------------------------------------+
                    | Network Address of Next Hop (variable)                  |
                    +---------------------------------------------------------+
                    | Reserved (1 octet)                                      |
                    +---------------------------------------------------------+
                    | Network Layer Reachability Information (variable)       |
                    +---------------------------------------------------------+
                 */
                if write_afi {
                    attr_buf.write_16b(v.afi.to_u16().unwrap())?;
                }
                if write_safi {
                    attr_buf.write_u8(v.safi.to_u8().unwrap())?;
                }
                match v.next_hop {
                    None => {
                        attr_buf.write_u8(0)?;
                    }
                    Some(h) => {
                        match h {
                            NextHopAddress::Ipv4(v) => {
                                attr_buf.write_u8(4)?;
                                attr_buf.write_ip(&IpAddr::from(v))?;
                            }
                            NextHopAddress::Ipv6(v) => {
                                attr_buf.write_u8(16)?;
                                attr_buf.write_ip(&IpAddr::from(v))?;
                            }
                            NextHopAddress::Ipv6LinkLocal(v1, v2) => {
                                attr_buf.write_u8(32)?;
                                attr_buf.write_ip(&IpAddr::from(v1))?;
                                attr_buf.write_ip(&IpAddr::from(v2))?;
                            }
                        }

                    }
                }

                if write_prefixes {
                    // reserved byte https://datatracker.ietf.org/doc/html/rfc4760#section-3
                    attr_buf.write_u8(0)?;
                    for prefix in &v.prefixes {
                        attr_buf.write_nlri(prefix, add_path)?;
                    }
                }
            }
            AttributeValue::MpUnreachNlri(v) => {
                /*
                    +---------------------------------------------------------+
                    | Address Family Identifier (2 octets)                    |
                    +---------------------------------------------------------+
                    | Subsequent Address Family Identifier (1 octet)          |
                    +---------------------------------------------------------+
                    | Withdrawn Routes (variable)                             |
                    +---------------------------------------------------------+
                 */
                if write_afi {
                    attr_buf.write_16b(v.afi.to_u16().unwrap())?;
                }
                if write_safi {
                    attr_buf.write_u8(v.safi.to_u8().unwrap())?;
                }
                if write_prefixes {
                    for prefix in &v.prefixes {
                        attr_buf.write_nlri(prefix, add_path)?;
                    }
                }
            }
            AttributeValue::Development(v) => {
                attr_buf.write_all(&v)?;
            }
        }

        // write attribute length
        match self.flag & AttributeFlagsBit::ExtendedLengthBit as u8 {
            0 => buffer.write_u8(attr_buf.len() as u8)?,
            _ => buffer.write_16b(attr_buf.len() as u16)?,
        };
        // write attribute value
        buffer.extend(attr_buf);

        Ok(buffer)
    }
}
