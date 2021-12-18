use std::io::Write;
use bgp_models::bgp::{BgpKeepAliveMessage, BgpMessage, BgpMessageType, BgpNotificationMessage, BgpOpenMessage, BgpUpdateMessage};
use bgp_models::mrt::{Bgp4Mp, Bgp4MpMessage, Bgp4MpStateChange, Bgp4MpType};
use bgp_models::network::AsnLength;
use byteorder::WriteBytesExt;
use crate::{DumpError, MrtDump};
use crate::utils::WriteUtils;
use num_traits::ToPrimitive;
use crate::attributes::MrtAttrDump;

impl MrtDump for Bgp4Mp {
    fn to_bytes(&self, subtype: u16) -> Result<Vec<u8>, DumpError> {
        match self {
            Bgp4Mp::Bgp4MpStateChange(v) |
            Bgp4Mp::Bgp4MpStateChangeAs4(v) => {
                v.to_bytes(subtype)
            }
            Bgp4Mp::Bgp4MpMessage(v) |
            Bgp4Mp::Bgp4MpMessageLocal(v) |
            Bgp4Mp::Bgp4MpMessageAs4(v) |
            Bgp4Mp::Bgp4MpMessageAs4Local(v) => {
                v.to_bytes(subtype)
            }
        }
    }
}

impl MrtDump for Bgp4MpStateChange {
    fn to_bytes(&self, subtype: u16) -> Result<Vec<u8>, DumpError> {
        let mut buffer: Vec<u8> = vec![];
        buffer.write_asn(&self.peer_asn)?;
        buffer.write_asn(&self.local_asn)?;
        buffer.write_16b(self.interface_index)?;
        buffer.write_16b(self.address_family.to_u16().unwrap())?;
        buffer.write_ip(&self.peer_addr)?;
        buffer.write_ip(&self.local_addr)?;
        buffer.write_16b(self.old_state.to_u16().unwrap())?;
        buffer.write_16b(self.new_state.to_u16().unwrap())?;
        Ok(buffer)
    }
}

impl MrtDump for Bgp4MpMessage {
    fn to_bytes(&self, subtype: u16) -> Result<Vec<u8>, DumpError> {
        let mut buffer: Vec<u8> = vec![];
        buffer.write_asn(&self.peer_asn)?;
        buffer.write_asn(&self.local_asn)?;
        buffer.write_16b(self.interface_index)?;
        buffer.write_16b(self.afi.to_u16().unwrap())?;
        buffer.write_ip(&self.peer_ip)?;
        buffer.write_ip(&self.local_ip)?;

        let add_path = match self.msg_type {
            Bgp4MpType::Bgp4MpMessageAddpath |
            Bgp4MpType::Bgp4MpMessageAs4Addpath |
            Bgp4MpType::Bgp4MpMessageLocalAddpath |
            Bgp4MpType::Bgp4MpMessageLocalAs4Addpath => {1}
            _ => {0}
        };

        let msg_bytes = self.bgp_message.to_bytes(add_path)?;
        buffer.extend(msg_bytes);
        Ok(buffer)
    }
}

/////////
// BGP //
/////////

impl MrtDump for BgpMessage {
    fn to_bytes(&self, subtype: u16) -> Result<Vec<u8>, DumpError> {
        let mut buffer: Vec<u8> = vec![];

        // https://tools.ietf.org/html/rfc4271#section-4
        // 16 (4 x 4 bytes) octets marker
        buffer.write_all(&[0;16])?;

        let mut msg_bytes: Vec<u8> = vec![];
        match self {
            BgpMessage::Open(m) => {
                msg_bytes.write_u8(BgpMessageType::OPEN.to_u8().unwrap())?;
                msg_bytes.extend(m.to_bytes(subtype)?);
            }
            BgpMessage::Update(m) => {
                msg_bytes.write_u8(BgpMessageType::UPDATE.to_u8().unwrap())?;
                msg_bytes.extend(m.to_bytes(subtype)?);
            }
            BgpMessage::Notification(m) => {
                msg_bytes.write_u8(BgpMessageType::NOTIFICATION.to_u8().unwrap())?;
                msg_bytes.extend(m.to_bytes(subtype)?);
            }
            BgpMessage::KeepAlive(m) => {
                msg_bytes.write_u8(BgpMessageType::KEEPALIVE.to_u8().unwrap())?;
                msg_bytes.extend(m.to_bytes(subtype)?);
            }
        };

        // length, minimum 19
        buffer.write_16b(2+16+msg_bytes.len() as u16)?;
        Ok(buffer)
    }
}

impl MrtDump for BgpOpenMessage {
    fn to_bytes(&self, subtype: u16) -> Result<Vec<u8>, DumpError> {
        let mut buffer: Vec<u8> = vec![];
        buffer.write_u8(self.version)?;
        buffer.write_16b(self.asn.asn as u16)?;
        buffer.write_16b(self.hold_time)?;
        buffer.write_ip(&self.sender_ip.into())?;
        // TODO: opt_parm is not current supported. https://github.com/bgpkit/bgpkit-parser/issues/48
        buffer.write_u8(0)?;
        Ok(buffer)
    }
}

impl MrtDump for BgpUpdateMessage {
    fn to_bytes(&self, subtype: u16) -> Result<Vec<u8>, DumpError> {
        // subtype is passed from Bgp4MpMessage
        let add_path = subtype>0;
        let mut buffer: Vec<u8> = vec![];

        let mut tmp_buf: Vec<u8> = vec![];
        for prefix in &self.withdrawn_prefixes {
            tmp_buf.write_nlri(prefix, add_path)?;
        }
        buffer.write_16b(tmp_buf.len() as u16)?;
        buffer.write(tmp_buf.as_slice())?;

        let mut tmp_buf: Vec<u8> = vec![];
        for attr in &self.attributes {
            tmp_buf.extend(attr.to_bytes(add_path, true, true, true)?);
        }
        buffer.write_16b(tmp_buf.len() as u16)?;
        buffer.write(tmp_buf.as_slice())?;

        let mut tmp_buf: Vec<u8> = vec![];
        for prefix in &self.announced_prefixes {
            tmp_buf.write_nlri(prefix, add_path)?;
        }
        buffer.write(tmp_buf.as_slice())?;
        Ok(buffer)
    }
}
impl MrtDump for BgpNotificationMessage {
    fn to_bytes(&self, subtype: u16) -> Result<Vec<u8>, DumpError> {
        let mut buffer: Vec<u8> = vec![];
        buffer.write_u8(self.error_code)?;
        buffer.write_u8(self.error_subcode)?;
        buffer.write_all(self.data.as_slice())?;
        Ok(buffer)
    }
}

impl MrtDump for BgpKeepAliveMessage {
    fn to_bytes(&self, subtype: u16) -> Result<Vec<u8>, DumpError> {
        Ok(vec![])
    }
}
