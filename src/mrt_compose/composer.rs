use bgp_models::prelude::*;
use crate::mrt_compose::error::ComposeError;
use crate::MrtDump;

pub trait MrtCompose {
    fn add_elem(&mut self, elem: &BgpElem) -> Result<(), ComposeError>;
    fn add_elems(&mut self, elems: &Vec<BgpElem>) -> Result<(), ComposeError>;
    fn export_bytes(&mut self) -> Result<Vec<u8>, ComposeError>;
}

pub struct TableDumpComposer {

}

pub struct BgpUpdatesComposer {
    mrt_messages: Vec<MrtRecord>,
}

fn elem_to_attributes(elem: &BgpElem) -> Vec<Attribute> {
    todo!()
}

impl MrtCompose for BgpUpdatesComposer {
    /// add single [BgpElem] as a BGP message entry
    fn add_elem(&mut self, elem: &BgpElem) -> Result<(), ComposeError> {
        let (a,w) = match elem.elem_type{
            ElemType::ANNOUNCE => {(vec![elem.prefix], vec![])}
            ElemType::WITHDRAW => {(vec![], vec![elem.prefix])}
        };

        let msg = BgpUpdateMessage{
            withdrawn_prefixes: w,
            attributes: elem_to_attributes(elem),
            announced_prefixes: a
        };

        self.mrt_messages.push (
            MrtRecord{
                common_header: CommonHeader {
                    timestamp: todo!(),
                    microsecond_timestamp: todo!(),
                    entry_type: todo!(),
                    entry_subtype: todo!(),
                    length: 0
                },
                message: MrtMessage::Bgp4Mp(
                    Bgp4Mp::Bgp4MpMessageAs4(
                        Bgp4MpMessage{
                            msg_type: Bgp4MpType::Bgp4MpMessageAs4,
                            peer_asn: todo!(),
                            local_asn: todo!(),
                            interface_index: todo!(),
                            afi: todo!(),
                            peer_ip: todo!(),
                            local_ip: todo!(),
                            bgp_message: BgpMessage::Update(msg)
                        }
                    )
                )

            }
        );
        todo!()
    }

    /// add a group of [BgpElem]s as a BGP message entry
    fn add_elems(&mut self, elems: &Vec<BgpElem>) -> Result<(), ComposeError> {
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