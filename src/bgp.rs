use bgp_models::bgp::{BgpKeepAliveMessage, BgpMessage, BgpNotificationMessage, BgpOpenMessage, BgpUpdateMessage};
use bgp_models::mrt::{Bgp4Mp, Bgp4MpMessage, Bgp4MpStateChange};
use crate::{DumpError, MrtDump};

impl MrtDump for Bgp4Mp {
    fn to_bytes(&self, subtype: u16) -> Result<Vec<u8>, DumpError> {
        todo!()
    }
}

impl MrtDump for Bgp4MpStateChange {
    fn to_bytes(&self, subtype: u16) -> Result<Vec<u8>, DumpError> {
        todo!()
    }
}

impl MrtDump for Bgp4MpMessage {
    fn to_bytes(&self, subtype: u16) -> Result<Vec<u8>, DumpError> {
        todo!()
    }
}

/////////
// BGP //
/////////

impl MrtDump for BgpMessage {
    fn to_bytes(&self, subtype: u16) -> Result<Vec<u8>, DumpError> {
        todo!()
    }
}

impl MrtDump for BgpOpenMessage {
    fn to_bytes(&self, subtype: u16) -> Result<Vec<u8>, DumpError> {
        todo!()
    }
}

impl MrtDump for BgpUpdateMessage {
    fn to_bytes(&self, subtype: u16) -> Result<Vec<u8>, DumpError> {
        todo!()
    }
}
impl MrtDump for BgpNotificationMessage {
    fn to_bytes(&self, subtype: u16) -> Result<Vec<u8>, DumpError> {
        todo!()
    }
}

impl MrtDump for BgpKeepAliveMessage {
    fn to_bytes(&self, subtype: u16) -> Result<Vec<u8>, DumpError> {
        todo!()
    }
}
