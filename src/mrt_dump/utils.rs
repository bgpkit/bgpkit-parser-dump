use std::net::{IpAddr, Ipv4Addr};

use bgp_models::network::{Asn, AsnLength, NetworkPrefix};
use byteorder::{BigEndian, WriteBytesExt};

use crate::DumpError;

#[allow(unused)]
pub fn ipv4_to_u32(ip: &Ipv4Addr) -> u32 {
    let o = ip.octets();
    ((o[0] as u32) <<24)+((o[1] as u32) <<16)+((o[2] as u32) <<8)+ o[3] as u32
}

pub trait WriteUtils: std::io::Write {

    fn write_16b(&mut self, v: u16) -> Result<(), DumpError>{
        self.write_u16::<BigEndian>(v)?;
        Ok(())
    }

    fn write_32b(&mut self, v: u32) -> Result<(), DumpError>{
        self.write_u32::<BigEndian>(v)?;
        Ok(())
    }

    fn write_ip(&mut self, addr: &IpAddr) -> Result<(), DumpError>{
        match addr {
            IpAddr::V4(ip) => {
                self.write_all(&ip.octets())?;
            }
            IpAddr::V6(ip) => {
                self.write_all(&ip.octets())?;
            }
        }
        Ok(())
    }

    fn write_asn(&mut self, asn: &Asn) -> Result<(), DumpError> {
        match asn.len {
            AsnLength::Bits16 => {
                self.write_16b(asn.asn as u16)?;
            }
            AsnLength::Bits32 => {
                self.write_32b(asn.asn as u32)?;
            }
        }
        Ok(())
    }

    fn write_nlri(&mut self, nlri: &NetworkPrefix, add_path: bool) -> Result<(), DumpError>{
        if add_path{
            self.write_32b(nlri.path_id)?;
        }
        let ip = nlri.prefix.ip();
        let ip_bytes = match ip {
            IpAddr::V4(ip) => {ip.octets().to_vec()}
            IpAddr::V6(ip) => {ip.octets().to_vec()}
        };

        let bit_len = nlri.prefix.prefix();
        let byte_len: usize = (bit_len as usize + 7) / 8;

        self.write_u8(bit_len as u8)?;

        for i in 0..byte_len {
            self.write_u8(ip_bytes[i])?;
        }

        Ok(())
    }
}

// All types that implement Read can now read prefixes
impl<W: std::io::Write> WriteUtils for W {}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_ip_to_u32() {
        let ip_u32 = ipv4_to_u32(&Ipv4Addr::from_str("1.2.3.4").unwrap());
        assert_eq!(ip_u32, 16909060);
    }

    // #[test]
    // fn test_nlri() {
    //     let prefix1 = NetworkPrefix{ prefix: IpNetwork::from_str("10.2.0.0/24").unwrap(), path_id: 0 };
    //     let mut buffer: Vec<u8> = vec![];
    //     buffer.write_nlri(&prefix1, false).unwrap();
    //     let prefix2 = buffer.as_slice().read_nlri_prefix(&Afi::Ipv4, false).unwrap();
    //     assert_eq!(prefix1, prefix2);

    //     // with path id but not toggled on
    //     let prefix1 = NetworkPrefix{ prefix: IpNetwork::from_str("10.2.0.0/24").unwrap(), path_id: 1 };
    //     let mut buffer: Vec<u8> = vec![];
    //     buffer.write_nlri(&prefix1, false).unwrap();
    //     let prefix2 = buffer.as_slice().read_nlri_prefix(&Afi::Ipv4, false).unwrap();
    //     assert_ne!(prefix1, prefix2);

    //     // with path id and toggled on
    //     let prefix1 = NetworkPrefix{ prefix: IpNetwork::from_str("10.2.0.0/24").unwrap(), path_id: 1 };
    //     let mut buffer: Vec<u8> = vec![];
    //     buffer.write_nlri(&prefix1, true).unwrap();
    //     let prefix2 = buffer.as_slice().read_nlri_prefix(&Afi::Ipv4, true).unwrap();
    //     assert_eq!(prefix1, prefix2);
    // }
}