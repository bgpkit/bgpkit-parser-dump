use std::net::{IpAddr, Ipv4Addr};
use bgp_models::network::{Asn, AsnLength};
use byteorder::{BigEndian, WriteBytesExt};
use crate::DumpError;

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

    fn write_asn(&mut self, asn: Asn) -> Result<(), DumpError> {
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
}