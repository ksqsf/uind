use tokio::codec::{Decoder, Encoder};
use bytes::{BytesMut, BufMut};
use std::io::{Error, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::message::{DnsMessage, DnsHeader, DnsQuestion, DnsResourceRecord};
use crate::message::{DnsRRData, DnsOpcode, DnsRcode, DnsType, DnsClass};

macro_rules! or_continue {
    ( $x:expr ) => {
        match $x {
            Ok(v) => v,
            Err(e) => {error!("{}", e); continue;}
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct DnsMessageCodec {
    tcp: bool,
    len: Option<usize>, // only for tcp
    offset: usize
}

impl DnsMessageCodec {
    pub fn new(tcp: bool) -> DnsMessageCodec {
        DnsMessageCodec { tcp, len: None, offset: 0 }
    }
}

impl Decoder for DnsMessageCodec {
    type Item = DnsMessage;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 12 {
            return Ok(None)
        }

        if self.tcp && self.len.is_none() {
            let len = (src[0] as usize) << 8 | src[1] as usize;
            self.len = Some(len);
            debug!("TCP mode DNS length = {}", len);
        }
        if let Some(len) = self.len {
            if src.len() < 2 + len {
                return Ok(None)
            } else {
                src.split_to(2);
            }
        }

        let id = ((src[self.offset] as u16) << 8) | (src[self.offset+1] as u16);
        let qr = (src[self.offset+2] >> 7) & 1;
        let opcode = (src[self.offset+2] >> 3) & 0xf;
        let aa = (src[self.offset+2] >> 2) & 1;
        let tc = (src[self.offset+2] >> 1) & 1;
        let rd = src[self.offset+2] & 1;
        let ra = (src[self.offset+3] >> 7) & 1;
        let _z = (src[self.offset+3] >> 4) & 0x7;
        let rcode = src[self.offset+3] & 0xf;
        let qdcount = ((src[self.offset+4] as u16) << 8) + (src[self.offset+5] as u16);
        let ancount = ((src[self.offset+6] as u16) << 8) + (src[self.offset+7] as u16);
        let nscount = ((src[self.offset+8] as u16) << 8) + (src[self.offset+9] as u16);
        let arcount = ((src[self.offset+10] as u16) << 8) + (src[self.offset+11] as u16);

        let header = DnsHeader {
            id,
            query: qr == 0,
            opcode: match DnsOpcode::try_from(opcode) {
                Some(opcode) => opcode,
                None => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("opcode {} not recognized", opcode)
                    ))
                }
            },
            authoritative: aa == 1,
            truncated: tc == 1,
            recur_desired: rd == 1,
            recur_available: ra == 1,
            rcode: match DnsRcode::try_from(rcode) {
                Some(rcode) => rcode,
                None => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("response code {} not recognized", rcode)
                    ))
                }
            },
        };

        self.offset += 12;

        debug!("Parse qdcount={}", qdcount);
        let mut question = Vec::new();
        for _ in 0..qdcount {
            let qname = or_continue!(self.next_name(src));
            let qtype = or_continue!(self.next_type(src));
            let qclass = or_continue!(self.next_class(src));
            question.push(DnsQuestion{qname, qtype, qclass});
        }

        debug!("Parse ancount={}", ancount);
        let mut answer = Vec::new();
        for _ in 0..ancount {
            match self.next_rr(src) {
                Ok(rr) => answer.push(rr),
                Err(e) => error!("error parsing answer {}", e)
            }
        }

        debug!("Parse nscount={}", nscount);
        let mut authority = Vec::new();
        for _ in 0..nscount {
            match self.next_rr(src) {
                Ok(rr) => authority.push(rr),
                Err(e) => error!("error parsing authority {}", e)
            }
        }

        debug!("Parse arcount={}", arcount);
        let mut additional = Vec::new();
        for _ in 0..arcount {
            match self.next_rr(src) {
                Ok(rr) => additional.push(rr),
                Err(e) => error!("error parsing additional: {}", e)
            }
        }

        src.split_to(self.offset);
        self.offset = 0;
        self.len = None;

        Ok(Some(DnsMessage{header, question, answer, authority, additional}))
    }
}

impl DnsMessageCodec {
    /// This function will skip this RR when error occurs.
    fn next_rr(&mut self, src: &mut BytesMut) -> Result<DnsResourceRecord, <Self as Decoder>::Error> {
        let name = self.next_name(src)?;

        // Get rdlen before
        let rdlen = (src[self.offset+8] as u16) << 8 | src[self.offset+9] as u16;
        let final_pos = self.offset+10+rdlen as usize;
        debug!("RDLEN = {}, Final Pos = {}", rdlen, final_pos);

        // Make sure the final position is correct!
        let rtype = match self.next_type(src) {
            Ok(ty) => ty,
            Err(e) => {self.offset = final_pos; return Err(e)}
        };

        let rclass = match self.next_class(src) {
            Ok(cls) => cls,
            Err(e) => {self.offset = final_pos; return Err(e)}
        };

        let ttl = ((src[self.offset] as u32) << 24) | ((src[self.offset+1] as u32) << 16) | ((src[self.offset+2] as u32) << 8) | (src[self.offset+3] as u32);
        self.offset += 4;
        self.offset += 2; // Skip rdlen

        let data = match (rclass, rtype) {
            (DnsClass::Internet, DnsType::A) => {
                let res = DnsRRData::A(Ipv4Addr::new(src[self.offset], src[self.offset+1],
                                                     src[self.offset+2], src[self.offset+3]));
                self.offset += rdlen as usize;
                res
            }
            (DnsClass::Internet, DnsType::AAAA) => {
                let res = DnsRRData::AAAA(Ipv6Addr::new(
                    ((src[self.offset+0] as u16) << 8) | (src[self.offset+1] as u16),
                    ((src[self.offset+2] as u16) << 8) | (src[self.offset+3] as u16),
                    ((src[self.offset+4] as u16) << 8) | (src[self.offset+5] as u16),
                    ((src[self.offset+6] as u16) << 8) | (src[self.offset+7] as u16),
                    ((src[self.offset+8] as u16) << 8) | (src[self.offset+9] as u16),
                    ((src[self.offset+10] as u16) << 8) | (src[self.offset+11] as u16),
                    ((src[self.offset+12] as u16) << 8) | (src[self.offset+13] as u16),
                    ((src[self.offset+14] as u16) << 8) | (src[self.offset+15] as u16),
                ));
                self.offset += rdlen as usize;
                res
            }
            (DnsClass::Internet, DnsType::MX) => {
                let preference = (src[self.offset+0] as u16) << 8 | (src[self.offset+1] as u16);
                self.offset += 2;
                DnsRRData::MX(preference, self.next_name(src)?)
            }
            (DnsClass::Internet, DnsType::CNAME) => {
                DnsRRData::CNAME(self.next_name(src)?)
            }
            (DnsClass::Internet, DnsType::TXT) => {
                debug!("TXT began at offset={}", self.offset);
                let mut txt = vec![];
                while self.offset != final_pos {
                    let len = src[self.offset] as usize;
                    txt.push(String::from_utf8_lossy(&src[self.offset+1..self.offset+len as usize]).to_string());
                    self.offset += 1 + len;
                }
                let res = DnsRRData::TXT(txt);
                res
            }
            (DnsClass::Internet, DnsType::SOA) => {
                let (mname, rname, serial, refresh, retry, expire, minimum);
                mname = self.next_name(src)?;
                rname = self.next_name(src)?;
                serial = (src[self.offset] as u32) << 24 | (src[self.offset+1] as u32) << 16 | (src[self.offset+2] as u32) << 8 | (src[self.offset+3] as u32);
                self.offset += 4;
                refresh = (src[self.offset] as u32) << 24 | (src[self.offset+1] as u32) << 16 | (src[self.offset+2] as u32) << 8 | (src[self.offset+3] as u32);
                self.offset += 4;
                retry = (src[self.offset] as u32) << 24 | (src[self.offset+1] as u32) << 16 | (src[self.offset+2] as u32) << 8 | (src[self.offset+3] as u32);
                self.offset += 4;
                expire = (src[self.offset] as u32) << 24 | (src[self.offset+1] as u32) << 16 | (src[self.offset+2] as u32) << 8 | (src[self.offset+3] as u32);
                self.offset += 4;
                minimum = (src[self.offset] as u32) << 24 | (src[self.offset+1] as u32) << 16 | (src[self.offset+2] as u32) << 8 | (src[self.offset+3] as u32);
                self.offset += 4;
                DnsRRData::SOA(mname, rname, serial, refresh, retry, expire, minimum)
            }
            (DnsClass::Internet, DnsType::NS) => {
                let nsdname = self.next_name(src)?;
                DnsRRData::NS(nsdname)
            }
            (_, _) => {
                self.offset += rdlen as usize; // Skip this RR
                return Err(Error::new(ErrorKind::InvalidData, format!("unknown rdata {}", rtype as u16)))
            }
        };

        Ok(DnsResourceRecord {name, rtype, rclass, ttl, data})
    }

    fn next_name(&mut self, src: &mut BytesMut) -> Result<Vec<String>, <Self as Decoder>::Error> {
        let mut name = Vec::new();
        let mut label_len = src[self.offset];
        self.offset += 1;

        while label_len != 0 && (label_len >> 6) & 0x3 != 0x3 {
            debug!("Found label at offset {}", self.offset);

            // Label
            name.push(String::from_utf8_lossy(&src[self.offset..self.offset+label_len as usize]).into_owned());
            self.offset += label_len as usize;
            label_len = src[self.offset];
            self.offset += 1;
            debug!("{:?}", name);
        }

        if (label_len >> 6) & 0x3 == 0x3 {
            let mut i = (label_len & 0b111111) as usize | (src[self.offset] as usize);
            self.offset += 1;  // Skip the second byte of the pointer
            debug!("Found pointer to {}", i);

            label_len = src[i];
            i += 1;

            while label_len != 0 {
                // Jump to the actual label
                while (label_len >> 6) & 0x3 == 0x3 {
                    i = (label_len & 0b111111) as usize | (src[i] as usize);
                    debug!("Indirect pointer, jump to {}", i);
                    label_len = src[i];
                    i += 1;
                }

                // Do the actual parse
                name.push(String::from_utf8_lossy(&src[i..i+label_len as usize]).into_owned());
                i += label_len as usize;
                label_len = src[i];
                i += 1;
                debug!("{:?}", name);
            }
        }

        Ok(name)
    }

    fn next_type(&mut self, src: &mut BytesMut) -> Result<DnsType, <Self as Decoder>::Error> {
        let x = ((src[self.offset] as u16) << 8) | (src[self.offset+1] as u16);
        debug!("Found type {} at offset {}", x, self.offset);
        self.offset += 2;
        let ty = match DnsType::try_from(x) {
            Some(ty) => ty,
            None => return Err(Error::new(
                ErrorKind::InvalidData,
                format!("unknown type {}", x)
            ))
        };
        Ok(ty)
    }

    fn next_class(&mut self, src: &mut BytesMut) -> Result<DnsClass, <Self as Decoder>::Error> {
        let x = ((src[self.offset] as u16) << 8) | (src[self.offset+1] as u16);
        self.offset += 2;
        let qclass = match DnsClass::try_from(x) {
            Some(qclass) => qclass,
            None => return Err(Error::new(
                ErrorKind::InvalidData,
                format!("unknown class {}", x)
            ))
        };
        Ok(qclass)
    }
}

impl Encoder for DnsMessageCodec {
    type Item = DnsMessage;
    type Error = std::io::Error;

    fn encode(&mut self, item: DnsMessage, buf: &mut BytesMut) -> Result<(), <Self as Encoder>::Error> {
        let mut this = BytesMut::with_capacity(4096);
        buf.reserve(4096);

        self.encode_header(&item, &mut this)?;
        for question in item.question {
            self.encode_name(&question.qname, &mut this)?;
            this.put_u16_be(question.qtype as u16);
            this.put_u16_be(question.qclass as u16);
        }
        for answer in item.answer {
           self.encode_rr(&answer, &mut this)?;
        }
        for authority in item.authority {
            self.encode_rr(&authority, &mut this)?;
        }
        for additional in item.additional {
            self.encode_rr(&additional, &mut this)?;
        }

        if self.tcp {
            buf.put_u16_be(this.len() as u16);
        } else if this.len() > 512 {
            debug!("Buffer length {} exceeds 512, truncating", buf.len());
            this[2] |= 0b10;
            this.truncate(512);
        } else {
            this[2] &= 0b11111101;
        }
        buf.extend(this);

        Ok(())
    }
}

impl DnsMessageCodec {
    fn encode_header(&mut self, message: &DnsMessage, buf: &mut BytesMut) -> Result<(), <Self as Encoder>::Error> {
        buf.put_u16_be(message.header.id);
        buf.put_u8(
            ((!message.header.query as u8) << 7) |
            ((message.header.opcode as u8) & 0xf << 3) |
            ((message.header.authoritative as u8) << 2) |
            ((message.header.truncated as u8) << 1) |
            message.header.recur_desired as u8
        );
        buf.put_u8(
            ((message.header.recur_available as u8) << 7) |
            (0 << 4) | // Z bits
            ((message.header.rcode as u8) & 0xf)
        );
        buf.put_u16_be(message.question.len() as u16);
        buf.put_u16_be(message.answer.len() as u16);
        buf.put_u16_be(message.authority.len() as u16);
        buf.put_u16_be(message.additional.len() as u16);
        Ok(())
    }

    fn encode_name(&mut self, name: &Vec<String>, buf: &mut BytesMut) -> Result<(), <Self as Encoder>::Error> {
        for label in name {
            buf.put_u8(label.as_bytes().len() as u8);
            buf.put_slice(label.as_bytes());
        }
        buf.put_u8(0);
        Ok(())
    }

    fn encode_rr(&mut self, rr: &DnsResourceRecord, buf: &mut BytesMut) -> Result<(), <Self as Encoder>::Error> {
        fn name_length(name: &Vec<String>) -> u16 {
            let mut len = 0u16;
            for i in name {
                len += 1;
                len += i.as_bytes().len() as u16;
            }
            len += 1; // final zero
            return len;
        }

        self.encode_name(&rr.name, buf)?;
        buf.put_u16_be(rr.rtype as u16);
        buf.put_u16_be(rr.rclass as u16);
        buf.put_u32_be(rr.ttl);
        match rr.data {
            DnsRRData::A(addr4) => {
                buf.put_u16_be(4);
                buf.put_u32_be(u32::from(addr4))
            }
            DnsRRData::AAAA(addr6) => {
                buf.put_u16_be(16);
                let octets = addr6.octets();
                for i in 0..16 {
                    buf.put_u8(octets[i]);
                }
            }
            DnsRRData::MX(pref, ref name) => {
                buf.put_u16_be(name_length(name) + 2);
                buf.put_u16_be(pref);
                self.encode_name(name, buf)?;
            }
            DnsRRData::CNAME(ref name) => {
                buf.put_u16_be(name_length(name));
                self.encode_name(name, buf)?;
            }
            DnsRRData::TXT(ref txt) => {
                let mut rdlen = 0;
                for i in txt {
                    rdlen += i.as_bytes().len() + 1;
                }
                buf.put_u16_be(rdlen as u16);
                for i in txt {
                    buf.put_u8(i.as_bytes().len() as u8);
                    buf.put(i.as_bytes());
                }
            }
            DnsRRData::SOA(ref mname, ref rname, serial, refresh, retry, expire, minimum) => {
                buf.put_u16_be(name_length(mname) + name_length(rname) + 4 * 5);
                self.encode_name(mname, buf)?;
                self.encode_name(rname, buf)?;
                buf.put_u32_be(serial);
                buf.put_u32_be(refresh);
                buf.put_u32_be(retry);
                buf.put_u32_be(expire);
                buf.put_u32_be(minimum);
            }
            DnsRRData::NS(ref name) => {
                buf.put_u16_be(name_length(name));
                self.encode_name(name, buf)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_both_1() {
        let message = DnsMessage {
            header: DnsHeader {
                id: 12345,
                query: true,
                truncated: true,
                ..Default::default()
            },
            question: vec![DnsQuestion {
                qname: vec!["ksqsf".to_owned(), "moe".to_owned()],
                qtype: DnsType::AAAA,
                qclass: DnsClass::Any,
            }],
            ..Default::default()
        };
        let mut buf = BytesMut::new();
        let mut codec = DnsMessageCodec::new(false);
        codec.encode(message, &mut buf).expect("encode");
        let decoded = codec.decode(&mut buf).expect("no error").expect("parse complete");
        assert_eq!(decoded.header.id, 12345);
        assert_eq!(decoded.header.query, true);
        assert_eq!(decoded.header.truncated, false); // truncated is overwritten
        assert_eq!(&decoded.question[0].qname.as_ref(), &["ksqsf", "moe"]);
    }

    #[test]
    fn test_both_2() {
        let message = DnsMessage {
            header: DnsHeader {
                id: 12345,
                truncated: true,
                ..Default::default()
            },
            question: vec![DnsQuestion {
                qname: vec!["ksqsf".to_owned(), "moe".to_owned()],
                qtype: DnsType::AAAA,
                qclass: DnsClass::Any,
            }],
            answer: vec![DnsResourceRecord {
                name: vec!["ksqsf".to_owned(), "moe".to_owned()],
                rtype: DnsType::A,
                rclass: DnsClass::Internet,
                ttl: 120,
                data: DnsRRData::A(Ipv4Addr::new(127, 0, 0, 1))
            }],
            ..Default::default()
        };
        let mut buf = BytesMut::with_capacity(4096);
        let mut codec = DnsMessageCodec::new(false);
        codec.encode(message, &mut buf).expect("encode");
        let decoded = codec.decode(&mut buf).expect("no error").expect("parse complete");
        assert_eq!(decoded.header.id, 12345);
        assert_eq!(decoded.header.truncated, false);
        assert_eq!(&decoded.answer[0].name.as_ref(), &["ksqsf", "moe"]);
        assert_eq!(decoded.answer[0].ttl, 120);
        assert_eq!(decoded.answer[0].data, DnsRRData::A(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn test_many() {
        std::env::set_var("RUST_LOG", "trace");
        let mut buf = BytesMut::with_capacity(4096);
        let mut codec = DnsMessageCodec::new(true);
        let message = DnsMessage {
            header: DnsHeader {
                id: 12345,
                truncated: true,
                ..Default::default()
            },
            question: vec![DnsQuestion {
                qname: vec!["ksqsf".to_owned(), "moe".to_owned()],
                qtype: DnsType::AAAA,
                qclass: DnsClass::Any,
            }],
            answer: vec![DnsResourceRecord {
                name: vec!["ksqsf".to_owned(), "moe".to_owned()],
                rtype: DnsType::A,
                rclass: DnsClass::Internet,
                ttl: 120,
                data: DnsRRData::A(Ipv4Addr::new(127, 0, 0, 1))
            }],
            ..Default::default()
        };
        for _ in 0..16 {
            codec.encode(message.clone(), &mut buf).expect("encode");
        }
        for _ in 0..16 {
            codec.decode(&mut buf).expect("decode");
        }
        match codec.decode(&mut buf) {
            Ok(Some(_)) => unreachable!(),
            _ => ()
        }
    }
}
