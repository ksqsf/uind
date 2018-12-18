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

#[derive(Clone, Default)]
pub struct DnsMessageCodec {
    offset: usize
}

impl DnsMessageCodec {
    pub fn new() -> DnsMessageCodec {
        DnsMessageCodec { offset: 0 }
    }
}

impl Decoder for DnsMessageCodec {
    type Item = DnsMessage;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        //return Err(Error::new(ErrorKind::Interrupted, "test"));
        if src.len() < 12 {
            return Ok(None)
        }

        let id = ((src[0] as u16) << 8) | (src[1] as u16);
        let qr = (src[2] >> 7) & 1;
        let opcode = (src[2] >> 3) & 0xf;
        let aa = (src[2] >> 2) & 1;
        let tc = (src[2] >> 1) & 1;
        let rd = src[2] & 1;
        let ra = (src[3] >> 7) & 1;
        let _z = (src[3] >> 4) & 0x7;
        let rcode = src[3] & 0xf;
        let qdcount = ((src[4] as u16) << 8) + (src[5] as u16);
        let ancount = ((src[6] as u16) << 8) + (src[7] as u16);
        let nscount = ((src[8] as u16) << 8) + (src[9] as u16);
        let arcount = ((src[10] as u16) << 8) + (src[11] as u16);

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

        self.offset = 12;

        let mut question = Vec::new();
        for _ in 0..qdcount {
            let qname = or_continue!(self.next_name(src));
            let qtype = or_continue!(self.next_type(src));
            let qclass = or_continue!(self.next_class(src));
            question.push(DnsQuestion{qname, qtype, qclass});
        }

        let mut answer = Vec::new();
        for _ in 0..ancount {
            match self.next_rr(src) {
                Ok(rr) => answer.push(rr),
                Err(e) => error!("error parsing answer {}", e)
            }
        }

        let mut authority = Vec::new();
        for _ in 0..nscount {
            match self.next_rr(src) {
                Ok(rr) => authority.push(rr),
                Err(e) => error!("error parsing authority {}", e)
            }
        }

        let mut additional = Vec::new();
        for _ in 0..arcount {
            match self.next_rr(src) {
                Ok(rr) => additional.push(rr),
                Err(e) => error!("error parsing additional: {}", e)
            }
        }

        src.split_to(self.offset);
        self.offset = 0;

        Ok(Some(DnsMessage{header, question, answer, authority, additional}))
    }
}

impl DnsMessageCodec {
    fn next_rr(&mut self, src: &mut BytesMut) -> Result<DnsResourceRecord, <Self as Decoder>::Error> {
        let name = self.next_name(src)?;
        let rtype = self.next_type(src)?;
        let rclass = self.next_class(src)?;
        let ttl = ((src[self.offset] as u32) << 24) | ((src[self.offset+1] as u32) << 16) | ((src[self.offset+2] as u32) << 8) | (src[self.offset+3] as u32);
        self.offset += 4;

        let rdlen = ((src[self.offset] as u16) << 8) | (src[self.offset+1] as u16);
        self.offset += 2;

        let data = match (rclass, rtype) {
            (DnsClass::Internet, DnsType::A) => {
                DnsRRData::A(Ipv4Addr::new(src[self.offset], src[self.offset+1],
                                           src[self.offset+2], src[self.offset+3]))
            }
            (DnsClass::Internet, DnsType::AAAA) => {
                DnsRRData::AAAA(Ipv6Addr::new(
                    ((src[self.offset+0] as u16) << 8) | (src[self.offset+1] as u16),
                    ((src[self.offset+2] as u16) << 8) | (src[self.offset+3] as u16),
                    ((src[self.offset+4] as u16) << 8) | (src[self.offset+5] as u16),
                    ((src[self.offset+6] as u16) << 8) | (src[self.offset+7] as u16),
                    ((src[self.offset+8] as u16) << 8) | (src[self.offset+9] as u16),
                    ((src[self.offset+10] as u16) << 8) | (src[self.offset+11] as u16),
                    ((src[self.offset+12] as u16) << 8) | (src[self.offset+13] as u16),
                    ((src[self.offset+14] as u16) << 8) | (src[self.offset+15] as u16),
                ))
            }
            (DnsClass::Internet, DnsType::MX) => {
                let preference = (src[self.offset+0] as u16) << 8 | (src[self.offset+1] as u16);
                self.offset += 2;
                let name = self.next_name(src)?;
                self.offset -= rdlen as usize;
                DnsRRData::MX(preference, name)
            }
            (DnsClass::Internet, DnsType::CNAME) => {
                let name = self.next_name(src)?;
                self.offset -= rdlen as usize;
                DnsRRData::CNAME(name)
            }
            (DnsClass::Internet, DnsType::TXT) => {
                DnsRRData::TXT(String::from_utf8_lossy(&src[self.offset..self.offset+rdlen as usize]).to_string())
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
            (_, _) => return Err(Error::new(ErrorKind::InvalidData, format!("unknown rdata {}", rtype as u16)))
        };

        self.offset += rdlen as usize;

        Ok(DnsResourceRecord {name, rtype, rclass, ttl, data})
    }

    fn next_name(&mut self, src: &mut BytesMut) -> Result<Vec<String>, <Self as Decoder>::Error> {
        let mut name = Vec::new();
        let mut label_len = src[self.offset];
        self.offset += 1;

        while label_len != 0 && (label_len >> 6) & 0x3 != 0x3 {
            // Label
            name.push(String::from_utf8_lossy(&src[self.offset..self.offset+label_len as usize]).into_owned());
            self.offset += label_len as usize;
            label_len = src[self.offset];
            self.offset += 1;
        }

        if (label_len >> 6) & 0x3 == 0x3 {
            let mut i = (label_len & 0b111111) as usize | (src[self.offset] as usize);
            self.offset += 1;  // Skip the second byte of the pointer
            debug!("pointer start at {}", i);

            label_len = src[i];
            i = i + 1;

            while label_len != 0 {
                // Jump to the actual label
                while (label_len >> 6) & 0x3 == 0x3 {
                    i = (label_len & 0b111111) as usize | (src[i] as usize);
                    debug!("Jump to {}", i);
                    label_len = src[i];
                    i += 1;
                }

                // Do the actual parse
                name.push(String::from_utf8_lossy(&src[i..i+label_len as usize]).into_owned());
                i += label_len as usize;
                label_len = src[i];
                i += 1;
            }
        }

        Ok(name)
    }

    fn next_type(&mut self, src: &mut BytesMut) -> Result<DnsType, <Self as Decoder>::Error> {
        let x = ((src[self.offset] as u16) << 8) | (src[self.offset+1] as u16);
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
        self.encode_header(&item, buf)?;
        for question in item.question {
            self.encode_name(&question.qname, buf)?;
            buf.put_u16_be(question.qtype as u16);
            buf.put_u16_be(question.qclass as u16);
        }
        for answer in item.answer {
            self.encode_rr(&answer, buf)?;
        }
        for authority in item.authority {
            self.encode_rr(&authority, buf)?;
        }
        for additional in item.additional {
            self.encode_rr(&additional, buf)?;
        }
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
                buf.put_u16_be(txt.as_bytes().len() as u16);
                buf.put(txt.as_bytes());
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
        let mut codec = DnsMessageCodec::new();
        codec.encode(message, &mut buf).expect("encode");
        let decoded = codec.decode(&mut buf).expect("no error").expect("parse complete");
        assert_eq!(decoded.header.id, 12345);
        assert_eq!(decoded.header.query, true);
        assert_eq!(decoded.header.truncated, true);
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
        let mut codec = DnsMessageCodec::new();
        codec.encode(message, &mut buf).expect("encode");
        let decoded = codec.decode(&mut buf).expect("no error").expect("parse complete");
        assert_eq!(decoded.header.id, 12345);
        assert_eq!(decoded.header.truncated, true);
        assert_eq!(&decoded.answer[0].name.as_ref(), &["ksqsf", "moe"]);
        assert_eq!(decoded.answer[0].ttl, 120);
        assert_eq!(decoded.answer[0].data, DnsRRData::A(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn test_many() {
        let mut buf = BytesMut::with_capacity(4096);
        let mut codec = DnsMessageCodec::new();
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
            match codec.decode(&mut buf) {
                Ok(Some(_)) => (),
                _ => unreachable!()
            }
        }
        match codec.decode(&mut buf) {
            Ok(Some(_)) => unreachable!(),
            _ => ()
        }
    }
}
