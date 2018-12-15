use tokio::codec::{Decoder, Encoder};
use bytes::{BytesMut, BufMut};
use std::io::{Error, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::message::{DnsMessage, DnsHeader, DnsQuestion, DnsResourceRecord};
use crate::message::{DnsRRData, DnsOpcode, DnsRcode, DnsType, DnsClass};

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
        let id = ((src[0] as u16) << 8) | (src[1] as u16);
        let qr = (src[2] >> 7) & 1;
        let opcode = (src[2] >> 3) & 0xf;
        let aa = (src[2] >> 2) & 1;
        let tc = (src[2] >> 1) & 1;
        let rd = src[2] & 1;
        let ra = (src[3] >> 7) & 1;
        let z = (src[3] >> 4) & 0x7;
        let rcode = src[3] & 0xf;
        let qdcount = ((src[4] as u16) << 8) + (src[5] as u16);
        let ancount = ((src[6] as u16) << 8) + (src[7] as u16);
        let nscount = ((src[8] as u16) << 8) + (src[9] as u16);
        let arcount = ((src[10] as u16) << 8) + (src[11] as u16);

        let header = DnsHeader {
            id,
            query: qr == 1,
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
            reserved: z,
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

        // TODO: 4.1.4 Message Compression
        let mut question = Vec::new();
        for _ in 0..qdcount {
            let qname = self.next_name(src)?;
            let qtype = self.next_type(src)?;
            let qclass = self.next_class(src)?;
            question.push(DnsQuestion{qname, qtype, qclass});
        }

        let mut answer = Vec::new();
        for _ in 0..ancount {
            match self.next_rr(src) {
                Ok(rr) => answer.push(rr),
                Err(e) => error!("{}", e)
            }
        }

        let mut authority = Vec::new();
        for _ in 0..nscount {
            match self.next_rr(src) {
                Ok(rr) => authority.push(rr),
                Err(e) => error!("{}", e)
            }
            authority.push(self.next_rr(src)?);
        }

        let mut additional = Vec::new();
        for _ in 0..arcount {
            match self.next_rr(src) {
                Ok(rr) => additional.push(rr),
                Err(e) => error!("{}", e)
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
            (_, _) => return Err(Error::new(ErrorKind::InvalidData, "unknown rdata"))
        };

        self.offset += rdlen as usize;

        Ok(DnsResourceRecord {name, rtype, rclass, ttl, data})
    }

    fn next_name(&mut self, src: &mut BytesMut) -> Result<Vec<String>, <Self as Decoder>::Error> {
        let mut name = Vec::new();
        let mut label_len = src[self.offset];
        self.offset += 1;

        while label_len != 0 {
            name.push(String::from_utf8_lossy(&src[self.offset..self.offset+label_len as usize]).into_owned());
            self.offset += label_len as usize;
            label_len = src[self.offset];
            self.offset += 1;
        }

        Ok(name)
    }

    fn next_type(&mut self, src: &mut BytesMut) -> Result<DnsType, <Self as Decoder>::Error> {
        let x = ((src[self.offset] as u16) << 8) | (src[self.offset+1] as u16);
        let ty = match DnsType::try_from(x) {
            Some(ty) => ty,
            None => return Err(Error::new(
                ErrorKind::InvalidData,
                format!("unknown type {}", x)
            ))
        };
        self.offset += 2;
        Ok(ty)
    }

    fn next_class(&mut self, src: &mut BytesMut) -> Result<DnsClass, <Self as Decoder>::Error> {
        let x = ((src[self.offset] as u16) << 8) | (src[self.offset+1] as u16);
        let qclass = match DnsClass::try_from(x) {
            Some(qclass) => qclass,
            None => return Err(Error::new(
                ErrorKind::InvalidData,
                format!("unknown class {}", x)
            ))
        };
        self.offset += 2;
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
            ((message.header.query as u8) << 7) |
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
        self.encode_name(&rr.name, buf)?;
        buf.put_u16_be(rr.rtype as u16);
        buf.put_u16_be(rr.rclass as u16);
        buf.put_u32_be(rr.ttl);
        match rr.data {
            DnsRRData::A(addr4) => {
                buf.put_u16_be(4);
                buf.put_u32_be(u32::from(addr4))
            },
            DnsRRData::AAAA(addr6) => {
                buf.put_u16_be(16);
                let octets = addr6.octets();
                for i in 0..16 {
                    buf.put_u8(octets[i]);
                }
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
}
