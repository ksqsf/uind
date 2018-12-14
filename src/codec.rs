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
            opcode: match opcode {
                0 => DnsOpcode::Query,
                1 => DnsOpcode::InverseQuery,
                2 => DnsOpcode::Status,
                _ => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "opcode not recognized"
                    ))
                }
            },
            authoritative: aa == 1,
            truncated: tc == 1,
            recur_desired: rd == 1,
            recur_available: ra == 1,
            reserved: z,
            rcode: match rcode {
                0 => DnsRcode::NoErrorCondition,
                1 => DnsRcode::FormatError,
                2 => DnsRcode::ServerFailure,
                3 => DnsRcode::NameError,
                4 => DnsRcode::NotImplemented,
                5 => DnsRcode::Refused,
                _ => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "response code not recognized"
                    ))
                }
            },
            qdcount, ancount, nscount, arcount
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
                Err(e) => println!("{}", e)
            }
        }

        let mut authority = Vec::new();
        for _ in 0..nscount {
            match self.next_rr(src) {
                Ok(rr) => authority.push(rr),
                Err(e) => println!("{}", e)
            }
            authority.push(self.next_rr(src)?);
        }

        let mut additional = Vec::new();
        for _ in 0..arcount {
            match self.next_rr(src) {
                Ok(rr) => additional.push(rr),
                Err(e) => println!("{}", e)
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
        println!("{:?}", name);
        let rtype = self.next_type(src)?;
        let rclass = self.next_class(src)?;
        let ttl = ((src[self.offset] as u32) << 24) | ((src[self.offset] as u32) << 16) | ((src[self.offset] as u32) << 8) | (src[self.offset] as u32);
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
        let ty = match ((src[self.offset] as u16) << 8) | (src[self.offset+1] as u16) {
            1 => DnsType::A,
            2 => DnsType::NS,
            3 => DnsType::MD,
            4 => DnsType::MF,
            5 => DnsType::CNAME,
            6 => DnsType::SOA,
            7 => DnsType::MB,
            8 => DnsType::MG,
            9 => DnsType::MR,
            10 => DnsType::NULL,
            11 => DnsType::WKS,
            12 => DnsType::PTR,
            13 => DnsType::HINFO,
            14 => DnsType::MINFO,
            15 => DnsType::MX,
            16 => DnsType::TXT,
            28 => DnsType::AAAA,
            252 => DnsType::AXFR,
            253 => DnsType::MAILB,
            254 => DnsType::MAILA,
            255 => DnsType::Any,
            i @ _ => return Err(Error::new(
                ErrorKind::InvalidData,
                format!("unknown type {}", i)
            ))
        };
        self.offset += 2;
        Ok(ty)
    }

    fn next_class(&mut self, src: &mut BytesMut) -> Result<DnsClass, <Self as Decoder>::Error> {
        let qclass = match ((src[self.offset] as u16) << 8) | (src[self.offset+1] as u16) {
            1 => DnsClass::Internet,
            255 => DnsClass::Any,
            _ => return Err(Error::new(
                ErrorKind::InvalidData,
                "unknown class"
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
        self.encode_header(&item.header, buf)?;
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
    fn encode_header(&mut self, header: &DnsHeader, buf: &mut BytesMut) -> Result<(), <Self as Encoder>::Error> {
        buf.put_u16_be(header.id);
        buf.put_u8(
            ((header.query as u8) << 7) |
            ((header.opcode as u8) & 0xf << 3) |
            ((header.authoritative as u8) << 2) |
            ((header.truncated as u8) << 1) |
            header.recur_desired as u8
        );
        buf.put_u8(
            ((header.recur_available as u8) << 7) |
            (0 << 4) | // Z bits
            ((header.rcode as u8) & 0xf)
        );
        buf.put_u16_be(header.qdcount);
        buf.put_u16_be(header.ancount);
        buf.put_u16_be(header.nscount);
        buf.put_u16_be(header.arcount);
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
