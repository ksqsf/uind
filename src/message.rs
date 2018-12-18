use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, Default)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub question: Vec<DnsQuestion>,
    pub answer: Vec<DnsResourceRecord>,
    pub authority: Vec<DnsResourceRecord>,
    pub additional: Vec<DnsResourceRecord>,
}

impl DnsMessage {
    pub fn is_query(&self) -> bool {
        self.header.query
    }
}

#[derive(Clone, Debug, Default)]
pub struct DnsHeader {
    pub id: u16,
    pub query: bool,
    pub opcode: DnsOpcode,
    pub authoritative: bool,
    pub truncated: bool,
    pub recur_desired: bool,
    pub recur_available: bool,
    pub rcode: DnsRcode,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd)]
pub enum DnsOpcode {
    Query,
    InverseQuery,
    Status,
}

impl DnsOpcode {
    pub fn try_from(x: u8) -> Option<DnsOpcode> {
        match x {
            0 => Some(DnsOpcode::Query),
            1 => Some(DnsOpcode::InverseQuery),
            2 => Some(DnsOpcode::Status),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd)]
pub enum DnsRcode {
    NoErrorCondition,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
}

impl DnsRcode {
    pub fn try_from(x: u8) -> Option<DnsRcode> {
        match x {
            0 => Some(DnsRcode::NoErrorCondition),
            1 => Some(DnsRcode::FormatError),
            2 => Some(DnsRcode::ServerFailure),
            3 => Some(DnsRcode::NameError),
            4 => Some(DnsRcode::NotImplemented),
            5 => Some(DnsRcode::Refused),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DnsQuestion {
    pub qname: Vec<String>,
    pub qtype: DnsType,
    pub qclass: DnsClass,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DnsResourceRecord {
    pub name: Vec<String>,
    pub rtype: DnsType,
    pub rclass: DnsClass,
    pub ttl: u32,
    pub data: DnsRRData
}

#[derive(Clone, Debug, PartialEq)]
pub enum DnsRRData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    MX(u16, Vec<String>),
    CNAME(Vec<String>),
    TXT(Vec<String>),
    SOA(Vec<String>, Vec<String>, u32, u32, u32, u32, u32),
    NS(Vec<String>),
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd)]
pub enum DnsType {
    A = 1,
    NS,
    MD,
    MF,
    CNAME,
    SOA,
    MB,
    MG,
    MR,
    NULL,
    WKS,
    PTR,
    HINFO,
    MINFO,
    MX,
    TXT,
    AAAA = 28,
    AXFR = 252,
    MAILB,
    MAILA,
    Any,
}

impl DnsType {
    pub fn try_from(x: u16) -> Option<DnsType> {
        match x {
            1 => Some(DnsType::A),
            2 => Some(DnsType::NS),
            3 => Some(DnsType::MD),
            4 => Some(DnsType::MF),
            5 => Some(DnsType::CNAME),
            6 => Some(DnsType::SOA),
            7 => Some(DnsType::MB),
            8 => Some(DnsType::MG),
            9 => Some(DnsType::MR),
            10 => Some(DnsType::NULL),
            11 => Some(DnsType::WKS),
            12 => Some(DnsType::PTR),
            13 => Some(DnsType::HINFO),
            14 => Some(DnsType::MINFO),
            15 => Some(DnsType::MX),
            16 => Some(DnsType::TXT),
            28 => Some(DnsType::AAAA),
            252 => Some(DnsType::AXFR),
            253 => Some(DnsType::MAILB),
            254 => Some(DnsType::MAILA),
            255 => Some(DnsType::Any),
            _ => None
        }
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd)]
pub enum DnsClass {
    Internet = 1,
    _CSNet,
    _CHAOS,
    _Hesiod,
    Any = 255,
}

impl DnsClass {
    pub fn try_from(x: u16) -> Option<DnsClass> {
        match x {
            1 => Some(DnsClass::Internet),
            255 => Some(DnsClass::Any),
            _ => None,
        }
    }
}

impl Default for DnsType {
    fn default() -> DnsType {
        DnsType::A
    }
}

impl Default for DnsClass {
    fn default() -> DnsClass {
        DnsClass::Internet
    }
}

impl Default for DnsOpcode {
    fn default() -> DnsOpcode {
        DnsOpcode::Query
    }
}

impl Default for DnsRcode {
    fn default() -> DnsRcode {
        DnsRcode::NoErrorCondition
    }
}
