use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, Default)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub question: Vec<DnsQuestion>,
    pub answer: Vec<DnsResourceRecord>,
    pub authority: Vec<DnsResourceRecord>,
    pub additional: Vec<DnsResourceRecord>,
}

#[derive(Clone, Debug, Default)]
pub struct DnsHeader {
    pub id: u16,
    pub query: bool,
    pub opcode: DnsOpcode,
    pub authoritative: bool,
    pub truncation: bool,
    pub recur_desired: bool,
    pub recur_available: bool,
    pub reserved: u8,
    pub rcode: DnsRcode,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd)]
pub enum DnsOpcode {
    Query,
    InverseQuery,
    Status,
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

#[derive(Clone, Debug, Default)]
pub struct DnsQuestion {
    pub qname: Vec<String>,
    pub qtype: DnsType,
    pub qclass: DnsClass,
}

#[derive(Clone, Debug)]
pub struct DnsResourceRecord {
    pub name: Vec<String>,
    pub rtype: DnsType,
    pub rclass: DnsClass,
    pub ttl: u32,
    pub data: DnsRRData
}

#[derive(Clone, Debug)]
pub enum DnsRRData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
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

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd)]
pub enum DnsClass {
    Internet = 1,
    _CSNet,
    _CHAOS,
    _Hesiod,
    Any = 255,
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
