struct DnsMessage {
    header: DnsHeader,
    question: Vec<DnsQuestion>,
    answer: Vec<DnsResourceRecord>,
    authority: Vec<DnsResourceRecord>,
    additional: Vec<DnsResourceRecord>,
}

struct DnsHeader {
    id: u16,
    query: bool,
    opcode: DnsOpcode,
    authoritative: bool,
    truncation: bool,
    recur_desired: bool,
    recur_available: bool,
    rcode: DnsRcode,
    qdcount: u16,
    nscount: u16,
    arcount: u16,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd)]
enum DnsOpcode {
    Query,
    InverseQuery,
    Status,
    _Reserved3,
    _Reserved4,
    _Reserved5,
    _Reserved6,
    _Reserved7,
    _Reserved8,
    _Reserved9,
    _Reserved10,
    _Reserved11,
    _Reserved12,
    _Reserved13,
    _Reserved14,
    _Reserved15,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd)]
enum DnsRcode {
    NoErrorCondition,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    _Reserved6,
    _Reserved7,
    _Reserved8,
    _Reserved9,
    _Reserved10,
    _Reserved11,
    _Reserved12,
    _Reserved13,
    _Reserved14,
    _Reserved15,
}

#[derive(Clone, Debug)]
struct DnsQuestion {
    qname: Vec<String>,
    qtype: u16,
    qclass: u16,
}

struct DnsResourceRecord {
    name: String,
    rrtype: u16,
    class: u16,
    ttl: u32,
}
