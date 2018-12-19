#![feature(drain_filter)]
#![feature(slice_concat_ext)]

use futures::prelude::*;
use futures::future::{self, Either};
use futures::sync::mpsc;
use tokio::prelude::*;
use tokio::net::{UdpSocket, UdpFramed};
use tokio::net::{TcpStream, TcpListener};
use tokio::codec::Decoder;
use std::collections::HashMap;
use std::net::{SocketAddr, Ipv4Addr, IpAddr};
use std::sync::{Arc, Mutex};
use std::env;
use std::fs;
use std::io::{BufRead, BufReader};
use std::time::Duration;
use ttl_cache::TtlCache;

#[macro_use]
extern crate log;

mod message;
mod codec;

use crate::message::*;
use crate::codec::DnsMessageCodec;

fn main() {
    let config = match init() {
        Ok(conf) => conf,
        Err(e) => {
            println!("{}", e);
            return
        }
    };
    debug!("Using config: {:#?}", config);
    let dns_addr = config.dns_addr;
    let local_entries_udp = config.local;
    let local_entries_tcp = local_entries_udp.clone();

    let udp_sock = UdpSocket::bind(&"0.0.0.0:53".parse().unwrap()).unwrap();
    let tcp_sock = TcpListener::bind(&"0.0.0.0:53".parse().unwrap()).unwrap();
    let (udp_out, udp_in) = UdpFramed::new(udp_sock, DnsMessageCodec::new(false)).split();
    let (tx, rx) = mpsc::unbounded::<(DnsMessage, SocketAddr)>();

    let clients: Arc<Mutex<TtlCache<u16, (SocketAddr, Vec<DnsResourceRecord>)>>> = Arc::new(Mutex::new(TtlCache::new(100000)));
    let ttl = Duration::from_secs(2);

    let udp_sender = rx.fold(udp_out, |udp_out, (message, addr)| {
        udp_out.send((message, addr))
            .map_err(|e| error!("{}", e))
    }).map_err(|e| error!("error in sender: {:?}", e));

    let udp_dispatcher = udp_in
        .map_err(DispatcherError::from)
        .fold(tx, move |tx, (mut message, addr)| {
            let id = message.header.id;

            if message.is_query() {
                info!("Message {:x} from {} is UDP query", id, addr);
                debug!("Message is {:#?}", message);

                // Filter out questions of type A which have local entries
                let answers_local = filter_questions(&mut message.question, &local_entries_udp);
                debug!("After filtration: {:#?}", message);

                // If no question raised, the server won't reply, let's construct a reply
                let message = if message.question.len() == 0 {from_answer(id, &answers_local)} else {message};
                let dest = if message.question.len() == 0 {addr} else {dns_addr};

                // Send packets
                let fut = tx.send((message.clone(), dest)).map_err(DispatcherError::from);
                debug!("UDP send to {} {:?}", dest, message);
                if message.question.len() > 0 {
                    clients.lock().unwrap().insert(id, (addr, answers_local), ttl);
                }
                Either::A(fut)
            } else {
                info!("Message {:x} from {} is UDP response", id, addr);
                if let Some((client_addr, answers_local)) = clients.lock().unwrap().remove(&id) {
                    message.answer.extend(answers_local);
                    report_answers(&message);
                    debug!("Message is {:#?}, sending to {}", message, client_addr);
                    Either::A(tx.send((message, client_addr)).map_err(DispatcherError::from))
                } else {
                    Either::B(future::ok(tx))
                }
            }
        }).map_err(|e| error!("error in udp dispatcher: {:?}", e));

    let tcp_dispatcher = tcp_sock.incoming().for_each(move |stream| {
        let local_entries = local_entries_tcp.clone();
        let client_addr = stream.peer_addr().expect("peer_addr");
        let (sink, stream) = DnsMessageCodec::new(true).framed(stream).split();

        let forwarder = stream
            .inspect(move |message| info!("Message {:x} from {} is TCP query",
                                          message.header.id, client_addr))
            .map_err(|e| error!("error in tcp stream {}", e))
            .fold(sink, move |sink, mut message| {
                let local_entries = local_entries.clone();

                // Connect to DNS server
                TcpStream::connect(&dns_addr)
                    .map(|conn| DnsMessageCodec::new(true).framed(conn))
                    .map_err(|e| error!("error in tcp request {}", e))
                // Send query to DNS server
                    .map(move |codec| {
                        let id = message.header.id;
                        let local_answers = filter_questions(&mut message.question, &local_entries);
                        if message.question.len() > 0 {
                            Either::A(codec.send(message).map_err(|e| error!("error sending tcp {}", e))
                                      .map(move |codec| (id, codec, local_answers, true)))
                        } else {
                            Either::B(future::ok((id, codec, local_answers, false)))
                        }
                    })
                    .flatten()
                // Get response
                    .map(|(id, codec, local_answers, requested)| {
                        if requested {
                            Either::A(codec.into_future().map_err(|e| error!("error into fut {:?}", e))
                                      .timeout(Duration::from_secs(2)).map_err(|_| error!("tcp timeout"))
                                      .map(move |(resp, _codec)| (resp, local_answers)))
                        } else {
                            Either::B(future::ok((Some(from_answer(id, &local_answers)), vec![])))
                        }
                    })
                    .flatten()
                    .then(|result| {
                        match result {
                            Ok((Some(mut response), local_answers)) => {
                                info!("Message {:x} is TCP response", response.header.id);
                                debug!("Response is {:#?}", response);
                                response.answer.extend(local_answers);
                                Ok(response)
                            }
                            _ => {
                                error!("can't get response!");
                                Err(())
                            }
                        }
                    })
                // Send to client
                    .inspect(|message| report_answers(message))
                    .map(|message| sink.send(message).map_err(|e| error!("{}", e)))
                    .flatten()
                // Done!
            }).map(|_| ());
        tokio::spawn(forwarder);

        future::ok(())
    }).map_err(|e| error!("error in tcp dispatcher: {:?}", e));

    let udp = udp_sender.join(udp_dispatcher).map(|_| ());
    tokio::run(udp.join(tcp_dispatcher).map(|_| ()));
}

fn init() -> Result<ServerConfig, String> {
    let mut config: ServerConfig = Default::default();
    let args: Vec<_> = env::args().collect();
    let mut dns_addr = String::from("202.141.178.13:53");
    let mut conf_file = String::from("dnsrelay.txt");
    let mut debug = "";

    if 1 < args.len() && args[1].starts_with("-d") {
        if args[1] == "-d" {
            debug = "uind=info";
        } else if args[1] == "-dd" {
            debug = "uind=debug";
        } else {
            return Err(format!("Unknown option {}", args[0]));
        }
        if 2 < args.len() {
            dns_addr = args[2].clone();
        }
        if 3 < args.len() {
            conf_file = args[3].clone();
        }
    } else {
        if 1 < args.len() {
            dns_addr = args[1].clone();
        }
        if 2 < args.len() {
            conf_file = args[2].clone();
        }
    }

    config.dns_addr = dns_addr.parse().map_err(|_| format!("Error parsing DNS server address {}", dns_addr))?;

    let file = fs::File::open(conf_file).map_err(|e| format!("Error opening config file: {}", e))?;
    let reader = BufReader::new(file);
    for (lineno, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("Error reading line {}", e))?;

        if line.trim_start().starts_with("#") {
            continue
        }

        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() != 2 {
            if parts.len() != 0 {
                warn!("Line {} is malformed, ignoring", lineno+1);
            }
            continue
        }
        let (domain_name, answer) = (parts[0], parts[1]);
        let answer = answer.parse().map_err(|_| format!("Can't parse IP address at line {}", lineno+1))?;
        let domain_name: Vec<_> = domain_name.split(".").map(String::from).collect();
        let answer = DnsResourceRecord {
            name: domain_name.clone(),
            rclass: DnsClass::Internet,
            rtype: DnsType::A,
            data: DnsRRData::A(answer),
            ttl: 10
        };
        let entry = config.local.entry(domain_name).or_insert(vec![]);
        (*entry).push(answer);
    }

    if let Err(_) = env::var("RUST_LOG") {
        env::set_var("RUST_LOG", debug);
    }

    env_logger::init();
    info!("Server config loaded!");

    Ok(config)
}

fn report_answers(message: &DnsMessage) {
    let report: Vec<_> = message.answer.iter()
        .filter(|x| match x.data { DnsRRData::A(_) | DnsRRData::AAAA(_) => true, _ => false })
        .map(|x| (&x.name, match x.data {
            DnsRRData::A(ip4) => IpAddr::V4(ip4),
            DnsRRData::AAAA(ip6) => IpAddr::V6(ip6),
            _ => unreachable!()
        }))
        .collect();
    for (name, ip) in report {
        println!("{:x}: {}: {}", message.header.id, name.join("."), ip)
    }
}

fn from_answer(id: u16, answer: &Vec<DnsResourceRecord>) -> DnsMessage {
    let refused = answer.iter().fold(false, |refused, x| refused || match x.data {
        DnsRRData::A(x) => x == Ipv4Addr::new(0, 0, 0, 0),
        _ => false
    });
    DnsMessage {
        header: DnsHeader {
            id: id,
            authoritative: false,
            query: false,
            opcode: DnsOpcode::Query,
            truncated: false,
            recur_available: false,
            recur_desired: true,
            rcode: if refused {DnsRcode::Refused} else {DnsRcode::NoErrorCondition},
        },
        answer: if refused {vec![]} else {answer.clone()},
        ..Default::default()
    }
}

fn filter_questions(questions: &mut Vec<DnsQuestion>, local_entries: &EntryTable) -> Vec<DnsResourceRecord> {
    questions.drain_filter(|x| local_entries.contains_key(&x.qname) && x.qtype == DnsType::A)
        .map(|q| local_entries[&q.qname].clone())
        .flatten()
        .collect()
}

type EntryTable = HashMap<DomainName, Vec<DnsResourceRecord>>;

#[derive(Debug, Clone)]
struct ServerConfig {
    dns_addr: SocketAddr,
    local: EntryTable,
}

impl Default for ServerConfig {
    fn default() -> ServerConfig {
        ServerConfig {
            dns_addr: "202.141.178.13:53".parse().unwrap(),
            local: HashMap::new(),
        }
    }
}

#[derive(Debug)]
enum DispatcherError<T> {
    ChannelError(mpsc::SendError<T>),
    NetworkError(std::io::Error)
}

impl<T> From<mpsc::SendError<T>> for DispatcherError<T> {
    fn from(e: mpsc::SendError<T>) -> Self {
        DispatcherError::ChannelError(e)
    }
}

impl<T> From<std::io::Error> for DispatcherError<T> {
    fn from(e: std::io::Error) -> Self {
        DispatcherError::NetworkError(e)
    }
}
