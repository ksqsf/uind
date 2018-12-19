use futures::prelude::*;
use futures::future::{self, Either};
use futures::sync::mpsc;
use tokio::net::{UdpSocket, UdpFramed};
use tokio::net::{TcpStream, TcpListener};
use tokio::codec::Decoder;
use std::collections::HashMap;
use std::net::{SocketAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::env;
use std::fs;
use std::io::{BufRead, BufReader};

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
    let local_entries = config.local;

    let udp_sock = UdpSocket::bind(&"0.0.0.0:53".parse().unwrap()).unwrap();
    let tcp_sock = TcpListener::bind(&"0.0.0.0:53".parse().unwrap()).unwrap();

    let clients: Arc<Mutex<HashMap<u16, SocketAddr>>> = Arc::new(Mutex::new(HashMap::new()));
    let (udp_out, udp_in) = UdpFramed::new(udp_sock, DnsMessageCodec::new(false)).split();
    let (tx, rx) = mpsc::unbounded::<(DnsMessage, SocketAddr)>();

    let udp_sender = rx.fold(udp_out, |udp_out, (message, addr)| {
        udp_out.send((message, addr))
            .map_err(|e| error!("{}", e))
    }).map_err(|e| error!("error in sender: {:?}", e));

    let udp_dispatcher = udp_in
        .map_err(DispatcherError::from)
        .fold(tx, move |tx, (message, addr)| {
            let id = message.header.id;

            if message.is_query() {
                info!("Message {:x} from {} is UDP query", id, addr);
                let fut = tx.send((message, dns_addr)).map_err(DispatcherError::from);
                clients.lock().unwrap().entry(id).and_modify(|e| *e = addr).or_insert(addr);
                Either::A(fut)
            } else {
                info!("Message {:x} from {} is UDP response", id, addr);
                if let Some(client_addr) = clients.lock().unwrap().remove(&id) {
                    Either::A(tx.send((message, client_addr)).map_err(DispatcherError::from))
                } else {
                    Either::B(future::ok(tx))
                }
            }
        }).map_err(|e| error!("error in udp dispatcher: {:?}", e));

    let tcp_dispatcher = tcp_sock.incoming().for_each(move |stream| {
        let client_addr = stream.peer_addr().expect("peer_addr");
        let (sink, stream) = DnsMessageCodec::new(true).framed(stream).split();

        let forwarder = stream
            .inspect(move |message| info!("Message {:x} from {} is TCP query",
                                     message.header.id, client_addr))
            .map_err(|e| error!("error in tcp stream {}", e))
            .fold(sink, move |sink, message| {
                // Connect to DNS server
                TcpStream::connect(&dns_addr)
                    .map(|conn| DnsMessageCodec::new(true).framed(conn))
                    .map_err(|e| error!("error in tcp request {}", e))
                // Send query to DNS server
                    .map(|codec| codec.send(message).map_err(|e| error!("error sending tcp {}", e)))
                    .flatten()
                // Get response
                    .map(|codec| codec.into_future().map_err(|_| error!("error into fut")))
                    .flatten()
                    .then(|result| {
                        match result {
                            Ok((Some(response), _codec)) => {
                                info!("Message {:x} is TCP response", response.header.id);
                                debug!("Response is {:#?}", response);
                                Ok(response)
                            }
                            _ => {
                                error!("can't get response!");
                                Err(())
                            }
                        }
                    })
                // Send to client
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
        let answer = DnsResourceRecord {
            name: domain_name.split(".").map(String::from).collect(),
            rclass: DnsClass::Internet,
            rtype: DnsType::A,
            data: DnsRRData::A(answer),
            ttl: 114514
        };
        let entry = config.local.entry(domain_name.to_string()).or_insert(vec![]);
        (*entry).push(answer);
    }

    if let Err(_) = env::var("RUST_LOG") {
        env::set_var("RUST_LOG", debug);
    }

    env_logger::init();
    info!("Server config loaded!");

    Ok(config)
}

fn from_answer(id: u16, answer: Vec<DnsResourceRecord>) -> DnsMessage {
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
        answer: if refused {vec![]} else {answer},
        ..Default::default()
    }
}

#[derive(Debug, Clone)]
struct ServerConfig {
    dns_addr: SocketAddr,
    local: HashMap<String, Vec<DnsResourceRecord>>,
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
