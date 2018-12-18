use futures::prelude::*;
use tokio::net::{UdpSocket, UdpFramed};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

#[macro_use]
extern crate log;

mod message;
mod codec;

use crate::codec::DnsMessageCodec;

fn main() {
    env_logger::init();

    let sock = UdpSocket::bind(&"0.0.0.0:1234".parse().unwrap()).unwrap();
    let records: Arc<Mutex<HashMap<u16, SocketAddr>>> = Arc::new(Mutex::new(HashMap::new()));
    let (udp_out, udp_in) = UdpFramed::new(sock, DnsMessageCodec::new()).split();
    let mut udp_out = udp_out.wait();

    tokio::run(udp_in.for_each(move |(message, addr)| {
        let id = message.header.id;
        let dnsaddr: SocketAddr = "202.141.178.13:5353".parse().unwrap();

        if message.is_query() {
            debug!("Message {:x} from {} is query", id, addr);
            match udp_out.send((message, dnsaddr)) {
                Ok(_) => debug!("request proxied to dns server"),
                Err(e) => error!("failed to send dgram to server: {}", e)
            }
            let mut records = records.lock().unwrap();
            records.entry(id).and_modify(|e| *e = addr).or_insert(addr);
        } else {
            debug!("Message {:x} from {} is response", id, addr);
            if let Some(client_addr) = records.lock().unwrap().remove(&id) {
                match udp_out.send((message, client_addr)) {
                    Ok(_) => debug!("sent to client {}", client_addr),
                    Err(e) => error!("failed to send dgram to client {}: {}", client_addr, e)
                }
            }
        }

        println!("{:?}", records);

        Ok(())
    }).map_err(|err| {
        println!("{:#?}", err);
    }));
}
