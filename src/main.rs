use futures::prelude::*;
use futures::future;
use futures::sync::mpsc;
use tokio::net::{UdpSocket, UdpFramed};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

#[macro_use]
extern crate log;

mod message;
mod codec;

use crate::message::DnsMessage;
use crate::codec::DnsMessageCodec;

fn main() {
    env_logger::init();

    let sock = UdpSocket::bind(&"0.0.0.0:1234".parse().unwrap()).unwrap();
    let records: Arc<Mutex<HashMap<u16, SocketAddr>>> = Arc::new(Mutex::new(HashMap::new()));
    let (udp_out, udp_in) = UdpFramed::new(sock, DnsMessageCodec::new()).split();
    let (tx, rx) = mpsc::unbounded::<(DnsMessage, SocketAddr)>();
    let mut tx = tx.wait();

    let sender = rx.fold(udp_out, |udp_out, msg| {
        udp_out.send(msg)
            .map_err(|e| error!("{}", e))
    }).map_err(|e| error!("error in sender: {:?}", e));

    let dispatcher = udp_in.for_each(move |(message, addr)| {
        let id = message.header.id;
        let dnsaddr: SocketAddr = "202.141.178.13:5353".parse().unwrap();

        if message.is_query() {
            debug!("Message {:x} from {} is query", id, addr);
            tx.send((message, dnsaddr));
            records.lock().unwrap().entry(id).and_modify(|e| *e = addr).or_insert(addr);
        } else {
            debug!("Message {:x} from {} is response", id, addr);
            if let Some(client_addr) = records.lock().unwrap().remove(&id) {
                tx.send((message, client_addr));
            }
        }

        Ok(())
    }).map_err(|e| error!("error in dispatcher: {}", e));

    tokio::run(sender.join(dispatcher).map(|_| ()));
}
