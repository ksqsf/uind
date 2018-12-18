use futures::prelude::*;
use futures::future::{self, Either};
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

    let sock = UdpSocket::bind(&"0.0.0.0:53".parse().unwrap()).unwrap();
    let records: Arc<Mutex<HashMap<u16, SocketAddr>>> = Arc::new(Mutex::new(HashMap::new()));
    let (udp_out, udp_in) = UdpFramed::new(sock, DnsMessageCodec::new()).split();
    let (tx, rx) = mpsc::unbounded::<(DnsMessage, SocketAddr)>();

    let sender = rx.fold(udp_out, |udp_out, (message, addr)| {
        udp_out.send((message, addr))
            .map_err(|e| error!("{}", e))
    }).map_err(|e| error!("error in sender: {:?}", e));

    let dispatcher = udp_in
        .map_err(DispatcherError::from)
        .fold(tx, move |tx, (message, addr)| {
            let id = message.header.id;
            let dnsaddr: SocketAddr = "202.141.178.13:5353".parse().unwrap();

            if message.is_query() {
                debug!("Message {:x} from {} is query", id, addr);
                let fut = tx.send((message, dnsaddr)).map_err(DispatcherError::from);
                records.lock().unwrap().entry(id).and_modify(|e| *e = addr).or_insert(addr);
                Either::A(fut)
            } else {
                debug!("Message {:x} from {} is response", id, addr);
                if let Some(client_addr) = records.lock().unwrap().remove(&id) {
                    Either::A(tx.send((message, client_addr)).map_err(DispatcherError::from))
                } else {
                    Either::B(future::ok(tx))
                }
            }
        }).map_err(|e| error!("error in dispatcher: {:?}", e));

    tokio::run(sender.join(dispatcher).map(|_| ()));
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
