use futures::prelude::*;
use futures::future::{self, Either};
use futures::sync::mpsc;
use tokio::net::{UdpSocket, UdpFramed};
use tokio::net::{TcpStream, TcpListener};
use tokio::codec::Decoder;
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
            let dnsaddr: SocketAddr = "202.141.178.13:53".parse().unwrap();

            if message.is_query() {
                debug!("Message {:x} from {} is query", id, addr);
                let fut = tx.send((message, dnsaddr)).map_err(DispatcherError::from);
                clients.lock().unwrap().entry(id).and_modify(|e| *e = addr).or_insert(addr);
                Either::A(fut)
            } else {
                debug!("Message {:x} from {} is response", id, addr);
                if let Some(client_addr) = clients.lock().unwrap().remove(&id) {
                    Either::A(tx.send((message, client_addr)).map_err(DispatcherError::from))
                } else {
                    Either::B(future::ok(tx))
                }
            }
        }).map_err(|e| error!("error in udp dispatcher: {:?}", e));

    let tcp_dispatcher = tcp_sock.incoming().for_each(|stream| {
        let (sink, stream) = DnsMessageCodec::new(true).framed(stream).split();
        let dnsaddr: SocketAddr = "202.141.178.13:53".parse().unwrap();

        let forwarder = stream
            .map_err(|e| error!("error in tcp stream {}", e))
            .fold(sink, move |sink, message| {
                // Connect to DNS server
                TcpStream::connect(&dnsaddr)
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
                                debug!("get response {:#?}", response);
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
