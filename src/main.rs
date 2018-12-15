use futures::prelude::*;
use tokio::net::UdpSocket;
use tokio::net::UdpFramed;

#[macro_use]
extern crate log;

mod message;
mod codec;
mod resolver;

use crate::codec::DnsMessageCodec;

fn main() {
    env_logger::init();

    let sock = UdpSocket::bind(&"0.0.0.0:1234".parse().unwrap()).unwrap();
    let (_udp_out, udp_in) = UdpFramed::new(sock, DnsMessageCodec::new()).split();

    tokio::run(udp_in.for_each(|(frame, addr)| {
        info!("Request from {}: {:#?}", addr, frame);
        Ok(())
    }).map_err(|err| {
        println!("{:#?}", err);
    }));
}
