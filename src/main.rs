use failure::Error;
use futures::prelude::*;
use tokio::net::UdpSocket;
use tokio::net::UdpFramed;

mod message;
mod codec;

use crate::codec::DnsMessageCodec;

fn main() -> Result<(), Error> {
    let sock = UdpSocket::bind(&"0.0.0.0:1234".parse().unwrap()).unwrap();
    let frames = UdpFramed::new(sock, DnsMessageCodec::new());

    tokio::run(frames.for_each(|(frame, addr)| {
        println!("Request from {}: {:#?}", addr, frame);
        Ok(())
    }).map_err(|err| {
        println!("{:#?}", err);
    }));

    Ok(())
}
