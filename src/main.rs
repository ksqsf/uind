extern crate tokio;
extern crate failure;
extern crate futures;

use failure::Error;
use futures::prelude::*;
use tokio::codec::BytesCodec;
use tokio::net::UdpSocket;
use tokio::net::UdpFramed;

mod message;

fn main() -> Result<(), Error> {
    let sock = UdpSocket::bind(&"0.0.0.0:1234".parse().unwrap()).unwrap();
    let frames = UdpFramed::new(sock, BytesCodec::new());

    tokio::run(frames.for_each(|(frame, addr)| {
        println!("{:?} from {}", frame, addr);
        Ok(())
    }).map_err(|err| {
        println!("{:?}", err);
    }));

    Ok(())
}
