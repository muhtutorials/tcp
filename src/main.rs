use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::error::Error;
use std::io::Read;
use std::net::Ipv4Addr;
use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};

mod connection;

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
struct Quad {
    // u16 is a port number
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

fn main() -> Result<(), Box<dyn Error>>  {
    let mut config = tun::Configuration::default();
    config
        .address((10, 0, 0, 9))
        .netmask((255, 255, 255, 0))
        .destination((10, 0, 0, 1))
        .up();
    let mut dev = tun::create(&config)?;

    let mut buf = [0u8; 4096];

    let mut conns: HashMap<Quad, connection::Connection> = HashMap::new();

    loop {
        let n_bytes = dev.read(&mut buf)?;

        if let Ok(ip_req_header) = Ipv4HeaderSlice::from_slice(&buf) {
            // checks if it's a TCP
            // https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
            let proto = ip_req_header.protocol();
            if proto.0 != 6 {
                continue
            }

            let src_addr = ip_req_header.source_addr();
            let dst_addr = ip_req_header.destination_addr();
            let ip_req_header_len = ip_req_header.slice().len();

            if let Ok(tcp_req_header) = TcpHeaderSlice::from_slice(&buf[ip_req_header_len..n_bytes]) {
                let data_idx = ip_req_header_len + tcp_req_header.slice().len();
                match conns.entry(Quad {
                    src: (src_addr, tcp_req_header.source_port()),
                    dst: (dst_addr, tcp_req_header.destination_port())
                }) {
                    Entry::Occupied(mut entry) => {
                        entry.get_mut().on_packet(&mut dev, ip_req_header, tcp_req_header, &buf[data_idx..n_bytes])?;
                    },
                    Entry::Vacant(entry) => {
                        if let Some(conn) = connection::Connection::accept(&mut dev, ip_req_header, tcp_req_header)? {
                            entry.insert(conn);
                        }
                    }
                }
            }
        }
    }
}