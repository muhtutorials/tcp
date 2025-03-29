use std::cmp::min;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::io::prelude::*;
use std::io::{Error, ErrorKind, Result};
use std::net::{Ipv4Addr, Shutdown};
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};
use tun::Device;

mod connection;

const SEND_QU_SIZE: usize = 1024;

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
struct Quad {
    // u16 is a port number
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

#[derive(Default)]
struct ConnManagerInner {
    conns: HashMap<Quad, connection::Connection>,
    pending: HashMap<u16, VecDeque<Quad>>,
}

type ConnManager = Arc<Mutex<ConnManagerInner>>;

pub struct Interface {
    conn_manager: ConnManager,
    jh: JoinHandle<Result<()>>,
}

impl Interface {
    pub fn new() -> Result<Self> {
        let mut config = tun::Configuration::default();
        config
            .address((10, 0, 0, 9))
            .netmask((255, 255, 255, 0))
            .destination((10, 0, 0, 1))
            .up();
        let dev = tun::create(&config)?;

        let conn_manager: ConnManager = Default::default();

        let jh = {
            let conn_manager = conn_manager.clone();
            thread::spawn(move || packet_loop(dev, conn_manager))
        };

        Ok(Interface { conn_manager, jh })
    }

    pub fn bind(&mut self, port: u16) -> Result<TcpListener> {
        let mut conn_manager = self.conn_manager.lock().unwrap();
        match conn_manager.pending.entry(port) {
            Entry::Vacant(ve) => ve.insert(VecDeque::new()),
            Entry::Occupied(_) => {
                return Err(Error::new(ErrorKind::AddrInUse, "port is already in use"));
            }
        };
        drop(conn_manager);

        Ok(TcpListener {
            port,
            conn_manager: self.conn_manager.clone(),
        })
    }
}

impl Drop for Interface {
    fn drop(&mut self) {
    }
}

pub struct TcpListener {
    port: u16,
    conn_manager: ConnManager,
}

impl TcpListener {
    pub fn accept(&mut self) -> Result<TcpStream> {
        let mut conn_manager = self.conn_manager.lock().unwrap();
        if let Some(quad) = conn_manager
            .pending
            .get_mut(&self.port)
            .expect("port closed while listener still active")
            .pop_front()
        {
            Ok(TcpStream {
                quad,
                conn_manager: self.conn_manager.clone(),
            })
        } else {
            Err(Error::new(ErrorKind::WouldBlock, "no connection available"))
        }
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut conn_manager = self.conn_manager.lock().unwrap();
        conn_manager
            .pending
            .remove(&self.port)
            .expect("port closed while listener still active");

    }
}

pub struct TcpStream {
    quad: Quad,
    conn_manager: ConnManager,
}

impl TcpStream {
    pub fn shutdown(&self, how: Shutdown) -> Result<()> {
        Ok(())
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut conn_manager = self.conn_manager.lock().unwrap();
        let conn = conn_manager.conns.get_mut(&self.quad).ok_or_else(|| {
            Error::new(
                ErrorKind::ConnectionAborted,
                "stream was terminated unexpectedly",
            )
        })?;
        if conn.data_in.is_empty() {
            // todo: block
            return Err(Error::new(ErrorKind::WouldBlock, "no bytes to read"));
        };

        let mut n_bytes = 0;
        let (head, tail) = conn.data_in.as_slices();
        let head_read = min(buf.len(), head.len());
        buf.copy_from_slice(&head[..head_read]);
        n_bytes += head_read;
        let tail_read = min(buf.len() - head_read, tail.len());
        buf.copy_from_slice(&head[..tail_read]);
        n_bytes += tail_read;
        drop(conn.data_in.drain(..n_bytes));

        Ok(n_bytes)
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut conn_manager = self.conn_manager.lock().unwrap();
        let conn = conn_manager.conns.get_mut(&self.quad).ok_or_else(|| {
            Error::new(
                ErrorKind::ConnectionAborted,
                "stream was terminated unexpectedly",
            )
        })?;
        if conn.data_out.len() >= SEND_QU_SIZE {
            // todo: block
            return Err(Error::new(ErrorKind::WouldBlock, "too many bytes buffered"));
        }

        if conn.data_out.is_empty() {
            return Err(Error::new(ErrorKind::WouldBlock, "no bytes to read"));
        };

        let n_bytes = min(buf.len(), SEND_QU_SIZE - conn.data_out.len());
        conn.data_out.extend(&buf[..n_bytes]);

        Ok(n_bytes)
    }

    fn flush(&mut self) -> Result<()> {
        let mut conn_manager = self.conn_manager.lock().unwrap();
        let conn = conn_manager.conns.get_mut(&self.quad).ok_or_else(|| {
            Error::new(
                ErrorKind::ConnectionAborted,
                "stream was terminated unexpectedly",
            )
        })?;

        if conn.data_out.is_empty() {
            return Ok(());
        };

        Err(Error::new(ErrorKind::WouldBlock, "too many bytes buffered"))
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
    }
}

fn packet_loop(mut dev: Device, cm: ConnManager) -> Result<()> {
    let mut buf = [0u8; 4096];

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
                let mut conn_manager = cm.lock().unwrap();
                let mut conn_manager = &mut *conn_manager;
                let quad = Quad {
                    src: (src_addr, tcp_req_header.source_port()),
                    dst: (dst_addr, tcp_req_header.destination_port())
                };
                let data_idx = ip_req_header_len + tcp_req_header.slice().len();

                match conn_manager.conns.entry(quad) {
                    Entry::Occupied(mut entry) => {
                        entry.get_mut().on_packet(&mut dev, ip_req_header, tcp_req_header, &buf[data_idx..n_bytes])?;
                    },
                    Entry::Vacant(entry) => {
                        if let Some(pending) = conn_manager.pending.get_mut(&tcp_req_header.destination_port()) {
                            if let Some(conn) = connection::Connection::accept(&mut dev, ip_req_header, tcp_req_header)? {
                                entry.insert(conn);
                                // todo: find out why the method can take by value
                                pending.push_back(quad);
                            }
                        }
                    }
                }
            }
        }
    }
}
