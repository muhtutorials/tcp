use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};
use nix::poll::{PollFd, PollFlags, poll};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::io::prelude::*;
use std::io::{Error, ErrorKind, Result};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::thread::JoinHandle;
use tun::Device;

mod connection;
use connection::{AvailableIo, Connection};

mod listener;
use listener::TcpListener;

pub mod stream;
pub use stream::TcpStream;

const SEND_QU_SIZE: usize = 1024;

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
struct AddrPair {
    // u16 is a port number
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

// todo: come up with a better naming
#[derive(Default)]
struct ConnManagerInner {
    conns: HashMap<AddrPair, Connection>,
    // Key is a listener's port number.
    // Value is a list of pending to be created connections with the listener.
    pending: HashMap<u16, VecDeque<AddrPair>>,
    shutdown: bool,
}

#[derive(Default)]
struct ConnManagerBlock {
    mutex: Mutex<ConnManagerInner>,
    // notifies about new connection
    conn_notify: Condvar,
    // notifies about available read operation
    read_notify: Condvar,
}

type ConnManager = Arc<ConnManagerBlock>;

pub struct Interface {
    conn_manager: Option<ConnManager>,
    // todo: rename to packet_handle
    handle: Option<JoinHandle<Result<()>>>,
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

        let handle = {
            let conn_manager = conn_manager.clone();
            thread::spawn(move || packet_loop(dev, conn_manager))
        };

        Ok(Interface {
            conn_manager: Some(conn_manager),
            handle: Some(handle),
        })
    }

    pub fn bind(&mut self, port: u16) -> Result<TcpListener> {
        let mut conn_manager = self.conn_manager.as_mut().unwrap().mutex.lock().unwrap();
        match conn_manager.pending.entry(port) {
            Entry::Vacant(entry) => entry.insert(VecDeque::new()),
            Entry::Occupied(_) => {
                return Err(Error::new(ErrorKind::AddrInUse, "port already in use"));
            }
        };
        drop(conn_manager);

        Ok(TcpListener {
            port,
            conn_manager: self.conn_manager.as_mut().unwrap().clone(),
        })
    }
}

impl Drop for Interface {
    fn drop(&mut self) {
        self.conn_manager
            .as_mut()
            .unwrap()
            .mutex
            .lock()
            .unwrap()
            .shutdown = true;
        drop(self.conn_manager.take());
        self.handle
            .take()
            .expect("interface dropped more than once")
            .join()
            .unwrap()
            .unwrap();
    }
}

fn packet_loop(mut dev: Device, cm: ConnManager) -> Result<()> {
    let mut buf = [0u8; 4096];

    loop {
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(dev.as_raw_fd()) };
        let mut fds = [PollFd::new(borrowed_fd, PollFlags::POLLIN)];
        let n = poll(&mut fds[..], 1u8).map_err(|err| Error::new(ErrorKind::Other, err))?;
        if n == 0 {
            let mut conn_manager = cm.mutex.lock().unwrap();
            for conn in conn_manager.conns {
                conn.on_tick(&mut dev)?;
            }
            continue;
        }

        let n_bytes = dev.read(&mut buf)?;

        if let Ok(ip_req_header) = Ipv4HeaderSlice::from_slice(&buf) {
            // checks if it's a TCP
            // https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
            let proto = ip_req_header.protocol();
            if proto.0 != 6 {
                continue;
            }

            let src_addr = ip_req_header.source_addr();
            let dst_addr = ip_req_header.destination_addr();
            let ip_req_header_len = ip_req_header.slice().len();

            if let Ok(tcp_req_header) = TcpHeaderSlice::from_slice(&buf[ip_req_header_len..n_bytes])
            {
                let mut conn_manager_mg = cm.mutex.lock().unwrap();
                // extracts conn_manager from mutex to make borrow checker see
                // that conn_manager.conns and conn_manager.pending are different "objects"
                let conn_manager = &mut *conn_manager_mg;
                let addr_pair = AddrPair {
                    src: (src_addr, tcp_req_header.source_port()),
                    dst: (dst_addr, tcp_req_header.destination_port()),
                };
                let data_idx = ip_req_header_len + tcp_req_header.slice().len();

                match conn_manager.conns.entry(addr_pair) {
                    Entry::Occupied(mut entry) => {
                        let aio = entry.get_mut().on_packet(
                            &mut dev,
                            ip_req_header,
                            tcp_req_header,
                            &buf[data_idx..n_bytes],
                        )?;

                        drop(conn_manager_mg);

                        if aio.contains(AvailableIo::READ) {
                            cm.read_notify.notify_all();
                        }

                        if aio.contains(AvailableIo::WRITE) {
                            cm.read_notify.notify_all();
                        }
                    }
                    Entry::Vacant(entry) => {
                        if let Some(pending) = conn_manager
                            .pending
                            .get_mut(&tcp_req_header.destination_port())
                        {
                            if let Some(conn) =
                                Connection::accept(&mut dev, ip_req_header, tcp_req_header)?
                            {
                                entry.insert(conn);
                                // todo: find out why the method can take by value
                                pending.push_back(addr_pair);
                                // release the lock so after waking up it's available
                                drop(conn_manager_mg);
                                cm.conn_notify.notify_all();
                            }
                        }
                    }
                }
            }
        }
    }
}
