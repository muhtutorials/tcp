use crate::{AddrPair, ConnManager, SEND_QU_SIZE};
use std::cmp::min;
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::net::Shutdown;

pub struct TcpStream {
    pub(crate) addr_pair: AddrPair,
    pub(crate) conn_manager: ConnManager,
}

impl TcpStream {
    pub fn shutdown(&self, how: Shutdown) -> Result<()> {
        let mut conn_manager = self.conn_manager.mutex.lock().unwrap();
        let conn = conn_manager.conns.get_mut(&self.addr_pair).ok_or_else(|| {
            Error::new(
                ErrorKind::ConnectionAborted,
                "stream was terminated unexpectedly",
            )
        })?;
        conn.close()
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut conn_manager = self.conn_manager.mutex.lock().unwrap();

        loop {
            let conn = conn_manager.conns.get_mut(&self.addr_pair).ok_or_else(|| {
                Error::new(
                    ErrorKind::ConnectionAborted,
                    "stream was terminated unexpectedly",
                )
            })?;

            if conn.is_received_closed() && conn.data_in.is_empty() {
                // no more data to read and no need to block because there won't
                // any more data
                return Ok(0);
            };

            if !conn.data_in.is_empty() {
                let mut n_bytes = 0;
                let (head, tail) = conn.data_in.as_slices();

                let head_end = min(buf.len(), head.len());
                buf[..head_end].copy_from_slice(&head[..head_end]);
                n_bytes += head_end;

                let tail_end = min(buf.len() - head_end, tail.len());
                buf[head_end..(head_end + tail_end)].copy_from_slice(&tail[..tail_end]);
                n_bytes += tail_end;
                
                drop(conn.data_in.drain(..n_bytes));

                return Ok(n_bytes);
            };

            conn_manager = self.conn_manager.read_notify.wait(conn_manager).unwrap();
        }
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut conn_manager = self.conn_manager.mutex.lock().unwrap();
        let conn = conn_manager.conns.get_mut(&self.addr_pair).ok_or_else(|| {
            Error::new(
                ErrorKind::ConnectionAborted,
                "stream was terminated unexpectedly",
            )
        })?;
        if conn.data_out.len() >= SEND_QU_SIZE {
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
        let mut conn_manager = self.conn_manager.mutex.lock().unwrap();
        let conn = conn_manager.conns.get_mut(&self.addr_pair).ok_or_else(|| {
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
        let mut conn_manager = self.conn_manager.mutex.lock().unwrap();
    }
}
