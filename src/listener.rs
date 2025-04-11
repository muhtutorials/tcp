use crate::{ConnManager, TcpStream};
use std::io::Result;

pub struct TcpListener {
    pub(crate) port: u16,
    pub(crate) conn_manager: ConnManager,
}

impl TcpListener {
    pub fn accept(&mut self) -> Result<TcpStream> {
        let mut conn_manager = self.conn_manager.mutex.lock().unwrap();
        loop {
            if let Some(addr_pair) = conn_manager
                .pending
                .get_mut(&self.port)
                .expect("port closed while listener still active")
                .pop_front()
            {
                return Ok(TcpStream {
                    addr_pair,
                    conn_manager: self.conn_manager.clone(),
                });
            }
            conn_manager = self.conn_manager.conn_notify.wait(conn_manager).unwrap();
        }
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut conn_manager = self.conn_manager.mutex.lock().unwrap();
        let pending = conn_manager
            .pending
            .remove(&self.port)
            .expect("port closed while listener is still active");
        for addr_pair in pending {
            unimplemented!()
        }
    }
}
