use std::io::{Read, Result};
use std::net::Shutdown;
use std::thread;
use tcp::Interface;

fn main() -> Result<()> {
    let mut iface = Interface::new()?;
    let mut lis = iface.bind(8000)?;

    let handle = thread::spawn(move || {
        while let Ok(mut stream) = lis.accept() {
            stream.shutdown(Shutdown::Write).unwrap();
            loop {
                let mut buf = [0; 512];
                println!("got connection on 8000");
                let n = stream.read(&mut buf[..]).unwrap();
                if n == 0 {
                    println!("no more data");
                    break;
                }
                println!("{n} bytes of data read");
                println!("{:?}", &buf[..n]);
            }
        }
    });

    handle.join().unwrap();

    Ok(())
}
