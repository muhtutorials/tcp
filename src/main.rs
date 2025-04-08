use std::io::{Read, Result, Write};
use std::net::Shutdown;
use std::thread;
use tcp::Interface;

fn main() -> Result<()> {
    let mut iface = Interface::new()?;
    let mut listener = iface.bind(8000)?;

    while let Ok(mut stream) = listener.accept() {
        println!("got connection");
        thread::spawn(move || {
            stream.write(b"hi").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
            loop {
                let mut buf = [0; 512];
                let n = stream.read(&mut buf[..]).unwrap();
                if n == 0 {
                    println!("no more data");
                    break;
                }
                println!("{n} bytes of data read");
                println!("{:?}", &buf[..n]);
            }
        });
    }

    Ok(())
}
