use std::io::{Read, Result};
use std::thread;
use tcp::Interface;

fn main() -> Result<()> {
    let mut iface = Interface::new()?;
    let mut lis = iface.bind(8000)?;

    let handle = thread::spawn(move || {
        while let Ok(mut stream) = lis.accept() {
            println!("got connection on 8000");
            let n = stream.read(&mut []).unwrap();
        }
    });

    handle.join().unwrap();

    Ok(())
}