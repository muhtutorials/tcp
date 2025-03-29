use std::io::Result;
use std::thread;

fn main() -> Result<()> {
    let mut iface = tcp::Interface::new()?;
    let mut listener_1 = iface.bind(9000)?;
    let mut listener_2 = iface.bind(9001)?;

    let jh1 = thread::spawn(move || {
        while let Ok(_stream) = listener_1.accept() {
            println!("got connection on 9000");
        }
    });

    let jh2 = thread::spawn(move || {
        while let Ok(_stream) = listener_2.accept() {
            println!("got connection on 9001");
        }
    });

    jh1.join().unwrap();
    jh2.join().unwrap();

    Ok(())
}