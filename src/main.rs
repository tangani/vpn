use std::net::TcpStream;
use std::io::prelude::*;


fn main() {
    let mut stream = TcpStream::connect("127.0.0.1:7878").unwrap();

    let _ = stream.write(b"Hello, server!");

    let mut buffer = [0; 512];
    stream.read(&mut buffer).unwrap();
    println!("Received: {}", String::from_utf8_lossy(&buffer[..]));
}
