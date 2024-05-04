// extern crate tokio;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};

async fn handle_client(mut stream: TcpStream) {
    // Read the data from the client and 
    // return the data to the client.

    let mut buffer = [0; 512];
    stream.read(&mut buffer).await.unwrap();
    println!("Received: {}", String::from_utf8_lossy(&buffer[..]));


    stream.write(b"Hello, client!").await.unwrap();
    stream.flush().await.unwrap();
}

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:7878").await.unwrap();

    loop {
        let (stream, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            handle_client(stream).await;
        });
    }
}