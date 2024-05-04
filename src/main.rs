extern crate crypto;
extern crate rand;
extern crate x25519_dalek;

use aes::KeySize::KeySize256;
use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
use rand::Rng;
// use rand_core::{RngCore, OsRng};
use secp256k1::{SecretKey, Secp256k1, PublicKey};
use std::net::TcpStream;
use std::io::prelude::*;
// use x25519_dalek::{PublicKey, StaticSecret};


fn generate_iv_key(size: usize) -> Vec<u8> {
    // Generate Initialization Vector
    // Generate Encryption Key
    let mut rng = rand::thread_rng();
    match size {
        32 => (0..32).map(|_| rng.gen()).collect(),
        16 => (0..16).map(|_| rng.gen()).collect(),
        _ => panic!("Invalid size"),
    }
}

// Encrypt a buffer with the given key and iv using
// AES-256/CBC/Pkcs encryption.
fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    
    let mut encryptor = aes::cbc_encryptor(
        KeySize256,
        key,
        iv,
        blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;

        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}

fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::cbc_decryptor(
            aes::KeySize::KeySize256,
            key,
            iv,
            blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}

// Key exchange protocols using the Diffie-Hellman Key Exchange using using the x25519-dalek crate.
// fn compute_shared_secret(local_secret: &SecretKey, remote_public: &PublicKey) -> [u8; 32] {
//     local_secret.diffie_hellman(remote_public).to_bytes()
// }


fn generate_keypair() -> (PublicKey, SecretKey){
    // let secret = StaticSecret::new(&mut OsRng);
    // let public = PublicKey::from(&secret);
    // (public, secret)

    // let mut key = [0u8; 16];
    // OsRng.fill_bytes(&mut key);
    // let random_u64 = OsRng.next_u64();

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    (public_key, secret_key)
}


fn main() {

    let encryption_key: Vec<u8> = generate_iv_key(32);
    let initializatiuon_vector: Vec<u8> = generate_iv_key(16);

    println!("{:?}", encryption_key);
    println!("{:?}", initializatiuon_vector);

    let mut stream = TcpStream::connect("127.0.0.1:7878").unwrap();

    let message = "Hellow world!";
    let data = stream.write(message.as_bytes());
    let encrypted_data = encrypt(message.as_bytes(), &encryption_key, &initializatiuon_vector).unwrap();

    // let data = stream.write(b"Hello, server!");
    let keypair = generate_keypair();
    println!("Public key: {:?}", keypair.0);
    println!("Secret key: {:?}", keypair.1);

    println!("Data to be sent across: {:?}", data);

    let mut buffer = [0; 512];
    stream.read(&mut buffer).unwrap();
    println!("Client received: {}", String::from_utf8_lossy(&buffer[..]));
}
