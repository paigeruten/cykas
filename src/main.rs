extern crate openssl;
extern crate num;
extern crate libc;
extern crate serialize;

use serialize::hex::{ToHex, FromHex};

use protocol::private_key::PrivateKey;
use protocol::public_key::PublicKey;
use protocol::address::Address;

pub mod protocol;
pub mod util;
//mod wallet_address;
//mod wallet;

#[allow(dead_code)]
fn aes_test() {
    let salt = openssl::crypto::rand::rand_bytes(16u);
    let key = openssl::crypto::pkcs5::pbkdf2_hmac_sha1("asdf", salt.as_slice(), 4000u, 32u);
    let iv = openssl::crypto::rand::rand_bytes(16u);

    let ciphertext = openssl::crypto::symm::encrypt(
        openssl::crypto::symm::AES_256_CBC,
        key.as_slice(),
        iv.clone(),
        [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,57]
    );

    for byte in ciphertext.iter() {
        print!("{} ", *byte);
    }
    println!("");

    let plaintext = openssl::crypto::symm::decrypt(
        openssl::crypto::symm::AES_256_CBC,
        key.as_slice(),
        iv.clone(),
        ciphertext.as_slice()
    );

    for byte in plaintext.iter() {
        print!("{} ", *byte);
    }
    println!("");
}

#[allow(dead_code)]
fn main() {
    let private_key = PrivateKey::generate();
    //let raw_wif = util::base58::decode("5KXHHtBba1Y6eWdxu3nXSxKN8UpW8CWMpCKUa8U51naNQA1Q6q9");
    //let private_key = PrivateKey::from_wif(raw_wif.as_slice()).unwrap();
    let to_wif = private_key.to_wif();
    let public_key = PublicKey::from_private_key(&private_key);
    let address = Address::from_public_key(&public_key);
    println!("priv: {}", private_key.get_data().to_hex());
    println!("pwif: {}", util::base58::encode(to_wif.as_slice()));
    println!("publ: {}", public_key.get_data().to_hex());
    println!("addr: {}", util::base58::encode(address.get_data()));
}

