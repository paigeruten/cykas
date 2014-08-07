extern crate openssl;
extern crate num;
extern crate libc;

use address::Address;

mod ecdsa;
mod private_key;
mod address;
mod base58;

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
    let addr = Address::new_random();
    println!("{}", addr.get_public_address());
}

