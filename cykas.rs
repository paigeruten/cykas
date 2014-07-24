extern crate num;
extern crate libc;

use bitcoin::address_from_private_key;

mod crypto;
mod bitcoin;

fn bitcoin_address_test() {
    let priv_key = [0x18, 0xE1, 0x4A, 0x7B, 0x6A, 0x30, 0x7F, 0x42, 0x6A, 0x94, 0xF8, 0x11, 0x47, 0x01, 0xE7, 0xC8, 0xE7, 0x74, 0xE7, 0xF9, 0xA4, 0x7E, 0x2C, 0x20, 0x35, 0xDB, 0x29, 0xA2, 0x06, 0x32, 0x17, 0x25];
    let address = address_from_private_key(priv_key);
    
    println!("{}", address);
}

fn aes_test() {
    let ciphertext = crypto::aes::aes256cbc(
        crypto::aes::Encrypt,
        [1,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1],
        vec!(1,2,3,4,5,6,7,8,9,0,1,2,3,4,5),
        [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53]
    );

    for byte in ciphertext.iter() {
        print!("{} ", *byte);
    }
    println!("");

    let plaintext = crypto::aes::aes256cbc(
        crypto::aes::Decrypt,
        [1,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1],
        vec!(1,2,3,4,5,6,7,8,9,0,1,2,3,4,5),
        ciphertext.as_slice()
    );

    for byte in plaintext.iter() {
        print!("{} ", *byte);
    }
    println!("");
}

fn main() {
    aes_test();
}

