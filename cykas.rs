extern crate num;
extern crate libc;

use bitcoin::address_from_private_key;

mod crypto;
mod bitcoin;

fn bitcoin_address_test() {
    let priv_key = crypto::rand::rand_bytes(32u);
    let address = address_from_private_key(priv_key.as_slice());

    for byte in priv_key.iter() {
        print!("{:02x}", *byte);
    }
    println!("");
    
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
    bitcoin_address_test();
}

