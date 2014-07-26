extern crate num;
extern crate libc;

mod crypto;
mod address;
mod base58;

fn bitcoin_address_test() {
    //let priv_key = vec!(0xffu8,0xff,0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff);
    let priv_key = vec!(0u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1);
    let addr = address::Address::new(priv_key);
    println!("{}", addr.to_string());
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

