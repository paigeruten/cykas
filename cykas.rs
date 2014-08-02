extern crate num;
extern crate libc;

mod crypto;
mod address;
mod base58;

fn bitcoin_address_test() {
    let priv_key = crypto::rand::rand_bytes(32u);
    let addr = address::Address::new(priv_key);
    println!("{}", addr.to_string());
}

fn aes_test() {
    let salt = crypto::rand::rand_bytes(16u);
    let key = crypto::pkcs5::pbkdf2_hmac_sha1("jer14ea", salt.as_slice(), 4000u, 32u);
    let iv = crypto::rand::rand_bytes(16u);

    let ciphertext = crypto::aes::aes256cbc(
        crypto::aes::Encrypt,
        key.as_slice(),
        iv.as_slice(),
        [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,57]
    );

    for byte in ciphertext.iter() {
        print!("{} ", *byte);
    }
    println!("");

    let plaintext = crypto::aes::aes256cbc(
        crypto::aes::Decrypt,
        key.as_slice(),
        iv.as_slice(),
        ciphertext.as_slice()
    );

    for byte in plaintext.iter() {
        print!("{} ", *byte);
    }
    println!("");
}

fn main() {
    bitcoin_address_test();
    aes_test();
}

