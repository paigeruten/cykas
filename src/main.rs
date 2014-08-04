extern crate openssl;
extern crate num;
extern crate libc;

mod ecdsa;
mod address;
mod base58;

fn openssl_test() {
    let hash = openssl::crypto::hash::hash(openssl::crypto::hash::RIPEMD160, [0x61, 0x62, 0x63]);

    for byte in hash.iter() {
        print!("{:02x}", *byte);
    }
    println!("");
}

fn bitcoin_address_test() {
    let priv_key = openssl::crypto::rand::rand_bytes(32u);
    let addr = address::Address::new(priv_key);
    println!("{}", addr.to_string());
}

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

fn main() {
    bitcoin_address_test();
    aes_test();
    openssl_test();
}

