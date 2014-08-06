// Need openssl for hashing, getting secure random numbers, and AES encryption.
// (Elliptic curve stuff we have to do ourself.)
extern crate openssl;

// Provides bigint types, used for base58 conversion.
extern crate num;

// Lets us talk to openssl who is written in C.
extern crate libc;

mod ecdsa;
mod address;
mod base58;

#[allow(dead_code)]
fn openssl_test() {
    let hash = openssl::crypto::hash::hash(openssl::crypto::hash::RIPEMD160, [0x61, 0x62, 0x63]);

    for byte in hash.iter() {
        print!("{:02x}", *byte);
    }
    println!("");
}

#[allow(dead_code)]
fn bitcoin_address_test() {
    let priv_key = [0x2f,0x11,0xa3,0xb7,0xa3,0x40,0x38,0x16,0x60,0x3c,0xa2,0x97,0xdf,0xc0,0xc3,0x45,0x0a,0xa1,0x1f,0x45,0x55,0xb0,0xca,0x2a,0xfd,0xa6,0x9f,0xf7,0x1d,0x04,0x82,0x37];
    //priv_key = openssl::crypto::rand::rand_bytes(32u);
    let addr = address::Address::new(priv_key.as_slice());
    println!("{}", addr.to_string());
}

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
    //bitcoin_address_test();
    //aes_test();
    //openssl_test();

    let wif_key = "5J4DvzSyPfxKbEe4uMEkEd8aBkHjUukjjYjg2Lg5R8FrJvhXNEd";
    let priv_key = base58::base58_decode(wif_key);

    for byte in priv_key.iter() {
        print!("{:02x}", *byte);
    }
    println!("");
}

