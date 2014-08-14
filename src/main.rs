extern crate debug; // temporary
extern crate openssl;
extern crate num;
extern crate libc;
extern crate serialize;

use wallet::Wallet;

pub mod protocol;
pub mod util;
pub mod wallet;
pub mod wallet_tokenizer;

/*
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
*/

fn main() {
    let wallet = match Wallet::load(&Path::new("WALLET.txt")) {
        Ok(w) => w,
        Err(e) => { println!("Error: {}", e); fail!(); }
    };

    match wallet.save() {
        Ok(()) => println!("WALLET.txt saved."),
        Err(e) => println!("Error: {}", e)
    }

/*    let mut wallet = Wallet::new(&Path::new("WALLET.txt"));
    wallet.gen("main");
    wallet.gen_multiple("change", 5);
    wallet.save();*/
}

