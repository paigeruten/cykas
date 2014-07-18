extern crate libc;

mod crypto;

fn main() {
    let hash = crypto::sha256([65]);
    for byte in hash.iter() {
        print!("{:02x}", *byte);
    }
    println!("");
}

