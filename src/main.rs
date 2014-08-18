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

fn main() {
    // Just in case someone comes along and actually tries to *use* this.
    println!("WARNING: Don't use this program for anything serious. If you really");
    println!("want to, then make sure to read and understand all of the code first.");
    println!("---");

    /*let wallet = match Wallet::load(&Path::new("WALLET.txt")) {
        Ok(w) => w,
        Err(e) => { println!("Error: {}", e); fail!(); }
    };

    match wallet.save() {
        Ok(()) => println!("WALLET.txt saved."),
        Err(e) => println!("Error: {}", e)
    }*/

    let mut wallet = Wallet::new(&Path::new("WALLET.txt"));
    wallet.gen("main");
    wallet.gen_multiple("change", 5);
    wallet.save();
}

