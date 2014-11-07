//! Cykas is (not yet!) a secure offline Bitcoin wallet.

extern crate openssl;
extern crate num;
extern crate libc;
extern crate serialize;

use std::os;

pub mod protocol;
pub mod util;
pub mod wallet;
pub mod wallet_parser;
pub mod commands;

fn print_usage(program: &str) {
    println!("Usage: {} <command> [args...]", program);
    println!("");
    println!("Available commands:");
    println!("  new            Create a new wallet");
}

fn main() {
    // Just in case someone comes along and actually tries to *use* this.
    println!("WARNING: Don't use this program for anything serious. If you really");
    println!("want to, then make sure to read and understand all of the code first.");
    println!("---");

    let args = os::args();
    let program = args[0].clone();

    if args.len() < 2 {
        print_usage(program.as_slice());
    } else {
        let command = args[1].as_slice();
        let args_rest = args.slice_from(2);

        // TODO: change this with an option.
        let wallet_path = Path::new("WALLET.txt");

        if command == "new" {
            commands::new::run(wallet_path, args_rest);
        } else {
            println!("'{}' is not a valid command!", command);
        }
    }
}

