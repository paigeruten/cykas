//! Cykas is (not yet!) a secure offline Bitcoin wallet.

extern crate debug; // temporary
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

fn print_usage() {
    println!("Usage: cykas <command> [args...]");
    println!("");
    println!("Available commands:");
    println!("  new [path]            Create a new wallet");
}

fn main() {
    // Just in case someone comes along and actually tries to *use* this.
    println!("WARNING: Don't use this program for anything serious. If you really");
    println!("want to, then make sure to read and understand all of the code first.");
    println!("---");

    let args = os::args();

    if args.len() < 2 {
        print_usage();
    } else {
        let command = args[1].as_slice();
        let args_rest = args.slice_from(2);

        if command == "new" {
            commands::new::run(args_rest);
        } else {
            println!("'{}' is not a valid command!", command);
        }
    }
}

