use wallet::Wallet;

pub fn run(args: &[String]) {
    let path = if args.len() == 1 {
        Path::new(args[0].as_slice())
    } else {
        Path::new("WALLET.txt")
    };

    let wallet = Wallet::new(&path);

    match wallet.save() {
        Ok(_) => println!("New wallet saved to {}.", path.display()),
        Err(e) => println!("Error saving wallet: {}", e)
    };
}

