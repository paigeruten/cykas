use wallet::Wallet;

pub fn run(wallet_path: Path, args: &[String]) {
    assert!(args.is_empty());

    let wallet = Wallet::new(&wallet_path);

    match wallet.save() {
        Ok(_) => println!("New wallet saved to {}.", wallet_path.display()),
        Err(e) => println!("Error saving wallet: {}", e)
    };
}

