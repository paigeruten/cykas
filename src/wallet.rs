use std::collections::HashMap;
use std::io::{File,BufferedReader,IoResult};

use util::base58;
use protocol::address::Address;
use protocol::private_key::PrivateKey;

pub struct Wallet {
    path: Path,
    entries: HashMap<String, Vec<WalletEntry>>
}

struct WalletEntry {
    address: Address,
    private_key: Option<PrivateKey>
}

impl Wallet {
    pub fn new(path: &Path) -> Wallet {
        if path.exists() {
            fail!("Wallet file already exists, will not overwrite!");
        }

        Wallet { path: path.clone(), entries: HashMap::new() }
    }

    pub fn load(path: &Path) -> IoResult<Wallet> {
        let file = try!(File::open(path));
        let mut reader = BufferedReader::new(file);

        let mut wallet = Wallet { path: path.clone(), entries: HashMap::new() };
        let mut current_alias = "lost+found".to_string();

        for line in reader.lines() {
            let line = try!(line);
            let trimmed = line.as_slice().trim_chars(|c: char| c.is_whitespace());
            if trimmed.len() == 0 || trimmed.starts_with("#") {
                continue;
            } else if trimmed.ends_with(":") {
                current_alias = trimmed.slice_to(trimmed.len() - 1).to_string();
            } else {
                let address_data = base58::decode(trimmed).unwrap(); // TODO: handle error.
                let address = Address::new(address_data.as_slice()).unwrap(); // TODO: handle error.
                let key_ring = wallet.entries.find_or_insert(current_alias.clone(), Vec::new());
                key_ring.push(WalletEntry { address: address, private_key: None });
            }
        }

        Ok(wallet)
    }

    pub fn save(&self) -> IoResult<()> {
        // TODO: make a backup copy first, to delete when the new file is
        // closed.

        let mut file = try!(File::create(&self.path));

        for (alias, entries) in self.entries.iter() {
            try!(writeln!(file, "{}:", alias));
            for entry in entries.iter() {
                try!(writeln!(file, "  {}", base58::encode(entry.address.get_data())));
            }
        }

        writeln!(file, "")
    }

    pub fn gen(&mut self, alias: &str) {
        self.gen_multiple(alias, 1);
    }

    pub fn gen_multiple(&mut self, alias: &str, n: uint) {
        let key_ring = self.entries.find_or_insert(String::from_str(alias), Vec::new());
        for _ in range(0, n) {
            let private_key = PrivateKey::generate();
            let address = private_key.to_address();
            key_ring.push(WalletEntry { address: address, private_key: Some(private_key) });
        }
    }
}

