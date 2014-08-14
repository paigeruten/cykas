use std::collections::TreeMap;
use std::io::{File,BufferedReader,IoResult};

use util::base58;
use protocol::address::Address;
use protocol::private_key::PrivateKey;
use wallet_tokenizer::{KeyToken, ValueToken};
use wallet_tokenizer;

pub struct Wallet {
    path: Path,
    entries: TreeMap<String, Vec<WalletEntry>>
}

#[deriving(Clone)]
struct WalletEntry {
    address: Address,
    private_key: Option<PrivateKey>
}

impl Wallet {
    pub fn new(path: &Path) -> Wallet {
        if path.exists() {
            fail!("Wallet file already exists, will not overwrite!");
        }

        Wallet { path: path.clone(), entries: TreeMap::new() }
    }

    pub fn load(path: &Path) -> IoResult<Wallet> {
        let file = try!(File::open(path));
        let mut reader = BufferedReader::new(file);
        let tokens = try!(wallet_tokenizer::tokenize(&mut reader));

        let mut wallet = Wallet { path: path.clone(), entries: TreeMap::new() };
        let mut current_alias = String::from_str("lost+found");

        for token in tokens.iter() {
            match *token {
                KeyToken(ref alias) => { current_alias = alias.clone(); },
                ValueToken(ref val) => {
                    let address_data = base58::decode(val.as_slice()).unwrap(); // TODO: handle error.
                    let address = Address::new(address_data.as_slice()).unwrap(); // TODO: handle error.
                    let wallet_entry = WalletEntry { address: address, private_key: None };
                    wallet.add(current_alias.clone(), vec![wallet_entry]);
                }
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
        let entries: Vec<WalletEntry> =
            range(0, n).map(|_| {
                let private_key = PrivateKey::generate();
                let address = private_key.to_address();
                WalletEntry { address: address, private_key: Some(private_key) }
            }).collect();

        self.add(alias.to_string(), entries);
    }

    fn add(&mut self, alias: String, entries: Vec<WalletEntry>) {
        if !self.entries.contains_key(&alias) {
            self.entries.insert(alias, entries);
        } else {
            let keyring = self.entries.find_mut(&alias).unwrap();
            keyring.push_all(entries.as_slice());
        }
    }
}

