use openssl;
use serialize::hex::ToHex;

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
            //fail!("Wallet file already exists, will not overwrite!");
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

        let (salt, iv, encrypted_data) = self.encrypt();

        let mut file = try!(File::create(&self.path));

        for (alias, entries) in self.entries.iter() {
            try!(writeln!(file, "{}:", alias));
            for entry in entries.iter() {
                try!(writeln!(file, "  {}", base58::encode(entry.address.get_data())));
            }
        }

        try!(writeln!(file, ""));
        try!(writeln!(file, "# Private key data encrypted with AES-256-CBC using"));
        try!(writeln!(file, "# PBKDF2-HMAC-SHA1 with 4000 iterations and the"));
        try!(writeln!(file, "# following salt and iv:"));
        try!(writeln!(file, "!salt: {}", salt.as_slice().to_hex()));
        try!(writeln!(file, "!iv: {}", iv.as_slice().to_hex()));
        try!(writeln!(file, ""));
        try!(writeln!(file, "# The decrypted data consists of concatenated 32-byte"));
        try!(writeln!(file, "# private keys in the same order as the addresses are"));
        try!(writeln!(file, "# are listed in this file."));
        try!(writeln!(file, "!encrypted_data:"));

        for chunk in encrypted_data.as_slice().chunks(32) {
            try!(writeln!(file, "  {}", chunk.to_hex()));
        }
        try!(writeln!(file, ""));

        Ok(())
    }

    fn encrypt(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        static KEY_LENGTH: uint = 32;
        static SALT_LENGTH: uint = 16;
        static PKCS5_ITERATIONS: uint = 4000;
        static IV_LENGTH: uint = 16;

        let salt = openssl::crypto::rand::rand_bytes(SALT_LENGTH);
        let key = openssl::crypto::pkcs5::pbkdf2_hmac_sha1("asdf", salt.as_slice(),
                                                           PKCS5_ITERATIONS, KEY_LENGTH);
        let iv = openssl::crypto::rand::rand_bytes(IV_LENGTH);

        let mut private_data = vec![];
        for (_, keyring) in self.entries.iter() {
            for entry in keyring.iter() {
                let entry = entry.clone(); // TODO: shouldn't have to clone...
                if entry.private_key.is_none() { continue; }
                private_data.push_all(entry.private_key.unwrap().get_data());
            }
        }

        let ciphertext = openssl::crypto::symm::encrypt(
            openssl::crypto::symm::AES_256_CBC,
            key.as_slice(),
            iv.clone(),
            private_data.as_slice()
        );

        (salt, iv, ciphertext)
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

