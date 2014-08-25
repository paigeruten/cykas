//! Contains Bitcoin private keys grouped by aliases.

use openssl;
use serialize::hex::{ToHex, FromHex};

use std::io::{File,BufferedReader,IoResult};

use util::base58;
use protocol::address::Address;
use protocol::private_key::PrivateKey;
use protocol::private_key;
use wallet_parser;

static KEY_LENGTH: uint = 32;
static SALT_LENGTH: uint = 16;
static PKCS5_ITERATIONS: uint = 4000;
static IV_LENGTH: uint = 16;

pub struct Wallet {
    path: Path,
    entries: Vec<(String, Vec<WalletEntry>)>
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

        Wallet { path: path.clone(), entries: Vec::new() }
    }

    pub fn load(path: &Path) -> IoResult<Wallet> {
        let file = try!(File::open(path));
        let mut reader = BufferedReader::new(file);
        let parsed = try!(wallet_parser::parse(&mut reader));

        let mut wallet = Wallet { path: path.clone(), entries: Vec::new() };

        let mut salt = None;
        let mut iv = None;
        let mut encrypted_data = None;

        for (key, values) in parsed.move_iter() {
            if key.as_slice().starts_with("!") {
                if key.as_slice() == "!salt" {
                    salt = values.concat().as_slice().from_hex().ok();
                } else if key.as_slice() == "!iv" {
                    iv = values.concat().as_slice().from_hex().ok();
                } else if key.as_slice() == "!encrypted_data" {
                    encrypted_data = values.concat().as_slice().from_hex().ok();
                } else {
                    fail!(); // TODO: handle error.
                }
            } else {
                let entries = values.iter().map(|value| {
                    let address_data = base58::decode(value.as_slice()).unwrap(); // TODO: handle error.
                    let address = Address::new(address_data.as_slice()).unwrap(); // TODO: handle error.
                    WalletEntry { address: address, private_key: None }
                }).collect();
                wallet.entries.push((key, entries));
            }
        }

        if encrypted_data.is_none() {
            fail!(); // TODO: handle error.
        } else if salt.is_none() {
            fail!(); // TODO: handle error.
        } else if iv.is_none() {
            fail!(); // TODO: handle error.
        }

        let private_keys = wallet.decrypt(salt.unwrap().as_slice(),
                                          iv.unwrap().as_slice(),
                                          encrypted_data.unwrap().as_slice());

        let mut private_keys_iter = private_keys.move_iter();

        for &(_, ref mut entries) in wallet.entries.mut_iter() {
            for entry in entries.mut_iter() {
                let private_key = private_keys_iter.next().unwrap(); // TODO: handle error.
                assert_eq!(private_key.to_address(), entry.address); // TODO: handle error.

                entry.private_key = Some(private_key);
            }
        }

        Ok(wallet)
    }

    pub fn save(&self) -> IoResult<()> {
        // TODO: make a backup copy first, to delete when the new file is
        // closed.

        let (salt, iv, encrypted_data) = self.encrypt();

        let mut file = try!(File::create(&self.path));

        for &(ref alias, ref entries) in self.entries.iter() {
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

        for chunk in encrypted_data.as_slice().chunks(38) {
            try!(writeln!(file, "  {}", chunk.to_hex()));
        }
        try!(writeln!(file, ""));

        Ok(())
    }

    fn encrypt(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let salt = openssl::crypto::rand::rand_bytes(SALT_LENGTH);
        let key = openssl::crypto::pkcs5::pbkdf2_hmac_sha1("asdf", salt.as_slice(),
                                                           PKCS5_ITERATIONS, KEY_LENGTH);
        let iv = openssl::crypto::rand::rand_bytes(IV_LENGTH);

        let mut private_data = vec![];
        for &(_, ref keyring) in self.entries.iter() {
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

    fn decrypt(&self, salt: &[u8], iv: &[u8], ciphertext: &[u8]) -> Vec<PrivateKey> {
        let key = openssl::crypto::pkcs5::pbkdf2_hmac_sha1("asdf", salt, PKCS5_ITERATIONS, KEY_LENGTH);

        let plaintext = openssl::crypto::symm::decrypt(
            openssl::crypto::symm::AES_256_CBC,
            key.as_slice(), iv.to_vec(), ciphertext
        );

        let raw_keys = plaintext.as_slice().chunks(private_key::LENGTH);
        let private_keys = raw_keys.map(|key| PrivateKey::new(key).unwrap()).collect();

        private_keys
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

        let index = self.entries.iter().position(|&(ref key, _)| key.as_slice() == alias);
        match index {
            Some(idx) => {
                let &(_, ref mut values) = self.entries.get_mut(idx);
                values.push_all(entries.as_slice());
            },
            None => {
                self.entries.push((alias.to_string(), entries));
            }
        }
    }
}

