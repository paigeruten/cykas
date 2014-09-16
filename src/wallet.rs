//! A Wallet contains Bitcoin private keys and addresses, grouped by aliases.

// TODO: write tests for each error that is handled by Wallet::load(), etc.

use openssl;
use serialize::hex::{ToHex, FromHex};

use std::io::{File, BufferedReader, IoResult, IoError, OtherIoError};
use std::io::fs::PathExtensions;

use util::base58;
use protocol::address::Address;
use protocol::private_key::PrivateKey;
use protocol::private_key;
use wallet_parser;

// The length of the private key that the PKCS5 algorithm should generate.
static PKCS5_KEY_LENGTH: uint = 32;

// The length of the random salt that the PKCS5 algorithm should use.
static PKCS5_SALT_LENGTH: uint = 16;

// The number of iterations the PKCS5 algorithm should use.
static PKCS5_ITERATIONS: uint = 4000;

// The length of the random initialization vector (IV) that the AES algorithm
// should use.
static AES_IV_LENGTH: uint = 16;

/// A Wallet contains a Path to the wallet file, and groups of addresses and
/// private keys that are associated with aliases.
pub struct Wallet {
    path: Path,
    entries: Vec<(String, Vec<WalletEntry>)>
}

// A WalletEntry contains a Bitcoin address and the associated private key, if
// it's available. (If the private key for an address isn't found in the
// encrypted part of the wallet file, then a warning should be displayed.)
#[deriving(Clone)]
struct WalletEntry {
    address: Address,
    private_key: Option<PrivateKey>
}

impl Wallet {
    /// Creates a blank Wallet at the given Path. Fails if the wallet file at
    /// that Path already exists, so as not to overwrite it.
    pub fn new(path: &Path) -> Wallet {
        if path.exists() {
            fail!("Wallet file '{}' already exists, will not overwrite!", path.display());
        }

        Wallet { path: path.clone(), entries: Vec::new() }
    }

    /// Loads a Wallet from the given wallet file Path. Returns an IoError on
    /// failure, and specifically an OtherIoError if the contents of the file
    /// are invalid.
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
                    return Err(IoError {
                        kind: OtherIoError,
                        desc: "invalid special key",
                        detail: Some(format!("Unexpected key '{}' in wallet file", key))
                    });
                }
            } else {
                let mut entries = Vec::with_capacity(values.len());

                for value in values.iter() {
                    let address_data = base58::decode(value.as_slice());
                    let address = match address_data {
                        Some(data) => Address::new(data.as_slice()),
                        None => {
                            return Err(IoError {
                                kind: OtherIoError,
                                desc: "invalid base-58 string",
                                detail: Some(format!("Address '{}' is not a valid base-58 string", value))
                            });
                        }
                    };

                    if address.is_some() {
                        entries.push(WalletEntry { address: address.unwrap(), private_key: None });
                    } else {
                        return Err(IoError {
                            kind: OtherIoError,
                            desc: "invalid address",
                            detail: Some(format!("Address '{}' is not a valid Bitcoin address", value))
                        });
                    }
                }

                wallet.entries.push((key, entries));
            }
        }

        if encrypted_data.is_none() {
            return Err(IoError {
                kind: OtherIoError,
                desc: "encrypted data not found or invalid",
                detail: Some(format!("'!encrypted_data' field not found or invalid"))
            });
        } else if salt.is_none() {
            return Err(IoError {
                kind: OtherIoError,
                desc: "salt not found or invalid",
                detail: Some(format!("'!salt' field not found or invalid"))
            });
        } else if iv.is_none() {
            return Err(IoError {
                kind: OtherIoError,
                desc: "iv not found or invalid",
                detail: Some(format!("'!iv' field not found or invalid"))
            });
        }

        let private_keys = wallet.decrypt(salt.unwrap().as_slice(),
                                          iv.unwrap().as_slice(),
                                          encrypted_data.unwrap().as_slice());

        let mut private_keys_iter = private_keys.move_iter();

        for &(_, ref mut entries) in wallet.entries.mut_iter() {
            for entry in entries.mut_iter() {
                let private_key = private_keys_iter.next();

                if private_key.is_none() {
                    return Err(IoError {
                        kind: OtherIoError,
                        desc: "missing private key",
                        detail: Some(format!("There are more addresses than private keys in the wallet file"))
                    });
                }

                let private_key = private_key.unwrap();

                if private_key.to_address() != entry.address {
                    return Err(IoError {
                        kind: OtherIoError,
                        desc: "address and private key mismatch",
                        detail: Some(format!("The private key given for '{}' is wrong",
                                             base58::encode(entry.address.get_data())))
                    });
                }

                entry.private_key = Some(private_key);
            }
        }

        Ok(wallet)
    }

    /// Saves the Wallet to its wallet file. Returns an IoError on failure.
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

    // Helper function for Wallet::save(). Encrypts the private keys in the
    // Wallet and returns a tuple containing the salt, iv, and ciphertext.
    fn encrypt(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let salt = openssl::crypto::rand::rand_bytes(PKCS5_SALT_LENGTH);
        let key = openssl::crypto::pkcs5::pbkdf2_hmac_sha1("asdf", salt.as_slice(),
                                                           PKCS5_ITERATIONS, PKCS5_KEY_LENGTH);
        let iv = openssl::crypto::rand::rand_bytes(AES_IV_LENGTH);

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

    // Helper function for Wallet::load(). Decrypts the given ciphertext with
    // the given salt and iv, and returns a vector of Bitcoin private keys.
    fn decrypt(&self, salt: &[u8], iv: &[u8], ciphertext: &[u8]) -> Vec<PrivateKey> {
        let key = openssl::crypto::pkcs5::pbkdf2_hmac_sha1("asdf", salt, PKCS5_ITERATIONS, PKCS5_KEY_LENGTH);

        assert_eq!(salt.len(), PKCS5_SALT_LENGTH); // TODO: handle error.
        assert_eq!(iv.len(), AES_IV_LENGTH); // TODO: handle error.

        let plaintext = openssl::crypto::symm::decrypt(
            openssl::crypto::symm::AES_256_CBC,
            key.as_slice(), iv.to_vec(), ciphertext
        );

        let raw_keys = plaintext.as_slice().chunks(private_key::LENGTH);
        let private_keys = raw_keys.map(|key| PrivateKey::new(key).unwrap()).collect();

        private_keys
    }

    /// Generates a single private key, appending it to the keyring with the
    /// given alias.
    pub fn gen(&mut self, alias: &str) {
        self.gen_multiple(alias, 1);
    }

    /// Generates `n` private keys, appending them to the keyring with the
    /// given alias.
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

