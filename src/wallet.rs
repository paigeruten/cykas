use std::collections::HashMap;

use util;
use protocol::private_key::PrivateKey;

pub struct Wallet {
    path: Path,
    entries: HashMap<String, Vec<PrivateKey>>
}

impl Wallet {
    pub fn new(path: Path) -> Wallet {
        if path.exists() {
            fail!("Will not overwrite wallet at '{}'!", path.display());
        }

        Wallet { path: path, entries: HashMap::new() }
    }

    pub fn load(path: Path) {
    }

    pub fn save(&self) {
        for (alias, keys) in self.entries.iter() {
            println!("{}:", alias);
            for key in keys.iter() {
                println!("  {}", util::base58::encode(key.to_address().get_data()));
            }
        }
    }

    pub fn gen(&mut self, alias: &str) {
        let key_ring = self.entries.find_or_insert(String::from_str(alias), Vec::new());
        let new_key = PrivateKey::generate();
        key_ring.push(new_key);
    }

    pub fn gen_multiple(&mut self, alias: &str, n: uint) {
        for _ in range(0, n) {
            self.gen(alias);
        }
    }

    pub fn move_key(&mut self, alias: &str, idx: uint, new_alias: &str) {
    }

    pub fn merge_aliases(&mut self, alias1: &str, alias2: &str, new_alias: &str) {
    }

    pub fn rename_alias(&mut self, old_alias: &str, new_alias: &str) {

    }
}

