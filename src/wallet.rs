// This is just a sketch!

use address;

use std::collections::HashMap;

struct Wallet {
    path: Path,
    entries: HashMap<String, Vec<Address>>
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
                print!("  ");
                for byte in key.iter() {
                    print!("{:02x}", *byte);
                }
                println!("");
            }
        }
    }

    pub fn gen(&mut self, alias: &str) {
        let key_ring = self.entries.find_or_insert(String::from_str(alias), Vec::new());
        let mut rng = rand::task_rng();
        let mut new_key: PrivateKey = Vec::with_capacity(PRIVATE_KEY_LENGTH);

        for _ in range(0, PRIVATE_KEY_LENGTH) {
            new_key.push(rng.gen::<u8>());
        }

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

fn main() {
    let mut wallet = Wallet::new(Path::new("WALLET.cykas"));
    wallet.gen("test");
    wallet.gen_multiple("change", 5);
    wallet.save();
}

