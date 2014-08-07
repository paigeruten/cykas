use private_key;

// A Bitcoin address. Represented as a standard base-58 public address, and an
// optional private key.
pub struct Address {
    public_address: String,
    private_key: Option<Vec<u8>>
}

impl Address {
    // Creates a new Address from a standard base-58 representation of a
    // Bitcoin address.
    pub fn from_base58(address: &str) -> Address {
        // TODO: validate it.
        Address {
            public_address: address.to_string(),
            private_key: None
        }
    }

    // Creates a new Address from a 256-bit private key.
    pub fn from_private_key(key: &[u8]) -> Address {
        if !private_key::is_valid(key) {
            fail!("Invalid private key!");
        }

        Address {
            public_address: private_key::derive_public_address(key),
            private_key: Some(Vec::from_slice(key))
        }
    }

    // Generate a new Address using openssl's random bytes generator.
    pub fn new_random() -> Address {
        let key = private_key::generate();
        Address::from_private_key(key.as_slice())
    }

    pub fn get_public_address(&self) -> &str {
        self.public_address.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::Address;

    static INVALID_PRIVATE_KEY: &'static [u8] =
        &[0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
          0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
    static VALID_PRIVATE_KEY: &'static [u8] =
        &[0xf7,0x47,0x65,0x32,0xfe,0x57,0x53,0xeb,0xcb,0xea,0x26,0xfe,0x02,0xff,0xf1,0x8b,
          0xf0,0x15,0x54,0x6f,0x85,0xca,0xf7,0x8a,0xc8,0xd5,0x99,0x54,0x7f,0x7d,0x3a,0xac];
    static VALID_PRIVATE_KEY_ADDRESS: &'static str = "19gL5Rq1uc5yspAtbM7NyDs1godKnGHMar";

    #[test]
    fn test_from_private_key() {
        let address = Address::from_private_key(VALID_PRIVATE_KEY);
        assert_eq!(address.private_key.unwrap().as_slice(), VALID_PRIVATE_KEY);
        assert_eq!(address.public_address.as_slice(), VALID_PRIVATE_KEY_ADDRESS);
    }

    #[test]
    #[should_fail]
    fn test_from_private_key_with_invalid_key() {
        Address::from_private_key(INVALID_PRIVATE_KEY);
    }

    #[test]
    fn test_new_random() {
        let address = Address::new_random();
        assert!(address.private_key != None);

        // If the same address is generated again, then there's a serious
        // problem. Even if it can happen in theory.
        let another = Address::new_random();
        assert!(address.private_key != another.private_key);
    }
}

