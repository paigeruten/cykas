use private_key::PrivateKey;
use address::Address;

/// A Bitcoin address, optionally with its private key.
pub struct WalletAddress {
    address: Address,
    private_key: Option<PrivateKey>
}

impl WalletAddress {
    /// Creates a new WalletAddress from a standard base-58 representation of a
    /// Bitcoin address.
    pub fn from_address(address: Address) -> WalletAddress {
        WalletAddress {
            address: address.clone(),
            private_key: None
        }
    }

    /// Creates a new WalletAddress from a 256-bit private key.
    pub fn from_private_key(private_key: PrivateKey) -> WalletAddress {
        WalletAddress {
            public_address: Address::from_private_key(private_key),
            private_key: Some(private_key.clone())
        }
    }

    /// Gets the public address.
    pub fn get_address(&self) -> Address {
        self.address.clone()
    }

    /// Gets the private key, or None if it's not known.
    pub fn get_private_key(&self) -> Option<PrivateKey> {
        self.private_key.clone()
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
    fn test_from_base58() {
        let address = Address::from_base58(VALID_PRIVATE_KEY_ADDRESS);
        assert_eq!(address.get_public_address().as_slice(), VALID_PRIVATE_KEY_ADDRESS);
        assert_eq!(address.get_private_key(), None);
    }

    #[test]
    #[should_fail]
    fn test_from_base58_with_invalid_address() {
        // Same as the above valid address, but with one letter changed in the
        // middle.
        Address::from_base58("19gL5Rq1uc5yspAtbM7Nyds1godKnGHMar");
    }

    #[test]
    #[should_fail]
    fn test_from_base58_with_tiny_address() {
        Address::from_base58("19HMar");
    }

    #[test]
    #[should_fail]
    fn test_from_base58_with_invalid_checksum() {
        // Same as the above valid address, but with one letter changed at the
        // end.
        Address::from_base58("19gL5Rq1uc5yspAtbM7NyDs1godKnGHMaR");
    }

    #[test]
    #[should_fail]
    fn test_from_base58_with_missing_version_byte() {
        // Same as the above valid address, but without the version byte at the
        // beginning.
        Address::from_base58("9gL5Rq1uc5yspAtbM7NyDs1godKnGHMar");
    }

    #[test]
    fn test_from_private_key() {
        let address = Address::from_private_key(VALID_PRIVATE_KEY);
        assert_eq!(address.get_private_key().unwrap().as_slice(), VALID_PRIVATE_KEY);
        assert_eq!(address.get_public_address().as_slice(), VALID_PRIVATE_KEY_ADDRESS);
    }

    #[test]
    #[should_fail]
    fn test_from_private_key_with_invalid_key() {
        Address::from_private_key(INVALID_PRIVATE_KEY);
    }

    #[test]
    fn test_new_random() {
        let address = Address::new_random();
        assert!(address.get_private_key().is_some());

        // If the same address is generated again, then there's a serious
        // problem. Even if it can happen in theory.
        let another = Address::new_random();
        assert!(address.get_private_key() != another.get_private_key());
    }
}

