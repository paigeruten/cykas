use util;
use protocol::private_key::PrivateKey;
use protocol::address::Address;

// TODO: support compressed public keys?
static LENGTH: uint = 65u;

// A Bitcoin public key is 65 bytes, consisting of a 0x04 byte (indicating it
// is in uncompressed format), a 32-byte X coordinate, and a 32-byte Y
// coordinate.
pub struct PublicKey {
    data: Vec<u8>
}

impl PublicKey {
    // Creates a PublicKey from the given raw data. Returns None if the data is
    // invalid.
    pub fn new(data: &[u8]) -> Option<PublicKey> {
        let key = PublicKey { data: data.to_vec() };
        if key.is_valid() {
            Some(key)
        } else {
            None
        }
    }

    // Creates a PublicKey from a PrivateKey.
    pub fn from_private_key(private_key: &PrivateKey) -> PublicKey {
        PublicKey { data: util::ecdsa::derive_public_key(private_key.get_data()) }
    }

    // Checks if the given public key is valid.
    fn is_valid(&self) -> bool {
        self.data.len() == LENGTH &&
        self.data[0] == 0x04
    }

    // Gets the raw data as a slice of bytes.
    pub fn get_data<'a>(&'a self) -> &'a [u8] {
        self.data.as_slice()
    }

    // Derives the address from the public key.
    pub fn to_address(&self) -> Address {
        Address::from_public_key(self)
    }
}

/*#[cfg(test)]
mod tests {
    use super::{LENGTH, ZERO, MAX};
    use super::{generate, is_valid, derive_public_address};

    static TINY_KEY: &'static [u8] = &[0x80,0x80,0x80,0x80];
    static INVALID_PRIVATE_KEY: &'static [u8] =
        &[0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
          0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
    static VALID_PRIVATE_KEY: &'static [u8] =
        &[0xf7,0x47,0x65,0x32,0xfe,0x57,0x53,0xeb,0xcb,0xea,0x26,0xfe,0x02,0xff,0xf1,0x8b,
          0xf0,0x15,0x54,0x6f,0x85,0xca,0xf7,0x8a,0xc8,0xd5,0x99,0x54,0x7f,0x7d,0x3a,0xac];
    static VALID_PRIVATE_KEY_ADDRESS: &'static str = "19gL5Rq1uc5yspAtbM7NyDs1godKnGHMar";


    #[test]
    fn test_generate() {
        let key = generate();
        assert!(key.len() == LENGTH);

        // If the same address is generated again, then there's a serious
        // problem. Even if it can happen in theory.
        let key2 = generate();
        assert!(key != key2);
    }

    #[test]
    fn test_zero_key_should_be_invalid() {
        assert!(!is_valid(ZERO));
    }

    #[test]
    fn test_max_key_should_be_valid() {
        assert!(is_valid(MAX));
    }

    #[test]
    fn test_valid_key_should_be_valid() {
        assert!(is_valid(VALID_PRIVATE_KEY));
    }

    #[test]
    fn test_invalid_key_should_not_be_valid() {
        assert!(!is_valid(INVALID_PRIVATE_KEY));
    }

    #[test]
    fn test_tiny_key_should_not_be_valid() {
        assert!(!is_valid(TINY_KEY));
    }

    #[test]
    fn test_derive_public_address() {
        let address = derive_public_address(VALID_PRIVATE_KEY);
        assert_eq!(address.as_slice(), VALID_PRIVATE_KEY_ADDRESS);
    }
}
*/
