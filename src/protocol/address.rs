use openssl;
use openssl::crypto::hash::{SHA256, RIPEMD160};

use util;
use protocol::public_key::PublicKey;
use protocol::private_key::PrivateKey;

static LENGTH: uint = 25u;

// The version byte to stick onto the front of a Bitcoin address.
static VERSION_BYTE: u8 = 0x00;

// An Address is a raw Bitcoin address. It consists of 25 bytes: 1 version
// byte (0x00), a 20-byte hash of the public key, and a 4-byte checksum.
pub struct Address {
    data: Vec<u8>
}

impl Address {
    // Creates an Address from raw data. Returns None if the data is not a
    // valid Bitcoin address.
    pub fn new(data: &[u8]) -> Option<Address> {
        let address = Address { data: data.to_vec() };
        if address.is_valid() {
            Some(address)
        } else {
            None
        }
    }

    // Creates an Address from a PublicKey.
    pub fn from_public_key(public_key: &PublicKey) -> Address {
        let public_key_sha = openssl::crypto::hash::hash(SHA256, public_key.get_data());
        let public_key_ripemd = openssl::crypto::hash::hash(RIPEMD160, public_key_sha.as_slice());

        let mut data = public_key_ripemd;
        data.insert(0, VERSION_BYTE);

        let checksum = util::check::checksum(data.as_slice());
        data.push_all(checksum.as_slice());

        Address { data: data }
    }

    // Creates an Address from a PrivateKey.
    pub fn from_private_key(private_key: &PrivateKey) -> Address {
        let public_key = PublicKey::from_private_key(private_key);
        Address::from_public_key(&public_key)
    }

    // Checks if the given public key is valid.
    fn is_valid(&self) -> bool {
        // The raw data consists of a version byte, a 20-byte RIPEMD-160 hash,
        // and a 4-byte checksum. We need to slice out the 20-byte hash to
        // compute the checksum.
        let inner_hash = self.data.slice(1, 21);
        let expected_checksum = util::check::checksum(inner_hash);

        self.data.len() == LENGTH &&
        self.data[0] == VERSION_BYTE &&
        self.data.slice(21, 25) == expected_checksum.as_slice()
    }

    // Gets the raw data as a slice of bytes.
    pub fn get_data<'a>(&'a self) -> &'a [u8] {
        self.data.as_slice()
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
}*/

