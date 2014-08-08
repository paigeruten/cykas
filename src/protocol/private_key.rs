use openssl;

use util;
use protocol::public_key::PublicKey;
use protocol::address::Address;

// A Bitcoin private key is 32 bytes (256 bits) in length.
static LENGTH: uint = 32u;

// Version byte for the Wallet Import Format.
static VERSION_BYTE: u8 = 0x80;

// Bitcoin keys must be less than or equal to this value, as dictated by the
// secp256k1 curve it uses.
static MAX: &'static [u8] = &[
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
    0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,
    0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x40
];

// ...also, Bitcoin keys can't be zero.
static ZERO: &'static [u8] = &[
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
];

// A Bitcoin private key is 32 bytes of data which must be greater than `ZERO`
// and no greater than `MAX`, as defined above.
pub struct PrivateKey {
    data: Vec<u8>
}

impl PrivateKey {
    // Creates a PrivateKey from the given raw data. Returns None if the data
    // is an invalid private key.
    pub fn new(data: &[u8]) -> Option<PrivateKey> {
        let key = PrivateKey { data: data.to_vec() };
        if key.is_valid() {
            Some(key)
        } else {
            None
        }
    }

    // Creates a PrivateKey from the given raw data that is in Bitcoin's
    // Wallet Import Format. Returns None if the data is invalid.
    pub fn from_wif(data: &[u8]) -> Option<PrivateKey> {
        if data.len() != 1 + LENGTH + 4 {
            return None;
        }

        let version_byte = data[0];
        let key = data.slice(1, 33);
        let checksum = data.slice(33, 37);
        let actual_checksum = util::check::checksum(data.slice(0, 33));

        let private_key = PrivateKey { data: key.to_vec() };
        let valid = version_byte == VERSION_BYTE &&
                    private_key.is_valid() &&
                    checksum == actual_checksum.as_slice();

        if valid {
            Some(private_key)
        } else {
            None
        }
    }

    // Generates a random key using openssl's random bytes generator.
    pub fn generate() -> PrivateKey {
        let mut key;
        loop {
            // To generate a random key, just ask openssl for 32 random bytes. Keep
            // generating a new one until we get a valid one. (The range of invalid
            // private keys is so tiny that it should pretty much never give us an
            // invalid one.)
            key = PrivateKey { data: openssl::crypto::rand::rand_bytes(LENGTH) };
            if key.is_valid() { break; }
        }
        key
    }

    // Checks if the given private key is valid. A Bitcoin private key is valid if
    // it is exactly 32 bytes long, and is less than MAX, and isn't zero.
    fn is_valid(&self) -> bool {
        self.data.len() == LENGTH &&
        self.data.as_slice() > ZERO &&
        self.data.as_slice() <= MAX
    }

    // Gets the raw private key as a slice of bytes.
    pub fn get_data<'a>(&'a self) -> &'a [u8] {
        self.data.as_slice()
    }

    // Converts the private key to Wallet Import Format.
    pub fn to_wif(&self) -> Vec<u8> {
        let mut wif = Vec::with_capacity(1 + LENGTH + 4);
        wif.push(VERSION_BYTE);
        wif.push_all(self.data.as_slice());

        let checksum = util::check::checksum(wif.as_slice());
        wif.push_all(checksum.as_slice());

        wif
    }

    // Derives the public key from the private key.
    pub fn to_public_key(&self) -> PublicKey {
        PublicKey::from_private_key(self)
    }

    // Derives the address from the private key.
    pub fn to_address(&self) -> Address {
        Address::from_private_key(self)
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
