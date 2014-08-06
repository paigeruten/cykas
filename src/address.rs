use openssl::crypto::rand::rand_bytes;
use openssl::crypto::hash::{hash, SHA256, RIPEMD160};
use ecdsa::derive_public_key;
use base58::base58_encode;

// A Bitcoin private key is 32 bytes in length.
static PRIVATE_KEY_LENGTH: uint = 32u;

// Bitcoin keys must be less than or equal to this value, as dictated by the
// secp256k1 curve it uses.
static MAX_PRIVATE_KEY: &'static [u8] = &[
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
    0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,
    0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x40
];

// ...also, Bitcoin keys can't be zero.
static ZERO_PRIVATE_KEY: &'static [u8] = &[
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
];

// A Bitcoin address. Represented as just a private key for now (which can be
// used to derive the public key and public address).
pub struct Address {
    private_key: Vec<u8>
}

impl Address {
    // Create new Address from 256-bit private key.
    pub fn new(private_key: &[u8]) -> Address {
        if !Address::is_private_key_valid(private_key) {
            fail!("Invalid private key!");
        }

        Address { private_key: Vec::from_slice(private_key) }
    }

    // Generate a new Address using openssl's random bytes generator.
    pub fn new_random() -> Address {
        let mut key;
        loop {
            // Generate a random key by asking openssl for 32 random bytes.
            // Keep generating a new one until we get a valid one. (The range
            // of invalid private keys is so tiny that it should pretty much
            // never happen.)
            key = rand_bytes(PRIVATE_KEY_LENGTH);
            if Address::is_private_key_valid(key.as_slice()) { break; }
        }
        Address { private_key: key }
    }

    // Check if the given private key is valid. A Bitcoin private key is valid
    // if it is exactly 32 bytes long, and is less than MAX_PRIVATE_KEY, and
    // isn't zero.
    fn is_private_key_valid(private_key: &[u8]) -> bool {
        private_key.len() == PRIVATE_KEY_LENGTH &&
        private_key > ZERO_PRIVATE_KEY &&
        private_key <= MAX_PRIVATE_KEY
    }

    // Get the public address as a String.
    pub fn to_string(&self) -> String {
        // Converting a private key to a Bitcoin address is a process with many
        // steps. First we derive the public key from the private key.
        let pub_key = derive_public_key(self.private_key.as_slice());

        // Next, obtain the SHA256 hash of the public key.
        let pub_key_sha = hash(SHA256, pub_key.as_slice());

        // Now obtain the RIPEMD-160 hash of that.
        let mut pub_key_ripemd = hash(RIPEMD160, pub_key_sha.as_slice());

        // Stick a version byte (0x00) to the front of that hash, to identify
        // this as a Bitcoin address. (It's why Bitcoin addresses start with a
        // "1".)
        pub_key_ripemd.insert(0, 0x00);

        // Perform a double SHA256 hash of the above hash that has the version
        // byte in front.
        let mut double_sha = hash(SHA256, pub_key_ripemd.as_slice());
        double_sha = hash(SHA256, double_sha.as_slice());

        // Get the first 4 bytes of the double hash. This will be the address's
        // checksum.
        let checksum = double_sha.slice(0, 4);

        // Stick the checksum onto the end of the RIPEMD-160 hash that has the
        // version byte in front.
        pub_key_ripemd.push_all(checksum);

        for b in pub_key_ripemd.iter() { print!("{:02x}", *b); } println!("");

        // pub_key_ripemd now consists of a version byte (0x00), a RIPEMD-160
        // hash, and a 4-byte checksum all concatenated together. The last step
        // is to convert this string of bytes to a base58 string.
        base58_encode(pub_key_ripemd.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::Address;
    use super::{PRIVATE_KEY_LENGTH, ZERO_PRIVATE_KEY, MAX_PRIVATE_KEY};

    static INVALID_PRIVATE_KEY: &'static [u8] =
        &[0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
          0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
    static VALID_PRIVATE_KEY: &'static [u8] =
        &[0xf7,0x47,0x65,0x32,0xfe,0x57,0x53,0xeb,0xcb,0xea,0x26,0xfe,0x02,0xff,0xf1,0x8b,
          0xf0,0x15,0x54,0x6f,0x85,0xca,0xf7,0x8a,0xc8,0xd5,0x99,0x54,0x7f,0x7d,0x3a,0xac];
    static VALID_PRIVATE_KEY_ADDRESS: &'static str = "19gL5Rq1uc5yspAtbM7NyDs1godKnGHMar";

    #[test]
    fn test_new() {
        Address::new(VALID_PRIVATE_KEY);
    }

    #[test]
    #[should_fail]
    fn test_new_with_invalid_key() {
        Address::new(INVALID_PRIVATE_KEY);
    }

    #[test]
    #[should_fail]
    fn test_new_with_invalid_zero_key() {
        Address::new(ZERO_PRIVATE_KEY);
    }

    #[test]
    fn test_new_random() {
        let address = Address::new_random();
        assert!(address.private_key.len() == PRIVATE_KEY_LENGTH);

        // If the same address is generated again, then there's a serious
        // problem. Even if it can happen in theory.
        let address2 = Address::new_random();
        assert!(address.private_key != address2.private_key);
    }

    #[test]
    fn test_is_private_key_valid() {
        assert!(!Address::is_private_key_valid(INVALID_PRIVATE_KEY));
        assert!(!Address::is_private_key_valid(ZERO_PRIVATE_KEY));
        assert!(Address::is_private_key_valid(VALID_PRIVATE_KEY));
        assert!(Address::is_private_key_valid(MAX_PRIVATE_KEY));
    }

    #[test]
    fn test_to_string() {
        let address = Address::new(VALID_PRIVATE_KEY);
        assert_eq!(address.to_string().as_slice(), VALID_PRIVATE_KEY_ADDRESS);
    }
}

