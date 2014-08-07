use openssl;
use openssl::crypto::hash::{SHA256, RIPEMD160};

use ecdsa;
use base58;

// A Bitcoin private key is 32 bytes (256 bits) in length.
static LENGTH: uint = 32u;

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

// Generate a random key using openssl's random bytes generator.
pub fn generate() -> Vec<u8> {
    let mut key;
    loop {
        // To generate a random key, just ask openssl for 32 random bytes. Keep
        // generating a new one until we get a valid one. (The range of invalid
        // private keys is so tiny that it should pretty much never give us an
        // invalid one.)
        key = openssl::crypto::rand::rand_bytes(LENGTH);
        if is_valid(key.as_slice()) { break; }
    }
    key
}

// Check if the given private key is valid. A Bitcoin private key is valid if
// it is exactly 32 bytes long, and is less than MAX, and isn't zero.
pub fn is_valid(key: &[u8]) -> bool {
    key.len() == LENGTH && key > ZERO && key <= MAX
}

// Convert a private key to a standard base-58 Bitcoin address.
pub fn derive_public_address(private_key: &[u8]) -> String {
    // Converting a private key to a Bitcoin address is a process with many
    // steps. First we derive the public key from the private key.
    let pub_key = ecdsa::derive_public_key(private_key.as_slice());

    // Next, obtain the SHA256 hash of the public key.
    let pub_key_sha = openssl::crypto::hash::hash(SHA256, pub_key.as_slice());

    // Now obtain the RIPEMD-160 hash of that.
    let mut pub_key_ripemd = openssl::crypto::hash::hash(RIPEMD160, pub_key_sha.as_slice());

    // Stick a version byte (0x00) to the front of that hash, to identify
    // this as a Bitcoin address. (It's why Bitcoin addresses start with a
    // "1".)
    pub_key_ripemd.insert(0, 0x00);

    // Perform a double SHA256 hash of the above hash that has the version
    // byte in front.
    let mut double_sha = openssl::crypto::hash::hash(SHA256, pub_key_ripemd.as_slice());
    double_sha = openssl::crypto::hash::hash(SHA256, double_sha.as_slice());

    // Get the first 4 bytes of the double hash. This will be the address's
    // checksum.
    let checksum = double_sha.slice(0, 4);

    // Stick the checksum onto the end of the RIPEMD-160 hash that has the
    // version byte in front.
    pub_key_ripemd.push_all(checksum);

    // pub_key_ripemd now consists of a version byte (0x00), a RIPEMD-160
    // hash, and a 4-byte checksum all concatenated together. The last step
    // is to convert this string of bytes to a base58 string.
    base58::encode(pub_key_ripemd.as_slice())
}

#[cfg(test)]
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

