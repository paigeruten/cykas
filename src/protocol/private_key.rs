//! Bitcoin private key representation.

use openssl;

use util::wif;
use protocol::public_key::PublicKey;
use protocol::address::Address;

/// Length of a raw Bitcoin private key.
pub static LENGTH: uint = 32u;

// This byte must be at the start of any Bitcoin private key that's in Wallet
// Import Format (WIF).
static VERSION_BYTE: u8 = 0x80;

// Bitcoin keys must be less than or equal to this value, as dictated by the
// secp256k1 curve it uses.
static MAX: &'static [u8] = &[
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
    0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,
    0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x40
];

// Bitcoin keys must be greater than zero.
static ZERO: &'static [u8] = &[
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
];

/// Represents a raw Bitcoin private key, consisting of 32 bytes of data which
/// must be greater than `ZERO` and no greater than `MAX`, as defined above.
#[deriving(Clone, PartialEq, Show)]
pub struct PrivateKey(Vec<u8>);

impl PrivateKey {
    /// Creates a PrivateKey from raw data. Returns None if the data is not a
    /// valid Bitcoin private key.
    pub fn new(data: &[u8]) -> Option<PrivateKey> {
        if PrivateKey::is_valid(data) {
            Some(PrivateKey(data.to_vec()))
        } else {
            None
        }
    }

    /// Generates a random Bitcoin private key securely, using openssl's random
    /// bytes generator.
    pub fn generate() -> PrivateKey {
        loop {
            // Just generate 32 random bytes. The result is almost certainly a
            // valid private key. Just in case it isn't, keep looping until we
            // get a valid one.
            let key = openssl::crypto::rand::rand_bytes(LENGTH);
            if PrivateKey::is_valid(key.as_slice()) {
                return PrivateKey(key)
            }
        }
    }

    // Checks if the given private key data is valid.
    fn is_valid(data: &[u8]) -> bool {
        data.len() == LENGTH &&
        data.as_slice() > ZERO &&
        data.as_slice() <= MAX
    }

    /// Decodes the given Wallet Import Format (WIF) raw data into a
    /// PrivateKey. The bytes of a WIF private key are laid out like this:
    ///
    ///     vkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkcccc
    ///
    /// Where `v` is the version byte, `k` is the 32-byte private key, and `c`
    /// is the 4-byte checksum.
    pub fn from_wif(data: &[u8]) -> Option<PrivateKey> {
        let key = wif::decode(data, VERSION_BYTE);

        if key.is_some() {
            let key = key.unwrap();
            if PrivateKey::is_valid(key.as_slice()) {
                return Some(PrivateKey(key));
            }
        }

        None
    }

    /// Gets the raw private key as a slice of bytes.
    pub fn get_data(&self) -> &[u8] {
        let PrivateKey(ref data) = *self;
        data.as_slice()
    }

    /// Converts the private key to Wallet Import Format (WIF), as raw bytes.
    /// See from_wif() for details on the format.
    pub fn to_wif(&self) -> Vec<u8> {
        wif::encode(self.get_data().as_slice(), VERSION_BYTE)
    }

    /// Derives the public key from the given private key.
    pub fn to_public_key(&self) -> PublicKey {
        PublicKey::from_private_key(self)
    }

    /// Derives the address from the given private key.
    pub fn to_address(&self) -> Address {
        Address::from_private_key(self)
    }
}

#[cfg(test)]
mod tests {
    use serialize::hex::FromHex;

    use util::base58;

    use super::{LENGTH, ZERO, MAX};
    use super::PrivateKey;

    #[test]
    fn test_new() {
        let data = "CFE1B4C8DDA7EBF5FCACC4086BD9530F1C2201AE5A7D1DEF090D911CF28E5C5F";
        let data = data.from_hex().unwrap();
        let private_key = PrivateKey::new(data.as_slice());
        assert!(private_key.is_some());
        assert_eq!(private_key.unwrap().get_data(), data.as_slice());
    }

    #[test]
    fn test_new_max() {
        let private_key = PrivateKey::new(MAX);
        assert!(private_key.is_some());
    }

    #[test]
    fn test_new_invalid_zero_key() {
        let private_key = PrivateKey::new(ZERO);
        assert!(private_key.is_none());
    }

    #[test]
    fn test_new_invalid_range() {
        let data = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000";
        let data = data.from_hex().unwrap();
        let private_key = PrivateKey::new(data.as_slice());
        assert!(private_key.is_none());
    }

    #[test]
    fn test_from_wif() {
        let data = base58::decode("5HqRSKD8yqyRjm1eaEmeAJcgs2iY5ywf7FD1xEMetNAZcUpqKAr").unwrap();
        let private_key = PrivateKey::from_wif(data.as_slice());
        assert!(private_key.is_some());
        assert_eq!(private_key.unwrap().get_data(), data.slice(1, 33));
    }

    #[test]
    fn test_from_wif_invalid_checksum() {
        let data = base58::decode("5J5gwp44QZSNJbaHS4f5w2Wisrt8bHHdmB7rQetgsH7tghvVPY8").unwrap();
        let private_key = PrivateKey::from_wif(data.as_slice());
        assert!(private_key.is_none());
    }

    #[test]
    fn test_generate() {
        let private_key = PrivateKey::generate();
        assert!(private_key.get_data().len() == LENGTH);

        let another_key = PrivateKey::generate();
        assert!(private_key.get_data() != another_key.get_data());
    }

    #[test]
    fn test_to_wif() {
        let data = "CFE1B4C8DDA7EBF5FCACC4086BD9530F1C2201AE5A7D1DEF090D911CF28E5C5F";
        let data = data.from_hex().unwrap();
        let private_key = PrivateKey::new(data.as_slice()).unwrap();
        let wif = private_key.to_wif();
        let wif_base58 = base58::encode(wif.as_slice());
        assert_eq!(wif_base58.as_slice(), "5KPqe3y95higsGQaWN6TQPtv2BQ2X1SqL87AmVAuiz811uCQRYQ");
    }

    #[test]
    fn test_to_public_key() {
        let data = "F91BCBB19F3A8A03204B70B08DB2950716C565E362912C5B368CC171FF578B9F";
        let data = data.from_hex().unwrap();
        let private_key = PrivateKey::new(data.as_slice()).unwrap();
        let public_key = private_key.to_public_key();
        let expected = "04F9C985FBFD543097E0870B36C98CE627BBC4EAD4668040214D53E96DB341A2A0\
                          A55DBBFF18F4422E90E038BECECA97461C4076FA33408D568154A66AC8FA702F";
        let expected = expected.from_hex().unwrap();
        assert_eq!(public_key.get_data(), expected.as_slice());
    }

    #[test]
    fn test_to_address() {
        let data = "CBBEC41B016517C3DA8E2F88BDACB293802CECF1AE2C47A7CB5D4BDA28353B5B";
        let data = data.from_hex().unwrap();
        let private_key = PrivateKey::new(data.as_slice()).unwrap();
        let address = private_key.to_address();
        let expected = base58::decode("14ydpwhvtVBMjt5NrechP46UKLSY7jYn7q").unwrap();
        assert_eq!(address.get_data(), expected.as_slice());
    }
}

