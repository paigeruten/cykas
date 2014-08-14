use openssl;
use openssl::crypto::hash::{SHA256, RIPEMD160};

use util::wif;
use protocol::public_key::PublicKey;
use protocol::private_key::PrivateKey;

// Length of a raw Bitcoin address.
static LENGTH: uint = 25;

// This byte must be at the start of every standard Bitcoin address. (In
// base-58, a zero byte maps to a '1' character, which is why addresses start
// with a one.)
static VERSION_BYTE: u8 = 0x00;

// Represents a raw Bitcoin address. The bytes of an address are laid out like
// this:
//
//     vhhhhhhhhhhhhhhhhhhhhcccc
//
// Where `v` is the version byte, `h` is a 20-byte hash of the public key, and
// `c` is the 4-byte checksum.
#[deriving(Clone)]
pub struct Address(Vec<u8>);

impl Address {
    // Creates an Address from raw data. Returns None if the data is not a
    // valid Bitcoin address.
    pub fn new(data: &[u8]) -> Option<Address> {
        if Address::is_valid(data) {
            Some(Address(data.to_vec()))
        } else {
            None
        }
    }

    // Checks if the given raw address data is valid.
    fn is_valid(data: &[u8]) -> bool {
        data.len() == LENGTH &&
        data[0] == VERSION_BYTE &&
        wif::check(data)
    }

    // Creates an Address from a PublicKey.
    pub fn from_public_key(public_key: &PublicKey) -> Address {
        // The meat of a Bitcoin address is a RIPEMD-160 hash of a SHA-256 hash
        // of the public key.
        let public_key_sha = openssl::crypto::hash::hash(SHA256, public_key.get_data());
        let public_key_ripemd = openssl::crypto::hash::hash(RIPEMD160, public_key_sha.as_slice());

        // Encode it in WIF format, which puts the version byte in front and a
        // 4-byte checksum at the end.
        let data = wif::encode(public_key_ripemd.as_slice(), VERSION_BYTE);

        Address(data)
    }

    // Creates an Address from a PrivateKey.
    pub fn from_private_key(private_key: &PrivateKey) -> Address {
        let public_key = PublicKey::from_private_key(private_key);
        Address::from_public_key(&public_key)
    }

    // Gets the raw address as a slice of bytes.
    pub fn get_data(&self) -> &[u8] {
        let Address(ref data) = *self;
        data.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use serialize::hex::FromHex;

    use util::base58;
    use protocol::public_key::PublicKey;
    use protocol::private_key::PrivateKey;

    use super::Address;

    #[test]
    fn test_new() {
        let data = base58::decode("19gL5Rq1uc5yspAtbM7NyDs1godKnGHMar").unwrap();
        let address = Address::new(data.as_slice());
        assert!(address.is_some());
        assert_eq!(address.unwrap().get_data(), data.as_slice());
    }

    #[test]
    fn test_new_invalid_checksum() {
        let data = base58::decode("18gL5Rq1uc5yspAtbM7NyDs1godKnGHMar").unwrap();
        let address = Address::new(data.as_slice());
        assert!(address.is_none());
    }

    #[test]
    fn test_from_public_key() {
        let data = "04EB4EA815229359CEC3965507FF68F8B3C7B8632FF9ABD46A06520A838C468AFC\
                      5B2EB3588549E626200A698D38966B38498EB27CBAAADE5EEE6DEF01DF061F73";
        let data = data.from_hex().unwrap();
        let public_key = PublicKey::new(data.as_slice()).unwrap();
        let address = Address::from_public_key(&public_key);
        let address_base58 = base58::encode(address.get_data());
        assert_eq!(address_base58.as_slice(), "1BN7qZoGjmpwD3nSLrFy6xfdDQbTvQDUbs");
    }

    #[test]
    fn test_from_private_key() {
        let data = "F704C5F491F6B1235E6571AD10157A29782A71DF33A8FD7298A50B5CF0A65281";
        let data = data.from_hex().unwrap();
        let private_key = PrivateKey::new(data.as_slice()).unwrap();
        let address = Address::from_private_key(&private_key);
        let address_base58 = base58::encode(address.get_data());
        assert_eq!(address_base58.as_slice(), "19pXLZXnPJjN1h2EWjzodArVV867Vqpo6p");
    }
}

