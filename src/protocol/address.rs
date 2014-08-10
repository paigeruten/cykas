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
        let data_without_checksum = self.data.slice(0, 21);
        let expected_checksum = util::check::checksum(data_without_checksum);

        self.data.len() == LENGTH &&
        self.data[0] == VERSION_BYTE &&
        self.data.slice(21, 25) == expected_checksum.as_slice()
    }

    // Gets the raw data as a slice of bytes.
    pub fn get_data(&self) -> &[u8] {
        self.data.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use serialize::hex::FromHex;

    use util;
    use protocol::public_key::PublicKey;
    use protocol::private_key::PrivateKey;

    use super::Address;

    #[test]
    fn test_new() {
        let data = util::base58::decode("19gL5Rq1uc5yspAtbM7NyDs1godKnGHMar");
        let address = Address::new(data.as_slice());
        assert!(address.is_some());
        assert_eq!(address.unwrap().get_data(), data.as_slice());
    }

    #[test]
    fn test_new_invalid_checksum() {
        let data = util::base58::decode("19gL5Rq1uc5yspAtbM7NyDs1godKnGHMas");
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
        let address_base58 = util::base58::encode(address.get_data());
        assert_eq!(address_base58.as_slice(), "1BN7qZoGjmpwD3nSLrFy6xfdDQbTvQDUbs");
    }

    #[test]
    fn test_from_private_key() {
        let data = "F704C5F491F6B1235E6571AD10157A29782A71DF33A8FD7298A50B5CF0A65281";
        let data = data.from_hex().unwrap();
        let private_key = PrivateKey::new(data.as_slice()).unwrap();
        let address = Address::from_private_key(&private_key);
        let address_base58 = util::base58::encode(address.get_data());
        assert_eq!(address_base58.as_slice(), "19pXLZXnPJjN1h2EWjzodArVV867Vqpo6p");
    }
}

