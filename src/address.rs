use openssl;
use ecdsa;
use base58;

type PrivateKey = Vec<u8>;

static PRIVATE_KEY_LENGTH: uint = 32u;
/*
static MAX_PRIVATE_KEY: &'static [u8] = [
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x40
];

static ZERO_PRIVATE_KEY: &'static [u8] = [
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
];*/

pub struct Address {
    private_key: PrivateKey
}

impl Address {
    pub fn new(private_key: PrivateKey) -> Address {
        if !Address::is_valid_private_key(private_key.clone()) {
            fail!("Invalid private key!");
        }

        Address { private_key: private_key.clone() }
    }

    pub fn gen() -> Address {
        let mut key;
        loop {
            key = openssl::crypto::rand::rand_bytes(PRIVATE_KEY_LENGTH);
            if Address::is_valid_private_key(key.clone()) { break; }
        }
        Address { private_key: key }
    }

    fn is_valid_private_key(private_key: PrivateKey) -> bool {
        private_key.len() == PRIVATE_KEY_LENGTH &&
        private_key > vec!(
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        ) &&
        private_key <= vec!(
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
            0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
            0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x40
        )
        // The above range for private keys is dicated by the secp256k1 curve
        // used by the Bitcoin protocol.
    }

    pub fn to_string(&self) -> String {
        let pub_key = ecdsa::derive_public_key(self.private_key.as_slice());
        let pub_key_hash = openssl::crypto::hash::hash(openssl::crypto::hash::SHA256, pub_key.as_slice());
        let mut pub_key_rmd = openssl::crypto::hash::hash(openssl::crypto::hash::RIPEMD160, pub_key_hash.as_slice());
        pub_key_rmd.insert(0, 0x00);
        let mut double_hash = openssl::crypto::hash::hash(openssl::crypto::hash::SHA256, pub_key_rmd.as_slice());
        double_hash = openssl::crypto::hash::hash(openssl::crypto::hash::SHA256, double_hash.as_slice());
        let address_checksum = double_hash.slice(0, 4);
        pub_key_rmd.push_all(address_checksum);
        base58::to_base58(pub_key_rmd.as_slice())
    }
}

