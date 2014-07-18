use num::bigint::ToBigUint;
use num::Integer;
use crypto::ecdsa::derive_public_key;
use crypto::hash::{sha256, ripemd160};

static BASE58_ALPHABET: &'static str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn to_base58(data: &[u8]) -> String {
    let mut n = 0u.to_biguint().unwrap();
    for (i, c) in data.iter().rev().enumerate() {
        let c = c.to_biguint().unwrap();
        n = n + (c << (i * 8));
    }

    let mut result = String::new();
    let limit = 58u.to_biguint().unwrap();
    while n >= limit {
        let (d, r) = n.div_rem(&limit);
        let r = r.to_uint().unwrap();

        n = d;
        result.push_char(BASE58_ALPHABET.char_at(r));
    }
    let r = n.to_uint().unwrap();

    if r > 0 {
        result.push_char(BASE58_ALPHABET.char_at(r));
    }

    while result.as_slice().char_at(0) == '1' {
        result.shift_char();
    }

    for c in data.iter() {
        if *c == 0 {
            result.push_char(BASE58_ALPHABET.char_at(0));
        } else {
            break;
        }
    }

    result.as_slice().chars().rev().collect()
}

pub fn address_from_private_key(priv_key: &[u8]) -> String {
    let pub_key = derive_public_key(priv_key);
    let pub_key_sha = sha256(pub_key.as_slice());
    let mut pub_key_sha_rmd = ripemd160(pub_key_sha.as_slice());
    pub_key_sha_rmd.unshift(0x00);
    let pub_key_sha_rmd_sha = sha256(pub_key_sha_rmd.as_slice());
    let pub_key_sha_rmd_sha_sha = sha256(pub_key_sha_rmd_sha.as_slice());
    let address_checksum = pub_key_sha_rmd_sha_sha.slice(0, 4);
    pub_key_sha_rmd.push_all(address_checksum);
    to_base58(pub_key_sha_rmd.as_slice())
}

