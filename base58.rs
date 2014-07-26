use num::bigint::ToBigUint;
use num::Integer;

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

