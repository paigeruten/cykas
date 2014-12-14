//! Base-58 encoding and decoding.

use num::Zero;
use num::bigint::{BigUint,ToBigUint};
use num::Integer;

// Bitcoin's base-58 alphabet.
static ALPHABET: &'static str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode a slice of bytes as base-58, preserving leading zero bytes.
pub fn encode(data: &[u8]) -> String {
    // Count the leading zeroes.
    let num_zeroes = data.iter().take_while(|byte| byte.is_zero()).count();

    // Convert data to a BigUint.
    let mut n = 0u.to_biguint().unwrap();
    for (idx, byte) in data.iter().rev().enumerate() {
        let byte = byte.to_biguint().unwrap();
        n = n + (byte << (idx * 8)); // Fast way of doing byte * (256 ^ idx).
    }

    // Convert that to a base-58 string.
    let base58 = simple_encode(n);

    // Allocate the result string.
    let mut result = String::with_capacity(base58.len() + num_zeroes);

    // First push a '1' character for each leading zero byte we wanted to
    // preserve.
    for _ in range(0, num_zeroes) {
        result.push('1');
    }

    // Append the base-58 after that.
    result.push_str(base58.as_slice());

    // Return the result.
    result
}

/// Decode a base-58 string into a vector of bytes, preserving leading zero
/// bytes. Returns None if the string contains non-base-58 characters.
pub fn decode(string: &str) -> Option<Vec<u8>> {
    // Count the leading zeroes ('1' characters in base-58).
    let num_zeroes = string.chars().take_while(|ch| *ch == '1').count();

    // Convert string to a BigUint, returning None if it failed.
    let mut n = match simple_decode(string) {
        Some(n) => n,
        None => return None
    };

    // Convert BigUint to a vector of bytes.
    let mut result = Vec::new();
    let byte_mask = 0xff_u8.to_biguint().unwrap();
    while !n.is_zero() {
        let byte = n & byte_mask;
        result.push(byte.to_u8().unwrap());
        n = n >> 8;
    }

    // Push a zero byte for each leading '1' character we wanted to preserve.
    for _ in range(0, num_zeroes) {
        result.push(0);
    }

    // Put the result in the right order and return.
    result.reverse();
    Some(result)
}

/// Encode a number as base-58.
pub fn simple_encode(mut n: BigUint) -> String {
    let mut result = String::new();
    let fifty_eight = 58u.to_biguint().unwrap();
    while !n.is_zero() {
        let (rest_of_n, digit) = n.div_rem(&fifty_eight);
        result.push(ALPHABET.char_at(digit.to_uint().unwrap()));
        n = rest_of_n;
    }

    // That got us a reversed string, so reverse it back before returning it.
    result.as_slice().chars().rev().collect()
}

/// Decode a base-58 string into a number. Returns None if the string contains
/// non-base-58 characters.
pub fn simple_decode(string: &str) -> Option<BigUint> {
    let mut result: BigUint = 0u.to_biguint().unwrap();
    let mut multiplier: BigUint = 1u.to_biguint().unwrap();
    let fifty_eight = 58u.to_biguint().unwrap();
    for digit in string.chars().rev() {
        let value = ALPHABET.chars().position(|ch| ch == digit );
        if value.is_none() { return None }
        result = result + value.unwrap().to_biguint().unwrap() * multiplier;
        multiplier = multiplier * fifty_eight;
    }

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::{encode,decode};

    #[test]
    fn test_encode_bitcoin_addresses() {
        // Normal Bitcoin address.
        let data = &[0x00,0x78,0x97,0x0e,0x37,0xa7,0xa4,0x71,0xdc,0x33,0xda,0xdb,
                     0x51,0x42,0x06,0x84,0x31,0xb4,0x85,0x17,0xab,0x00,0xed,0xb1,0x45];
        assert_eq!(encode(data).as_slice(), "1Bzd3YTSDwdFfAhMwYNV6A3K5hwYHbaUeG");

        // Bitcoin address that starts with two 1's.
        let data = &[0x00,0x00,0x51,0x34,0xda,0xfd,0x60,0x2d,0xcc,0x55,0x36,0x87,
                     0x06,0xd7,0x56,0xc7,0x4f,0xb7,0x74,0x48,0x31,0xf3,0x22,0xdc,0xe3];
        assert_eq!(encode(data).as_slice(), "112gHKoeKQ3PEXEdAZeC5tBoonPR2UCQot");

        // Bitcoin address that starts with three 1's (took a while to find
        // this one).
        let data = &[0x00,0x00,0x00,0x23,0xc5,0x36,0xed,0x86,0x7d,0x66,0xa0,0x6b,
                     0x5a,0xfe,0x67,0x5d,0xe8,0xcb,0xe9,0x03,0x94,0x33,0xe5,0x57,0x3d];
        assert_eq!(encode(data).as_slice(), "111Ai6JPjhcuWxu6ULnRtk34cEj2ZJXfa");
    }

    #[test]
    fn test_encode_out_of_bounds() {
        // This test case caused an out of bounds bug at one point.
        let data = &[0x00,0xc3,0xd2,0x6e,0xc2,0x04,0x8a,0x9f,0x52,0x8f,0xfb,0xbf,
                     0xf4,0xb8,0x08,0xaf,0x16,0x7e,0x12,0xac,0x82,0x5b,0x40,0x2b,0xb2];
        encode(data);
    }

    #[test]
    fn test_encode_zeroes() {
        let data = &[0x00,0x00,0x00,0x00];
        assert_eq!(encode(data).as_slice(), "1111");
    }

    #[test]
    fn test_decode_bitcoin_addresses() {
        // Normal Bitcoin address.
        let data: &[u8] = &[0x00,0x78,0x97,0x0e,0x37,0xa7,0xa4,0x71,0xdc,0x33,0xda,0xdb,
                            0x51,0x42,0x06,0x84,0x31,0xb4,0x85,0x17,0xab,0x00,0xed,0xb1,0x45];
        assert_eq!(decode("1Bzd3YTSDwdFfAhMwYNV6A3K5hwYHbaUeG").unwrap().as_slice(), data);

        // Bitcoin address that starts with two 1's.
        let data: &[u8] = &[0x00,0x00,0x51,0x34,0xda,0xfd,0x60,0x2d,0xcc,0x55,0x36,0x87,
                            0x06,0xd7,0x56,0xc7,0x4f,0xb7,0x74,0x48,0x31,0xf3,0x22,0xdc,0xe3];
        assert_eq!(decode("112gHKoeKQ3PEXEdAZeC5tBoonPR2UCQot").unwrap().as_slice(), data);

        // Bitcoin address that starts with three 1's (took a while to find
        // this one).
        let data: &[u8] = &[0x00,0x00,0x00,0x23,0xc5,0x36,0xed,0x86,0x7d,0x66,0xa0,0x6b,
                            0x5a,0xfe,0x67,0x5d,0xe8,0xcb,0xe9,0x03,0x94,0x33,0xe5,0x57,0x3d];
        assert_eq!(decode("111Ai6JPjhcuWxu6ULnRtk34cEj2ZJXfa").unwrap().as_slice(), data);
    }

    #[test]
    fn test_decode_zeroes() {
        let data: &[u8] = &[0x00,0x00,0x00,0x00];
        assert_eq!(decode("1111").unwrap().as_slice(), data);
    }

    #[test]
    fn test_decode_invalid() {
        assert!(decode("123OI321").is_none());
        assert!(decode("123 321").is_none());
    }
}

