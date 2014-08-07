use std::num::Zero;
use num::bigint::{BigUint,ToBigUint};
use num::Integer;

static ALPHABET: &'static str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Converts `data` to a base-58 string, that can be decoded by decode().
pub fn encode(data: &[u8]) -> String {
    // Count the number of zero bytes at the beginning of the data. In the
    // Bitcoin base-58 format, leading zero bytes are treated separately. After
    // the real base-58 conversion, they will be added back as '1' characters.
    let mut num_zeroes = 0u;
    for byte in data.iter() {
        if *byte == 0 {
            num_zeroes += 1;
        } else {
            break;
        }
    }

    // Disregard the leading zero bytes for the actual base-58 conversion.
    let data = data.slice_from(num_zeroes);

    // Convert data to a BigUint.
    let mut n: BigUint = Zero::zero();
    for (idx, byte) in data.iter().rev().enumerate() {
        let byte = byte.to_biguint().unwrap();
        n = n + (byte << (idx * 8)); // Fast way of doing byte * (256 ^ idx).
    }

    // Convert the number to a (reversed) string using repeated division.
    let mut result = String::new();
    let fifty_eight = 58u.to_biguint().unwrap();
    while !n.is_zero() {
        // Using integer division, chop off a piece of the big number that can
        // have one of 58 values, and use it as the next digit in the result
        // string. The rest of the number becomes the new `n`.
        let (rest_of_n, digit) = n.div_rem(&fifty_eight);
        result.push_char(ALPHABET.char_at(digit.to_uint().unwrap()));
        n = rest_of_n;
    }

    // Push a '1' character for each zero byte that we removed at the beginning
    // of this method.
    for _ in range(0, num_zeroes) {
        result.push_char('1');
    }

    // Finally, reverse the string and return it.
    result.as_slice().chars().rev().collect()
}

// Converts a base-58 string back to the data it represents, as a vector of
// bytes.
pub fn decode(string: &str) -> Vec<u8> {
    // Count the number of leading zeroes at the beginning of the string. Each
    // leading zero (which appears as '1' in base-58) represents one zero-byte
    // at the beginning of the decoded data, so we treat these separately
    // before beginning the base-58 conversion.
    let mut num_zeroes = 0u;
    for digit in string.chars() {
        if digit == '1' {
            num_zeroes += 1;
        } else {
            break;
        }
    }

    // Reslice the string to disregard the zeroes we just made a note of.
    let string = string.slice_chars(num_zeroes, string.len());

    // Convert the base-58 string to a BigUint, by multiplying each digit by
    // successive powers of 58 and adding all the resulting parts together.
    let mut n: BigUint = Zero::zero();
    let mut multiplier: BigUint = 1u.to_biguint().unwrap();
    let fifty_eight = 58u.to_biguint().unwrap();
    for digit in string.chars().rev() {
        let digit = ALPHABET.chars().position(|ch| ch == digit ).unwrap();
        n = n + digit.to_biguint().unwrap() * multiplier;
        multiplier = multiplier * fifty_eight;
    }

    // Convert the number to a (reversed) vector of bytes by repeatedly using a
    // bitmask on the lowest byte of the BigUint.
    let mut result = Vec::new();
    let byte_mask = 0xffu8.to_biguint().unwrap();
    while !n.is_zero() {
        let byte = n & byte_mask;
        result.push(byte.to_u8().unwrap());
        n = n >> 8;
    }

    // Push a zero byte for each zero digit we removed from the original string
    // at the beginning of this method.
    for _ in range(0, num_zeroes) {
        result.push(0);
    }

    // Put the vector in the right order before returning it.
    result.reverse();
    result
}

#[cfg(test)]
mod tests {
    use super::{encode,decode};

    #[test]
    fn test_encode_bitcoin_addresses() {
        // Normal Bitcoin address.
        let data = [0x00,0x78,0x97,0x0e,0x37,0xa7,0xa4,0x71,0xdc,0x33,0xda,0xdb,
                    0x51,0x42,0x06,0x84,0x31,0xb4,0x85,0x17,0xab,0x00,0xed,0xb1,0x45];
        assert_eq!(encode(data).as_slice(), "1Bzd3YTSDwdFfAhMwYNV6A3K5hwYHbaUeG");

        // Bitcoin address that starts with two 1's.
        let data = [0x00,0x00,0x51,0x34,0xda,0xfd,0x60,0x2d,0xcc,0x55,0x36,0x87,
                    0x06,0xd7,0x56,0xc7,0x4f,0xb7,0x74,0x48,0x31,0xf3,0x22,0xdc,0xe3];
        assert_eq!(encode(data).as_slice(), "112gHKoeKQ3PEXEdAZeC5tBoonPR2UCQot");

        // Bitcoin address that starts with three 1's (took a while to find
        // this one).
        let data = [0x00,0x00,0x00,0x23,0xc5,0x36,0xed,0x86,0x7d,0x66,0xa0,0x6b,
                    0x5a,0xfe,0x67,0x5d,0xe8,0xcb,0xe9,0x03,0x94,0x33,0xe5,0x57,0x3d];
        assert_eq!(encode(data).as_slice(), "111Ai6JPjhcuWxu6ULnRtk34cEj2ZJXfa");
    }

    #[test]
    fn test_encode_out_of_bounds() {
        // This test case caused an out of bounds bug at one point.
        let data = [0x00,0xc3,0xd2,0x6e,0xc2,0x04,0x8a,0x9f,0x52,0x8f,0xfb,0xbf,
                    0xf4,0xb8,0x08,0xaf,0x16,0x7e,0x12,0xac,0x82,0x5b,0x40,0x2b,0xb2];
        encode(data);
    }

    #[test]
    fn test_encode_zeroes() {
        let data = [0x00,0x00,0x00,0x00];
        assert_eq!(encode(data).as_slice(), "1111");
    }

    #[test]
    fn test_decode_bitcoin_addresses() {
        // Normal Bitcoin address.
        let data: &[u8] = &[0x00u8,0x78,0x97,0x0e,0x37,0xa7,0xa4,0x71,0xdc,0x33,0xda,0xdb,
                            0x51,0x42,0x06,0x84,0x31,0xb4,0x85,0x17,0xab,0x00,0xed,0xb1,0x45];
        assert_eq!(decode("1Bzd3YTSDwdFfAhMwYNV6A3K5hwYHbaUeG").as_slice(), data);

        // Bitcoin address that starts with two 1's.
        let data: &[u8] = &[0x00,0x00,0x51,0x34,0xda,0xfd,0x60,0x2d,0xcc,0x55,0x36,0x87,
                            0x06,0xd7,0x56,0xc7,0x4f,0xb7,0x74,0x48,0x31,0xf3,0x22,0xdc,0xe3];
        assert_eq!(decode("112gHKoeKQ3PEXEdAZeC5tBoonPR2UCQot").as_slice(), data);

        // Bitcoin address that starts with three 1's (took a while to find
        // this one).
        let data: &[u8] = &[0x00,0x00,0x00,0x23,0xc5,0x36,0xed,0x86,0x7d,0x66,0xa0,0x6b,
                            0x5a,0xfe,0x67,0x5d,0xe8,0xcb,0xe9,0x03,0x94,0x33,0xe5,0x57,0x3d];
        assert_eq!(decode("111Ai6JPjhcuWxu6ULnRtk34cEj2ZJXfa").as_slice(), data);
    }

    #[test]
    fn test_decode_zeroes() {
        let data: &[u8] = &[0x00,0x00,0x00,0x00];
        assert_eq!(decode("1111").as_slice(), data);
    }
}

