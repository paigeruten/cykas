//! Bitcoin Wallet Import Format (WIF) encoding, decoding, and checking.

use openssl;
use openssl::crypto::hash::HashType::SHA256;

// The length of checksums used in the Wallet Import Format.
static CHECKSUM_LENGTH: uint = 4;

/// Encode the given data in Wallet Import Format.
pub fn encode(data: &[u8], version_byte: u8) -> Vec<u8> {
    let mut result = Vec::with_capacity(1 + data.len() + CHECKSUM_LENGTH);

    result.push(version_byte);
    result.push_all(data);

    let checksum = checksum(result.as_slice());
    result.push_all(checksum.as_slice());

    result
}

/// Decode the given data from Wallet Import Format, by validating the version
/// byte and checksum, and then stripping those off and returning what's left.
pub fn decode(data: &[u8], version_byte: u8) -> Option<Vec<u8>> {
    let valid = data.len() >= 1 + CHECKSUM_LENGTH &&
                data[0] == version_byte &&
                check(data);

    if valid {
        Some(data.slice(1, data.len() - CHECKSUM_LENGTH).to_vec())
    } else {
        None
    }
}

/// Checks whether the given data satisfies the checksum. (Assumes the last four
/// bytes of the slice is the checksum.)
pub fn check(data: &[u8]) -> bool {
    assert!(data.len() > CHECKSUM_LENGTH);
    let (payload, given_checksum) = data.split_at(data.len() - CHECKSUM_LENGTH);
    checksum(payload).as_slice() == given_checksum
}

// Computes a checksum of the given data.
fn checksum(data: &[u8]) -> Vec<u8> {
    let double_hash = double_sha256(data);
    double_hash.slice(0, 4).to_vec()
}

// Performs a double SHA256 hash of the given data.
fn double_sha256(data: &[u8]) -> Vec<u8> {
    let first_hash = openssl::crypto::hash::hash(SHA256, data);
    openssl::crypto::hash::hash(SHA256, first_hash.as_slice())
}

#[cfg(test)]
mod tests {
    use serialize::hex::FromHex;

    use super::{encode, decode, check, checksum, double_sha256};

    #[test]
    fn test_encode() {
        let data = b"abc";
        let wif = encode(data.as_slice(), 0xff);
        assert_eq!(wif.as_slice(), b"\xFFabc\x6E\x16\xC9\x0D");
    }

    #[test]
    fn test_encode_empty_string() {
        let data = b"";
        let wif = encode(data.as_slice(), 0xff);
        assert_eq!(wif.as_slice(), b"\xFF\xC0\xB0\x57\xF5");
    }

    #[test]
    fn test_decode() {
        let wif = b"\xFFabc\x6E\x16\xC9\x0D";
        let data = decode(wif.as_slice(), 0xff);
        assert!(data.is_some());
        assert_eq!(data.unwrap().as_slice(), b"abc");
    }

    #[test]
    fn test_decode_empty_string() {
        let wif = b"\xFF\xC0\xB0\x57\xF5";
        let data = decode(wif.as_slice(), 0xff);
        assert!(data.is_some());
        assert_eq!(data.unwrap().as_slice(), b"");
    }

    #[test]
    fn test_decode_invalid_version_byte() {
        let wif = b"\xFEabc\x6E\x16\xC9\x0D";
        let data = decode(wif.as_slice(), 0xff);
        assert!(data.is_none());
    }

    #[test]
    fn test_decode_invalid_checksum() {
        let wif = b"\xFFabd\x6E\x16\xC9\x0D";
        let data = decode(wif.as_slice(), 0xff);
        assert!(data.is_none());
    }

    #[test]
    fn test_check() {
        let data = "00010966776006953D5567439E5E39F86A0D273BEED61967F6".from_hex().unwrap();
        assert!(check(data.as_slice()));

        let data = "10010966776006953D5567439E5E39F86A0D273BEED61967F6".from_hex().unwrap();
        assert!(!check(data.as_slice()));
    }

    #[test]
    fn test_checksum() {
        let data = "00010966776006953D5567439E5E39F86A0D273BEE".from_hex().unwrap();
        let expected = "D61967F6".from_hex().unwrap();
        assert_eq!(checksum(data.as_slice()), expected);
    }

    #[test]
    fn test_double_sha256() {
        let data = "00010966776006953D5567439E5E39F86A0D273BEE".from_hex().unwrap();
        let expected = "D61967F63C7DD183914A4AE452C9F6AD5D462CE3D277798075B107615C1A8A30";
        let expected = expected.from_hex().unwrap();
        assert_eq!(double_sha256(data.as_slice()), expected);
    }
}

