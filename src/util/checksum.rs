use openssl;
use openssl::crypto::hash::SHA256;

// The length of checksums used in Bitcoin addresses and Wallet Import Format
// (WIF) private keys.
static LENGTH: uint = 4;

// Checks whether the given data satisfies the checksum. (Assumes the last four
// bytes of the slice is the checksum.)
pub fn check(data: &[u8]) -> bool {
    let (payload, given_checksum) = data.split_at(data.len() - LENGTH);
    checksum(payload).as_slice() == given_checksum
}

// Computes a checksum of the given data.
pub fn checksum(data: &[u8]) -> Vec<u8> {
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

    use super::{check, checksum, double_sha256};

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

