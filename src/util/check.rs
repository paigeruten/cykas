use openssl;
use openssl::crypto::hash::SHA256;

pub fn checksum(data: &[u8]) -> Vec<u8> {
    let double_hash = double_sha256(data);
    double_hash.slice(0, 4).to_vec()
}

fn double_sha256(data: &[u8]) -> Vec<u8> {
    let first_hash = openssl::crypto::hash::hash(SHA256, data);
    openssl::crypto::hash::hash(SHA256, first_hash.as_slice())
}

