use libc::c_uint;
use std::ptr;

enum HashType {
    SHA256,
    RIPEMD160
}

#[allow(non_camel_case_types)]
struct EVP_MD_CTX;

#[allow(non_camel_case_types)]
struct EVP_MD;

#[link(name = "crypto")]
extern {
    fn EVP_MD_CTX_create() -> *mut EVP_MD_CTX;
    fn EVP_MD_CTX_destroy(ctx: *mut EVP_MD_CTX);

    fn EVP_sha256() -> *const EVP_MD;
    fn EVP_ripemd160() -> *const EVP_MD;

    fn EVP_DigestInit(ctx: *mut EVP_MD_CTX, typ: *const EVP_MD);
    fn EVP_DigestUpdate(ctx: *mut EVP_MD_CTX, data: *const u8, n: c_uint);
    fn EVP_DigestFinal(ctx: *mut EVP_MD_CTX, res: *mut u8, n: *mut u32);
}

fn hash_len(typ: HashType) -> uint {
    match typ {
        SHA256 => 32,
        RIPEMD160 => 20
    }
}

fn hash_evp(typ: HashType) -> *const EVP_MD {
    unsafe {
        match typ {
            SHA256 => EVP_sha256(),
            RIPEMD160 => EVP_ripemd160()
        }
    }
}

fn hash(typ: HashType, data: &[u8]) -> Vec<u8> {
    unsafe {
        let ctx = EVP_MD_CTX_create();
        let evp = hash_evp(typ);
        let mut result = Vec::from_elem(hash_len(typ), 0u8);
        EVP_DigestInit(ctx, evp);
        EVP_DigestUpdate(ctx, data.as_ptr(), data.len() as c_uint);
        EVP_DigestFinal(ctx, result.as_mut_ptr(), ptr::mut_null());
        EVP_MD_CTX_destroy(ctx);
        result
    }
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    hash(SHA256, data)
}

pub fn ripemd160(data: &[u8]) -> Vec<u8> {
    hash(RIPEMD160, data)
}

