use libc::{c_int, c_uint};
use libc;

#[allow(non_camel_case_types)]
pub type EVP_CIPHER_CTX = *mut libc::c_void;

#[allow(non_camel_case_types)]
pub type EVP_CIPHER = *mut libc::c_void;

#[link(name = "crypto")]
extern {
    fn EVP_CIPHER_CTX_new() -> EVP_CIPHER_CTX;
    fn EVP_CIPHER_CTX_free(ctx: EVP_CIPHER_CTX);

    fn EVP_aes_256_cbc() -> EVP_CIPHER;

    fn EVP_CipherInit(ctx: EVP_CIPHER_CTX, evp: EVP_CIPHER, key: *const u8, iv: *const u8, mode: c_int);
    fn EVP_CipherUpdate(ctx: EVP_CIPHER_CTX, outbuf: *mut u8, outlen: &mut c_uint, inbuf: *const u8, inlen: c_int);
    fn EVP_CipherFinal(ctx: EVP_CIPHER_CTX, res: *mut u8, len: &mut c_int);
}

pub enum Mode {
    Encrypt,
    Decrypt
}

pub fn aes256cbc(mode: Mode, key: &[u8], iv: Vec<u8>, data: &[u8]) -> Vec<u8> {
    unsafe {
        let ctx = EVP_CIPHER_CTX_new();
        let evp = EVP_aes_256_cbc();
        let keylen = 32u;
        let blocksize = 16u;
        let mode = match mode {
            Encrypt => 1 as c_int,
            Decrypt => 0 as c_int
        };
        assert_eq!(key.len(), keylen);

        EVP_CipherInit(ctx, evp, key.as_ptr(), iv.as_ptr(), mode); // FIXME: This segfaults. Okay?

        let mut res = Vec::from_elem(data.len() + blocksize, 0u8);
        let mut reslen = (data.len() + blocksize) as u32;

        EVP_CipherUpdate(ctx, res.as_mut_ptr(), &mut reslen, data.as_ptr(), data.len() as c_int);
        
        res.truncate(reslen as uint);

        let mut rest = Vec::from_elem(blocksize, 0u8);
        let mut restlen = blocksize as c_int;

        EVP_CipherFinal(ctx, rest.as_mut_ptr(), &mut restlen);
        EVP_CIPHER_CTX_free(ctx);

        rest.truncate(restlen as uint);
        res.append(rest.as_slice())
    }
}

