use libc::c_int;

#[link(name = "crypto")]
extern {
    fn PKCS5_PBKDF2_HMAC_SHA1(pass: *const u8, passlen: c_int,
                              salt: *const u8, saltlen: c_int,
                              iter: c_int, keylen: c_int,
                              out: *mut u8) -> c_int;
}

pub fn pbkdf2_hmac_sha1(pass: &str, salt: &[u8], iter: uint, keylen: uint) -> Vec<u8> {
    unsafe {
        assert!(iter >= 1);
        assert!(keylen >= 1);

        let mut out = Vec::with_capacity(keylen);

        let r = PKCS5_PBKDF2_HMAC_SHA1(
                    pass.as_ptr(), pass.len() as c_int,
                    salt.as_ptr(), salt.len() as c_int,
                    iter as c_int, keylen as c_int,
                    out.as_mut_ptr());

        if r != 1 { fail!(); }

        out.set_len(keylen);
        out
    }
}

