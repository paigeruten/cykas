use libc::{c_int, c_uchar, size_t};
use std::ptr;

static NID_secp256k1: int = 714i;

#[allow(non_camel_case_types)]
struct EC_GROUP;

#[allow(non_camel_case_types)]
struct EC_POINT;

#[allow(non_camel_case_types)]
struct BIGNUM;

#[allow(non_camel_case_types)]
struct BN_CTX;

#[allow(non_camel_case_types)]
enum point_conversion_form_t {
    POINT_CONVERSION_COMPRESSED = 2,
    POINT_CONVERSION_UNCOMPRESSED = 4,
    POINT_CONVERSION_HYBRID = 6
}

#[link(name = "crypto")]
extern {
    fn EC_POINT_new(group: *const EC_GROUP) -> *mut EC_POINT;
    fn EC_POINT_free(point: *mut EC_POINT);
    fn EC_POINT_mul(group: *const EC_GROUP, r: *mut EC_POINT, n: *const BIGNUM, q: *const EC_POINT, m: *const BIGNUM, ctx: *mut BN_CTX) -> c_int;
    fn EC_POINT_point2oct(group: *const EC_GROUP, p: *const EC_POINT, form: point_conversion_form_t, buf: *mut c_uchar, len: size_t, ctx: *mut BN_CTX) -> size_t;

    fn EC_GROUP_new_by_curve_name(nid: c_int) -> *mut EC_GROUP;

    fn BN_new() -> *mut BIGNUM;
    fn BN_free(a: *mut BIGNUM);
    fn BN_bin2bn(s: *const c_uchar, len: c_int, ret: *mut BIGNUM) -> *mut BIGNUM;

    fn BN_CTX_new() -> *mut BN_CTX;
    fn BN_CTX_free(c: *mut BN_CTX);
}

pub fn derive_public_key(private_key: &[u8]) -> Vec<u8> {
    unsafe {
        let priv_key = BN_bin2bn(private_key.as_ptr(), private_key.len() as c_int, BN_new());
        let curve = EC_GROUP_new_by_curve_name(NID_secp256k1 as c_int) as *const EC_GROUP;
        let ctx = BN_CTX_new();

        let pub_key = EC_POINT_new(curve);
        EC_POINT_mul(curve, pub_key, priv_key as *const BIGNUM, ptr::null(), ptr::null(), ctx);

        let mut result = Vec::from_elem(65, 0u8);
        EC_POINT_point2oct(curve, pub_key as *const EC_POINT, POINT_CONVERSION_UNCOMPRESSED, result.as_mut_ptr(), 65, ctx);
        *result.get_mut(0) = 0x04;

        BN_CTX_free(ctx);
        EC_POINT_free(pub_key);
        BN_free(priv_key);

        result
    }
}

