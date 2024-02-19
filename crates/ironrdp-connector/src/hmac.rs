use hmac::{Hmac, Mac};
use md5::Md5;

type HmacMD5 = Hmac<Md5>;


fn new_hmac_md5(key: &[u8]) -> HmacMD5 {
    HmacMD5::new_from_slice(key).unwrap()
}

pub fn hmac(key: &[u8], data: &[u8]) -> [u8; 16]{
    let mut mac = new_hmac_md5(key);
    mac.update(data);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use crate::hmac::hmac;
    #[test]
    fn vector1() {
        let key = vec![0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb];
        let data = b"Hi There";
        assert_eq!(hmac(&key, data), [0x92u8, 0x94u8, 0x72u8, 0x7au8, 0x36u8, 0x38u8, 0xbbu8, 0x1cu8, 0x13u8, 0xf4u8, 0x8eu8, 0xf8u8, 0x15u8, 0x8bu8, 0xfcu8, 0x9du8]);
    }

    #[test]
    fn vector2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        assert_eq!(hmac(key, data), [0x75u8, 0x0cu8, 0x78u8, 0x3eu8, 0x6au8, 0xb0u8, 0xb5u8, 0x03u8, 0xeau8, 0xa8u8, 0x6eu8, 0x31u8, 0x0au8, 0x5du8, 0xb7u8, 0x38u8]);
    }
}