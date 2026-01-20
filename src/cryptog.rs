use openssl::{error::ErrorStack, symm::{Cipher, decrypt, encrypt}};

#[allow(dead_code)]
pub fn aes_128_ecb_encrypt(key :&[u8], plaintext: &[u8]) -> Result<Vec<u8>,ErrorStack> {
  encrypt(Cipher::aes_128_ecb(), key, None, plaintext)
}

pub fn aes_128_ecb_decrypt(key :&[u8], ciphertext: &[u8]) -> Result<Vec<u8>,ErrorStack> {
  decrypt(Cipher::aes_128_ecb(), key, None, ciphertext)
}
