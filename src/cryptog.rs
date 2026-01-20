use openssl::{error::ErrorStack, symm::{Cipher, decrypt, encrypt}};
use rand::rand_core::block;

#[allow(dead_code)]
pub fn aes_128_ecb_encrypt(key :&[u8], plaintext: &[u8]) -> Result<Vec<u8>,ErrorStack> {
  encrypt(Cipher::aes_128_ecb(), key, None, plaintext)
}

pub fn aes_128_ecb_decrypt(key :&[u8], ciphertext: &[u8]) -> Result<Vec<u8>,ErrorStack> {
  decrypt(Cipher::aes_128_ecb(), key, None, ciphertext)
}



pub fn pkcs7_padding(data :&mut Vec<u8>,block_size:usize){
  if data.len() == 0 {
    data.clone_from(&vec![block_size as u8;block_size]);
  }
  let padding = (data.len() % block_size).abs_diff(block_size);
  if padding != block_size{
    data.append(&mut vec![padding as u8;padding]);
  }
}
