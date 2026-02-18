use openssl::{
  error::ErrorStack, symm::{Cipher, Crypter}
};

use crate::xor::{self, xor_fixed_length};

#[derive(Debug, Clone,PartialEq)]
pub struct InvalidPadding {

}

#[allow(dead_code)]
pub fn aes_128_ecb_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, ErrorStack> {
  let cipher = Cipher::aes_128_ecb();
  let mut crypter = Crypter::new(cipher, openssl::symm::Mode::Encrypt, key, None)?;

  crypter.pad(false);
  let mut out = vec![0; plaintext.len() + cipher.block_size()];
  let n = crypter.update(plaintext, &mut out)?;
  let m = crypter.finalize(&mut out)?;

  Ok(out[0..n + m].to_owned())
}

pub fn aes_128_ecb_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ErrorStack> {
  let cipher = Cipher::aes_128_ecb();
  let mut crypter = Crypter::new(cipher, openssl::symm::Mode::Decrypt, key, None)?;
  crypter.pad(false);
  let mut out = vec![0; ciphertext.len() + cipher.block_size()];
  let n = crypter.update(ciphertext, &mut out)?;
  let m = crypter.finalize(&mut out)?;
  Ok(out[0..n + m].to_owned())
}

pub fn pkcs7_padding(data: Vec<u8>, block_size: usize) -> Vec<u8> {
  let padding = block_size - (data.len() % block_size);
  let mut res = data.clone();
  res.append(&mut vec![padding as u8; padding]);
  res
}

pub fn undo_pkcs7_padding(plaintext: &[u8]) -> Vec<u8> {
  let size = plaintext.len();
  let padding_guess = plaintext[size - 1];
  plaintext.iter().take(size - padding_guess as usize).copied().collect()
}

#[allow(dead_code)]
pub fn validate_undo_pkcs7_padding(plaintext: &[u8]) -> Result<Vec<u8>,InvalidPadding> {
  let size = plaintext.len();
  let padding_guess = plaintext[size - 1];
  let padding:Vec<&u8> = plaintext.iter().skip(size-padding_guess as usize).take(padding_guess as usize).collect();
  if padding.len() == padding_guess as usize && padding.iter().all(|v| **v == padding_guess) {
    Ok(plaintext.iter().take(size - padding_guess as usize).copied().collect())
  } else {
    Err(InvalidPadding{})
  }
}

#[allow(dead_code)]
pub fn aes_cbc_encrypt(iv: &[u8], key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, ErrorStack> {
  let data = pkcs7_padding(plaintext.to_owned(), key.len());
  let mut prev_ciphertext = iv.to_owned();
  let mut ciphertext: Vec<u8> = Vec::new();
  for chunk in data.chunks(16) {
    let input = xor::xor_fixed_length(&prev_ciphertext, chunk)
      .expect("Failed to xor chunk with key in aes_cbc_encrypt");
    prev_ciphertext = aes_128_ecb_encrypt(key, &input)?;
    ciphertext.append(&mut prev_ciphertext.clone());
  }
  Ok(ciphertext)
}


pub fn aes_cbc_decrypt(iv: &[u8], key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ErrorStack> {
  Ok(undo_pkcs7_padding(&aes_cbc_decrypt_no_unpadding(iv, key, ciphertext)?))
}


pub fn aes_cbc_decrypt_no_unpadding(iv: &[u8], key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ErrorStack> {
  let mut prev_ciphertext = iv.to_owned();
  let mut plaintext: Vec<u8> = Vec::new();
  for chunk in ciphertext.chunks(key.len()) {
    let output = aes_128_ecb_decrypt(key, chunk)?;
    plaintext.append(
      &mut xor_fixed_length(&output, &prev_ciphertext)
        .expect("Failed to xor chunk with key in aes_cbc_decrypt")
        .to_owned(),
    );
    prev_ciphertext = chunk.to_owned();
  }
  Ok(plaintext)
}
