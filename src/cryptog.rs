use base64::{Engine, prelude::BASE64_STANDARD};
use openssl::{
  error::ErrorStack,
  symm::{Cipher, Crypter},
};
use rand::Rng;

use crate::xor::{self, xor_fixed_length};

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

#[allow(dead_code)]
pub fn aes_cbc_decrypt(iv: &[u8], key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ErrorStack> {
  let mut prev_ciphertext = iv.to_owned();
  let mut plaintext: Vec<u8> = Vec::new();
  for chunk in ciphertext.chunks(16) {
    let output = aes_128_ecb_decrypt(key, chunk)?;
    plaintext.append(
      &mut xor_fixed_length(&output, &prev_ciphertext)
        .expect("Failed to xor chunk with key in aes_cbc_decrypt")
        .to_owned(),
    );
    prev_ciphertext = chunk.to_owned();
  }
  let size = plaintext.len();
  let padding_guess = plaintext[size - 1];
  Ok(plaintext.into_iter().take(size - padding_guess as usize).collect())
}

pub fn encryption_oracle(plaintext: String) -> (Vec<u8>, String) {
  let rng = &mut rand::rng();
  let mut plaintext_bytes = plaintext.as_bytes().to_owned();
  let prefix_size = rng.random_range(5..=10);
  let postfix_size = rng.random_range(5..=10);
  let mut prefix: Vec<u8> = rng.random_iter().take(prefix_size).collect();
  let mut postfix: Vec<u8> = rng.random_iter().take(postfix_size).collect();
  prefix.append(&mut plaintext_bytes);
  prefix.append(&mut postfix);
  plaintext_bytes = prefix;

  let key: Vec<u8> = rng.random_iter().take(16).collect();
  if rng.random_bool(0.5) {
    (
      aes_cbc_encrypt(&rng.random_iter().take(16).collect::<Vec<u8>>(), &key, &plaintext_bytes)
        .unwrap(),
      "CBC".to_owned(),
    )
  } else {
    (aes_128_ecb_encrypt(&key, &pkcs7_padding(plaintext_bytes, 16)).unwrap(), "ECB".to_owned())
  }
}

pub fn consistent_encryption_oracle(input_bytes: &[u8], consistent_oracle_key: &[u8]) -> Vec<u8> {
  let unknown_string_base64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
  let unknown_string = String::from_utf8(
    BASE64_STANDARD
      .decode(unknown_string_base64)
      .expect("Failed to decode unknown base 64 string for challenge 12"),
  )
  .expect("Failed to create string based on unknown string for challenge 12");
  let mut plaintext_bytes:Vec<u8> = Vec::with_capacity(input_bytes.len()+unknown_string.len());
  plaintext_bytes.append(&mut input_bytes.to_owned());
  plaintext_bytes.append(&mut unknown_string.as_bytes().to_owned());

  aes_128_ecb_encrypt(
    &consistent_oracle_key,
    &pkcs7_padding(plaintext_bytes, consistent_oracle_key.len()),
  )
  .unwrap()
}
