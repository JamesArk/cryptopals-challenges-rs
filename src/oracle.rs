use base64::{Engine, prelude::BASE64_STANDARD};
use rand::Rng;

use crate::cryptog::{aes_128_ecb_encrypt, aes_cbc_encrypt, pkcs7_padding};

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
