use std::collections::HashMap;

use base64::{Engine, prelude::BASE64_STANDARD};
use rand::Rng;

use crate::{cryptog::{aes_128_ecb_decrypt, aes_128_ecb_encrypt, aes_cbc_encrypt, pkcs7_padding, undo_pkcs7_padding}};

#[derive(Debug, PartialEq, Eq)]
pub enum CookieValue {
  StringValue(String),
  NumberValue(i64),
  BoolValue(bool),
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
  let mut plaintext_bytes: Vec<u8> = Vec::with_capacity(input_bytes.len() + unknown_string.len());
  plaintext_bytes.append(&mut input_bytes.to_owned());
  plaintext_bytes.append(&mut unknown_string.as_bytes().to_owned());

  aes_128_ecb_encrypt(
    consistent_oracle_key,
    &pkcs7_padding(plaintext_bytes, consistent_oracle_key.len()),
  )
  .unwrap()
}

pub fn consistent_encryption_oracle_prefixed(input_bytes: &[u8], consistent_oracle_key: &[u8]) -> Vec<u8> {
  let prefix_length = 10;
  let mut prefix:Vec<u8> = rand::random_iter().take(prefix_length).collect();
  prefix.append(&mut input_bytes.to_owned());
  consistent_encryption_oracle(&prefix, consistent_oracle_key)
}

pub fn parse_cookie(input: String) -> HashMap<String, CookieValue> {
  let mut res = HashMap::new();
  let input_string: String = input.chars().filter(|c| !c.is_whitespace()).collect();
  let props: Vec<&str> = input_string.split("&").filter(|v| v.contains("=")).collect();
  for p in props {
    let mut s = p.split("=");
    let name = s.next().unwrap();
    let value_string: String = s.collect();
    let value = if value_string.parse::<i64>().is_ok() {
      CookieValue::NumberValue(value_string.parse::<i64>().unwrap())
    } else if value_string.parse::<bool>().is_ok() {
      CookieValue::BoolValue(value_string.parse::<bool>().unwrap())
    } else {
      CookieValue::StringValue(value_string)
    };
    res.insert(name.to_owned(), value);
  }
  res
}

pub fn profile_for(email: String) -> String {
  [
    "email=".to_owned() + &email.replace("&", "").replace("=", ""),
    "uid=10".to_owned(),
    "role=user".to_owned(),
  ]
  .join("&")
}

pub fn oracle_create_token(email: String, key: &[u8]) -> Vec<u8> {
  let token = profile_for(email);
  aes_128_ecb_encrypt(key, &pkcs7_padding(token.as_bytes().to_owned(), key.len())).unwrap()

}

pub fn oracle_parse_token(token: &[u8], key: &[u8]) -> HashMap<String,CookieValue>{
  let token_string = undo_pkcs7_padding(&aes_128_ecb_decrypt(key, token).unwrap());
  parse_cookie(String::from_utf8(token_string).unwrap())
}
