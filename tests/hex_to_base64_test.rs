use base64::{Engine, prelude::BASE64_STANDARD};
use cryptopals_challeges_rs::htb64;
use rand::seq::IndexedRandom;

#[test]
fn invalid_hex_size() {
  let res = htb64::hex_to_base64("1".as_bytes());
  assert!(res.is_err())
}

#[test]
fn invalid_hex_char() {
  let res = htb64::hex_to_base64("abcdefghijklmnopqrstuvwxyz".as_bytes());
  assert!(res.is_err())
}

#[test]
fn small_hex() {
  let input = "ABCDEF0123456789";
  let res = htb64::hex_to_base64(input.as_bytes());
  assert!(!res.is_err());
  assert!(res.unwrap() == BASE64_STANDARD.encode(hex::decode(input).unwrap()))
}

#[test]
fn big_hex() {
  let symbols: Vec<String> = "0123456789ABCDEFabcdef"
    .as_bytes()
    .iter()
    .map(|c| String::from_utf8(vec![c.clone()]).unwrap())
    .collect();
  let input = (0..40960)
    .map(|_| symbols.choose(&mut rand::rng()).unwrap())
    .map(|c| c.clone())
    .collect::<Vec<_>>()
    .concat();
  println!("Input {}", input);
  let res = htb64::hex_to_base64(input.as_bytes());
  let real_res = BASE64_STANDARD.encode(hex::decode(input).unwrap());
  println!("Expected {}", real_res);
  assert!(!res.is_err());
  let res_string = res.unwrap();
  println!("Actual {}", res_string);
  assert!(res_string == real_res)
}

#[test]
fn cryptopals_challenge_set_01_challenge_01() {
  let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
  let res = htb64::hex_to_base64(input.as_bytes());
  assert!(res.is_ok());
  assert!(res.unwrap() == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
}
