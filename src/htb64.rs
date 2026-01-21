use std::{char, fmt::Display};
use byteorder::{BigEndian, ByteOrder};

#[derive(Debug, Clone)]
enum BadHexErrorKind {
  BadChar,
  BadSize,
}

#[derive(Debug, Clone)]
pub struct BadHexError {
  error_kind: BadHexErrorKind,
  character: char,
  position: usize,
}

impl Display for BadHexError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self.error_kind {
      BadHexErrorKind::BadChar => {
        let position = self.position;
        let character = self.character;
        write!(f, "Invalid char for hex string '{character}' at position {position}")
      }
      BadHexErrorKind::BadSize => {
        write!(f, "Invalid size for hex string, hex string must be divisible by 2")
      }
    }
  }
}

fn get_hex_val(c1: u8, c2: u8, idx: usize) -> Result<u8, BadHexError> {
  let v1 = match c1 {
    b'A'..=b'F' => (c1 + 9) << 4,
    b'a'..=b'f' => (c1 + 9) << 4,
    b'0'..=b'9' => (c1 & 0b00001111) << 4,
    _ => {
      return Err(BadHexError {
        error_kind: BadHexErrorKind::BadChar,
        character: char::from(c1),
        position: idx * 2,
      });
    }
  };
  let res = match c2 {
    b'A'..=b'F' => v1 | (c2 + 9) & 0x0f,
    b'a'..=b'f' => v1 | (c2 + 9) & 0x0f,
    b'0'..=b'9' => v1 | (c2 & 0b00001111),
    _ => {
      return Err(BadHexError {
        error_kind: BadHexErrorKind::BadChar,
        character: char::from(c2),
        position: idx * 2 + 1,
      });
    }
  };
  Ok(res)
}

pub fn hex_bytes_to_bytes(hex_bytes: &[u8]) -> Result<Vec<u8>, BadHexError> {
  if hex_bytes.len() % 2 == 1 {
    // we will assume we can only convert from complete 8 byte chunks
    return Err(BadHexError { error_kind: BadHexErrorKind::BadSize, position: 0, character: '\0' });
  }
  hex_bytes
      .chunks(2)
      .enumerate()
      .map(|(i, cs)| get_hex_val(cs[0], cs[1], i))
      .collect::<Result<Vec<u8>, BadHexError>>()
}

pub fn bytes_to_hex(bytes :&[u8]) -> String{
  bytes.iter().map(|b| {
    let left = b >> 4;
    let right = b & 0x0f;
    let res:String = match (left,right) {
      (0..=9, 0..=9) => String::from_utf8(vec![left|0b0011_0000,right|0b0011_0000]).unwrap(),
      (a,0..=9) => String::from_utf8(vec![(a-9)|0b0100_0000,right|0b0011_0000]).unwrap(),
      (0..=9,b) => String::from_utf8(vec![left|0b0011_0000,(b-9)|0b0100_0000]).unwrap(),
      (a,b) => String::from_utf8(vec![(a-9)|0b0100_0000,(b-9)|0b0100_0000]).unwrap(),
    };
    return res
  }).collect::<String>()
}

#[allow(dead_code)]
fn hex_bytes_to_base64(hex_bytes: &[u8]) -> Result<String, BadHexError> {
  let bin_codon = hex_bytes_to_bytes(hex_bytes)?;
  let mut res: Vec<u8> = vec![0, 0, 0, 0];
  if hex_bytes.len() == 6 {
    let bin_uint = BigEndian::read_u24(bin_codon.as_ref());
    res[0] = BASE64_SYMBOLS[((bin_uint & 0x00fc0000) >> 18) as usize];
    res[1] = BASE64_SYMBOLS[((bin_uint & 0x0003f000) >> 12) as usize];
    res[2] = BASE64_SYMBOLS[((bin_uint & 0x00000fc0) >> 6) as usize];
    res[3] = BASE64_SYMBOLS[(bin_uint & 0x0000003f) as usize];
  } else if hex_bytes.len() == 4 {
    let bin_uint = BigEndian::read_u16(bin_codon.as_ref());
    res[0] = BASE64_SYMBOLS[((bin_uint & 0xfc00) >> 10) as usize];
    res[1] = BASE64_SYMBOLS[((bin_uint & 0x03f0) >> 4) as usize];
    res[2] = BASE64_SYMBOLS[((bin_uint & 0x000f) << 2) as usize];
    res[3] = b'=';
  } else {
    let bin_uint = bin_codon[0];
    res[0] = BASE64_SYMBOLS[((bin_uint & 0xfc) >> 2) as usize];
    res[1] = BASE64_SYMBOLS[((bin_uint & 0x03) << 4) as usize];
    res[2] = b'=';
    res[3] = b'=';
  }

  Ok(String::from_utf8(res).expect("Invalid UTF-8 for base 64 string"))
}

const BASE64_SYMBOLS: &[u8] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".as_bytes();

#[allow(dead_code)]
pub fn hex_to_base64(hex_string_bin: &[u8]) -> Result<String, BadHexError> {
  if hex_string_bin.len() % 2 == 1 {
    // we will assume we can only convert from complete 8 bit chunks (a byte)
    return Err(BadHexError { error_kind: BadHexErrorKind::BadSize, position: 0, character: '\0' });
  }
  hex_string_bin.chunks(6).map(hex_bytes_to_base64).collect()
}
