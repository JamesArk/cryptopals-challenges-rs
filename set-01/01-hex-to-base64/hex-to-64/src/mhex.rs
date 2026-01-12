use std::{
  char, fmt::Display, fs::File, io::{BufRead, BufReader, BufWriter, Write}
};

use base64::{Engine, alphabet::STANDARD, prelude::BASE64_STANDARD};
use byteorder::{ByteOrder, LittleEndian};
use indicatif::ProgressBar;
use itertools::Itertools;

#[derive(Debug, Clone)]
enum BadHexErrorKind {
  BadChar,
  BadSize,
}

#[derive(Debug, Clone)]
struct BadHexError {
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
    b'0'..=b'9' => c1,
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
    b'0'..=b'9' => v1 | c2 & 0x0f,
    _ => {
      return Err(BadHexError {
        error_kind: BadHexErrorKind::BadChar,
        character: char::from(c2),
        position: idx * 2 + 1,
      });
    }
  };
  return Ok(res);
}

fn hex_to_bytes(hex_string: &str) -> Result<Vec<u8>, BadHexError> {
  if hex_string.len() % 2 == 1 {
    // we will assume we can only convert from complete 8 byte chunks
    return Err(BadHexError { error_kind: BadHexErrorKind::BadSize, position: 0, character: '\0' });
  }
  let string_bytes: &[u8] = hex_string.as_bytes();
  let res = string_bytes
    .chunks(2)
    .enumerate()
    .map(|(i, cs)| match get_hex_val(cs[0], cs[1], i) {
      Ok(c) => c,
      Err(e) => panic!("{}", e),
    })
    .collect_vec();
  Ok(res)
}

// fn bytes_to_base64(bytes: Vec<u8>) -> String {
//   let mut symbols:Vec<char> = Vec::new();
//   let mut current_byte = 0;
//   if bytes.len() == 0 {
//     return "not valid".to_owned();
//   } else if bytes.len() > 4 {
//     // 1111 11|11 ** 1111| 1111 ** 11|11 1111| ** 1111 11|11 ** 1111| 1111 ** 11|11 1111  % 4 = 2
//     // 1111 11|11 ** 1111| 1111 ** 11|11 1111| ** 1111 11|11 ** 1111| 1111 % 4 = 1
//     // 1111 11|11 ** 1111| 1111 ** 11|11 1111| ** 1111 11|11 % 4 = 0
//     // 1111 11|11 ** 1111| 1111 ** 11|11 1111  % 4 = 3
//     // 1111 11|11 ** 1111| 1111 % 4 = 2
//     // 1111 11|11 % 4 = 1
//     for i in (0..bytes.len()-2).step_by(3) {
//       let idx1:usize = ((bytes[i] & 0b1111_1100) >> 2) as usize;
//       let idx2:usize = ((bytes[i] & 0b0000_0011) << 4) as usize + ((bytes[i+1] & 0b1111_0000) >> 4) as usize;
//       let idx3:usize = ((bytes[i+1] & 0b0000_1111) << 2) as usize + ((bytes[i+2] & 0b1100_0000) >> 6) as usize;
//       let idx4:usize = ((bytes[i+2] & 0b0011_1111)) as usize;

//       symbols.push(BASE64_SYMBOLS.chars().nth(idx1).unwrap());
//       symbols.push(BASE64_SYMBOLS.chars().nth(idx2).unwrap());
//       symbols.push(BASE64_SYMBOLS.chars().nth(idx3).unwrap());
//       symbols.push(BASE64_SYMBOLS.chars().nth(idx4).unwrap());
//       current_byte += 3;
//     }

//   }
//   if bytes.len() % 3 == 1 {
//     // padding twice
//     symbols.push(BASE64_SYMBOLS.chars().nth(((bytes[current_byte] & 0b1111_1100) >> 2) as usize).unwrap());
//     symbols.push(BASE64_SYMBOLS.chars().nth(((bytes[current_byte] & 0b0000_0011) << 4) as usize).unwrap());
//     symbols.push(BASE64_SYMBOLS.chars().last().unwrap());
//     symbols.push(BASE64_SYMBOLS.chars().last().unwrap());
//   } else if bytes.len() % 3 == 2 {
//     // padding once
//     symbols.push(BASE64_SYMBOLS.chars().nth(((bytes[current_byte] & 0b1111_1100) >> 2) as usize).unwrap());
//     symbols.push(BASE64_SYMBOLS.chars().nth(((bytes[current_byte] & 0b0000_0011) << 4) as usize + ((bytes[current_byte+1] & 0b1111_0000) >> 4) as usize).unwrap());
//     symbols.push(BASE64_SYMBOLS.chars().nth(((bytes[current_byte] & 0b0000_1111) << 2) as usize).unwrap());
//     symbols.push(BASE64_SYMBOLS.chars().last().unwrap());
//   }
//   return symbols.iter().collect();
// }

pub fn input_from_file_real(path: String, out: String) {
  let mut buf = String::new();
  let mut input = BufReader::new(File::open(path).unwrap());
  let mut output = BufWriter::new(File::create(out).unwrap());
  while input.read_line(&mut buf).expect("Error occured while reading line") != 0 {
    buf.pop(); // removes new line
    let base64_string = BASE64_STANDARD.encode(hex::decode(&buf).unwrap());
    output.write_all(&base64_string.as_bytes()).expect("Error while writing to output file");
  }
}

pub fn input_from_file_mine(path: String, out: String) {
  let mut buf = String::new();
  let mut input = BufReader::new(File::open(path).unwrap());
  let mut output = BufWriter::new(File::create(out).unwrap());
  while input.read_line(&mut buf).expect("Error occured while reading line") != 0 {
    buf.pop(); // removes new line
    let base64_string = hex_to_base64(&buf).unwrap();
    output.write_all(&base64_string.as_bytes()).expect("Error while writing to output file");
  }
}

const BASE64_SYMBOLS: &[u8] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".as_bytes();

fn hex_to_base64(hex_string: &str) -> Result<String, BadHexError> {
  if hex_string.len() % 2 == 1 {
    // we will assume we can only convert from complete 8 bit chunks (a byte)
    return Err(BadHexError { error_kind: BadHexErrorKind::BadSize, position: 0, character: '\0' });
  }
  let mut base64_res: Vec<u8> = Vec::new() ;
  let mod_6 = hex_string.len() % 6;
  //wip 2 or 4 extra hex chars
  let iterations = hex_string.len() / 6; // 2 and 4 hex characters are the only cases we need to watch out for
  for i in 0..iterations {
    let codon = hex_string.get(i..=i+2).unwrap();
    dbg!("{}",codon);
    dbg!("{}",i..=i+2);
    dbg!("{}",iterations);
    let bin_codon = hex_to_bytes(codon).unwrap();
    let bin_uint = LittleEndian::read_u48(bin_codon.as_ref());
    let mut codon_res:Vec<u8> = vec![0,0,0,0];
    codon_res[0] = BASE64_SYMBOLS[(bin_uint & 0x00fc0000 >> 18) as usize];
    codon_res[1] = BASE64_SYMBOLS[(bin_uint & 0x0003f000 >> 12) as usize];
    codon_res[2] = BASE64_SYMBOLS[(bin_uint & 0x00000fc0 >> 6) as usize];
    codon_res[3] = BASE64_SYMBOLS[(bin_uint & 0x0000003f) as usize];
    base64_res.append(&mut codon_res);
  }
  let mut padding_str = vec![b'=';padding];
  base64_res.append(&mut padding_str);

  return Ok(String::from_utf8(base64_res).expect("base64 result is not utf8 valid"));
}
