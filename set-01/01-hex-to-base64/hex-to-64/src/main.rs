use std::{fmt::Display, io::stdin};

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
                write!(
                    f,
                    "Invalid char for hex string '{character}' at position {position}"
                )
            }
            BadHexErrorKind::BadSize => {
                write!(
                    f,
                    "Invalid size for hex string, hex string must be divisible by 2"
                )
            }
        }
    }
}

fn main() {
    let input = stdin();
    loop {
        let mut buf = String::new();
        println!("Please provide a hex string:");
        input
            .read_line(&mut buf)
            .expect("Error occured while reading line");
        buf.pop(); // removes new line
        let hex_bytes = hex_to_bytes(&buf).unwrap();
        println!("Binary representation:");
        let mut out = String::new();
        for b in hex_bytes.clone() {
            out.push_str(&format!("{:08b}", b));
        }
        println!("{}", out);
        println!("Hex string: {}",buf);
        println!("Base64: {}",bytes_to_base64(hex_bytes));
    }
}

const BASE64_SYMBOLS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const HEX_SYMBOLS: &str = "0123456789ABCDEF";


// fn hex_to_base64(hex_string: &String) -> Result<String,Error> {

// }

fn hex_to_bytes(hex_string: &String) -> Result<Vec<u8>, BadHexError> {
    if hex_string.len() % 2 == 1 {
        // we will assume we can only convert from complete 8 byte chunks
        return Err(BadHexError {
            error_kind: BadHexErrorKind::BadSize,
            position: 0,
            character: '\0',
        });
    }
    let mut res = Vec::with_capacity(hex_string.len() * 2);
    let upper_hex_string = hex_string.to_ascii_uppercase();
    let mut hex_symbols = upper_hex_string.chars();
    for i in 0..(upper_hex_string.len() / 2) {
        let c1 = hex_symbols.next().unwrap();
        let c2 = hex_symbols.next().unwrap();
        if !HEX_SYMBOLS.contains(c1.to_ascii_uppercase()) { // invalid char causes error
            return Err(BadHexError {
                error_kind: BadHexErrorKind::BadChar,
                character: c1,
                position: i,
            });
        }
        if !HEX_SYMBOLS.contains(c2.to_ascii_uppercase()) { // invalid char causes error
            return Err(BadHexError {
                error_kind: BadHexErrorKind::BadChar,
                character: c2,
                position: i + 1,
            });
        }

        let idx1: u64 = HEX_SYMBOLS.chars().position(|s| s == c1).unwrap() as u64; // usize is never bigger than 64 bits and the value will never be bigger than 15
        let idx2: u64 = HEX_SYMBOLS.chars().position(|s| s == c2).unwrap() as u64; // usize is never bigger than 64 bits and the value will never be bigger than 15
        res.push(((idx1 << 4) + idx2) as u8); // first hex represents first 4 bytes, seconds hex the next 4 bytes
    }
    Ok(res)
}

fn bytes_to_base64(bytes: Vec<u8>) -> String {
  let mut symbols:Vec<char> = Vec::new();
  let mut current_byte = 0;
  if bytes.len() == 0 {
    return "not valid".to_owned();
  } else if bytes.len() > 4 {
    // 1111 11|11 ** 1111| 1111 ** 11|11 1111| ** 1111 11|11 ** 1111| 1111 ** 11|11 1111  % 4 = 2
    // 1111 11|11 ** 1111| 1111 ** 11|11 1111| ** 1111 11|11 ** 1111| 1111 % 4 = 1
    // 1111 11|11 ** 1111| 1111 ** 11|11 1111| ** 1111 11|11 % 4 = 0
    // 1111 11|11 ** 1111| 1111 ** 11|11 1111  % 4 = 3
    // 1111 11|11 ** 1111| 1111 % 4 = 2
    // 1111 11|11 % 4 = 1
    for i in (0..bytes.len()-2).step_by(3) {
      let idx1:usize = ((bytes[i] & 0b1111_1100) >> 2) as usize;
      let idx2:usize = ((bytes[i] & 0b0000_0011) << 4) as usize + ((bytes[i+1] & 0b1111_0000) >> 4) as usize;
      let idx3:usize = ((bytes[i+1] & 0b0000_1111) << 2) as usize + ((bytes[i+2] & 0b1100_0000) >> 6) as usize;
      let idx4:usize = ((bytes[i+2] & 0b0011_1111)) as usize;

      symbols.push(BASE64_SYMBOLS.chars().nth(idx1).unwrap());
      symbols.push(BASE64_SYMBOLS.chars().nth(idx2).unwrap());
      symbols.push(BASE64_SYMBOLS.chars().nth(idx3).unwrap());
      symbols.push(BASE64_SYMBOLS.chars().nth(idx4).unwrap());
      current_byte += 3;
    }

  }
  if bytes.len() % 3 == 1 {
    // padding twice
    symbols.push(BASE64_SYMBOLS.chars().nth(((bytes[current_byte] & 0b1111_1100) >> 2) as usize).unwrap());
    symbols.push(BASE64_SYMBOLS.chars().nth(((bytes[current_byte] & 0b0000_0011) << 4) as usize).unwrap());
    symbols.push(BASE64_SYMBOLS.chars().last().unwrap());
    symbols.push(BASE64_SYMBOLS.chars().last().unwrap());
  } else if bytes.len() % 3 == 2 {
    // padding once
    symbols.push(BASE64_SYMBOLS.chars().nth(((bytes[current_byte] & 0b1111_1100) >> 2) as usize).unwrap());
    symbols.push(BASE64_SYMBOLS.chars().nth(((bytes[current_byte] & 0b0000_0011) << 4) as usize + ((bytes[current_byte+1] & 0b1111_0000) >> 4) as usize).unwrap());
    symbols.push(BASE64_SYMBOLS.chars().nth(((bytes[current_byte] & 0b0000_1111) << 2) as usize).unwrap());
    symbols.push(BASE64_SYMBOLS.chars().last().unwrap());
  }
  return symbols.iter().collect();
}
