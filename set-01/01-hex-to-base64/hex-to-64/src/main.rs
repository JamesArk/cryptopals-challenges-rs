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
        input
            .read_line(&mut buf)
            .expect("Error occured while reading line");
        buf.pop(); // removes new line

        let hex_bytes = hex_to_bytes(&buf).unwrap();
        println!("Binary representation of {:?} is:", buf);
        let mut out = String::new();
        for b in hex_bytes.clone() {
            out.push_str(&format!("{:04b} {:04b} ", b >> 4, b & 0x0f));
        }
        out.pop();
        out.push_str("\n");
        for b in hex_bytes {
            out.push_str(&format!("{:08b}", b));
        }
        println!("{}", out)
    }
}

const BASE64_SYMBOLS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const HEX_SYMBOLS: &str = "0123456789ABCDEF";

// fn hex_to_base64(hex_string: &String) -> Result<String,Error> {

// }
//  shift 4
// 0000 0001 -> 0001 0000

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

// fn bytes_to_base64(bytes: &[u8]) -> String {

// }
