use std::{char, fmt::Display, fs::File, io::{BufRead, BufReader, BufWriter, Write}, time};

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
    let now = time::Instant::now();
    input_from_file_real("./input_hex.txt".to_string(),"./output_hex_real.txt".to_string());
    let dur = now.elapsed();
    println!("Time taken real {:?}",dur);

    let now = time::Instant::now();
    input_from_file_mine("./input_hex.txt".to_string(),"./output_hex.txt".to_string());
    let dur = now.elapsed();
    println!("Time taken mine {:?}",dur);
    // let input = stdin();
    // loop {
    //     let mut buf = String::new();
    //     println!("Please provide a hex string:");
    //     input
    //         .read_line(&mut buf)
    //         .expect("Error occured while reading line");
    //     buf.pop(); // removes new line
    //     let hex_bytes = hex_to_bytes(&buf).unwrap();
    //     println!("Binary representation:");
    //     let mut out = String::new();
    //     for b in hex_bytes.clone() {
    //         out.push_str(&format!("{:08b}", b));
    //     }
    //     println!("{}", out);
    //     println!("Hex string: {}",buf);
    //     println!("Base64: {}",bytes_to_base64(hex_bytes));
    // }
}

// const BASE64_SYMBOLS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";


// fn hex_to_base64(hex_string: &String) -> Result<String,Error> {

// }

fn get_hex_val(c1:u8, c2:u8, idx:usize) -> Result<u8,BadHexError> {
  let v1 = match c1 {
    b'A' ..= b'F' => (c1 + 9) << 4,
    b'a' ..= b'f' => (c1 + 9) << 4,
    b'0' ..= b'9' => c1,
    _ => return Err(BadHexError {
        error_kind: BadHexErrorKind::BadChar,
        character: char::from(c1),
        position: idx*2,
      })
    };
  let res = match c2 {
    b'A' ..= b'F' => v1 | (c2 + 9) & 0x0f,
    b'a' ..= b'f' => v1 | (c2 + 9) & 0x0f,
    b'0' ..= b'9' => v1 | c2 & 0x0f,
    _ => return Err(BadHexError {
        error_kind: BadHexErrorKind::BadChar,
        character: char::from(c2),
        position: idx*2+1,
      })
    };
  return Ok(res)
}

fn hex_to_bytes(hex_string: &String) -> Result<Vec<u8>, BadHexError> {
    if hex_string.len() % 2 == 1 {
        // we will assume we can only convert from complete 8 byte chunks
        return Err(BadHexError {
            error_kind: BadHexErrorKind::BadSize,
            position: 0,
            character: '\0',
        });
    }
    let string_bytes:&[u8] = hex_string.as_bytes();
    let res = string_bytes.chunks(2).enumerate().map(|(i,cs)|
      match get_hex_val(cs[0], cs[1], i) {
        Ok(c) => c,
        Err(e) => panic!("{}",e)
      }

        ).collect_vec();
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

fn input_from_file_real(path: String, out: String){
  let mut buf = String::new();
  let mut input = BufReader::new(File::open(path).unwrap());
  let mut output = BufWriter::new(File::create(out).unwrap());
  let bar = ProgressBar::new(4352);
  while input.read_line(&mut buf).expect("Error occured while reading line") != 0 {
      buf.pop(); // removes new line
      let hex_bytes = hex::decode(&buf).unwrap();
      for b in hex_bytes {
        output.write_all(format!("{:08b}", b).as_bytes()).expect("Error while writing to output file");
      }
      bar.inc(1);
      // println!("Binary representation:");
      // let mut out = String::new();
      // for b in hex_bytes.clone() {
      //     out.push_str(&format!("{:08b}", b));
      // }
      // println!("{}", out);
      // println!("Hex string: {}",buf);
      // println!("Base64: {}",bytes_to_base64(hex_bytes));
  }
}

fn input_from_file_mine(path: String, out: String){
  let mut buf = String::new();
  let mut input = BufReader::new(File::open(path).unwrap());
  let mut output = BufWriter::new(File::create(out).unwrap());
  let bar = ProgressBar::new(4352);
  while input.read_line(&mut buf).expect("Error occured while reading line") != 0 {
      buf.pop(); // removes new line
      let hex_bytes = hex_to_bytes(&buf).unwrap();
      for b in hex_bytes {
        output.write_all(format!("{:08b}", b).as_bytes()).expect("Error while writing to output file");
      }
      bar.inc(1);
  }
}
