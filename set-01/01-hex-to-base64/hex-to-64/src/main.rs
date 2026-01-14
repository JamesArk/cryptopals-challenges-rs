use std::{fs::File, io::{BufRead, BufReader, BufWriter, Write}, time};

use base64::{Engine, prelude::BASE64_STANDARD};

mod mhex;
fn main() {
  let now = time::Instant::now();
  real_hex_string_file_to_base64_file("./input_hex.txt".to_string(),"./output_base64_real.txt".to_string());
  let dur = now.elapsed();
  println!("Time taken hex to base64 real {:?}",dur);

  let now = time::Instant::now();
  real_hex_string_file_to_bin_file("./input_hex.txt".to_string(),"./output_bin_real.txt".to_string());
  let dur = now.elapsed();
  println!("Time taken hex to bin real {:?}",dur);

  let now = time::Instant::now();
  mine_hex_string_file_to_base64_file("./input_hex.txt".to_string(),"./output_base64.txt".to_string());
  let dur = now.elapsed();
  println!("Time taken hex to base64 mine {:?}",dur);

  let now = time::Instant::now();
  mine_hex_string_file_to_bin_file("./input_hex.txt".to_string(),"./output_bin.txt".to_string());
  let dur = now.elapsed();
  println!("Time taken hex to bin mine {:?}",dur);
}

pub fn real_hex_string_file_to_bin_file(path: String, out: String) {
  let mut buf = String::new();
  let mut input = BufReader::new(File::open(path).unwrap());
  let mut output = BufWriter::new(File::create(out).unwrap());
  while input.read_line(&mut buf).expect("Error occured while reading line") != 0 {
    buf.pop(); // removes new line
    let hex_bin = hex::decode(&buf).unwrap();
    for i in hex_bin {
      output.write_all(format!("{:08b} ",i).as_bytes()).expect("Error while writing to output file");
    }
    output.write_all("\n".as_bytes()).expect("Error while writing to output file");
  }
}

pub fn mine_hex_string_file_to_bin_file(path: String, out: String) {
  let mut buf = String::new();
  let mut input = BufReader::new(File::open(path).unwrap());
  let mut output = BufWriter::new(File::create(out).unwrap());
  while input.read_line(&mut buf).expect("Error occured while reading line") != 0 {
    buf.pop(); // removes new line
    let hex_bin = mhex::hex_bytes_to_bytes(buf.as_bytes()).unwrap();
    for i in hex_bin {
      output.write_all(format!("{:08b} ",i).as_bytes()).expect("Error while writing to output file");
    }
    output.write_all("\n".as_bytes()).expect("Error while writing to output file");
  }
}


pub fn real_hex_string_file_to_base64_file(path: String, out: String) {
  let mut buf = String::new();
  let mut input = BufReader::new(File::open(path).unwrap());
  let mut output = BufWriter::new(File::create(out).unwrap());
  while input.read_line(&mut buf).expect("Error occured while reading line") != 0 {
    buf.pop(); // removes new line
    let hex_bin = hex::decode(&buf).unwrap();
    let base64_string = BASE64_STANDARD.encode(hex_bin);
    output.write_all(&base64_string.as_bytes()).expect("Error while writing to output file");
  }
}

pub fn mine_hex_string_file_to_base64_file(path: String, out: String) {
  let mut buf = String::new();
  let mut input = BufReader::new(File::open(path).unwrap());
  let mut output = BufWriter::new(File::create(out).unwrap());
  while input.read_line(&mut buf).expect("Error occured while reading line") != 0 {
    buf.pop(); // removes new line
    let base64_string = mhex::hex_to_base64(&buf).unwrap();
    output.write_all(&base64_string.as_bytes()).expect("Error while writing to output file");
  }
}
