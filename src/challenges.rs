use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;

use crate::xor;

use crate::htb64;

pub fn character_frequency_score(sample: String) -> f64 {
  let freq_table: BTreeMap<u8, f64> = BTreeMap::from([
    (b'E', 12.7),
    (b'T', 9.1),
    (b'A', 8.2),
    (b'O', 7.5),
    (b'I', 7.0),
    (b'N', 6.7),
    (b'S', 6.3),
    (b'H', 6.1),
    (b'R', 6.0),
    (b'D', 4.3),
    (b'L', 4.0),
    (b'C', 2.8),
    (b'U', 2.8),
    (b'M', 2.4),
    (b'W', 2.4),
    (b'F', 2.2),
    (b'G', 2.0),
    (b'Y', 2.0),
    (b'P', 1.9),
    (b'B', 1.5),
    (b'V', 0.98),
    (b'K', 0.77),
    (b'J', 0.16),
    (b'X', 0.15),
    (b'Q', 0.12),
    (b'Z', 0.074),
  ]);
  sample.to_ascii_uppercase()
    .as_bytes()
    .iter()
    .map(|c| freq_table.get(c).unwrap_or(&0.0).clone())
    .fold(0.0, |acc, e| acc + e)
}

#[allow(dead_code)]
pub fn challenge_3_set_01() {
  let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".to_owned();
  let chars = "abcdefghijklmnopqrstuvewxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !@$%^&*()-_+=[{}]'\"\t<>,./?\\|:;`~\n".to_owned();
  let valid = "abcdefghijklmnopqrstuvewxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !@$%^&*()-_+=[{}]'\"\t<>,./?\\|:;`~\n";
  let cipher = htb64::hex_bytes_to_bytes(input.as_bytes()).unwrap();
  let mut table: BTreeMap<u8, f64> = BTreeMap::new();
  for c in chars.as_bytes() {
    let attempt = String::from_utf8(xor::xor_single_byte(&cipher, c.clone()));
    if let Ok(s) = attempt {
      if s.chars().any(|ch| !valid.contains(ch)) {
        continue;
      }
      table.insert(c.clone(), character_frequency_score(s));
    }
  }
  let mut res = Vec::from_iter(table);
  res.sort_by(|&(_, v1), &(_, v2)| v1.total_cmp(&v2).reverse());

  for (k, v) in res {
    println!("Character: '{}' | Score:{:.5}", String::from_utf8(vec![k.clone()]).unwrap(), v);
    println!("Attempt: {:?}", String::from_utf8(xor::xor_single_byte(&cipher, k.clone())).unwrap())
  }

}

#[allow(dead_code)]
pub fn challenge_4_set_01(){
  let input_file = "./res/challenge_4_set_01_extended.txt";
  // let input_file = "./res/challenge_4_set_01.txt";
  let chars = "abcdefghijklmnopqrstuvewxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !@$%^&*()-_+=[{}]'\"\t<>,./?\\|:;`~\n".to_owned();
  let valid = "abcdefghijklmnopqrstuvewxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !@$%^&*()-_+=[{}]'\"\t<>,./?\\|:;`~\n";
  let mut candidates_table:BTreeMap<(usize,String),Vec<(u8,f64,String)>> = BTreeMap::new();
  let reader = BufReader::new(File::open(input_file).expect("Failed to open challenge 4 set 01 input file.")).lines().enumerate();

  for (idx,l) in reader {
    let line = l.expect("Failed to read line from challenge 4 set 01 input file.");
    let cipher_text = htb64::hex_bytes_to_bytes(line.as_bytes()).expect("Invalid Hexadecimal string");
    let mut valid_attempts:Vec<(u8,f64,String)> = Vec::new();
    for c in chars.as_bytes() {
      let attempt = String::from_utf8(xor::xor_single_byte(&cipher_text, c.clone()));
      if let Ok(s) = attempt {
        if s.chars().any(|v| !valid.contains(v)){
          continue;
        }
        valid_attempts.push((c.clone(),character_frequency_score(s.clone()),s));
      }
    }
    if !valid_attempts.is_empty() {
      valid_attempts.sort_by(|&(_,s1,_),&(_,s2,_)| s1.total_cmp(&s2).reverse());
      candidates_table.insert((idx,line), valid_attempts);
    }
  }
  for ((idx,k),v) in candidates_table {
    if v[0].1 < 90.0 {
      continue
    }
    println!("Line Number: {}\nLine hex: '{}'\nTop Score: {:.5}\nTop Plaintext Attempt: {:?}",idx,k,v[0].1,v[0].2);
    print!("Candidates: [\n");
    let top_3_candidates = &v[0..(if v.len() <= 3 { v.len() } else { 3 } )];
    for (k,s,p) in  top_3_candidates {
      println!("Key: '{}' | Score: {:.5} | Plaintext: {:?}",String::from_utf8(vec![k.clone()]).unwrap(),s,p);
    }
    println!("]\n------------------------------------");
  }
}
