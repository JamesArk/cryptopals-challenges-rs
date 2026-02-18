use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use cryptopals_challeges_rs::distance::hamming_distance;

use crate::cryptog;
use crate::oracle;
use crate::oracle::oracle_create_token;
use crate::oracle::oracle_parse_token;
use crate::oracle_hacker;
use crate::oracle_hacker::detect_ecb;
use crate::xor;

use crate::htb64;

pub fn character_frequency_score(sample: String) -> u64 {
  let freq_table: BTreeMap<u8, u64> = BTreeMap::from([
    (b'E', 1270),
    (b'T', 910),
    (b'A', 820),
    (b'O', 750),
    (b'I', 700),
    (b'N', 670),
    (b'S', 630),
    (b'H', 610),
    (b'R', 600),
    (b'D', 430),
    (b'L', 400),
    (b'C', 280),
    (b'U', 280),
    (b'M', 240),
    (b'W', 240),
    (b'F', 220),
    (b'G', 200),
    (b'Y', 200),
    (b'P', 190),
    (b'B', 150),
    (b'V', 98),
    (b'K', 77),
    (b'J', 16),
    (b'X', 15),
    (b'Q', 12),
    (b'Z', 7),
  ]);
  let mut sample_freq_table: HashMap<u8, u64> = HashMap::new();
  let size = sample.len();
  sample.to_ascii_uppercase().as_bytes().iter().filter(|c| c.is_ascii_alphabetic()).for_each(|c| {
    sample_freq_table.entry(c.to_ascii_uppercase()).and_modify(|v| *v += 1).or_insert(1);
  });

  freq_table
    .iter()
    .map(|(k, score)| {
      let count = sample_freq_table.get(k).unwrap_or(&0);
      score * count / size as u64
    })
    .sum::<u64>()
}

#[allow(dead_code)]
pub fn challenge_3() {
  let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".to_owned();
  let chars = "abcdefghijklmnopqrstuvewxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !@$%^&*()-_+=[{}]'\"\t<>,./?\\|:;`~".to_owned();
  let valid = "abcdefghijklmnopqrstuvewxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !@$%^&*()-_+=[{}]'\"\t<>,./?\\|:;`~";
  let cipher = htb64::hex_bytes_to_bytes(input.as_bytes()).unwrap();
  let mut table: BTreeMap<u8, u64> = BTreeMap::new();
  for c in chars.as_bytes() {
    let attempt = String::from_utf8(xor::xor_single_byte(&cipher, *c));
    if let Ok(s) = attempt {
      if s.chars().any(|ch| !valid.contains(ch)) {
        continue;
      }
      table.insert(*c, character_frequency_score(s));
    }
  }
  let mut res = Vec::from_iter(table);
  res.sort_by(|&(_, v1), &(_, v2)| v1.cmp(&v2).reverse());

  for (k, v) in res {
    println!("Character: '{}' | Score:{:.5}", String::from_utf8(vec![k]).unwrap(), v);
    println!("Attempt: {:?}", String::from_utf8(xor::xor_single_byte(&cipher, k)).unwrap())
  }
}

#[allow(dead_code)]
pub fn challenge_4() {
  let input_file = "./res/challenge_4_extended.txt";
  // let input_file = "./res/challenge_4.txt";
  let chars = "abcdefghijklmnopqrstuvewxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !@$%^&*()-_+=[{}]'\"\t<>,./?\\|:;`~\n\r".to_owned();
  let valid = "abcdefghijklmnopqrstuvewxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !@$%^&*()-_+=[{}]'\"\t<>,./?\\|:;`~\n\r";
  let mut candidates_table: BTreeMap<(usize, String), Vec<(u8, u64, String)>> = BTreeMap::new();
  let reader =
    BufReader::new(File::open(input_file).expect("Failed to open challenge 4 set 01 input file."))
      .lines()
      .enumerate();

  for (idx, l) in reader {
    let line = l.expect("Failed to read line from challenge 4 set 01 input file.");
    let cipher_text =
      htb64::hex_bytes_to_bytes(line.as_bytes()).expect("Invalid Hexadecimal string");
    let mut valid_attempts: Vec<(u8, u64, String)> = Vec::new();
    for c in chars.as_bytes() {
      let attempt = String::from_utf8(xor::xor_single_byte(&cipher_text, *c));
      if let Ok(s) = attempt {
        if s.chars().any(|v| !valid.contains(v)) {
          continue;
        }
        valid_attempts.push((*c, character_frequency_score(s.clone()), s));
      }
    }
    if !valid_attempts.is_empty() {
      valid_attempts.sort_by(|&(_, s1, _), &(_, s2, _)| s1.cmp(&s2).reverse());
      candidates_table.insert((idx, line), valid_attempts);
    }
  }
  for ((idx, k), v) in candidates_table {
    if v[0].1 < 90 {
      continue;
    }
    println!(
      "Line Number: {}\nLine hex: '{}'\nTop Score: {:.5}\nTop Plaintext Attempt: {:?}",
      idx, k, v[0].1, v[0].2
    );
    println!("Candidates: [");
    let top_3_candidates = &v[0..(if v.len() <= 3 { v.len() } else { 3 })];
    for (k, s, p) in top_3_candidates {
      println!(
        "Key: '{}' | Score: {:.5} | Plaintext: {:?}",
        String::from_utf8(vec![*k]).unwrap(),
        s,
        p
      );
    }
    println!("]\n------------------------------------");
  }
}

#[allow(dead_code)]
pub fn challenge_6() {
  let input_file = "./res/challenge_6.txt";
  let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !@$%^&*()-_+=[{}]'\"\t<>,./?\\|:;`~\n\r".to_owned();
  let valid_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !@$%^&*()-_+=[{}]'\"\t<>,./?\\|:;`~\n\r".to_owned();

  let lines =
    BufReader::new(File::open(input_file).expect("Failed to open input file for challenge 6"))
      .lines();
  let base64_ciphertext: Vec<u8> = lines
    .into_iter()
    .flat_map(|v| {
      v.expect("Failed to read line from challenge 6 input file").bytes().collect::<Vec<u8>>()
    })
    .collect();

  let ciphertext_bytes = BASE64_STANDARD
    .decode(base64_ciphertext)
    .expect("Failed to decode Base64 string from input file for challenge 6");
  let key_sizes = 2..=40;

  let mut scores: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
  for ks in key_sizes {
    let sample: Vec<&[u8]> =
      ciphertext_bytes.chunks(ks).enumerate().take_while(|v| v.0 < 30).map(|(_, v)| v).collect();
    let s = sample
      .chunks(2)
      .map(|v| {
        hamming_distance(v[0], v[1])
          .expect("Failed to calculate hamming distance between two vecs of bytes in challenge 6")
      })
      .reduce(|v1, v2| v1 + v2)
      .unwrap_or_default()
      / (15 * ks as u32);
    scores.entry(s).or_default().push(ks);
  }
  let top: Vec<usize> = scores.iter().take(5).flat_map(|(_, v)| v).copied().collect();
  // top 5 scores and their key sizes
  let mut solutions_table: BTreeMap<usize, (String, String)> = BTreeMap::new();
  for size in top {
    let mut cols: Vec<Vec<u8>> = vec![vec![]; size];
    for idx in 0..ciphertext_bytes.len() {
      cols[idx % size].push(ciphertext_bytes[idx]);
    }
    let mut key: Vec<u8> = vec![];
    for column in cols {
      let mut char_scores: Vec<(u64, u8)> = Vec::new();
      for c in chars.as_bytes() {
        let attempt = String::from_utf8(xor::xor_single_byte(&column, *c));
        if let Ok(s) = attempt {
          if s.chars().any(|v| !valid_chars.contains(v)) {
            continue;
          }
          char_scores.push((character_frequency_score(s), *c));
        }
      }
      if char_scores.is_empty() {
        continue;
      }
      char_scores.sort_by(|(s1, _), (s2, _)| s1.cmp(s2).reverse());
      let (_, best) = char_scores[0];
      key.append(&mut vec![best]);
    }
    if !key.is_empty() {
      let plaintext = String::from_utf8(xor::xor_repeating_key(&key, &ciphertext_bytes)).unwrap();
      solutions_table.insert(size, (String::from_utf8(key).unwrap(), plaintext));
    }
  }
  let mut best_solution: (u64, usize, (String, String)) = (0, 0, ("".to_owned(), "".to_owned()));
  for (key_size, (key, plaintext)) in solutions_table {
    let score = character_frequency_score(plaintext.clone());

    if best_solution.0 < score {
      best_solution = (score, key_size, (key, plaintext));
    }
  }
  println!(
    "Key size:{:?}\nKey: {:?}\nPlaintext:\n{}\n---------------------------",
    best_solution.1, best_solution.2.0, best_solution.2.1
  );
}
#[allow(dead_code)]
pub fn challenge_7() {
  let input_file = "./res/challenge_7.txt";
  let lines =
    BufReader::new(File::open(input_file).expect("Failed to open input file for challenge 7"))
      .lines();
  let base64_ciphertext: Vec<u8> = lines
    .into_iter()
    .flat_map(|v| {
      v.expect("Failed to read line from challenge 7 input file").bytes().collect::<Vec<u8>>()
    })
    .collect();

  let ciphertext_bytes = BASE64_STANDARD
    .decode(base64_ciphertext)
    .expect("Failed to decode Base64 string from input file for challenge 7");

  let plaintext = cryptog::aes_128_ecb_decrypt("YELLOW SUBMARINE".as_bytes(), &ciphertext_bytes)
    .expect("Failed to decrypt input file from challenge 7");
  println!(
    "Plaintext:\n{}\n-------------------------------------",
    String::from_utf8(plaintext).unwrap()
  );
}

#[allow(dead_code)]
pub fn challenge_8() {
  let input_file = "./res/challenge_8.txt";
  let lines =
    BufReader::new(File::open(input_file).expect("Failed to open input file for challenge 8"))
      .lines();

  let lines_bytes: Vec<Vec<u8>> = lines
    .map(|line| {
      htb64::hex_bytes_to_bytes(
        line.expect("Failed to read line from input file for challenge 8").as_bytes(),
      )
      .expect("Failed to hex decode line from input file from challenge 8")
    })
    .collect();
  let mut best_guess_idx = 0;
  let mut best_guess_len = 0;
  for (idx, line_bytes) in lines_bytes.iter().enumerate() {
    let vec_chunks: Vec<&[u8]> = line_bytes.chunks(16).collect();
    let size = vec_chunks.len();
    let chunks: HashSet<&[u8]> = HashSet::from_iter(vec_chunks.into_iter());
    if chunks.len() == size {
      continue;
    }
    best_guess_idx = idx;
    best_guess_len = chunks.len();
  }

  println!(
    "Best guess line {} with {} chunks of 16 bytes instead of 10 chunks",
    best_guess_idx, best_guess_len,
  );
}

#[allow(dead_code)]
pub fn challenge_10() {
  let input_file = "./res/challenge_10.txt";
  let lines =
    BufReader::new(File::open(input_file).expect("Failed to open input file for challenge 10"))
      .lines();
  let base64_ciphertext: Vec<u8> = lines
    .into_iter()
    .flat_map(|v| {
      v.expect("Failed to read line from challenge 10 input file").bytes().collect::<Vec<u8>>()
    })
    .collect();

  let ciphertext_bytes = BASE64_STANDARD
    .decode(base64_ciphertext)
    .expect("Failed to decode Base64 string from input file for challenge 10");
  let plaintext_bytes =
    cryptog::aes_cbc_decrypt(&[0; 16], "YELLOW SUBMARINE".as_bytes(), &ciphertext_bytes).unwrap();
  println!("{}", String::from_utf8(plaintext_bytes).unwrap());
}

#[allow(dead_code)]
pub fn challenge_11() {
  let input = "SEVENTYSEVEN".to_owned().repeat(10);
  let (ciphertext, mode) = oracle::encryption_oracle(input.clone());
  let is_ecb = detect_ecb("SEVENTYSEVER".len(), &ciphertext);

  let guess = if is_ecb { "ECB".to_owned() } else { "CBC".to_owned() };
  println!("Guess: {}\nMode: {}", guess, mode);
  if guess != mode {
    panic!();
  }
}

#[allow(dead_code)]
pub fn challenge_12() {
  let oracle_key: Vec<u8> = rand::random_iter().take(16).collect();

  let key_size_guess =
    oracle_hacker::guess_key_size(&oracle_key, oracle::consistent_encryption_oracle);

  let unknown_string_size = oracle_hacker::guess_target_size(
    key_size_guess,
    &oracle_key,
    oracle::consistent_encryption_oracle,
  );
  let input = "SEVENTYSEVEN".to_owned().repeat(20);
  let ciphertext = oracle::consistent_encryption_oracle(input.as_bytes(), &oracle_key);
  if !detect_ecb(key_size_guess, &ciphertext) {
    panic!("ECB mode not detected")
  }

  let guess = oracle_hacker::guess_unknown_string(
    key_size_guess,
    oracle_hacker::guess_prefix_size(
      key_size_guess,
      &oracle_key,
      oracle::consistent_encryption_oracle,
    ),
    unknown_string_size,
    &oracle_key,
    oracle::consistent_encryption_oracle,
  );

  println!("Key size guess: {} bytes", key_size_guess);
  println!("Unknown string guess size: {} bytes", unknown_string_size);
  println!("Unknown String guess:");
  println!("{}", "-".repeat(20));
  print!("{}", guess);
  println!("{}", "-".repeat(20));
}

#[allow(dead_code)]
pub fn challenge_13() {
  let key: Vec<u8> = rand::random_iter().take(16).collect();
  let mut fake_padding = "".to_owned();
  fake_padding.push(char::from_u32(11).unwrap());
  fake_padding = fake_padding.repeat(11);

  let input_email = "foooo@bar.admin".to_owned() + &fake_padding + "com";
  let mut ciphertext = oracle_create_token(input_email, &key);
  let size = ciphertext.len();
  ciphertext.copy_within(key.len()..key.len() * 2, size - (key.len()));
  let res = oracle_parse_token(&ciphertext, &key);
  println!("{:#?}", res);
}

#[allow(dead_code)]
pub fn challenge_14() {
  let oracle_key: Vec<u8> = rand::random_iter().take(16).collect();

  let key_size_guess =
    oracle_hacker::guess_key_size(&oracle_key, oracle::consistent_encryption_oracle_prefixed);

  let unknown_string_size = oracle_hacker::guess_target_size(
    key_size_guess,
    &oracle_key,
    oracle::consistent_encryption_oracle_prefixed,
  );
  let input = "SEVENTYSEVEN".to_owned().repeat(20);
  let ciphertext = oracle::consistent_encryption_oracle_prefixed(input.as_bytes(), &oracle_key);
  if !detect_ecb(key_size_guess, &ciphertext) {
    panic!("ECB mode not detected")
  }

  let guess = oracle_hacker::guess_unknown_string(
    key_size_guess,
    oracle_hacker::guess_prefix_size(
      key_size_guess,
      &oracle_key,
      oracle::consistent_encryption_oracle_prefixed,
    ),
    unknown_string_size,
    &oracle_key,
    oracle::consistent_encryption_oracle_prefixed,
  );

  println!("Key size guess: {} bytes", key_size_guess);
  println!("Unknown string guess size: {} bytes", unknown_string_size);
  println!("Unknown String guess:");
  println!("{}", "-".repeat(20));
  print!("{}", guess);
  println!("{}", "-".repeat(20));
}

#[allow(dead_code)]
pub fn challenge_16(){
  let oracle_key:Vec<u8> = rand::random_iter().take(16).collect();
  let oracle_iv:Vec<u8> = rand::random_iter().take(16).collect();

  let attacker_plaintext = "something:admin<true".to_owned();
  let mut encrypted_token = oracle::oracle_cbc_token(attacker_plaintext, &oracle_iv, &oracle_key).unwrap();

  let oracle_fn = |plaintext:&[u8],key:&[u8]| -> Vec<u8> {oracle::oracle_cbc_token(String::from_utf8(plaintext.to_owned()).unwrap(), &oracle_iv, &key).unwrap()};
  let key_size = oracle_hacker::guess_key_size(&oracle_key, oracle_fn);
  let prefix_size = oracle_hacker::guess_prefix_size_cbc(key_size, &oracle_key, oracle_fn);

  let diff = prefix_size %key_size;
  let prefix_block = if prefix_size == 0 { 0 } else {prefix_size.div_ceil(key_size)-1};

  encrypted_token[prefix_block * key_size + diff + 9] ^= 0b0000_00001;
  encrypted_token[prefix_block * key_size + diff + 15] ^= 0b0000_00001;

  println!("Admin priviliges: {}",oracle::oracle_cbc_is_admin(&encrypted_token, &oracle_iv, &oracle_key).unwrap());
}
