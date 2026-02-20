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

pub fn challenge_1() {
  let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
  let res = htb64::hex_to_base64(input.as_bytes());
  println!("Challenge: hex to Base64");
  println!("Input: {:?}", input);
  println!("Expected: \"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t\"");
  println!("Actual: {:?}", res.unwrap());
}

pub fn challenge_2() {
  let input1 = "1c0111001f010100061a024b53535009181c";
  let input2 = "686974207468652062756c6c277320657965";
  let res = xor::xor_fixed_length(
    &htb64::hex_bytes_to_bytes(&input1.as_bytes()).unwrap(),
    &htb64::hex_bytes_to_bytes(&input2.as_bytes()).unwrap(),
  );
  println!("Challenge: fixed/same size xor");
  println!("Input1: {:?}", input1);
  println!("Input2: {:?}", input2);
  println!("Expected: \"746865206b696420646f6e277420706c6179\"");
  println!("Actual: {:?}", htb64::bytes_to_hex(&res.unwrap()));
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

  println!("Challenge: Crack Single-byte XOR cipher");
  println!("Input: {:?}", input);
  println!("Attempts:");
  for (k, v) in res {
    println!("{}", "-".repeat(16));
    println!("Character: {:?} | Score:{:.5}", String::from_utf8(vec![k]).unwrap(), v);
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
  println!("Challenge: Detect single-character XOR");
  println!("Input: {:?}", input_file);
  println!("Line Candidates:");
  for ((idx, k), v) in candidates_table {
    if v[0].1 < 90 {
      continue;
    }
    println!("{}", "-".repeat(16));
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
    println!("]");
  }
}

pub fn challenge_5() {
  let input = "\
Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
  let res = htb64::bytes_to_hex(&xor::xor_repeating_key("ICE".as_bytes(), input.as_bytes()));
  println!("Challenge: Implement repeating-key XOR");
  println!("Input: {:?}", input);
  println!(
    "Expected:\n\"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f\""
  );
  println!("Actual:\n{:?}",res.to_ascii_lowercase());
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
  println!("Challenge: Break repeating-key XOR");
  println!("Input: {:?}",input_file);
  println!("Guess Key size: {:?}",best_solution.1);
  println!("Guess Key: {:?}",best_solution.2.0);
  println!("Actual Key size: 29");
  println!("Actual Key: \"Terminator X: Bring the noise\"");
  println!("Plaintext:\n{}","-".repeat(16));
  print!("{}",best_solution.2.1);
  println!("{}","-".repeat(16));
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
  println!("Challenge: AES in ECB mode");
  println!("Input: {:?}",input_file);
  println!(
    "Plaintext:\n{}",
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
    best_guess_idx = idx+1;
    best_guess_len = chunks.len();
  }

  println!("Challenge: Detect AES in ECB mode");
  println!("Input: {:?}",input_file);
  println!(
    "Best guess line {} with {} chunks of 16 bytes instead of 10 chunks",
    best_guess_idx, best_guess_len,
  );
  println!("Actual line: 133");
  println!("Actual unique sequence size: {} chunks of 16 bytes",7);
}

pub fn challenge_9() {
  let input = "YELLOW SUBMARINE";
  let res = cryptog::pkcs7_padding(input.as_bytes().to_owned(), 20);
  println!("Challenge: Implement PKCS#7 padding");
  println!("Input: {:?}", input);
  println!("Expected: {:?}",input.to_owned()+&String::from_utf8(vec![4;4]).unwrap());
  println!("Expected: {:?}",String::from_utf8(res).unwrap());
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
  let key = "YELLOW SUBMARINE";
  let iv = vec![0; 16];
  let plaintext_bytes =
    cryptog::aes_cbc_decrypt(&iv,key.as_bytes(), &ciphertext_bytes).unwrap();
  println!("Challenge: Implement CBC mode");
  println!("Input: {:?}",input_file);
  println!("Key: {:?}",key);
  println!("IV: {:?}",String::from_utf8(iv).unwrap());
  println!("Plaintext:");
  println!("{}", String::from_utf8(plaintext_bytes).unwrap());
}

#[allow(dead_code)]
pub fn challenge_11() {
  let input = "SEVENTYSEVEN".to_owned().repeat(10);
  let (ciphertext, mode) = oracle::encryption_oracle(input.clone());
  let is_ecb = detect_ecb("SEVENTYSEVER".len(), &ciphertext);

  let guess = if is_ecb { "ECB".to_owned() } else { "CBC".to_owned() };
  println!("Challenge: ECB/CBC detection oracle");
  println!("Expected: {:?}",mode);
  println!("Guess: {:?}",guess);
}

#[allow(dead_code)]
pub fn challenge_12() {
  let oracle_key: Vec<u8> = rand::random_iter().take(16).collect();
  let oracle_fn = |pt: &[u8]| oracle::consistent_encryption_oracle(pt, &oracle_key);
  let key_size_guess = oracle_hacker::guess_key_size(oracle_fn);

  let unknown_string_size = oracle_hacker::guess_target_size(key_size_guess, oracle_fn);
  let input = "SEVENTYSEVEN".to_owned().repeat(20);
  let ciphertext = oracle::consistent_encryption_oracle(input.as_bytes(), &oracle_key);
  if !detect_ecb(key_size_guess, &ciphertext) {
    panic!("ECB mode not detected")
  }

  let guess = oracle_hacker::guess_unknown_string(
    key_size_guess,
    oracle_hacker::guess_prefix_size(key_size_guess, oracle_fn),
    unknown_string_size,
    &oracle_key,
    oracle::consistent_encryption_oracle,
  );

  println!("Challenge: Byte-at-a-time ECB decryption (Simple)");
  println!("Actual Key size: 16 bytes");
  println!("Key size guess: {} bytes", key_size_guess);
  println!("Actual Unknown String size: 138 bytes");
  println!("Unknown string guess size: {} bytes", unknown_string_size);
  println!("Plaintext guess:");
  println!("{}","-".repeat(20));
  print!("{}", guess);
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
  println!("Challenge: ECB cut-and-paste");
  println!("Resulting token fields:");
  println!("{:#?}", res);
}

#[allow(dead_code)]
pub fn challenge_14() {
  let oracle_key: Vec<u8> = rand::random_iter().take(16).collect();
  let oracle_fn = |pt: &[u8]| oracle::consistent_encryption_oracle_prefixed(pt, &oracle_key);
  let key_size_guess = oracle_hacker::guess_key_size(oracle_fn);

  let unknown_string_size = oracle_hacker::guess_target_size(key_size_guess, oracle_fn);
  let input = "SEVENTYSEVEN".to_owned().repeat(20);
  let ciphertext = oracle::consistent_encryption_oracle_prefixed(input.as_bytes(), &oracle_key);
  if !detect_ecb(key_size_guess, &ciphertext) {
    panic!("ECB mode not detected")
  }

  let guess = oracle_hacker::guess_unknown_string(
    key_size_guess,
    oracle_hacker::guess_prefix_size(key_size_guess, oracle_fn),
    unknown_string_size,
    &oracle_key,
    oracle::consistent_encryption_oracle_prefixed,
  );

  println!("Challenge: Byte-at-a-time ECB decryption (Harder)");
  println!("Actual Key size: 16 bytes");
  println!("Key size guess: {} bytes", key_size_guess);
  println!("Actual Unknown String size: 138 bytes");
  println!("Unknown string guess size: {} bytes", unknown_string_size);
  println!("Plaintext guess:");
  println!("{}","-".repeat(20));
  print!("{}", guess);
}

pub fn challenge_15() {
  let input_correct = "ICE ICE BABY\x04\x04\x04\x04";
  let input_incorrect_1 = "ICE ICE BABY\x05\x05\x05\x05";
  let input_incorrect_2 = "ICE ICE BABY\x01\x02\x03\x04";
  let correct_guess = cryptog::validate_undo_pkcs7_padding(input_correct.as_bytes());
  let incorrect_guess_1 = cryptog::validate_undo_pkcs7_padding(input_incorrect_1.as_bytes());
  let incorrect_guess_2 = cryptog::validate_undo_pkcs7_padding(input_incorrect_1.as_bytes());

  println!("Challenge: PKCS#7 padding validation");
  println!("Input correct: {:?}",input_correct);
  println!("Input incorrect 1: {:?}",input_incorrect_1);
  println!("Input incorrect 2: {:?}",input_incorrect_2);
  println!("Actual validation:");
  println!("Input correct result: {:?}",correct_guess);
  println!("Input correct unpadded: {:?}", String::from_utf8(correct_guess.unwrap()).unwrap());
  println!("Input incorrect 1 result: {:?}",incorrect_guess_1);
  println!("Input incorrect 2 result: {:?}",incorrect_guess_2)
}

#[allow(dead_code)]
pub fn challenge_16() {
  let oracle_key: Vec<u8> = rand::random_iter().take(16).collect();
  let oracle_iv: Vec<u8> = rand::random_iter().take(16).collect();

  let oracle_fn = |plaintext: &[u8]| -> Vec<u8> {
    oracle::oracle_cbc_token(
      String::from_utf8(plaintext.to_owned()).unwrap(),
      &oracle_iv,
      &oracle_key,
    )
    .unwrap()
  };
  let key_size = oracle_hacker::guess_key_size(oracle_fn);
  let prefix_size = oracle_hacker::guess_prefix_size_cbc(key_size, oracle_fn);

  let attacker_plaintext = "A".repeat(key_size) + ":admin<true";
  let mut encrypted_token =
    oracle::oracle_cbc_token(attacker_plaintext, &oracle_iv, &oracle_key).unwrap();

  let diff = prefix_size % key_size;
  let prefix_block = if prefix_size == 0 { 0 } else { prefix_size.div_ceil(key_size) - 1 };

  encrypted_token[(prefix_block + 1) * key_size + diff] ^= 0b0000_00001;
  encrypted_token[(prefix_block + 1) * key_size + diff + 6] ^= 0b0000_00001;

  println!("Challenge: CBC bitflipping attacks");
  println!(
    "Admin priviliges: {}",
    oracle::oracle_cbc_is_admin(&encrypted_token, &oracle_iv, &oracle_key).unwrap()
  );
}
