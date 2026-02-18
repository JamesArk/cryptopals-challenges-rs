use std::collections::{HashMap, HashSet, VecDeque};

use crate::htb64;

pub fn detect_ecb(key_size: usize, ciphertext: &[u8]) -> bool {
  let ciphertext_hex = htb64::bytes_to_hex(ciphertext);
  let set: HashSet<String> = HashSet::from_iter(
    ciphertext_hex.as_bytes().chunks(key_size * 2).map(|v| String::from_utf8(v.to_vec()).unwrap()),
  );
  let res: Vec<u8> = set.iter().flat_map(|v| v.as_bytes()).copied().collect();
  res.len() != ciphertext_hex.len()
}

pub fn guess_key_size(oracle_key: &[u8], oracle_fn: impl Fn(&[u8], &[u8]) -> Vec<u8>) -> usize {
  let plaintext = "A".to_string();
  let ciphertext = oracle_fn(plaintext.as_bytes(), oracle_key);
  let hex_ciphertext = htb64::bytes_to_hex(&ciphertext);
  let last_size = hex_ciphertext.len() / 2usize;
  for input_size in 2..=64 {
    let plaintext = "A".repeat(input_size);
    let ciphertext = oracle_fn(plaintext.as_bytes(), oracle_key);
    let hex_ciphertext = htb64::bytes_to_hex(&ciphertext);
    if last_size < hex_ciphertext.len() / 2usize {
      return hex_ciphertext.len() / 2usize - last_size;
    }
  }
  last_size
}

pub fn guess_prefix_size(
  key_size: usize,
  oracle_key: &[u8],
  oracle_fn: impl Fn(&[u8], &[u8]) -> Vec<u8>,
) -> usize {
  let mut input: Vec<u8> = vec![key_size as u8];
  let starting_size = oracle_fn(&input, oracle_key).len();
  for _ in 1..=key_size {
    input.push(key_size as u8);
    let size = oracle_fn(&input, oracle_key).len();
    if starting_size != size {
      break;
    }
  }
  let target = htb64::bytes_to_hex(oracle_fn(&input, oracle_key).chunks(key_size).last().unwrap());
  input.clear();

  let mut first_block_idx = 0;
  'outer: for _ in 1..(key_size * 2) {
    input.push(key_size as u8);
    let ciphertext_hex_blocks: Vec<String> =
      oracle_fn(&input, oracle_key).chunks(key_size).map(htb64::bytes_to_hex).collect();
    for (idx, block) in
      ciphertext_hex_blocks.iter().enumerate().take(ciphertext_hex_blocks.len() - 1)
    {
      if *block == target {
        first_block_idx = idx;
        break 'outer;
      }
    }
  }

  if first_block_idx > 0 { first_block_idx * key_size - (input.len() % key_size) } else { 0 }
}

pub fn guess_target_size(
  key_size: usize,
  oracle_key: &[u8],
  oracle_fn: impl Fn(&[u8], &[u8]) -> Vec<u8>,
) -> usize {
  let prefix_length = guess_prefix_size(key_size, oracle_key, |u,v| oracle_fn(u,v));
  let last_size = oracle_fn("A".as_bytes(), oracle_key).len();
  for i in 2..key_size {
    let total_size = oracle_fn("A".repeat(i).as_bytes(), oracle_key).len();
    if total_size != last_size {
      return last_size - i - prefix_length;
    }
  }
  0
}

pub fn guess_unknown_string(
  key_size: usize,
  prefix_size: usize,
  string_size: usize,
  oracle_key: &[u8],
  oracle_fn: fn(&[u8], &[u8]) -> Vec<u8>,
) -> String {
  let prefix_padding = (key_size - prefix_size % key_size) % key_size;
  let string_padding = (key_size - string_size % key_size) % key_size;

  let mut input_buffer: VecDeque<u8> =
    VecDeque::from(vec![b'A'; prefix_padding + string_size + string_padding + key_size]);
  let mut dictionary: HashMap<String, Vec<u8>> = HashMap::new();
  let mut solution = vec![];
  input_buffer.pop_back();
  for chars_found in 0..string_size {
    let target_ciphertext: Vec<u8> = oracle_fn(input_buffer.make_contiguous(), oracle_key)
      .into_iter()
      .skip(prefix_size + input_buffer.len() - key_size + chars_found + 1)
      .take(key_size)
      .collect();
    for c in solution.iter() {
      input_buffer.push_back(*c);
    }

    for c in 0..=255u8 {
      input_buffer.push_back(c);
      let guess_ciphertext: Vec<u8> = oracle_fn(input_buffer.make_contiguous(), oracle_key)
        .into_iter()
        .skip(prefix_size + input_buffer.len() - key_size)
        .take(key_size)
        .collect();
      let input_size = input_buffer.len();
      let guess_input: Vec<u8> = input_buffer
        .make_contiguous()
        .iter()
        .skip(input_size - key_size)
        .take(key_size)
        .copied()
        .collect();
      dictionary.insert(htb64::bytes_to_hex(&guess_ciphertext), guess_input);
      input_buffer.pop_back();
    }
    for _ in solution.iter() {
      input_buffer.pop_back();
    }
    input_buffer.pop_front();

    let sol =
      dictionary.get(&htb64::bytes_to_hex(&target_ciphertext)).unwrap().iter().last().unwrap();
    solution.push(*sol);
  }
  String::from_utf8(solution).unwrap()
}


pub fn guess_prefix_size_cbc(
  key_size: usize,
  oracle_key: &[u8],
  oracle_fn: impl Fn(&[u8], &[u8]) -> Vec<u8>,
) -> usize {
  let mut input: Vec<u8> = vec![key_size as u8];
  let starting_size = oracle_fn(&input, oracle_key).len();
  for _ in 1..=key_size {
    input.push(key_size as u8);
    let size = oracle_fn(&input, oracle_key).len();
    if starting_size != size {
      break;
    }
  }
  let ciphertext_hex_blocks: Vec<String> = oracle_fn(&input, oracle_key).chunks(key_size).map(htb64::bytes_to_hex).collect();
  input[0] = 0;
  let altered_ciphertext_hex_blocks: Vec<String> = oracle_fn(&input, oracle_key).chunks(key_size).map(htb64::bytes_to_hex).collect();

  let mut known_prefix_blocks = 0;
  for i in 0..ciphertext_hex_blocks.len() {
    if ciphertext_hex_blocks[i] != altered_ciphertext_hex_blocks[i] {
      break;
    }
    known_prefix_blocks+=1;
  }
  input[0] = key_size as u8;
  input.append(&mut vec![key_size as u8;key_size]);
  let ciphertext_hex_blocks: Vec<String> = oracle_fn(&input, oracle_key).chunks(key_size).map(htb64::bytes_to_hex).collect();

  let skipped_bytes = 0;
  for i in 0..input.len() {
    input[i] = 0;
    let altered_ciphertext_hex_blocks: Vec<String> = oracle_fn(&input, oracle_key).chunks(key_size).map(htb64::bytes_to_hex).collect();
    if ciphertext_hex_blocks[known_prefix_blocks] == altered_ciphertext_hex_blocks[known_prefix_blocks]{
      break;
    }
    input[i] = key_size as u8;
  }
  known_prefix_blocks*key_size - skipped_bytes

}
