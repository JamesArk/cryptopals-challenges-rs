use std::fmt::Display;

use itertools::Itertools;


#[derive(Debug, Clone)]
pub struct XORMismatchSizeError {}

impl Display for XORMismatchSizeError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "Arrays of bytes do not have the same length")
  }
}

pub fn xor_fixed_length(a :&[u8], b :&[u8]) -> Result<Vec<u8>,XORMismatchSizeError> {
  if a.len() != b.len() {
    return Err(XORMismatchSizeError{})
  }
  Ok(a.iter().zip(b).map(|(a,b)| a^b).collect_vec())
}


pub fn xor_single_byte(a :&[u8], b :u8) -> Vec<u8>{
  a.iter().map(|c| c ^ b).collect()
}
