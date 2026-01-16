use itertools::{Itertools};

use crate::xor::{self, XORMismatchSizeError};

pub fn hamming_distance<A: Into<Vec<u8>>, B: Into<Vec<u8>>>(a: A, b: B) -> Result<u32, XORMismatchSizeError>
{
  fn inner (a_inner: &[u8], b_inner: &[u8]) -> Result<u32, XORMismatchSizeError> {
    Ok(xor::xor_fixed_length(a_inner, b_inner)?.iter().map(|v| v.count_ones()).sum::<u32>())
  }
  inner(&a.into(), &b.into())
}


pub fn levenshtein_distance_char(a: String, b: String) -> u32 {
  let (s1,s2) = if a.len() > b.len() {
    (b.chars().collect_vec(),a.chars().collect_vec())
  } else {
    (a.chars().collect_vec(),b.chars().collect_vec())
  };

  let mut v0:Vec<u32> = (0..(s2.len() as u32 + 1)).collect_vec();
  let mut v1:Vec<u32> = vec![0;s2.len()+1];
  for i in 0..s1.len() {
    v1[0] = i as u32 + 1;
    for j in 0..s2.len(){
      let del_cost = v0[j+1] + 1;
      let insert_cost = v1[j] + 1;
      let subs_cost = if s1[i] == s2[j] {
        v0[j]
      } else {
        v0[j] + 1
      };
      v1[j+1] = del_cost.min(insert_cost).min(subs_cost);
    }
    (v0,v1) = (v1,v0);
  }

  v0[v0.len()-1]
}
