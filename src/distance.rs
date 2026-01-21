use crate::xor::{self, XORMismatchSizeError};

pub fn hamming_distance<A: Into<Vec<u8>>, B: Into<Vec<u8>>>(a: A, b: B) -> Result<u32, XORMismatchSizeError>
{
  fn inner (a_inner: &[u8], b_inner: &[u8]) -> Result<u32, XORMismatchSizeError> {
    Ok(xor::xor_fixed_length(a_inner, b_inner)?.iter().map(|v| v.count_ones()).sum::<u32>())
  }
  inner(&a.into(), &b.into())
}
