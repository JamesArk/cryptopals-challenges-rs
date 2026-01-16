use cryptopals_challeges_rs::distance::{hamming_distance};


#[test]
fn small_distance() {
  assert!(hamming_distance("ab".to_owned(), "ba".to_owned()).unwrap() == 4);
  assert!(hamming_distance("ab".to_owned(), "ab".to_owned()).unwrap() == 0);
  assert!(hamming_distance("abc".to_owned(), "cba".to_owned()).unwrap() == 2);
  assert!(hamming_distance(vec![0b00000000], vec![0b00000000]).unwrap() == 0);
  assert!(hamming_distance(vec![0b00000000], vec![0b11111111]).unwrap() == 8);
  assert!(hamming_distance(vec![0b10101010], vec![0b01010101]).unwrap() == 8);
}

#[test]
fn big_distance() {
  assert!(hamming_distance("ABCdefHIJklmnopqrstuvwxyz".to_owned(), "123445678901234567890wxyz".to_owned()).unwrap() == 70);

}

#[test]
fn challenge_6(){
  assert!( hamming_distance("this is a test".to_owned(), "wokka wokka!!!".to_owned()).unwrap() == 37)
}
