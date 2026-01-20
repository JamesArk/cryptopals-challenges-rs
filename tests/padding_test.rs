use cryptopals_challeges_rs::cryptog::pkcs7_padding;

#[test]
fn challenge_9() {
  let mut data = "YELLOW SUBMARINE".as_bytes().to_owned();
  pkcs7_padding(&mut data,20);
  assert!(hex::encode(&data) == hex::encode("YELLOW SUBMARINE") + "04040404");
}

#[test]
fn small_block_size() {
  let mut data = vec![0x01,0x02,0x03,0x04];
  pkcs7_padding(&mut data,20);
  let expected = hex::encode(vec![0x01,0x02,0x03,0x04]) + &vec!["10".to_owned();16].join(&"".to_owned());
  assert!( hex::encode(&data) == expected );
}

#[test]
fn multiple_of_block_size() {
  let mut data:Vec<u8> = vec![0;1024];
  rand::fill(&mut data[..]);
  let mut res_data = data.clone();
  pkcs7_padding(&mut res_data,16);
  let expected = hex::encode(data.clone());
  assert!( hex::encode(&res_data) == expected );
}


#[test]
fn big_message() {
  let mut data:Vec<u8> = vec![0;111_111];
  rand::fill(&mut data[..]);
  let mut res_data = data.clone();
  pkcs7_padding(&mut res_data,32);
  let expected = hex::encode(data.clone()) + &vec!["19".to_owned();25].join(&"".to_owned());
  assert!( hex::encode(&res_data) == expected );
}
