use cryptopals_challeges_rs::cryptog::pkcs7_padding;

#[test]
fn challenge_9() {
  let data = "YELLOW SUBMARINE".as_bytes().to_owned();
  let res = pkcs7_padding(data,20);
  assert!(hex::encode(&res) == hex::encode("YELLOW SUBMARINE") + "04040404");
}

#[test]
fn small_block_size() {
  let data = vec![0x01,0x02,0x03,0x04];
  let res = pkcs7_padding(data,20);
  let expected = hex::encode(vec![0x01,0x02,0x03,0x04]) + &vec!["10".to_owned();16].join(&"".to_owned());
  assert!( hex::encode(&res) == expected );
}

#[test]
fn multiple_of_block_size() {
  let mut data:Vec<u8> = vec![0;1024];
  rand::fill(&mut data[..]);
  let res_data = pkcs7_padding(data.clone(),16);
  let expected = hex::encode(data.clone()) + &hex::encode(vec![16;16]);
  assert!( hex::encode(&res_data) == expected );
}


#[test]
fn big_message() {
  let mut data:Vec<u8> = vec![0;111_111];
  rand::fill(&mut data[..]);
  let res_data = pkcs7_padding(data.clone(),32);
  let expected = hex::encode(data.clone()) + &vec!["19".to_owned();25].join(&"".to_owned());
  assert!( hex::encode(&res_data) == expected );
}
