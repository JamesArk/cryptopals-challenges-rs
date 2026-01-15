use cryptopalls_challeges_rs::xor;


#[test]
fn xor_mismatch_sizes() {
  assert!(xor::xor_bytes(&vec![10,20,30], &vec![50]).is_err())
}

#[test]
fn small_xor() {
  let a = vec![101;10];
  let b = vec![50;10];
  let res = xor::xor_bytes(&a, &b);
  let mut c = vec![0;10];
  for i in 0..a.len() {
    c[i] = a[i]^b[i];
  }
  assert!(res.is_ok());
  assert_eq!(c,res.unwrap())
}

#[test]
fn big_xor() {
  let a:Vec<u8> = (0..4096).map(|_| rand::random_range(0..=255)).collect();
  let b:Vec<u8> = (0..4096).map(|_| rand::random_range(0..=255)).collect();
  let res = xor::xor_bytes(&a, &b);
  let mut c = vec![0;4096];
  for i in 0..a.len() {
    c[i] = a[i]^b[i];
  }
  assert!(res.is_ok());
  assert_eq!(c,res.unwrap())
}

#[test]
fn cryptopals_challenge_set_01_challenge_02() {
  let input1 = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
  let input2 = hex::decode("686974207468652062756c6c277320657965").unwrap();
  let res = xor::xor_bytes(&input1, &input2);
  assert!(res.is_ok());
  assert!(hex::encode(res.unwrap()) == "746865206b696420646f6e277420706c6179")
}
