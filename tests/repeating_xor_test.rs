use cryptopals_challeges_rs::xor;

#[test]
fn simple_key() {
  let res = xor::xor_repeating_key("I AM A KEY".as_bytes(),"I am a very long phrase compared to the key and i am going to be xor'd good bye".as_bytes());
  assert!(hex::encode(res) == "000020200020003d202b30002d224e26003b2d2b2853246d432e4d3b242b2c4461394f61542320792245386d412f446b2c79284d612a4f284e2c652d2600232800394f39623d69472e224461423220")
}

#[test]
fn cryptopals_challenge_set_01_challenge_05(){
  let input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
  let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
  let res = xor::xor_repeating_key("ICE".as_bytes(), input.as_bytes());
  assert!(hex::encode(res) == expected)
}
