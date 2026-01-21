use cryptopals_challeges_rs::cryptog::{aes_cbc_decrypt, aes_cbc_encrypt};


#[test]
fn small_plaintext() {
  let input = "I AM HERE";
  let key:Vec<u8> = rand::random_iter().take(16).collect();
  let iv:Vec<u8> = vec![0;16];
  let ciphertext = aes_cbc_encrypt(&iv, &key, input.as_bytes());
  assert!(ciphertext.is_ok());

  let plaintext = aes_cbc_decrypt(&iv, &key, &ciphertext.unwrap());
  assert!(plaintext.is_ok());
  assert!(String::from_utf8(plaintext.unwrap()).unwrap() == input)
}

#[test]
fn big_plaintext() {
  let input = "What's so hard about good-byes?I'm sorry, I'm just not as keen on planning out our perfect lives when I'm only 19. I am happy to be only all that you see.";
  let key:Vec<u8> = rand::random_iter().take(16).collect();
  let iv:Vec<u8> = rand::random_iter().take(16).collect();
  let ciphertext = aes_cbc_encrypt(&iv, &key, input.as_bytes());
  assert!(ciphertext.is_ok());

  let plaintext = aes_cbc_decrypt(&iv, &key, &ciphertext.unwrap());
  assert!(plaintext.is_ok());
  assert!(String::from_utf8(plaintext.unwrap()).unwrap() == input)
}

#[test]
fn huge_plaintext() {
  let input:Vec<u8> = rand::random_iter().take(10240).collect();
  let key:Vec<u8> = rand::random_iter().take(16).collect();
  let iv:Vec<u8> = rand::random_iter().take(16).collect();
  let ciphertext = aes_cbc_encrypt(&iv, &key, &input);
  assert!(ciphertext.is_ok());

  let plaintext = aes_cbc_decrypt(&iv, &key, &ciphertext.unwrap());
  assert!(plaintext.is_ok());
  assert!(hex::encode(plaintext.unwrap()) == hex::encode(input));

}

#[test]
fn wrong_key_size() {
  let input:Vec<u8> = rand::random_iter().take(10240).collect();
  let key:Vec<u8> = rand::random_iter().take(100).collect();
  let iv:Vec<u8> = rand::random_iter().take(16).collect();
  let res = aes_cbc_encrypt(&iv, &key, &input);
  assert!(res.is_err());
}
