mod htb64;
mod xor;
fn main() {
  let stdin = std::io::stdin();
  let mut buf1 = String::new();
  let mut buf2 = String::new();
  stdin.read_line(&mut buf1).expect("Something went wrong when reading from stdin");
  stdin.read_line(&mut buf2).expect("Something went wrong when reading from stdin");
  while buf1 != "\n" || buf2 != "\n" {
    buf1.pop();
    buf2.pop();
    let res = xor::xor_bytes(&hex::decode(buf1.clone()).unwrap(), &hex::decode(buf2.clone()).unwrap());
    match res {
      Ok(xor) => println!("{}", hex::encode(xor)),
      Err(err) => println!("{}", err),
    }

    buf1.clear();
    buf2.clear();
    stdin.read_line(&mut buf1).expect("Something went wrong when reading from stdin");
    stdin.read_line(&mut buf2).expect("Something went wrong when reading from stdin");
  }
}
