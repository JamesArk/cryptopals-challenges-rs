use std::io::stdin;


mod challenges;
mod htb64;
mod xor;

fn main() {
  let stdin = stdin();
  let mut buf = String::new();
  stdin.read_line(&mut buf).expect("Failed to read from stdin");
  let res = xor::xor_repeating_key("ICE".as_bytes(), buf.as_bytes());
  println!("{:?}",String::from_utf8(res));
}
