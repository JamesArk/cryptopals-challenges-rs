use std;

mod htb64;
fn main() {
   let stdin = std::io::stdin();
   let mut buf = String::new();
   stdin.read_line(&mut buf).expect("Something went wrong when reading from stdin");
   while buf != "\n" {
     buf.pop();
     let res = htb64::hex_to_base64(buf.as_bytes());
     match res {
      Ok(base64_string) => println!("{}",base64_string),
      Err(err) => println!("{}",err)
     }

     buf.clear();
     stdin.read_line(&mut buf).expect("Something went wrong when reading from stdin");
   }
}
