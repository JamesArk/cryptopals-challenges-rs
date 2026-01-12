use std::time;

mod mhex;
fn main() {
  let now = time::Instant::now();
  mhex::input_from_file_real("./input_hex.txt".to_string(),"./output_base64_real.txt".to_string());
  let dur = now.elapsed();
  println!("Time taken hex to base64 real {:?}",dur);

  let now = time::Instant::now();
  mhex::input_from_file_mine("./input_hex.txt".to_string(),"./output_base64.txt".to_string());
  let dur = now.elapsed();
  println!("Time taken hex to base64 mine {:?}",dur);
}
