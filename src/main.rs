use std::env;

mod challenges;
mod cryptog;
mod htb64;
mod oracle;
mod oracle_hacker;
mod xor;

fn main() {
  let challenges_vec: Vec<fn()> = vec![
    challenges::challenge_1,
    challenges::challenge_2,
    challenges::challenge_3,
    challenges::challenge_4,
    challenges::challenge_5,
    challenges::challenge_6,
    challenges::challenge_7,
    challenges::challenge_8,
    challenges::challenge_9,
    challenges::challenge_10,
    challenges::challenge_11,
    challenges::challenge_12,
    challenges::challenge_13,
    challenges::challenge_14,
    challenges::challenge_15,
    challenges::challenge_16,
    challenges::challenge_17,
    challenges::challenge_18,
    challenges::challenge_19,
    challenges::challenge_20,
  ];

  let args:Vec<String> = env::args().collect();
  let challenge = if args.len() == 1 || args.len() > 2 {
    challenges_vec.len() as i32
  } else if args[1].chars().all(|v| v.is_digit(10)) {
    args[1].parse::<i32>().unwrap()
  } else {
    println!("Please specify a number from {} to {} for the challenge",1,challenges_vec.len());
    return;
  };
  if challenge > challenges_vec.len() as i32 || challenge < 1 {
    println!("Challenge not available");
    return;
  }

  let line = format!("{}CHALLENGE {}{}","-".repeat(16),challenge,"-".repeat(16));
  println!("{}",line);
  challenges_vec[challenge as usize - 1]();
  println!("{}","-".repeat(line.len()));
}
