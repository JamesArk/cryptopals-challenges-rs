use cryptopals_challeges_rs::oracle::{self, CookieValue, profile_for};


#[test]
fn all_types() {
  let input = "year=2026&admin=false&name=I AM THE ONE THAT IS APPROACHING".to_owned();
  let obj = oracle::parse_cookie(input);
  assert!(obj.get("year").unwrap() == &CookieValue::NumberValue(2026));
  assert!(obj.get("admin").unwrap() == &CookieValue::BoolValue(false));
  dbg!(obj.get("name").unwrap());
  assert!(obj.get("name").unwrap() == &CookieValue::StringValue("IAMTHEONETHATISAPPROACHING".to_owned()));
}

#[test]
fn challenge_13() {
  let input = "foo=bar&baz=qux&zap=zazzle".to_owned();
  let obj = oracle::parse_cookie(input);
  assert!(obj.get("foo").unwrap() == &CookieValue::StringValue("bar".to_owned()));
  assert!(obj.get("baz").unwrap() == &CookieValue::StringValue("qux".to_owned()));
  assert!(obj.get("zap").unwrap() == &CookieValue::StringValue("zazzle".to_owned()));
  assert!(profile_for("foo@bar.com".to_owned()) == "email=foo@bar.com&uid=10&role=user".to_owned());
}
