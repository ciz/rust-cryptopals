use utils::utils::{CryptoData};

mod utils;

fn chal1() {
	// string: "I'm killing your brain like a poisonous mushroom"
	// base64: "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	let test_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

	let cd = CryptoData::from_hex(test_hex);
	println!("hex: {}", test_hex);
	println!("base64: {}", cd.to_base64());
	println!("text: {}", cd.to_text());
}

fn chal2() {
	let a = CryptoData::from_hex("1c0111001f010100061a024b53535009181c");
	let b = CryptoData::from_hex("686974207468652062756c6c277320657965");
	let expected = CryptoData::from_hex("746865206b696420646f6e277420706c6179");
	println!("a: {}", a);
	println!("b: {}", b);
	println!("expected: {}", expected);
	let res = a.xor(b);
	assert!(res == expected);
	println!("res: {}", res);
}

fn main() {
	chal1();
	chal2();
}
