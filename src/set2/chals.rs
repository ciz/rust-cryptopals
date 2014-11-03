extern crate collections;

use utils::utils::{CryptoData};
use self::collections::vec::Vec;

// Implement PKCS#7 padding
pub fn chal9() {
	let text = CryptoData::from_text("YELLOW SUBMARINE");
	let padded_text = text.pkcs7_pad(20);
	println!("text: {}", text.to_hex());
	println!("padded text: {}", padded_text.to_hex());
}

// Implement CBC mode
pub fn chal10() {
	use std::io::File;

	let key = CryptoData::from_text("YELLOW SUBMARINE");
	let fname = "src/set2/10.txt";
	//let fname = "x";
	let path = Path::new(fname);
	let contents = File::open(&path).read_to_string();
	let base64_str = match contents { Ok(x) => x, Err(e) => panic!(e) };

	let mut zero_vec: Vec<u8> = Vec::new();
	for _ in range(0i, 16) {
		zero_vec.push(0u8);
	}
	let iv = CryptoData::from_vec(&zero_vec);

/*
	let encrypted = CryptoData::from_text(base64_str.as_slice());
	//println!("hex: {}", encrypted.to_hex());
	let decrypted = encrypted.CBC_encrypt(&key, &iv);
	//let decrypted = encrypted.CBC_encrypt(&key, &iv);
	println!("text: {}", decrypted.to_hex());
*/

	let encrypted = CryptoData::from_base64(base64_str.as_slice());
	//println!("hex: {}", encrypted.to_hex());
	let decrypted = encrypted.CBC_decrypt(&key, &iv);
	//let decrypted = encrypted.CBC_encrypt(&key, &iv);
	println!("text: {}", decrypted.to_text());
}

// An ECB/CBC detection oracle
pub fn chal11() {
	//TODO
}

// Byte-at-a-time ECB decryption (Simple)
pub fn chal12() {
	//TODO
}

// ECB cut-and-paste
pub fn chal13() {
	//TODO
}

// Byte-at-a-time ECB decryption (Harder)
pub fn chal14() {
	//TODO
}

// PKCS#7 padding validation
pub fn chal15() {
	//let text = CryptoData::from_text("ICE ICE BABY\x04\x04\x04");
	let text = CryptoData::from_text("ICE ICE BABY\x04\x04\x04\x04");
	if text.pkcs7_pad_verify(16) {
		println!("text padded correctly");
	} else {
		println!("text has invalid padding");
	}
}

// CBC bitflipping attacks
pub fn chal16() {
	//TODO
}
