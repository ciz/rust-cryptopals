use std::char;
use utils::cryptodata::{CryptoData};

fn eng_char_freq(c: char) -> f32 {
	match c {
		'E' => 12.02,
		'T' => 9.10,
		'A' => 8.12,
		'O' => 7.68,
		'I' => 7.31,
		'N' => 6.95,
		'S' => 6.28,
		'R' => 6.02,
		'H' => 5.92,
		'D' => 4.32,
		'L' => 3.98,
		'U' => 2.88,
		'C' => 2.71,
		'M' => 2.61,
		'F' => 2.30,
		'Y' => 2.11,
		'W' => 2.09,
		'G' => 2.03,
		'P' => 1.82,
		'B' => 1.49,
		'V' => 1.11,
		'K' => 0.69,
		'X' => 0.17,
		'Q' => 0.11,
		'J' => 0.10,
		'Z' => 0.07,
		'\'' => 0.05,
		'!' => 0.05,
		'?' => 0.05,
		',' => 0.2,
		'.' => 0.2,
		'"' => 0.05,
		' ' => 10.0,
		'\x00'...'\x19' =>  -10.0,
		_ =>  -1.0,
	}
}

fn score_bytes(data: &CryptoData) -> f32 {
	let it = data.vec().iter();
	it.fold(0.0, |x, y| x + eng_char_freq(UnicodeChar::to_uppercase(*y as char)))
}

pub fn guess_xor_byte(xored: &CryptoData) -> (CryptoData, CryptoData, f32) {
	use std::iter::{range_inclusive};
	let mut best = CryptoData::new();
	let mut best_score: f32 = 0.0;
	let mut best_byte = CryptoData::new();

	for b in range_inclusive(0u8, 255) {
		let byte = CryptoData::from_byte(b);
		let res = xored.xor(&byte);
		let score = score_bytes(&res);

		if score > best_score {
			best_score = score;
			best = res;
			best_byte = byte;
		}
	}

	(best_byte, best, best_score)
}

pub fn guess_xor_key(enc: &CryptoData, keysize: uint) -> CryptoData {
	let mut key = CryptoData::new();
	// transpose into blocks
	for position in range(0, keysize) {
		let mut bytes = Vec::new();
		for block in range(0, enc.len() / keysize) {
			bytes.push(enc.vec()[block * keysize + position]);
		}
		let (ch, _, _) = guess_xor_byte(&CryptoData::from_vec(&bytes));
		//println!("char: {}, score: {}", ch, best_score);
		key = key.cat(&ch);
	}
	key
}

fn wrap_and(input: &str) -> CryptoData {
	let prefix = "comment1=cooking%20MCs;userdata=";
	let postfix = ";comment2=%20like%20a%20pound%20of%20bacon";
	let mut s = String::from_str(prefix);

	let escaped = String::from_str(input).replace(";", "%3B").replace("=", "%3D");
	s.push_str(escaped.as_slice());
	s.push_str(postfix);

	CryptoData::from_text(s.as_slice())
}

pub fn wrap_and_encrypt_CBC(input: &str, key: &CryptoData, iv: &CryptoData) -> CryptoData {
	wrap_and(input).CBC_encrypt(key, iv)
}

pub fn wrap_and_encrypt_CTR(input: &str, key: &CryptoData, nonce: &CryptoData, counter: u64) -> CryptoData {
	wrap_and(input).CTR_encrypt(key, nonce, counter)
}

fn and_find(decrypted: &CryptoData) -> bool {
	let s = decrypted.to_text();
	println!("decrypted: {}", s);
	println!("decrypted: {}", decrypted.to_hex());
	match s.find_str(";admin=true;") {
		Some(_) => true,
		_ => false
	}
}

pub fn decrypt_and_find_CBC(input: &CryptoData, key: &CryptoData, iv: &CryptoData) -> bool {
	let decrypted = input.CBC_decrypt(key, iv);
	and_find(&decrypted)
}

pub fn decrypt_and_find_CTR(input: &CryptoData, key: &CryptoData, nonce: &CryptoData, counter: u64) -> bool {
	let decrypted = input.CTR_decrypt(key, nonce, counter);
	and_find(&decrypted)
}

//TODO: more general solution
pub fn flip_bits(input: &CryptoData, positions: &Vec<uint>) -> CryptoData {
	let mut vec = input.vec().clone();
	for idx in positions.iter() {
		vec[*idx] = vec[*idx] ^ 1;
	}
	CryptoData::from_vec(&vec)
}
