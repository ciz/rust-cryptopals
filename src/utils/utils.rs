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
	let mut score: f32;
	score = 0.0;
	let mut it = data.vec().iter();
	for c in it {
		score += eng_char_freq(char::to_uppercase(*c as char));
	}
	score
}

pub fn guess_xor_byte(xored: &CryptoData) -> (CryptoData, CryptoData, f32) {
	use std::iter::{range_inclusive};
	let mut best = CryptoData::new();
	let mut best_score: f32 = 0.0;
	let mut best_byte = CryptoData::new();

	for c in range_inclusive(0u8, 255) {
		let bytestr = String::from_char(1, c as char);
		let byte = CryptoData::from_text(bytestr.as_slice());
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
