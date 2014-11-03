extern crate openssl;

use std::char;
use utils::utils::{CryptoData};

// Convert hex to base64
pub fn chal1() {
	// string: "I'm killing your brain like a poisonous mushroom"
	// base64: "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	let test_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

	let cd = CryptoData::from_hex(test_hex);
	println!("hex: {}", test_hex);
	println!("base64: {}", cd.to_base64());
	println!("text: {}", cd.to_text());
}

// fixed length xor
pub fn chal2() {
	let a = CryptoData::from_hex("1c0111001f010100061a024b53535009181c");
	let b = CryptoData::from_hex("686974207468652062756c6c277320657965");
	let expected = CryptoData::from_hex("746865206b696420646f6e277420706c6179");
	println!("a: {}", a);
	println!("b: {}", b);
	println!("expected: {}", expected);
	let res = a.xor(&b);
	assert!(res == expected);
	println!("res: {}", res);
}

pub fn eng_char_freq(c: char) -> f32 {
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

pub fn score_bytes(data: &CryptoData) -> f32 {
	let mut score: f32;
	score = 0.0;
	let mut it = data.get_data().iter();
	for c in it {
		score += eng_char_freq(char::to_uppercase(*c as char));
	}
	score
}

pub fn guess_xor_byte(xored: CryptoData) -> (CryptoData, CryptoData, f32) {
	let mut best = CryptoData::new();
	let mut best_score: f32 = 0.0;
	let mut best_byte = CryptoData::new();

	for c in range(0u8, 256) {
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

// single byte XOR
pub fn chal3() {
	let xored = CryptoData::from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");

	let (c, best, best_score) = guess_xor_byte(xored);

	println!("score: {}", best_score);
	println!("text: {}", best.to_text());
	println!("hex: {}", best.to_hex());
	println!("byte: {}", c);
}

// Detect single-character XOR
pub fn chal4() {
	use std::io::BufferedReader;
	use std::io::File;

	let mut best = CryptoData::new();
	let mut best_score: f32 = 0.0;

	let fname = "src/set1/4.txt";
	let path = Path::new(fname);
	let mut file = BufferedReader::new(File::open(&path));

	for line_iter in file.lines() {
		let line = match line_iter { Ok(x) => x, Err(e) => panic!(e) };
		let xored = CryptoData::from_hex(line.as_slice());
		let (_, line_best, line_best_score) = guess_xor_byte(xored);

		if line_best_score > best_score {
			best_score = line_best_score;
			best = line_best;
		}
	}

	println!("best score: {}", best_score);
	println!("text: {}", best.to_text());
	println!("hex: {}", best.to_hex());
}

// repeating key xor
pub fn chal5() {
	//let key = CryptoData::from_hex("000001");
	let key = CryptoData::from_text("ICE");
	let data = CryptoData::from_text("Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal");

	let res = data.xor(&key);
	println!("hex: {}", res.to_hex());
	println!("text: {}", res.to_text());
}

// Break repeating-key XOR
pub fn chal6() {
	//TODO
}

// AES in ECB mode
pub fn chal7() {
	use std::io::File;
	let key = CryptoData::from_text("YELLOW SUBMARINE");

	let fname = "src/set1/7.txt";
	let path = Path::new(fname);
	let contents = File::open(&path).read_to_string();
	let base64_str = match contents { Ok(x) => x, Err(e) => panic!(e) };

	let encrypted = CryptoData::from_base64(base64_str.as_slice());
	let decrypted = encrypted.ECB_decrypt(&key);
	println!("text: {}", decrypted.to_text());
}

// Detect AES in ECB mode
pub fn chal8() {
	use std::io::BufferedReader;
	use std::io::File;
	use std::collections::HashSet;
	use std::collections::HashMap;

	let fname = "src/set1/8.txt";
	let path = Path::new(fname);
	let mut file = BufferedReader::new(File::open(&path));
	let mut dup_blocks: HashMap<String, uint> = HashMap::new();

	for line_iter in file.lines() {
		let mut dups = 0u;
		let line = match line_iter { Ok(x) => x, Err(e) => panic!(e) };
		let mut block_set = HashSet::new();

		for i in range(0, line.len() / 32 - 1) {
			let idx = i * 32;
			let block = line.as_slice().slice(idx, idx + 32);
			if block_set.contains(&block) {
				//println!("dup block: {}", block);
				dups += 1;
			} else {
				//println!("block: {}", block);
				block_set.insert(block.clone());
			}
		}

		if dups > 0 {
			//println!("dups: {}, text: {}", dups, line);
			dup_blocks.insert(line.clone(), dups);
		}
	}

	for (line, dups) in dup_blocks.iter() {
		println!("dups: {}, text: {}", dups, line);
	}
}

