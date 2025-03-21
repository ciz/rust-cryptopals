extern crate openssl;

use utils::utils::{guess_xor_byte, guess_xor_key};
use utils::cryptodata::{CryptoData};
use std::fs::read_to_string;

use std::collections::HashSet;
use std::collections::HashMap;

// Convert hex to base64
pub fn chal1() {
	// string: "I'm killing your brain like a poisonous mushroom"
	// base64: "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	let test_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
	let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

	let cd = CryptoData::from_hex(test_hex);
	let res = cd.to_base64();
	assert!(res == expected);
	println!("hex: {}", test_hex);
	println!("base64: {}", res);
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

// single byte XOR
pub fn chal3() {
	let xored = CryptoData::from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");

	let (c, best, best_score) = guess_xor_byte(&xored);

	println!("score: {}", best_score);
	println!("text: {}", best.to_text());
	println!("hex: {}", best.to_hex());
	println!("byte: {}", c);
}

// Detect single-character XOR
pub fn chal4() {
	let mut best = CryptoData::new();
	let mut best_score: f32 = 0.0;

	let fname = "src/set1/4.txt";

	for line in read_to_string(fname).unwrap().lines() {
		let xored = CryptoData::from_hex(line);
		let (_, line_best, line_best_score) = guess_xor_byte(&xored);

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
	//println!("text: {}", res.to_text());
}

// Break repeating-key XOR
pub fn chal6() {
	println!("Chal6");
	let fname = "src/set1/6.txt";
	let contents = read_to_string(fname);
	let base64_str = match contents { Ok(x) => x, Err(e) => panic!("{}", e) };

	let enc = CryptoData::from_base64(&base64_str);
	let mut size: u32 = 0;
	let mut best_dist: u32 = 100000;

	// find best keysize
	for keysize in 2..40 {
		let mut sum = 0;
		let count = enc.len() / keysize - 1;
		for i in 0..count {
			let first_block = enc.slice(i * keysize, (i+1) * keysize);
			let second_block = enc.slice((i+1) * keysize, (i+2) * keysize);
			let dist = first_block.hamming_distance(&second_block);
			sum += dist;
		}

		let my_dist = sum / count / keysize;
		if my_dist < best_dist as usize {
			size = keysize as u32;
			best_dist = my_dist as u32;
		}
	}

	println!("best keysize: {}", size);
	let key = guess_xor_key(&enc, size as usize);
	let dec = enc.xor(&key);
	println!("key: {}", key.to_text());
	println!("chal 6 decrypted: {}", dec.to_text());
}

// AES in ECB mode
pub fn chal7() {
	let key = CryptoData::from_text("YELLOW SUBMARINE");

	let fname = "src/set1/7.txt";
	let contents = read_to_string(fname);
	let base64_str = match contents { Ok(x) => x, Err(e) => panic!("{}", e) };

	let encrypted = CryptoData::from_base64(&base64_str);
	let decrypted = encrypted.ECB_decrypt(&key);
	println!("chal 7 text: {}", decrypted.to_text());
}

// Detect AES in ECB mode
pub fn chal8() {
	let fname = "src/set1/8.txt";
	let mut dup_blocks: HashMap<String, usize> = HashMap::new();

	for line in read_to_string(fname).unwrap().lines() {
		let mut dups: u32 = 0;
		let mut block_set = HashSet::new();

		for i in 0..(line.len() / 32 - 1) {
			let idx = i * 32;
			let block = &line[idx..idx + 32];
			if block_set.contains(&block) {
				//println!("dup block: {}", block);
				dups += 1;
			} else {
				//println!("block: {}", block);
				block_set.insert(block);
			}
		}

		if dups > 0 {
			//println!("dups: {}, text: {}", dups, line);
			dup_blocks.insert(line.to_string(), dups as usize);
		}
	}

	for (line, dups) in dup_blocks.iter() {
		println!("chal 8 dups: {}, text: {}", dups, line);
	}
}

