extern crate collections;

use utils::utils::{CryptoData};
use self::collections::vec::Vec;
use std::iter::{range_step};

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
	let path = Path::new(fname);
	let contents = File::open(&path).read_to_string();
	let base64_str = match contents { Ok(x) => x, Err(e) => panic!(e) };

	let mut zero_vec: Vec<u8> = Vec::new();
	for _ in range(0i, 16) {
		zero_vec.push(0u8);
	}
	let iv = CryptoData::from_vec(&zero_vec);
	let encrypted = CryptoData::from_base64(base64_str.as_slice());
	let decrypted = encrypted.CBC_decrypt(&key, &iv);
	println!("text: {}", decrypted.to_text());
}

fn encryption_oracle(input: CryptoData) -> CryptoData {
	use std::rand;
	use std::rand::Rng;
	let mut rng = rand::task_rng();

	let cbc = rng.gen::<bool>();
	let mut key_vec = Vec::new();
	for _ in range(0u, 16) {
		key_vec.push(rng.gen::<u8>());
	}
	//TODO: use fill_bytes
	//gives "possibly uninitialized variable" for the array
	//let mut key_bytes: [u8, ..16];
	//rng.fill_bytes(&mut key_bytes);
	let key = CryptoData::from_vec(&key_vec);

	if cbc {
		println!("CBC");
		let mut iv_vec = Vec::new();
		for _ in range(0u, 16) {
			iv_vec.push(rng.gen::<u8>());
		}
		let iv = CryptoData::from_vec(&iv_vec);
		input.CBC_encrypt(&key, &iv)
	} else {
		// ECB
		println!("ECB");
		input.ECB_encrypt(&key)
	}
}

fn encrypted_with_ECB(ciphertext: CryptoData, bsize: uint) -> bool {
	use std::collections::HashSet;

	println!("len: {}", ciphertext.len());
	let mut block_set = HashSet::new();
	let ciph_vec = ciphertext.vec();
	let mut dups = 0u;

	for idx in range_step (0, ciph_vec.len(), bsize) {
		let block = ciph_vec.as_slice().slice(idx, idx + bsize);
		if block_set.contains(&block) {
			println!("dup block: {}", block);
			dups += 1;
		} else {
			println!("new block: {}", block);
			block_set.insert(block.clone());
		}
	}

	println!("dups: {}", dups);
	dups > 0
}

// An ECB/CBC detection oracle
pub fn chal11() {
	let plain_text = String::from_char(256, 'a');
	let plain = CryptoData::from_text(plain_text.as_slice());
	println!("plain len: {}", plain.len())
	let encrypted = encryption_oracle(plain);
	println!("encrypted len: {}", encrypted.len())

	if encrypted_with_ECB(encrypted, 16) {
		println!("probably encrypted using ECB");
	} else {
		println!("probably encrypted using CBC");
	}
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
