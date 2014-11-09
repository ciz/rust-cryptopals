extern crate collections;

use utils::utils::{CryptoData};
use self::collections::vec::Vec;
use std::collections::HashMap;
use std::iter::{range_step,range_inclusive};

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
	//TODO: use fill_bytes
	//gives "possibly uninitialized variable" for the array
	//let mut key_bytes: [u8, ..16];
	//rng.fill_bytes(&mut key_bytes);
	use std::rand;
	use std::rand::Rng;
	let mut rng = rand::task_rng();

	let prefix_size = rng.gen_range(5u, 10);
	let suffix_size = rng.gen_range(5u, 10);
	let mut prefix = Vec::new();
	let mut suffix = Vec::new();

	for _ in range(0, prefix_size) {
		prefix.push(rng.gen::<u8>());
	}
	for _ in range(0, suffix_size) {
		suffix.push(rng.gen::<u8>());
	}

	let cbc = rng.gen::<bool>();
	let mut key_vec = Vec::new();
	for _ in range(0u, 16) {
		key_vec.push(rng.gen::<u8>());
	}
	let key = CryptoData::from_vec(&key_vec);

	// add random bytes to the beginning and the end
	prefix.push_all(input.vec().as_slice());
	prefix.push_all(suffix.as_slice());
	let plain = CryptoData::from_vec(&prefix);
	println!("padded: {}", plain.len());
	println!("plain: {}", plain.to_hex());


	if cbc {
		println!("CBC");
		let mut iv_vec = Vec::new();
		for _ in range(0u, 16) {
			iv_vec.push(rng.gen::<u8>());
		}
		let iv = CryptoData::from_vec(&iv_vec);
		plain.CBC_encrypt(&key, &iv)
	} else {
		// ECB
		println!("ECB");
		plain.ECB_encrypt(&key)
	}
}

fn encrypted_with_ECB(ciphertext: CryptoData, bsize: uint) -> bool {
	use std::collections::HashSet;

	let mut block_set = HashSet::new();
	let ciph_vec = ciphertext.vec();
	let mut dups = 0u;

	for idx in range_step (0, ciph_vec.len(), bsize) {
		let block = ciph_vec.as_slice().slice(idx, idx + bsize);
		if block_set.contains(&block) {
			//println!("dup block ({}): {}", idx, block);
			dups += 1;
		} else {
			//println!("new block ({}): {}", idx, block);
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
	let encrypted = encryption_oracle(plain);

	if encrypted_with_ECB(encrypted, 16) {
		println!("probably encrypted using ECB");
	} else {
		println!("probably encrypted using CBC");
	}
}

fn oracle_12(input: &CryptoData, key: &CryptoData) -> CryptoData {
	input.ECB_encrypt(key)
}

fn create_table(input: &CryptoData, key: &CryptoData, blocksize: uint) -> HashMap<CryptoData, u8> {
	let mut byte_block: HashMap<CryptoData, u8> = HashMap::new();

	for b in range_inclusive(0u8, 255) {
		let mut byte_vec = Vec::new();
		byte_vec.push(b);
		let cated = input.cat(&CryptoData::from_vec(&byte_vec));
		let output = oracle_12(&cated, key);

		let block_slice = output.vec().as_slice().slice(0, blocksize);
		let mut block_vec = Vec::new();
		block_vec.push_all(block_slice);
		let first_block = CryptoData::from_vec(&block_vec);

		byte_block.insert(first_block.clone(), b);
		//println!("xkey: {} xval: {}", first_block, b);
	}
	byte_block
}

// Byte-at-a-time ECB decryption (Simple)
pub fn chal12() {
	use std::rand;
	use std::rand::Rng;
	let mut rng = rand::task_rng();

	let mut key_vec = Vec::new();
	for _ in range(0u, 16) {
		key_vec.push(rng.gen::<u8>());
	}
	let key = CryptoData::from_vec(&key_vec);

	let sec_b64ed = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK";
	let secret = CryptoData::from_base64(sec_b64ed);

	//TODO: points 1 and 2
	let blocksize = 16;

	let short_block_str = String::from_char(blocksize - 1, 'a');
	let short_block = CryptoData::from_text(short_block_str.as_slice());
	let table = create_table(&short_block, &key, blocksize);
	let mut res = Vec::new();
	let mut secvec = secret.vec().clone();

	while secvec.len() > 0 {
		let cat_block = short_block.cat(&CryptoData::from_vec(&secvec));
		let short_enc = oracle_12(&cat_block, &key);

		let block_slice = short_enc.vec().as_slice().slice(0, blocksize);
		let mut block_vec = Vec::new();
		block_vec.push_all(block_slice);
		let first_block = CryptoData::from_vec(&block_vec);

		//TODO: find is renamed to get in newer versions
		let byte = table.find(&first_block).unwrap();
		res.push(*byte);
		secvec.remove(0);
	}
	println!("Deciphered:\n{}", CryptoData::from_vec(&res).to_text());
}

// ECB cut-and-paste
pub fn chal13() {
	//TODO
}

// Byte-at-a-time ECB decryption (Harder)
pub fn chal14() {
	use std::rand;
	use std::rand::Rng;
	let mut rng = rand::task_rng();

	let mut key_vec = Vec::new();
	for _ in range(0u, 16) {
		key_vec.push(rng.gen::<u8>());
	}
	let key = CryptoData::from_vec(&key_vec);

	let mut prefix_vec = Vec::new();
	for _ in range(0u, 128) {
		prefix_vec.push(rng.gen::<u8>());
	}
	let prefix = CryptoData::from_vec(&prefix_vec);

	let sec_b64ed = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK";
	let secret = CryptoData::from_base64(sec_b64ed);

	//TODO: points 1 and 2
	let blocksize = 16;

	let prefix_remain = prefix.len() % blocksize;
	let prefix_full_blocks = prefix.len() / blocksize;
	let remain_str = String::from_char(blocksize - prefix_remain - 1, 'a');
	let cut_prefix_vec = prefix.vec().as_slice().slice(prefix_full_blocks, prefix_full_blocks + prefix_remain);
	let mut cut_prefix = Vec::new();
	cut_prefix.push_all(cut_prefix_vec);
	cut_prefix.push_all(remain_str.as_bytes());

	let short_block = CryptoData::from_vec(&cut_prefix);
	let table = create_table(&short_block, &key, blocksize);
	let mut res = Vec::new();
	let mut secvec = secret.vec().clone();

	while secvec.len() > 0 {
		let cat_block = short_block.cat(&CryptoData::from_vec(&secvec));
		let short_enc = oracle_12(&cat_block, &key);

		let block_slice = short_enc.vec().as_slice().slice(0, blocksize);
		let mut block_vec = Vec::new();
		block_vec.push_all(block_slice);
		let first_block = CryptoData::from_vec(&block_vec);

		//TODO: find is renamed to get in newer versions
		let byte = table.find(&first_block).unwrap();
		res.push(*byte);
		secvec.remove(0);
	}
	println!("Deciphered:\n{}", CryptoData::from_vec(&res).to_text());
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
