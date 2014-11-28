extern crate collections;

use utils::cryptodata::{CryptoData};
use utils::utils::{decrypt_and_find_CBC,flip_bits,wrap_and_encrypt_CBC};
use self::collections::vec::Vec;
use std::collections::HashMap;
use std::iter::{range_step,range_inclusive};

// Implement PKCS#7 padding
pub fn chal9() {
	let text = CryptoData::from_text("YELLOW SUBMARINE");
	let padded_text = text.pad(20);
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

	let prefix_size = rng.gen_range(5u, 10);
	let suffix_size = rng.gen_range(5u, 10);
	let prefix = CryptoData::random(prefix_size);
	let suffix = CryptoData::random(suffix_size);

	let key = CryptoData::random(16);

	// add random bytes to the beginning and the end
	let plain = prefix.cat(&input).cat(&suffix);
	//println!("padded size: {}", plain.len());
	//println!("plain: {}", plain.to_hex());

	if cbc {
		println!("CBC");
		let iv = CryptoData::random(16);
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
		let first_block = CryptoData::from_vec(&block_slice.to_vec());

		byte_block.insert(first_block.clone(), b);
		//println!("xkey: {} xval: {}", first_block, b);
	}
	byte_block
}

// Byte-at-a-time ECB decryption (Simple)
pub fn chal12() {
	let key = CryptoData::random(16);

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
		let first_block = CryptoData::from_vec(&block_slice.to_vec());

		let byte = table.get(&first_block).unwrap();
		res.push(*byte);
		secvec.remove(0);
	}
	println!("Deciphered:\n{}", CryptoData::from_vec(&res).to_text());
}

fn parse_object(text: &str) -> HashMap<String, String> {
	let mut res: HashMap<String, String> = HashMap::new();
	for params in String::from_str(text).split_str("&") {
		// ignore potential other =
		let mut keyval = params.split_str("=").take(2);

		let key = match keyval.next() {
			Some(key) => key,
			None => continue
		};
		let val = match keyval.next() {
			Some(val) => val,
			None => continue
		};

		res.insert(String::from_str(key), String::from_str(val));
	}
	res
}

fn profile_for(email: &str) -> String {
	let mut escaped = String::from_str(email).replace("&", "%26").replace("=", "%3D");
	escaped.push_str("&uid=10&role=user");
	escaped
}

fn attack_profile(key: &CryptoData) -> CryptoData {
	// force "role=" at the end of the first block
	let input1 = "a@b";
	let profile1 = profile_for(input1);
	let enc_profile1 = CryptoData::from_text(profile1.as_slice()).ECB_encrypt(key);
	let block1 = enc_profile1.vec().as_slice().slice(0, 16);

	// force "admin" at the beginning of the second block
	let input2 = "aaaaaaaaaaaaaaaaadmin";
	let profile2 = profile_for(input2);
	let enc_profile2 = CryptoData::from_text(profile2.as_slice()).ECB_encrypt(key);
	let block2 = enc_profile2.vec().as_slice().slice(16, 32);

	let mut cat_blocks = Vec::new();
	cat_blocks.push_all(block1);
	cat_blocks.push_all(block2);

	CryptoData::from_vec(&cat_blocks)
}

// ECB cut-and-paste
pub fn chal13() {
	let key = CryptoData::random(16);
	let tampered = attack_profile(&key);
	//println!("tampered: {}", tampered);

	let dec_profile = tampered.ECB_decrypt(&key);
	println!("text {}", dec_profile.to_text());
	let parsed_profile = parse_object(dec_profile.to_text().as_slice());

	match parsed_profile.get(&String::from_str("role")) {
		Some(role) => match role.as_slice() {
			"admin" => println!("ADMIN!"),
			_ => println!("No")
		},
		None => println!("failed")
	}
}

// Byte-at-a-time ECB decryption (Harder)
pub fn chal14() {
	let key = CryptoData::random(16);
	let prefix = CryptoData::random(128);

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
	let cut_prefix = CryptoData::from_vec(&cut_prefix_vec.to_vec());
	let short_block = cut_prefix.cat(&CryptoData::from_text(remain_str.as_slice()));

	let table = create_table(&short_block, &key, blocksize);
	let mut res = Vec::new();
	let mut secvec = secret.vec().clone();

	while secvec.len() > 0 {
		let cat_block = short_block.cat(&CryptoData::from_vec(&secvec));
		let short_enc = oracle_12(&cat_block, &key);

		let block_slice = short_enc.vec().as_slice().slice(0, blocksize);
		let first_block = CryptoData::from_vec(&block_slice.to_vec());

		let byte = table.get(&first_block).unwrap();
		res.push(*byte);
		secvec.remove(0);
	}
	println!("Deciphered:\n{}", CryptoData::from_vec(&res).to_text());
}

// PKCS#7 padding validation
pub fn chal15() {
	//let text = CryptoData::from_text("ICE ICE BABY\x04\x04\x04");
	let text = CryptoData::from_text("ICE ICE BABY\x04\x04\x04\x04");
	if text.pad_verify(16) {
		println!("text padded correctly");
	} else {
		println!("text has invalid padding");
	}
}

// CBC bitflipping attacks
pub fn chal16() {
	let key = CryptoData::random(16);
	let iv = CryptoData::random(16);
	let text = "aaaaaaaaaaaaaaaa:admin<true:aaaa";
	let c = CryptoData::from_text(text);
	println!("input: {}", c.to_hex());
	let encrypted = wrap_and_encrypt_CBC(text, &key, &iv);
	println!("encrypted: {}", encrypted.to_hex());
	let mut positions = Vec::new();
	positions.push_all(&[32, 38, 43]);
	let tampered = flip_bits(&encrypted, &positions);
	println!("tampered:  {}", tampered.to_hex());

	if decrypt_and_find_CBC(&tampered, &key, &iv) {
		println!("FOUND");
	} else {
		println!("not found");
	}
}
