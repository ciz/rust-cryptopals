use utils::cryptodata::{CryptoData};
use std::iter::{range_step,range_inclusive};

// TODO: skip blocks before offset
fn edit_ctr(ciphertext: &CryptoData, key: &CryptoData, nonce: &CryptoData, counter: u64, offset: uint, newtext: &CryptoData) -> CryptoData {
	assert!(offset < ciphertext.len());
	let plain = ciphertext.CTR_decrypt(key, nonce, counter);
	let notail = plain.cut(offset).cat(newtext);
	let modified = if plain.len() > offset + newtext.len() {
		let rest = plain.slice(offset + newtext.len(), plain.len());
		notail.cat(&rest)
		} else {
			notail
		};
	modified.CTR_encrypt(key, nonce, counter)
}

fn crack_edit_ctr(ciphertext: &CryptoData, key: &CryptoData, nonce: &CryptoData, counter: u64) -> CryptoData {
	let mut result = CryptoData::new();
	for idx in range(0, ciphertext.len()) {
		for b in range_inclusive(0u8, 255) {
			let mut vec = Vec::new();
			vec.push(b);
			let byte = CryptoData::from_vec(&vec);
			let mod_enc = edit_ctr(ciphertext, key, nonce, counter, idx, &byte);
			if mod_enc == *ciphertext {
				println!("guessed byte: {}", byte);
				result = result.cat(&byte);
			}
		}
	}
	result
}

// Break "random access read/write" AES CTR
pub fn chal25() {
	//TODO: this challenge runs *really* slowly!
	//the CryptoData implementation should be checked
	use std::io::File;

	let key_ctr = CryptoData::random(16);
	let nonce = CryptoData::random(8);
	let counter = 100u64;

	let fname = "src/set4/25.txt";
	let key_ecb = CryptoData::from_text("YELLOW SUBMARINE");
	let path = Path::new(fname);
	let contents = File::open(&path).read_to_string();
	let base64_str = match contents { Ok(x) => x, Err(e) => panic!(e) };

	let encrypted = CryptoData::from_base64(base64_str.as_slice());
//	let text = encrypted.ECB_decrypt(&key_ecb);
	let text = CryptoData::from_text("abcdefghijklmnopqrstuvwxyz");
	let enc = text.CTR_encrypt(&key_ctr, &nonce, counter);
	let cracked = crack_edit_ctr(&enc, &key_ctr, &nonce, counter);

	println!("orig: {}", text.to_text());
	println!("cracked: {}", cracked.to_text());
}

//TODO: these functions are common with challenge 16
fn wrap_and_encrypt(input: &str, key: &CryptoData, nonce: &CryptoData, counter: u64) -> CryptoData {
	let prefix = "comment1=cooking%20MCs;userdata=";
	let postfix = ";comment2=%20like%20a%20pound%20of%20bacon";
	let mut s = String::from_str(prefix);

	let escaped = String::from_str(input).replace(";", "%3B").replace("=", "%3D");
	println!("escaped {}", escaped);
	s.push_str(escaped.as_slice());
	s.push_str(postfix);

	let c = CryptoData::from_text(s.as_slice());
	println!("orig hex: {}", c);
	c.CTR_encrypt(key, nonce, counter)
}

fn decrypt_and_find(input: &CryptoData, key: &CryptoData, nonce: &CryptoData, counter: u64) -> bool {
	let decrypted = input.CTR_decrypt(key, nonce, counter);
	let s = decrypted.to_text();
	println!("decrypted: {}", s);
	println!("decrypted: {}", decrypted.to_hex());
	match s.find_str(";admin=true;") {
		Some(_) => true,
		_ => false
	}
}

fn flip_bits(input: &CryptoData) -> CryptoData {
	let mut vec = input.vec().clone();
	vec[48] = vec[48] ^ 1;
	vec[54] = vec[54] ^ 1;
	vec[59] = vec[59] ^ 1;
	CryptoData::from_vec(&vec)
}

// CTR bitflipping
pub fn chal26() {
	let key = CryptoData::random(16);
	let nonce = CryptoData::random(8);
	let counter = 1u64;
	let text = "aaaaaaaaaaaaaaaa:admin<true:aaaa";
	let c = CryptoData::from_text(text);
	println!("input: {}", c.to_hex());
	let encrypted = wrap_and_encrypt(text, &key, &nonce, counter);
	println!("encrypted: {}", encrypted.to_hex());
	let tampered = flip_bits(&encrypted);
	println!("tampered:  {}", tampered.to_hex());

	if decrypt_and_find(&tampered, &key, &nonce, counter) {
		println!("FOUND");
	} else {
		println!("not found");
	}
}

//fn check_valid_ascii(text: &CryptoData) -> bool {
fn check_valid_ascii(text: &str) -> bool {
	let mut ret = true;
	for byte in text.chars() {
	//for byte in text.vec().iter() {
		//match *byte {
		match byte as u8 {
			0...31 | 128...255 => ret = false,
			_ => ()
		}
	}
	ret
}

//TODO: these functions are common with challenge 16
fn wrap_and_encrypt_27(input: &str, key: &CryptoData, iv: &CryptoData) -> CryptoData {
	let prefix = "comment1=cooking%20MCs;userdata=";
	let postfix = ";comment2=%20like%20a%20pound%20of%20bacon";
	let mut s = String::from_str(prefix);

	let escaped = String::from_str(input).replace(";", "%3B").replace("=", "%3D");
	s.push_str(escaped.as_slice());
	s.push_str(postfix);

	let c = CryptoData::from_text(s.as_slice());
	println!("orig hex: {}", c);
	c.CBC_encrypt(key, iv)
}

// Recover the key from CBC with IV=Key
pub fn chal27() {
	let text = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	if !check_valid_ascii(text) {
		println!("invalid input: {}", text);
		return;
	}
	let key = CryptoData::from_text("SUPERTAJNE HESLO");
	let enc = wrap_and_encrypt_27(text, &key, &key);
	let zeros = CryptoData::zero(16);
	let first = enc.block(0, 16);
	let tampered = first.cat(&zeros).cat(&first).cat(&enc.slice(3 * 16, enc.len()));
	let dec = tampered.CBC_decrypt(&key, &key);
	if !check_valid_ascii(dec.to_text().as_slice()) {
	//if !check_valid_ascii(&dec) {
		println!("invalid input: {}", dec);
	}
	let plain = dec.block(0, 16).xor(&dec.block(2, 16));
	println!("key/iv: {}", plain.to_text());
}

// Implement a SHA-1 keyed MAC
pub fn chal28() {
	//TODO
}

// Break a SHA-1 keyed MAC using length extension
pub fn chal29() {
	//TODO
}

// Break an MD4 keyed MAC using length extension
pub fn chal30() {
	//TODO
}

// Implement and break HMAC-SHA1 with an artificial timing leak
pub fn chal31() {
	//TODO
}

// Break HMAC-SHA1 with a slightly less artificial timing leak
pub fn chal32() {
	//TODO
}

