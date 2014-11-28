use utils::cryptodata::{CryptoData};
use utils::utils::{decrypt_and_find_CTR,flip_bits,wrap_and_encrypt_CBC,wrap_and_encrypt_CTR};
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

// CTR bitflipping
pub fn chal26() {
	let key = CryptoData::random(16);
	let nonce = CryptoData::random(8);
	let counter = 1u64;
	let text = "aaaaaaaaaaaaaaaa:admin<true:aaaa";
	let c = CryptoData::from_text(text);
	println!("input: {}", c.to_hex());
	let encrypted = wrap_and_encrypt_CTR(text, &key, &nonce, counter);
	println!("encrypted: {}", encrypted.to_hex());
	let mut positions = Vec::new();
	positions.push_all(&[48, 54, 59]);
	let tampered = flip_bits(&encrypted, &positions);
	println!("tampered:  {}", tampered.to_hex());

	if decrypt_and_find_CTR(&tampered, &key, &nonce, counter) {
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

// Recover the key from CBC with IV=Key
pub fn chal27() {
	let text = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	if !check_valid_ascii(text) {
		println!("invalid input: {}", text);
		return;
	}
	let key = CryptoData::from_text("SUPERTAJNE HESLO");
	let enc = wrap_and_encrypt_CBC(text, &key, &key);
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

