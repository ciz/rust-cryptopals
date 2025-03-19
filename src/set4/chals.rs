//# ! [allow(unknown_features)]

use http::client::RequestWriter;
use http::method::Get;
use url::Url;

//use time::{precise_time_ns};
use std::fs::read_to_string;
use std::time::{Duration, Instant};

use utils::cryptodata::{CryptoData};
use utils::utils::{decrypt_and_find_CTR,flip_bits,wrap_and_encrypt_CBC,wrap_and_encrypt_CTR};

// TODO: skip blocks before offset
fn edit_ctr(ciphertext: &CryptoData, key: &CryptoData, nonce: &CryptoData, counter: u64, offset: usize, newtext: &CryptoData) -> CryptoData {
	assert!(offset < ciphertext.len());
	let plain = ciphertext.CTR_decrypt(key, nonce, counter);
/*
	let block = offset / 16;
	let ncounter = counter + block as u64;
	let cut_cipher = ciphertext.slice(block * 16, ciphertext.len());
	let plain = cut_cipher.CTR_decrypt(key, nonce, ncounter);
*/
	let notail = plain.cut(offset).cat(newtext);
	let modified = if plain.len() > offset + newtext.len() {
			let rest = plain.slice(offset + newtext.len(), plain.len());
			notail.cat(&rest)
		} else {
			notail
		};
	modified.CTR_encrypt(key, nonce, counter)
/*
	let skipped = ciphertext.cut(block * 16);
	skipped.cat(&modified.CTR_encrypt(key, nonce, counter))
*/
}

fn crack_edit_ctr(ciphertext: &CryptoData, key: &CryptoData, nonce: &CryptoData, counter: u64) -> CryptoData {
	let mut result = CryptoData::new();
	for idx in 0..ciphertext.len() {
		println!("idx: {}", idx);
		for b in 0u8..=255 {
			println!("b: {}", b);
			let byte = CryptoData::from_byte(b);
			let mod_enc = edit_ctr(ciphertext, key, nonce, counter, idx, &byte);
			if mod_enc == *ciphertext {
				result = result.cat(&byte);
				println!("guessed so far: {}", result.to_text());
				break;
			}
		}
	}
	result
}

// Break "random access read/write" AES CTR
pub fn chal25() {
	//TODO: this challenge runs *really* slowly!
	//the CryptoData implementation should be checked

	let key_ctr = CryptoData::random(16);
	let nonce = CryptoData::random(8);
	let counter = 100u64;

	let fname = "src/set4/25.txt";
	let contents = read_to_string(fname);
	let base64_str = match contents { Ok(x) => x, Err(e) => panic!("{}", e) };

	let key_ecb = CryptoData::from_text("YELLOW SUBMARINE");
	let encrypted = CryptoData::from_base64(&base64_str);
	//let text = encrypted.ECB_decrypt(&key_ecb);
	let text = CryptoData::from_text("abcdefghijklmnopqrstuvwxyzQWFPGJLUY:ARSTDHNENEIIZXCVBKM1234567890[]['o'o,.,/,`");
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
	positions.append(&mut vec![48, 54, 59]);
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
			0..=31 | 128..=255 => ret = false,
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
	if !check_valid_ascii(&dec.to_text()) {
	//if !check_valid_ascii(&dec) {
		println!("invalid input: {}", dec);
	}
	let plain = dec.block(0, 16).xor(&dec.block(2, 16));
	println!("key/iv: {}", plain.to_text());
}

// Implement a SHA-1 keyed MAC
pub fn chal28() {
	let text = CryptoData::from_text("lalala a nanana a sasasa");
	let key = CryptoData::from_text("koala");
	let digest = text.SHA1_mac_prefix(&key);
	println!("{} | {}", key.to_text(), text.to_text());
	println!("{} | {} -> {}", key, text, digest);
}

// Break a SHA-1 keyed MAC using length extension
pub fn chal29() {
	//TODO
/*
	let msg = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
	let prefix = CryptoData::from_text(msg);
	let padding = prefix.len();
	let postfix = ";admin=true";
*/
}

// Break an MD4 keyed MAC using length extension
pub fn chal30() {
	//TODO
}

//TODO: terminate on code 200
fn process_request(url: &str) {
    let url = Url::parse(url).ok().expect("Invalid URL :-(");
    let request: RequestWriter = RequestWriter::new(Get, url).unwrap();

    let response = match request.read_response() {
        Ok(response) => response,
        Err(_request) => panic!("This example can progress no further with no response :-("),
    };
}

fn guess_hmac(url: &str, file: &str) -> String {
	let mut times: [u128; 256] = [0; 256];
	let mut res = Vec::new();

	for position in 0..20 {
		//TODO: go back a step if the elapsed time doesn't grow enough
		for byte in 0u8..=255 {
			let mut sig = CryptoData::from_vec(&res).to_hex();
			let hex = CryptoData::from_byte(byte).to_hex();
			sig.push_str(&hex);
			let postfix = CryptoData::zero(19 - position).to_hex();
			sig.push_str(&postfix);
			let my_url = format!("{}?file={}&signature={}", url, file, sig);

			let start_time = Instant::now();
			for _ in 0..10 {
				process_request(&my_url);
			}
			//let end_time = precise_time_ns();
			let duration = start_time.elapsed().as_nanos();
			//println!("{} duration: {}", &hex, duration);
			times[byte as usize] = duration;
		}
		let mut max = 0;
		let mut best = 0;
		//let best = times.iter().max_by(|x| *x)
		for i in 0..=255 {
			if times[i] > max {
				max = times[i];
				best = i;
			}
		}
		res.push(best as u8);
		let hex = CryptoData::from_vec(&res);
		println!("guessed so far: {}", hex);
		println!("it should be  : 8e9c16a922d10c647979bffb9fe655c6bdca030c");
	}

	CryptoData::from_vec(&res).to_hex()
}

// Implement and break HMAC-SHA1 with an artificial timing leak
pub fn chal31() {
	let file = "secret";
	let url = "http://localhost:8080";
	let hmac = guess_hmac(url, file);
	println!("hmac for file {} is {}", file, hmac);
	println!("should be 8e9c16a922d10c647979bffb9fe655c6bdca030c");
}

// Break HMAC-SHA1 with a slightly less artificial timing leak
pub fn chal32() {
	// same as chal31
	chal31();
}

