use utils::utils::{CryptoData};
use std::iter::{range_inclusive};

fn select_and_encrypt() -> (CryptoData, CryptoData, CryptoData) {
	use std::rand;
	use std::rand::Rng;

	let texts = [
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	];

	let key = CryptoData::random(16);
	let iv = CryptoData::random(16);
	let mut rng = rand::task_rng();

	let text_num = rng.gen_range(0u, 10);
	let text = CryptoData::from_base64(texts[text_num]);
	(text.CBC_encrypt(&key, &iv), key, iv)
}

//TODO: rewrite so key/iv doesn't need to be passed
fn check_padding(enc: &CryptoData, key: &CryptoData, iv: &CryptoData) -> bool {
	enc.CBC_decrypt(key, iv).pad_verify(16)
}

// decrypt a single block using the padding oracle
fn guess_block(c1: &CryptoData, c2: &CryptoData, key: &CryptoData, iv: &CryptoData, bsize: uint) -> CryptoData {
	let mut p2_bytes = Vec::from_elem(16, 0u8);

	for i in range(0, bsize) {
		let mut end_bytes_vec = Vec::from_elem(16, 0u8);
		let mut p2_mod = 0u8;

		// prepare end bytes for c_my vector
		for j in range(0, i) {
			let xored = (i as u8 + 1) ^ p2_bytes[15 - j] ^ c1.vec()[15 - j];
			end_bytes_vec[15 - j] = xored;
		}

		// find byte that decrypts to chosen padding byte
		for byte in range_inclusive(0u8, 255) {
			end_bytes_vec[15 - i] = byte;
			let c_my = CryptoData::from_vec(&end_bytes_vec);
			let for_oracle = c_my.cat(c2);

			if check_padding(&for_oracle, key, iv) {
				p2_mod = byte;
				break;
			}
		}

		let plain_byte = (i as u8 + 1) ^ c1.vec()[15 - i] ^ p2_mod;
		p2_bytes[15 - i] = plain_byte;
	}
	CryptoData::from_vec(&p2_bytes)
}

fn guess_all_blocks(enc: &CryptoData, key: &CryptoData, iv: &CryptoData, bsize: uint) -> CryptoData {
	let mut res = CryptoData::new();
	for idx in range(0, enc.len() / bsize) {
		let c1 = match idx {
			0 => iv.clone(),
			_ => enc.block(idx - 1, 16),
		};
		let c2 = enc.block(idx, 16);
		let dec = guess_block(&c1, &c2, key, iv, 16);
		res = res.cat(&dec);
	}
	res
}

// The CBC padding oracle
pub fn chal17() {
	//let x = CryptoData::from_text("aaaaaaaaaaaaaaaahgfedcbaHGFEDCB");
	//let key = CryptoData::from_text("ABCDEFGHIJKLMNOP");
	//let iv = CryptoData::from_text("rstuvwxyRSTUVWXY");
	//let enc = x.CBC_encrypt(&key, &iv);
	let (enc, key, iv) = select_and_encrypt();
	let bytes = guess_all_blocks(&enc, &key, &iv, 16);
	println!("decrypted: {}", bytes.pad_strip(16).to_text());
}

// Implement CTR
pub fn chal18() {
	let enc_str = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
	let key_str = "YELLOW SUBMARINE";

	let enc = CryptoData::from_base64(enc_str);
	let key = CryptoData::from_text(key_str);
	let nonce = CryptoData::zero(8);

	let dec = enc.CTR_decrypt(&key, &nonce, 0);
	println!("hex: {}\ntext = {}", dec, dec.to_text());
}

// Break fixed-nonce CTR mode using substitions
pub fn chal19() {
//TODO
}

// Break fixed-nonce CTR statistically
pub fn chal20() {
//TODO
}

// Implement the MT19937 Mersenne Twister RNG
pub fn chal21() {
	// implemented in utils::MersenneTwister
}

// Crack an MT19937 seed
pub fn chal22() {
//TODO
}

// Clone an MT19937 RNG from its output
pub fn chal23() {
//TODO
}

// Create the MT19937 stream cipher and break it
pub fn chal24() {
//TODO
}
