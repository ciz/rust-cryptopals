use utils::cryptodata::{CryptoData};

fn edit_ctr(ciphertext: &CryptoData, key: &CryptoData, nonce: &CryptoData, counter: u64, offset: uint, newtext: &CryptoData) -> CryptoData {
	assert!(offset < ciphertext.len());
	let plain = ciphertext.CTR_decrypt(key, nonce, counter);
	let rest = plain.slice(offset + newtext.len(), plain.len());
	let modified = plain.cut(offset).cat(newtext).cat(&rest);
	modified.CTR_encrypt(key, nonce, counter)
}

// Break "random access read/write" AES CTR
pub fn chal25() {
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
	let text = encrypted.ECB_decrypt(&key_ecb);
	let enc = text.CTR_encrypt(&key_ctr, &nonce, counter);
	let newtext = CryptoData::from_text("VACICE SE TAKE HLASI O SLOVO");
	let offset = 200;
	let newenc = edit_ctr(&enc, &key_ctr, &nonce, counter, offset, &newtext);
	let newdec = newenc.CTR_decrypt(&key_ctr, &nonce, counter);
	println!("old: {}", text.to_text());
	println!("new: {}", newdec.to_text());
}

// CTR bitflipping
pub fn chal26() {
	//TODO
}

// Recover the key from CBC with IV=Key
pub fn chal27() {
	//TODO
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

