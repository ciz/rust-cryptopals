use utils::utils::{CryptoData};

// The CBC padding oracle
pub fn chal17() {
//TODO
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
