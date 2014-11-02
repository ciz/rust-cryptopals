use utils::utils::{CryptoData};

pub fn chal9() {
	let text = CryptoData::from_text("YELLOW SUBMARINE");
	let padded_text = text.pkcs7_pad(20);
	println!("text: {}", text.to_hex());
	println!("padded text: {}", padded_text.to_hex());
}

pub fn chal10() {
	//TODO
}

pub fn chal11() {
	//TODO
}

pub fn chal12() {
	//TODO
}

pub fn chal13() {
	//TODO
}

pub fn chal14() {
	//TODO
}

pub fn chal15() {
	//let text = CryptoData::from_text("ICE ICE BABY\x04\x04\x04");
	let text = CryptoData::from_text("ICE ICE BABY\x04\x04\x04\x04");
	if text.pkcs7_pad_verify(16) {
		println!("text padded correctly");
	} else {
		println!("text has invalid padding");
	}
}

pub fn chal16() {
	//TODO
}
