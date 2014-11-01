extern crate serialize;
extern crate collections;

use std::str;
use std::fmt;
// have to use "self", otherwise it's an "unresolved import"
use self::collections::vec::Vec;
use self::serialize::base64::{ToBase64, STANDARD};
use self::serialize::hex::{FromHex,ToHex};

#[deriving (PartialEq)]
pub struct CryptoData {
	data: Vec<u8>,
}

impl fmt::Show for CryptoData {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", self.data.to_hex())
	}
}

impl CryptoData {
	pub fn from_hex(hexstring: &str) -> CryptoData {
		CryptoData { data: hexstring.from_hex().unwrap() }
	}

	pub fn to_base64(&self) -> String {
		let byte_str = str::from_utf8(self.data.as_slice()).unwrap();
		byte_str.as_bytes().to_base64(STANDARD)
	}

	pub fn to_hex(&self) -> String {
		self.data.as_slice().to_hex()
	}

	pub fn to_text(&self) -> String {
		let x = str::from_utf8(self.data.as_slice());
		match x {
			Some(s) => s.to_string(),
			None => panic!("Can't convert to text"),
		}
	}

	pub fn get_data(&self) -> &Vec<u8> {
		&self.data
	}

	pub fn xor(&self, key: CryptoData) -> CryptoData {
		let mut res: Vec<u8> = Vec::new();
		let mut data_it = self.data.iter();

		'outer: loop {
			for k in key.get_data().iter() {
				let d =
				match data_it.next() {
					None => break 'outer,
					Some(d) => *d,
				};

				let xor = *k ^ d;
				res.push(xor);
			}
		}

		CryptoData { data: res, }
	}
}
