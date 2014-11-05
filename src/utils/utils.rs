extern crate serialize;
extern crate collections;
extern crate openssl;

use std::char;
use std::str;
use std::fmt;
use std::vec;
use std::iter::{range_step};
// have to use "self", otherwise it's an "unresolved import"
use self::collections::vec::Vec;
use self::serialize::base64::{ToBase64,FromBase64,STANDARD};
use self::serialize::hex::{FromHex,ToHex};
use self::openssl::crypto::symm;

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
	pub fn new() -> CryptoData {
		CryptoData { data: Vec::new() }
	}

	pub fn clone(&self) -> CryptoData {
		CryptoData { data: self.data.clone() }
	}

	pub fn from_hex(hexstring: &str) -> CryptoData {
		CryptoData { data: hexstring.from_hex().unwrap() }
	}

	pub fn from_text(ascii: &str) -> CryptoData {
		let bytes = vec::as_vec(ascii.as_bytes());
		CryptoData { data: bytes.deref().clone() }
	}

	pub fn from_vec(vec: &Vec<u8>) -> CryptoData {
		CryptoData { data: vec.clone() }
	}

	pub fn from_base64(base64_str: &str) -> CryptoData {
		let byte_str = base64_str.from_base64().unwrap();
		CryptoData { data: byte_str.clone() }
	}

	pub fn to_base64(&self) -> String {
		// FIXME: invalid UTF-8 byte sequences cause panics
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

	pub fn vec(&self) -> &Vec<u8> {
		&self.data
	}

	pub fn len(&self) -> uint {
		self.data.len()
	}

	pub fn xor(&self, key: &CryptoData) -> CryptoData {
		let mut res: Vec<u8> = Vec::new();
		let mut data_it = self.data.iter();

		'outer: loop {
			for k in key.vec().iter() {
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

	pub fn pkcs7_pad(&self, bsize: uint) -> CryptoData {
		let mut res = self.data.clone();
		let pad_size = bsize - res.len() % bsize;
		//println!("len: {}, pad: {}", res.len(), pad_size);
		let pad_byte = char::from_u32(pad_size as u32).unwrap();
		for _ in range(0, pad_size) {
			res.push(pad_byte as u8);
		}
		CryptoData { data: res }
	}

	pub fn pkcs7_pad_verify(&self, bsize: uint) -> bool {
		let len = self.data.len();
		let pad_byte = *self.data.last().unwrap();
		let pad_size = pad_byte as uint;

		// is it padded to bsize?
		if len % bsize != 0 {
			return false;
		}

		// check that all padding bytes are the same
		for i in range(1, pad_size) {
			if self.data[len - i] != pad_byte {
				return false;
			}
		}
		true
	}

	//FIXME: always returns an extra block at the end
	pub fn encrypt(&self, key: &CryptoData, iv: &CryptoData, cipher: symm::Type) -> CryptoData {
		println!("data: {}, key {}", self.data.to_hex(), key.to_hex());
		let encrypted = symm::encrypt(	cipher,
						key.vec().as_slice(),
						iv.vec().clone(),
						self.data.as_slice());

		println!("res: {}", encrypted.to_hex());
		CryptoData { data: encrypted }
	}

	pub fn decrypt(&self, key: &CryptoData, iv: &CryptoData, cipher: symm::Type) -> CryptoData {
		//println!("data: {}, key {}", self.to_hex(), key.to_hex());
		//println!("b64 data: {}, key {}", self.to_base64(), key.to_base64());
		let decrypted = symm::decrypt(	cipher,
						key.vec().as_slice(),
						iv.vec().clone(),
						self.data.as_slice());

		//println!("res: {}", decrypted.to_hex());
		CryptoData { data: decrypted }
	}

	pub fn ECB_encrypt(&self, key: &CryptoData) -> CryptoData {
		//self.encrypt(key, &CryptoData::new(), symm::AES_128_ECB)

		// pad input data if its length doesn't match blocksize
		let plain = if (self.len() % 16 != 0) {
			self.pkcs7_pad(16)
		} else {
			self.clone()
		};

		let c = symm::Crypter::new(symm::AES_128_ECB);
		c.init(symm::Encrypt, key.vec().as_slice(), Vec::new());
		c.pad(false);
		let mut r = c.update(plain.vec().as_slice());
		let rest = c.finalize();
		r.extend(rest.into_iter());
		CryptoData { data: r }
	}

	pub fn ECB_decrypt(&self, key: &CryptoData) -> CryptoData {
		//TODO: this doesn't work
		//https://github.com/sfackler/rust-openssl/issues/40
		//self.decrypt(key, &CryptoData::new(), symm::AES_128_ECB)

		let c = symm::Crypter::new(symm::AES_128_ECB);
		c.init(symm::Decrypt, key.vec().as_slice(), Vec::new());
		// need to disable padding, otherwise there's an additional padding block at the end
		c.pad(false);
		let mut r = c.update(self.vec().as_slice());
		let rest = c.finalize();
		r.extend(rest.into_iter());
		CryptoData { data: r }
	}

	pub fn CBC_encrypt(&self, key: &CryptoData, iv: &CryptoData) -> CryptoData {
		//TODO: doesn't store the intermediate blocks
		let mut result = Vec::new();
		let mut to_xor = iv.clone();

		// pad input data
		let plain = self.pkcs7_pad(16);

		for idx in range_step (0, plain.len(), 16) {
			let block_slice = plain.vec().as_slice().slice(idx, idx + 16);
			//FIXME: isn't there a better way to create Vec from array?
			let mut block_vec = Vec::new();
			block_vec.push_all(block_slice);

			let block = CryptoData::from_vec(&block_vec);
			let xored = block.xor(&to_xor);
			let encrypted = xored.ECB_encrypt(key);
			//println!("enc size: {}", encrypted.len());
			//println!("enc : {}", encrypted.to_hex());
			result.push_all(encrypted.vec().as_slice());
			to_xor = encrypted;
		}
		CryptoData { data: result }
	}

	// TODO: strip pad
	pub fn CBC_decrypt(&self, key: &CryptoData, iv: &CryptoData) -> CryptoData {
		let mut result = Vec::new();
		let mut to_xor = iv.clone();

		for idx in range_step (0, self.len(), 16) {
			let block_slice = self.data.as_slice().slice(idx, idx + 16);
			//FIXME: isn't there a better way to create Vec from array?
			let mut block_vec = Vec::new();
			block_vec.push_all(block_slice);

			let block = CryptoData::from_vec(&block_vec);
			let decrypted = block.ECB_decrypt(key);
			let xored = decrypted.xor(&to_xor);

			// xor with ciphertext block
			to_xor = block;
			result.push_all(xored.vec().as_slice());
		}
		CryptoData { data: result }
	}
}
