extern crate serialize;
extern crate collections;
extern crate openssl;
extern crate "rust-crypto" as rust_crypto;

use std::char;
use std::fmt;
use std::vec;
use std::iter::{range_step};

// have to use "self", otherwise it's an "unresolved import"
use self::collections::vec::Vec;
use self::serialize::base64::{ToBase64,FromBase64,STANDARD};
use self::serialize::hex::{FromHex,ToHex};
use self::openssl::crypto::symm;
use self::rust_crypto::sha1::{Sha1};

#[deriving (Hash,PartialEq,Eq)]
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

	pub fn random(size: uint) -> CryptoData {
		use std::rand;
		use std::rand::Rng;
		let mut rng = rand::task_rng();

		//TODO: seems to be impossible to use array and fill_bytes,
		// because the size isn't known at compile time
		let mut bytes = Vec::new();
		for _ in range(0u, size) {
			bytes.push(rng.gen::<u8>());
		}

		CryptoData::from_vec(&bytes)
	}

	pub fn zero(size: uint) -> CryptoData {
		let zeros = Vec::from_elem(size, 0u8);
		CryptoData { data: zeros }
	}

	pub fn cut(&self, count: uint) -> CryptoData {
		//assert!(count > 0);
		self.slice(0, count)
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

	pub fn from_byte(byte: u8) -> CryptoData {
		let vec = vec![byte];
		CryptoData { data: vec }
	}

	pub fn from_base64(base64_str: &str) -> CryptoData {
		//TODO: handle errors
		let byte_str = base64_str.from_base64().unwrap();
		CryptoData { data: byte_str.clone() }
	}

	pub fn to_base64(&self) -> String {
		self.data.as_slice().to_base64(STANDARD)
	}

	pub fn to_hex(&self) -> String {
		self.data.as_slice().to_hex()
	}

	pub fn to_text(&self) -> String {
		let char_vec: Vec<char> = self.data.iter().map(|&x| x as char).collect();
		String::from_chars(char_vec.as_slice())
	}

	pub fn vec(&self) -> &Vec<u8> {
		&self.data
	}

	pub fn block(&self, idx: uint, bsize: uint) -> CryptoData {
		self.slice(idx * bsize, (idx + 1) * bsize)
	}

	pub fn slice(&self, start: uint, end: uint) -> CryptoData {
		assert!(start <= end);
		assert!(end <= self.data.len());
		CryptoData { data: self.data.as_slice().slice(start, end).to_vec() }
	}

	pub fn len(&self) -> uint {
		self.data.len()
	}

	pub fn cat(&self, other: &CryptoData) -> CryptoData {
		let mut res = Vec::new();
		res.push_all(self.data.as_slice());
		res.push_all(other.vec().as_slice());

		CryptoData { data: res }
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

	pub fn pad(&self, bsize: uint) -> CryptoData {
		let mut res = self.data.clone();
		let pad_size = bsize - res.len() % bsize;
		//println!("len: {}, pad: {}", res.len(), pad_size);
		let pad_byte = char::from_u32(pad_size as u32).unwrap();
		for _ in range(0, pad_size) {
			res.push(pad_byte as u8);
		}
		CryptoData { data: res }
	}

	pub fn pad_verify(&self, bsize: uint) -> bool {
		let len = self.data.len();
		let pad_byte = *self.data.last().unwrap();
		let pad_size = pad_byte as uint;

		// is it padded to bsize?
		if len % bsize != 0 {
			return false;
		}

		// check for allowed padding bytes
		if !(0 < pad_size && pad_size <= bsize) {
			//println!("wrong pad byte: {}", pad_size);
			return false;
		}

		// check that all padding bytes are the same
		for i in range(0, pad_size) {
			if self.data[len - i - 1] != pad_byte {
				return false;
			}
		}
		true
	}

	pub fn pad_strip(&self, bsize: uint) -> CryptoData {
		let len = self.data.len();
		let pad_byte = *self.data.last().unwrap();
		let pad_size = pad_byte as uint;

		// is it padded to bsize?
		if len % bsize != 0 {
			return self.clone();
		}

		let mut ok = true;
		// check that all padding bytes are the same
		for i in range(1, pad_size) {
			if self.data[len - i] != pad_byte {
				ok = false;
			}
		}

		if ok {
			let new_slice = self.vec().as_slice().slice(0, len - 1);
			CryptoData::from_vec(&new_slice.to_vec())
		} else {
			self.clone()
		}
	}

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
		let plain = if self.len() % 16 != 0 {
			self.pad(16)
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
		let mut result = CryptoData::new();
		let mut to_xor = iv.clone();

		// pad input data
		let plain = self.pad(16);
		let plain_slice = plain.vec().as_slice();

		for idx in range_step (0, plain.len(), 16) {
			let block_slice = plain_slice.slice(idx, idx + 16);
			let block = CryptoData::from_vec(&block_slice.to_vec());
			let xored = block.xor(&to_xor);
			let encrypted = xored.ECB_encrypt(key);
			//println!("enc size: {}", encrypted.len());
			//println!("enc : {}", encrypted.to_hex());
			result = result.cat(&encrypted);
			to_xor = encrypted;
		}
		result
	}

	// TODO: strip pad
	pub fn CBC_decrypt(&self, key: &CryptoData, iv: &CryptoData) -> CryptoData {
		let mut result = CryptoData::new();
		let mut to_xor = iv.clone();
		let self_slice = self.data.as_slice();

		for idx in range_step (0, self.len(), 16) {
			let block_slice = self_slice.slice(idx, idx + 16);
			let block = CryptoData::from_vec(&block_slice.to_vec());
			let decrypted = block.ECB_decrypt(key);
			let xored = decrypted.xor(&to_xor);

			// xor with ciphertext block
			to_xor = block;
			result = result.cat(&xored);
		}
		//TODO: doesn't work
		//result.pad_strip(16)
		result
	}

	pub fn CTR_encrypt(&self, key: &CryptoData, nonce: &CryptoData, counter: u64) -> CryptoData {
		use std::io::MemWriter;
		let mut result = CryptoData::new();
		let mut w = MemWriter::new();
		//TODO: this used to work on older rustc
		//let mut le_ctr = counter.to_le();
		let mut le_ctr = counter;
		//w.write_le_u64(le_ctr);
		w.write_le_u64(counter);
		let ctr_cd = CryptoData::from_vec(&w.clone().into_inner());
		let mut nonce_ctr = nonce.cat(&ctr_cd);

		for idx in range_step (0, self.data.len(), 16) {
			let end = if idx + 16 < self.data.len() {
				idx + 16
			} else {
				self.data.len()
			};

			let block_slice = self.data.slice(idx, end);
			let block = CryptoData::from_vec(&block_slice.to_vec());
			let encrypted = nonce_ctr.ECB_encrypt(key);
			let xored = block.xor(&encrypted.cut(block.len()));
			result = result.cat(&xored);

			le_ctr += 1;
			w.write_le_u64(le_ctr);
			w.write_le_u64(counter);
			let new_ctr = CryptoData::from_vec(&w.clone().into_inner());
			nonce_ctr = nonce.cat(&new_ctr);
		}
		result
	}

	// same as encryption
	pub fn CTR_decrypt(&self, key: &CryptoData, nonce: &CryptoData, counter: u64) -> CryptoData {
		self.CTR_encrypt(key, nonce, counter)
	}

	// count Hamming distance to a data string
	pub fn hamming_distance(&self, other: &CryptoData) -> uint {
		let mut total_dist = 0u;
		for (xc, yc) in self.data.iter().zip(other.vec().iter()) {
			let mut val = *xc ^ *yc;
			let mut dist = 0u;

			// Count the number of bits set
			while val != 0 {
				// A bit is set, so increment the count and clear the bit
				dist += 1;
				val &= val - 1;
			}
			total_dist += dist;
		}

		// Return the number of differing bits
		total_dist
	}
	// count Hamming distance between characters
	pub fn char_hamming_distance(&self, other: &CryptoData) -> uint {
		let mut dist = 0u;
		assert!(self.data.len() == other.len());
		for (xc, yc) in self.data.iter().zip(other.vec().iter()) {
			if *xc != *yc {
				dist += 1;
			}
		}
		dist
	}

	pub fn SHA1_mac_prefix(&self, key: &CryptoData) -> CryptoData {
		use self::rust_crypto::digest::Digest;
		use self::rust_crypto::sha1::Sha1;
		let mut digest: [u8, ..20] = [0, ..20];
		let to_mac = key.cat(self);

		let mut sha = Sha1::new();
		sha.input(to_mac.vec().as_slice());
		sha.result(&mut digest);
		CryptoData::from_vec(&digest.to_vec())
	}
}
