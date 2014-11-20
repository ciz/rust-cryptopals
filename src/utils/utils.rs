extern crate serialize;
extern crate collections;
extern crate openssl;

use std::char;
use std::fmt;
use std::vec;
use std::iter::{range_step};

// have to use "self", otherwise it's an "unresolved import"
use self::collections::vec::Vec;
use self::serialize::base64::{ToBase64,FromBase64,STANDARD};
use self::serialize::hex::{FromHex,ToHex};
use self::openssl::crypto::symm;

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
		//TODO: there must be an easier way than this
		// and handle errors
		let mut bytes = Vec::new();
		for byte in self.data.iter().take(count) {
			bytes.push(*byte);
		}
		CryptoData { data: bytes }
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
		let data_it = self.data.iter();
		let mut char_it = data_it.map(|&x| x as char);
		let char_vec: Vec<char> = char_it.collect();
		let s = String::from_chars(char_vec.as_slice());
		s
	}

	pub fn vec(&self) -> &Vec<u8> {
		&self.data
	}

	pub fn block(&self, idx: uint, bsize: uint) -> CryptoData {
		assert!(idx < self.data.len() / bsize);
		CryptoData { data: self.data.as_slice().slice(idx * bsize, (idx + 1) * bsize).to_vec() }
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
		result
	}

	pub fn CTR_encrypt(&self, key: &CryptoData, nonce: &CryptoData, counter: u64) -> CryptoData {
		use std::io::MemWriter;
		let mut result = CryptoData::new();
		let mut w = MemWriter::new();
		let mut le_ctr = counter.to_le();
		w.write_le_u64(le_ctr);
		let ctr_cd = CryptoData::from_vec(&w.unwrap());
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

			let mut w = MemWriter::new();
			le_ctr += 1;
			w.write_le_u64(le_ctr);
			let new_ctr = CryptoData::from_vec(&w.unwrap());
			nonce_ctr = nonce.cat(&new_ctr);
		}
		result
	}

	// same as encryption
	pub fn CTR_decrypt(&self, key: &CryptoData, nonce: &CryptoData, counter: u64) -> CryptoData {
		self.CTR_encrypt(key, nonce, counter)
	}
}

/*
# [deriving (Hash,PartialEq,Eq)]
*/
pub struct MersenneTwister {
	// Create a length 624 array to store the state of the generator
	MT: [uint, ..624],
	index: uint,
}

/*
impl fmt::Show for MersenneTwister {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", self.MT)
	}
}
*/

impl MersenneTwister {
	// Initialize the generator from a seed
	pub fn init(&mut self, seed: uint) {
		self.index = 0;
		self.MT[0] = seed;
		for i in range(1, 624) { // loop over each other element
			//TODO: this likely won't work
			self.MT[i] = ((1812433253 * (self.MT[i-1] ^ (self.MT[i-1] >> 30)) + i) as u32 as uint); // 0x6c078965
			//self.MT[i] = lowest_32_bits_of(1812433253 * (self.MT[i-1] ^ (self.MT[i-1] >> 30)) + i); // 0x6c078965
		}
	}

	// Extract a tempered pseudorandom number based on the index-th value,
	// calling generate_numbers() every 624 numbers
	pub fn extract_number(&mut self) -> uint {
		if self.index == 0 {
			self.generate_numbers();
		}

		let mut y = self.MT[self.index];
		y = y ^ (y >> 11);
		y = y ^ ((y << 7) & 2636928640); // 0x9d2c5680
		y = y ^ ((y << 15) & 4022730752); // 0xefc60000
		y = y ^ (y >> 18);

		self.index = (self.index + 1) % 624;
		y
	}

	// Generate an array of 624 untempered numbers
	pub fn generate_numbers(&mut self) {
		for i in range(0, 624) {
			let y = (self.MT[i] & 0x80000000) // bit 31 (32nd bit) of self.MT[i]
				+ (self.MT[(i + 1) % 624] & 0x7fffffff); // bits 0-30 (first 31 bits) of self.MT[...]
			self.MT[i] = self.MT[(i + 397) % 624] ^ (y >> 1);
			if (y % 2) != 0 { // y is odd
				self.MT[i] = self.MT[i] ^ (2567483615); // 0x9908b0df
			}
		}
	}
}
