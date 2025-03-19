use rand::Rng;
use byteorder::{LittleEndian, WriteBytesExt};

use std::char;
use std::fmt;
use std::vec;

use openssl::symm;
use openssl::symm::{encrypt, Crypter, Mode, Cipher};

use base64::Engine;

#[derive (Hash,PartialEq,Eq)]
pub struct CryptoData {
	data: Vec<u8>,
}

impl fmt::Display for CryptoData {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", self.to_hex())
	}
}

impl CryptoData {
	pub fn new() -> CryptoData {
		CryptoData { data: Vec::new() }
	}

	pub fn random(size: usize) -> CryptoData {
		let mut rng = rand::rng();
		//let n: u32 = rng.gen_range(0..100);
	
		//TODO: seems to be impossible to use array and fill_bytes,
		// because the size isn't known at compile time
		let mut bytes = Vec::new();
		for _ in 0..size {
			let x: u8 = rng.random();
			bytes.push(x);
		}

		CryptoData::from_vec(&bytes)
	}

	pub fn zero(size: usize) -> CryptoData {
		let zeros: Vec<u8> = vec![0; size];
		CryptoData { data: zeros }
	}

	pub fn cut(&self, count: usize) -> CryptoData {
		//assert!(count > 0);
		self.slice(0, count)
	}

	pub fn clone(&self) -> CryptoData {
		CryptoData { data: self.data.clone() }
	}

	pub fn from_hex(hexstring: &str) -> CryptoData {
		let vec = hex::decode(hexstring).unwrap();
		CryptoData { data: vec }
//		CryptoData { data: hexstring.from_hex().unwrap() }
	}

	pub fn from_text(ascii: &str) -> CryptoData {
		let bytes: Vec<u8> = ascii.as_bytes().into_iter().map(|b| *b).collect();
		CryptoData { data: bytes }
	}

	pub fn from_vec(vec: &Vec<u8>) -> CryptoData {
		CryptoData { data: vec.clone() }
	}

	pub fn from_byte(byte: u8) -> CryptoData {
		let vec = vec![byte];
		CryptoData { data: vec }
	}

	pub fn from_base64(base64_str: &str) -> CryptoData {
		// TODO: handle errors
		let byte_str = base64::prelude::BASE64_STANDARD
					.decode(base64_str)
					.expect("Failed to decode base64 data.");

		CryptoData { data: byte_str.clone() }
	}

	pub fn to_base64(&self) -> String {
		base64::prelude::BASE64_STANDARD.encode(&self.data)
	}

	pub fn to_hex(&self) -> String {
		hex::encode(&self.data)
	}

	pub fn to_text(&self) -> String {
		String::from_utf8(self.data.clone()).unwrap()
	}

	pub fn vec(&self) -> &Vec<u8> {
		&self.data
	}

	pub fn block(&self, idx: usize, bsize: usize) -> CryptoData {
		self.slice(idx * bsize, (idx + 1) * bsize)
	}

	pub fn slice(&self, start: usize, end: usize) -> CryptoData {
		assert!(start <= end);
		assert!(end <= self.data.len());
		CryptoData { data: self.data[start..end].to_vec() }
	}

	pub fn len(&self) -> usize {
		self.data.len()
	}

	pub fn cat(&self, other: &CryptoData) -> CryptoData {
		let mut res = self.data.clone();
		//res.push(&self.data);
		res.append(&mut other.vec().clone());

		CryptoData { data: res }
	}

	pub fn xor(&self, key: &CryptoData) -> CryptoData {
		let mut res: Vec<u8> = Vec::new();
		let mut data_it = self.data.iter();

		// TODO: wtf goto?
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

	pub fn pad(&self, bsize: usize) -> CryptoData {
		let mut res = self.data.clone();
		let pad_size = bsize - res.len() % bsize;
		//println!("len: {}, pad: {}", res.len(), pad_size);
		let pad_byte = char::from_u32(pad_size as u32).unwrap();
		for _ in 0..pad_size {
			res.push(pad_byte as u8);
		}
		CryptoData { data: res }
	}

	pub fn pad_verify(&self, bsize: usize) -> bool {
		let len = self.data.len();
		let pad_byte = *self.data.last().unwrap();
		let pad_size = pad_byte as usize;

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
		for i in 0..pad_size {
			if self.data[len - i - 1] != pad_byte {
				return false;
			}
		}
		true
	}

	pub fn pad_strip(&self, bsize: usize) -> CryptoData {
		let len = self.data.len();
		let pad_byte = *self.data.last().unwrap();
		let pad_size = pad_byte as usize;

		// is it padded to bsize?
		if len % bsize != 0 {
			return self.clone();
		}

		let mut ok = true;
		// check that all padding bytes are the same
		for i in 1..pad_size {
			if self.data[len - i] != pad_byte {
				ok = false;
			}
		}

		if ok {
			let new_slice = &self.vec()[0..len - 1];
			CryptoData::from_vec(&new_slice.to_vec())
		} else {
			self.clone()
		}
	}

	pub fn encrypt(&self, key: &CryptoData, iv: &CryptoData, cipher: Cipher) -> CryptoData {
		println!("data: {}, key {}", self.to_hex(), key.to_hex());
		let encrypted = encrypt(	cipher,
						key.vec().as_slice(),
						Some(&iv.vec()),
						//Some(&iv.vec().clone()),
						self.data.as_slice()).unwrap();

		//println!("res: {}", encrypted.to_hex());
		CryptoData { data: encrypted }
	}

	pub fn decrypt(&self, key: &CryptoData, iv: &CryptoData, cipher: Cipher) -> CryptoData {
		//println!("data: {}, key {}", self.to_hex(), key.to_hex());
		let decrypted = symm::decrypt(cipher,
						key.vec(),
						Some(iv.vec()),
						&self.data).unwrap();

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

		let mut c = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, &key.vec(), Some(&vec![])).unwrap();
		c.pad(false);
		let mut r: Vec<u8> = vec![]; 
		let _ = c.update(plain.vec(), &mut r);
		let mut rest: Vec<u8> = vec![]; 
		let _ = c.finalize(&mut rest);
		r.extend(rest.into_iter());
		CryptoData { data: r }
	}

	pub fn ECB_decrypt(&self, key: &CryptoData) -> CryptoData {
		//TODO: this doesn't work
		//https://github.com/sfackler/rust-openssl/issues/40
		//self.decrypt(key, &CryptoData::new(), symm::AES_128_ECB)

		let mut c = symm::Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key.vec(), Some(&vec![])).unwrap();
		// need to disable padding, otherwise there's an additional padding block at the end
		c.pad(false);
		let mut r: Vec<u8> = vec![];
		let _ = c.update(self.vec(), &mut r);
		let mut rest: Vec<u8> = vec![]; 
		let _ = c.finalize(&mut rest);
		r.extend(rest.into_iter());
		CryptoData { data: r }
	}

	pub fn CBC_encrypt(&self, key: &CryptoData, iv: &CryptoData) -> CryptoData {
		let mut result = CryptoData::new();
		let mut to_xor = iv.clone();

		// pad input data
		let plain = self.pad(16);
		let plain_slice = plain.vec().as_slice();

		for idx in (0..plain.len()).step_by(16) {
			let block_slice = &plain_slice[idx..idx + 16];
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

		for idx in (0..self.len()).step_by(16) {
			let block_slice = &self_slice[idx..idx + 16];
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
		let mut result = CryptoData::new();
		let mut le_ctr = counter;

		let mut le = vec![];
		le.write_u64::<LittleEndian>(counter).unwrap();

		let ctr_cd = CryptoData::from_vec(&le);
		let mut nonce_ctr = nonce.cat(&ctr_cd);

		for idx in (0..self.data.len()).step_by(16) {
			let end = if idx + 16 < self.data.len() {
				idx + 16
			} else {
				self.data.len()
			};

			let block_slice = &self.data[idx..end];
			let block = CryptoData::from_vec(&block_slice.to_vec());
			let encrypted = nonce_ctr.ECB_encrypt(key);
			let xored = block.xor(&encrypted.cut(block.len()));
			result = result.cat(&xored);

			le_ctr += 1;
			le.write_u64::<LittleEndian>(le_ctr).unwrap();
			le.write_u64::<LittleEndian>(counter).unwrap();
			let new_ctr = CryptoData::from_vec(&le);
			nonce_ctr = nonce.cat(&new_ctr);
		}
		result
	}

	// same as encryption
	pub fn CTR_decrypt(&self, key: &CryptoData, nonce: &CryptoData, counter: u64) -> CryptoData {
		self.CTR_encrypt(key, nonce, counter)
	}

	// count Hamming distance to a data string
	pub fn hamming_distance(&self, other: &CryptoData) -> usize {
		let mut total_dist = 0;
		for (xc, yc) in self.data.iter().zip(other.vec().iter()) {
			let mut val = *xc ^ *yc;
			let mut dist = 0;

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
	pub fn char_hamming_distance(&self, other: &CryptoData) -> usize {
		let mut dist = 0;
		assert!(self.data.len() == other.len());
		for (xc, yc) in self.data.iter().zip(other.vec().iter()) {
			if *xc != *yc {
				dist += 1;
			}
		}
		dist
	}

	pub fn SHA1_mac_prefix(&self, key: &CryptoData) -> CryptoData {
		use crypto::digest::Digest;
		use crypto::sha1::Sha1;
		let mut digest: [u8; 20] = [0; 20];
	
		let binding = key.cat(self);
		let to_mac = binding.vec();
/*
		use openssl::sha;
		let mut hasher = sha::Sha1::new();
		hasher.update(to_mac);
		let mut digest = hasher.finish();
*/
		let mut sha = Sha1::new();
		sha.input(&to_mac);
		sha.result(&mut digest);

		CryptoData::from_vec(&digest.to_vec())
	}
}
