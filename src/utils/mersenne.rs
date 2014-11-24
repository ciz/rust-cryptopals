/*
# [deriving (Hash,PartialEq,Eq)]
*/
pub struct MersenneTwister {
	// Create a length 624 array to store the state of the generator
	MT: [u32, ..624],
	index: u32,
}

/*
impl fmt::Show for MersenneTwister {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", self.MT)
	}
}
*/

impl MersenneTwister {
	pub fn new() -> MersenneTwister {
		MersenneTwister { MT: [0u32, ..624], index: 0 }
	}

	// Initialize the generator from a seed
	pub fn init(&mut self, seed: u32) {
		self.index = 0;
		self.MT[0] = seed;
		for i in range(1, 624) { // loop over each other element
			//TODO: need lowest 32 bits of that,
			//is this ok?
			self.MT[i] = (1812433253 * (self.MT[i-1] ^ (self.MT[i-1] >> 30)) + i as u32) as u32; // 0x6c078965
		}
	}

	// Extract a tempered pseudorandom number based on the index-th value,
	// calling generate_numbers() every 624 numbers
	pub fn extract_number(&mut self) -> u32 {
		if self.index == 0 {
			self.generate_numbers();
		}

		let mut y = self.MT[self.index as uint];
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

