extern crate openssl;
extern crate crypto;

extern crate rand;
extern crate base64;
extern crate hex;
extern crate byteorder;

use set1::chals::{chal1,chal2,chal3,chal4,chal5,chal6,chal7,chal8};
/*
use set2::chals::{chal9,chal10,chal11,chal12,chal13,chal14,chal15,chal16};
use set3::chals::{chal17,chal18,chal19,chal20,chal21,chal22,chal23,chal24};
use set4::chals::{chal25,chal26,chal27,chal28,chal29,chal30,chal31,chal32};
use set5::chals::{chal33,chal34,chal35,chal36,chal37,chal38,chal39,chal40};
*/

mod utils;
mod set1;
/*
mod set2;
mod set3;
mod set4;
*/
fn main() {

	// set 1
	chal1();
	chal2();
	chal3();
	chal4();
	chal5();
//	chal6();

//	chal7();

	chal8();
/*
	// set 2
	chal9();
	chal10();
	chal11();
	chal12();
	chal13();
	chal14();
	chal15();
	chal16();

	// set 3
	chal17();
	chal18();
	chal20();
	chal21();

	// set 4
	chal25();
	chal26();
	chal27();
	chal28();
	chal31();
	chal32();
*/
	// set 5
//	chal33();
}
