#![feature(phase)]
#[phase(plugin)]
extern crate rustful_macros;

extern crate rustful;
extern crate http;
extern crate "rust-crypto" as rust_crypto;
extern crate serialize;
extern crate collections;

//Include `rustful_macros` during the plugin phase
//to be able to use `router!` and `try_send!`.
use rustful::{Server, Request, Response};
use http::method::Get;
use http::status::Status;

fn say_hello(request: Request, response: &mut Response) {
	use self::rust_crypto::hmac::{Hmac};
	use self::rust_crypto::mac::{Mac};
	use self::rust_crypto::sha1::{Sha1};
	use self::rust_crypto::digest::Digest;
	use self::serialize::hex::{ToHex};
	use std::io::Timer;
	use std::time::Duration;

	// Get the values of the query variables
	let file = match request.query.get(&"file".into_string()) {
		Some(name) => name.as_slice(),
		None => { response.status = Status::InternalServerError; "no file" }
	};
	let sig = match request.query.get(&"signature".into_string()) {
		Some(name) => name.as_slice(),
		None => { response.status = Status::InternalServerError; "no signature" }
	};

	let key = "abc";

	let sha = Sha1::new();
	let mut hmac = Hmac::new(sha, key.as_bytes());

	hmac.input(file.as_bytes());
	let macres = hmac.result();
	let vec: Vec<u8> = macres.code().iter().map(|x| *x).collect();
	let comp_sig = vec.as_slice().to_hex();
	//println!("get: {}\nmy : {}", sig, comp_sig);

	let mut timer = Timer::new().unwrap();
	let mut ok = true;

	//TODO: should compare raw bytes
	// compare MACs byte by byte with early exit
	if sig.len() != comp_sig.len() {
		println!("invalid length {} != {}", sig.len(), comp_sig.len());
		response.status = Status::InternalServerError;
	} else {
		for (a, b) in sig.as_bytes().iter().zip(comp_sig.as_bytes().iter()) {
			if *a != *b {
				ok = false;
				break;
			}
			// challenge 31
			//timer.sleep(Duration::milliseconds(5));
			// challenge 32
			timer.sleep(Duration::milliseconds(5));
		}

		if !ok {
			response.status = Status::InternalServerError;
		}
	}

	try_send!(response, format!("file: {}\nyour sig: {}\n  my sig: {}\n{}", file, sig, comp_sig, if ok { "MAC matches" } else { "MAC mismatch" }) while "saying hello");
}

fn main() {
	println!("Visit http://localhost:8080");

	let router = router!{
		//Handle requests for root...
		"/" => Get: say_hello,

		//...and one level below.
		//`:person` is a path variable and it will be accessible in the handler.
		"/:person" => Get: say_hello
	};

	//Build and run the server. Anything below this point is unreachable.
	Server::new().port(8080).handlers(router).run();
}
