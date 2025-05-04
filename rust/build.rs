use std::env;
use std::path::PathBuf;

fn main() {
	println!("cargo:rustc-link-search=../build");
	println!("cargo:rustc-link-lib=leancrypto");

	// Update location of header file as necessary
	let header="/usr/local/include/leancrypto.h";

	println!("cargo:rerun-if-changed={}", header);

	let bindings = bindgen::Builder::default()
		.header(header)
		.generate()
		.expect("Unable to generate bindings");

	let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
	bindings
		.write_to_file(out_path.join("bindings.rs"))
		.expect("Couldn't write bindings!");
	println!("Generated bindings at: {}", out_path.join("bindings.rs").display());
}

