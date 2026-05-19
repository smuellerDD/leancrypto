fn main() {
	println!("cargo:rustc-check-cfg=cfg(fips_module)");
	println!("cargo:rustc-cfg=fips_module");
	println!("cargo::rustc-env=LD_LIBRARY_PATH=../build");
	println!("cargo::rustc-env=LDFLAGS=-L../build");
}
