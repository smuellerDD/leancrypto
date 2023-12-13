use bindgen::{Builder, CargoCallbacks};
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Tell cargo to look for shared libraries in the specified directory
	println!("cargo:rustc-link-search=../build");

	// Tell cargo to tell rustc to link the system leancrypto
	// shared library.
	println!("cargo:rustc-link-lib=leancrypto");

	// Tell cargo to invalidate the built crate whenever the wrapper changes
	println!("cargo:rerun-if-changed=leancrypto.h");


    let input = "leancrypto.h";

    // Tell bindgen to generate wrappers for static functions
    let bindings = Builder::default()
        .header(input)
        .parse_callbacks(Box::new(CargoCallbacks))
        .wrap_static_fns(true)
        .generate()
        .unwrap();

    let output_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    // This is the path to the object file.
    let obj_path = output_path.join("extern.o");
    // This is the path to the static library file.
    let lib_path = output_path.join("libextern.a");

    // Compile the generated wrappers into an object file.
    let clang_output = std::process::Command::new("clang")
        .arg("-O")
        .arg("-c")
        .arg("-o")
        .arg(&obj_path)
        .arg(std::env::temp_dir().join("bindgen").join("extern.c"))
        .arg("-include")
        .arg(input)
        .output()
        .unwrap();

    if !clang_output.status.success() {
        panic!(
            "Could not compile object file:\n{}",
            String::from_utf8_lossy(&clang_output.stderr)
        );
    }

    // Turn the object file into a static library
    #[cfg(not(target_os = "windows"))]
    let lib_output = Command::new("ar")
        .arg("rcs")
        .arg(output_path.join("libextern.a"))
        .arg(obj_path)
        .output()
        .unwrap();
    #[cfg(target_os = "windows")]
    let lib_output = Command::new("LIB")
        .arg(obj_path)
        .arg(format!("/OUT:{}", output_path.join("libextern.lib").display()))
        .output()
        .unwrap();
    if !lib_output.status.success() {
        panic!(
            "Could not emit library file:\n{}",
            String::from_utf8_lossy(&lib_output.stderr)
        );
    }

    // Tell cargo to statically link against the `libextern` static library.
    println!("cargo:rustc-link-lib=static=extern");

    // Write the rust bindings.
    bindings
        .write_to_file(output_path.join("bindings.rs"))
        .expect("Cound not write bindings to the Rust file");
}
