#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

//Disable warnings about problematic FFI types
#[allow(improper_ctypes)]
//Disable warnings about unused symbols from leancrypto
#[allow(dead_code)]

pub mod leancrypto {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
