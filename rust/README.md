# Leancrypto RUST Binding

## Compile example code

1. Build leancrypto with meson directory `build` and install header files to `/usr/local/include` (if it is a different target, update build.rs)

2. Build test code: `cargo build --release`

3. Execute test code: `cargo test --release`

4. Build application `example/lc_hash_sha3_512.rs`: `cargo run --example lc_hash_sha3_512`

## Develop your own code

Use the sample applications in `examples/` as well as test code in `tests/` as
starting point.

An excellent introduction into the RUST code development with linkage to a
C library is given by [Quin](https://github.com/Quin-Darcy/rust-c-ffi-guide).
