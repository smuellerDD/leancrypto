# Leancrypto RUST Binding

1. Build leancrypto with meson directory `build`

2. env RUSTFLAGS="-Clinker-plugin-lto -Clinker=clang -Clink-arg=-fuse-ld=lld" cargo build --release

3. `cargo test`
