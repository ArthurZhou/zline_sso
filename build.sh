export RUSTFLAGS="-C target-cpu=broadwell -C target-feature=+avx2 -C link-arg=-s"
cargo build --release --target x86_64-unknown-linux-musl