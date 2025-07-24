setup:
	rustup update
	rustup component add clippy
	cargo install cargo-audit

build:
	cargo build

build-wasm:
	rustup target add wasm32-unknown-unknown
	cargo build --target wasm32-unknown-unknown

fmt:
	cargo +nightly fmt --all

test:
	cargo test --all-features --workspace

lint:
	cargo clippy --all-targets --all-features -- -D warnings

doc:
	cargo doc --workspace --no-deps --all-features --document-private-items --examples

bench-all:
	cargo bench --features benchmarking --workspace
bench-maurer:
	cargo bench --features benchmarking --package maurer
bench-2pc:
	cargo bench --features benchmarking --package 2pc-mpc
bench-tiresias:
	cargo bench --features benchmarking --package tiresias

audit:
	cargo audit
