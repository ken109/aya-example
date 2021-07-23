build:
	@cargo +nightly build --package bpf --target=bpfel-unknown-none -Z build-std=core
	@cargo build
