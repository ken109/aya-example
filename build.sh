#!/bin/sh

set -e

(cd probe && cargo +nightly build --target=bpfel-unknown-none -Z build-std=core)

cargo build
