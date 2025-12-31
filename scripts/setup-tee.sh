#!/bin/bash
set -e

# Install system dependencies
apt update
apt install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libclang-dev \
    libzstd-dev \
    git \
    curl

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Set up Rust toolchain
rustup default stable
rustup target add x86_64-unknown-linux-musl

# Build the project
cargo build -p amadeusd --bin amadeusd --release

# Set up Gramine SGX
gramine-sgx-gen-private-key
gramine-manifest amadeusd.manifest.template amadeusd.manifest
gramine-sgx-sign --manifest amadeusd.manifest --output amadeusd.manifest.sgx

# Run
# gramine-sgx amadeusd
