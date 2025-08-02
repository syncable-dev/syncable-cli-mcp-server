#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Build the project.
echo "Building the project..."
cargo build --all

# Format the code.
echo "Formatting the code..."
cargo fmt --all -- --check

# Lint the code.
echo "Linting the code..."
cargo clippy --all-targets --all-features -- -D warnings

# Run tests.
echo "Running tests..."
cargo test --all

echo "Build process completed successfully."
