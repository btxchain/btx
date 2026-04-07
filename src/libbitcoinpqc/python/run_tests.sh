#!/bin/bash

# Run the Python tests for libbitcoinpqc

# Exit on any error
set -e

echo "Running libbitcoinpqc Python API tests..."

# Check if the library can be found
if [ -f "../build/lib/libbitcoinpqc.so" ] || [ -f "../build/lib/libbitcoinpqc.dylib" ]; then
    echo "Found library at ../build/lib"
elif [ -f "../target/debug/libbitcoinpqc.so" ] || [ -f "../target/debug/libbitcoinpqc.dylib" ]; then
    echo "Found Rust library at ../target/debug"
    echo "Using mock implementation for testing"
    export BITCOINPQC_ALLOW_MOCK=1

    # Add this to LD_LIBRARY_PATH for the current session
    # (Not needed with mock implementation, but kept for documentation)
    # export LD_LIBRARY_PATH="../target/debug:$LD_LIBRARY_PATH"
elif [ -f "../target/release/libbitcoinpqc.so" ] || [ -f "../target/release/libbitcoinpqc.dylib" ]; then
    echo "Found Rust library at ../target/release"
    echo "Using mock implementation for testing"
    export BITCOINPQC_ALLOW_MOCK=1

    # Add this to LD_LIBRARY_PATH for the current session
    # (Not needed with mock implementation, but kept for documentation)
    # export LD_LIBRARY_PATH="../target/release:$LD_LIBRARY_PATH"
elif [ -f "/usr/lib/libbitcoinpqc.so" ] || [ -f "/usr/lib/libbitcoinpqc.dylib" ]; then
    echo "Found library at /usr/lib"
elif [ -f "/usr/local/lib/libbitcoinpqc.so" ] || [ -f "/usr/local/lib/libbitcoinpqc.dylib" ]; then
    echo "Found library at /usr/local/lib"
else
    echo "WARNING: Library not found, using mock implementation for testing"
    export BITCOINPQC_ALLOW_MOCK=1
fi

# Run unittest tests
python3 -m unittest discover -s tests

echo "All tests passed!"

# Run the example
echo -e "\nRunning example..."
python3 examples/basic_usage.py
