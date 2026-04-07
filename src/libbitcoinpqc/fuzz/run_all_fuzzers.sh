#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Define the fuzz targets to run (names must match Cargo.toml)
TARGETS="keypair_generation sign_verify cross_algorithm key_parsing signature_parsing"

echo "Running all fuzz targets in parallel: $TARGETS"

# Check if GNU Parallel is installed
if ! command -v parallel &> /dev/null
then
    echo "Error: GNU Parallel is not installed. Please install it to run fuzzers in parallel."
    echo "(e.g., 'sudo apt install parallel' or 'brew install parallel')"
    exit 1
fi

# Run targets in parallel using GNU Parallel
# -j 0: Run one job per CPU core. Adjust if needed (e.g., -j 4 for 4 cores).
# --line-buffer: Buffer output line by line, helps prevent excessively interleaved output.
# {}: Placeholder for each target name.

printf "%s\n" $TARGETS | parallel -j 0 --line-buffer \
  'echo "--- Starting fuzzer: {} ---"; cargo fuzz run "{}"; echo "--- Finished fuzzer: {} ---"'


echo "-------------------------------------"
echo "All parallel fuzz jobs launched (may still be running)."
