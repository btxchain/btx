#!/bin/bash

# Script to sync C source files from parent directory to src/c_sources
# This should be run before building or publishing the package

set -e

echo "Syncing C source files..."

# Remove existing c_sources directory
rm -rf src/c_sources

# Create new c_sources directory
mkdir -p src/c_sources

# Copy C source files
echo "Copying main C source file..."
cp ../src/bitcoinpqc.c src/c_sources/

echo "Copying ML-DSA source files..."
cp -r ../src/ml_dsa src/c_sources/

echo "Copying SLH-DSA source files..."
cp -r ../src/slh_dsa src/c_sources/

echo "Copying Dilithium reference implementation..."
cp -r ../dilithium/ref src/c_sources/dilithium_ref

echo "Copying SPHINCS+ reference implementation..."
cp -r ../sphincsplus/ref src/c_sources/sphincsplus_ref

echo "Copying include files..."
cp -r ../include src/c_sources/

# Update include paths in C source files
echo "Updating include paths..."
find src/c_sources -name "*.c" -exec sed -i 's|../../dilithium/ref/|../dilithium_ref/|g' {} \;
find src/c_sources -name "*.c" -exec sed -i 's|../../sphincsplus/ref/|../sphincsplus_ref/|g' {} \;
find src/c_sources -name "*.c" -exec sed -i 's|../../include/|../include/|g' {} \;

echo "C source files synced successfully!"