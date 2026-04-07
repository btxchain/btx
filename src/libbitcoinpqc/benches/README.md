# Post-Quantum Cryptography Benchmarks

This directory contains benchmarks for the post-quantum cryptography algorithms implemented in the library, as well as benchmarks for secp256k1 for comparison.

## Running All Benchmarks

To run all benchmarks:

```
cargo bench
```

## Running Algorithm-Specific Benchmarks

You can run benchmarks for a specific algorithm by using the filter option with `cargo bench`:

### ML-DSA-44 (CRYSTALS-Dilithium)

```
cargo bench -- ml_dsa_44
```

### SLH-DSA-128S (SPHINCS+)

```
cargo bench -- slh_dsa_128s
```

### secp256k1 (for comparison)

```
cargo bench -- secp256k1
```

## Running Operation-Specific Benchmarks

You can also run benchmarks for specific operations:

### Key Generation Benchmarks

```
cargo bench -- keygen
```

### Signing Benchmarks

```
cargo bench -- signing
```

### Verification Benchmarks

```
cargo bench -- verification
```

### Size Comparison Benchmarks

```
cargo bench -- sizes
```

## Comparing Algorithms

To see how post-quantum algorithms compare to current standards:

```
# Compare key generation speed
cargo bench -- keygen

# Compare signing speed
cargo bench -- signing

# Compare verification speed
cargo bench -- verification

# Compare key and signature sizes
cargo bench -- sizes
```

## Troubleshooting

If you encounter any issues with a specific algorithm, try running only that algorithm's benchmarks:

```
cargo bench -- ml_dsa_44
```

This can help identify any issues with the algorithm implementation.
