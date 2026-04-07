#!/usr/bin/env python3
"""
Basic usage example for the bitcoinpqc Python bindings.
"""

import os
import sys
import secrets
from pathlib import Path
import time

# Add the parent directory to the path so we can import the module
sys.path.insert(0, str(Path(__file__).parent.parent))

from bitcoinpqc import Algorithm, keygen, sign, verify


def main():
    """Run a basic example of bitcoinpqc usage."""
    # Choose an algorithm
    algorithm = Algorithm.ML_DSA_44  # CRYSTALS-Dilithium

    # Generate random data for key generation
    random_data = secrets.token_bytes(128)

    print(f"Generating key pair for {algorithm.name}...")
    start = time.time()
    keypair = keygen(algorithm, random_data)
    keygen_time = time.time() - start

    print(f"Key generation took {keygen_time:.4f} seconds")
    print(f"Public key size: {len(keypair.public_key)} bytes")
    print(f"Secret key size: {len(keypair.secret_key)} bytes")

    # Sign a message
    message = b"This is a test message for Bitcoin PQC signatures."
    print(f"\nSigning message: {message.decode('utf-8')}")

    start = time.time()
    signature = sign(algorithm, keypair.secret_key, message)
    sign_time = time.time() - start

    print(f"Signing took {sign_time:.4f} seconds")
    print(f"Signature size: {len(signature.signature)} bytes")

    # Verify the signature
    print("\nVerifying signature...")

    start = time.time()
    is_valid = verify(algorithm, keypair.public_key, message, signature)
    verify_time = time.time() - start

    print(f"Verification took {verify_time:.4f} seconds")
    print(f"Signature is valid: {is_valid}")

    # Verify with incorrect message
    bad_message = b"This is NOT the original message!"
    print("\nVerifying signature with incorrect message...")

    is_valid = verify(algorithm, keypair.public_key, bad_message, signature)
    print(f"Signature is valid (should be False): {is_valid}")


if __name__ == "__main__":
    main()
