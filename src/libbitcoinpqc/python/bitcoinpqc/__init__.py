"""
Bitcoin PQC Python API

This package provides Python bindings for the libbitcoinpqc library,
which implements post-quantum cryptographic signature algorithms.
"""

from .bitcoinpqc import (
    Algorithm,
    Error,
    KeyPair,
    Signature,
    public_key_size,
    secret_key_size,
    signature_size,
    keygen,
    sign,
    verify
)

__version__ = "0.1.0"
