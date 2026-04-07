import unittest
import os
import sys
import secrets
from pathlib import Path

# Add the parent directory to the path so we can import the module
sys.path.insert(0, str(Path(__file__).parent.parent))

import bitcoinpqc
from bitcoinpqc import Algorithm


class TestBitcoinPQC(unittest.TestCase):

    def test_key_sizes(self):
        """Test key size reporting functions."""
        for algo in [
            Algorithm.FN_DSA_512,
            Algorithm.ML_DSA_44,
            Algorithm.SLH_DSA_SHAKE_128S
        ]:
            # Verify sizes are non-zero
            self.assertGreater(bitcoinpqc.public_key_size(algo), 0)
            self.assertGreater(bitcoinpqc.secret_key_size(algo), 0)
            self.assertGreater(bitcoinpqc.signature_size(algo), 0)

    def _test_algorithm(self, algorithm):
        """Test key generation, signing, and verification for a specific algorithm."""
        # Generate random data for key generation
        random_data = secrets.token_bytes(128)

        # Generate a keypair
        keypair = bitcoinpqc.keygen(algorithm, random_data)

        # Verify key sizes match reported sizes
        self.assertEqual(len(keypair.public_key), bitcoinpqc.public_key_size(algorithm))
        self.assertEqual(len(keypair.secret_key), bitcoinpqc.secret_key_size(algorithm))

        # Test message signing
        message = b"Hello, Bitcoin PQC!"
        signature = bitcoinpqc.sign(algorithm, keypair.secret_key, message)

        # Verify signature size matches reported size
        self.assertEqual(len(signature.signature), bitcoinpqc.signature_size(algorithm))

        # Verify the signature
        self.assertTrue(bitcoinpqc.verify(
            algorithm, keypair.public_key, message, signature
        ))

        # Verify with raw signature bytes
        self.assertTrue(bitcoinpqc.verify(
            algorithm, keypair.public_key, message, signature.signature
        ))

        # Verify that the signature doesn't verify for a different message
        bad_message = b"Bad message!"
        self.assertFalse(bitcoinpqc.verify(
            algorithm, keypair.public_key, bad_message, signature
        ))

    def test_fn_dsa(self):
        """Test FN-DSA-512 (FALCON) algorithm."""
        self._test_algorithm(Algorithm.FN_DSA_512)

    def test_ml_dsa(self):
        """Test ML-DSA-44 (Dilithium) algorithm."""
        self._test_algorithm(Algorithm.ML_DSA_44)

    def test_slh_dsa(self):
        """Test SLH-DSA-SHAKE-128s (SPHINCS+) algorithm."""
        self._test_algorithm(Algorithm.SLH_DSA_SHAKE_128S)


if __name__ == "__main__":
    unittest.main()
