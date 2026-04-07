import {
  Algorithm,
  ErrorCode,
  PqcError,
  generateKeyPair,
  publicKeySize,
  secretKeySize,
  sign,
  signatureSize,
  verify,
} from "../index";

import { getLibrary, setLibraryForTesting, BitcoinPqcNative } from "../library";

describe("Bitcoin PQC", () => {
  // Generate random data for tests
  function getRandomBytes(size: number): Uint8Array {
    const bytes = new Uint8Array(size);
    for (let i = 0; i < size; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
    return bytes;
  }

  describe("key sizes", () => {
    test("should report correct key sizes for each algorithm", () => {
      // Test key size reporting functions
      for (const algo of [
        Algorithm.SECP256K1_SCHNORR,
        Algorithm.ML_DSA_44,
        Algorithm.SLH_DSA_SHAKE_128S,
      ]) {
        expect(publicKeySize(algo)).toBeGreaterThan(0);
        expect(secretKeySize(algo)).toBeGreaterThan(0);
        expect(signatureSize(algo)).toBeGreaterThan(0);
      }
    });
  });

  describe("ML-DSA-44 (Dilithium)", () => {
    const algorithm = Algorithm.ML_DSA_44;

    // Skip this test for now
    test.skip("should generate keypair, sign and verify", () => {
      // Generate random data for key generation
      const randomData = getRandomBytes(128);

      // Generate a keypair
      const keypair = generateKeyPair(algorithm, randomData);

      // Verify key sizes match reported sizes
      expect(keypair.publicKey.bytes.length).toBe(publicKeySize(algorithm));
      expect(keypair.secretKey.bytes.length).toBe(secretKeySize(algorithm));

      // Test message signing
      const message = new TextEncoder().encode("Hello, Bitcoin PQC!");
      const signature = sign(keypair.secretKey, message);

      // Verify signature size matches reported size
      expect(signature.bytes.length).toBe(signatureSize(algorithm));

      // Verify the signature - should not throw
      expect(() => {
        verify(keypair.publicKey, message, signature);
      }).not.toThrow();

      // Verify with raw signature bytes
      expect(() => {
        verify(keypair.publicKey, message, signature.bytes);
      }).not.toThrow();

      // Verify that the signature doesn't verify for a different message
      const badMessage = new TextEncoder().encode("Bad message!");
      expect(() => {
        verify(keypair.publicKey, badMessage, signature);
      }).toThrow(PqcError);
    });
  });

  describe("SLH-DSA-SHAKE-128s (SPHINCS+)", () => {
    const algorithm = Algorithm.SLH_DSA_SHAKE_128S;

    test("should generate keypair, sign and verify", () => {
      // Generate random data for key generation
      const randomData = getRandomBytes(128);

      // Generate a keypair
      const keypair = generateKeyPair(algorithm, randomData);

      // Verify key sizes match reported sizes
      expect(keypair.publicKey.bytes.length).toBe(publicKeySize(algorithm));
      expect(keypair.secretKey.bytes.length).toBe(secretKeySize(algorithm));

      // Test message signing
      const message = new TextEncoder().encode("Hello, Bitcoin PQC!");
      const signature = sign(keypair.secretKey, message);

      // Verify signature size matches reported size
      expect(signature.bytes.length).toBe(signatureSize(algorithm));

      // Verify the signature - should not throw
      expect(() => {
        verify(keypair.publicKey, message, signature);
      }).not.toThrow();
    });
  });


  test("should generate keypair, sign and verify", () => {
    // Generate random data for key generation
    const randomData = getRandomBytes(128);

    // Generate a keypair
    const keypair = generateKeyPair(algorithm, randomData);

    // Verify key sizes match reported sizes
    expect(keypair.publicKey.bytes.length).toBe(publicKeySize(algorithm));
    expect(keypair.secretKey.bytes.length).toBe(secretKeySize(algorithm));

    // Test message signing
    const message = new TextEncoder().encode("Hello, Bitcoin PQC!");
    const signature = sign(keypair.secretKey, message);

    // Verify signature size matches reported size
    expect(signature.bytes.length).toBe(signatureSize(algorithm));

    // Verify the signature - should not throw
    expect(() => {
      verify(keypair.publicKey, message, signature);
    }).not.toThrow();
  });
});

describe("error conditions", () => {
  test("should throw on invalid input", () => {
    // Invalid algorithm
    expect(() => {
      const randomData = getRandomBytes(128);
      generateKeyPair(99 as Algorithm, randomData);
    }).toThrow(PqcError);

    // Invalid random data size
    expect(() => {
      const randomData = getRandomBytes(16); // Less than 128 bytes
      generateKeyPair(Algorithm.ML_DSA_44, randomData);
    }).toThrow(PqcError);
  });
});
});
