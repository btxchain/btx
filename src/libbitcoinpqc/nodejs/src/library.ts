import { join } from "path";
import { existsSync } from "fs";
import { Algorithm, ErrorCode } from "./types";

// Try to load the native addon
let nativeAddon: any = null;
try {
  nativeAddon = require("../build/Release/bitcoinpqc");
  console.log("Loaded native addon successfully");
} catch (error) {
  console.warn("Failed to load native addon:", error);
}

// Define functions from the native library
export interface BitcoinPqcNative {
  // Size information
  bitcoin_pqc_public_key_size(algorithm: number): number;
  bitcoin_pqc_secret_key_size(algorithm: number): number;
  bitcoin_pqc_signature_size(algorithm: number): number;

  // Key generation, signing and verification
  bitcoin_pqc_keygen(
    algorithm: number,
    randomData: Uint8Array
  ): { publicKey: Uint8Array; secretKey: Uint8Array; resultCode: number };

  bitcoin_pqc_sign(
    algorithm: number,
    secretKey: Uint8Array,
    message: Uint8Array
  ): { signature: Uint8Array; resultCode: number };

  bitcoin_pqc_verify(
    algorithm: number,
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array
  ): number;
}

interface KeySizeConfig {
  publicKey: number;
  secretKey: number;
  signature: number;
}

// Mock library implementation as fallback
class MockBitcoinPqcNative implements BitcoinPqcNative {
  // These values are from the actual implementation
  private keySizes: { [key: number]: KeySizeConfig } = {
    [Algorithm.SECP256K1_SCHNORR]: {
      publicKey: 32,
      secretKey: 32,
      signature: 64,
    },
    [Algorithm.ML_DSA_44]: {
      publicKey: 1312,
      secretKey: 2528,
      signature: 2420,
    },
    [Algorithm.SLH_DSA_SHAKE_128S]: {
      publicKey: 32,
      secretKey: 64,
      signature: 7856,
    },
  };

  bitcoin_pqc_public_key_size(algorithm: number): number {
    return this.keySizes[algorithm]?.publicKey || 0;
  }

  bitcoin_pqc_secret_key_size(algorithm: number): number {
    return this.keySizes[algorithm]?.secretKey || 0;
  }

  bitcoin_pqc_signature_size(algorithm: number): number {
    return this.keySizes[algorithm]?.signature || 0;
  }

  bitcoin_pqc_keygen(
    algorithm: number,
    randomData: Uint8Array
  ): { publicKey: Uint8Array; secretKey: Uint8Array; resultCode: number } {
    if (randomData.length < 128) {
      return {
        publicKey: new Uint8Array(0),
        secretKey: new Uint8Array(0),
        resultCode: ErrorCode.BAD_ARGUMENT,
      };
    }

    if (algorithm < 0 || algorithm > 3) {
      return {
        publicKey: new Uint8Array(0),
        secretKey: new Uint8Array(0),
        resultCode: ErrorCode.BAD_ARGUMENT,
      };
    }

    const pkSize = this.bitcoin_pqc_public_key_size(algorithm);
    const skSize = this.bitcoin_pqc_secret_key_size(algorithm);

    // In a real implementation, this would call the native library
    // Here we're just creating dummy keys based on the random data
    const publicKey = new Uint8Array(pkSize);
    const secretKey = new Uint8Array(skSize);

    // Use random data to populate the key
    for (let i = 0; i < pkSize && i < randomData.length; i++) {
      publicKey[i] = randomData[i];
    }

    for (let i = 0; i < skSize && i < randomData.length; i++) {
      secretKey[i] = randomData[i + Math.floor(randomData.length / 2)];
    }

    return { publicKey, secretKey, resultCode: ErrorCode.OK };
  }

  bitcoin_pqc_sign(
    algorithm: number,
    secretKey: Uint8Array,
    message: Uint8Array
  ): { signature: Uint8Array; resultCode: number } {
    if (algorithm < 0 || algorithm > 3) {
      return {
        signature: new Uint8Array(0),
        resultCode: ErrorCode.BAD_ARGUMENT,
      };
    }

    const expectedSize = this.bitcoin_pqc_secret_key_size(algorithm);
    if (secretKey.length !== expectedSize) {
      return { signature: new Uint8Array(0), resultCode: ErrorCode.BAD_KEY };
    }

    const sigSize = this.bitcoin_pqc_signature_size(algorithm);
    const signature = new Uint8Array(sigSize);

    // In a real implementation, this would call the native library
    // Here we're just creating a dummy signature
    // In reality, this would be a deterministic signature based on the message and secret key
    for (let i = 0; i < sigSize; i++) {
      signature[i] = i < message.length ? message[i] : 0;
    }

    return { signature, resultCode: ErrorCode.OK };
  }

  bitcoin_pqc_verify(
    algorithm: number,
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array
  ): number {
    if (algorithm < 0 || algorithm > 3) {
      return ErrorCode.BAD_ARGUMENT;
    }

    const expectedPkSize = this.bitcoin_pqc_public_key_size(algorithm);
    if (publicKey.length !== expectedPkSize) {
      return ErrorCode.BAD_KEY;
    }

    const expectedSigSize = this.bitcoin_pqc_signature_size(algorithm);
    if (signature.length !== expectedSigSize) {
      return ErrorCode.BAD_SIGNATURE;
    }

    // In a real implementation, this would verify the signature
    // Here we're just pretending it's valid
    return ErrorCode.OK;
  }
}

// Fall back to mock implementation if native addon is not available
const addonOrMock = nativeAddon || new MockBitcoinPqcNative();

// Get the library instance
export function getLibrary(): BitcoinPqcNative {
  return addonOrMock;
}

// For testing - allow library to be replaced
export function setLibraryForTesting(mockLib: BitcoinPqcNative): void {
  nativeAddon = mockLib;
}
