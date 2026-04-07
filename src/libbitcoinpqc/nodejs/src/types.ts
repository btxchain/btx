/**
 * Bitcoin PQC algorithm identifiers
 */
export enum Algorithm {
  /** BIP-340 Schnorr + X-Only - Elliptic Curve Digital Signature Algorithm */
  SECP256K1_SCHNORR = 0,
  /** ML-DSA-44 (CRYSTALS-Dilithium) - Lattice-based signature scheme */
  ML_DSA_44 = 1,
  /** SLH-DSA-Shake-128s (SPHINCS+) - Hash-based signature scheme */
  SLH_DSA_SHAKE_128S = 2,
}

/**
 * Error types for PQC operations
 */
export enum ErrorCode {
  /** Operation completed successfully */
  OK = 0,
  /** Invalid arguments provided */
  BAD_ARGUMENT = -1,
  /** Invalid key provided */
  BAD_KEY = -2,
  /** Invalid signature provided */
  BAD_SIGNATURE = -3,
  /** Algorithm not implemented */
  NOT_IMPLEMENTED = -4,
}

/**
 * Error class for PQC operations
 */
export class PqcError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message?: string) {
    // Use a default message if none provided
    const defaultMessage = (() => {
      switch (code) {
        case ErrorCode.BAD_ARGUMENT:
          return "Invalid arguments provided";
        case ErrorCode.BAD_KEY:
          return "Invalid key provided";
        case ErrorCode.BAD_SIGNATURE:
          return "Invalid signature provided";
        case ErrorCode.NOT_IMPLEMENTED:
          return "Algorithm not implemented";
        default:
          return `Unexpected error code: ${code}`;
      }
    })();

    super(message || defaultMessage);
    this.code = code;
    this.name = "PqcError";

    // For better stack traces in Node.js
    Error.captureStackTrace(this, PqcError);
  }
}

/**
 * Public key wrapper
 */
export class PublicKey {
  /** The algorithm this key belongs to */
  readonly algorithm: Algorithm;
  /** The raw key bytes */
  readonly bytes: Uint8Array;

  constructor(algorithm: Algorithm, bytes: Uint8Array) {
    this.algorithm = algorithm;
    this.bytes = bytes;
  }
}

/**
 * Secret key wrapper
 */
export class SecretKey {
  /** The algorithm this key belongs to */
  readonly algorithm: Algorithm;
  /** The raw key bytes */
  readonly bytes: Uint8Array;

  constructor(algorithm: Algorithm, bytes: Uint8Array) {
    this.algorithm = algorithm;
    this.bytes = bytes;
  }
}

/**
 * Signature wrapper
 */
export class Signature {
  /** The algorithm this signature belongs to */
  readonly algorithm: Algorithm;
  /** The raw signature bytes */
  readonly bytes: Uint8Array;

  constructor(algorithm: Algorithm, bytes: Uint8Array) {
    this.algorithm = algorithm;
    this.bytes = bytes;
  }
}

/**
 * Key pair containing both public and secret keys
 */
export class KeyPair {
  /** The public key */
  readonly publicKey: PublicKey;
  /** The secret key */
  readonly secretKey: SecretKey;

  constructor(publicKey: PublicKey, secretKey: SecretKey) {
    if (publicKey.algorithm !== secretKey.algorithm) {
      throw new PqcError(
        ErrorCode.BAD_ARGUMENT,
        "Public and secret key algorithms must match"
      );
    }
    this.publicKey = publicKey;
    this.secretKey = secretKey;
  }
}
