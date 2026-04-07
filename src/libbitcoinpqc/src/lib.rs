#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[cfg(feature = "serde")]
use std::convert::TryFrom;
use std::error::Error as StdError;
use std::fmt;
use std::hash::Hash;
use std::ptr;

use bitmask_enum::bitmask;
use secp256k1::{
    schnorr, All, Keypair as SecpKeypair, Secp256k1, SecretKey as SecpSecretKey, XOnlyPublicKey,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serde")]
mod hex_bytes {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};
    use std::vec::Vec; // Ensure Vec is in scope

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(s).map_err(Error::custom)
    }
}

// Include the auto-generated bindings using our wrapper
// Make it pub(crate) so doctests can access these symbols
pub(crate) mod bindings_include;
// Use a glob import to get all the symbols consistently
use bindings_include::*;

/// Error type for PQC operations
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum PqcError {
    /// Invalid arguments provided
    BadArgument,
    /// Not enough data provided (e.g., for key generation)
    InsufficientData,
    /// Invalid key provided or invalid format for the specified algorithm
    BadKey,
    /// Invalid signature provided or invalid format for the specified algorithm
    BadSignature,
    /// Algorithm not implemented (e.g., trying to sign/keygen Secp256k1)
    NotImplemented,
    /// Provided public key and signature algorithms do not match
    AlgorithmMismatch,
    /// Secp256k1 context error (should be rare with global context)
    Secp256k1Error(secp256k1::Error),
    /// Other unexpected error from the C library
    Other(i32),
}

impl fmt::Display for PqcError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PqcError::BadArgument => write!(f, "Invalid arguments provided"),
            PqcError::InsufficientData => write!(f, "Not enough data provided"),
            PqcError::BadKey => write!(f, "Invalid key provided or invalid format"),
            PqcError::BadSignature => write!(f, "Invalid signature provided or invalid format"),
            PqcError::NotImplemented => write!(f, "Algorithm not implemented"),
            PqcError::AlgorithmMismatch => {
                write!(f, "Public key and signature algorithms mismatch")
            }
            PqcError::Secp256k1Error(e) => write!(f, "Secp256k1 error: {e}"),
            PqcError::Other(code) => write!(f, "Unexpected error code: {code}"),
        }
    }
}

impl StdError for PqcError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            PqcError::Secp256k1Error(e) => Some(e),
            _ => None,
        }
    }
}

impl From<secp256k1::Error> for PqcError {
    fn from(e: secp256k1::Error) -> Self {
        PqcError::Secp256k1Error(e)
    }
}

impl From<bitcoin_pqc_error_t> for Result<(), PqcError> {
    fn from(error: bitcoin_pqc_error_t) -> Self {
        match error {
            bitcoin_pqc_error_t::BITCOIN_PQC_OK => Ok(()),
            bitcoin_pqc_error_t::BITCOIN_PQC_ERROR_BAD_ARG => Err(PqcError::BadArgument),
            bitcoin_pqc_error_t::BITCOIN_PQC_ERROR_BAD_KEY => Err(PqcError::BadKey),
            bitcoin_pqc_error_t::BITCOIN_PQC_ERROR_BAD_SIGNATURE => Err(PqcError::BadSignature),
            bitcoin_pqc_error_t::BITCOIN_PQC_ERROR_NOT_IMPLEMENTED => Err(PqcError::NotImplemented),
            _ => Err(PqcError::Other(error.0)),
        }
    }
}

/// PQC Algorithm type
#[bitmask(u8)]
// We derive serde conditionally, other traits like Debug, Clone, Eq, Hash etc.
// should be provided by the included C bindings or the bitmask macro.
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(try_from = "String", into = "String")
)]
pub enum Algorithm {
    /// BIP-340 Schnorr + X-Only - Elliptic Curve Digital Signature Algorithm
    SECP256K1_SCHNORR,
    /// ML-DSA-44 (CRYSTALS-Dilithium) - Lattice-based signature scheme
    ML_DSA_44,
    /// SLH-DSA-Shake-128s (SPHINCS+) - Hash-based signature scheme
    SLH_DSA_128S,
}

impl From<Algorithm> for bitcoin_pqc_algorithm_t {
    fn from(alg: Algorithm) -> Self {
        match alg {
            Algorithm::SECP256K1_SCHNORR => bitcoin_pqc_algorithm_t::BITCOIN_PQC_SECP256K1_SCHNORR,
            Algorithm::ML_DSA_44 => bitcoin_pqc_algorithm_t::BITCOIN_PQC_ML_DSA_44,
            Algorithm::SLH_DSA_128S => bitcoin_pqc_algorithm_t::BITCOIN_PQC_SLH_DSA_SHAKE_128S,
            _ => panic!("Invalid algorithm"),
        }
    }
}

// Serde implementations using string representation directly on Algorithm
#[cfg(feature = "serde")]
impl TryFrom<String> for Algorithm {
    type Error = String; // Serde requires specific error handling

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_str() {
            "SECP256K1_SCHNORR" => Ok(Algorithm::SECP256K1_SCHNORR),
            "ML_DSA_44" => Ok(Algorithm::ML_DSA_44),
            "SLH_DSA_128S" => Ok(Algorithm::SLH_DSA_128S),
            _ => Err(format!("Unknown algorithm string: {s}")),
        }
    }
}

#[cfg(feature = "serde")]
impl From<Algorithm> for String {
    fn from(alg: Algorithm) -> Self {
        match alg {
            Algorithm::SECP256K1_SCHNORR => "SECP256K1_SCHNORR".to_string(),
            Algorithm::ML_DSA_44 => "ML_DSA_44".to_string(),
            Algorithm::SLH_DSA_128S => "SLH_DSA_128S".to_string(),
            _ => panic!("Invalid algorithm variant"), // Should not happen with bitmask
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Algorithm::SECP256K1_SCHNORR => write!(f, "SECP256K1_SCHNORR"),
            Algorithm::ML_DSA_44 => write!(f, "ML_DSA_44"),
            Algorithm::SLH_DSA_128S => write!(f, "SLH_DSA_128S"),
            _ => write!(f, "Unknown({:b})", self.bits),
        }
    }
}

impl Algorithm {
    /// Returns a user-friendly debug string with the algorithm name
    pub fn debug_name(&self) -> String {
        match *self {
            Algorithm::SECP256K1_SCHNORR => "SECP256K1_SCHNORR".to_string(),
            Algorithm::ML_DSA_44 => "ML_DSA_44".to_string(),
            Algorithm::SLH_DSA_128S => "SLH_DSA_128S".to_string(),
            _ => format!("Unknown({:b})", self.bits),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PublicKey {
    /// The algorithm this key belongs to
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub algorithm: Algorithm,
    /// The raw key bytes (serialized as hex)
    #[cfg_attr(feature = "serde", serde(with = "hex_bytes"))]
    pub bytes: Vec<u8>,
}

impl PublicKey {
    /// Creates a PublicKey from an algorithm and a byte slice.
    ///
    /// Validates the length of the byte slice against the expected size for the algorithm.
    /// For Secp256k1, also validates the byte format.
    pub fn try_from_slice(algorithm: Algorithm, bytes: &[u8]) -> Result<Self, PqcError> {
        let expected_len = public_key_size(algorithm);
        if bytes.len() != expected_len {
            return Err(PqcError::BadKey); // Use BadKey for length mismatch
        }

        // Additional validation for Secp256k1 keys
        if algorithm == Algorithm::SECP256K1_SCHNORR {
            XOnlyPublicKey::from_slice(bytes).map_err(|_| PqcError::BadKey)?;
        }

        Ok(PublicKey {
            algorithm,
            bytes: bytes.to_vec(),
        })
    }

    /// Creates a PublicKey from an algorithm and a hex string.
    pub fn from_str(algorithm: Algorithm, s: &str) -> Result<Self, PqcError> {
        let bytes = hex::decode(s).map_err(|_| PqcError::BadArgument)?;
        Self::try_from_slice(algorithm, &bytes)
    }

    /// Returns the underlying secp256k1 XOnlyPublicKey if applicable.
    pub fn secp256k1_key(&self) -> Result<XOnlyPublicKey, PqcError> {
        if self.algorithm == Algorithm::SECP256K1_SCHNORR {
            XOnlyPublicKey::from_slice(&self.bytes).map_err(|_| PqcError::BadKey)
        // Should be valid if constructed correctly
        } else {
            Err(PqcError::AlgorithmMismatch)
        }
    }
}

/// Secret key wrapper
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecretKey {
    /// The algorithm this key belongs to
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub algorithm: Algorithm,
    /// The raw key bytes (serialized as hex)
    #[cfg_attr(feature = "serde", serde(with = "hex_bytes"))]
    pub bytes: Vec<u8>,
}

impl SecretKey {
    /// Creates a SecretKey from an algorithm and a hex string.
    pub fn from_str(algorithm: Algorithm, s: &str) -> Result<Self, PqcError> {
        let bytes = hex::decode(s).map_err(|_| PqcError::BadArgument)?;
        Self::try_from_slice(algorithm, &bytes)
    }

    /// Creates a SecretKey from an algorithm and a byte slice.
    ///
    /// Validates the length of the byte slice against the expected size for the algorithm.
    /// For Secp256k1, also validates the byte format.
    pub fn try_from_slice(algorithm: Algorithm, bytes: &[u8]) -> Result<Self, PqcError> {
        let expected_len = secret_key_size(algorithm);
        if bytes.len() != expected_len {
            return Err(PqcError::BadKey);
        }

        // Additional validation for Secp256k1 keys
        if algorithm == Algorithm::SECP256K1_SCHNORR {
            // SecpSecretKey::from_slice does verification, checking if the key is valid (non-zero)
            SecpSecretKey::from_slice(bytes).map_err(|_| PqcError::BadKey)?;
        }

        Ok(SecretKey {
            algorithm,
            bytes: bytes.to_vec(),
        })
    }

    /// Returns the underlying secp256k1 SecretKey if applicable.
    pub fn secp256k1_key(&self) -> Result<SecpSecretKey, PqcError> {
        if self.algorithm == Algorithm::SECP256K1_SCHNORR {
            SecpSecretKey::from_slice(&self.bytes).map_err(|_| PqcError::BadKey)
        // Should be valid if constructed correctly
        } else {
            Err(PqcError::AlgorithmMismatch)
        }
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // Zero out secret key memory on drop
        // Consider using crates like `zeroize` for more robust clearing
        for byte in &mut self.bytes {
            *byte = 0;
        }
    }
}

/// Represents a signature (PQC or Secp256k1)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Signature {
    /// The algorithm this signature belongs to
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub algorithm: Algorithm,
    /// The raw signature bytes (serialized as hex)
    #[cfg_attr(feature = "serde", serde(with = "hex_bytes"))]
    pub bytes: Vec<u8>,
}

impl Signature {
    /// Creates a Signature from an algorithm and a byte slice.
    ///
    /// Validates the length of the byte slice against the expected size for the algorithm.
    /// For Secp256k1, also validates the byte format.
    pub fn try_from_slice(algorithm: Algorithm, bytes: &[u8]) -> Result<Self, PqcError> {
        let expected_len = signature_size(algorithm);
        if bytes.len() != expected_len {
            return Err(PqcError::BadSignature);
        }

        // Additional validation for Secp256k1 signatures
        if algorithm == Algorithm::SECP256K1_SCHNORR {
            // Schnorr signatures don't have a cheap validity check like keys,
            // but from_slice checks the length (already done above).
            schnorr::Signature::from_slice(bytes).map_err(|_| PqcError::BadSignature)?;
        }

        Ok(Signature {
            algorithm,
            bytes: bytes.to_vec(),
        })
    }

    /// Creates a Signature from an algorithm and a hex string.
    pub fn from_str(algorithm: Algorithm, s: &str) -> Result<Self, PqcError> {
        let bytes = hex::decode(s).map_err(|_| PqcError::BadArgument)?;
        Self::try_from_slice(algorithm, &bytes)
    }

    /// Returns the underlying secp256k1 Schnorr Signature if applicable.
    pub fn secp256k1_signature(&self) -> Result<schnorr::Signature, PqcError> {
        if self.algorithm == Algorithm::SECP256K1_SCHNORR {
            schnorr::Signature::from_slice(&self.bytes).map_err(|_| PqcError::BadSignature)
        // Should be valid if constructed correctly
        } else {
            Err(PqcError::AlgorithmMismatch)
        }
    }
}

/// Key pair containing both public and secret keys
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct KeyPair {
    /// The public key
    pub public_key: PublicKey,
    /// The secret key
    pub secret_key: SecretKey,
}

/// Generate a key pair for the specified algorithm using provided seed data.
///
/// # Arguments
///
/// * `algorithm` - The algorithm to use (PQC or Secp256k1)
/// * `random_data` - Seed bytes for key generation.
///     - For PQC algorithms, must be at least 128 bytes.
///     - For `SECP256K1_SCHNORR`, must be exactly 32 bytes representing the desired secret key.
///
/// # Returns
///
/// A new key pair on success, or an error if the `random_data` is invalid for the algorithm.
///
pub fn generate_keypair(algorithm: Algorithm, random_data: &[u8]) -> Result<KeyPair, PqcError> {
    if algorithm == Algorithm::SECP256K1_SCHNORR {
        // For Secp256k1, random_data *is* the secret key.
        let required_size = secret_key_size(algorithm); // Should be 32

        // Check for insufficient data
        if random_data.len() < required_size {
            return Err(PqcError::InsufficientData);
        }

        // Use the first 32 bytes, truncating excess data if provided
        let key_data = &random_data[..required_size];

        let secp = Secp256k1::<All>::new(); // Context needed for key derivation

        // Attempt to create secret key from the provided data
        let sk_result = SecpSecretKey::from_slice(key_data);
        let sk = sk_result.map_err(|_| PqcError::BadKey)?;

        // Create KeyPair from secret key
        let keypair = SecpKeypair::from_secret_key(&secp, &sk);

        // Derive the public key using from_keypair
        let (pk, _parity) = XOnlyPublicKey::from_keypair(&keypair); // Destructure the tuple

        // Construct the structs
        let public_key = PublicKey {
            algorithm: Algorithm::SECP256K1_SCHNORR,
            bytes: pk.serialize().to_vec(), // Serialize the XOnlyPublicKey part
        };
        let secret_key = SecretKey {
            algorithm: Algorithm::SECP256K1_SCHNORR,
            bytes: sk.as_ref().to_vec(), // Use as_ref() to get &[u8] slice
        };
        Ok(KeyPair {
            public_key,
            secret_key,
        })
    } else {
        // PQC key generation requires specific random data length
        if random_data.len() < 128 {
            return Err(PqcError::InsufficientData);
        }

        unsafe {
            let mut keypair = bitcoin_pqc_keypair_t {
                algorithm: algorithm.into(),
                public_key: ptr::null_mut(),
                secret_key: ptr::null_mut(),
                public_key_size: 0,
                secret_key_size: 0,
            };

            let result = bitcoin_pqc_keygen(
                algorithm.into(),
                &mut keypair,
                random_data.as_ptr(),
                random_data.len(),
            );

            if result != bitcoin_pqc_error_t::BITCOIN_PQC_OK {
                // Free potentially allocated (but invalid) memory on error
                bitcoin_pqc_keypair_free(&mut keypair);
                return Err(match result {
                    bitcoin_pqc_error_t::BITCOIN_PQC_ERROR_BAD_ARG => PqcError::BadArgument,
                    bitcoin_pqc_error_t::BITCOIN_PQC_ERROR_BAD_KEY => PqcError::BadKey,
                    bitcoin_pqc_error_t::BITCOIN_PQC_ERROR_NOT_IMPLEMENTED => {
                        PqcError::NotImplemented
                    }
                    _ => PqcError::Other(result.0 as i32),
                });
            }

            // Extract and copy the keys
            let pk_slice = std::slice::from_raw_parts(
                keypair.public_key as *const u8,
                keypair.public_key_size,
            );
            let sk_slice = std::slice::from_raw_parts(
                keypair.secret_key as *const u8,
                keypair.secret_key_size,
            );

            let pk_bytes = pk_slice.to_vec();
            let sk_bytes = sk_slice.to_vec();

            // Free the C memory
            bitcoin_pqc_keypair_free(&mut keypair);

            // Construct the structs (validation is implicitly done by FFI success)
            let public_key = PublicKey {
                algorithm,
                bytes: pk_bytes,
            };
            let secret_key = SecretKey {
                algorithm,
                bytes: sk_bytes,
            };

            Ok(KeyPair {
                public_key,
                secret_key,
            })
        }
    }
}

/// Sign a message using the specified secret key
///
/// # Arguments
///
/// * `secret_key` - The secret key to sign with
/// * `message` - The message to sign.
///     - For PQC algorithms, this is the raw message.
///     - For `SECP256K1_SCHNORR`, this *must* be a 32-byte hash of the message.
///
/// # Returns
///
/// A signature on success, or an error
pub fn sign(secret_key: &SecretKey, message: &[u8]) -> Result<Signature, PqcError> {
    match secret_key.algorithm {
        Algorithm::SECP256K1_SCHNORR => {
            // For Secp256k1, message must be a 32-byte hash
            let required_size = 32;

            // Check if message is too short
            if message.len() < required_size {
                return Err(PqcError::InsufficientData);
            }

            // Use only the first 32 bytes if message is longer
            let msg_data = &message[..required_size];

            let secp = Secp256k1::<All>::new(); // Signing context

            // Parse secret key
            let sk = secret_key.secp256k1_key()?;

            // Create Keypair
            let keypair = SecpKeypair::from_secret_key(&secp, &sk);

            // Sign using sign_schnorr_no_aux_rand with the (potentially truncated) message slice
            let schnorr_sig = secp.sign_schnorr_no_aux_rand(msg_data, &keypair);

            // Construct result Signature
            Ok(Signature {
                algorithm: Algorithm::SECP256K1_SCHNORR,
                bytes: schnorr_sig.as_ref().to_vec(),
            })
        }
        pqc_alg => {
            // PQC Signing logic using FFI
            unsafe {
                let mut signature = bitcoin_pqc_signature_t {
                    algorithm: pqc_alg.into(),
                    signature: ptr::null_mut(),
                    signature_size: 0,
                };

                let result = bitcoin_pqc_sign(
                    pqc_alg.into(),
                    secret_key.bytes.as_ptr(),
                    secret_key.bytes.len(),
                    message.as_ptr(),
                    message.len(),
                    &mut signature,
                );

                if result != bitcoin_pqc_error_t::BITCOIN_PQC_OK {
                    return Err(match result {
                        bitcoin_pqc_error_t::BITCOIN_PQC_ERROR_BAD_ARG => PqcError::BadArgument,
                        bitcoin_pqc_error_t::BITCOIN_PQC_ERROR_BAD_KEY => PqcError::BadKey,
                        bitcoin_pqc_error_t::BITCOIN_PQC_ERROR_BAD_SIGNATURE => {
                            PqcError::BadSignature
                        }
                        bitcoin_pqc_error_t::BITCOIN_PQC_ERROR_NOT_IMPLEMENTED => {
                            PqcError::NotImplemented
                        }
                        _ => PqcError::Other(result.0 as i32),
                    });
                }

                let sig_slice = std::slice::from_raw_parts(
                    signature.signature as *const u8,
                    signature.signature_size,
                );
                let sig_bytes = sig_slice.to_vec();

                bitcoin_pqc_signature_free(&mut signature);

                Ok(Signature {
                    algorithm: pqc_alg,
                    bytes: sig_bytes,
                })
            }
        }
    }
}

/// Verify a signature using the specified public key
///
/// # Arguments
///
/// * `public_key` - The public key to verify with
/// * `message` - The message that was signed (assumed to be pre-hashed for Secp256k1)
/// * `signature` - The signature to verify
///
/// # Returns
///
/// Ok(()) if the signature is valid, an error otherwise
pub fn verify(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), PqcError> {
    // Ensure the key and signature algorithms match
    if public_key.algorithm != signature.algorithm {
        return Err(PqcError::AlgorithmMismatch);
    }

    match public_key.algorithm {
        Algorithm::SECP256K1_SCHNORR => {
            // For Secp256k1, message must be a 32-byte hash
            let required_size = 32;

            // Check if message is too short
            if message.len() < required_size {
                return Err(PqcError::InsufficientData);
            }

            // Use only the first 32 bytes if message is longer
            let msg_data = &message[..required_size];

            // Use secp256k1 library for verification
            let secp = Secp256k1::<secp256k1::VerifyOnly>::verification_only();
            let pk = public_key.secp256k1_key()?;
            let sig = signature.secp256k1_signature()?;

            // Verify using verify_schnorr with the (potentially truncated) message slice
            secp.verify_schnorr(&sig, msg_data, &pk)
                .map_err(PqcError::Secp256k1Error)
        }
        pqc_alg => {
            // Length check for public key (still useful)
            if public_key.bytes.len() != public_key_size(pqc_alg) {
                return Err(PqcError::BadKey);
            }

            // NOTE: We do NOT check the signature length here against signature_size(pqc_alg)
            // because some algorithms like FN-DSA have variable signature lengths.
            // The C library's verify function should handle invalid lengths internally.

            // PQC Verification logic using FFI
            unsafe {
                let result = bitcoin_pqc_verify(
                    pqc_alg.into(),
                    public_key.bytes.as_ptr(),
                    public_key.bytes.len(),
                    message.as_ptr(),
                    message.len(),
                    signature.bytes.as_ptr(),
                    signature.bytes.len(),
                );
                result.into() // Converts C error enum to Result<(), PqcError>
            }
        }
    }
}

/// Get the public key size for an algorithm
///
/// # Arguments
///
/// * `algorithm` - The algorithm to get the size for
///
/// # Returns
///
/// The size in bytes
pub fn public_key_size(algorithm: Algorithm) -> usize {
    if algorithm == Algorithm::SECP256K1_SCHNORR {
        32 // XOnlyPublicKey size
    } else {
        unsafe { bitcoin_pqc_public_key_size(algorithm.into()) }
    }
}

/// Get the secret key size for an algorithm
///
/// # Arguments
///
/// * `algorithm` - The algorithm to get the size for
///
/// # Returns
///
/// The size in bytes
pub fn secret_key_size(algorithm: Algorithm) -> usize {
    if algorithm == Algorithm::SECP256K1_SCHNORR {
        32 // secp256k1::SecretKey size
    } else {
        unsafe { bitcoin_pqc_secret_key_size(algorithm.into()) }
    }
}

/// Get the signature size for an algorithm
///
/// # Arguments
///
/// * `algorithm` - The algorithm to get the size for
///
/// # Returns
///
/// The size in bytes
pub fn signature_size(algorithm: Algorithm) -> usize {
    if algorithm == Algorithm::SECP256K1_SCHNORR {
        64 // schnorr::Signature size
    } else {
        unsafe { bitcoin_pqc_signature_size(algorithm.into()) }
    }
}
