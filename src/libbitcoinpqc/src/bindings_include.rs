// This file exists to solve the problem with OUT_DIR not being
// available in the IDE but required for builds.
// The build script always generates bindings.rs in the OUT_DIR.

// When compiling for real, include the real bindings
#[cfg(all(not(feature = "ide"), not(doc)))]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// For documentation, we need stubs to make doctests work
#[cfg(doc)]
pub mod doc_bindings {
    // Define the essential types needed for documentation
    #[repr(C)]
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub struct bitcoin_pqc_algorithm_t(pub u32);

    impl bitcoin_pqc_algorithm_t {
        pub const BITCOIN_PQC_SECP256K1_SCHNORR: bitcoin_pqc_algorithm_t =
            bitcoin_pqc_algorithm_t(0);
        pub const BITCOIN_PQC_ML_DSA_44: bitcoin_pqc_algorithm_t = bitcoin_pqc_algorithm_t(1);
        pub const BITCOIN_PQC_SLH_DSA_SHAKE_128S: bitcoin_pqc_algorithm_t =
            bitcoin_pqc_algorithm_t(2);
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub struct bitcoin_pqc_error_t(pub i32);

    impl bitcoin_pqc_error_t {
        pub const BITCOIN_PQC_OK: bitcoin_pqc_error_t = bitcoin_pqc_error_t(0);
        pub const BITCOIN_PQC_ERROR_BAD_ARG: bitcoin_pqc_error_t = bitcoin_pqc_error_t(-1);
        pub const BITCOIN_PQC_ERROR_BAD_KEY: bitcoin_pqc_error_t = bitcoin_pqc_error_t(-2);
        pub const BITCOIN_PQC_ERROR_BAD_SIGNATURE: bitcoin_pqc_error_t = bitcoin_pqc_error_t(-3);
        pub const BITCOIN_PQC_ERROR_NOT_IMPLEMENTED: bitcoin_pqc_error_t = bitcoin_pqc_error_t(-4);
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct bitcoin_pqc_keypair_t {
        pub algorithm: bitcoin_pqc_algorithm_t,
        pub public_key: *mut ::std::os::raw::c_uchar,
        pub secret_key: *mut ::std::os::raw::c_uchar,
        pub public_key_size: usize,
        pub secret_key_size: usize,
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct bitcoin_pqc_signature_t {
        pub algorithm: bitcoin_pqc_algorithm_t,
        pub signature: *mut ::std::os::raw::c_uchar,
        pub signature_size: usize,
    }

    // Dummy function declarations
    pub unsafe fn bitcoin_pqc_keygen(
        _algorithm: bitcoin_pqc_algorithm_t,
        _keypair: *mut bitcoin_pqc_keypair_t,
        _random_data: *const ::std::os::raw::c_uchar,
        _random_data_len: usize,
    ) -> bitcoin_pqc_error_t {
        unimplemented!("This is a doc stub")
    }

    pub unsafe fn bitcoin_pqc_keypair_free(_keypair: *mut bitcoin_pqc_keypair_t) {}

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn bitcoin_pqc_sign(
        _algorithm: bitcoin_pqc_algorithm_t,
        _secret_key: *const ::std::os::raw::c_uchar,
        _secret_key_len: usize,
        _message: *const ::std::os::raw::c_uchar,
        _message_len: usize,
        _signature: *mut bitcoin_pqc_signature_t,
    ) -> bitcoin_pqc_error_t {
        unimplemented!("This is a doc stub")
    }

    pub unsafe fn bitcoin_pqc_verify(
        _algorithm: bitcoin_pqc_algorithm_t,
        _public_key: *const ::std::os::raw::c_uchar,
        _public_key_len: usize,
        _message: *const ::std::os::raw::c_uchar,
        _message_len: usize,
        _signature: *const ::std::os::raw::c_uchar,
        _signature_len: usize,
    ) -> bitcoin_pqc_error_t {
        unimplemented!("This is a doc stub")
    }

    pub unsafe fn bitcoin_pqc_signature_free(_signature: *mut bitcoin_pqc_signature_t) {}

    pub unsafe fn bitcoin_pqc_public_key_size(_algorithm: bitcoin_pqc_algorithm_t) -> usize {
        0
    }

    pub unsafe fn bitcoin_pqc_secret_key_size(_algorithm: bitcoin_pqc_algorithm_t) -> usize {
        0
    }

    pub unsafe fn bitcoin_pqc_signature_size(_algorithm: bitcoin_pqc_algorithm_t) -> usize {
        0
    }
}

// For IDE support - similar stubs but are never compiled for release
#[cfg(feature = "ide")]
pub mod ide_bindings {
    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct bitcoin_pqc_keypair_t {
        pub algorithm: bitcoin_pqc_algorithm_t,
        pub public_key: *mut ::std::os::raw::c_uchar,
        pub secret_key: *mut ::std::os::raw::c_uchar,
        pub public_key_size: usize,
        pub secret_key_size: usize,
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct bitcoin_pqc_signature_t {
        pub algorithm: bitcoin_pqc_algorithm_t,
        pub signature: *mut ::std::os::raw::c_uchar,
        pub signature_size: usize,
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub struct bitcoin_pqc_algorithm_t(pub u32);

    impl bitcoin_pqc_algorithm_t {
        pub const BITCOIN_PQC_SECP256K1_SCHNORR: bitcoin_pqc_algorithm_t =
            bitcoin_pqc_algorithm_t(0);
        pub const BITCOIN_PQC_ML_DSA_44: bitcoin_pqc_algorithm_t = bitcoin_pqc_algorithm_t(1);
        pub const BITCOIN_PQC_SLH_DSA_SHAKE_128S: bitcoin_pqc_algorithm_t =
            bitcoin_pqc_algorithm_t(2);
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub struct bitcoin_pqc_error_t(pub i32);

    impl bitcoin_pqc_error_t {
        pub const BITCOIN_PQC_OK: bitcoin_pqc_error_t = bitcoin_pqc_error_t(0);
        pub const BITCOIN_PQC_ERROR_BAD_ARG: bitcoin_pqc_error_t = bitcoin_pqc_error_t(-1);
        pub const BITCOIN_PQC_ERROR_BAD_KEY: bitcoin_pqc_error_t = bitcoin_pqc_error_t(-2);
        pub const BITCOIN_PQC_ERROR_BAD_SIGNATURE: bitcoin_pqc_error_t = bitcoin_pqc_error_t(-3);
        pub const BITCOIN_PQC_ERROR_NOT_IMPLEMENTED: bitcoin_pqc_error_t = bitcoin_pqc_error_t(-4);
    }

    // Function declarations for IDE support
    pub unsafe fn bitcoin_pqc_keygen(
        _algorithm: bitcoin_pqc_algorithm_t,
        _keypair: *mut bitcoin_pqc_keypair_t,
        _random_data: *const ::std::os::raw::c_uchar,
        _random_data_len: usize,
    ) -> bitcoin_pqc_error_t {
        unimplemented!("This is an IDE stub")
    }

    pub unsafe fn bitcoin_pqc_keypair_free(_keypair: *mut bitcoin_pqc_keypair_t) {}

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn bitcoin_pqc_sign(
        _algorithm: bitcoin_pqc_algorithm_t,
        _secret_key: *const ::std::os::raw::c_uchar,
        _secret_key_len: usize,
        _message: *const ::std::os::raw::c_uchar,
        _message_len: usize,
        _signature: *mut bitcoin_pqc_signature_t,
    ) -> bitcoin_pqc_error_t {
        unimplemented!("This is an IDE stub")
    }

    pub unsafe fn bitcoin_pqc_verify(
        _algorithm: bitcoin_pqc_algorithm_t,
        _public_key: *const ::std::os::raw::c_uchar,
        _public_key_len: usize,
        _message: *const ::std::os::raw::c_uchar,
        _message_len: usize,
        _signature: *const ::std::os::raw::c_uchar,
        _signature_len: usize,
    ) -> bitcoin_pqc_error_t {
        unimplemented!("This is an IDE stub")
    }

    pub unsafe fn bitcoin_pqc_signature_free(_signature: *mut bitcoin_pqc_signature_t) {}

    pub unsafe fn bitcoin_pqc_public_key_size(_algorithm: bitcoin_pqc_algorithm_t) -> usize {
        0
    }

    pub unsafe fn bitcoin_pqc_secret_key_size(_algorithm: bitcoin_pqc_algorithm_t) -> usize {
        0
    }

    pub unsafe fn bitcoin_pqc_signature_size(_algorithm: bitcoin_pqc_algorithm_t) -> usize {
        0
    }
}

// Re-export the right set of bindings based on configuration
#[cfg(doc)]
pub use doc_bindings::*;

#[cfg(feature = "ide")]
pub use ide_bindings::*;
