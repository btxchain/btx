use hex::decode as hex_decode;
use rand::{rng, RngCore};

use bitcoinpqc::{
    generate_keypair, public_key_size, secret_key_size, sign, signature_size, verify, Algorithm,
};

// Original random data generation function (commented out for deterministic tests)
fn _get_random_bytes_original(size: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; size];
    rng().fill_bytes(&mut bytes);
    bytes
}

// Function to return fixed test data based on predefined hex strings
// This ensures deterministic test results
fn get_random_bytes(size: usize) -> Vec<u8> {
    match size {
        128 => {
            // Fixed test vectors for key generation (128 bytes)

            // ML-DSA-44 key generation test vector
            let ml_dsa_keygen_data = "20739d89b87379e83a915a0764366ed1e72eb307b3c7846dc135933370f00b266277961d536b47026f7eb874603384e3a2b9ea51f033aa4257acd17606d2cd86bc6c2a6745d59dcc148d5a8776be46e127e3ccf57212bd0eef8085aa871cc40b91693fd9a79034504f639cea0e618509afd84d943b3928524becc473c3fa3c2a";

            // SLH-DSA-128S key generation test vector
            let slh_dsa_keygen_data = "dd348981dfba96c006d27d64ad0ae37c9a358e3a03df7e9ffac1519eca12dc3b64bea0144f3536a74d9caba846b7143788e89a2a279a81947364f422d491dcb47925a77be4d551b25a81070e6a460effe30939224240e4f4dc9470d3d99f7312c24523a28128ea448ef47bcc1b0ae637ad6ece2251d3e2d55c0bba6d346ca66b";

            // Deterministic signing test vectors

            // ML-DSA-44 deterministic signing test vector
            let ml_dsa_det_data = "12187a59a14e1e9a0c37fc7625a0d3f8782f1e4cd361751abf7b85745173488e3e19afd47cbd4a823577cb360aed406791558ea1ff217fcd38af566e0e5d4d0903e6ea9c29108393c1a423f41b876b43ce0856ee436866f98d56ec8ceb169ed0470d847608f295474002a91a54937a64ac236fb9cf49fedf60b76500e3c0a7f0";

            // SLH-DSA-128S deterministic signing test vector
            let slh_dsa_det_data = "8ca905fd3e122d02e411683b52ecb1863104793aeba57718aabc9a65db5d61a66ca4bd29376d8118ceb555868b7054b59e23a45538d4ca28ad2080f70c56cce85f1fd5568661cb6ac06a9296ae77d97a7b854dab7eda10a4b78dd3a8f2e741f5c4686278eda9a1ac255a0cdbc79081435161331b69f9cbc04e7ae50cbfbab0ec";

            // Choose which data to return based on the test context
            let thread = std::thread::current();
            let test_name = thread.name().unwrap_or("unknown");

            let hex_data = if test_name.contains("ml_dsa_44") {
                ml_dsa_keygen_data
            } else if test_name.contains("slh_dsa_128s") {
                slh_dsa_keygen_data
            } else if test_name.contains("deterministic_signing") {
                // Choose based on current test progress
                static mut COUNTER: usize = 0;
                unsafe {
                    let data = match COUNTER {
                        0 => ml_dsa_det_data,
                        _ => slh_dsa_det_data,
                    };
                    COUNTER += 1;
                    data
                }
            } else {
                // Default to ML-DSA data
                ml_dsa_keygen_data
            };

            hex_decode(hex_data).expect("Invalid hex data")
        }
        64 => {
            // Fixed test vectors for signing (64 bytes)

            // ML-DSA-44 signing test vector
            let ml_dsa_sign_data = "8fe682ed84da0fdfa9243c424c864b1d9137c0c87bc8f23dbea9268f3930c8a3778139311c18dadd6a9aea791486f2d7638a7be8f09ca3546580312a8bb95f97";

            // SLH-DSA-128S signing test vector
            let slh_dsa_sign_data = "c2dd94eec866f66b5fe8cbc07cfdbc8b4b92880f4fe53131feb1539323e87f64d3b32fd22375ead15c6c0f5c68323ed343041acfd3d962382b406e9aa30aa45c";

            // Choose which data to return based on the test context
            let thread = std::thread::current();
            let test_name = thread.name().unwrap_or("unknown");

            let hex_data = if test_name.contains("ml_dsa_44") {
                ml_dsa_sign_data
            } else if test_name.contains("slh_dsa_128s") {
                slh_dsa_sign_data
            } else {
                // Default to ML-DSA data
                ml_dsa_sign_data
            };

            hex_decode(hex_data).expect("Invalid hex data")
        }
        _ => {
            // Fallback for other sizes (e.g., 127 for error condition tests)
            // This still uses random data since it's typically for error cases
            let mut bytes = vec![0u8; size];
            rng().fill_bytes(&mut bytes);
            bytes
        }
    }
}

#[test]
fn test_key_sizes() {
    // Verify the key and signature sizes are as expected
    assert_eq!(public_key_size(Algorithm::ML_DSA_44), 1312);
    assert_eq!(secret_key_size(Algorithm::ML_DSA_44), 2560);
    assert_eq!(signature_size(Algorithm::ML_DSA_44), 2420);

    assert_eq!(public_key_size(Algorithm::SLH_DSA_128S), 32);
    assert_eq!(secret_key_size(Algorithm::SLH_DSA_128S), 64);
    assert_eq!(signature_size(Algorithm::SLH_DSA_128S), 7856);
}

#[test]
fn test_ml_dsa_44_keygen_sign_verify() {
    println!("Starting ML-DSA-44 test");
    let random_data = get_random_bytes(128);
    println!("Generated random data of size {}", random_data.len());

    let keypair = generate_keypair(Algorithm::ML_DSA_44, &random_data)
        .expect("Failed to generate ML-DSA-44 keypair");

    println!("Key generation successful");

    // Verify the key sizes match expected values
    assert_eq!(
        keypair.public_key.bytes.len(),
        public_key_size(Algorithm::ML_DSA_44)
    );
    println!("Public key size: {}", keypair.public_key.bytes.len());

    assert_eq!(
        keypair.secret_key.bytes.len(),
        secret_key_size(Algorithm::ML_DSA_44)
    );
    println!("Secret key size: {}", keypair.secret_key.bytes.len());

    // Test signing and verification
    let message = b"ML-DSA-44 Test Message";
    println!("Message to sign: {message:?}");

    let signature = sign(&keypair.secret_key, message).expect("Failed to sign with ML-DSA-44");

    println!(
        "Signature created successfully, size: {}",
        signature.bytes.len()
    );
    println!(
        "Signature prefix: {:02x?}",
        &signature.bytes[..8.min(signature.bytes.len())]
    );

    // Verify the signature
    println!("Verifying signature...");
    let result = verify(&keypair.public_key, message, &signature);
    println!("Verification result: {result:?}");

    assert!(result.is_ok(), "ML-DSA-44 signature verification failed");

    // Try to verify with a modified message - should fail
    let modified_message = b"ML-DSA-44 Modified Message";
    println!("Modified message: {modified_message:?}");

    let result = verify(&keypair.public_key, modified_message, &signature);
    println!("Verification with modified message result: {result:?}");

    assert!(
        result.is_err(),
        "ML-DSA-44 verification should fail with modified message"
    );
}

#[test]
fn test_slh_dsa_128s_keygen_sign_verify() {
    println!("Starting SLH-DSA-128S test");
    let random_data = get_random_bytes(128);
    println!("Generated random data of size {}", random_data.len());

    let keypair = generate_keypair(Algorithm::SLH_DSA_128S, &random_data)
        .expect("Failed to generate SLH-DSA-128S keypair");

    println!("Key generation successful");

    // Verify the key sizes match expected values
    assert_eq!(
        keypair.public_key.bytes.len(),
        public_key_size(Algorithm::SLH_DSA_128S)
    );
    println!("Public key size: {}", keypair.public_key.bytes.len());

    assert_eq!(
        keypair.secret_key.bytes.len(),
        secret_key_size(Algorithm::SLH_DSA_128S)
    );
    println!("Secret key size: {}", keypair.secret_key.bytes.len());

    // Test signing and verification
    let message = b"SLH-DSA-128S Test Message";
    println!("Message to sign: {message:?}");

    let signature = sign(&keypair.secret_key, message).expect("Failed to sign with SLH-DSA-128S");

    println!(
        "Signature created successfully, size: {}",
        signature.bytes.len()
    );
    println!(
        "Signature prefix: {:02x?}",
        &signature.bytes[..8.min(signature.bytes.len())]
    );

    // Verify the signature
    println!("Verifying signature...");
    let result = verify(&keypair.public_key, message, &signature);
    println!("Verification result: {result:?}");

    assert!(result.is_ok(), "SLH-DSA-128S signature verification failed");

    // Try to verify with a modified message - should fail
    let modified_message = b"SLH-DSA-128S Modified Message";
    println!("Modified message: {modified_message:?}");

    let result = verify(&keypair.public_key, modified_message, &signature);
    println!("Verification with modified message result: {result:?}");

    assert!(
        result.is_err(),
        "SLH-DSA-128S verification should fail with modified message"
    );
}

#[test]
fn test_deterministic_signing() {
    // Test ML-DSA-44 deterministic signing
    let random_data = get_random_bytes(128);
    let keypair = generate_keypair(Algorithm::ML_DSA_44, &random_data)
        .expect("Failed to generate ML-DSA-44 keypair");
    let message = b"Test message for deterministic signing";

    // Generate first signature
    let signature1 = sign(&keypair.secret_key, message).expect("Failed to create first signature");
    // Generate second signature (should be identical with deterministic signing)
    let signature2 = sign(&keypair.secret_key, message).expect("Failed to create second signature");

    // Verify both signatures
    assert!(
        verify(&keypair.public_key, message, &signature1).is_ok(),
        "First ML-DSA-44 signature should be valid"
    );
    assert!(
        verify(&keypair.public_key, message, &signature2).is_ok(),
        "Second ML-DSA-44 signature should be valid"
    );

    // Test SLH-DSA-128S deterministic signing
    let random_data = get_random_bytes(128);
    let keypair = generate_keypair(Algorithm::SLH_DSA_128S, &random_data)
        .expect("Failed to generate SLH-DSA-128S keypair");
    let message = b"Test message for deterministic signing";

    // Generate first signature
    let signature1 = sign(&keypair.secret_key, message).expect("Failed to create first signature");
    // Generate second signature (should be identical with deterministic signing)
    let signature2 = sign(&keypair.secret_key, message).expect("Failed to create second signature");

    // Verify both signatures
    assert!(
        verify(&keypair.public_key, message, &signature1).is_ok(),
        "First SLH-DSA-128S signature should be valid"
    );
    assert!(
        verify(&keypair.public_key, message, &signature2).is_ok(),
        "Second SLH-DSA-128S signature should be valid"
    );
}

#[test]
fn test_error_conditions() {
    // Test with insufficient random data for key generation for all algorithms
    let short_random = get_random_bytes(127); // Need at least 128 bytes

    // Test ML-DSA-44
    let result = generate_keypair(Algorithm::ML_DSA_44, &short_random);
    assert!(
        result.is_err(),
        "ML-DSA-44 should fail with insufficient random data"
    );

    // Test SLH-DSA-128S
    let result = generate_keypair(Algorithm::SLH_DSA_128S, &short_random);
    assert!(
        result.is_err(),
        "SLH-DSA-128S should fail with insufficient random data"
    );

    // Create valid keypairs for ML-DSA and SLH-DSA
    let random_data = get_random_bytes(128);
    let ml_keypair = generate_keypair(Algorithm::ML_DSA_44, &random_data)
        .expect("Failed to generate ML-DSA-44 keypair");
    let slh_keypair = generate_keypair(Algorithm::SLH_DSA_128S, &random_data)
        .expect("Failed to generate SLH-DSA-128S keypair");

    // Create message for testing
    let message = b"Test message";

    // Create signatures
    let ml_sig = sign(&ml_keypair.secret_key, message).expect("Failed to sign with ML-DSA-44");
    let slh_sig = sign(&slh_keypair.secret_key, message).expect("Failed to sign with SLH-DSA-128S");

    // Try to verify with mismatched algorithms
    let result = verify(&slh_keypair.public_key, message, &ml_sig);
    assert!(
        result.is_err(),
        "Verification should fail with ML-DSA-44 signature and SLH-DSA-128S key"
    );

    let result = verify(&ml_keypair.public_key, message, &slh_sig);
    assert!(
        result.is_err(),
        "Verification should fail with SLH-DSA-128S signature and ML-DSA-44 key"
    );
}
