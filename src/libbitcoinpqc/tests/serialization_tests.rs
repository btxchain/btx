use hex::{decode as hex_decode, encode as hex_encode};
use rand::{rng, RngCore};

use bitcoinpqc::{generate_keypair, sign, verify, Algorithm, PublicKey, SecretKey, Signature};

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
            // Single common test vector for all tests (128 bytes)
            let random_data = "f47e7324fb639d867a35eea3558a54224e7ca5e357c588c136d2d514facd5fc0d93a31a624a7c3d9ba02f8a73bd2e9dac7b2e3a0dcf1900b2c3b8e56c6efec7ef2aa654567e42988f6c1b71ae817db8f7dbf25c5e7f3ddc87f39b8fc9b3c44caacb6fe8f9df68e895f6ae603e1c4db3c6a0e1ba9d52ac34a63426f9be2e2ac16";
            hex_decode(random_data).expect("Invalid hex data")
        }
        64 => {
            // Fixed test vector for signing (64 bytes)
            let sign_data = "7b8681d6e06fa65ef3b77243e7670c10e7c983cbe07f09cb1ddd10e9c4bc8ae6409a756b5bc35a352ab7dcf08395ce6994f4aafa581a843db147db47cf2e6fbd";
            hex_decode(sign_data).expect("Invalid hex data")
        }
        _ => {
            // Fallback for other sizes
            let mut bytes = vec![0u8; size];
            rng().fill_bytes(&mut bytes);
            bytes
        }
    }
}

#[test]
fn test_public_key_serialization() {
    // Generate a keypair with deterministic data
    let random_data = get_random_bytes(128);
    let keypair =
        generate_keypair(Algorithm::ML_DSA_44, &random_data).expect("Failed to generate keypair");

    // Print public key prefix for informational purposes
    let pk_prefix = hex_encode(&keypair.public_key.bytes[0..16]);
    println!("ML-DSA-44 Public key prefix: {pk_prefix}");

    // Check the public key has the expected length
    assert_eq!(
        keypair.public_key.bytes.len(),
        1312,
        "Public key should have the correct length"
    );

    // Check the public key has a non-empty prefix
    assert!(
        !pk_prefix.is_empty(),
        "Public key should have a non-empty prefix"
    );

    // Extract the public key bytes
    let pk_bytes = keypair.public_key.bytes.clone();

    // Create a new PublicKey from the bytes
    let reconstructed_pk = PublicKey {
        algorithm: Algorithm::ML_DSA_44,
        bytes: pk_bytes,
    };

    // Sign a message using the original key
    let message = b"Serialization test message";
    let signature = sign(&keypair.secret_key, message).expect("Failed to sign message");

    // Print signature for informational purposes
    println!(
        "ML-DSA-44 Signature prefix: {}",
        hex_encode(&signature.bytes[0..16])
    );

    // Verify the signature using the reconstructed public key
    let result = verify(&reconstructed_pk, message, &signature);
    assert!(
        result.is_ok(),
        "Verification with reconstructed public key failed"
    );
}

#[test]
fn test_secret_key_serialization() {
    // Generate a keypair with deterministic data
    let random_data = get_random_bytes(128);
    let keypair = generate_keypair(Algorithm::SLH_DSA_128S, &random_data)
        .expect("Failed to generate keypair");

    // Print key prefixes for diagnostic purposes
    let sk_prefix = hex_encode(&keypair.secret_key.bytes[0..16]);
    let pk_prefix = hex_encode(&keypair.public_key.bytes[0..16]);
    println!("SLH-DSA-128S Secret key prefix: {sk_prefix}");
    println!("SLH-DSA-128S Public key prefix: {pk_prefix}");

    // Extract the secret key bytes
    let sk_bytes = keypair.secret_key.bytes.clone();

    // Create a new SecretKey from the bytes
    let reconstructed_sk = SecretKey {
        algorithm: Algorithm::SLH_DSA_128S,
        bytes: sk_bytes,
    };

    // Sign a message using the reconstructed secret key
    let message = b"Secret key serialization test message";
    let signature =
        sign(&reconstructed_sk, message).expect("Failed to sign with reconstructed key");

    // Print signature for informational purposes
    println!(
        "SLH-DSA-128S Signature prefix: {}",
        hex_encode(&signature.bytes[0..16])
    );

    // Verify the signature using the original public key
    let result = verify(&keypair.public_key, message, &signature);
    assert!(
        result.is_ok(),
        "Verification of signature from reconstructed secret key failed"
    );
}

#[test]
fn test_signature_serialization() {
    // Generate a keypair with deterministic data
    let random_data = get_random_bytes(128);
    let keypair =
        generate_keypair(Algorithm::ML_DSA_44, &random_data).expect("Failed to generate keypair");

    // Sign a message
    let message = b"Signature serialization test";
    let signature = sign(&keypair.secret_key, message).expect("Failed to sign message");

    // Print signature for informational purposes
    println!(
        "ML-DSA-44 Signature prefix: {}",
        hex_encode(&signature.bytes[0..16])
    );

    // Create a new Signature from the bytes
    let reconstructed_sig = Signature {
        algorithm: Algorithm::ML_DSA_44,
        bytes: signature.bytes.clone(),
    };

    // Verify that the reconstructed signature bytes match
    assert_eq!(
        signature.bytes, reconstructed_sig.bytes,
        "Reconstructed signature bytes should match original"
    );

    // Verify the reconstructed signature
    let result = verify(&keypair.public_key, message, &reconstructed_sig);
    assert!(
        result.is_ok(),
        "Verification with reconstructed signature failed"
    );
}

#[test]
fn test_cross_algorithm_serialization_failure() {
    // Generate keypairs for different algorithms with deterministic data
    let random_data = get_random_bytes(128);
    let keypair_ml_dsa = generate_keypair(Algorithm::ML_DSA_44, &random_data)
        .expect("Failed to generate ML-DSA keypair");
    let keypair_slh_dsa = generate_keypair(Algorithm::SLH_DSA_128S, &random_data)
        .expect("Failed to generate SLH-DSA keypair");

    // Sign with ML-DSA
    let message = b"Cross algorithm test";
    let signature = sign(&keypair_ml_dsa.secret_key, message).expect("Failed to sign message");

    // Print signature for informational purposes
    println!(
        "ML-DSA signature prefix: {}",
        hex_encode(&signature.bytes[0..16])
    );

    // Attempt to verify ML-DSA signature with SLH-DSA public key
    // This should fail because the algorithms don't match
    let result = verify(&keypair_slh_dsa.public_key, message, &signature);
    assert!(
        result.is_err(),
        "Verification should fail when using public key from different algorithm"
    );

    // Create an invalid signature by changing the algorithm but keeping the bytes
    let invalid_sig = Signature {
        algorithm: Algorithm::SLH_DSA_128S, // Wrong algorithm
        bytes: signature.bytes.clone(),
    };

    // This should fail because the signature was generated with ML-DSA but claimed to be SLH-DSA
    let result = verify(&keypair_slh_dsa.public_key, message, &invalid_sig);
    assert!(
        result.is_err(),
        "Verification should fail with mismatched algorithm"
    );

    // Also verify that the library correctly checks algorithm consistency
    let result = verify(&keypair_ml_dsa.public_key, message, &invalid_sig);
    assert!(
        result.is_err(),
        "Verification should fail when signature algorithm doesn't match public key algorithm"
    );
}

// Add new test for serialization consistency
#[test]
fn test_serialization_consistency() {
    // Generate keypairs for each algorithm using deterministic data
    let random_data = get_random_bytes(128);

    // ML-DSA-44
    let ml_keypair = generate_keypair(Algorithm::ML_DSA_44, &random_data)
        .expect("Failed to generate ML-DSA keypair");

    // Expected ML-DSA key serialization (from test output)
    let expected_ml_pk_prefix = "b3f22d3e1f93e3122063898b98eb89e6";
    let expected_ml_sk_prefix = "b3f22d3e1f93e3122063898b98eb89e6";

    // Print and verify ML-DSA public key
    let actual_ml_pk_prefix = hex_encode(&ml_keypair.public_key.bytes[0..16]);
    println!("ML-DSA-44 public key prefix: {actual_ml_pk_prefix}");

    assert_eq!(
        actual_ml_pk_prefix, expected_ml_pk_prefix,
        "ML-DSA-44 public key serialization should be deterministic"
    );

    // Print and verify ML-DSA secret key
    let actual_ml_sk_prefix = hex_encode(&ml_keypair.secret_key.bytes[0..16]);
    println!("ML-DSA-44 secret key prefix: {actual_ml_sk_prefix}");

    assert_eq!(
        actual_ml_sk_prefix, expected_ml_sk_prefix,
        "ML-DSA-44 secret key serialization should be deterministic"
    );

    // SLH-DSA-128S - Just print for informational purposes
    let slh_keypair = generate_keypair(Algorithm::SLH_DSA_128S, &random_data)
        .expect("Failed to generate SLH-DSA keypair");

    println!(
        "SLH-DSA-128S public key prefix: {}",
        hex_encode(&slh_keypair.public_key.bytes[0..16])
    );
    println!(
        "SLH-DSA-128S secret key prefix: {}",
        hex_encode(&slh_keypair.secret_key.bytes[0..16])
    );

    // Test serialization/deserialization consistency
    let message = b"Serialization consistency test";

    // ML-DSA-44 signature consistency
    let ml_sig = sign(&ml_keypair.secret_key, message).expect("Failed to sign with ML-DSA-44");

    // Print ML-DSA signature for informational purposes
    println!(
        "ML-DSA-44 signature prefix: {}",
        hex_encode(&ml_sig.bytes[0..16])
    );

    // Verify keys generated with the same random data are consistent
    let new_ml_keypair = generate_keypair(Algorithm::ML_DSA_44, &random_data)
        .expect("Failed to generate second ML-DSA-44 keypair");

    assert_eq!(
        hex_encode(&ml_keypair.public_key.bytes),
        hex_encode(&new_ml_keypair.public_key.bytes),
        "ML-DSA-44 public key generation should be deterministic"
    );

    assert_eq!(
        hex_encode(&ml_keypair.secret_key.bytes),
        hex_encode(&new_ml_keypair.secret_key.bytes),
        "ML-DSA-44 secret key generation should be deterministic"
    );
}

// // Add new test for serde roundtrip serialization/deserialization
// #[cfg(feature = "serde")]
// #[test]
// fn test_serde_roundtrip() {
//     // Use deterministic random data
//     let random_data = get_random_bytes(128);
//     let message = b"Serde roundtrip test message";

//     // Test each algorithm
//     for algorithm in [Algorithm::ML_DSA_44, Algorithm::SLH_DSA_128S].iter() {
//         // Generate keypair
//         let keypair = generate_keypair(*algorithm, &random_data)
//             .unwrap_or_else(|_| panic!("Failed to generate keypair for {algorithm:?}"));

//         // Sign message
//         let signature = sign(&keypair.secret_key, message)
//             .unwrap_or_else(|_| panic!("Failed to sign message for {algorithm:?}"));

//         // --- PublicKey Test ---
//         let pk_json = serde_json::to_string_pretty(&keypair.public_key)
//             .expect("Failed to serialize PublicKey"); // Use pretty print for readability

//         // Define the expected fixture (UPDATE THIS STRING)
//         let expected_pk_json = match *algorithm {
//             Algorithm::ML_DSA_44 => {
//                 r#"{
//   "algorithm": "ML_DSA_44",
//   "bytes": "b3f22d3e1f93e3122063898b98eb89e65278d56bd6e81478d0f45dbd94640febdec294921bd45b3bea23bc1d0158e1e34daf4c82e734524d505d10fa6113285e726ac719246cc34d032fd1e16c85821597acd5452af5a87e5fc84d8c5f332c839c0cd9d48b1dfa47352976ad7835e36577fdb30126c28ce2d214584ee2dbc2ca8a40499c02442015268800312090890b331250b40ccc8869031210910411d1c4501b24121b060a8b126cc80265e0364294184d99c464cc2866d2326998486601894880b06d984891a0142119491104106c5384450a05625c100a2421508c021049944192b22da422681aa2049c002202478810134618113224983081c20c1a1500212191db984d0b488164868d61308804298421a630d4340a984449c0426002a690c04249031721821802901091843820d2b41010c529e02405e3342823164111099192800123161220c925029785181728e1c6891b883181c6655c488249b64009a07082802dc042692422310b804411142264203111456c1c308104220a4b16801b432401a169032832d98209531489e4123198c001449631a2486119924c1c258444008d4232860316642147060c272821b70021266ae3c67122b760102170109808a444294b900823b1704a8040d4188611b0091c24001218669a82419b0060d3c04cd9400dca4471221724003846981461c9962dd038401022851345729b304622b8044a0461d186651895805936698aa27091802c928000cc8811c94885003389098021994680a3a251942652c9426c9ac669d38890910661cb9270211300c41884e190400a1062e11841d2245160308e59064a94908899b83123956454c28801c060c4868d5a948850806004463199880852960c60208021b94519366d0189051b086624328d89c26da11865203428d8a45041b8896498711c450e621468024290c194301a990c5916711a05304112280027210b2741c4c289d39465c3365240c850e0c04114444a64203109884114a13154902844c88001c26493807193a49101c6082003266146529c28110c12024c4088c9b00d1ac08153464013a88010426c08890823271290b62091228a6418458ba0641c272acc8630e0486d0ca371d3868da0168e48a23062800580142189b268a2884d0c373214038090c4711b477258002e64026a1aa12d00c8245b98684844019a004149026d10a08d82840012b45102435221a32d5b908c648290939250023986081711212905dcc2619d5be95a339c1bc29c0538fe02924c096b7c7063deb34148fc2ac4297d5f2e85aea1ef57e1236204f75c6264559eb6f933df5b55302d09d6c6cb889fd44508a2122accc2b3cc2a0699147ec848a846c37c33f55dad55aff5de196966d3d01f71aca8fbb72c9d9018e0830a5eb3424bccae6288c13558faf85f1b8f095365a6c7d3b699f9a6332a377b12498df39a595fe1265eb04f10c81b826aed2a266bab5d2ce07020395961fd6358cbabde2264c6083cda237f13db7481d6100b46480bef4652c786871196fec4564a96ab056f8c15586b351391a6d808c9e7f4359a1499f8f07d99aad4e589a25be4e617ab70b39ba9eed53aaec3a4bc400e294d7eed7583489cd5cf6ae450fafe2db09098fd0a8ccc68e4d2b77064874501daf62757daf653365acfaca2df2280520f8374ac8d5e84b6a43f98f4afae4f84413c030ec7f21cf0e8a7d23b5d12654f7364460c5d8b4c75f790e3ba538c2e3f776b2769b794f45d1e1aac14febcb24eb335afac4154a73dd4435ebb9d5326d74dfaf349e44d88703c08748d6c850d4107990f0a18fecf2beebb88123894d489cbfe0c26fb88ca76a89ab233fec7a5cbb8566145c0a4a3a0d86f9e9689e5450f90d3a099870cea373243793ca3e5a92ff916f935fabacda0bf6bd8977b1bcf36f52f7812645e615f26e7df37c7278da16e8024d9027673f942fd7b8d738b525a629f1ba6ac66779db0bd8c90ab3903f7e9047f66b21dac94a9c335fe6aa78c6927663c0a74c89550bdc9d8201127984aa89ee2b80728be9b3f0d54a73172ba2ea4d1f7c4804af6998f8cd081d2e04b5448d2952749e09dae4354b893f26d355635d20764055e30459c613bb32fdb4ae074f545deafb3c532aac9559c8d3674cd132e4f854f1d9aab8c23bc94a0269a61b0f3d0b5ac3afb1ea35a45aca151ec63ec5bcc02ca647f2982c205549a2c8a5382ddd0c9e06ce545a18718a1bcea27623814bd3a8ce3b8ff8494f89cc32e05bd5749daa63b894685ce6906dfbfc411c2917d4b35fed903d8dc22a3056c28438c772c592d850a4d58becf2a286ed2e72f4ec13835236b3734367ea0b0f2eb38eff07c87d69fc4c7e86dd135459da3c96aa34400ca2db9eac2018a6a9c8d1339b6752023df35e1bb97b44555d194bae18232f68d2206fc35ba3754a33c91e82819c62ef864166910c7e40ed375647069d98fe7805e75e285a160a7950348304791208d4d82c5410ea019c39076ec36e8ed9a4d3eb87dac7eb3067b5776535301d2c622e7fa67a13d70cc4450c3093c5a47689e90a1b4178ccde8719baed1d3a2630078740a502977474b7025abdcb7998ec442d5aea31d6a8533aacff0111f935de36dfc6e266701d7c3778e7f4ebfa6f7ff9e6b1fab8962f30e5276b2a76f20acbf7087bd2d092dbf642843fa980f8a4b80ce730902c0e637f6c480f1f441ee731c9fa4d33258d00ff47be9b413eb176ac1cbc0c06edf67a59f9a996f9175327de3b829d1d830a638bf6056a87ec4150b440440a2ef9e5bafcdcedf4753ff11b1f2b00e52070f4984af34cefd224f36e6d04358418b05e52ed089dac28aac67c0e4d0ab79e4ee82377c9c4ceda877dcdc2fad48a88ae1fe4cc2582f1e41b5d557897902435a27a9bffc63357135c7e6e60516f56dccbd412afb250f117cbfa234619d75f199e397c587c523e4942728cd7d4d59aca9b52fa9364a7b81d9fd7c23e688b04bdaa986e21d7dbfcbfa634b8fcdfa2619d9b6904e3d8e3205bbf5a3d526c4bf9017723fa8944a0b08595e5252e361c5a353ae737177f043e9c2460f48a8aadbd342d773ad6e034191763d87e8c33a3a443cba0174f0bc49385b5a6ca75bb7c000888dcef43bc22252eac9710afb4a6c7a63b363d08e083e691aa848cad7bec731067a1a90a7803328aed4c987eb586461a523ab8fbda4829511f7a427940b94351966c8cb37dc22dd34a81c0542adeb97fff1f1460e72c575c9d18c571ae7175a9ce269fc570c0945484e6e5fca628b5bf0904bad7027e691f1fc8d740ed172fe8816b06b7a672d67faffa91affad41828204d5dbc10c68edbe911131c6f8993c054a2165675794bf6dd1b617a9e5fca0a1a884b21d236163c559be4daf02d5ed54034f735fb031bc17e95066ab3ac9120fd24e238e6255f5ae72fe81c0f9fb69979c746b893421842aa7641d50ff2b2506d078b0aeee703f08223be66255e62fa568a244ef8642eda22ca33472c07e3d8398fe12dae1dcb37dab68aca08a8aa439c4f2257910a0f46af5bcbdad3f987c17ac6c52703a04705ed920c69526fc748f366974706d19143cef2c3441ffa01e06"
// }"#
//             }
//             Algorithm::SLH_DSA_128S => {
//                 r#"{
//   "algorithm": "SLH_DSA_128S",
//   "bytes": "f47e7324fb639d867a35eea3558a54224e7ca5e357c588c136d2d514facd5fc0d93a31a624a7c3d9ba02f8a73bd2e9dad0261c237a3fa1df610b30f2a06bc750"
// }"#
//             }
//             _ => panic!("Fixture missing for algorithm {algorithm:?}"),
//         };

//         println!("Algorithm: {algorithm:?}, Generated PublicKey JSON:\n{pk_json}"); // Print generated JSON to help update fixtures
//         assert_eq!(
//             pk_json,
//             serde_json::to_string_pretty(
//                 &serde_json::from_str::<PublicKey>(expected_pk_json).unwrap()
//             )
//             .unwrap(), // Compare pretty formats
//             "PublicKey JSON does not match fixture for {algorithm:?}"
//         );

//         // Roundtrip check (still useful)
//         let reconstructed_pk: PublicKey =
//             serde_json::from_str(&pk_json).expect("Failed to deserialize PublicKey");
//         assert_eq!(
//             keypair.public_key, reconstructed_pk,
//             "PublicKey roundtrip failed for {algorithm:?}"
//         );

//         // --- SecretKey Test ---
//         let sk_json = serde_json::to_string_pretty(&keypair.secret_key)
//             .expect("Failed to serialize SecretKey");

//         // Define the expected fixture (UPDATE THIS STRING)
//         let expected_sk_json = match *algorithm {
//             Algorithm::ML_DSA_44 => {
//                 r#"{
//   "algorithm": "ML_DSA_44",
//   "bytes": "b3f22d3e1f93e3122063898b98eb89e65278d56bd6e81478d0f45dbd94640febdec294921bd45b3bea23bc1d0158e1e34daf4c82e734524d505d10fa6113285e726ac719246cc34d032fd1e16c85821597acd5452af5a87e5fc84d8c5f332c839c0cd9d48b1dfa47352976ad7835e36577fdb30126c28ce2d214584ee2dbc2ca8a40499c02442015268800312090890b331250b40ccc8869031210910411d1c4501b24121b060a8b126cc80265e0364294184d99c464cc2866d2326998486601894880b06d984891a0142119491104106c5384450a05625c100a2421508c021049944192b22da422681aa2049c002202478810134618113224983081c20c1a1500212191db984d0b488164868d61308804298421a630d4340a984449c0426002a690c04249031721821802901091843820d2b41010c529e02405e3342823164111099192800123161220c925029785181728e1c6891b883181c6655c488249b64009a07082802dc042692422310b804411142264203111456c1c308104220a4b16801b432401a169032832d98209531489e4123198c001449631a2486119924c1c258444008d4232860316642147060c272821b70021266ae3c67122b760102170109808a444294b900823b1704a8040d4188611b0091c24001218669a82419b0060d3c04cd9400dca4471221724003846981461c9962dd038401022851345729b304622b8044a0461d186651895805936698aa27091802c928000cc8811c94885003389098021994680a3a251942652c9426c9ac669d38890910661cb9270211300c41884e190400a1062e11841d2245160308e59064a94908899b83123956454c28801c060c4868d5a948850806004463199880852960c60208021b94519366d0189051b086624328d89c26da11865203428d8a45041b8896498711c450e621468024290c194301a990c5916711a05304112280027210b2741c4c289d39465c3365240c850e0c04114444a64203109884114a13154902844c88001c26493807193a49101c6082003266146529c28110c12024c4088c9b00d1ac08153464013a88010426c08890823271290b62091228a6418458ba0641c272acc8630e0486d0ca371d3868da0168e48a23062800580142189b268a2884d0c373214038090c4711b477258002e64026a1aa12d00c8245b98684844019a004149026d10a08d82840012b45102435221a32d5b908c648290939250023986081711212905dcc2619d5be95a339c1bc29c0538fe02924c096b7c7063deb34148fc2ac4297d5f2e85aea1ef57e1236204f75c6264559eb6f933df5b55302d09d6c6cb889fd44508a2122accc2b3cc2a0699147ec848a846c37c33f55dad55aff5de196966d3d01f71aca8fbb72c9d9018e0830a5eb3424bccae6288c13558faf85f1b8f095365a6c7d3b699f9a6332a377b12498df39a595fe1265eb04f10c81b826aed2a266bab5d2ce07020395961fd6358cbabde2264c6083cda237f13db7481d6100b46480bef4652c786871196fec4564a96ab056f8c15586b351391a6d808c9e7f4359a1499f8f07d99aad4e589a25be4e617ab70b39ba9eed53aaec3a4bc400e294d7eed7583489cd5cf6ae450fafe2db09098fd0a8ccc68e4d2b77064874501daf62757daf653365acfaca2df2280520f8374ac8d5e84b6a43f98f4afae4f84413c030ec7f21cf0e8a7d23b5d12654f7364460c5d8b4c75f790e3ba538c2e3f776b2769b794f45d1e1aac14febcb24eb335afac4154a73dd4435ebb9d5326d74dfaf349e44d88703c08748d6c850d4107990f0a18fecf2beebb88123894d489cbfe0c26fb88ca76a89ab233fec7a5cbb8566145c0a4a3a0d86f9e9689e5450f90d3a099870cea373243793ca3e5a92ff916f935fabacda0bf6bd8977b1bcf36f52f7812645e615f26e7df37c7278da16e8024d9027673f942fd7b8d738b525a629f1ba6ac66779db0bd8c90ab3903f7e9047f66b21dac94a9c335fe6aa78c6927663c0a74c89550bdc9d8201127984aa89ee2b80728be9b3f0d54a73172ba2ea4d1f7c4804af6998f8cd081d2e04b5448d2952749e09dae4354b893f26d355635d20764055e30459c613bb32fdb4ae074f545deafb3c532aac9559c8d3674cd132e4f854f1d9aab8c23bc94a0269a61b0f3d0b5ac3afb1ea35a45aca151ec63ec5bcc02ca647f2982c205549a2c8a5382ddd0c9e06ce545a18718a1bcea27623814bd3a8ce3b8ff8494f89cc32e05bd5749daa63b894685ce6906dfbfc411c2917d4b35fed903d8dc22a3056c28438c772c592d850a4d58becf2a286ed2e72f4ec13835236b3734367ea0b0f2eb38eff07c87d69fc4c7e86dd135459da3c96aa34400ca2db9eac2018a6a9c8d1339b6752023df35e1bb97b44555d194bae18232f68d2206fc35ba3754a33c91e82819c62ef864166910c7e40ed375647069d98fe7805e75e285a160a7950348304791208d4d82c5410ea019c39076ec36e8ed9a4d3eb87dac7eb3067b5776535301d2c622e7fa67a13d70cc4450c3093c5a47689e90a1b4178ccde8719baed1d3a2630078740a502977474b7025abdcb7998ec442d5aea31d6a8533aacff0111f935de36dfc6e266701d7c3778e7f4ebfa6f7ff9e6b1fab8962f30e5276b2a76f20acbf7087bd2d092dbf642843fa980f8a4b80ce730902c0e637f6c480f1f441ee731c9fa4d33258d00ff47be9b413eb176ac1cbc0c06edf67a59f9a996f9175327de3b829d1d830a638bf6056a87ec4150b440440a2ef9e5bafcdcedf4753ff11b1f2b00e52070f4984af34cefd224f36e6d04358418b05e52ed089dac28aac67c0e4d0ab79e4ee82377c9c4ceda877dcdc2fad48a88ae1fe4cc2582f1e41b5d557897902435a27a9bffc63357135c7e6e60516f56dccbd412afb250f117cbfa234619d75f199e397c587c523e4942728cd7d4d59aca9b52fa9364a7b81d9fd7c23e688b04bdaa986e21d7dbfcbfa634b8fcdfa2619d9b6904e3d8e3205bbf5a3d526c4bf9017723fa8944a0b08595e5252e361c5a353ae737177f043e9c2460f48a8aadbd342d773ad6e034191763d87e8c33a3a443cba0174f0bc49385b5a6ca75bb7c000888dcef43bc22252eac9710afb4a6c7a63b363d08e083e691aa848cad7bec731067a1a90a7803328aed4c987eb586461a523ab8fbda4829511f7a427940b94351966c8cb37dc22dd34a81c0542adeb97fff1f1460e72c575c9d18c571ae7175a9ce269fc570c0945484e6e5fca628b5bf0904bad7027e691f1fc8d740ed172fe8816b06b7a672d67faffa91affad41828204d5dbc10c68edbe911131c6f8993c054a2165675794bf6dd1b617a9e5fca0a1a884b21d236163c559be4daf02d5ed54034f735fb031bc17e95066ab3ac9120fd24e238e6255f5ae72fe81c0f9fb69979c746b893421842aa7641d50ff2b2506d078b0aeee703f08223be66255e62fa568a244ef8642eda22ca33472c07e3d8398fe12dae1dcb37dab68aca08a8aa439c4f2257910a0f46af5bcbdad3f987c17ac6c52703a04705ed920c69526fc748f366974706d19143cef2c3441ffa01e06"
// }"#
//             }
//             Algorithm::SLH_DSA_128S => {
//                 r#"{
//   "algorithm": "SLH_DSA_128S",
//   "bytes": "f47e7324fb639d867a35eea3558a54224e7ca5e357c588c136d2d514facd5fc0d93a31a624a7c3d9ba02f8a73bd2e9dad0261c237a3fa1df610b30f2a06bc750"
// }"#
//             }
//             _ => panic!("Fixture missing for algorithm {algorithm:?}"),
//         };

//         println!("Algorithm: {algorithm:?}, Generated SecretKey JSON:\n{sk_json}");
//         assert_eq!(
//             sk_json,
//             serde_json::to_string_pretty(
//                 &serde_json::from_str::<SecretKey>(expected_sk_json).unwrap()
//             )
//             .unwrap(),
//             "SecretKey JSON does not match fixture for {algorithm:?}"
//         );

//         // Roundtrip check
//         let reconstructed_sk: SecretKey =
//             serde_json::from_str(&sk_json).expect("Failed to deserialize SecretKey");
//         assert_eq!(
//             keypair.secret_key, reconstructed_sk,
//             "SecretKey roundtrip failed for {algorithm:?}"
//         );

//         // --- Signature Test ---
//         let sig_json =
//             serde_json::to_string_pretty(&signature).expect("Failed to serialize Signature");

//         // Only check fixture for deterministic algorithms
//         if *algorithm != Algorithm::SLH_DSA_128S {
//             // Define the expected fixture (UPDATE THIS STRING)
//             let expected_sig_json = match *algorithm {
//                 Algorithm::ML_DSA_44 => {
//                     r#"{
//       "algorithm": "ML_DSA_44",
//       "bytes": "d44770409f4dacafbc779f68ef129f8f15138a5befa38a9ced36031ebae7bdcbb09e900350de29cf4b9c2ce04e41bfb40739dd9bd985ed1bbed4c9c7bc96cca6f4d0c921b43b8e4067789b6e7744e7a055a5edc5b4bf0d8fc5ec404c980b5b298e5d930df3375b7ab686177c99ec4be848ce7cc162adb578896d11d4fcc5f0cf1af5f9ad070ea6f3460c06627f937782aaa185304c068748ee86c91fec03853a7ce81a304fcc2afcbb66c2e308af5269cd1c9b45a2ab73d04474d96b1c5890947485dd6c3d6e7bdc7b8e445fb27fb525677b2a3b95954dfd3bb163985d4640a4c1c1102452341e4ad5cbf5b8eb4d30c3323a6572502670e748cddca9d18f12d3a3fffcfec7099f16f6542eb39d3032094023649de67af9ee8e06c9a53cc926388345d6a9412d2de82a4e59c6c11b6f3b259243e45ee57ccd2e4f3a68a8e53b808911b4afe9d72891ca40739e1ab7142ca935e161a19dedf234ed27a7c18ba722780dd53aefc40e921ff0de9ca3ed37ebbe02237f802ea073f11c1b2ef2b703d65739b1d8c060d62a834138d7a2e663854ac794999c95360d849f57b00c37f1cf90a13e0b831df1ada26742097b6465bd2755794e20271077b80ac4d2aa6b5c8e3c77c34ee574dace472eee5eb88b0c59209bb6081a63e3cd9280b4d766e00da79af6d496c90b3ae5800397ecabcaa94d80e765b016a250dddc227d2fd1f6342290cc4ed53d1416fca988cb3d4577e27d76bbd1adcc6b22e80bf9d5901ab5797081012e4fddd320238f5ebf4c4dc5cb17ca57cc76089c8fe54ac7b3bd909ffd37ab4440c4716bb1ea42582c12b195ec38f5654146476bb72bead204fc250671567098ef2fc7c63c111a8cd3abdc5ab6aa4ff47ba5e2998e2aa4950f0725c4c770f974e7e16975068ece9b81e76fe65c84134f31855d910bb2f8ce6de08b59c6020b9292913a6322757176bdb70d2a01428161cc4f858b777d0af656366aaab65bd54cf2ed7820c26f93152cc7e827e403b71a10863409e75dbfb450618c718c3d0ac6b6686f3efc41c07a226547fa21721aeacf09b9707cedca25624f17b52a9fbb80045b62099d31f71dffa551af1d7a7276aed9036939f6c04884d13db33783adfbdd9de05824f6fe2cfbadeecf0e318f1e34bfc03d5a70c4dc8c9cebe1c1b9b605d421144a3d66b7d86710a2b87171680569222480db421b1bd678999d22aa561c55942fd7c2a7900759ee095ed2213d6ed0b5354846a010328f81600b42949be02f48fce7caf64a03dcc97edadc42ef4971f5371ff3e520d2c1de923c0dac6439c3a7e9dd4e55090584f9e2eeea96f29b69417673a8e150efe779166ba498f4ec58b9ecd00aac8b01dff155f29750852fe2e30cb0d6378b1a17ce9d90b93a5c838bbea80cedeb609c600f3bb44314a8c36713c849ec47a3794f3b828b7a8f169f33f3a1eb6867ba5d1fb71e658e1709dd08ac7e874ef3b2077edf570eb3d3989874d729aea331e03caa07ba672bc6b512a7902557bea55ee5466205064193de95ff92d2f5fac41d914e6c7e6fc62cbfe5b9ada3383a502c391782374a1b1241c7368598492f48085aea05f065213f13d9463c4b144e80a426fa5c415e593bef0b541068a8ffa1464e9b8f4ded4da5caad827142778a17d119c3e7121020ff452aefaf816c7ebf190b684d43e2c5547cece9eb7fa4f5312b19fae7f2645ff38c6c9a2514fdfdb74d3ec40e93402027f5af826aaa6c076dc1815b0b7425d5c9f7880f0e82258ff88cc3090e561524bab84bd167840463802df66a18340d7d0ef438a5c99c788ab7f07aaa2ee6e37ae0488967600421e6ddcde2a44dd3ceec3e8914f7fb5a1a42c38e20c1666ccfad1a1ae0364cc85a5612f35e087c77c0c212099c4a60138cb9486a571a59a9993ee00abd77902b684163b50fb02373baa75834ac3638a6c8e6a6038ce2a907c6ba2647cbd3437fb4920b1a5d46fb04b2c36a8aee0f3fcae7709e4508d2c7cfdfb724483dc71881a385eecd8b4dc32f793037be625a8427690ddbd6e0e8d80a15516cbadba4034d6700cb6ec807815f6dd5e8619a336bab503cfe6473cc913a80f9e5897ea68f2866ef145a3f1ef371ebe1151a4a93eceb3059a27fa93a309363b8b23cbf401dff0134a6080805837ae9fcff26a58e86ce37ded0d08f7022a979f0f788e99e7cdf32f16e09282b61d4528c5b79a38feeedf210722a20a428ae5b404c7923d1fa10e790b166b98ab1e44ae6fa3612a723045d7c4b77570345f7e7204227433611644a2c75715184da36f0688fd406c878773c58646bb130146f7ec75f8b03c97eb4329c942d9d6006bd1fcbb4e9f56031191d00334ca77cf71bb895521ea7ba6f9c4d9b67f7c4fd38f4e914cbb9717dac45c802234505de0951f8d897365002feac6dcc8616bab1ec0583de1c3cbbbaab3cbd5db94ff2721c9a22541e6796fca0a217f4eee5e1441398a1286b4638533d4a455f3c83c85d886911072eb45c808306514ef4ad1c31e3e5f7151dab4d2d18ec8ac812e0c03c86d879865281cfa517b955c1842c7e093e35b107eda832356e2992adaa697565e2c4a8e9994767a9a61d717dd2a860695c83ea2c5b5f692493e79f2c184df7db7973dfd79abf00f042ba10ad9ade75ea1b01b62efcebc6a2c7b59a2af01b8691855919b1826799f0bba13509f5db2cb55e3f7c7f72eec95df0da8021ebbbb60d2f063c4129fcd9ed825d8671bb913b4b9cf91e148d941590536a44511b62296be5222a253a19c9293126b5e8b1aebb7a58c4353fced6f23c35f7414730e78024b7ba2f8bfead124bed379d4098a3be2abd3cc10a47fd0fdb40b35ec517fbc66bf2c06e1f6960f8595452705339cdda9a9b5102b8a1a5c1f1f872d0fc564555cc431f95b7ac24fb679188f4d49a94a20f6734c20acc0c7a2463e4eb23350d386198c086818f6ddf32d5842f41d7ef3f1644f76dc401f41e87027aa77671132e3d6faa099f1e28b10d4642fe3364cd82b4950211d741392454d5b395dbf89745cdcf43910add671639829495ceca0b0d6fb2c85a9a3369cc6228ab65d88198167de7519a4857d9f2a5b37b88f4258f9d01780f23174eb9c0b3cbc888e59144c3ccfcef165f6ebe1be85a73976bcb54ba95966299e6eeeeb8fbfc51ce86075a672107e84a56c61a00ebb08e579407da3651fcec5c515ca4a5e49a51fbb07915356b0fc1654a86be032fe6ca14a0ae2526b5c78c04c842ce586a85aa1dd7a80cf355af293be254236c9952f8b1a2f2663613154a74754d0913181d2324272f3d4b577285868999abb5b9bcc5d3dde9f5fbfc050e51595eadf0f1f3273d415e6069799da1b7babfc8c9cdd1d6e7f90a16313345465d7677aeafb5c8ced4ecfb00000000000000001b243748"
//     }"#
//                 }
//                 // Add cases for other deterministic algorithms like SECP256K1_SCHNORR if needed
//                 _ => panic!("Fixture check not applicable for algorithm {algorithm:?}"),
//             };

//             println!("Algorithm: {algorithm:?}, Generated Signature JSON:\n{sig_json}");
//             // Compare generated JSON with the pretty-printed version of the parsed fixture
//             assert_eq!(
//                 sig_json,
//                 serde_json::to_string_pretty(
//                     &serde_json::from_str::<Signature>(expected_sig_json).unwrap()
//                 )
//                 .unwrap(),
//                 "Signature JSON does not match fixture for {algorithm:?}"
//             );
//         } else {
//             println!("Skipping fixture check for non-deterministic SLH_DSA_128S signature.");
//         }

//         // Roundtrip check (always perform this)
//         let reconstructed_sig: Signature =
//             serde_json::from_str(&sig_json).expect("Failed to deserialize Signature");
//         assert_eq!(
//             signature, reconstructed_sig,
//             "Signature roundtrip failed for {algorithm:?}"
//         );

//         // --- Verification Tests ---
//         // Verify reconstructed signature with reconstructed public key
//         let result1 = verify(&reconstructed_pk, message, &reconstructed_sig);
//         assert!(
//             result1.is_ok(),
//             "Verification failed: reconstructed_pk with reconstructed_sig for {algorithm:?}"
//         );

//         // Verify original signature with reconstructed public key
//         let result2 = verify(&reconstructed_pk, message, &signature);
//         assert!(
//             result2.is_ok(),
//             "Verification failed: reconstructed_pk with original signature for {algorithm:?}"
//         );

//         // Verify reconstructed signature with original public key
//         let result3 = verify(&keypair.public_key, message, &reconstructed_sig);
//         assert!(
//             result3.is_ok(),
//             "Verification failed: original public_key with reconstructed_sig for {algorithm:?}"
//         );

//         println!("Serde roundtrip test passed for {algorithm:?}");
//     }
// }
