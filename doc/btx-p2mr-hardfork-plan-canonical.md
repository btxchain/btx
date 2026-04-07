> **Note**: This document is a historical implementation plan. Current values: 24 MB serialized, 24 MWU weight, 480k sigops, 90s blocks. See README.md for current parameters.

# BTX P2MR HARD FORK IMPLEMENTATION PLAN
Test-Driven Development from Genesis
====================================

This file is the verbatim canonical prompt provided by the user, retained for handoff and context-compression resilience.

OVERVIEW
--------
Transform BTX from Taproot/ECDSA to P2MR-only (BIP-360) with ML-DSA-44
primary and SLH-DSA-SHAKE-128s backup. 12 MB blocks, 90s intervals.
No backwards compatibility. Clean genesis.

PREREQUISITES
- BTX node compiles and existing test suite passes
- libbitcoinpqc GitHub repo cloned and reviewed
- FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) specs available for reference

EXECUTION ORDER: Phases must be completed in sequence.
Within each phase, follow strict TDD: write test, watch it fail,
write code, watch it pass, refactor.


========================================================================
PHASE 0: BLOCK PARAMETER CHANGES (12 MB blocks, 90s intervals)
========================================================================
Estimated: ~85 lines across 18 files. Independent of PQ work.

STEP 0.1 - WRITE PARAMETER TESTS

File: src/test/matmul_block_capacity_tests.cpp
  Update all assertions:
    MAX_BLOCK_SERIALIZED_SIZE == 12000000 (was 8000000)
    MAX_BLOCK_WEIGHT == 24000000 (was 16000000)
    MAX_BLOCK_SIGOPS_COST == 240000 (was 160000)
    nDefaultBlockMaxWeight == 12000000 (was 8000000)

File: src/test/matmul_dgw_tests.cpp
  Update all timing assertions:
    Line 90: ExpectedDgwTimespan for all-normal window = 16200 (was 27000, now 180 * 90)
    Line 96: Mixed window formula uses 90 not 150 for normal spacing
    Line 108: Full normal window = 16200

Run tests. Confirm they FAIL with current values.

STEP 0.2 - UPDATE CONSENSUS CONSTANTS

File: src/consensus/consensus.h
  Line 13: MAX_BLOCK_SERIALIZED_SIZE = 12000000
  Line 15: MAX_BLOCK_WEIGHT = 24000000
  Line 17: MAX_BLOCK_SIGOPS_COST = 240000

File: src/consensus/params.h
  Line 147: nPowTargetSpacingNormal{90}
  Line 152: nMaxBlockWeight{24000000}
  Line 153: nMaxBlockSerializedSize{12000000}
  Line 154: nMaxBlockSigOpsCost{240000}
  Line 155: nDefaultBlockMaxWeight{12000000}

STEP 0.3 - UPDATE CHAIN PARAMETERS (all networks)

File: src/kernel/chainparams.cpp
  Mainnet section:
    nPowTargetSpacing = 90 (was 150)
    nPowTargetSpacingNormal = 90
    nMaxBlockWeight = 24000000
    nMaxBlockSerializedSize = 12000000
    nMaxBlockSigOpsCost = 240000
    nDefaultBlockMaxWeight = 12000000
  Repeat for testnet, testnet4, and regtest sections with same values.

STEP 0.4 - UPDATE POLICY DEFAULTS

File: src/policy/policy.h
  DEFAULT_BLOCK_MAX_WEIGHT = 12000000 (was 8000000)
  MAX_STANDARD_TX_WEIGHT = 1200000 (was 400000, scale proportionally)
  Adjust any other hardcoded weight references.

STEP 0.5 - UPDATE DOCUMENTATION

File: doc/btx-matmul-pow-spec.md
  Replace all references to 150s with 90s
  Replace all references to 27000s DGW timespan with 16200s
  Replace all references to 8 MB / 16 MWU with 12 MB / 24 MWU

STEP 0.6 - RUN ALL EXISTING TESTS

Command: cd src && make check
  All matmul_block_capacity_tests must pass
  All matmul_dgw_tests must pass
  All other existing tests must still pass

CHECKPOINT 0: Block parameters are updated. All tests green.


========================================================================
PHASE 1: INTEGRATE LIBBITCOINPQC
========================================================================
Estimated: ~200 lines build system + ~150 lines wrapper.

STEP 1.1 - WRITE PQ PRIMITIVE TESTS

File: src/test/pq_crypto_tests.cpp (NEW)
  Test suite: pq_crypto_tests
  Test: mldsa44_keygen_produces_valid_sizes
    Generate ML-DSA-44 keypair
    Assert pubkey size == 1312 bytes
    Assert secret key size == 2560 bytes
  Test: mldsa44_sign_verify_roundtrip
    Generate keypair
    Sign 32-byte message hash
    Assert signature size == 2420 bytes
    Verify signature against pubkey and message
    Assert verification succeeds
  Test: mldsa44_verify_rejects_wrong_message
    Generate keypair, sign message A
    Verify signature against message B
    Assert verification fails
  Test: mldsa44_verify_rejects_wrong_key
    Generate two keypairs, sign with key1
    Verify with key2 pubkey
    Assert verification fails
  Test: slhdsa128s_keygen_produces_valid_sizes
    Generate SLH-DSA-SHAKE-128s keypair
    Assert pubkey size == 32 bytes
    Assert secret key size == 64 bytes
  Test: slhdsa128s_sign_verify_roundtrip
    Generate keypair, sign, verify
    Assert signature size == 7856 bytes
    Assert verification succeeds
  Test: slhdsa128s_verify_rejects_wrong_message
    Same pattern as ML-DSA test
  Test: pq_key_zeroization
    Generate key, clear it
    Assert secret key memory is zeroed

Run tests. Confirm they FAIL (library not yet integrated).

STEP 1.2 - ADD LIBBITCOINPQC AS SUBTREE

Command: git subtree add --prefix=src/libbitcoinpqc <repo-url> main --squash

File: src/CMakeLists.txt
  After the secp256k1 integration block (around line 80), add:
    if(NOT WITH_SYSTEM_LIBBITCOINPQC)
      message("Configuring libbitcoinpqc subtree...")
      set(LIBBITCOINPQC_DISABLE_SHARED ON CACHE BOOL "" FORCE)
      add_subdirectory(libbitcoinpqc)
      set_target_properties(bitcoinpqc PROPERTIES EXCLUDE_FROM_ALL TRUE)
    endif()

  In target_link_libraries for bitcoin_consensus, add:
    bitcoinpqc (or libbitcoinpqc::libbitcoinpqc)

  In target_link_libraries for bitcoin_common, add same.

STEP 1.3 - CREATE C++ WRAPPER HEADER

File: src/pqkey.h (NEW)
  Include libbitcoinpqc C headers.
  Define constants:
    MLDSA44_PUBKEY_SIZE = 1312
    MLDSA44_SECRET_KEY_SIZE = 2560
    MLDSA44_SIGNATURE_SIZE = 2420
    SLHDSA128S_PUBKEY_SIZE = 32
    SLHDSA128S_SECRET_KEY_SIZE = 64
    SLHDSA128S_SIGNATURE_SIZE = 7856
  Declare enum PQAlgorithm { ML_DSA_44 = 0, SLH_DSA_128S = 1 }
  Declare class CPQKey:
    Private:
      PQAlgorithm m_algo
      secure_unique_ptr for secret key bytes
      std::vector<unsigned char> m_pubkey
    Public:
      void MakeNewKey(PQAlgorithm algo)
      bool Sign(const uint256& hash, std::vector<unsigned char>& sig) const
      std::vector<unsigned char> GetPubKey() const
      PQAlgorithm GetAlgorithm() const
      bool IsValid() const
      void ClearKeyData()  // secure zeroize
      size_t GetPubKeySize() const
      size_t GetSigSize() const
  Declare class CPQPubKey:
    Private:
      PQAlgorithm m_algo
      std::vector<unsigned char> m_data
    Public:
      CPQPubKey(PQAlgorithm algo, Span<const unsigned char> data)
      bool Verify(const uint256& hash, Span<const unsigned char> sig) const
      PQAlgorithm GetAlgorithm() const
      Span<const unsigned char> GetData() const
      size_t size() const

STEP 1.4 - IMPLEMENT C++ WRAPPER

File: src/pqkey.cpp (NEW)
  Include pqkey.h and libbitcoinpqc headers.
  Include support/allocators/secure.h for secure memory.
  Implement CPQKey::MakeNewKey:
    Call bitcoin_pqc_keygen(algo, pubkey_out, seckey_out)
    Store seckey in secure-allocated buffer
    Store pubkey
  Implement CPQKey::Sign:
    Call bitcoin_pqc_sign(algo, seckey, msg, msg_len, sig_out, sig_len_out)
    Return true on success
  Implement CPQKey::ClearKeyData:
    memory_cleanse(seckey_data, seckey_size)
    Reset pointers
  Implement CPQPubKey::Verify:
    Call bitcoin_pqc_verify(algo, pubkey, msg, msg_len, sig, sig_len)
    Return true on success
  Destructor for CPQKey calls ClearKeyData.

STEP 1.5 - ADD TO BUILD AND RUN TESTS

File: src/CMakeLists.txt
  Add pqkey.cpp to bitcoin_common sources.
  Add src/test/pq_crypto_tests.cpp to test sources.

Command: make -j$(nproc) && src/test/test_btx --run_test=pq_crypto_tests
  All 8 tests must pass.

CHECKPOINT 1: PQ crypto primitives work. Sign/verify roundtrips pass.


========================================================================
PHASE 2: P2MR MERKLE TREE AND LEAF HASHING
========================================================================
Estimated: ~300 lines.

STEP 2.1 - WRITE MERKLE TREE TESTS

File: src/test/pq_merkle_tests.cpp (NEW)
  Test suite: pq_merkle_tests
  Test: compute_single_leaf_hash
    Create ML-DSA leaf script: <pubkey_1312_bytes> OP_CHECKSIG_MLDSA
    Compute leaf hash: SHA256(0xc2 || compact_size(script_len) || script)
    Assert hash is 32 bytes and deterministic
  Test: compute_two_leaf_merkle_root
    Create ML-DSA leaf and SLH-DSA leaf
    Compute leaf hashes
    Compute branch: SHA256(sorted(leaf_a, leaf_b))
    Assert root is 32 bytes
  Test: single_leaf_merkle_root_equals_leaf_hash
    Single leaf tree: root == leaf_hash (tagged)
    Verify this property
  Test: default_wallet_tree_produces_deterministic_root
    Given fixed ML-DSA and SLH-DSA pubkeys
    Build default 2-leaf tree
    Assert merkle root matches expected value
  Test: control_block_single_leaf_is_one_byte
    Single leaf P2MR: control block = just leaf_version byte (0xc2)
    Assert control block size == 1
  Test: control_block_two_leaves_is_33_bytes
    Two leaf P2MR: control = leaf_version(1) + sibling_hash(32)
    Assert control block size == 33
  Test: verify_merkle_proof_valid
    Build 2-leaf tree, create proof for leaf 0
    Verify proof against root
    Assert success
  Test: verify_merkle_proof_invalid_sibling
    Tamper with sibling hash in proof
    Assert verification fails

Run tests. Confirm FAIL.

STEP 2.2 - IMPLEMENT P2MR MERKLE FUNCTIONS

File: src/script/pqm.h (NEW)
  Define constants:
    P2MR_LEAF_VERSION = 0xc2
    P2MR_LEAF_MASK = 0xfe
    P2MR_CONTROL_BASE_SIZE = 1 (just leaf version, no internal pubkey)
    P2MR_CONTROL_NODE_SIZE = 32
    P2MR_CONTROL_MAX_SIZE = 1 + 128 * 32 (max 128 depth)
    WITNESS_V2_P2MR_SIZE = 32
    OP_CHECKSIG_MLDSA = 187
    OP_CHECKSIG_SLHDSA = 188
  Declare:
    uint256 ComputeP2MRLeafHash(uint8_t leaf_version, Span<const unsigned char> script)
    uint256 ComputeP2MRBranchHash(const uint256& left, const uint256& right)
    uint256 ComputeP2MRMerkleRoot(const std::vector<uint256>& leaf_hashes)
    bool VerifyP2MRCommitment(Span<const unsigned char> control,
                              Span<const unsigned char> program,
                              const uint256& leaf_hash)
    std::vector<unsigned char> BuildP2MRScript(PQAlgorithm algo,
                                               Span<const unsigned char> pubkey)

File: src/script/pqm.cpp (NEW)
  Implement ComputeP2MRLeafHash:
    HashWriter with tag "P2MRLeaf"
    Write leaf_version byte, then script bytes
    Return SHA256
  Implement ComputeP2MRBranchHash:
    HashWriter with tag "P2MRBranch"
    Sort the two hashes lexicographically (consistent ordering)
    Write both, return SHA256
  Implement ComputeP2MRMerkleRoot:
    If 1 leaf: return tagged single-leaf hash
    If 2 leaves: return branch hash
    If more: build balanced binary tree recursively
  Implement VerifyP2MRCommitment:
    Extract leaf_version from control[0]
    Walk merkle path in control[1..] in 32-byte chunks
    Reconstruct root from leaf_hash + path nodes
    Compare reconstructed root to program (the 32-byte witness program)
    Return true if match
  Implement BuildP2MRScript:
    For ML-DSA-44: OP_PUSHDATA2 + len_le16(1312) + pubkey + OP_CHECKSIG_MLDSA(187)
    For SLH-DSA: OP_PUSH32(32) + pubkey + OP_CHECKSIG_SLHDSA(188)
    Return script bytes as vector

STEP 2.3 - ADD TO BUILD AND RUN TESTS

Add pqm.cpp to bitcoin_consensus in CMakeLists.txt.
Add pq_merkle_tests.cpp to test sources.

Command: make -j$(nproc) && src/test/test_btx --run_test=pq_merkle_tests
  All 8 tests must pass.

CHECKPOINT 2: Merkle tree construction and verification works.


========================================================================
PHASE 3: DESTINATION TYPE AND ADDRESS ENCODING
========================================================================
Estimated: ~250 lines.

STEP 3.1 - WRITE ADDRESS TESTS

File: src/test/pq_address_tests.cpp (NEW)
  Test suite: pq_address_tests
  Test: witness_v2_p2mr_destination_type_exists
    Create a WitnessV2P2MR destination with a 32-byte merkle root
    Assert it holds the correct 32 bytes
    Assert it is distinguishable from WitnessV1Taproot
  Test: encode_p2mr_address_mainnet
    Create WitnessV2P2MR destination
    Call EncodeDestination
    Assert result starts with "btx1z" (version 2 = 'z' in Bech32m)
    Assert encoding is Bech32m
  Test: decode_p2mr_address_mainnet
    Encode a P2MR address, then decode it
    Assert decoded destination holds WitnessV2P2MR variant
    Assert round-trip preserves the 32-byte program
  Test: p2mr_address_rejects_wrong_length
    Try decoding a btx1z address with 20 bytes (wrong)
    Assert decode returns CNoDestination
  Test: output_type_p2mr_exists
    Assert OutputType::P2MR is a valid enum value
    Assert FormatOutputType(OutputType::P2MR) == "p2mr"
    Assert ParseOutputType("p2mr") == OutputType::P2MR
  Test: output_type_from_p2mr_destination
    Create WitnessV2P2MR dest
    Assert OutputTypeFromDestination returns OutputType::P2MR
  Test: get_script_for_p2mr_destination
    Create WitnessV2P2MR with known 32 bytes
    Call GetScriptForDestination
    Assert script is: OP_2 <push 32 bytes>
    Assert script.IsWitnessProgram returns version=2, program=32 bytes

Run tests. Confirm FAIL.

STEP 3.2 - ADD WITNESSV2P2MR DESTINATION TYPE

File: src/addresstype.h
  After WitnessV1Taproot definition, add:
    struct WitnessV2P2MR : public BaseHash<uint256>
    {
        WitnessV2P2MR() : BaseHash() {}
        explicit WitnessV2P2MR(const uint256& merkle_root) : BaseHash(merkle_root) {}
        static constexpr size_t size() { return 32; }
    };
  Update CTxDestination variant to include WitnessV2P2MR:
    using CTxDestination = std::variant<CNoDestination, PubKeyDestination,
        PKHash, ScriptHash, WitnessV0ScriptHash, WitnessV0KeyHash,
        WitnessV1Taproot, PayToAnchor, WitnessV2P2MR, WitnessUnknown>;

File: src/addresstype.cpp
  In GetScriptForDestination visitor, add case for WitnessV2P2MR:
    Produce: OP_2 <32-byte merkle_root>
  In ExtractDestination, add case for 32-byte witness v2 program:
    Return WitnessV2P2MR

STEP 3.3 - ADD OUTPUT TYPE P2MR

File: src/outputtype.h
  Add P2MR to enum before UNKNOWN:
    enum class OutputType { LEGACY, P2SH_SEGWIT, BECH32, BECH32M, P2MR, UNKNOWN };
  Update OUTPUT_TYPES array to include P2MR.

File: src/outputtype.cpp
  Add OUTPUT_TYPE_STRING_P2MR = "p2mr"
  Add P2MR case to ParseOutputType
  Add P2MR case to FormatOutputType
  Add P2MR case to GetDestinationForKey: assert(false) since P2MR uses PQ keys
  Add P2MR case to AddAndGetDestinationForScript: assert(false) for now
  Add WitnessV2P2MR case to OutputTypeFromDestination returning P2MR

STEP 3.4 - ADD ADDRESS ENCODING/DECODING

File: src/key_io.cpp
  In DestinationEncoder, add visitor for WitnessV2P2MR:
    std::vector<unsigned char> data = {2}  // witness version 2
    data.reserve(53)
    ConvertBits<8, 5, true>(push_back_to_data, mr.begin(), mr.end())
    return bech32::Encode(bech32::Encoding::BECH32M, m_params.Bech32HRP(), data)
  In DecodeDestination, after the version==1 Taproot block (around line 182):
    if (version == 2 && data.size() == WITNESS_V2_P2MR_SIZE) {
        WitnessV2P2MR mr;
        std::copy(data.begin(), data.end(), mr.begin());
        return mr;
    }
  Define WITNESS_V2_P2MR_SIZE = 32 constant at top of file or in pqm.h

STEP 3.5 - RUN TESTS

Command: make -j$(nproc) && src/test/test_btx --run_test=pq_address_tests
  All 7 tests must pass.
Also run: src/test/test_btx --run_test=key_io_tests
  Existing address tests must still pass.

CHECKPOINT 3: P2MR addresses encode/decode correctly as btx1z...


========================================================================
PHASE 4: CONSENSUS VALIDATION (WITNESS V2 SCRIPT EXECUTION)
========================================================================
Estimated: ~400 lines. This is the core consensus change.

STEP 4.1 - WRITE CONSENSUS TESTS

File: src/test/pq_consensus_tests.cpp (NEW)
  Test suite: pq_consensus_tests
  Test: witness_v2_recognized_as_p2mr
    Create script: OP_2 <32 bytes>
    Assert IsWitnessProgram returns version=2, size=32
  Test: p2mr_single_leaf_mldsa_valid_spend
    Create ML-DSA-44 keypair
    Build single-leaf P2MR script and merkle root
    Create P2MR output: OP_2 <merkle_root>
    Build witness stack: [mldsa_signature, leaf_script, control_block(0xc2)]
    Run VerifyWitnessProgram with version=2
    Assert success
  Test: p2mr_single_leaf_mldsa_invalid_sig_fails
    Same setup but corrupt the signature
    Assert script execution fails with SIG_MLDSA error
  Test: p2mr_two_leaf_spend_leaf0_mldsa
    Create 2-leaf tree (ML-DSA + SLH-DSA)
    Spend via leaf 0 (ML-DSA)
    Witness: [mldsa_sig, leaf0_script, control(0xc2 || sibling_hash)]
    Assert success
  Test: p2mr_two_leaf_spend_leaf1_slhdsa
    Same tree, spend via leaf 1 (SLH-DSA)
    Witness: [slhdsa_sig, leaf1_script, control(0xc2 || sibling_hash)]
    Assert success
  Test: p2mr_wrong_merkle_proof_fails
    Provide wrong sibling hash in control block
    Assert WITNESS_PROGRAM_MISMATCH error
  Test: p2mr_wrong_leaf_version_fails
    Use leaf version 0xc0 (tapscript) instead of 0xc2
    Assert failure
  Test: p2mr_empty_witness_fails
    Provide empty witness stack
    Assert WITNESS_PROGRAM_WITNESS_EMPTY error
  Test: op_checksig_mldsa_pops_correct_stack
    Execute leaf script with: <sig> <pubkey> OP_CHECKSIG_MLDSA
    Assert correct stack behavior
  Test: op_checksig_slhdsa_pops_correct_stack
    Execute leaf script with: <sig> <pubkey> OP_CHECKSIG_SLHDSA
    Assert correct stack behavior

Run tests. Confirm FAIL.

STEP 4.2 - ADD SIGVERSION AND CONSTANTS

File: src/script/interpreter.h
  Add to SigVersion enum:
    P2MR = 4
  Add constants:
    static constexpr size_t WITNESS_V2_P2MR_SIZE = 32;
    static constexpr size_t P2MR_CONTROL_BASE_SIZE = 1;
    static constexpr size_t P2MR_CONTROL_NODE_SIZE = 32;
    static constexpr uint8_t P2MR_LEAF_VERSION = 0xc2;
    static constexpr uint8_t P2MR_LEAF_MASK = 0xfe;

File: src/script/script.h
  Add opcode enum entries:
    OP_CHECKSIG_MLDSA = 187
    OP_CHECKSIG_SLHDSA = 188

STEP 4.3 - IMPLEMENT WITNESS V2 EXECUTION PATH

File: src/script/interpreter.cpp
  In VerifyWitnessProgram, after the witness version 1 (Taproot) block
  and before the else catch-all (around line 1992), insert:

    } else if (witversion == 2 && program.size() == WITNESS_V2_P2MR_SIZE) {
        // P2MR: Post-Quantum Merkle Root spending
        if (stack.size() < 2) {
            return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);
        }
        // Stack: [script_args..., script, control_block]
        const valtype& control = SpanPopBack(stack);
        const valtype& script = SpanPopBack(stack);
        // Validate control block size
        if (control.size() < P2MR_CONTROL_BASE_SIZE ||
            control.size() > P2MR_CONTROL_MAX_SIZE ||
            ((control.size() - P2MR_CONTROL_BASE_SIZE) % P2MR_CONTROL_NODE_SIZE) != 0) {
            return set_error(serror, SCRIPT_ERR_P2MR_WRONG_CONTROL_SIZE);
        }
        // Verify leaf version
        if ((control[0] & P2MR_LEAF_MASK) != P2MR_LEAF_VERSION) {
            return set_error(serror, SCRIPT_ERR_P2MR_WRONG_LEAF_VERSION);
        }
        // Compute leaf hash and verify Merkle commitment
        uint256 leaf_hash = ComputeP2MRLeafHash(control[0] & P2MR_LEAF_MASK, script);
        if (!VerifyP2MRCommitment(control, program, leaf_hash)) {
            return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
        }
        // Execute the leaf script
        CScript exec_script(script.begin(), script.end());
        execdata.m_validation_weight_left =
            ::GetSerializeSize(witness.stack) + VALIDATION_WEIGHT_OFFSET;
        execdata.m_validation_weight_left_init = true;
        return ExecuteWitnessScript(stack, exec_script, flags,
            SigVersion::P2MR, checker, execdata, serror);
    }

STEP 4.4 - IMPLEMENT PQ SIGNATURE OPCODES

File: src/script/interpreter.cpp
  In EvalScript or ExecuteWitnessScript, handle the new opcodes
  when SigVersion::P2MR is active.

  Remove OP_CHECKSIG_MLDSA (187) and OP_CHECKSIG_SLHDSA (188) from
  the IsOpSuccess set (they are no longer anyone-can-spend in P2MR).

  For OP_CHECKSIG_MLDSA (opcode 187):
    Pop signature from stack
    Pop pubkey from stack (1312 bytes expected)
    Verify pubkey size == MLDSA44_PUBKEY_SIZE
    Compute sighash using BIP341-style transaction digest
    Call CPQPubKey(ML_DSA_44, pubkey).Verify(sighash, sig)
    Push OP_TRUE or OP_FALSE based on result
    If SCRIPT_VERIFY_NULLFAIL and sig is non-empty and verify failed:
      return set_error SCRIPT_ERR_SIG_MLDSA

  For OP_CHECKSIG_SLHDSA (opcode 188):
    Same pattern but:
    Pop pubkey (32 bytes expected)
    Verify pubkey size == SLHDSA128S_PUBKEY_SIZE
    Call CPQPubKey(SLH_DSA_128S, pubkey).Verify(sighash, sig)

File: src/script/script_error.h
  Add new error codes:
    SCRIPT_ERR_SIG_MLDSA
    SCRIPT_ERR_SIG_SLHDSA
    SCRIPT_ERR_P2MR_WRONG_CONTROL_SIZE
    SCRIPT_ERR_P2MR_WRONG_LEAF_VERSION
    SCRIPT_ERR_PQ_PUBKEY_SIZE

STEP 4.5 - UPDATE SIGHASH FOR P2MR

File: src/script/interpreter.cpp
  In SignatureHashSchnorr (or create SignatureHashP2MR):
    Reuse BIP341 sighash structure but with epoch byte = 2 (instead of 0).
    Input: spending transaction, input index, prevouts, leaf_hash, sighash_type
    Output: 32-byte hash for PQ signing
    This is the message that ML-DSA/SLH-DSA signs.

STEP 4.6 - RUN TESTS

Command: make -j$(nproc) && src/test/test_btx --run_test=pq_consensus_tests
  All 10 tests must pass.
Also run full test suite to confirm no regressions.

CHECKPOINT 4: P2MR consensus validation works end-to-end.


========================================================================
PHASE 5: DESCRIPTOR SYSTEM (MRDescriptor)
========================================================================
Estimated: ~350 lines.

STEP 5.1 - WRITE DESCRIPTOR TESTS

File: src/test/pq_descriptor_tests.cpp (NEW)
  Test suite: pq_descriptor_tests
  Test: parse_mr_descriptor_single_key
    Parse "mr(<hex_mldsa_pubkey>)" with provider
    Assert parse succeeds, returns 1 descriptor
    Assert descriptor GetOutputType() == OutputType::P2MR
  Test: mr_descriptor_produces_correct_script
    Parse mr descriptor with known pubkey
    Expand at index 0
    Assert produced script is OP_2 <32-byte-merkle-root>
    Assert merkle root matches hand-computed value
  Test: mr_descriptor_hd_derivation
    Parse "mr(<xpub>/87h/0h/0/*)" descriptor
    Expand at indices 0, 1, 2
    Assert each produces different merkle root
    Assert all scripts are OP_2 <32 bytes>
  Test: mr_descriptor_two_leaf_tree
    Parse "mr(<mldsa_key>, {pk_slh(<slhdsa_key>)})" or equivalent syntax
    Expand and verify merkle root includes both leaves
  Test: mr_descriptor_roundtrip_string
    Parse descriptor, convert back to string
    Assert strings match (minus checksum differences)
  Test: mr_descriptor_checksum_validation
    Parse descriptor with correct checksum: passes
    Parse descriptor with wrong checksum: fails

Run tests. Confirm FAIL.

STEP 5.2 - IMPLEMENT MRDESCRIPTOR CLASS

File: src/script/descriptor.cpp
  Create class MRDescriptor implementing DescriptorImpl:
    Private members:
      std::vector<std::unique_ptr<PubkeyProvider>> m_pq_providers
      (one per leaf in the Merkle tree)
    Public methods:
      GetOutputType(): return OutputType::P2MR
      IsSingleType(): return true
      GetWitnessVersion(): return 2
      MakeScripts():
        For each provider, derive PQ pubkey
        Build leaf script for each (ML-DSA or SLH-DSA based on key type)
        Compute leaf hashes
        Compute merkle root
        Return CScript: OP_2 <merkle_root>
      ToStringExtra(): return descriptor string representation

  The HD key derivation for PQ keys:
    At each BIP32 derivation step, use HMAC-SHA512(chain_code, key || index)
    Left 32 bytes = seed for PQ keygen at that level
    Right 32 bytes = new chain code
    This is deterministic: same master seed + path = same PQ keypair

STEP 5.3 - ADD DESCRIPTOR PARSER

File: src/script/descriptor.cpp
  In the Parse function (around line 1944-2043), add handler for "mr(":
    When encountering "mr(" token:
      Parse the first argument as a PQ pubkey or xpub HD key
      Optionally parse a script tree (same syntax as tr() tree)
      Construct MRDescriptor with the parsed providers
      Return the descriptor

STEP 5.4 - ADD PQ PUBKEY PROVIDER

File: src/script/descriptor.cpp
  Create PQPubkeyProvider (or extend existing BIP32PubkeyProvider):
    For HD derivation: takes xpub + path, derives PQ seed at each level
    For fixed key: takes raw PQ pubkey bytes
    GetPubKey(): returns the PQ public key for the given position
    GetAlgorithm(): returns ML_DSA_44 or SLH_DSA_128S based on descriptor

STEP 5.5 - RUN TESTS

Command: make -j$(nproc) && src/test/test_btx --run_test=pq_descriptor_tests
  All 6 tests must pass.

CHECKPOINT 5: Descriptor system can parse and expand mr() descriptors.


========================================================================
PHASE 6: WALLET INTEGRATION
========================================================================
Estimated: ~500 lines.

STEP 6.1 - WRITE WALLET TESTS

File: src/wallet/test/pq_wallet_tests.cpp (NEW)
  Test suite: pq_wallet_tests
  Test: generate_wallet_descriptor_p2mr
    Call GenerateWalletDescriptor with OutputType::P2MR
    Assert returned descriptor string starts with "mr("
    Assert path contains "/87h/"
  Test: create_wallet_default_address_is_p2mr
    Create new descriptor wallet
    Call GetNewDestination(OutputType::P2MR)
    Assert result holds WitnessV2P2MR variant
    Encode address, assert starts with "btx1z"
  Test: wallet_creates_p2mr_only_descriptors
    Create wallet with SetupDescriptorScriptPubKeyMans
    Assert P2MR descriptor managers exist
    For each manager, assert GetOutputType() == P2MR
  Test: sign_p2mr_transaction_mldsa
    Create wallet, get P2MR address
    Fund the address with a mock coinbase
    Create transaction spending the UTXO to another P2MR address
    Sign the transaction
    Assert witness contains ML-DSA signature (2420 bytes)
    Assert witness contains leaf script with 1312-byte pubkey
    Assert witness contains control block
  Test: sign_p2mr_transaction_slhdsa_backup
    Same setup but force spending via SLH-DSA leaf
    Assert witness contains SLH-DSA signature (7856 bytes)
  Test: p2mr_transaction_weight_calculation
    Create and sign a 1-in-2-out P2MR ML-DSA transaction
    Assert weight is approximately 4294 WU
    Assert serialized size is approximately 3883 bytes
  Test: wallet_rejects_non_p2mr_address_type
    Call GetNewDestination with OutputType::BECH32
    Assert it fails or returns error for P2MR-only wallet

Run tests. Confirm FAIL.

STEP 6.2 - UPDATE WALLET DESCRIPTOR GENERATION

File: src/wallet/walletutil.cpp
  In GenerateWalletDescriptor, add case for OutputType::P2MR:
    desc_prefix = "mr(" + xpub + "/87h"
    (same suffix pattern as other types)

File: src/wallet/wallet.h
  Change DEFAULT_ADDRESS_TYPE:
    constexpr OutputType DEFAULT_ADDRESS_TYPE{OutputType::P2MR};

STEP 6.3 - UPDATE OUTPUT_TYPES FOR P2MR-ONLY

File: src/outputtype.h
  For P2MR-only chain, change OUTPUT_TYPES to contain only P2MR:
    static constexpr auto OUTPUT_TYPES = std::array{
        OutputType::P2MR,
    };
  Keep other OutputType enum values for code compilation but they
  will never be instantiated in wallet setup.

STEP 6.4 - IMPLEMENT PQ SIGNING IN WALLET

File: src/script/sign.cpp
  Add new function CreatePQSignature:
    Input: signing provider, spending tx, input index, prev output,
           leaf_hash, sighash_type, PQAlgorithm
    Compute sighash using SignatureHashP2MR
    Retrieve PQ secret key from provider
    Call CPQKey::Sign(sighash, sig_out)
    Return signature bytes

  In SignStep, add case for TxoutType::WITNESS_V2_P2MR:
    Identify which leaf to use (prefer ML-DSA, fall back to SLH-DSA)
    Get the PQ pubkey for that leaf
    Call CreatePQSignature
    Push signature onto witness stack
    Push leaf script onto witness stack
    Push control block onto witness stack

File: src/script/sign.h
  Add PQ key types to SignatureData:
    std::map<std::vector<unsigned char>, CPQKey> pq_keys;
    (keyed by PQ pubkey bytes)

STEP 6.5 - IMPLEMENT PQ KEY PROVIDER IN WALLET

File: src/wallet/scriptpubkeyman.h and .cpp
  In DescriptorScriptPubKeyMan:
    Override GetPQKey to retrieve PQ secret key for signing
    The key is derived deterministically from the HD master seed
    using the mr() descriptor expansion at the correct index
    Store derived PQ keys in encrypted wallet database

File: src/wallet/walletdb.h and .cpp
  Add serialization for PQ key material:
    DB key: "pqkey" + pubkey_hash
    DB value: encrypted PQ secret key bytes
  Use existing wallet encryption infrastructure (CCrypter)

STEP 6.6 - UPDATE COIN SELECTION AND TX CREATION

File: src/wallet/spend.cpp
  In CreateTransaction:
    When building P2MR transactions, estimate witness size correctly:
    ML-DSA input witness = sig(2420) + script(~1316) + control(1-33) = ~3740 bytes
    Update GetVirtualTransactionInputSize for P2MR inputs
    Update fee estimation to account for larger witnesses

STEP 6.7 - RUN TESTS

Command: make -j$(nproc) && src/test/test_btx --run_test=pq_wallet_tests
  All 7 tests must pass.
Also run: src/test/test_btx --run_test=wallet_tests
  Existing wallet tests must still compile (some may need updating
  since DEFAULT_ADDRESS_TYPE changed).

CHECKPOINT 6: Wallet creates, signs, and broadcasts P2MR transactions.


========================================================================
PHASE 7: POLICY AND MEMPOOL (P2MR-ONLY ENFORCEMENT)
========================================================================
Estimated: ~150 lines.

STEP 7.1 - WRITE POLICY TESTS

File: src/test/pq_policy_tests.cpp (NEW)
  Test suite: pq_policy_tests
  Test: p2mr_output_is_standard
    Create transaction with P2MR output: OP_2 <32 bytes>
    Call IsStandard
    Assert true
  Test: legacy_p2pkh_output_is_nonstandard
    Create transaction with P2PKH output
    Call IsStandard
    Assert false (rejected by P2MR-only policy)
  Test: p2wpkh_output_is_nonstandard
    Create transaction with P2WPKH output
    Assert false
  Test: taproot_output_is_nonstandard
    Create transaction with P2TR output (OP_1 <32 bytes>)
    Assert false
  Test: p2mr_witness_is_standard
    Create spending tx with valid P2MR witness
    Call IsWitnessStandard
    Assert true
  Test: p2mr_transaction_accepted_by_mempool
    Submit valid P2MR transaction to test mempool
    Assert accepted

Run tests. Confirm FAIL.

STEP 7.2 - UPDATE ISSTANDARD

File: src/policy/policy.cpp
  In IsStandard():
    Modify the output script type checks:
    Only allow TxoutType::WITNESS_V2_P2MR (and NULL_DATA for OP_RETURN)
    Reject P2PKH, P2SH, P2WPKH, P2WSH, P2TR as non-standard
  In IsWitnessStandard():
    Add witness v2 validation:
    Verify witness stack format matches P2MR expectations
    Verify control block is well-formed

File: src/script/solver.cpp
  Add TxoutType::WITNESS_V2_P2MR to Solver():
    Recognize OP_2 <32 bytes> as P2MR output type
    Return the 32-byte program as solution

STEP 7.3 - RUN TESTS

Command: make -j$(nproc) && src/test/test_btx --run_test=pq_policy_tests
  All 6 tests must pass.

CHECKPOINT 7: Mempool only accepts P2MR transactions.


========================================================================
PHASE 8: GENESIS BLOCK UPDATE
========================================================================
Estimated: ~100 lines.

STEP 8.1 - WRITE GENESIS TESTS

File: src/test/pq_genesis_tests.cpp (NEW)
  Test suite: pq_genesis_tests
  Test: genesis_coinbase_is_p2mr
    Load mainnet genesis block
    Extract coinbase transaction output script
    Assert script matches OP_2 <32 bytes> (P2MR format)
  Test: genesis_block_valid
    Load genesis block
    Validate block header (hash, merkle root, nBits, timestamp)
    Assert CheckBlock passes
  Test: genesis_coinbase_amount_correct
    Assert coinbase output value == nInitialSubsidy (20 BTX)
  Test: regtest_genesis_is_p2mr
    Same checks for regtest genesis

Run tests. Confirm FAIL.

STEP 8.2 - GENERATE GENESIS PQ KEYPAIR

Create a script or tool that:
  1. Generates an ML-DSA-44 keypair for genesis coinbase
  2. Generates an SLH-DSA-SHAKE-128s keypair for genesis backup leaf
  3. Builds the default 2-leaf P2MR merkle tree
  4. Outputs the 32-byte merkle root
  5. Constructs the genesis coinbase script: OP_2 <merkle_root>
  6. Prints all values for embedding in chainparams.cpp

Store genesis PQ private key securely (or use a known-unspendable
commitment if the genesis coinbase should be unspendable, which is
conventional).

For an unspendable genesis (recommended, following Bitcoin convention):
  Use a deterministic but unspendable commitment:
  merkle_root = SHA256("BTX P2MR Genesis - Quantum Safe Since Block 0")
  This makes the genesis coinbase provably unspendable since no one
  has PQ keys corresponding to this arbitrary hash.

STEP 8.3 - UPDATE GENESIS BLOCK IN CHAINPARAMS

File: src/kernel/chainparams.cpp
  In CreateGenesisBlock function:
    Replace the existing coinbase script (which uses ECDSA pubkey)
    with the P2MR genesis script: OP_2 <genesis_merkle_root>
  Update genesis block parameters:
    hashMerkleRoot (recomputed)
    hashGenesisBlock (recomputed by mining genesis with new content)
    nBits (keep current or adjust per prior calibration work)

  Update for all networks: mainnet, testnet, testnet4, regtest.
  Each network can share the same unspendable genesis merkle root
  or use network-specific commitments.

File: doc/btx-genesis-tuples.json
  Update all genesis hashes to reflect new P2MR coinbase.

File: scripts/verify_btx_todo_closure.py
  Update defaultAssumeValid hashes.

STEP 8.4 - RUN TESTS

Command: make -j$(nproc) && src/test/test_btx --run_test=pq_genesis_tests
  All 4 tests must pass.
Also run: src/test/test_btx
  Full test suite must pass with new genesis.

CHECKPOINT 8: Genesis block uses P2MR. Chain boots from quantum-safe block 0.


========================================================================
PHASE 9: RPC AND CLI INTEGRATION
========================================================================
Estimated: ~200 lines.

STEP 9.1 - WRITE RPC TESTS

File: test/functional/rpc_pq_wallet.py (NEW)
  Test: test_getnewaddress_returns_p2mr
    Call getnewaddress with address_type="p2mr"
    Assert address starts with "btx1z"
  Test: test_getnewaddress_default_is_p2mr
    Call getnewaddress with no address_type
    Assert address starts with "btx1z"
  Test: test_validateaddress_p2mr
    Generate P2MR address
    Call validateaddress
    Assert isvalid=true, witness_version=2, isscript=false
  Test: test_sendtoaddress_p2mr
    Mine blocks to get spendable coins
    Send to a P2MR address
    Assert transaction is created and broadcast
    Mine a block, confirm transaction
  Test: test_getblocktemplate_shows_pq_params
    Call getblocktemplate
    Assert response includes pq_algorithm field
    Assert block capacity shows 24 MWU weight limit
  Test: test_decodescript_p2mr
    Decode a P2MR output script
    Assert type shows "witness_v2_p2mr"

STEP 9.2 - UPDATE RPC METHODS

File: src/rpc/mining.cpp
  In getblocktemplate (around line 1229-1246):
    Add pq_info object:
      "pq_algorithm": "ml-dsa-44"
      "pq_backup_algorithm": "slh-dsa-shake-128s"
      "pq_pubkey_size": 1312
      "pq_signature_size": 2420
    Add min_dimension, max_dimension (from prior audit findings)
    Update block_capacity to show new 24 MWU values

File: src/rpc/output_script.cpp
  In decodescript and validateaddress:
    Add handling for witness_v2_p2mr type
    Show "witness_version": 2 in output

File: src/wallet/rpc/addresses.cpp
  In getnewaddress:
    Accept "p2mr" as valid address_type string
    Default to P2MR when no type specified

STEP 9.3 - RUN FUNCTIONAL TESTS

Command: test/functional/rpc_pq_wallet.py
  All 6 tests must pass.
Command: test/functional/test_runner.py
  Run full functional test suite, note any failures from changed defaults.
  Fix tests that assume non-P2MR address types.

CHECKPOINT 9: All RPC and CLI interfaces support P2MR.


========================================================================
PHASE 10: CONSTANT-TIME HARDENING
========================================================================
Estimated: ~500 lines of hardening in libbitcoinpqc wrapper.

STEP 10.1 - WRITE TIMING TESTS

File: src/test/pq_timing_tests.cpp (NEW)
  Test suite: pq_timing_tests
  Test: mldsa_sign_constant_time
    Sign 1000 different messages
    Record CPU cycle count for each (using rdtsc or clock_gettime)
    Compute standard deviation of timing
    Assert std_dev / mean < threshold (eg 0.05)
    This is a statistical test: timing should not depend on message content
  Test: mldsa_verify_constant_time
    Verify 1000 valid signatures
    Assert timing variance is within threshold
  Test: key_comparison_constant_time
    Compare 1000 key pairs using secure_memcmp
    Assert timing does not correlate with number of matching bytes
  Test: key_zeroization_complete
    Generate key, copy raw bytes, zeroize key
    Assert all copied byte positions are now zero in original buffer
    (Read back from secure buffer before zeroization to verify)

STEP 10.2 - IMPLEMENT HARDENING

File: src/pqkey.cpp (modify)
  Replace any branching on secret data with constant-time operations:
    Use sodium_memcmp or custom ct_memcmp for comparisons
    Use ct_select/ct_cmov for conditional operations

File: src/crypto/ct_utils.h (NEW)
  Implement constant-time utilities:
    ct_memcmp(a, b, len): compare without early exit
    ct_select(condition, a, b): branchless selection
    ct_is_zero(x): branchless zero check
    secure_memzero(ptr, len): guaranteed not optimized away
  These wrap compiler intrinsics or volatile operations.

File: src/pqkey.cpp
  In CPQKey::Sign:
    Use hedged signing: hash(secret_key || random_nonce || message) as
    internal randomness, preventing nonce reuse even if RNG fails
  In CPQKey destructor and ClearKeyData:
    Call secure_memzero, not regular memset
    Use volatile pointer or memory barrier to prevent optimization

STEP 10.3 - RUN TIMING TESTS

Command: make -j$(nproc) && src/test/test_btx --run_test=pq_timing_tests
  All 4 tests must pass.
  Note: timing tests may be flaky on loaded systems. Run on quiet machine.

CHECKPOINT 10: PQ implementation is hardened against side-channel attacks.


========================================================================
PHASE 11: INTEGRATION TESTING AND FUZZING
========================================================================

STEP 11.1 - END-TO-END FUNCTIONAL TESTS

File: test/functional/p2mr_end_to_end.py (NEW)
  Test: test_mine_and_spend_p2mr
    Start regtest node
    Create wallet
    Mine 101 blocks (coinbase maturity)
    Get new P2MR address
    Send coins to P2MR address
    Mine block to confirm
    Send from P2MR address to another P2MR address
    Mine block to confirm
    Verify both transactions in blockchain
    Verify UTXO set is correct

  Test: test_multiple_wallets_p2mr
    Start 2 regtest nodes connected to each other
    Create wallet on each
    Mine on node 1
    Send from node 1 to node 2 P2MR address
    Mine on node 2
    Verify node 2 has balance
    Send back from node 2 to node 1
    Verify round-trip works

  Test: test_reorg_p2mr
    Mine competing chains
    Verify P2MR transactions survive reorg correctly
    Verify mempool returns disconnected P2MR transactions

  Test: test_p2mr_block_full_capacity
    Create many P2MR transactions filling a block near 24 MWU
    Mine block
    Verify all transactions included and valid

STEP 11.2 - FUZZ TARGETS

File: src/test/fuzz/pq_script_verify.cpp (NEW)
  Fuzz target: p2mr_script_verification
    Generate random witness stacks
    Run through VerifyWitnessProgram with version 2
    Assert no crashes, no undefined behavior
    Assert consistent error handling

File: src/test/fuzz/pq_merkle.cpp (NEW)
  Fuzz target: p2mr_merkle_tree
    Generate random leaf scripts and control blocks
    Run through VerifyP2MRCommitment
    Assert no crashes

File: src/test/fuzz/pq_descriptor_parse.cpp (NEW)
  Fuzz target: mr_descriptor_parsing
    Feed random strings to Parse("mr(...)")
    Assert no crashes, proper error handling

STEP 11.3 - RUN FULL TEST SUITE

Command: make -j$(nproc) check
  All unit tests must pass.

Command: test/functional/test_runner.py
  All functional tests must pass.
  Update any tests that assumed non-P2MR defaults.

Command: Run fuzz targets for minimum 1 hour each:
  src/test/fuzz/pq_script_verify
  src/test/fuzz/pq_merkle
  src/test/fuzz/pq_descriptor_parse

STEP 11.4 - DOCUMENTATION UPDATE

File: doc/btx-matmul-pow-spec.md
  Add section on P2MR (BIP-360) integration:
    Witness version 2 consensus rules
    ML-DSA-44 and SLH-DSA-SHAKE-128s parameters
    Default 2-leaf wallet tree structure
    Address format: btx1z...
    Block parameters: 12 MB / 24 MWU / 90s

File: doc/btx-pqc-spec.md (NEW)
  Full specification of BTX post-quantum cryptography:
    Algorithm choices and rationale
    Sighash computation
    Merkle tree construction
    Opcode semantics (OP_CHECKSIG_MLDSA, OP_CHECKSIG_SLHDSA)
    Wallet descriptor format
    HD key derivation for PQ keys
    Constant-time implementation requirements

CHECKPOINT 11: Full integration tests pass. Chain is quantum-safe from genesis.


========================================================================
SUMMARY OF ALL NEW AND MODIFIED FILES
========================================================================

NEW FILES (17):
  src/pqkey.h                           PQ key class declarations
  src/pqkey.cpp                         PQ key implementation
  src/script/pqm.h                      P2MR constants and Merkle functions
  src/script/pqm.cpp                    P2MR Merkle implementation
  src/crypto/ct_utils.h                 Constant-time utilities
  src/test/pq_crypto_tests.cpp          PQ primitive tests
  src/test/pq_merkle_tests.cpp          Merkle tree tests
  src/test/pq_address_tests.cpp         Address encoding tests
  src/test/pq_consensus_tests.cpp       Consensus validation tests
  src/test/pq_descriptor_tests.cpp      Descriptor parsing tests
  src/test/pq_policy_tests.cpp          Policy enforcement tests
  src/test/pq_genesis_tests.cpp         Genesis block tests
  src/test/pq_timing_tests.cpp          Constant-time tests
  src/wallet/test/pq_wallet_tests.cpp   Wallet integration tests
  src/test/fuzz/pq_script_verify.cpp    Fuzz: script verification
  src/test/fuzz/pq_merkle.cpp           Fuzz: merkle tree
  src/test/fuzz/pq_descriptor_parse.cpp Fuzz: descriptor parsing
  test/functional/rpc_pq_wallet.py      RPC functional tests
  test/functional/p2mr_end_to_end.py    End-to-end functional tests
  doc/btx-pqc-spec.md                   PQC specification

MODIFIED FILES (~25):
  src/consensus/consensus.h             Block size and weight constants
  src/consensus/params.h                Timing and capacity parameters
  src/kernel/chainparams.cpp            All network parameters + genesis
  src/addresstype.h                     WitnessV2P2MR type + CTxDestination
  src/addresstype.cpp                   Script/destination conversion
  src/outputtype.h                      P2MR enum + OUTPUT_TYPES
  src/outputtype.cpp                    Parse/format/convert functions
  src/key_io.cpp                        Bech32m encode/decode for btx1z
  src/script/interpreter.h              SigVersion::P2MR + constants
  src/script/interpreter.cpp            Witness v2 execution + PQ opcodes
  src/script/script.h                   OP_CHECKSIG_MLDSA/SLHDSA opcodes
  src/script/script.cpp                 Remove 187-188 from IsOpSuccess
  src/script/script_error.h             New error codes
  src/script/sign.h                     PQ key types in SignatureData
  src/script/sign.cpp                   PQ signing path
  src/script/solver.cpp                 WITNESS_V2_P2MR type
  src/script/descriptor.cpp             MRDescriptor class + parser
  src/wallet/walletutil.cpp             P2MR descriptor generation
  src/wallet/wallet.h                   DEFAULT_ADDRESS_TYPE = P2MR
  src/wallet/wallet.cpp                 Wallet setup (auto via OUTPUT_TYPES)
  src/wallet/scriptpubkeyman.h/cpp      PQ key provider
  src/wallet/walletdb.h/cpp             PQ key persistence
  src/wallet/spend.cpp                  P2MR weight estimation
  src/policy/policy.cpp                 P2MR-only standard policy
  src/rpc/mining.cpp                    PQ info in getblocktemplate
  src/CMakeLists.txt                    libbitcoinpqc + new source files
  src/test/matmul_dgw_tests.cpp         Updated timing assertions
  src/test/matmul_block_capacity_tests.cpp  Updated size assertions
  doc/btx-matmul-pow-spec.md            Updated parameters + PQC section
  doc/btx-genesis-tuples.json           New genesis hashes
  scripts/verify_btx_todo_closure.py    Updated hashes

ESTIMATED TOTAL: ~3500 lines new code, ~500 lines modified, 11 checkpoints.

EXECUTION SEQUENCE:
  Phase 0  -> Phase 1  -> Phase 2  -> Phase 3  -> Phase 4
  (params)   (library)   (merkle)   (address)   (consensus)

  Phase 5  -> Phase 6  -> Phase 7  -> Phase 8
  (descriptor) (wallet)  (policy)   (genesis)

  Phase 9  -> Phase 10 -> Phase 11
  (rpc)      (harden)    (integration)

Each phase depends on prior phases. Do not skip ahead.
Each step within a phase follows TDD: test first, code second.
Run the full test suite at every checkpoint before proceeding.
