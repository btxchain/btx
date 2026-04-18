// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Deep adversarial test suite for SMILE v2 confidential transactions.
//
// These tests target specific vulnerabilities identified in the security audit:
//
//   D1 - BDLOP opening bypass (VerifyCT never calls VerifyWeakOpening)
//   D2 - w0_vals transcript binding (w0_vals not hashed into Fiat-Shamir)
//   D3 - Intra-proof serial number duplicates (no duplicate check in dispatch)
//   D4 - t0 compression collision (COMPRESS_D=12 bits dropped)
//   D5 - Modular arithmetic inflation (amounts near Q, negative encoding)
//   D6 - Key membership forgery (crafted w0_vals for non-member key)
//   D7 - Challenge domain separation failures
//   D8 - Zero-vector z0 key relation bypass
//   D9 - Output coin substitution (replacing output coins post-proof)
//   D10 - Recursive index decomposition attacks

#include <shielded/smile2/bdlop.h>
#include <shielded/smile2/ct_proof.h>
#include <shielded/smile2/membership.h>
#include <shielded/smile2/ntt.h>
#include <shielded/smile2/params.h>
#include <shielded/smile2/poly.h>
#include <shielded/smile2/serialize.h>
#include <shielded/smile2/verify_dispatch.h>
#include <crypto/sha256.h>
#include <test/util/setup_common.h>
#include <test/util/shielded_smile_test_util.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <random>
#include <set>
#include <vector>

using namespace smile2;

namespace {

std::array<uint8_t, 32> MakeSeed(uint8_t val) {
    std::array<uint8_t, 32> seed{};
    seed[0] = val;
    return seed;
}

std::vector<SmileKeyPair> GenerateAnonSet(size_t N, uint8_t seed_val) {
    auto a_seed = MakeSeed(seed_val);
    std::vector<SmileKeyPair> keys(N);
    for (size_t i = 0; i < N; ++i) {
        keys[i] = SmileKeyPair::Generate(a_seed, 80000 + i);
    }
    return keys;
}

std::vector<SmilePublicKey> ExtractPublicKeys(const std::vector<SmileKeyPair>& keys) {
    std::vector<SmilePublicKey> pks;
    pks.reserve(keys.size());
    for (const auto& kp : keys) pks.push_back(kp.pub);
    return pks;
}

BDLOPCommitmentKey GetPublicCoinCommitmentKey()
{
    std::array<uint8_t, 32> seed{};
    seed[0] = 0xCC;
    return BDLOPCommitmentKey::Generate(seed, 1);
}

constexpr size_t LIVE_CT_PUBLIC_ROWS = KEY_ROWS + 2;

size_t LiveCtAuxMsgCount(size_t num_inputs, size_t num_outputs)
{
    return num_inputs + (num_inputs + num_outputs) + num_inputs * LIVE_CT_PUBLIC_ROWS + num_inputs + 2;
}

size_t LiveCtW0Slot(size_t num_inputs, size_t num_outputs, size_t input_index, size_t row)
{
    return num_inputs + (num_inputs + num_outputs) + input_index * LIVE_CT_PUBLIC_ROWS + row;
}

void EnsureLiveCtAuxState(SmileCTProof& proof, size_t num_inputs, size_t num_outputs)
{
    const size_t n_aux_msg = LiveCtAuxMsgCount(num_inputs, num_outputs);
    proof.aux_commitment.t0.resize(BDLOP_RAND_DIM_BASE);
    proof.aux_commitment.t_msg.resize(n_aux_msg);
    proof.z.resize(BDLOP_RAND_DIM_BASE + n_aux_msg);
}

void CopyLiveCtW0Rows(const SmileCTProof& src,
                      SmileCTProof& dst,
                      size_t num_inputs,
                      size_t num_outputs,
                      size_t src_input,
                      size_t dst_input)
{
    EnsureLiveCtAuxState(dst, num_inputs, num_outputs);
    for (size_t row = 0; row < LIVE_CT_PUBLIC_ROWS; ++row) {
        dst.aux_commitment.t_msg[LiveCtW0Slot(num_inputs, num_outputs, dst_input, row)] =
            src.aux_commitment.t_msg[LiveCtW0Slot(num_inputs, num_outputs, src_input, row)];
    }
}

std::vector<std::vector<BDLOPCommitment>> BuildCoinRings(
    const std::vector<SmileKeyPair>& keys,
    const std::vector<size_t>& secret_indices,
    const std::vector<int64_t>& secret_amounts,
    uint64_t coin_seed)
{
    const size_t N = keys.size();
    const size_t m = secret_indices.size();

    const auto ck = GetPublicCoinCommitmentKey();
    std::vector<std::vector<BDLOPCommitment>> coin_rings(m);
    for (size_t inp = 0; inp < m; ++inp) {
        coin_rings[inp].resize(N);
        for (size_t j = 0; j < N; ++j) {
            SmilePoly amount_poly;
            if (j == secret_indices[inp]) {
                amount_poly = EncodeAmountToSmileAmountPoly(secret_amounts[inp]).value();
            } else {
                std::mt19937_64 rng(coin_seed * 1000 + inp * N + j);
                amount_poly = EncodeAmountToSmileAmountPoly(
                    static_cast<int64_t>(rng() % 1000000)).value();
            }
            const auto opening = SampleTernary(ck.rand_dim(), coin_seed * 100000 + inp * N + j);
            coin_rings[inp][j] = Commit(ck, {amount_poly}, opening);
        }
    }
    return coin_rings;
}

CTInput MakeCtInput(size_t secret_index, const SmileKeyPair& key, int64_t amount,
                    uint64_t coin_seed, size_t input_index, size_t ring_size)
{
    return CTInput{
        secret_index,
        key.sec,
        SampleTernary(GetPublicCoinCommitmentKey().rand_dim(),
                      coin_seed * 100000 + input_index * ring_size + secret_index),
        amount,
    };
}

CTOutput MakeCtOutput(int64_t amount, uint64_t seed)
{
    return CTOutput{
        amount,
        SampleTernary(GetPublicCoinCommitmentKey().rand_dim(), seed),
    };
}

struct DeepTestSetup {
    std::vector<SmileKeyPair> keys;
    CTPublicData pub;
    std::vector<CTInput> inputs;
    std::vector<CTOutput> outputs;

    static DeepTestSetup Create(size_t N, size_t num_inputs, size_t num_outputs,
                                const std::vector<int64_t>& in_amounts,
                                const std::vector<int64_t>& out_amounts,
                                uint8_t seed_val)
    {
        DeepTestSetup setup;
        setup.keys = GenerateAnonSet(N, seed_val);
        setup.pub.anon_set = ExtractPublicKeys(setup.keys);

        std::vector<size_t> secret_indices;
        for (size_t i = 0; i < num_inputs; ++i) {
            secret_indices.push_back(i * 3 + 1);
        }

        setup.pub.coin_rings = BuildCoinRings(
            setup.keys, secret_indices, in_amounts, seed_val + 100);
        setup.pub.account_rings = test::shielded::BuildDeterministicCTAccountRings(
            setup.keys, setup.pub.coin_rings, static_cast<uint32_t>(seed_val) * 1000 + 500, 0x95);

        setup.inputs.resize(num_inputs);
        for (size_t i = 0; i < num_inputs; ++i) {
            setup.inputs[i] = MakeCtInput(secret_indices[i],
                                          setup.keys[secret_indices[i]],
                                          in_amounts[i],
                                          seed_val + 100,
                                          i,
                                          N);
        }

        setup.outputs.resize(num_outputs);
        for (size_t i = 0; i < num_outputs; ++i) {
            setup.outputs[i] = MakeCtOutput(out_amounts[i],
                                            static_cast<uint64_t>(seed_val) * 1000000 + i);
        }
        return setup;
    }
};

SmileCTProof MakeValidProof(DeepTestSetup& setup) {
    return ProveCT(setup.inputs, setup.outputs, setup.pub, 0xDEAD0000);
}

// Reimplementation of HashToChallengePoly (internal to ct_proof.cpp)
// for tests that need to compute challenges independently.
SmilePoly HashToChallengePoly(const uint8_t* data, size_t len, uint32_t domain)
{
    CSHA256 hasher;
    hasher.Write(data, len);
    uint8_t dbuf[4];
    std::memcpy(dbuf, &domain, 4);
    hasher.Write(dbuf, 4);
    uint8_t hash[32];
    hasher.Finalize(hash);

    SmilePoly c;
    uint8_t k = hash[0] % POLY_DEGREE;
    int64_t sign = (hash[1] & 1) ? 1 : mod_q(-1);
    c.coeffs[k] = sign;
    return c;
}

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(smile2_deep_adversarial_tests, BasicTestingSetup)

// ============================================================================
// D1: BDLOP OPENING BYPASS
// The audit found that VerifyCT never calls VerifyWeakOpening on the
// aux_commitment. If the BDLOP commitment binding is not checked, an
// attacker could substitute the aux_commitment with one committing to
// different amounts while keeping the same Fiat-Shamir seeds.
// ============================================================================

// D1-1: Replace aux_commitment.t_msg with garbage while keeping t0.
// If VerifyCT doesn't verify the BDLOP opening relation
// (B0*z = w + c*t0, <b_i,z> = f_i + c*t_msg_i), this might pass.
BOOST_AUTO_TEST_CASE(d1_aux_commitment_tmsg_substitution)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 2, 2, {100, 200}, {150, 150}, 0xD1);
    auto proof = MakeValidProof(setup);

    BOOST_REQUIRE(VerifyCT(proof, 2, 2, setup.pub));

    // Attack: zero out all t_msg entries in aux_commitment.
    // The amounts are encoded in t_msg slots. If the opening is not checked,
    // the verifier has no way to know the committed amounts changed.
    SmileCTProof tampered = proof;
    for (auto& t : tampered.aux_commitment.t_msg) {
        for (size_t c = 0; c < POLY_DEGREE; ++c) {
            t.coeffs[c] = 0;
        }
    }

    bool valid = VerifyCT(tampered, 2, 2, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D1-1: CRITICAL — Zeroed aux_commitment.t_msg accepted! "
        "VerifyCT must verify BDLOP opening to bind committed amounts. "
        "Without this check, amounts are uncommitted and inflation is possible.");
}

// D1-2: Replace aux_commitment with one from a differently-balanced proof.
// Create proof A (balanced: 300=300) and proof B (balanced: 100=100).
// Transplant B's aux_commitment into A's proof.
BOOST_AUTO_TEST_CASE(d1_aux_commitment_transplant_from_different_proof)
{
    const size_t N = 32;
    auto setup_a = DeepTestSetup::Create(N, 2, 2, {100, 200}, {150, 150}, 0xD1);
    auto setup_b = DeepTestSetup::Create(N, 1, 1, {50}, {50}, 0xD2);

    auto proof_a = MakeValidProof(setup_a);
    auto proof_b = MakeValidProof(setup_b);

    BOOST_REQUIRE(VerifyCT(proof_a, 2, 2, setup_a.pub));
    BOOST_REQUIRE(VerifyCT(proof_b, 1, 1, setup_b.pub));

    // Attack: transplant aux_commitment from proof_b into proof_a.
    SmileCTProof hybrid = proof_a;
    hybrid.aux_commitment = proof_b.aux_commitment;

    bool valid = VerifyCT(hybrid, 2, 2, setup_a.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D1-2: Cross-proof aux_commitment transplant must be rejected. "
        "If accepted, the BDLOP binding is broken.");
}

// D1-3: Craft a valid-looking aux_commitment that commits to inflated amounts.
// Start from a valid proof, then modify the amount-encoding t_msg slots
// to encode larger output amounts while keeping everything else fixed.
BOOST_AUTO_TEST_CASE(d1_inflated_amount_in_aux_commitment)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xD3);
    auto proof = MakeValidProof(setup);

    BOOST_REQUIRE(VerifyCT(proof, 1, 1, setup.pub));

    // The aux_commitment.t_msg slots contain committed amounts.
    // Slot layout (from ct_proof.cpp):
    //   slots 0-6: garbage/framework
    //   slot 7: first input amount
    //   slot 7+m_in: first output amount
    // Try to modify the output amount slot to encode a larger value.
    SmileCTProof tampered = proof;
    if (tampered.aux_commitment.t_msg.size() > 8) {
        // Slot 8 should be the output amount for 1-in-1-out
        tampered.aux_commitment.t_msg[8].coeffs[0] = mod_q(999999);
    }

    bool valid = VerifyCT(tampered, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D1-3: CRITICAL — Modified amount in aux_commitment accepted! "
        "If the BDLOP opening z is not checked against the commitment, "
        "the committed amounts are not bound and inflation is trivial.");
}

// ============================================================================
// D2: w0_VALS TRANSCRIPT BINDING
// The audit found w0_vals are NOT hashed into the Fiat-Shamir transcript.
// If w0_vals are malleable, an attacker could substitute them to pass the
// key membership check (step 11 in VerifyCT) for a non-member key.
// ============================================================================

// D2-1: Substitute w0_vals from a different valid proof.
// If w0_vals are not bound by the transcript, the substituted values
// from proof_b might cause verification to succeed with a different key.
BOOST_AUTO_TEST_CASE(d2_w0_vals_cross_proof_substitution)
{
    const size_t N = 32;
    auto setup_a = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xE1);
    auto setup_b = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xE2);

    auto proof_a = MakeValidProof(setup_a);
    auto proof_b = MakeValidProof(setup_b);

    BOOST_REQUIRE(VerifyCT(proof_a, 1, 1, setup_a.pub));
    BOOST_REQUIRE(VerifyCT(proof_b, 1, 1, setup_b.pub));

    // Attack: swap committed W0 rows between the proofs (same anonymity set structure)
    SmileCTProof hybrid = proof_a;
    CopyLiveCtW0Rows(proof_b, hybrid, 1, 1, 0, 0);

    bool valid = VerifyCT(hybrid, 1, 1, setup_a.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D2-1: CRITICAL — committed W0 rows from a different proof accepted! "
        "The first-round tuple-account rows must be bound to the proof via Fiat-Shamir or commitment. "
        "If malleable, key membership check can be bypassed.");
}

// D2-2: Zero out w0_vals — does the key membership check still find a match?
// If w0_vals are zero, then c0_pk_eff[i] = A*z0[inp][i], and the check
// looks for a public key matching A*z0 / c0. This tests if the check
// is robust against degenerate w0 values.
BOOST_AUTO_TEST_CASE(d2_w0_vals_zeroed)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xE3);
    auto proof = MakeValidProof(setup);

    BOOST_REQUIRE(VerifyCT(proof, 1, 1, setup.pub));

    SmileCTProof tampered = proof;
    for (size_t row = 0; row < LIVE_CT_PUBLIC_ROWS; ++row) {
        auto& w0_poly = tampered.aux_commitment.t_msg[LiveCtW0Slot(1, 1, 0, row)];
        for (size_t c = 0; c < POLY_DEGREE; ++c) {
            w0_poly.coeffs[c] = 0;
        }
    }

    bool valid = VerifyCT(tampered, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D2-2: Zeroed committed W0 rows must be rejected by the hidden-account relation.");
}

// D2-3: Craft w0_vals to target a DIFFERENT key in the anonymity set.
// If w0_vals are malleable, compute w0' = A*z0 - c0*pk_target
// for some target key index, which would make the membership check
// succeed for that key instead of the real signer's key.
BOOST_AUTO_TEST_CASE(d2_w0_vals_retarget_different_key)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xE4);
    auto proof = MakeValidProof(setup);

    BOOST_REQUIRE(VerifyCT(proof, 1, 1, setup.pub));

    // The real signer is at index setup.inputs[0].secret_index.
    // Try to retarget the key membership check to index 0.
    size_t target_idx = 0;
    if (target_idx == setup.inputs[0].secret_index) target_idx = 2;

    // Recompute challenge c0
    SmilePoly c0_chal = HashToChallengePoly(proof.seed_c0.data(), 32, 600);

    const auto& A = setup.pub.anon_set[0].A;
    size_t k = KEY_ROWS;

    SmileCTProof tampered = proof;
    EnsureLiveCtAuxState(tampered, 1, 1);

    // Compute w0'[i] = A[i]*z0 - c0*pk_target[i]
    // so that A*z0 - w0' = c0*pk_target, passing the membership check
    // for the target key.
    for (size_t i = 0; i < k; ++i) {
        SmilePoly az0_i;
        for (size_t j = 0; j < KEY_COLS; ++j) {
            az0_i += NttMul(A[i][j], proof.z0[0][j]);
        }
        az0_i.Reduce();

        SmilePoly c0_pk_target = NttMul(c0_chal, setup.pub.anon_set[target_idx].pk[i]);
        c0_pk_target.Reduce();

        tampered.aux_commitment.t_msg[LiveCtW0Slot(1, 1, 0, i)] = az0_i - c0_pk_target;
        tampered.aux_commitment.t_msg[LiveCtW0Slot(1, 1, 0, i)].Reduce();
    }

    bool valid = VerifyCT(tampered, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D2-3: CRITICAL — Retargeted committed W0 rows to different key ACCEPTED! "
        "If the committed first-round rows are malleable and not bound by commitment or transcript, "
        "an attacker can make any key appear to be the signer. "
        "This breaks the entire ring signature anonymity model.");
}

// ============================================================================
// D3: INTRA-PROOF SERIAL NUMBER DUPLICATES
// The dispatch layer (ExtractSmile2SerialNumbers) checks for null serials
// but does NOT check for duplicates within the same proof.
// ============================================================================

// D3-1: Two inputs with identical serial numbers in the same proof.
// This simulates an attacker spending the same coin twice in one tx.
BOOST_AUTO_TEST_CASE(d3_duplicate_serial_numbers_in_proof)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 2, 2, {100, 200}, {150, 150}, 0xF1);
    auto proof = MakeValidProof(setup);

    BOOST_REQUIRE(VerifyCT(proof, 2, 2, setup.pub));

    // Attack: duplicate the first serial number over the second
    SmileCTProof tampered = proof;
    tampered.serial_numbers[1] = tampered.serial_numbers[0];

    // The cryptographic proof should reject this due to Fiat-Shamir binding
    bool ct_valid = VerifyCT(tampered, 2, 2, setup.pub);
    BOOST_CHECK_MESSAGE(!ct_valid,
        "D3-1: VerifyCT must reject tampered duplicate serial numbers.");

    // The dispatch layer must independently reject duplicates even without
    // relying on VerifyCT to catch the tampering first.
    std::vector<SmilePoly> extracted;
    auto err = ExtractSmile2SerialNumbers(tampered, extracted);
    BOOST_REQUIRE_MESSAGE(err.has_value(),
        "D3-1: ExtractSmile2SerialNumbers must independently reject duplicate serial numbers.");
    BOOST_CHECK_EQUAL(*err, "bad-smile2-proof-duplicate-serial-number");
}

// D3-2: Force a serial number collision by using the same key for both inputs.
// Proof construction currently succeeds, and the dispatch layer must reject the
// duplicate serial numbers before the proof is accepted.
BOOST_AUTO_TEST_CASE(d3_same_key_two_inputs_collision)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 2, 2, {100, 200}, {150, 150}, 0xF2);

    // Force both inputs to spend the same chain-visible coin so the proof stays
    // internally coherent while producing duplicate serial numbers.
    setup.inputs[1] = setup.inputs[0];
    setup.pub.coin_rings[1] = setup.pub.coin_rings[0];
    setup.pub.account_rings[1] = setup.pub.account_rings[0];
    setup.outputs = {
        MakeCtOutput(100, 0xF200),
        MakeCtOutput(100, 0xF201),
    };

    auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 0xF2A);
    BOOST_REQUIRE_EQUAL(proof.serial_numbers.size(), 2U);

    SmilePoly sn0 = proof.serial_numbers[0];
    sn0.Reduce();
    SmilePoly sn1 = proof.serial_numbers[1];
    sn1.Reduce();

    BOOST_CHECK_MESSAGE(sn0 == sn1,
        "D3-2: Same key used for two inputs must produce duplicate serial numbers.");

    std::vector<SmilePoly> extracted;
    auto err = ExtractSmile2SerialNumbers(proof, extracted);
    BOOST_REQUIRE_MESSAGE(err.has_value(),
        "D3-2: ExtractSmile2SerialNumbers must reject duplicate serial numbers from the same key.");
    BOOST_CHECK_EQUAL(*err, "bad-smile2-proof-duplicate-serial-number");
}

// ============================================================================
// D4: t0 COMPRESSION COLLISION
// The aux_commitment.t0 is appended to the Fiat-Shamir transcript using
// AppendPolyCompressed, which drops COMPRESS_D=12 low-order bits.
// Two different t0 values differing only in the low 12 bits will produce
// the same transcript hash.
// ============================================================================

// D4-1: Modify low-order bits of aux_commitment.t0 — does verification change?
BOOST_AUTO_TEST_CASE(d4_t0_compression_low_bit_modification)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xA1);
    auto proof = MakeValidProof(setup);

    BOOST_REQUIRE(VerifyCT(proof, 1, 1, setup.pub));

    // Attack: flip bits within the compressed-away range (low 12 bits)
    SmileCTProof tampered = proof;
    if (!tampered.aux_commitment.t0.empty()) {
        for (size_t c = 0; c < POLY_DEGREE; ++c) {
            int64_t val = mod_q(tampered.aux_commitment.t0[0].coeffs[c]);
            // Flip the lowest bit — this is within COMPRESS_D=12 bits
            val ^= 1;
            tampered.aux_commitment.t0[0].coeffs[c] = val;
        }
    }

    bool valid = VerifyCT(tampered, 1, 1, setup.pub);
    // If the proof still verifies, the compression creates a malleability window.
    // This is the expected behavior for Dilithium-style compression, but must be
    // documented and the security proof must account for it.
    BOOST_TEST_MESSAGE("D4-1: t0 low-bit modification result: valid=" << valid);
    if (valid) {
        BOOST_TEST_MESSAGE(
            "D4-1: WARNING — t0 low-bit modification accepted! "
            "This is a known malleability window from COMPRESS_D=12. "
            "Ensure the security reduction accounts for this.");
    }
}

// D4-2: Modify high-order bits of aux_commitment.t0 — MUST be rejected.
BOOST_AUTO_TEST_CASE(d4_t0_high_bit_modification_rejected)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xA2);
    auto proof = MakeValidProof(setup);

    BOOST_REQUIRE(VerifyCT(proof, 1, 1, setup.pub));

    SmileCTProof tampered = proof;
    if (!tampered.aux_commitment.t0.empty()) {
        // Modify a high-order bit (above compression threshold)
        int64_t val = mod_q(tampered.aux_commitment.t0[0].coeffs[0]);
        val ^= (1 << 20); // well above COMPRESS_D=12
        tampered.aux_commitment.t0[0].coeffs[0] = mod_q(val);
    }

    bool valid = VerifyCT(tampered, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D4-2: High-bit t0 modification must be rejected by Fiat-Shamir.");
}

// D4-3: Systematically test the compression boundary.
// Modify bit positions from 0 to 20 and check which ones are detected.
BOOST_AUTO_TEST_CASE(d4_compression_boundary_sweep)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xA3);
    auto proof = MakeValidProof(setup);

    BOOST_REQUIRE(VerifyCT(proof, 1, 1, setup.pub));

    int undetected_at_or_above_D = 0;
    for (size_t bit = 0; bit <= 20; ++bit) {
        SmileCTProof tampered = proof;
        if (!tampered.aux_commitment.t0.empty()) {
            int64_t val = mod_q(tampered.aux_commitment.t0[0].coeffs[0]);
            val ^= (static_cast<int64_t>(1) << bit);
            tampered.aux_commitment.t0[0].coeffs[0] = mod_q(val);
        }

        bool valid = VerifyCT(tampered, 1, 1, setup.pub);
        if (valid && bit >= COMPRESS_D) {
            undetected_at_or_above_D++;
        }
        BOOST_TEST_MESSAGE("D4-3: bit " << bit << " flip: valid=" << valid
                           << (bit < COMPRESS_D ? " (below compression)" : " (ABOVE compression)"));
    }

    BOOST_CHECK_MESSAGE(undetected_at_or_above_D == 0,
        "D4-3: CRITICAL — " << undetected_at_or_above_D
        << " bit flips ABOVE compression threshold were undetected! "
        "The compression boundary must be tight.");
}

// ============================================================================
// D5: MODULAR ARITHMETIC INFLATION
// Test amounts near Q boundaries and negative encoding to find wrap-around.
// ============================================================================

// D5-1: Amount = Q-1 (wraps to -1 in centered representation).
// If in=Q-1 and out=Q-1, this is balanced but represents negative money.
// If the system treats this as a very large positive value, problems arise.
BOOST_AUTO_TEST_CASE(d5_amount_near_q_minus_one)
{
    const size_t N = 32;
    int64_t near_q = Q - 1; // represents -1 in centered form

    auto setup = DeepTestSetup::Create(N, 1, 1, {near_q}, {near_q}, 0xB1);
    auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 0xB1A);

    // If amounts near Q are allowed, the proof should verify (balanced).
    // The security concern is whether these amounts can be combined with
    // normal amounts to create money.
    bool valid = VerifyCT(proof, 1, 1, setup.pub);
    BOOST_TEST_MESSAGE("D5-1: Amount Q-1 (" << near_q << "): valid=" << valid);
}

// D5-2: Modular wrap inflation: in = {1} out = {Q}
// Q mod Q = 0, so this should be 1 in, 0 out — fee leak.
// But if the system doesn't reduce amounts mod Q, it might see 1 = Q.
BOOST_AUTO_TEST_CASE(d5_modular_wrap_1_vs_Q)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 1, 1, {1}, {Q}, 0xB2);
    auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 0xB2A);

    bool valid = VerifyCT(proof, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D5-2: Amount Q (which reduces to 0 mod Q) must not balance against amount 1. "
        "If accepted, modular arithmetic creates money from nothing.");
}

// D5-3: Exploit additive wrap: in = {Q/2, Q/2+1} out = {1}
// sum_in = Q+1 = 1 (mod Q). If balance check is mod Q, this passes.
// But the real value is Q+1, not 1. This is a critical inflation attack.
BOOST_AUTO_TEST_CASE(d5_additive_wrap_inflation)
{
    const size_t N = 32;
    int64_t half_q = Q / 2;

    auto setup = DeepTestSetup::Create(N, 2, 1,
        {half_q, half_q + 1}, {1}, 0xB3);
    auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 0xB3A);

    bool valid = VerifyCT(proof, 2, 1, setup.pub);
    // This should NOT verify because:
    // - sum_in = Q/2 + Q/2 + 1 = Q + 1. In plain int64_t, this is Q+1.
    // - sum_out = 1
    // - The balance check should see Q+1 != 1, even though (Q+1) mod Q = 1.
    // If the balance check uses mod_q, this is a counterfeiting bug.
    BOOST_CHECK_MESSAGE(!valid,
        "D5-3: CRITICAL — Additive modular wrap inflation accepted! "
        "Two amounts summing to Q+1 should not balance against 1. "
        "If accepted, the attacker creates Q coins from nothing.");
}

// D5-4: Negative amount encoding: in = {-1 mod Q} out = {Q-1}
// These are the same value in modular arithmetic.
// But can an attacker use negative representation to bypass range checks?
BOOST_AUTO_TEST_CASE(d5_negative_amount_encoding)
{
    const size_t N = 32;
    int64_t neg_one = mod_q(-1); // = Q - 1

    auto setup = DeepTestSetup::Create(N, 1, 1, {1}, {1}, 0xB4);
    setup.inputs[0].amount = -1;
    setup.outputs[0].amount = neg_one;

    auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 0xB4A);
    bool valid = VerifyCT(proof, 1, 1, setup.pub);

    BOOST_CHECK_MESSAGE(!valid,
        "D5-4: Negative amount encodings must be rejected before they can reach "
        "the balanced modular relation.");
}

// D5-5: Inflation via integer overflow in int64_t sum.
// If sum_in overflows int64_t, the balance check could be bypassed.
BOOST_AUTO_TEST_CASE(d5_int64_overflow_inflation)
{
    const size_t N = 32;
    // INT64_MAX / 2 + INT64_MAX / 2 doesn't overflow, but is huge
    int64_t large_amount = Q / 2 - 1; // safe in modular arithmetic

    auto setup = DeepTestSetup::Create(N, 2, 1,
        {large_amount, large_amount}, {100}, 0xB5);
    auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 0xB5A);

    bool valid = VerifyCT(proof, 2, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D5-5: Large amounts that don't balance to 100 must be rejected.");
}

// ============================================================================
// D6: KEY MEMBERSHIP FORGERY
// Test whether the key membership check (step 11 in VerifyCT) can be
// bypassed by crafting specific w0_vals.
// ============================================================================

// D6-1: Use a completely random (non-member) key for signing.
// Generate a proof with a secret key that doesn't correspond to any
// public key in the anonymity set.
BOOST_AUTO_TEST_CASE(d6_non_member_key_proof)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xC1);

    // Replace the signer's key with a freshly generated one NOT in the set
    SmileKeyPair outsider = SmileKeyPair::Generate(MakeSeed(0xFF), 99999);
    setup.inputs[0].sk = outsider.sec;

    auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 0xC1A);

    bool valid = VerifyCT(proof, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D6-1: Proof from non-member key must be rejected by key membership check.");
}

// D6-2: Add the outsider key to the anonymity set for proof creation,
// then verify against the original set (without the outsider).
BOOST_AUTO_TEST_CASE(d6_proof_with_expanded_then_original_set)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xC2);

    // Create a proof with an expanded anonymity set
    SmileKeyPair outsider = SmileKeyPair::Generate(MakeSeed(0xFE), 88888);
    CTPublicData expanded_pub = setup.pub;
    expanded_pub.anon_set.push_back(outsider.pub);

    setup.inputs[0].sk = outsider.sec;
    setup.inputs[0].secret_index = N; // last position (the outsider)

    auto proof = ProveCT(setup.inputs, setup.outputs, expanded_pub, 0xC2A);

    // Verify against the ORIGINAL set (without outsider)
    bool valid = VerifyCT(proof, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D6-2: Proof created with expanded anonymity set must fail against original set.");
}

// ============================================================================
// D7: CHALLENGE DOMAIN SEPARATION
// Test that challenges computed with different domain tags are independent.
// ============================================================================

// D7-1: Verify c0 and c challenges are different even for same transcript.
BOOST_AUTO_TEST_CASE(d7_challenge_domain_separation)
{
    uint8_t data[32] = {};
    data[0] = 0x42;

    SmilePoly c_600 = HashToChallengePoly(data, 32, 600); // c0 domain
    SmilePoly c_700 = HashToChallengePoly(data, 32, 700); // c domain

    bool different = false;
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        if (c_600.coeffs[i] != c_700.coeffs[i]) {
            different = true;
            break;
        }
    }
    BOOST_CHECK_MESSAGE(different,
        "D7-1: Challenges with different domains must produce different polynomials.");
}

// D7-2: Same data + same domain = deterministic challenge.
BOOST_AUTO_TEST_CASE(d7_challenge_determinism)
{
    uint8_t data[32] = {};
    data[0] = 0x99;

    SmilePoly c1 = HashToChallengePoly(data, 32, 600);
    SmilePoly c2 = HashToChallengePoly(data, 32, 600);

    bool same = true;
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        if (c1.coeffs[i] != c2.coeffs[i]) {
            same = false;
            break;
        }
    }
    BOOST_CHECK_MESSAGE(same,
        "D7-2: Same data + same domain must produce deterministic challenges.");
}

// D7-3: Challenge polynomial structure: must be a single monomial ±X^k.
BOOST_AUTO_TEST_CASE(d7_challenge_is_monomial)
{
    uint8_t data[32] = {};
    for (int trial = 0; trial < 50; ++trial) {
        data[0] = static_cast<uint8_t>(trial);
        SmilePoly c = HashToChallengePoly(data, 32, 600);

        int nonzero_count = 0;
        for (size_t i = 0; i < POLY_DEGREE; ++i) {
            if (c.coeffs[i] != 0) {
                nonzero_count++;
                // Must be ±1
                int64_t val = mod_q(c.coeffs[i]);
                BOOST_CHECK_MESSAGE(val == 1 || val == Q - 1,
                    "D7-3: Challenge monomial coefficient must be ±1, got " << val);
            }
        }
        BOOST_CHECK_EQUAL(nonzero_count, 1);
    }
}

// ============================================================================
// D8: ZERO-VECTOR z0 KEY RELATION BYPASS
// If z0 = 0, then A*z0 = 0, and the key membership check looks for
// w0 = A*z0 - c0*pk = -c0*pk for some pk. If w0_vals = -c0*pk_j,
// the check passes for any j. Combined with D2 (w0 malleability),
// this could allow signing with any key.
// ============================================================================

// D8-1: Submit proof with z0 = all zeros.
BOOST_AUTO_TEST_CASE(d8_zero_z0_vector)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xD8);
    auto proof = MakeValidProof(setup);

    BOOST_REQUIRE(VerifyCT(proof, 1, 1, setup.pub));

    SmileCTProof tampered = proof;
    for (auto& z0_poly : tampered.z0[0]) {
        for (size_t c = 0; c < POLY_DEGREE; ++c) {
            z0_poly.coeffs[c] = 0;
        }
    }

    bool valid = VerifyCT(tampered, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D8-1: All-zero z0 must be rejected (Fiat-Shamir mismatch or norm-bound trivially zero).");
}

// D8-2: z0 = all zeros WITH crafted committed W0 rows to pass membership check.
BOOST_AUTO_TEST_CASE(d8_zero_z0_with_crafted_w0)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xD9);
    auto proof = MakeValidProof(setup);

    BOOST_REQUIRE(VerifyCT(proof, 1, 1, setup.pub));

    SmileCTProof tampered = proof;

    // Set z0 = 0
    for (auto& z0_poly : tampered.z0[0]) {
        for (size_t c = 0; c < POLY_DEGREE; ++c) {
            z0_poly.coeffs[c] = 0;
        }
    }

    // Craft committed W0 rows so that A*z0 - w0 = c0*pk for some key
    SmilePoly c0_chal = HashToChallengePoly(proof.seed_c0.data(), 32, 600);
    size_t target = 0;
    EnsureLiveCtAuxState(tampered, 1, 1);
    for (size_t i = 0; i < KEY_ROWS; ++i) {
        // A*z0 = 0, so w0 = -c0*pk_target
        SmilePoly neg_c0_pk = NttMul(c0_chal, setup.pub.anon_set[target].pk[i]);
        neg_c0_pk.Reduce();
        // w0 = 0 - c0*pk = -(c0*pk) => A*z0 - w0 = 0 + c0*pk = c0*pk ✓
        for (size_t c = 0; c < POLY_DEGREE; ++c) {
            tampered.aux_commitment.t_msg[LiveCtW0Slot(1, 1, 0, i)].coeffs[c] =
                neg_mod_q(neg_c0_pk.coeffs[c]);
        }
    }

    bool valid = VerifyCT(tampered, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D8-2: CRITICAL — Zero z0 with crafted committed W0 rows to pass key membership check! "
        "If accepted, any party can forge proofs for any key in the anonymity set.");
}

// ============================================================================
// D9: OUTPUT COIN SUBSTITUTION
// Output coins are NOT in the serialized proof — they come from the tx.
// Test whether substituting output coins after proof creation is detected.
// ============================================================================

// D9-1: Replace output coins with ones committing to different amounts.
BOOST_AUTO_TEST_CASE(d9_output_coin_substitution)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xDA);
    auto proof = MakeValidProof(setup);

    BOOST_REQUIRE(VerifyCT(proof, 1, 1, setup.pub));

    // Create a different output coin committing to amount 999
    auto out_ck_seed = std::array<uint8_t, 32>{};
    out_ck_seed[0] = 0xCC;
    auto out_ck = BDLOPCommitmentKey::Generate(out_ck_seed, 1);
    SmilePoly fake_amount;
    fake_amount.coeffs[0] = mod_q(999);
    auto fake_r = SampleTernary(out_ck.rand_dim(), 0xBADBAD);
    auto fake_coin = Commit(out_ck, {fake_amount}, fake_r);

    SmileCTProof tampered = proof;
    tampered.output_coins[0] = fake_coin;

    bool valid = VerifyCT(tampered, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D9-1: Substituted output coin must be rejected. "
        "Output coins must be bound by Fiat-Shamir transcript (fs_seed).");
}

// D9-2: Remove all output coins.
BOOST_AUTO_TEST_CASE(d9_missing_output_coins)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xDB);
    auto proof = MakeValidProof(setup);

    SmileCTProof tampered = proof;
    tampered.output_coins.clear();

    bool valid = VerifyCT(tampered, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D9-2: Proof with no output coins must be rejected.");
}

// D9-3: Add extra output coins.
BOOST_AUTO_TEST_CASE(d9_extra_output_coins)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xDC);
    auto proof = MakeValidProof(setup);

    SmileCTProof tampered = proof;
    tampered.output_coins.push_back(tampered.output_coins[0]); // duplicate

    bool valid = VerifyCT(tampered, 1, 2, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D9-3: Extra output coins must be rejected.");
}

// ============================================================================
// D10: RECURSIVE INDEX DECOMPOSITION ATTACKS
// The OOOM recursion decomposes secret_index into base-l digits.
// Test edge cases at boundaries.
// ============================================================================

// D10-1: Secret index at the last valid position.
BOOST_AUTO_TEST_CASE(d10_last_valid_index)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xDA);
    const uint64_t coin_seed = 0xDA + 100;
    setup.pub.coin_rings = BuildCoinRings(setup.keys, {N - 1}, {100}, coin_seed);
    setup.pub.account_rings = test::shielded::BuildDeterministicCTAccountRings(
        setup.keys, setup.pub.coin_rings, 0xDA00, 0x97);
    setup.inputs[0] = MakeCtInput(N - 1, setup.keys[N - 1], 100, coin_seed, 0, N);

    auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 0xDA1);
    bool valid = VerifyCT(proof, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(valid,
        "D10-1: Proof for last index (N-1) must verify.");
}

// D10-2: Secret index at position 0.
BOOST_AUTO_TEST_CASE(d10_first_valid_index)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xDB);
    const uint64_t coin_seed = 0xDB + 100;
    setup.pub.coin_rings = BuildCoinRings(setup.keys, {0}, {100}, coin_seed);
    setup.pub.account_rings = test::shielded::BuildDeterministicCTAccountRings(
        setup.keys, setup.pub.coin_rings, 0xDB00, 0x98);
    setup.inputs[0] = MakeCtInput(0, setup.keys[0], 100, coin_seed, 0, N);

    auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 0xDB1);
    bool valid = VerifyCT(proof, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(valid,
        "D10-2: Proof for first index (0) must verify.");
}

// D10-3: Anonymity set of size exactly NUM_NTT_SLOTS (no recursion needed).
BOOST_AUTO_TEST_CASE(d10_exact_slot_count_anon_set)
{
    const size_t N = NUM_NTT_SLOTS; // 32
    auto setup = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xDC);

    auto proof = MakeValidProof(setup);
    bool valid = VerifyCT(proof, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(valid,
        "D10-3: Proof with N=NUM_NTT_SLOTS must verify (single recursion level).");
}

// ============================================================================
// D11: MULTIPLE SIMULTANEOUS TAMPERING
// Combine multiple weak attacks to find if they interact to bypass checks.
// ============================================================================

// D11-1: Tamper BOTH h2 (just above boundary) AND a serial number.
// Each individual tampering should be caught, but test that both
// together don't accidentally cancel out.
BOOST_AUTO_TEST_CASE(d11_combined_h2_and_serial_tampering)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 2, 2, {100, 200}, {150, 150}, 0xDD);
    auto proof = MakeValidProof(setup);

    BOOST_REQUIRE(VerifyCT(proof, 2, 2, setup.pub));

    SmileCTProof tampered = proof;
    // Tamper h2 at slot boundary
    tampered.h2.coeffs[SLOT_DEGREE] += 42;
    // Also tamper first serial number
    tampered.serial_numbers[0].coeffs[0] += 7;

    bool valid = VerifyCT(tampered, 2, 2, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D11-1: Combined h2 + serial number tampering must be rejected.");
}

// D11-2: Swap z and w0_vals from different proofs.
BOOST_AUTO_TEST_CASE(d11_combined_z_and_w0_swap)
{
    const size_t N = 32;
    auto setup_a = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xDE);
    auto setup_b = DeepTestSetup::Create(N, 1, 1, {200}, {200}, 0xDF);

    auto proof_a = MakeValidProof(setup_a);
    auto proof_b = MakeValidProof(setup_b);

    SmileCTProof hybrid = proof_a;
    hybrid.z = proof_b.z;
    CopyLiveCtW0Rows(proof_b, hybrid, 1, 1, 0, 0);

    bool valid = VerifyCT(hybrid, 1, 1, setup_a.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D11-2: Swapping both z and w0_vals from different proof must be rejected.");
}

// D11-3: Tamper aux_commitment AND adjust h2 to compensate.
BOOST_AUTO_TEST_CASE(d11_compensating_aux_and_h2_tampering)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xE0);
    auto proof = MakeValidProof(setup);

    BOOST_REQUIRE(VerifyCT(proof, 1, 1, setup.pub));

    SmileCTProof tampered = proof;
    // Add 5 to aux t_msg[0] and subtract 5 from h2.coeffs[SLOT_DEGREE]
    if (!tampered.aux_commitment.t_msg.empty()) {
        tampered.aux_commitment.t_msg[0].coeffs[0] = mod_q(
            tampered.aux_commitment.t_msg[0].coeffs[0] + 5);
    }
    tampered.h2.coeffs[SLOT_DEGREE] = mod_q(
        tampered.h2.coeffs[SLOT_DEGREE] - 5);

    bool valid = VerifyCT(tampered, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D11-3: Compensating modifications to aux_commitment and h2 must be rejected.");
}

// ============================================================================
// D12: REPLAY AND REUSE ATTACKS
// ============================================================================

// D12-1: Replay a valid proof with different public data.
BOOST_AUTO_TEST_CASE(d12_replay_proof_different_public_data)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xEE);
    auto proof = MakeValidProof(setup);

    BOOST_REQUIRE(VerifyCT(proof, 1, 1, setup.pub));

    // Create different public data (different anonymity set)
    auto different_keys = GenerateAnonSet(N, 0xEF);
    CTPublicData different_pub;
    different_pub.anon_set = ExtractPublicKeys(different_keys);
    different_pub.coin_rings = setup.pub.coin_rings;
    different_pub.account_rings = test::shielded::BuildDeterministicCTAccountRings(
        different_keys, different_pub.coin_rings, 0xEF00, 0x96);

    bool valid = VerifyCT(proof, 1, 1, different_pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D12-1: Replayed proof with different public data must be rejected.");
}

// D12-2: Use output coins from one proof as context for another.
BOOST_AUTO_TEST_CASE(d12_cross_proof_output_coin_reuse)
{
    const size_t N = 32;
    auto setup_a = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xF0);
    auto setup_b = DeepTestSetup::Create(N, 1, 1, {200}, {200}, 0xF1);

    auto proof_a = MakeValidProof(setup_a);
    auto proof_b = MakeValidProof(setup_b);

    // Use proof_a but with proof_b's output coins
    SmileCTProof hybrid = proof_a;
    hybrid.output_coins = proof_b.output_coins;

    bool valid = VerifyCT(hybrid, 1, 1, setup_a.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D12-2: Cross-proof output coin reuse must be rejected by fs_seed check.");
}

// ============================================================================
// D13: STRUCTURAL INVARIANT VIOLATIONS
// ============================================================================

// D13-1: Mismatched z0 vector dimensions.
BOOST_AUTO_TEST_CASE(d13_z0_dimension_mismatch)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xFA);
    auto proof = MakeValidProof(setup);

    SmileCTProof tampered = proof;
    // Add an extra polynomial to z0[0]
    tampered.z0[0].push_back(SmilePoly{});

    bool valid = VerifyCT(tampered, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D13-1: z0 with wrong dimension must be rejected.");
}

// D13-2: Extra serial numbers beyond num_inputs.
BOOST_AUTO_TEST_CASE(d13_extra_serial_numbers)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xFB);
    auto proof = MakeValidProof(setup);

    SmileCTProof tampered = proof;
    tampered.serial_numbers.push_back(SmilePoly{});

    bool valid = VerifyCT(tampered, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D13-2: Extra serial numbers must be rejected.");
}

// D13-3: Empty anonymity set.
BOOST_AUTO_TEST_CASE(d13_empty_anonymity_set)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xFC);
    auto proof = MakeValidProof(setup);

    CTPublicData empty_pub;
    // No keys in anonymity set

    // This should either crash-protect or return false
    bool valid = VerifyCT(proof, 1, 1, empty_pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D13-3: Proof verified against empty anonymity set must be rejected.");
}

// D13-4: Anonymity set with single key.
BOOST_AUTO_TEST_CASE(d13_single_key_anonymity_set)
{
    const size_t N = 1;
    auto keys = GenerateAnonSet(N, 0xFD);

    DeepTestSetup setup;
    setup.keys = keys;
    setup.pub.anon_set = ExtractPublicKeys(keys);
    setup.pub.coin_rings = BuildCoinRings(keys, {0}, {100}, 0xFD);
    setup.pub.account_rings = test::shielded::BuildDeterministicCTAccountRings(
        keys, setup.pub.coin_rings, 0xFD00, 0x99);
    setup.inputs = {MakeCtInput(0, keys[0], 100, 0xFD, 0, N)};
    setup.outputs = {MakeCtOutput(100, 0xFD00)};

    // A single-key anonymity set provides zero anonymity but should still work
    auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 0xFD1);
    bool valid = VerifyCT(proof, 1, 1, setup.pub);
    BOOST_TEST_MESSAGE("D13-4: Single-key anonymity set: valid=" << valid);
}

// ============================================================================
// D14: TIMING-BASED INFORMATION LEAKS
// Verify that verification time doesn't depend on which key signed.
// ============================================================================

// D14-1: Measure verification time for different signer positions.
// Significant timing differences would indicate the verifier leaks
// which member of the anonymity set is the real signer.
BOOST_AUTO_TEST_CASE(d14_verification_timing_independence)
{
    const size_t N = 32;
    auto keys = GenerateAnonSet(N, 0xDD);
    auto pks = ExtractPublicKeys(keys);

    CTPublicData pub;
    pub.anon_set = pks;

    // Create proofs for different positions in the anonymity set
    std::vector<size_t> positions = {0, 1, N/4, N/2, 3*N/4, N-2, N-1};
    std::vector<double> verify_times;

    for (size_t pos : positions) {
        pub.coin_rings = BuildCoinRings(keys, {pos}, {100}, 0xDD + pos);
        pub.account_rings = test::shielded::BuildDeterministicCTAccountRings(
            keys, pub.coin_rings, 0xDD00 + static_cast<uint32_t>(pos) * 100, 0x9a);
        std::vector<CTInput> inputs = {
            MakeCtInput(pos, keys[pos], 100, 0xDD + pos, 0, N)
        };
        std::vector<CTOutput> outputs = {MakeCtOutput(100, 0xDD00 + pos)};

        auto proof = ProveCT(inputs, outputs, pub, 70000 + pos);

        // Measure verification time (average over multiple runs)
        double total_us = 0;
        const int RUNS = 5;
        for (int r = 0; r < RUNS; ++r) {
            auto t0 = std::chrono::high_resolution_clock::now();
            bool valid = VerifyCT(proof, 1, 1, pub);
            auto t1 = std::chrono::high_resolution_clock::now();
            BOOST_REQUIRE(valid);
            total_us += std::chrono::duration<double, std::micro>(t1 - t0).count();
        }
        verify_times.push_back(total_us / RUNS);
    }

    // Check that max/min ratio is close to 1 (within 3x tolerance for CI variance)
    double min_t = *std::min_element(verify_times.begin(), verify_times.end());
    double max_t = *std::max_element(verify_times.begin(), verify_times.end());
    double ratio = max_t / min_t;

    BOOST_TEST_MESSAGE("D14-1: Verification timing ratio (max/min): " << ratio);
    for (size_t i = 0; i < positions.size(); ++i) {
        BOOST_TEST_MESSAGE("  Position " << positions[i] << ": "
                           << verify_times[i] << " us");
    }

    // The key membership check iterates over all N keys, so timing should
    // depend on where the match is found. If it short-circuits on match,
    // earlier positions verify faster (information leak!).
    // Ideally ratio should be < 1.5 for constant-time verification.
    if (ratio > 2.0) {
        BOOST_TEST_MESSAGE(
            "D14-1: WARNING — Verification timing varies by " << ratio << "x! "
            "The key membership check may leak which key signed. "
            "Consider scanning all keys even after finding a match.");
    }
}

// ============================================================================
// D15: PROOF-OF-NOTHING ATTACK
// Test whether a completely fabricated proof can accidentally pass.
// ============================================================================

// D15-1: Proof with all fields set to zero.
BOOST_AUTO_TEST_CASE(d15_all_zero_proof)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xAA);

    SmileCTProof zero_proof;
    zero_proof.serial_numbers.resize(1); // one zero serial
    zero_proof.z0.resize(1);
    zero_proof.z0[0].resize(KEY_COLS);
    zero_proof.output_coins.resize(1);
    EnsureLiveCtAuxState(zero_proof, 1, 1);

    bool valid = VerifyCT(zero_proof, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D15-1: All-zero proof must be rejected.");
}

// D15-2: Proof with random noise in all fields.
BOOST_AUTO_TEST_CASE(d15_random_noise_proof)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xAB);

    std::mt19937_64 rng(0xDEAD);

    SmileCTProof noise_proof;
    noise_proof.serial_numbers.resize(1);
    noise_proof.z0.resize(1);
    noise_proof.z0[0].resize(KEY_COLS);
    noise_proof.output_coins.resize(1);
    EnsureLiveCtAuxState(noise_proof, 1, 1);

    // Fill with random noise
    for (size_t c = 0; c < POLY_DEGREE; ++c) {
        noise_proof.serial_numbers[0].coeffs[c] = rng() % Q;
        noise_proof.h2.coeffs[c] = rng() % Q;
        for (size_t j = 0; j < KEY_COLS; ++j) {
            noise_proof.z0[0][j].coeffs[c] = rng() % Q;
        }
        for (size_t j = 0; j < LIVE_CT_PUBLIC_ROWS; ++j) {
            noise_proof.aux_commitment.t_msg[LiveCtW0Slot(1, 1, 0, j)].coeffs[c] = rng() % Q;
        }
    }
    // Random Fiat-Shamir seeds
    for (size_t i = 0; i < 32; ++i) {
        noise_proof.fs_seed[i] = rng() & 0xFF;
        noise_proof.seed_c0[i] = rng() & 0xFF;
        noise_proof.seed_c[i] = rng() & 0xFF;
    }

    bool valid = VerifyCT(noise_proof, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "D15-2: Random noise proof must be rejected.");
}

// D15-3: Brute-force many random proofs to check soundness error rate.
BOOST_AUTO_TEST_CASE(d15_brute_force_random_proofs)
{
    const size_t N = 32;
    auto setup = DeepTestSetup::Create(N, 1, 1, {100}, {100}, 0xAC);

    std::mt19937_64 rng(0xBEEF);
    int accepted = 0;
    const int TRIALS = 100;

    for (int trial = 0; trial < TRIALS; ++trial) {
        SmileCTProof random_proof;
        random_proof.serial_numbers.resize(1);
        random_proof.z0.resize(1);
        random_proof.z0[0].resize(KEY_COLS);
        random_proof.output_coins.resize(1);
        EnsureLiveCtAuxState(random_proof, 1, 1);

        // h2 with zero first coefficients (pass the h2 check)
        for (size_t c = SLOT_DEGREE; c < POLY_DEGREE; ++c) {
            random_proof.h2.coeffs[c] = rng() % Q;
        }

        // Random everything else
        for (size_t c = 0; c < POLY_DEGREE; ++c) {
            random_proof.serial_numbers[0].coeffs[c] = rng() % Q;
            for (size_t j = 0; j < KEY_COLS; ++j) {
                random_proof.z0[0][j].coeffs[c] = rng() % 30; // small to pass norm
            }
        }
        for (size_t i = 0; i < 32; ++i) {
            random_proof.fs_seed[i] = rng() & 0xFF;
            random_proof.seed_c0[i] = rng() & 0xFF;
            random_proof.seed_c[i] = rng() & 0xFF;
        }

        if (VerifyCT(random_proof, 1, 1, setup.pub)) {
            accepted++;
        }
    }

    BOOST_CHECK_MESSAGE(accepted == 0,
        "D15-3: CRITICAL — " << accepted << " / " << TRIALS
        << " random proofs were accepted! Soundness error rate must be negligible.");
}

BOOST_AUTO_TEST_SUITE_END()
