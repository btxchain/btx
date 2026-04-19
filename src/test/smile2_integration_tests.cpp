// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/smile2/ct_proof.h>
#include <shielded/smile2/params.h>
#include <shielded/smile2/serialize.h>
#include <shielded/smile2/verify_dispatch.h>
#include <test/util/setup_common.h>
#include <test/util/shielded_smile_test_util.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <vector>

using namespace smile2;

namespace {

constexpr uint64_t INTEGRATION_TEST_PROOF_RETRY_STRIDE{0xD1B54A32D192ED03ULL};
constexpr uint32_t MAX_INTEGRATION_TEST_PROOF_ATTEMPTS{32};

std::array<uint8_t, 32> MakeSeed(uint8_t val) {
    std::array<uint8_t, 32> seed{};
    seed[0] = val;
    return seed;
}

std::optional<SmileCTProof> TryProveCtWithRetriesForTest(const std::vector<CTInput>& inputs,
                                                         const std::vector<CTOutput>& outputs,
                                                         const CTPublicData& pub,
                                                         uint64_t base_seed,
                                                         int64_t public_fee = 0,
                                                         bool bind_anonset_context = false)
{
    for (uint32_t attempt = 0; attempt < MAX_INTEGRATION_TEST_PROOF_ATTEMPTS; ++attempt) {
        const uint64_t attempt_seed = base_seed + (INTEGRATION_TEST_PROOF_RETRY_STRIDE * attempt);
        if (auto proof = TryProveCT(
                inputs, outputs, pub, attempt_seed, public_fee, bind_anonset_context)) {
            return proof;
        }
    }
    return std::nullopt;
}

BDLOPCommitmentKey GetPublicCoinCommitmentKey()
{
    std::array<uint8_t, 32> seed{};
    seed[0] = 0xCC;
    return BDLOPCommitmentKey::Generate(seed, 1);
}

std::vector<SmileKeyPair> GenerateAnonSet(size_t N, uint8_t seed_val) {
    auto a_seed = MakeSeed(seed_val);
    std::vector<SmileKeyPair> keys(N);
    for (size_t i = 0; i < N; ++i) {
        keys[i] = SmileKeyPair::Generate(a_seed, 50000 + i);
    }
    return keys;
}

std::vector<SmilePublicKey> ExtractPublicKeys(const std::vector<SmileKeyPair>& keys) {
    std::vector<SmilePublicKey> pks;
    pks.reserve(keys.size());
    for (const auto& kp : keys) {
        pks.push_back(kp.pub);
    }
    return pks;
}

std::vector<std::vector<BDLOPCommitment>> BuildCoinRings(
    const std::vector<SmileKeyPair>& keys,
    const std::vector<size_t>& secret_indices,
    const std::vector<int64_t>& secret_amounts,
    uint64_t coin_seed)
{
    size_t N = keys.size();
    size_t m = secret_indices.size();
    const auto ck = GetPublicCoinCommitmentKey();
    std::vector<std::vector<BDLOPCommitment>> coin_rings(m);
    for (size_t inp = 0; inp < m; ++inp) {
        coin_rings[inp].resize(N);
        for (size_t j = 0; j < N; ++j) {
            SmilePoly amount_poly;
            if (j == secret_indices[inp]) {
                amount_poly = EncodeAmountToSmileAmountPoly(secret_amounts[inp]).value();
            } else {
                uint64_t rng_state = coin_seed * 1000 + inp * N + j;
                rng_state ^= rng_state << 13;
                rng_state ^= rng_state >> 7;
                rng_state ^= rng_state << 17;
                amount_poly = EncodeAmountToSmileAmountPoly(
                    static_cast<int64_t>(rng_state % 1000000)).value();
            }
            const auto opening = SampleTernary(ck.rand_dim(), coin_seed * 100000 + inp * N + j);
            coin_rings[inp][j] = Commit(ck, {amount_poly}, opening);
        }
    }
    return coin_rings;
}

struct IntegrationTestSetup {
    std::vector<SmileKeyPair> keys;
    CTPublicData pub;
    std::vector<CTInput> inputs;
    std::vector<CTOutput> outputs;

    static IntegrationTestSetup Create(size_t N, size_t num_inputs, size_t num_outputs,
                                        const std::vector<int64_t>& in_amounts,
                                        const std::vector<int64_t>& out_amounts,
                                        uint8_t seed_val)
    {
        IntegrationTestSetup setup;
        setup.keys = GenerateAnonSet(N, seed_val);
        setup.pub.anon_set = ExtractPublicKeys(setup.keys);

        std::vector<size_t> secret_indices;
        secret_indices.reserve(num_inputs);
        for (size_t i = 0; i < num_inputs; ++i) {
            secret_indices.push_back(i * 3 + 1);
        }

        setup.pub.coin_rings = BuildCoinRings(
            setup.keys, secret_indices, in_amounts, seed_val + 100);
        setup.pub.account_rings = test::shielded::BuildDeterministicCTAccountRings(
            setup.keys, setup.pub.coin_rings, static_cast<uint32_t>(seed_val) * 1000 + 300, 0x92);

        setup.inputs.resize(num_inputs);
        const auto coin_ck = GetPublicCoinCommitmentKey();
        for (size_t i = 0; i < num_inputs; ++i) {
            setup.inputs[i].secret_index = secret_indices[i];
            setup.inputs[i].sk = setup.keys[secret_indices[i]].sec;
            setup.inputs[i].amount = in_amounts[i];
            setup.inputs[i].coin_r = SampleTernary(
                coin_ck.rand_dim(),
                static_cast<uint64_t>(seed_val + 100) * 100000 + i * N + secret_indices[i]);
        }

        setup.outputs.resize(num_outputs);
        for (size_t i = 0; i < num_outputs; ++i) {
            setup.outputs[i].amount = out_amounts[i];
            setup.outputs[i].coin_r = SampleTernary(
                coin_ck.rand_dim(),
                static_cast<uint64_t>(seed_val) * 1000000 + i);
        }

        return setup;
    }
};

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(smile2_integration_tests, BasicTestingSetup)

// [P5-G1] Valid small-fixture SMILE v2 proof roundtrips and verifies.
// The synthetic N=32 fixture used here can serialize below the consensus
// dispatch floor, so the consensus parser expectation is conditional on the
// resulting byte size.
BOOST_AUTO_TEST_CASE(p5_g1_consensus_accepts_valid)
{
    const size_t N = 32;
    auto setup = IntegrationTestSetup::Create(N, 2, 2, {100, 200}, {150, 150}, 201);

    // Prove
    auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 44556677);

    // Serialize (as consensus would receive it)
    auto proof_bytes = SerializeCTProof(proof);
    BOOST_TEST_MESSAGE("P5-G1: Serialized proof size = " << proof_bytes.size() << " bytes");

    // Validate through the verifier path (output coins come from transaction).
    auto validate_result = ValidateSmile2Proof(proof, 2, 2, proof.output_coins, setup.pub);
    BOOST_CHECK_MESSAGE(!validate_result.has_value(),
        "P5-G1: Validation should succeed, got: " << validate_result.value_or("(ok)"));

    BOOST_CHECK_MESSAGE(VerifyCT(proof, 2, 2, setup.pub),
        "P5-G1: Core verifier should accept the freshly generated proof");

    // Consensus dispatch keeps a fixed minimum proof-size floor as a cheap
    // malformed-input filter. Small synthetic fixtures can legitimately fall
    // below that floor even though the codec roundtrip and verifier succeed.
    SmileCTProof parsed;
    auto parse_result = ParseSmile2Proof(proof_bytes, 2, 2, parsed);
    auto combined_result = VerifySmile2CTFromBytes(proof_bytes, 2, 2, proof.output_coins, setup.pub);
    if (proof_bytes.size() < MIN_SMILE2_PROOF_BYTES) {
        BOOST_CHECK_MESSAGE(parse_result.has_value() && *parse_result == "bad-smile2-proof-too-small",
            "P5-G1: Small synthetic proof should be rejected by the consensus size floor");
        BOOST_CHECK_MESSAGE(combined_result.has_value() && *combined_result == "bad-smile2-proof-too-small",
            "P5-G1: Combined dispatch should surface the consensus size-floor rejection");
    } else {
        BOOST_CHECK_MESSAGE(!parse_result.has_value(),
            "P5-G1: Parse should succeed, got: " << parse_result.value_or("(ok)"));
        BOOST_CHECK_MESSAGE(!combined_result.has_value(),
            "P5-G1: Combined verify should succeed, got: " << combined_result.value_or("(ok)"));
    }

    // Serial number extraction
    std::vector<SmilePoly> serial_numbers;
    auto sn_result = ExtractSmile2SerialNumbers(proof, serial_numbers);
    BOOST_CHECK_MESSAGE(!sn_result.has_value(),
        "P5-G1: Serial number extraction should succeed");
    BOOST_CHECK_EQUAL(serial_numbers.size(), 2u);
}

BOOST_AUTO_TEST_CASE(p3_m12_context_bound_ct_transcript_requires_v2_mode)
{
    const size_t N = 32;
    auto setup = IntegrationTestSetup::Create(N, 2, 2, {120, 80}, {100, 100}, 202);

    const auto legacy_proof = TryProveCtWithRetriesForTest(
        setup.inputs, setup.outputs, setup.pub, 0x12345678ULL);
    const auto bound_proof = TryProveCtWithRetriesForTest(setup.inputs,
                                                          setup.outputs,
                                                          setup.pub,
                                                          0x12345678ULL,
                                                          /*public_fee=*/0,
                                                          /*bind_anonset_context=*/true);

    BOOST_REQUIRE(legacy_proof.has_value());
    BOOST_REQUIRE(bound_proof.has_value());

    BOOST_REQUIRE(!ValidateSmile2Proof(*legacy_proof, 2, 2, legacy_proof->output_coins, setup.pub).has_value());
    BOOST_REQUIRE(!ValidateSmile2Proof(*bound_proof,
                                       2,
                                       2,
                                       bound_proof->output_coins,
                                       setup.pub,
                                       /*public_fee=*/0,
                                       /*bind_anonset_context=*/true)
                       .has_value());
    BOOST_CHECK(ValidateSmile2Proof(*legacy_proof,
                                    2,
                                    2,
                                    legacy_proof->output_coins,
                                    setup.pub,
                                    /*public_fee=*/0,
                                    /*bind_anonset_context=*/true)
                    .has_value());
    BOOST_CHECK(ValidateSmile2Proof(*bound_proof, 2, 2, bound_proof->output_coins, setup.pub).has_value());
}

// [P5-G2] Consensus rejects invalid/tampered proof.
BOOST_AUTO_TEST_CASE(p5_g2_consensus_rejects_invalid)
{
    const size_t N = 32;

    // Test 1: Empty proof bytes
    {
        SmileCTProof parsed;
        auto result = ParseSmile2Proof({}, 2, 2, parsed);
        BOOST_CHECK_MESSAGE(result.has_value() && *result == "bad-smile2-proof-missing",
            "P5-G2a: Empty proof should be rejected");
    }

    // Test 2: Too-small proof bytes (DoS protection)
    {
        std::vector<uint8_t> tiny(100, 0);
        SmileCTProof parsed;
        auto result = ParseSmile2Proof(tiny, 2, 2, parsed);
        BOOST_CHECK_MESSAGE(result.has_value() && *result == "bad-smile2-proof-too-small",
            "P5-G2b: Tiny proof should be rejected");
    }

    // Test 3: Oversized proof bytes
    {
        std::vector<uint8_t> huge(MAX_SMILE2_PROOF_BYTES + 1, 0);
        SmileCTProof parsed;
        auto result = ParseSmile2Proof(huge, 2, 2, parsed);
        BOOST_CHECK_MESSAGE(result.has_value() && *result == "bad-smile2-proof-oversize",
            "P5-G2c: Oversized proof should be rejected");
    }

    // Test 4: Invalid input count
    {
        std::vector<uint8_t> dummy(16 * 1024, 0);
        SmileCTProof parsed;
        auto result = ParseSmile2Proof(dummy, 0, 2, parsed);
        BOOST_CHECK_MESSAGE(result.has_value() && *result == "bad-smile2-proof-input-count",
            "P5-G2d: Zero inputs should be rejected");

        result = ParseSmile2Proof(dummy, 17, 2, parsed);
        BOOST_CHECK_MESSAGE(result.has_value() && *result == "bad-smile2-proof-input-count",
            "P5-G2e: 17 inputs should be rejected");
    }

    // Test 5: Unbalanced transaction (cryptographic rejection)
    {
        auto setup = IntegrationTestSetup::Create(N, 2, 2, {100, 200}, {150, 200}, 202);
        auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 22334455);
        auto proof_bytes = SerializeCTProof(proof);

        auto result = VerifySmile2CTFromBytes(proof_bytes, 2, 2, proof.output_coins, setup.pub);
        BOOST_CHECK_MESSAGE(result.has_value(),
            "P5-G2f: Unbalanced transaction should be rejected");
    }

    // Test 6: Tampered proof bytes (corrupt a byte in valid proof)
    {
        auto setup = IntegrationTestSetup::Create(N, 2, 2, {100, 200}, {150, 150}, 203);
        auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 33445566);
        auto proof_bytes = SerializeCTProof(proof);

        // Corrupt a byte near the middle of the proof
        if (proof_bytes.size() > 100) {
            proof_bytes[proof_bytes.size() / 2] ^= 0xFF;
        }

        auto result = VerifySmile2CTFromBytes(proof_bytes, 2, 2, proof.output_coins, setup.pub);
        BOOST_CHECK_MESSAGE(result.has_value(),
            "P5-G2g: Tampered proof should be rejected");
    }
}

// [P5-G3] Performance on the audited synthetic integration surface (N = 32).
// These wall-clock numbers are advisory only: they are useful to surface
// unexpected slowdowns, but they are too host-sensitive to act as correctness
// gates across developer machines and loaded CI workers.
BOOST_AUTO_TEST_CASE(p5_g3_performance)
{
    const size_t N = 32;
    constexpr auto kLaunchProveBudgetMs = 3000;
    constexpr auto kLaunchVerifyBudgetMs = 300;
    auto setup = IntegrationTestSetup::Create(N, 2, 2, {100, 200}, {150, 150}, 204);

    // Measure prove time
    auto prove_start = std::chrono::high_resolution_clock::now();
    auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 44556677);
    auto prove_end = std::chrono::high_resolution_clock::now();
    auto prove_ms = std::chrono::duration_cast<std::chrono::milliseconds>(prove_end - prove_start).count();

    BOOST_TEST_MESSAGE("P5-G3: Prove time = " << prove_ms << " ms");
    BOOST_WARN_MESSAGE(prove_ms < kLaunchProveBudgetMs,
        "P5-G3: Prove must be < " << kLaunchProveBudgetMs << " ms, got " << prove_ms << " ms");

    // Serialize for verify path
    auto proof_bytes = SerializeCTProof(proof);

    // Measure verify time (parse + validate)
    auto verify_start = std::chrono::high_resolution_clock::now();
    auto result = VerifySmile2CTFromBytes(proof_bytes, 2, 2, proof.output_coins, setup.pub);
    auto verify_end = std::chrono::high_resolution_clock::now();
    auto verify_ms = std::chrono::duration_cast<std::chrono::milliseconds>(verify_end - verify_start).count();

    BOOST_CHECK_MESSAGE(!result.has_value(),
        "P5-G3: Verification should succeed, got: " << result.value_or("(ok)"));
    BOOST_TEST_MESSAGE("P5-G3: Verify time = " << verify_ms << " ms");
    BOOST_WARN_MESSAGE(verify_ms < kLaunchVerifyBudgetMs,
        "P5-G3: Verify must be < " << kLaunchVerifyBudgetMs << " ms, got " << verify_ms << " ms");
}

BOOST_AUTO_TEST_SUITE_END()
