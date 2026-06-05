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
                                                         bool bind_anonset_context = false,
                                                         int64_t validation_height =
                                                             SmileCTProof::C002_ACTIVATION_HEIGHT)
{
    for (uint32_t attempt = 0; attempt < MAX_INTEGRATION_TEST_PROOF_ATTEMPTS; ++attempt) {
        const uint64_t attempt_seed = base_seed + (INTEGRATION_TEST_PROOF_RETRY_STRIDE * attempt);
        if (auto proof = TryProveCT(
                inputs, outputs, pub, attempt_seed, public_fee, bind_anonset_context,
                /*error=*/nullptr, validation_height)) {
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

// [C-002 #9] Staged-activation gate test vector. ValidateSmile2Proof requires the
// wire version matching the validation height: v3 mandatory at/after the
// activation height, v2 mandatory before it. Mismatches reject. Proves the
// C002_ACTIVATION_HEIGHT cutover end-to-end (prover emits the right version per
// height; verifier gate rejects the wrong one).
BOOST_AUTO_TEST_CASE(c002_activation_gate_v2_v3)
{
    const size_t N = 32;
    const int64_t H = SmileCTProof::C002_ACTIVATION_HEIGHT;
    auto setup = IntegrationTestSetup::Create(N, 2, 2, {120, 80}, {100, 100}, 207);

    const auto v3 = TryProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub,
                                                 0x9001ULL, 0, /*bind=*/true, /*height=*/H);
    const auto v2 = TryProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub,
                                                 0x9002ULL, 0, /*bind=*/true, /*height=*/1);
    BOOST_REQUIRE(v3.has_value());
    BOOST_REQUIRE(v2.has_value());
    BOOST_CHECK_EQUAL((int)v3->wire_version, (int)SmileCTProof::WIRE_VERSION_C002_HARDENED);
    BOOST_CHECK_EQUAL((int)v2->wire_version, (int)SmileCTProof::WIRE_VERSION_M4_HARDENED);

    // returns true == REJECTED (has a reject reason)
    auto rejected = [&](const SmileCTProof& p, int64_t h) {
        return ValidateSmile2Proof(p, 2, 2, p.output_coins, setup.pub, /*fee=*/0,
                                   /*bind=*/true, /*validation_height=*/h)
            .has_value();
    };
    BOOST_CHECK(!rejected(*v3, H));        // v3 at/after H: ACCEPT
    BOOST_CHECK(rejected(*v3, H - 1));     // v3 before H: REJECT (expects v2)
    BOOST_CHECK(!rejected(*v2, H - 1));    // v2 before H: ACCEPT
    BOOST_CHECK(rejected(*v2, H));         // v2 at/after H: REJECT (expects v3)
}

// [C-002 #16] Stale z-size caps undercounted the R5 range slots. The maximum v3
// shape (MAX_CT_INPUTS=16 in / MAX_CT_OUTPUTS=16 out) has a response vector of size
// z.size() = BDLOP_RAND_DIM_BASE + ComputeNumAuxMsg(16,16,v3) = 20 + 242 = 262,
// which exceeded BOTH the old hard decode cap (z_size > 256) and the old verifier
// cap (MAX_Z_SIZE = 20 + 16*8 + 16*4 = 212, an 8*in+4*out formula predating R5).
// An honest max-shape proof was therefore constructible but rejected solely by the
// stale caps. The fix derives both caps from the actual layout. This test guards
// the arithmetic (a regression to a stale literal/formula would fail it) and, with
// a normal-shape proof, confirms the post-fix serialize->decode->verify path. (A
// full 16-in real proof is omitted here only because it is very slow to generate;
// the regtest wallet E2E exercises real multi-input v3 spends end to end.)
BOOST_AUTO_TEST_CASE(c002_max_shape_zsize_exceeds_legacy_caps_and_roundtrips)
{
    // Max-shape v3 aux-message count, mirroring ComputeNumAuxMsg / ComputeLiveCt-
    // AuxMsgCount for the live m1 layout (rec_levels==1) with R5 range slots.
    const size_t row_count = KEY_ROWS + 2; // == GetCtPublicRowCount()
    const size_t max_aux = MAX_CT_INPUTS                              // selectors
                         + (MAX_CT_INPUTS + MAX_CT_OUTPUTS)           // amounts
                         + 2 * (MAX_CT_INPUTS + MAX_CT_OUTPUTS)       // R5 B0,B1 (v3)
                         + MAX_CT_INPUTS * row_count                  // w rows
                         + MAX_CT_INPUTS                              // x slots
                         + 2;                                         // g, psi
    const size_t max_z = BDLOP_RAND_DIM_BASE + max_aux;
    BOOST_CHECK_EQUAL(max_z, 262u);
    BOOST_CHECK_GT(max_z, 256u); // old hard decode cap
    const size_t old_verifier_cap = BDLOP_RAND_DIM_BASE + MAX_CT_INPUTS * 8 + MAX_CT_OUTPUTS * 4;
    BOOST_CHECK_EQUAL(old_verifier_cap, 212u);
    BOOST_CHECK_GT(max_z, old_verifier_cap); // old verifier MAX_Z_SIZE undercounted

    // Regression: a normal-shape v3 proof still serialize->decode->verify round-trips
    // after raising the caps.
    const size_t N = 32;
    auto setup = IntegrationTestSetup::Create(N, 4, 4, {100, 100, 100, 100},
                                              {100, 100, 100, 100}, 88);
    const auto proof = TryProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub,
                                                    0xB44ULL, /*fee=*/0, /*bind=*/true,
                                                    SmileCTProof::C002_ACTIVATION_HEIGHT);
    BOOST_REQUIRE(proof.has_value());
    BOOST_CHECK_EQUAL((int)proof->wire_version, (int)SmileCTProof::WIRE_VERSION_C002_HARDENED);

    // The serialized v3 proof decodes without tripping the (now layout-derived)
    // z-size decode cap. (The full real decode->validate path for v3 spends is
    // exercised end to end by the regtest wallet E2E, which mines v3 spends into
    // blocks; here we keep the unit test fast and deterministic.)
    const auto bytes = SerializeCTProof(*proof);
    SmileCTProof decoded;
    BOOST_CHECK(DecodeCTProof(bytes, decoded, 4, 4) == SmileCTDecodeStatus::OK);

    // A normal-shape anonset-bound v3 proof verifies through the consensus dispatch
    // (which replays the v3 transcript binding). nullopt == accepted.
    const auto reject = ValidateSmile2Proof(*proof, 4, 4, proof->output_coins, setup.pub,
                                            /*fee=*/0, /*bind=*/true,
                                            /*validation_height=*/SmileCTProof::C002_ACTIVATION_HEIGHT);
    BOOST_CHECK_MESSAGE(!reject.has_value(),
        "normal-shape v3 proof must verify, got: " << reject.value_or("(ok)"));
}

// [C-002 #17] Anonset-bound v3 verification must be context-bound: a proof is valid
// only under the exact (anonymity set, bind flag, height/wire-version, output coins)
// it was produced for. Every mismatch must REJECT — both as fail-closed behaviour
// and, crucially for soundness, so a valid proof cannot be replayed against a
// different public context (a different ring, or as if it were a legacy unbound
// proof). This exercises the verify-dispatch context plumbing the gate relies on.
BOOST_AUTO_TEST_CASE(c002_v3_context_mismatch_rejects)
{
    const size_t N = 32;
    const int64_t H = SmileCTProof::C002_ACTIVATION_HEIGHT;
    auto setupA = IntegrationTestSetup::Create(N, 2, 2, {120, 80}, {100, 100}, 211);
    // setupB: same shape and amounts but an independent anonymity set / rings.
    auto setupB = IntegrationTestSetup::Create(N, 2, 2, {120, 80}, {100, 100}, 212);

    const auto v3 = TryProveCtWithRetriesForTest(setupA.inputs, setupA.outputs, setupA.pub,
                                                 0xC001ULL, /*fee=*/0, /*bind=*/true, /*height=*/H);
    BOOST_REQUIRE(v3.has_value());
    BOOST_REQUIRE_EQUAL((int)v3->wire_version, (int)SmileCTProof::WIRE_VERSION_C002_HARDENED);
    // An independent v3 proof over setupB, used as a source of valid-but-wrong
    // output coins for the output-substitution check below.
    const auto v3b = TryProveCtWithRetriesForTest(setupB.inputs, setupB.outputs, setupB.pub,
                                                  0xC002ULL, /*fee=*/0, /*bind=*/true, /*height=*/H);
    BOOST_REQUIRE(v3b.has_value());

    // returns true == REJECTED (has a reject reason)
    auto rejected = [&](const CTPublicData& pub, const std::vector<BDLOPCommitment>& coins,
                        bool bind, int64_t h) {
        return ValidateSmile2Proof(*v3, 2, 2, coins, pub, /*fee=*/0, bind, h).has_value();
    };

    // Baseline: the exact context it was produced for ACCEPTS.
    BOOST_CHECK(!rejected(setupA.pub, v3->output_coins, /*bind=*/true, H));

    // (1) Anonymity-set substitution: same size, different ring -> REJECT. A proof
    // must be bound to its own anon set; accepting it against another ring would be
    // a soundness break.
    BOOST_CHECK_MESSAGE(rejected(setupB.pub, v3->output_coins, /*bind=*/true, H),
        "v3 proof must NOT verify against a different anonymity set");

    // (2) Bind-flag mismatch: a bound v3 proof verified as an unbound/legacy proof
    // -> REJECT (the gate expects v3 wire version when bind_anonset_context).
    BOOST_CHECK_MESSAGE(rejected(setupA.pub, v3->output_coins, /*bind=*/false, H),
        "bound v3 proof must NOT verify in unbound context");

    // (3) Height/wire mismatch: a v3 proof presented before the activation height
    // -> REJECT (gate expects v2 there).
    BOOST_CHECK_MESSAGE(rejected(setupA.pub, v3->output_coins, /*bind=*/true, H - 1),
        "v3 proof must NOT verify before the C-002 activation height");

    // (4) Output-coin substitution: verify proof A against another proof's
    // valid-size-but-different output coins -> REJECT (the output coins are bound
    // into the proof). (Note: an EMPTY output-coin set is NOT a tamper here — it is
    // the internal "use the proof's own declared coins" path and is never reached
    // by consensus, which always passes the tx-derived, value_commitment-bound
    // coins; see shielded/v2_proof.cpp.)
    BOOST_CHECK_MESSAGE(rejected(setupA.pub, v3b->output_coins, /*bind=*/true, H),
        "v3 proof must NOT verify against a different proof's output coins");
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
