// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/smile2/ct_proof.h>
#include <shielded/smile2/membership.h>
#include <shielded/smile2/ntt.h>
#include <shielded/smile2/params.h>
#include <shielded/smile2/poly.h>
#include <shielded/smile2/public_account.h>
#include <shielded/smile2/serialize.h>
#include <test/util/setup_common.h>
#include <test/util/shielded_smile_test_util.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <random>
#include <vector>

using namespace smile2;

namespace {

constexpr uint64_t CT_TEST_PROOF_RETRY_STRIDE{0xD1B54A32D192ED03ULL};
constexpr uint32_t MAX_CT_TEST_PROOF_ATTEMPTS{32};
constexpr int64_t POSTFORK_TUPLE_COIN_SIGMA{4096};

size_t ComputeRecursionLevelsForTest(size_t N)
{
    if (N <= NUM_NTT_SLOTS) return 1;
    size_t m = 0;
    size_t power = 1;
    while (power < N) {
        power *= NUM_NTT_SLOTS;
        ++m;
    }
    return m;
}

size_t ComputeExpectedCtAuxSlots(size_t num_inputs, size_t num_outputs, size_t N)
{
    const size_t rec_levels = ComputeRecursionLevelsForTest(N);
    const size_t ct_public_rows = KEY_ROWS + 2;
    if (rec_levels == 1) {
        const size_t selectors = num_inputs;
        const size_t amounts = num_inputs + num_outputs;
        const size_t w_rows = num_inputs * ct_public_rows;
        const size_t x_slots = num_inputs;
        const size_t tail = 2;
        return selectors + amounts + w_rows + x_slots + tail;
    }
    return 7 + num_inputs + num_outputs +
           num_inputs * ct_public_rows +
           num_inputs * (rec_levels > 0 ? rec_levels - 1 : 0) * ct_public_rows +
           num_inputs * rec_levels;
}

std::array<uint8_t, 32> MakeSeed(uint8_t val) {
    std::array<uint8_t, 32> seed{};
    seed[0] = val;
    return seed;
}

SmileCTProof ProveCtWithRetriesForTest(const std::vector<CTInput>& inputs,
                                       const std::vector<CTOutput>& outputs,
                                       const CTPublicData& pub,
                                       uint64_t base_seed,
                                       int64_t public_fee = 0)
{
    for (uint32_t attempt = 0; attempt < MAX_CT_TEST_PROOF_ATTEMPTS; ++attempt) {
        const uint64_t attempt_seed = base_seed + (CT_TEST_PROOF_RETRY_STRIDE * attempt);
        SmileCTProof proof = smile2::ProveCT(inputs, outputs, pub, attempt_seed, public_fee);
        if (!proof.serial_numbers.empty() &&
            !proof.z.empty() &&
            !proof.z0.empty() &&
            !proof.aux_commitment.t0.empty()) {
            return proof;
        }
    }
    return {};
}

BDLOPCommitmentKey GetPublicCoinCommitmentKey()
{
    std::array<uint8_t, 32> seed{};
    seed[0] = 0xCC;
    return BDLOPCommitmentKey::Generate(seed, 1);
}

// Generate an anonymity set of N key pairs sharing the same A matrix
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

// Build coin commitments for the anonymity set
// Each member j gets a coin commitment: t_{coin} = ⟨b_coin, r_j⟩ + amount_j
// For non-secret members, amount is random (we don't know their opening)
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

SmilePoly ComputeLinearOpening(Span<const SmilePoly> row, Span<const SmilePoly> opening)
{
    SmilePoly acc;
    const size_t limit = std::min(row.size(), opening.size());
    for (size_t i = 0; i < limit; ++i) {
        acc += NttMul(row[i], opening[i]);
    }
    acc.Reduce();
    return acc;
}

bool HasBoundedCenteredNorm(const SmilePolyVec& response, int64_t sigma)
{
    const int64_t half_q = Q / 2;
    __int128 norm_sq = 0;
    for (const auto& poly : response) {
        for (size_t c = 0; c < POLY_DEGREE; ++c) {
            int64_t val = mod_q(poly.coeffs[c]);
            if (val > half_q) val -= Q;
            norm_sq += static_cast<__int128>(val) * val;
        }
    }
    const __int128 bound_sq =
        static_cast<__int128>(sigma) * sigma * 2 * response.size() * POLY_DEGREE;
    return norm_sq < bound_sq;
}

// Helper to set up a CT test scenario
struct CTTestSetup {
    std::vector<SmileKeyPair> keys;
    CTPublicData pub;
    std::vector<CTInput> inputs;
    std::vector<CTOutput> outputs;

    static CTTestSetup Create(size_t N, size_t num_inputs, size_t num_outputs,
                               const std::vector<int64_t>& in_amounts,
                               const std::vector<int64_t>& out_amounts,
                               uint8_t seed_val)
    {
        CTTestSetup setup;
        setup.keys = GenerateAnonSet(N, seed_val);
        setup.pub.anon_set = ExtractPublicKeys(setup.keys);

        // Select secret indices for inputs
        std::vector<size_t> secret_indices;
        for (size_t i = 0; i < num_inputs; ++i) {
            const size_t preferred_index = i * 3 + 1;
            secret_indices.push_back(preferred_index < N ? preferred_index : N - 1);
        }

        // Build coin rings
        setup.pub.coin_rings = BuildCoinRings(
            setup.keys, secret_indices, in_amounts, seed_val + 100);
        setup.pub.account_rings = test::shielded::BuildDeterministicCTAccountRings(
            setup.keys, setup.pub.coin_rings, static_cast<uint32_t>(seed_val) * 1000 + 200, 0x91);

        // Set up inputs
        const auto coin_ck = GetPublicCoinCommitmentKey();
        setup.inputs.resize(num_inputs);
        for (size_t i = 0; i < num_inputs; ++i) {
            setup.inputs[i].secret_index = secret_indices[i];
            setup.inputs[i].sk = setup.keys[secret_indices[i]].sec;
            setup.inputs[i].amount = in_amounts[i];
            setup.inputs[i].coin_r = SampleTernary(
                coin_ck.rand_dim(),
                static_cast<uint64_t>(seed_val + 100) * 100000 + i * N + secret_indices[i]);
        }

        // Set up outputs
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

BOOST_FIXTURE_TEST_SUITE(smile2_ct_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(p4_g0_try_prove_ct_reports_failure_without_ambiguous_empty_proof)
{
    const auto setup = CTTestSetup::Create(/*N=*/16,
                                           /*num_inputs=*/1,
                                           /*num_outputs=*/1,
                                           {25},
                                           {25},
                                           /*seed_val=*/0x31);

    BOOST_CHECK(!TryProveCT(setup.inputs, setup.outputs, setup.pub, /*rng_seed=*/0x7004, /*public_fee=*/-1).has_value());

    const auto legacy = ProveCT(setup.inputs, setup.outputs, setup.pub, /*rng_seed=*/0x7004, /*public_fee=*/-1);
    BOOST_CHECK(legacy.serial_numbers.empty());
    BOOST_CHECK(legacy.z.empty());
    BOOST_CHECK(legacy.z0.empty());
    BOOST_CHECK(legacy.aux_commitment.t0.empty());
}

BOOST_AUTO_TEST_CASE(p4_g0_try_prove_ct_rejects_unbalanced_statement_early)
{
    const auto setup = CTTestSetup::Create(/*N=*/16,
                                           /*num_inputs=*/1,
                                           /*num_outputs=*/2,
                                           {25},
                                           {10, 20},
                                           /*seed_val=*/0x32);

    BOOST_CHECK(!TryProveCT(setup.inputs, setup.outputs, setup.pub, /*rng_seed=*/0x7005).has_value());

    const auto legacy = ProveCT(setup.inputs, setup.outputs, setup.pub, /*rng_seed=*/0x7005);
    BOOST_CHECK(legacy.serial_numbers.empty());
    BOOST_CHECK(legacy.z.empty());
    BOOST_CHECK(legacy.z0.empty());
    BOOST_CHECK(legacy.aux_commitment.t0.empty());
}

BOOST_AUTO_TEST_CASE(p4_g0_amount_encoding_roundtrip)
{
    for (const int64_t value : {0LL, 1LL, 3LL, 4LL, 42LL, 255LL, 65535LL, 1000000LL}) {
        const auto encoded = EncodeAmountToSmileAmountPoly(value);
        BOOST_REQUIRE(encoded.has_value());
        BOOST_CHECK(IsCanonicalSmileAmountPoly(*encoded));

        const auto decoded = DecodeAmountFromSmileAmountPoly(*encoded);
        BOOST_REQUIRE(decoded.has_value());
        BOOST_CHECK_EQUAL(*decoded, value);

        const NttForm ntt = NttForward(*encoded);
        for (size_t slot = 0; slot < NUM_NTT_SLOTS; ++slot) {
            BOOST_CHECK_LE(mod_q(ntt.slots[slot].coeffs[0]), 3);
            for (size_t coeff = 1; coeff < SLOT_DEGREE; ++coeff) {
                BOOST_CHECK_EQUAL(mod_q(ntt.slots[slot].coeffs[coeff]), 0);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(p4_g0_amount_encoding_rejects_noncanonical_slot_data)
{
    auto encoded = EncodeAmountToSmileAmountPoly(42);
    BOOST_REQUIRE(encoded.has_value());

    NttForm tampered_ntt = NttForward(*encoded);
    tampered_ntt.slots[0].coeffs[1] = 1;
    const SmilePoly tampered = NttInverse(tampered_ntt);

    BOOST_CHECK(!IsCanonicalSmileAmountPoly(tampered));
    BOOST_CHECK(!DecodeAmountFromSmileAmountPoly(tampered).has_value());
}

BOOST_AUTO_TEST_CASE(p4_g0_selected_input_opening_must_match_public_coin)
{
    auto setup = CTTestSetup::Create(/*N=*/32, /*num_inputs=*/1, /*num_outputs=*/1, {100}, {100}, 100);

    auto valid = ProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub, 0xABC001);
    BOOST_REQUIRE(VerifyCT(valid, 1, 1, setup.pub));

    auto tampered_setup = setup;
    BOOST_REQUIRE(!tampered_setup.inputs[0].coin_r.empty());
    BOOST_REQUIRE(!tampered_setup.inputs[0].coin_r[0].coeffs.empty());
    tampered_setup.inputs[0].coin_r[0].coeffs[0] =
        mod_q(tampered_setup.inputs[0].coin_r[0].coeffs[0] + 1);

    auto tampered = smile2::ProveCT(tampered_setup.inputs, tampered_setup.outputs, tampered_setup.pub, 0xABC002);
    BOOST_CHECK(tampered.output_coins.empty());
    BOOST_CHECK(!VerifyCT(tampered, 1, 1, tampered_setup.pub));
}

BOOST_AUTO_TEST_CASE(p4_g0_selected_input_message_must_match_public_coin)
{
    auto setup = CTTestSetup::Create(/*N=*/32, /*num_inputs=*/1, /*num_outputs=*/1, {100}, {100}, 150);

    auto proof = ProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub, 0xABC101);
    BOOST_REQUIRE(VerifyCT(proof, 1, 1, setup.pub));

    auto tampered_pub = setup.pub;
    const size_t secret_index = setup.inputs[0].secret_index;
    BOOST_REQUIRE(secret_index < tampered_pub.coin_rings[0].size());
    BOOST_REQUIRE(!tampered_pub.coin_rings[0][secret_index].t_msg.empty());
    tampered_pub.coin_rings[0][secret_index].t_msg[0].coeffs[0] =
        mod_q(tampered_pub.coin_rings[0][secret_index].t_msg[0].coeffs[0] + 1);
    BOOST_REQUIRE(secret_index < tampered_pub.account_rings[0].size());
    tampered_pub.account_rings[0][secret_index].public_coin = tampered_pub.coin_rings[0][secret_index];

    BOOST_CHECK(!VerifyCT(proof, 1, 1, tampered_pub));
}

BOOST_AUTO_TEST_CASE(p4_g0_selected_input_leaf_must_match_bound_account_leaf)
{
    auto setup = CTTestSetup::Create(/*N=*/32, /*num_inputs=*/1, /*num_outputs=*/1, {100}, {100}, 151);

    auto proof = ProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub, 0xABC102);
    BOOST_REQUIRE(VerifyCT(proof, 1, 1, setup.pub));

    auto tampered_pub = setup.pub;
    const size_t secret_index = setup.inputs[0].secret_index;
    BOOST_REQUIRE(secret_index < tampered_pub.account_rings[0].size());
    tampered_pub.account_rings[0][secret_index].account_leaf_commitment = uint256{0xa5};

    BOOST_CHECK(!VerifyCT(proof, 1, 1, tampered_pub));
}

BOOST_AUTO_TEST_CASE(p4_g0_committed_public_key_slots_share_coin_opening_and_match_hidden_rows)
{
    auto setup = CTTestSetup::Create(/*N=*/32, /*num_inputs=*/1, /*num_outputs=*/1, {125}, {125}, 177);
    const size_t secret_index = setup.inputs[0].secret_index;
    const auto& key_pair = setup.keys[secret_index];
    const auto coin_ck = GetPublicCoinCommitmentKey();
    const auto slot_ck = GetCompactPublicKeySlotCommitmentKey();
    const auto amount_poly = EncodeAmountToSmileAmountPoly(setup.inputs[0].amount);
    BOOST_REQUIRE(amount_poly.has_value());

    const SmilePolyVec account_opening = ExtendCompactPublicKeySlotOpening(
        Span<const SmilePoly>{setup.inputs[0].coin_r.data(), setup.inputs[0].coin_r.size()});
    BOOST_REQUIRE_EQUAL(account_opening.size(), slot_ck.rand_dim());

    const SmilePolyVec public_key_slots = ComputeCompactPublicKeySlots(
        Span<const SmilePoly>{key_pair.pub.pk.data(), key_pair.pub.pk.size()},
        Span<const SmilePoly>{setup.inputs[0].coin_r.data(), setup.inputs[0].coin_r.size()});
    BOOST_REQUIRE_EQUAL(public_key_slots.size(), KEY_ROWS);

    const auto selected_coin = Commit(coin_ck, {*amount_poly}, setup.inputs[0].coin_r);
    for (size_t row = 0; row < BDLOP_RAND_DIM_BASE; ++row) {
        BOOST_CHECK(ComputeLinearOpening(
                        Span<const SmilePoly>{slot_ck.B0[row].data(), slot_ck.B0[row].size()},
                        Span<const SmilePoly>{account_opening.data(), account_opening.size()}) ==
                    selected_coin.t0[row]);
    }

    const SmilePolyVec y0 = SampleTernary(KEY_COLS, /*seed=*/0x55112233ULL);
    const SmilePolyVec y_account = SampleTernary(slot_ck.rand_dim(), /*seed=*/0xAA773355ULL);

    SmilePoly challenge;
    challenge.coeffs[0] = 1;
    SmilePoly alpha;
    alpha.coeffs[0] = 5;
    SmilePoly beta;
    beta.coeffs[0] = 7;

    SmilePolyVec z0(KEY_COLS);
    for (size_t col = 0; col < KEY_COLS; ++col) {
        z0[col] = y0[col] + NttMul(challenge, key_pair.sec.s[col]);
        z0[col].Reduce();
    }

    SmilePolyVec z_account(slot_ck.rand_dim());
    for (size_t col = 0; col < slot_ck.rand_dim(); ++col) {
        z_account[col] = y_account[col] + NttMul(challenge, account_opening[col]);
        z_account[col].Reduce();
    }

    for (size_t row = 0; row < KEY_ROWS; ++row) {
        SmilePoly key_mask;
        for (size_t col = 0; col < KEY_COLS; ++col) {
            key_mask += NttMul(key_pair.pub.A[row][col], y0[col]);
        }
        key_mask.Reduce();
        const SmilePoly slot_mask = ComputeLinearOpening(
            Span<const SmilePoly>{slot_ck.b[row].data(), slot_ck.b[row].size()},
            Span<const SmilePoly>{y_account.data(), y_account.size()});
        const SmilePoly t0_mask = ComputeLinearOpening(
            Span<const SmilePoly>{slot_ck.B0[row].data(), slot_ck.B0[row].size()},
            Span<const SmilePoly>{y_account.data(), y_account.size()});

        SmilePoly lhs;
        for (size_t col = 0; col < KEY_COLS; ++col) {
            lhs += NttMul(key_pair.pub.A[row][col], z0[col]);
        }
        lhs += ComputeLinearOpening(Span<const SmilePoly>{slot_ck.b[row].data(), slot_ck.b[row].size()},
                                    Span<const SmilePoly>{z_account.data(), z_account.size()});
        lhs = NttMul(alpha, lhs);
        lhs += NttMul(beta,
                      ComputeLinearOpening(Span<const SmilePoly>{slot_ck.B0[row].data(), slot_ck.B0[row].size()},
                                           Span<const SmilePoly>{z_account.data(), z_account.size()}));
        lhs -= NttMul(alpha, key_mask + slot_mask);
        lhs -= NttMul(beta, t0_mask);
        lhs.Reduce();

        SmilePoly rhs = NttMul(challenge,
                               NttMul(alpha, public_key_slots[row]) +
                                   NttMul(beta, selected_coin.t0[row]));
        rhs.Reduce();
        BOOST_CHECK(lhs == rhs);
    }
}

BOOST_AUTO_TEST_CASE(p4_g0_committed_public_key_slots_reject_tampered_public_slot)
{
    auto setup = CTTestSetup::Create(/*N=*/32, /*num_inputs=*/1, /*num_outputs=*/1, {125}, {125}, 178);
    const size_t secret_index = setup.inputs[0].secret_index;
    const auto& key_pair = setup.keys[secret_index];
    const auto coin_ck = GetPublicCoinCommitmentKey();
    const auto slot_ck = GetCompactPublicKeySlotCommitmentKey();
    const auto amount_poly = EncodeAmountToSmileAmountPoly(setup.inputs[0].amount);
    BOOST_REQUIRE(amount_poly.has_value());

    SmilePolyVec public_key_slots = ComputeCompactPublicKeySlots(
        Span<const SmilePoly>{key_pair.pub.pk.data(), key_pair.pub.pk.size()},
        Span<const SmilePoly>{setup.inputs[0].coin_r.data(), setup.inputs[0].coin_r.size()});
    BOOST_REQUIRE_EQUAL(public_key_slots.size(), KEY_ROWS);
    public_key_slots[0].coeffs[0] = mod_q(public_key_slots[0].coeffs[0] + 1);

    const SmilePolyVec account_opening = ExtendCompactPublicKeySlotOpening(
        Span<const SmilePoly>{setup.inputs[0].coin_r.data(), setup.inputs[0].coin_r.size()});
    BOOST_REQUIRE_EQUAL(account_opening.size(), slot_ck.rand_dim());
    const auto selected_coin = Commit(coin_ck, {*amount_poly}, setup.inputs[0].coin_r);

    const SmilePolyVec y0 = SampleTernary(KEY_COLS, /*seed=*/0x66112233ULL);
    const SmilePolyVec y_account = SampleTernary(slot_ck.rand_dim(), /*seed=*/0xBB773355ULL);

    SmilePoly challenge;
    challenge.coeffs[0] = 1;
    SmilePoly alpha;
    alpha.coeffs[0] = 5;
    SmilePoly beta;
    beta.coeffs[0] = 7;

    SmilePolyVec z0(KEY_COLS);
    for (size_t col = 0; col < KEY_COLS; ++col) {
        z0[col] = y0[col] + NttMul(challenge, key_pair.sec.s[col]);
        z0[col].Reduce();
    }
    SmilePolyVec z_account(slot_ck.rand_dim());
    for (size_t col = 0; col < slot_ck.rand_dim(); ++col) {
        z_account[col] = y_account[col] + NttMul(challenge, account_opening[col]);
        z_account[col].Reduce();
    }

    SmilePoly key_mask;
    for (size_t col = 0; col < KEY_COLS; ++col) {
        key_mask += NttMul(key_pair.pub.A[0][col], y0[col]);
    }
    key_mask.Reduce();
    const SmilePoly slot_mask = ComputeLinearOpening(
        Span<const SmilePoly>{slot_ck.b[0].data(), slot_ck.b[0].size()},
        Span<const SmilePoly>{y_account.data(), y_account.size()});
    const SmilePoly t0_mask = ComputeLinearOpening(
        Span<const SmilePoly>{slot_ck.B0[0].data(), slot_ck.B0[0].size()},
        Span<const SmilePoly>{y_account.data(), y_account.size()});

    SmilePoly lhs;
    for (size_t col = 0; col < KEY_COLS; ++col) {
        lhs += NttMul(key_pair.pub.A[0][col], z0[col]);
    }
    lhs += ComputeLinearOpening(Span<const SmilePoly>{slot_ck.b[0].data(), slot_ck.b[0].size()},
                                Span<const SmilePoly>{z_account.data(), z_account.size()});
    lhs = NttMul(alpha, lhs);
    lhs += NttMul(beta,
                  ComputeLinearOpening(Span<const SmilePoly>{slot_ck.B0[0].data(), slot_ck.B0[0].size()},
                                       Span<const SmilePoly>{z_account.data(), z_account.size()}));
    lhs -= NttMul(alpha, key_mask + slot_mask);
    lhs -= NttMul(beta, t0_mask);
    lhs.Reduce();

    SmilePoly rhs = NttMul(challenge,
                           NttMul(alpha, public_key_slots[0]) +
                               NttMul(beta, selected_coin.t0[0]));
    rhs.Reduce();
    BOOST_CHECK(lhs != rhs);
}

BOOST_AUTO_TEST_CASE(p4_g0_output_openings_are_required)
{
    auto setup = CTTestSetup::Create(/*N=*/32, /*num_inputs=*/1, /*num_outputs=*/1, {100}, {100}, 101);
    setup.outputs[0].coin_r.clear();

    auto proof = smile2::ProveCT(setup.inputs, setup.outputs, setup.pub, 0xABC003);
    BOOST_CHECK(proof.output_coins.empty());
    BOOST_CHECK(!VerifyCT(proof, 1, 1, setup.pub));
}

BOOST_AUTO_TEST_CASE(p4_g0_tampered_input_coin_opening_proof_rejected)
{
    auto setup = CTTestSetup::Create(/*N=*/32, /*num_inputs=*/1, /*num_outputs=*/1, {100}, {100}, 102);

    auto proof = ProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub, 0xABC004);
    BOOST_REQUIRE(VerifyCT(proof, 1, 1, setup.pub));
    BOOST_REQUIRE(!proof.coin_opening.z.empty());

    proof.coin_opening.z[0].coeffs[0] = mod_q(proof.coin_opening.z[0].coeffs[0] + 1);
    BOOST_CHECK(!VerifyCT(proof, 1, 1, setup.pub));
}

BOOST_AUTO_TEST_CASE(p4_g0_tampered_input_tuple_coin_accumulator_rejected)
{
    auto setup = CTTestSetup::Create(/*N=*/32, /*num_inputs=*/1, /*num_outputs=*/1, {100}, {100}, static_cast<uint8_t>(0xFD));

    auto proof = ProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub, 0xABC0041);
    BOOST_REQUIRE(VerifyCT(proof, 1, 1, setup.pub));
    BOOST_REQUIRE(!proof.tuple_opening_acc.IsZero());

    proof.tuple_opening_acc.coeffs[0] =
        mod_q(proof.tuple_opening_acc.coeffs[0] + 1);
    BOOST_CHECK(!VerifyCT(proof, 1, 1, setup.pub));
}

BOOST_AUTO_TEST_CASE(p1_m4_tampered_input_tuple_amount_opening_rejected)
{
    auto setup = CTTestSetup::Create(/*N=*/32, /*num_inputs=*/1, /*num_outputs=*/1, {100}, {100}, static_cast<uint8_t>(0xFC));

    auto proof = ProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub, 0xABC0044);
    BOOST_REQUIRE(VerifyCT(proof, 1, 1, setup.pub));
    BOOST_REQUIRE(!proof.input_tuples.empty());

    for (auto& coeff : proof.input_tuples[0].z_amount.coeffs) {
        coeff = Q / 2;
    }
    BOOST_CHECK(!VerifyCT(proof, 1, 1, setup.pub));
}

BOOST_AUTO_TEST_CASE(p1_m4_tampered_input_tuple_leaf_opening_rejected)
{
    auto setup = CTTestSetup::Create(/*N=*/32, /*num_inputs=*/1, /*num_outputs=*/1, {100}, {100}, static_cast<uint8_t>(0xFB));

    auto proof = ProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub, 0xABC0045);
    BOOST_REQUIRE(VerifyCT(proof, 1, 1, setup.pub));
    BOOST_REQUIRE(!proof.input_tuples.empty());

    for (auto& coeff : proof.input_tuples[0].z_leaf.coeffs) {
        coeff = Q / 2;
    }
    BOOST_CHECK(!VerifyCT(proof, 1, 1, setup.pub));
}

BOOST_AUTO_TEST_CASE(p1_m4_postfork_tuple_opening_hardening_roundtrips_and_binds_to_v2_wire)
{
    auto setup = CTTestSetup::Create(/*N=*/32, /*num_inputs=*/1, /*num_outputs=*/1, {100}, {100}, static_cast<uint8_t>(0xF9));

    auto proof = ProveCT(setup.inputs,
                         setup.outputs,
                         setup.pub,
                         0xABC0046,
                         /*public_fee=*/0,
                         /*bind_anonset_context=*/true);
    BOOST_REQUIRE_EQUAL(proof.wire_version, SmileCTProof::WIRE_VERSION_M4_HARDENED);
    BOOST_REQUIRE(VerifyCT(proof, 1, 1, setup.pub, /*public_fee=*/0, /*bind_anonset_context=*/true));
    BOOST_REQUIRE_EQUAL(proof.input_tuples.size(), 1U);
    BOOST_CHECK(HasBoundedCenteredNorm(proof.input_tuples[0].z_coin, POSTFORK_TUPLE_COIN_SIGMA));

    const auto proof_bytes = SerializeCTProof(proof);
    BOOST_REQUIRE_GE(proof_bytes.size(), 5U);
    BOOST_CHECK_EQUAL(proof_bytes[0], 0xFF);
    BOOST_CHECK_EQUAL(proof_bytes[1], 0xFF);
    BOOST_CHECK_EQUAL(proof_bytes[2], 0xFF);
    BOOST_CHECK_EQUAL(proof_bytes[3], 0xFF);
    BOOST_CHECK_EQUAL(proof_bytes[4], SmileCTProof::WIRE_VERSION_M4_HARDENED);

    SmileCTProof parsed;
    auto parse_err = ParseSmile2Proof(proof_bytes, 1, 1, parsed);
    BOOST_REQUIRE_MESSAGE(!parse_err.has_value(), parse_err.value_or("ok"));
    BOOST_CHECK_EQUAL(parsed.wire_version, SmileCTProof::WIRE_VERSION_M4_HARDENED);
    BOOST_CHECK_EQUAL(parsed.input_tuples.size(), proof.input_tuples.size());
    BOOST_CHECK(parsed.input_tuples[0].z_amount == proof.input_tuples[0].z_amount);
    BOOST_CHECK(parsed.input_tuples[0].z_leaf == proof.input_tuples[0].z_leaf);
    BOOST_CHECK_MESSAGE(
        !ValidateSmile2Proof(parsed,
                             1,
                             1,
                             proof.output_coins,
                             setup.pub,
                             /*public_fee=*/0,
                             /*bind_anonset_context=*/true)
             .has_value(),
        "postfork hardened proof should validate under bound transcript mode");
    BOOST_CHECK_EQUAL(
        ValidateSmile2Proof(parsed,
                            1,
                            1,
                            proof.output_coins,
                            setup.pub,
                            /*public_fee=*/0,
                            /*bind_anonset_context=*/false)
            .value_or(""),
        "bad-smile2-proof-wire-version");
}

BOOST_AUTO_TEST_CASE(p4_g0_tampered_compressed_w0_commitment_rejected)
{
    auto setup = CTTestSetup::Create(/*N=*/32, /*num_inputs=*/1, /*num_outputs=*/1, {100}, {100}, static_cast<uint8_t>(0xFE));

    auto proof = ProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub, 0xABC0042);
    BOOST_REQUIRE(VerifyCT(proof, 1, 1, setup.pub));
    BOOST_REQUIRE(std::any_of(proof.pre_h2_binding_digest.begin(),
                              proof.pre_h2_binding_digest.end(),
                              [](uint8_t byte) { return byte != 0; }));

    proof.pre_h2_binding_digest[0] ^= 0x01;
    BOOST_CHECK(!VerifyCT(proof, 1, 1, setup.pub));
}

BOOST_AUTO_TEST_CASE(p4_g0_tampered_round1_aux_binding_rejected)
{
    auto setup = CTTestSetup::Create(/*N=*/32, /*num_inputs=*/1, /*num_outputs=*/1, {100}, {100}, static_cast<uint8_t>(0xA7));

    auto proof = ProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub, 0xABC0043);
    BOOST_REQUIRE(VerifyCT(proof, 1, 1, setup.pub));

    proof.round1_aux_binding_digest[0] ^= 0x01;
    BOOST_CHECK(!VerifyCT(proof, 1, 1, setup.pub));
}

BOOST_AUTO_TEST_CASE(p4_g0_tampered_output_coin_opening_proof_rejected)
{
    auto setup = CTTestSetup::Create(/*N=*/32, /*num_inputs=*/1, /*num_outputs=*/1, {100}, {100}, 103);

    auto proof = ProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub, 0xABC005);
    BOOST_REQUIRE(VerifyCT(proof, 1, 1, setup.pub));
    BOOST_REQUIRE(std::any_of(proof.coin_opening.binding_digest.begin(),
                              proof.coin_opening.binding_digest.end(),
                              [](uint8_t byte) { return byte != 0; }));

    proof.coin_opening.binding_digest[0] ^= 0x01;
    BOOST_CHECK(!VerifyCT(proof, 1, 1, setup.pub));
}

BOOST_AUTO_TEST_CASE(p4_g0_tampered_public_garbage_rejected)
{
    auto setup = CTTestSetup::Create(/*N=*/32, /*num_inputs=*/1, /*num_outputs=*/1, {100}, {100}, 104);

    auto proof = ProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub, 0xABC006);
    BOOST_REQUIRE(VerifyCT(proof, 1, 1, setup.pub));

    proof.post_h2_binding_digest[0] ^= 0x01;
    BOOST_CHECK(!VerifyCT(proof, 1, 1, setup.pub));
}

// [P4-G1] Balance proof: in=(100,200), out=(150,150) → verify succeeds.
BOOST_AUTO_TEST_CASE(p4_g1_balance_proof)
{
    const size_t N = 32;
    auto setup = CTTestSetup::Create(N, 2, 2, {100, 200}, {150, 150}, 101);

    auto proof = ProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub, 12345678);

    bool valid = VerifyCT(proof, 2, 2, setup.pub);
    BOOST_CHECK_MESSAGE(valid, "P4-G1: Balance proof should verify for in=(100,200), out=(150,150)");
}

// [P4-G2] Balance rejection: in=(100,200), out=(150,200) → verify FAILS.
BOOST_AUTO_TEST_CASE(p4_g2_balance_rejection)
{
    const size_t N = 32;
    // Amounts don't balance: 100+200=300 ≠ 150+200=350
    auto setup = CTTestSetup::Create(N, 2, 2, {100, 200}, {150, 200}, 102);

    auto proof = smile2::ProveCT(setup.inputs, setup.outputs, setup.pub, 23456789);

    bool valid = VerifyCT(proof, 2, 2, setup.pub);
    BOOST_CHECK_MESSAGE(!valid, "P4-G2: Unbalanced transaction should be rejected");
}

// [P4-G3] Range proof: digit constraint enforces slots ∈ {0,1,2,3}.
BOOST_AUTO_TEST_CASE(p4_g3_range_proof)
{
    const size_t N = 32;
    // Use amounts that fit in base-4 NTT slot encoding
    auto setup = CTTestSetup::Create(N, 1, 1, {255}, {255}, 103);

    auto proof = ProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub, 34567890);

    bool valid = VerifyCT(proof, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(valid, "P4-G3: Valid range proof should verify");

    // Verify that amounts are properly encoded in base-4 via NTT slots
    // 255 in base 4 = 3*4^3 + 3*4^2 + 3*4 + 3 = 3333 base 4
    // Each slot coefficient should be in {0,1,2,3}
    BOOST_CHECK(valid);
}

// [P4-G4] Serial numbers: sn_i = ⟨b_1, s_i⟩ correctly revealed and verified.
BOOST_AUTO_TEST_CASE(p4_g4_serial_numbers)
{
    const size_t N = 32;
    auto setup = CTTestSetup::Create(N, 2, 2, {100, 200}, {150, 150}, 104);

    auto proof = ProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub, 45678901);

    // Check that serial numbers are present
    BOOST_REQUIRE_EQUAL(proof.serial_numbers.size(), 2u);

    // Verify the proof (which checks serial number correctness)
    bool valid = VerifyCT(proof, 2, 2, setup.pub);
    BOOST_CHECK(valid);

    // Serial numbers should be non-zero (overwhelmingly likely)
    bool any_nonzero = false;
    for (const auto& sn : proof.serial_numbers) {
        for (size_t c = 0; c < POLY_DEGREE; ++c) {
            if (mod_q(sn.coeffs[c]) != 0) {
                any_nonzero = true;
                break;
            }
        }
        if (any_nonzero) break;
    }
    BOOST_CHECK(any_nonzero);
}

// [P4-G5] Amortized membership: 2 inputs sharing single z vector.
BOOST_AUTO_TEST_CASE(p4_g5_amortized_membership)
{
    const size_t N = 32;
    auto setup = CTTestSetup::Create(N, 2, 2, {100, 200}, {150, 150}, 105);

    auto proof = ProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub, 56789012);

    // The z vector should be shared (single vector, not per-input)
    BOOST_CHECK(!proof.z.empty());

    // Verify that the proof passes with amortized membership
    bool valid = VerifyCT(proof, 2, 2, setup.pub);
    BOOST_CHECK_MESSAGE(valid, "P4-G5: Amortized membership proof should verify");
}

// [P4-G6] Full 2-in-2-out CT proof at N=32.
// The current rewritten verifier carries the exact coin-opening material and
// the full recursive aux rows needed for the eventual Appendix E verifier, so
// the in-tree target is the higher measured post-rewrite size regime.
BOOST_AUTO_TEST_CASE(p4_g6_full_ct_small)
{
    const size_t N = 32;
    auto setup = CTTestSetup::Create(N, 2, 2, {100, 200}, {150, 150}, 106);

    auto proof = ProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub, 67890123);

    bool valid = VerifyCT(proof, 2, 2, setup.pub);
    BOOST_CHECK(valid);

    size_t proof_size = proof.SerializedSize();
    BOOST_TEST_MESSAGE("P4-G6: 2-in-2-out N=32 proof size = " << proof_size
                       << " bytes (" << (proof_size / 1024.0) << " KB)");
    BOOST_CHECK_LE(proof_size, 96 * 1024);
}

BOOST_AUTO_TEST_CASE(p4_g6c_empty_anonymity_set_rejected)
{
    auto setup = CTTestSetup::Create(/*N=*/16, /*num_inputs=*/1, /*num_outputs=*/1, {100}, {100}, 0x7C);
    setup.pub.anon_set.clear();
    setup.pub.coin_rings.clear();
    setup.pub.account_rings.clear();

    const auto proof = TryProveCT(setup.inputs, setup.outputs, setup.pub, /*rng_seed=*/0x7C01);
    BOOST_CHECK(!proof.has_value());
}

BOOST_AUTO_TEST_CASE(p4_g6c_malformed_public_account_ring_shapes_rejected)
{
    auto setup = CTTestSetup::Create(/*N=*/1, /*num_inputs=*/1, /*num_outputs=*/1, {100}, {100}, 0x7C);

    auto malformed_prove_pub = setup.pub;
    BOOST_REQUIRE(!malformed_prove_pub.account_rings.empty());
    BOOST_REQUIRE(!malformed_prove_pub.account_rings[0].empty());
    malformed_prove_pub.account_rings[0][0].public_key.pk.clear();
    BOOST_CHECK(!TryProveCT(setup.inputs,
                            setup.outputs,
                            malformed_prove_pub,
                            /*rng_seed=*/0x7C02).has_value());

    const auto valid_proof = TryProveCT(setup.inputs, setup.outputs, setup.pub, /*rng_seed=*/0x7C03);
    BOOST_REQUIRE(valid_proof.has_value());

    auto malformed_verify_pub = setup.pub;
    BOOST_REQUIRE(!malformed_verify_pub.account_rings.empty());
    BOOST_REQUIRE(!malformed_verify_pub.account_rings[0].empty());
    malformed_verify_pub.account_rings[0][0].public_coin.t_msg.clear();
    BOOST_CHECK(!VerifyCT(*valid_proof, 1, 1, malformed_verify_pub));
}

BOOST_AUTO_TEST_CASE(p4_g6d_single_member_ring_proves_and_verifies)
{
    auto setup = CTTestSetup::Create(/*N=*/1, /*num_inputs=*/1, /*num_outputs=*/1, {100}, {100}, 0x7D);

    const auto proof = TryProveCT(setup.inputs, setup.outputs, setup.pub, /*rng_seed=*/0x7D01);
    BOOST_REQUIRE(proof.has_value());
    BOOST_CHECK(VerifyCT(*proof, 1, 1, setup.pub));
}

BOOST_AUTO_TEST_CASE(p4_g6e_balanced_zero_amount_input_verifies)
{
    auto setup = CTTestSetup::Create(/*N=*/32, /*num_inputs=*/2, /*num_outputs=*/1, {0, 100}, {100}, 0x7E);

    auto proof = ProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub, 0x7E01);
    BOOST_REQUIRE(!proof.output_coins.empty());
    BOOST_CHECK(VerifyCT(proof, 2, 1, setup.pub));
}

BOOST_AUTO_TEST_CASE(p4_g6f_balanced_zero_amount_output_verifies)
{
    auto setup = CTTestSetup::Create(/*N=*/32, /*num_inputs=*/1, /*num_outputs=*/2, {100}, {0, 100}, 0x7F);

    auto proof = ProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub, 0x7F01);
    BOOST_REQUIRE(!proof.output_coins.empty());
    BOOST_CHECK(VerifyCT(proof, 1, 2, setup.pub));
}

BOOST_AUTO_TEST_CASE(p4_g6b_repeated_two_input_proofs_stay_valid_and_nonlinkable)
{
    const size_t N = 16;
    auto setup = CTTestSetup::Create(N, 2, 2, {125, 275}, {200, 200}, 0x7A);

    std::vector<SmilePoly> reference_serials;
    std::array<uint8_t, 32> first_seed_c{};
    std::array<uint8_t, 32> first_seed_z{};
    std::array<uint8_t, 32> first_fs_seed{};
    bool saw_distinct_transcript = false;

    for (uint64_t i = 0; i < 8; ++i) {
        auto proof = ProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub, 0xD00D0000ULL + i);
        BOOST_REQUIRE_MESSAGE(!proof.output_coins.empty(),
                              "P4-G6b: prover returned an empty proof on repeated 2-input stress attempt " << i);
        BOOST_REQUIRE_MESSAGE(VerifyCT(proof, 2, 2, setup.pub),
                              "P4-G6b: repeated 2-input proof should verify on attempt " << i);

        if (i == 0) {
            reference_serials = proof.serial_numbers;
            first_seed_c = proof.seed_c;
            first_seed_z = proof.seed_z;
            first_fs_seed = proof.fs_seed;
            continue;
        }

        BOOST_CHECK_MESSAGE(proof.serial_numbers == reference_serials,
                            "P4-G6b: repeated proofs for the same hidden spend should keep nullifier binding stable");

        if (proof.seed_c != first_seed_c ||
            proof.seed_z != first_seed_z ||
            proof.fs_seed != first_fs_seed) {
            saw_distinct_transcript = true;
        }
    }

    BOOST_CHECK_MESSAGE(saw_distinct_transcript,
                        "P4-G6b: repeated proofs should not collapse onto one deterministic transcript surface");
}

BOOST_AUTO_TEST_CASE(p4_l7_ct_prover_padding_preserves_output_and_validity)
{
    BOOST_CHECK_EQUAL(smile2::GetCtTimingPaddingAttemptLimit(),
                      smile2::GetCtRejectionRetryBudget());

    auto setup = CTTestSetup::Create(/*N=*/16, /*num_inputs=*/1, /*num_outputs=*/1, {125}, {125}, 0x82);

    const auto proof_a =
        ProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub, 0x5566778899ULL);
    const auto proof_b =
        ProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub, 0x5566778899ULL);

    BOOST_REQUIRE(!proof_a.output_coins.empty());
    BOOST_REQUIRE(!proof_b.output_coins.empty());
    BOOST_REQUIRE(VerifyCT(proof_a, 1, 1, setup.pub));
    BOOST_REQUIRE(VerifyCT(proof_b, 1, 1, setup.pub));
    BOOST_REQUIRE_EQUAL(proof_a.output_coins.size(), proof_b.output_coins.size());
    for (size_t i = 0; i < proof_a.output_coins.size(); ++i) {
        BOOST_CHECK(proof_a.output_coins[i].t0 == proof_b.output_coins[i].t0);
        BOOST_CHECK(proof_a.output_coins[i].t_msg == proof_b.output_coins[i].t_msg);
    }
    BOOST_CHECK(proof_a.aux_commitment.t0 == proof_b.aux_commitment.t0);
    BOOST_CHECK(proof_a.aux_commitment.t_msg == proof_b.aux_commitment.t_msg);
    BOOST_CHECK(proof_a.z == proof_b.z);
    BOOST_CHECK(proof_a.z0 == proof_b.z0);
    BOOST_CHECK(proof_a.serial_numbers == proof_b.serial_numbers);
    BOOST_CHECK(proof_a.seed_c0 == proof_b.seed_c0);
    BOOST_CHECK(proof_a.seed_c == proof_b.seed_c);
    BOOST_CHECK(proof_a.seed_z == proof_b.seed_z);
}

// [P4-G7] The reset-chain launch protocol intentionally supports only the
// single-round CT surface N <= NUM_NTT_SLOTS. Larger prototype CT sets are
// rejected instead of silently falling back to the legacy multi-level path.
BOOST_AUTO_TEST_CASE(p4_g7_large_ct_surface_rejected)
{
    const size_t N = 32768;
    auto setup = CTTestSetup::Create(N, 2, 2, {100, 200}, {150, 150}, 107);

    auto proof = smile2::ProveCT(setup.inputs, setup.outputs, setup.pub, 78901234);

    BOOST_CHECK(!VerifyCT(proof, 2, 2, setup.pub));
    BOOST_CHECK(proof.serial_numbers.empty());
    BOOST_CHECK(proof.aux_commitment.t_msg.empty());
}

BOOST_AUTO_TEST_CASE(p4_g7b_live_single_round_aux_layout)
{
    const size_t N = 32;
    auto setup = CTTestSetup::Create(N, 2, 2, {100, 200}, {150, 150}, 107);

    auto proof = ProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub, 78901235);

    BOOST_REQUIRE(VerifyCT(proof, 2, 2, setup.pub));
    BOOST_CHECK_EQUAL(proof.aux_commitment.t_msg.size(),
                      ComputeExpectedCtAuxSlots(/*num_inputs=*/2, /*num_outputs=*/2, N));
}

// [P4-G8] ZK property: two proofs with different (sender, amount)
// are computationally indistinguishable (statistical test).
BOOST_AUTO_TEST_CASE(p4_g8_zero_knowledge)
{
    const size_t N = 32;

    // Create two different transactions with same public structure
    auto setup1 = CTTestSetup::Create(N, 2, 2, {100, 200}, {150, 150}, 108);
    auto setup2 = CTTestSetup::Create(N, 2, 2, {50, 250}, {175, 125}, 109);

    // Generate multiple proofs for each scenario
    const size_t num_proofs = 20;
    std::vector<double> h2_means1(POLY_DEGREE, 0.0);
    std::vector<double> h2_means2(POLY_DEGREE, 0.0);

    for (size_t i = 0; i < num_proofs; ++i) {
        auto proof1 = ProveCtWithRetriesForTest(setup1.inputs, setup1.outputs, setup1.pub, 80000000 + i);
        auto proof2 = ProveCtWithRetriesForTest(setup2.inputs, setup2.outputs, setup2.pub, 90000000 + i);

        for (size_t c = SLOT_DEGREE; c < POLY_DEGREE; ++c) {
            h2_means1[c] += static_cast<double>(mod_q(proof1.h2.coeffs[c])) / num_proofs;
            h2_means2[c] += static_cast<double>(mod_q(proof2.h2.coeffs[c])) / num_proofs;
        }
    }

    // Both distributions should look uniform ~ Q/2
    double expected_mean = static_cast<double>(Q) / 2.0;
    size_t outlier_count = 0;
    for (size_t c = SLOT_DEGREE; c < POLY_DEGREE; ++c) {
        double dev1 = std::abs(h2_means1[c] - expected_mean) / expected_mean;
        double dev2 = std::abs(h2_means2[c] - expected_mean) / expected_mean;
        if (dev1 > 0.5 || dev2 > 0.5) outlier_count++;
    }

    BOOST_CHECK_LT(outlier_count, POLY_DEGREE / 4);
    BOOST_TEST_MESSAGE("P4-G8: ZK outlier count = " << outlier_count);
}

// [P4-G9] Serialization roundtrip: serialize → deserialize → re-verify.
BOOST_AUTO_TEST_CASE(p4_g9_serialization_roundtrip)
{
    const size_t N = 32;
    auto setup = CTTestSetup::Create(N, 2, 2, {100, 200}, {150, 150}, 110);

    auto proof = ProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub, 89012345);

    // Serialize (compact: excludes output coins, compresses t0)
    auto serialized = SerializeCTProof(proof);
    BOOST_TEST_MESSAGE("P4-G9: Serialized proof size = " << serialized.size()
                       << " bytes (" << (serialized.size() / 1024.0) << " KB)");
    size_t theoretical = proof.SerializedSize();
    BOOST_TEST_MESSAGE("P4-G9: Theoretical proof size = " << theoretical
                       << " bytes (" << (theoretical / 1024.0) << " KB)");

    // Deserialize
    SmileCTProof proof2;
    bool ok = DeserializeCTProof(serialized, proof2, 2, 2);
    BOOST_CHECK_MESSAGE(ok, "P4-G9: Deserialization should succeed");

    // Output coins are NOT in the serialized proof (they are transaction data).
    proof2.output_coins = proof.output_coins;

    BOOST_CHECK_MESSAGE(proof.z == proof2.z,
                        "P4-G9: z should survive serialization roundtrip exactly");
    BOOST_CHECK_MESSAGE(proof.aux_commitment.t0 == proof2.aux_commitment.t0,
                        "P4-G9: aux_commitment.t0 should survive serialization roundtrip exactly");
    BOOST_REQUIRE_EQUAL(proof.aux_commitment.t_msg.size(), proof2.aux_commitment.t_msg.size());
    BOOST_REQUIRE_EQUAL(proof.aux_residues.size(), proof2.aux_residues.size());
    const size_t retained_aux_msg = 0;
    const size_t w0_slot_begin = 2 + 2 + 2;
    const size_t w0_slot_end = w0_slot_begin + 2 * (KEY_ROWS + 2);
    for (size_t slot = 0; slot < retained_aux_msg; ++slot) {
        BOOST_CHECK_MESSAGE(proof.aux_commitment.t_msg[slot] == proof2.aux_commitment.t_msg[slot],
                            "P4-G9: retained aux_commitment.t_msg prefix should survive roundtrip exactly");
    }
    for (size_t slot = retained_aux_msg; slot < proof.aux_commitment.t_msg.size(); ++slot) {
        BOOST_CHECK_MESSAGE(proof2.aux_commitment.t_msg[slot].IsZero(),
                            "P4-G9: omitted aux_commitment.t_msg tail should not be serialized directly");
        if (slot >= w0_slot_begin && slot < w0_slot_end) {
            BOOST_CHECK_MESSAGE(proof2.aux_residues[slot].IsZero(),
                                "P4-G9: omitted W0 aux residues should be replaced by compressed accumulators");
        } else {
            BOOST_CHECK_MESSAGE(proof.aux_residues[slot] == proof2.aux_residues[slot],
                                "P4-G9: omitted non-W0 aux residues should survive roundtrip exactly");
        }
    }
    BOOST_CHECK_MESSAGE(proof.w0_residue_accs == proof2.w0_residue_accs,
                        "P4-G9: compressed W0 residues should survive serialization roundtrip exactly");
    BOOST_CHECK_MESSAGE(proof.round1_aux_binding_digest == proof2.round1_aux_binding_digest,
                        "P4-G9: round-1 aux binding digest should survive serialization roundtrip exactly");
    BOOST_CHECK_MESSAGE(proof.pre_h2_binding_digest == proof2.pre_h2_binding_digest,
                        "P4-G9: pre-h2 binding digest should survive serialization roundtrip exactly");
    BOOST_CHECK_MESSAGE(proof.post_h2_binding_digest == proof2.post_h2_binding_digest,
                        "P4-G9: post-h2 binding digest should survive serialization roundtrip exactly");
    BOOST_CHECK_MESSAGE(proof.input_tuples.size() == proof2.input_tuples.size(),
                        "P4-G9: input tuple count should survive serialization roundtrip exactly");
    if (proof.input_tuples.size() == proof2.input_tuples.size()) {
        for (size_t i = 0; i < proof.input_tuples.size(); ++i) {
            BOOST_CHECK_MESSAGE(proof.input_tuples[i].z_coin == proof2.input_tuples[i].z_coin,
                                "P4-G9: input tuple z_coin should survive serialization roundtrip exactly");
            BOOST_CHECK_MESSAGE(proof.input_tuples[i].z_amount == proof2.input_tuples[i].z_amount,
                                "P4-G9: input tuple z_amount should survive serialization roundtrip exactly");
            BOOST_CHECK_MESSAGE(proof.input_tuples[i].z_leaf == proof2.input_tuples[i].z_leaf,
                                "P4-G9: input tuple z_leaf should survive serialization roundtrip exactly");
        }
    }
    BOOST_CHECK_MESSAGE(proof.tuple_opening_acc == proof2.tuple_opening_acc,
                        "P4-G9: aggregated tuple opening accumulator should survive serialization roundtrip exactly");
    BOOST_CHECK_MESSAGE(proof2.omega.IsZero(),
                        "P4-G9: omega should be reconstructed, not serialized directly");
    BOOST_CHECK_MESSAGE(proof2.framework_omega.IsZero(),
                        "P4-G9: framework omega should be reconstructed, not serialized directly");
    BOOST_CHECK_MESSAGE(proof2.g0.IsZero(),
                        "P4-G9: g0 should be omitted from the hard-fork wire format");

    // Re-verify
    bool valid = VerifyCT(proof2, 2, 2, setup.pub);
    BOOST_CHECK_MESSAGE(valid, "P4-G9: Deserialized proof should verify");
}

BOOST_AUTO_TEST_CASE(p4_g9_roundtrip_zero_omega_tamper_regression)
{
    auto setup = CTTestSetup::Create(/*N=*/32, /*num_inputs=*/1, /*num_outputs=*/1, {100}, {100}, 0x91);
    auto proof = ProveCtWithRetriesForTest(setup.inputs, setup.outputs, setup.pub, 0xABC009);

    const auto serialized = SerializeCTProof(proof);
    SmileCTProof proof2;
    BOOST_REQUIRE(DeserializeCTProof(serialized, proof2, 1, 1));
    proof2.output_coins = proof.output_coins;

    BOOST_REQUIRE(proof2.omega.IsZero());
    BOOST_REQUIRE(proof2.framework_omega.IsZero());
    BOOST_REQUIRE_EQUAL(proof2.w0_residue_accs.size(), 1U);
    BOOST_REQUIRE(VerifyCT(proof2, 1, 1, setup.pub));

    proof2.w0_residue_accs[0].coeffs[0] =
        mod_q(proof2.w0_residue_accs[0].coeffs[0] + 1);
    BOOST_CHECK(!VerifyCT(proof2, 1, 1, setup.pub));
}

// [P4-G10] Double-spend: same input in 2 txns → same serial number.
BOOST_AUTO_TEST_CASE(p4_g10_double_spend)
{
    const size_t N = 32;

    // Two transactions spending the same input (same secret key + index)
    auto setup1 = CTTestSetup::Create(N, 1, 1, {100}, {100}, 111);
    auto setup2 = CTTestSetup::Create(N, 1, 1, {100}, {100}, 111); // same seed = same keys

    // Same input in both transactions
    setup2.inputs[0] = setup1.inputs[0];

    auto proof1 = ProveCtWithRetriesForTest(setup1.inputs, setup1.outputs, setup1.pub, 90123456);
    auto proof2 = ProveCtWithRetriesForTest(setup2.inputs, setup2.outputs, setup2.pub, 11111111);

    // Serial numbers should be the same (derived from same secret key)
    BOOST_REQUIRE_EQUAL(proof1.serial_numbers.size(), 1u);
    BOOST_REQUIRE_EQUAL(proof2.serial_numbers.size(), 1u);

    SmilePoly sn1 = proof1.serial_numbers[0];
    SmilePoly sn2 = proof2.serial_numbers[0];
    sn1.Reduce();
    sn2.Reduce();

    BOOST_CHECK_MESSAGE(sn1 == sn2, "P4-G10: Same input should produce same serial number");
}

// [P4-G11] Soundness: wrong secret key for one input → verify REJECTS.
BOOST_AUTO_TEST_CASE(p4_g11_soundness_wrong_key)
{
    const size_t N = 32;
    auto setup = CTTestSetup::Create(N, 2, 2, {100, 200}, {150, 150}, 112);

    // Replace the first input's secret key with a fake one
    SmileSecretKey fake_sk;
    fake_sk.s = SampleTernary(KEY_COLS, 99999999);
    setup.inputs[0].sk = fake_sk;

    auto proof = smile2::ProveCT(setup.inputs, setup.outputs, setup.pub, 11223344);

    bool valid = VerifyCT(proof, 2, 2, setup.pub);
    BOOST_CHECK_MESSAGE(!valid, "P4-G11: CT proof with wrong secret key should be rejected");
}

BOOST_AUTO_TEST_SUITE_END()
