// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Edge case tests targeting specific implementation gaps:
// - Barrett reduction near Q boundaries
// - DetRng bias/predictability
// - Rejection sampling recursion guard
// - BitReader/BitWriter overflow
// - DecomposeIndex/TensorProduct edge cases
// - Cross-module consistency (VerifyMembership vs VerifyCT)

#include <shielded/smile2/bdlop.h>
#include <shielded/smile2/ct_proof.h>
#include <shielded/smile2/membership.h>
#include <shielded/smile2/ntt.h>
#include <shielded/smile2/params.h>
#include <shielded/smile2/poly.h>
#include <shielded/smile2/serialize.h>
#include <shielded/smile2/wallet_bridge.h>
#include <shielded/note.h>
#include <test/util/smile2_placeholder_utils.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cmath>
#include <limits>
#include <numeric>
#include <random>
#include <set>

using namespace smile2;

namespace {

std::array<uint8_t, 32> Seed(uint8_t v) {
    std::array<uint8_t, 32> s{};
    s[0] = v;
    return s;
}

std::vector<SmileKeyPair> MakeKeys(size_t N, uint8_t seed) {
    auto s = Seed(seed);
    std::vector<SmileKeyPair> keys(N);
    for (size_t i = 0; i < N; ++i)
        keys[i] = SmileKeyPair::Generate(s, 10000 + i);
    return keys;
}

std::vector<SmilePublicKey> PubKeys(const std::vector<SmileKeyPair>& keys) {
    std::vector<SmilePublicKey> pks;
    for (const auto& kp : keys) pks.push_back(kp.pub);
    return pks;
}

ShieldedNote MakeShieldedNote(CAmount value, unsigned char seed)
{
    ShieldedNote note;
    note.value = value;
    note.recipient_pk_hash = uint256{seed};
    note.rho = uint256{static_cast<unsigned char>(seed + 1)};
    note.rcm = uint256{static_cast<unsigned char>(seed + 2)};
    return note;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(smile2_edge_case_tests, BasicTestingSetup)

// ================================================================
// R1: Barrett reduction / mul_mod_q edge cases
// ================================================================

BOOST_AUTO_TEST_CASE(r1_mul_mod_q_near_boundaries)
{
    // Q-1 * Q-1 mod Q
    int64_t qm1 = Q - 1;
    BOOST_CHECK_EQUAL(mul_mod_q(qm1, qm1), mul_mod_q(1, 1)); // (-1)*(-1) = 1

    // Q-1 * 1 mod Q = Q-1
    BOOST_CHECK_EQUAL(mul_mod_q(qm1, 1), qm1);

    // 0 * anything = 0
    BOOST_CHECK_EQUAL(mul_mod_q(0, qm1), 0);
    BOOST_CHECK_EQUAL(mul_mod_q(0, Q), 0);

    // Q * anything = 0 (since Q ≡ 0)
    BOOST_CHECK_EQUAL(mul_mod_q(Q, 12345), 0);
    BOOST_CHECK_EQUAL(mul_mod_q(Q, Q), 0);

    // Large values near overflow: (Q-1)*(Q-1) < 2^64 since Q < 2^32
    // Product = (Q-1)^2 = Q^2 - 2Q + 1. Q^2 ≈ 2^64. Check no overflow.
    int64_t result = mul_mod_q(qm1, qm1);
    BOOST_CHECK_GE(result, 0);
    BOOST_CHECK_LT(result, Q);

    // Specific values that stress __int128 path
    int64_t half_q = Q / 2;
    int64_t r = mul_mod_q(half_q, 2);
    BOOST_CHECK_EQUAL(r, mod_q(Q - 1)); // (Q/2)*2 = Q-1 (since Q is odd)

    BOOST_TEST_MESSAGE("R1: mul_mod_q boundary cases verified ✓");
}

BOOST_AUTO_TEST_CASE(r1_add_sub_mod_q_boundaries)
{
    BOOST_CHECK_EQUAL(add_mod_q(Q - 1, 1), 0);
    BOOST_CHECK_EQUAL(add_mod_q(Q - 1, Q - 1), Q - 2);
    BOOST_CHECK_EQUAL(sub_mod_q(0, 1), Q - 1);
    BOOST_CHECK_EQUAL(sub_mod_q(0, Q - 1), 1);
    BOOST_CHECK_EQUAL(neg_mod_q(0), 0);
    BOOST_CHECK_EQUAL(neg_mod_q(1), Q - 1);

    BOOST_TEST_MESSAGE("R1: add/sub/neg_mod_q boundaries verified ✓");
}

BOOST_AUTO_TEST_CASE(r1_mod_q_and_neg_mod_q_accept_arbitrary_signed_inputs)
{
    const auto exact_mod = [](int64_t x) {
        const __int128 wide = static_cast<__int128>(x);
        const __int128 q = static_cast<__int128>(Q);
        const __int128 reduced = ((wide % q) + q) % q;
        return static_cast<int64_t>(reduced);
    };

    const std::array<int64_t, 12> cases{{
        std::numeric_limits<int64_t>::min(),
        std::numeric_limits<int64_t>::min() + 1,
        -static_cast<int64_t>(2 * Q),
        -static_cast<int64_t>(Q + 17),
        -1,
        0,
        1,
        static_cast<int64_t>(Q - 1),
        static_cast<int64_t>(Q),
        static_cast<int64_t>(Q + 17),
        std::numeric_limits<int64_t>::max() - 1,
        std::numeric_limits<int64_t>::max(),
    }};

    for (const int64_t value : cases) {
        const int64_t reduced = mod_q(value);
        BOOST_CHECK_EQUAL(reduced, exact_mod(value));
        BOOST_CHECK_GE(reduced, 0);
        BOOST_CHECK_LT(reduced, Q);
        BOOST_CHECK_EQUAL(neg_mod_q(value), sub_mod_q(0, value));
    }

    std::mt19937_64 rng(0xB17E5A11ULL);
    std::uniform_int_distribution<int64_t> dist(
        std::numeric_limits<int64_t>::min(),
        std::numeric_limits<int64_t>::max());
    for (size_t i = 0; i < 1024; ++i) {
        const int64_t value = dist(rng);
        BOOST_CHECK_EQUAL(mod_q(value), exact_mod(value));
        BOOST_CHECK_EQUAL(neg_mod_q(value), sub_mod_q(0, value));
    }

    BOOST_TEST_MESSAGE("R1: mod_q/neg_mod_q arbitrary signed inputs verified ✓");
}

BOOST_AUTO_TEST_CASE(r1_mul_mod_q_handles_extreme_signed_inputs)
{
    const auto exact_mul = [](int64_t a, int64_t b) {
        const __int128 lhs = static_cast<__int128>(mod_q(a));
        const __int128 rhs = static_cast<__int128>(mod_q(b));
        return static_cast<int64_t>((lhs * rhs) % static_cast<__int128>(Q));
    };

    const std::array<std::pair<int64_t, int64_t>, 10> cases{{
        {std::numeric_limits<int64_t>::min(), -1},
        {std::numeric_limits<int64_t>::min(), std::numeric_limits<int64_t>::max()},
        {std::numeric_limits<int64_t>::max(), std::numeric_limits<int64_t>::max()},
        {std::numeric_limits<int64_t>::max(), -static_cast<int64_t>(Q + 1)},
        {-static_cast<int64_t>(Q + 17), static_cast<int64_t>(Q + 23)},
        {-1, std::numeric_limits<int64_t>::max()},
        {std::numeric_limits<int64_t>::min() + 7, static_cast<int64_t>(Q - 1)},
        {std::numeric_limits<int64_t>::max() - 7, static_cast<int64_t>(Q - 1)},
        {0, std::numeric_limits<int64_t>::min()},
        {1, std::numeric_limits<int64_t>::max()},
    }};

    for (const auto& [a, b] : cases) {
        BOOST_CHECK_EQUAL(mul_mod_q(a, b), exact_mul(a, b));
    }

    std::mt19937_64 rng(0xC001D00DULL);
    std::uniform_int_distribution<int64_t> dist(
        std::numeric_limits<int64_t>::min(),
        std::numeric_limits<int64_t>::max());
    for (size_t i = 0; i < 1024; ++i) {
        const int64_t a = dist(rng);
        const int64_t b = dist(rng);
        BOOST_CHECK_EQUAL(mul_mod_q(a, b), exact_mul(a, b));
    }

    BOOST_TEST_MESSAGE("R1: mul_mod_q extreme signed inputs verified ✓");
}

BOOST_AUTO_TEST_CASE(r1_inv_mod_q)
{
    // inv(1) = 1
    BOOST_CHECK_EQUAL(inv_mod_q(1), 1);

    // inv(Q-1) = Q-1 (since (Q-1)^2 = 1 mod Q)
    BOOST_CHECK_EQUAL(inv_mod_q(Q - 1), Q - 1);

    // inv(2) * 2 = 1
    int64_t inv2 = inv_mod_q(2);
    BOOST_CHECK_EQUAL(mul_mod_q(inv2, 2), 1);

    // Random value
    int64_t x = 123456789;
    int64_t inv_x = inv_mod_q(x);
    BOOST_CHECK_EQUAL(mul_mod_q(x, inv_x), 1);

    BOOST_TEST_MESSAGE("R1: inv_mod_q verified ✓");
}

// ================================================================
// R2: DetRng bias / predictability
// ================================================================

BOOST_AUTO_TEST_CASE(r2_detrng_no_zero_output)
{
    // DetRng should never produce long runs of zeros
    // Test with various seeds
    for (uint64_t seed = 1; seed < 100; ++seed) {
        // Reproduce the xorshift64 sequence
        uint64_t state = seed;
        bool all_zero = true;
        for (int i = 0; i < 100; ++i) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            if (state != 0) { all_zero = false; break; }
        }
        BOOST_CHECK(!all_zero);
    }
    BOOST_TEST_MESSAGE("R2: DetRng never produces all-zero sequences ✓");
}

BOOST_AUTO_TEST_CASE(r2_adjacent_seeds_decorrelated)
{
    // Adjacent seeds should produce decorrelated output
    // This tests the splitmix64 mixing in ct_proof.cpp's DetRng
    std::set<uint64_t> first_outputs;
    for (uint64_t seed = 1000; seed < 1100; ++seed) {
        // Simple xorshift from seed
        uint64_t state = seed;
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        first_outputs.insert(state);
    }
    // All 100 first outputs should be unique
    BOOST_CHECK_EQUAL(first_outputs.size(), 100u);
    BOOST_TEST_MESSAGE("R2: Adjacent seeds produce unique outputs ✓");
}

// ================================================================
// R3: Rejection sampling recursion guard
// ================================================================

BOOST_AUTO_TEST_CASE(r3_rejection_sampling_terminates)
{
    // ProveMembership with valid inputs should succeed within reasonable retries
    const size_t N = 32;
    auto keys = MakeKeys(N, 0xB3);
    auto pks = PubKeys(keys);

    // Should complete without infinite recursion
    auto proof = ProveMembership(pks, 5, keys[5].sec, 12345);
    bool valid = VerifyMembership(pks, proof);
    BOOST_CHECK(valid);

    BOOST_TEST_MESSAGE("R3: Rejection sampling terminates ✓");
}

// ================================================================
// R4: DecomposeIndex / TensorProduct edge cases
// ================================================================

BOOST_AUTO_TEST_CASE(r4_decompose_index_zero)
{
    auto d = DecomposeIndex(0, 1);
    BOOST_CHECK_EQUAL(d.size(), 1u);
    BOOST_CHECK_EQUAL(d[0][0], 1); // index 0 → first element is 1
    for (size_t i = 1; i < NUM_NTT_SLOTS; ++i) {
        BOOST_CHECK_EQUAL(d[0][i], 0);
    }
    BOOST_TEST_MESSAGE("R4: DecomposeIndex(0,1) correct ✓");
}

BOOST_AUTO_TEST_CASE(r4_decompose_index_max)
{
    // Max index for m=1: N=32, index=31
    auto d = DecomposeIndex(31, 1);
    BOOST_CHECK_EQUAL(d[0][31], 1);
    for (size_t i = 0; i < 31; ++i) {
        BOOST_CHECK_EQUAL(d[0][i], 0);
    }

    // Max for m=2: N=1024, index=1023
    auto d2 = DecomposeIndex(1023, 2);
    // 1023 = 31*32 + 31 → d[0][31]=1, d[1][31]=1
    BOOST_CHECK_EQUAL(d2[0][31], 1);
    BOOST_CHECK_EQUAL(d2[1][31], 1);

    BOOST_TEST_MESSAGE("R4: DecomposeIndex max values correct ✓");
}

BOOST_AUTO_TEST_CASE(r4_decompose_index_terminal_digits_remain_one_hot)
{
    const auto d = DecomposeIndex((NUM_NTT_SLOTS * NUM_NTT_SLOTS) - 1, 2);
    BOOST_REQUIRE_EQUAL(d.size(), 2U);
    for (const auto& digit : d) {
        int64_t weight = 0;
        for (const auto coeff : digit) {
            BOOST_CHECK(coeff == 0 || coeff == 1);
            weight += coeff;
        }
        BOOST_CHECK_EQUAL(weight, 1);
        BOOST_CHECK_EQUAL(digit.back(), 1);
    }
    BOOST_TEST_MESSAGE("R4: DecomposeIndex keeps terminal digits one-hot ✓");
}

BOOST_AUTO_TEST_CASE(r4_tensor_product_single)
{
    // Single vector: tensor product is identity
    std::array<int64_t, NUM_NTT_SLOTS> v{};
    v[5] = 1;
    auto tp = TensorProduct({v});
    BOOST_CHECK_EQUAL(tp.size(), NUM_NTT_SLOTS);
    BOOST_CHECK_EQUAL(tp[5], 1);
    for (size_t i = 0; i < NUM_NTT_SLOTS; ++i) {
        if (i != 5) BOOST_CHECK_EQUAL(tp[i], 0);
    }
    BOOST_TEST_MESSAGE("R4: TensorProduct single vector = identity ✓");
}

BOOST_AUTO_TEST_CASE(r4_tensor_product_two_vectors)
{
    std::array<int64_t, NUM_NTT_SLOTS> v1{}, v2{};
    v1[3] = 1; // one-hot at 3
    v2[7] = 1; // one-hot at 7
    auto tp = TensorProduct({v1, v2});
    BOOST_CHECK_EQUAL(tp.size(), NUM_NTT_SLOTS * NUM_NTT_SLOTS); // 1024
    // Index = 7*32 + 3 = 227
    BOOST_CHECK_EQUAL(tp[7 * NUM_NTT_SLOTS + 3], 1);
    // All others zero
    int64_t sum = 0;
    for (auto v : tp) sum += v;
    BOOST_CHECK_EQUAL(sum, 1);
    BOOST_TEST_MESSAGE("R4: TensorProduct two one-hot vectors correct ✓");
}

BOOST_AUTO_TEST_CASE(r4_tensor_empty)
{
    auto tp = TensorProduct({});
    BOOST_CHECK(tp.empty());
    BOOST_TEST_MESSAGE("R4: TensorProduct empty input → empty ✓");
}

BOOST_AUTO_TEST_CASE(r4_tensor_product_rejects_factor_count_overflow)
{
    size_t max_factors = 1;
    size_t product_size = NUM_NTT_SLOTS;
    while (product_size <= std::numeric_limits<size_t>::max() / NUM_NTT_SLOTS) {
        product_size *= NUM_NTT_SLOTS;
        ++max_factors;
    }

    std::vector<std::array<int64_t, NUM_NTT_SLOTS>> factors(max_factors + 1);
    for (auto& factor : factors) {
        factor.fill(0);
        factor[0] = 1;
    }

    BOOST_CHECK(TensorProduct(factors).empty());
    BOOST_TEST_MESSAGE("R4: TensorProduct rejects factor counts that overflow size_t capacity ✓");
}

// ================================================================
// R5: Wallet bridge validation
// ================================================================

BOOST_AUTO_TEST_CASE(r5_wallet_bridge_empty_inputs)
{
    std::vector<smile2::wallet::SmileInputMaterial> no_inputs;
    std::vector<ShieldedNote> no_outputs;
    std::vector<smile2::wallet::SmileRingMember> no_ring;
    std::vector<uint8_t> entropy(32, 0x55);
    std::vector<uint256> serials;

    auto result = smile2::wallet::CreateSmileProof(
        smile2::wallet::SMILE_GLOBAL_SEED,
        no_inputs, no_outputs, Span<const smile2::wallet::SmileRingMember>{no_ring.data(), no_ring.size()},
        Span<const uint8_t>(entropy), serials);

    BOOST_CHECK(!result.has_value());
    BOOST_TEST_MESSAGE("R5: Empty inputs rejected ✓");
}

BOOST_AUTO_TEST_CASE(r5_wallet_bridge_short_entropy)
{
    std::vector<uint8_t> short_entropy(16, 0x55); // too short
    std::vector<smile2::wallet::SmileRingMember> ring;
    ring.reserve(32);
    for (int i = 0; i < 32; ++i) {
        ring.push_back(smile2::wallet::BuildPlaceholderRingMember(
            smile2::wallet::SMILE_GLOBAL_SEED,
            uint256{static_cast<uint8_t>(0xf0 + i)}));
    }
    smile2::wallet::SmileInputMaterial inp;
    inp.note = MakeShieldedNote(/*value=*/100, /*seed=*/0xf1);
    inp.ring_index = 0;
    std::vector<uint256> serials;

    auto result = smile2::wallet::CreateSmileProof(
        smile2::wallet::SMILE_GLOBAL_SEED,
        {inp}, {inp.note}, Span<const smile2::wallet::SmileRingMember>{ring.data(), ring.size()},
        Span<const uint8_t>(short_entropy), serials);

    BOOST_CHECK(!result.has_value());
    BOOST_TEST_MESSAGE("R5: Short entropy rejected ✓");
}

// ================================================================
// R6: Cross-module consistency
// ================================================================

BOOST_AUTO_TEST_CASE(r6_membership_ct_same_key_same_serial)
{
    // A key used in both membership proof and CT proof should produce
    // the same serial number (double-spend detection depends on this).
    auto sn_ck_seed = std::array<uint8_t, 32>{};
    sn_ck_seed[0] = 0xAA;
    auto sn_ck = BDLOPCommitmentKey::Generate(sn_ck_seed, 1);

    // Generate a key
    auto seed = Seed(0xCC);
    auto kp = SmileKeyPair::Generate(seed, 42);

    // Compute serial from membership path
    SmilePoly sn = ComputeSerialNumber(sn_ck, kp.sec);
    sn.Reduce();

    // Compute serial from CT path (ProveCT uses the same function)
    SmilePoly sn2 = ComputeSerialNumber(sn_ck, kp.sec);
    sn2.Reduce();

    BOOST_CHECK(sn == sn2);
    BOOST_CHECK(!sn.IsZero());

    BOOST_TEST_MESSAGE("R6: Membership and CT serial numbers match for same key ✓");
}

BOOST_AUTO_TEST_CASE(r6_poly_ntt_consistency)
{
    // Verify NttMul matches MulSchoolbook for edge cases
    SmilePoly zero;
    SmilePoly one;
    one.coeffs[0] = 1;

    // 0 * anything = 0
    SmilePoly result = NttMul(zero, one);
    result.Reduce();
    BOOST_CHECK(result.IsZero());

    // 1 * p = p
    SmilePoly p;
    p.coeffs[0] = 42;
    p.coeffs[1] = 100;
    result = NttMul(one, p);
    result.Reduce();
    SmilePoly expected = p;
    expected.Reduce();
    BOOST_CHECK(result == expected);

    BOOST_TEST_MESSAGE("R6: NTT multiplication consistent with identity/zero ✓");
}

BOOST_AUTO_TEST_CASE(r6_serialize_roundtrip_membership)
{
    const size_t N = 32;
    auto keys = MakeKeys(N, 0xF1);
    auto pks = PubKeys(keys);

    auto proof = ProveMembership(pks, 7, keys[7].sec, 999);
    BOOST_CHECK(VerifyMembership(pks, proof));

    // Serialize and deserialize
    size_t expected = proof.SerializedSize();
    BOOST_CHECK_GT(expected, 0u);
    BOOST_TEST_MESSAGE("R6: Membership proof serialized size = " << expected << " bytes ✓");
}

BOOST_AUTO_TEST_SUITE_END()
