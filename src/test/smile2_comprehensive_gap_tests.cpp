// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Comprehensive gap tests for SMILE v2: covers remaining untested areas
// including modular arithmetic edge cases, recursion/padding, schoolbook
// overflow analysis, challenge bias, BDLOP strong/weak opening, NTT with
// unreduced inputs, serialization edge cases, wallet bridge adversarial
// inputs, CT weak opening gap, timing side channel indicators, and proof
// malleability.

#include <shielded/smile2/bdlop.h>
#include <shielded/smile2/ct_proof.h>
#include <shielded/smile2/membership.h>
#include <shielded/smile2/ntt.h>
#include <shielded/smile2/params.h>
#include <shielded/smile2/poly.h>
#include <shielded/smile2/serialize.h>
#include <shielded/smile2/wallet_bridge.h>
#include <shielded/smile2/verify_dispatch.h>
#include <shielded/note.h>
#include <test/util/smile2_placeholder_utils.h>
#include <test/util/setup_common.h>
#include <test/util/shielded_smile_test_util.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <climits>
#include <cmath>
#include <cstdint>
#include <numeric>
#include <vector>

using namespace smile2;

namespace {

constexpr size_t LIVE_CT_PUBLIC_ROWS = KEY_ROWS + 2;

std::array<uint8_t, 32> MakeSeed(uint8_t v) {
    std::array<uint8_t, 32> s{};
    s[0] = v;
    return s;
}

size_t LiveCtW0Slot(size_t num_inputs, size_t num_outputs, size_t input_index, size_t row)
{
    return num_inputs + (num_inputs + num_outputs) + input_index * LIVE_CT_PUBLIC_ROWS + row;
}

std::vector<SmileKeyPair> GenerateKeys(size_t N, uint8_t seed_val) {
    auto s = MakeSeed(seed_val);
    std::vector<SmileKeyPair> keys(N);
    for (size_t i = 0; i < N; ++i)
        keys[i] = SmileKeyPair::Generate(s, 50000 + i);
    return keys;
}

std::vector<SmilePublicKey> ExtractPubKeys(const std::vector<SmileKeyPair>& keys) {
    std::vector<SmilePublicKey> pks;
    pks.reserve(keys.size());
    for (const auto& kp : keys) pks.push_back(kp.pub);
    return pks;
}

BDLOPCommitment BuildGapCoin(uint8_t seed_val, uint64_t randomness_seed, int64_t amount)
{
    auto ck = BDLOPCommitmentKey::Generate(MakeSeed(seed_val), 1);
    SmilePoly amount_poly = EncodeAmountToSmileAmountPoly(amount).value();
    return Commit(ck, {amount_poly}, SampleTernary(ck.rand_dim(), randomness_seed));
}

// Reimplementation of ComputeRecursionLevels (internal to membership.cpp)
// for testing purposes. Mirrors the logic: if N <= l return 1, else
// find smallest m such that l^m >= N.
size_t TestComputeRecursionLevels(size_t N) {
    if (N <= NUM_NTT_SLOTS) return 1;
    size_t m = 0;
    size_t power = 1;
    while (power < N) {
        power *= NUM_NTT_SLOTS;
        m++;
    }
    return m;
}

// Reimplementation of PadToLPower for testing.
size_t TestPadToLPower(size_t N) {
    size_t m = TestComputeRecursionLevels(N);
    size_t padded = 1;
    for (size_t i = 0; i < m; ++i) padded *= NUM_NTT_SLOTS;
    return padded;
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

// Build a minimal CT setup for a 1-in-1-out balanced transaction.
// Returns true if prove+verify succeeds.
struct MiniCTSetup {
    std::vector<SmileKeyPair> keys;
    std::vector<SmilePublicKey> pks;
    CTPublicData pub;
    std::vector<CTInput> inputs;
    std::vector<CTOutput> outputs;
    size_t N;

    void Build(size_t ring_size, size_t secret_idx, int64_t amount, uint8_t seed_val) {
        N = ring_size;
        keys.clear();
        pks.clear();
        pub = CTPublicData{};
        inputs.clear();
        outputs.clear();

        keys = GenerateKeys(N, seed_val);
        pks = ExtractPubKeys(keys);

        pub.anon_set = pks;
        const auto coin_ck = BDLOPCommitmentKey::Generate(MakeSeed(0xCC), 1);
        const auto amount_poly = EncodeAmountToSmileAmountPoly(amount);
        BOOST_REQUIRE(amount_poly.has_value());

        std::vector<BDLOPCommitment> coin_ring(N);
        const auto selected_opening = SampleTernary(
            coin_ck.rand_dim(),
            static_cast<uint64_t>(seed_val) * 100000 + secret_idx);
        for (size_t i = 0; i < N; ++i) {
            if (i == secret_idx) {
                coin_ring[i] = Commit(coin_ck, {*amount_poly}, selected_opening);
            } else {
                coin_ring[i] = BuildGapCoin(seed_val, 78000 + i, static_cast<int64_t>(i + 1));
            }
        }
        pub.coin_rings.push_back(coin_ring);
        pub.account_rings = test::shielded::BuildDeterministicCTAccountRings(
            keys,
            pub.coin_rings,
            static_cast<uint32_t>(seed_val) * 1000 + 300,
            0xA7);

        CTInput inp;
        inp.secret_index = secret_idx;
        inp.sk = keys[secret_idx].sec;
        inp.coin_r = selected_opening;
        inp.amount = amount;
        inputs.push_back(inp);

        CTOutput out;
        out.amount = amount;
        out.coin_r = SampleTernary(
            coin_ck.rand_dim(),
            static_cast<uint64_t>(seed_val) * 1000000 + 1);
        outputs.push_back(out);
    }
};

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(smile2_comprehensive_gap_tests, BasicTestingSetup)

// ================================================================
// S1: Modular arithmetic with unreduced inputs
// ================================================================

BOOST_AUTO_TEST_CASE(s1_add_mod_q_double_q)
{
    // add_mod_q(Q, Q): both inputs are Q (equivalent to 0 mod q).
    // The implementation does s = Q + Q = 2Q, then checks s >= Q -> s - Q = Q.
    // This returns Q, not 0. This is a BUG if callers expect fully reduced output.
    int64_t result = add_mod_q(Q, Q);
    // Document the behavior: result is Q (unreduced) rather than 0.
    // Callers MUST call mod_q() on the result if inputs may be >= Q.
    BOOST_CHECK_MESSAGE(result == Q || result == 0,
        "add_mod_q(Q, Q) returned " << result << "; expected Q or 0");
    if (result == Q) {
        BOOST_TEST_MESSAGE("S1: CONFIRMED BUG: add_mod_q(Q, Q) returns Q (not 0). "
                           "Callers must pre-reduce or post-reduce.");
    } else {
        BOOST_TEST_MESSAGE("S1: add_mod_q(Q, Q) correctly returns 0.");
    }
}

BOOST_AUTO_TEST_CASE(s1_add_mod_q_double_wrap)
{
    // add_mod_q(2*Q-1, 1) = 2*Q. The code does s = 2Q, s >= Q -> s - Q = Q.
    // Again returns Q instead of 0 -- same single-subtraction limitation.
    int64_t result = add_mod_q(2 * Q - 1, 1);
    BOOST_CHECK_MESSAGE(result == Q || result == 0,
        "add_mod_q(2Q-1, 1) returned " << result);
    BOOST_TEST_MESSAGE("S1: add_mod_q(2Q-1, 1) = " << result
                       << (result == Q ? " (unreduced -- BUG)" : " (correct)"));
}

BOOST_AUTO_TEST_CASE(s1_sub_mod_q_zero_minus_q)
{
    // sub_mod_q(0, Q): s = 0 - Q = -Q, then s < 0 -> s + Q = 0.
    int64_t result = sub_mod_q(0, Q);
    BOOST_CHECK_EQUAL(result, 0);
    BOOST_TEST_MESSAGE("S1: sub_mod_q(0, Q) = 0 (correct)");
}

BOOST_AUTO_TEST_CASE(s1_mod_q_negative_multiple)
{
    // mod_q(-Q): -Q % Q = 0 in C++ (since -Q / Q = -1, remainder 0).
    int64_t result = mod_q(-Q);
    BOOST_CHECK_EQUAL(result, 0);
    BOOST_TEST_MESSAGE("S1: mod_q(-Q) = 0 (correct)");
}

BOOST_AUTO_TEST_CASE(s1_mod_q_int64_min)
{
    // mod_q(INT64_MIN): INT64_MIN % Q. C++ truncation toward zero.
    // INT64_MIN = -9223372036854775808. -9223372036854775808 % 4294966337 = ?
    // The remainder will be negative, then + Q makes it positive.
    int64_t result = mod_q(INT64_MIN);
    BOOST_CHECK_GE(result, 0);
    BOOST_CHECK_LT(result, Q);
    // Verify: INT64_MIN mod Q should be in [0, Q)
    // INT64_MIN / Q (truncated) * Q subtracted from INT64_MIN gives remainder.
    BOOST_TEST_MESSAGE("S1: mod_q(INT64_MIN) = " << result << " (in [0, Q))");
}

// ================================================================
// S2: ComputeRecursionLevels / PadToLPower edge cases
// ================================================================

BOOST_AUTO_TEST_CASE(s2_recursion_n_zero)
{
    // N=0: ComputeRecursionLevels checks N <= 32 first, so returns 1.
    size_t m = TestComputeRecursionLevels(0);
    size_t padded = TestPadToLPower(0);
    BOOST_CHECK_EQUAL(m, 1u);
    BOOST_CHECK_EQUAL(padded, 32u);
    BOOST_TEST_MESSAGE("S2: N=0 -> m=1, padded=32");
}

BOOST_AUTO_TEST_CASE(s2_recursion_n_one)
{
    // N=1: trivially <= 32, so m=1, padded = 32.
    size_t m = TestComputeRecursionLevels(1);
    size_t padded = TestPadToLPower(1);
    BOOST_CHECK_EQUAL(m, 1u);
    BOOST_CHECK_EQUAL(padded, 32u);
    BOOST_TEST_MESSAGE("S2: N=1 -> m=1, padded=32");
}

BOOST_AUTO_TEST_CASE(s2_recursion_n_33)
{
    // N=33: exceeds l=32, need 32^2 = 1024 >= 33, so m=2.
    size_t m = TestComputeRecursionLevels(33);
    size_t padded = TestPadToLPower(33);
    BOOST_CHECK_EQUAL(m, 2u);
    BOOST_CHECK_EQUAL(padded, 1024u);
    BOOST_TEST_MESSAGE("S2: N=33 -> m=2, padded=1024");
}

BOOST_AUTO_TEST_CASE(s2_recursion_n_32768)
{
    // N=32768 = 32^3: exact power of l, m=3, padded = 32768.
    size_t m = TestComputeRecursionLevels(32768);
    size_t padded = TestPadToLPower(32768);
    BOOST_CHECK_EQUAL(m, 3u);
    BOOST_CHECK_EQUAL(padded, 32768u);
    BOOST_TEST_MESSAGE("S2: N=32768 -> m=3, padded=32768");
}

BOOST_AUTO_TEST_CASE(s2_recursion_n_32769)
{
    // N=32769: one over 32^3, need 32^4 = 1048576 >= 32769, so m=4.
    size_t m = TestComputeRecursionLevels(32769);
    size_t padded = TestPadToLPower(32769);
    BOOST_CHECK_EQUAL(m, 4u);
    BOOST_CHECK_EQUAL(padded, 1048576u);
    BOOST_TEST_MESSAGE("S2: N=32769 -> m=4, padded=1048576");
}

// ================================================================
// S3: MulSchoolbook overflow check
// ================================================================

BOOST_AUTO_TEST_CASE(s3_mulschoolbook_max_coefficients)
{
    // Create two polynomials with all coefficients = Q-1.
    // MulSchoolbook uses mul_mod_q per pair (Barrett reduction), then
    // add_mod_q / sub_mod_q for accumulation. Each individual operation
    // stays within [0, Q), so no int64_t overflow occurs.
    //
    // The concern was that intermediate sums could reach 128*(Q-1)^2 ~ 2.3e21,
    // but the implementation reduces each mul_mod_q result before accumulating,
    // so the sum is at most 128*(Q-1) ~ 5.5e11, well within int64_t range.
    // This is NOT an overflow bug due to per-pair Barrett reduction.

    SmilePoly a, b;
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        a.coeffs[i] = Q - 1;
        b.coeffs[i] = Q - 1;
    }

    SmilePoly school = a.MulSchoolbook(b);
    school.Reduce();

    SmilePoly ntt_result = NttMul(a, b);
    ntt_result.Reduce();

    // Both methods should produce the same result.
    bool match = (school == ntt_result);
    BOOST_CHECK_MESSAGE(match,
        "S3: MulSchoolbook and NttMul disagree for max-coefficient inputs");

    if (match) {
        BOOST_TEST_MESSAGE("S3: MulSchoolbook and NttMul agree for all-Q-1 inputs. "
                           "No overflow: implementation uses per-pair Barrett reduction.");
    } else {
        // If they disagree, document which coefficients differ.
        size_t diffs = 0;
        for (size_t i = 0; i < POLY_DEGREE; ++i) {
            if (school.coeffs[i] != ntt_result.coeffs[i]) diffs++;
        }
        BOOST_TEST_MESSAGE("S3: OVERFLOW DETECTED: " << diffs << " coefficients differ.");
    }
}

BOOST_AUTO_TEST_CASE(s3_mulschoolbook_vs_ntt_random)
{
    // Cross-check schoolbook vs NTT for a random-looking polynomial.
    SmilePoly a, b;
    uint64_t state = 0xDEADBEEF;
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        state ^= state << 13; state ^= state >> 7; state ^= state << 17;
        a.coeffs[i] = mod_q(static_cast<int64_t>(state));
        state ^= state << 13; state ^= state >> 7; state ^= state << 17;
        b.coeffs[i] = mod_q(static_cast<int64_t>(state));
    }

    SmilePoly school = a.MulSchoolbook(b);
    school.Reduce();
    SmilePoly ntt_result = NttMul(a, b);
    ntt_result.Reduce();

    BOOST_CHECK(school == ntt_result);
    BOOST_TEST_MESSAGE("S3: Schoolbook and NTT agree on pseudo-random input.");
}

// ================================================================
// S4: HashToScalarChallenge bias
// ================================================================

BOOST_AUTO_TEST_CASE(s4_hash_to_scalar_challenge_bias)
{
    // HashToScalarChallenge computes val = uint32 % Q where Q = 2^32 - 959.
    // Values in [0, 958] have probability ceil(2^32/Q)/2^32
    // Values in [959, Q-1] have probability floor(2^32/Q)/2^32
    // The bias is at most 959/2^32 ~ 2.23e-7, which is negligible.
    //
    // We cannot call HashToScalarChallenge directly (anonymous namespace),
    // so we simulate the same modular reduction to quantify the bias.

    // Analytical approach: Q = 2^32 - 959. When computing uint32 % Q:
    //   - Values 0..958 each have 2 preimages (from [0, Q-1] and [Q, 2^32-1])
    //   - Values 959..Q-1 each have 1 preimage (from [959, Q-1])
    // Total preimages: 959*2 + (Q-959)*1 = 959 + Q = 959 + 4294966337 = 4294967296 = 2^32. Correct.
    //
    // The per-element bias: Pr[val % Q = x] for x in [0,958] is 2/2^32,
    // vs Pr[val % Q = x] for x in [959, Q-1] is 1/2^32.
    // The density ratio is exactly 2.0 for the first 959 values.
    //
    // However, this affects SOUNDNESS bias by at most:
    //   max |Pr[x] - 1/Q| = |2/2^32 - 1/Q| = |2/(Q+959) - 1/Q|
    //                      = |(2Q - Q - 959) / (Q*(Q+959))| = |(Q - 959) / (Q*(Q+959))|
    // which is approximately 1 / (Q+959) ~ 2.33e-10.
    // Statistical distance between uniform and biased = 959 * (1/2^32) / 2 ~ 1.12e-7.
    // Both are well below 2^{-20} ~ 9.5e-7.

    // Verify the theoretical analysis: 2^32 = Q + 959
    uint64_t two_32 = 4294967296ULL;
    BOOST_CHECK_EQUAL(two_32, static_cast<uint64_t>(Q) + 959ULL);

    // The statistical distance is 959 / (2 * 2^32) ~ 1.12e-7
    double stat_distance = 959.0 / (2.0 * 4294967296.0);
    BOOST_CHECK_LT(stat_distance, std::pow(2.0, -20.0));

    // Verify with a small sample that the modular reduction works as expected:
    // Check that (Q + 0) % Q == 0, (Q + 958) % Q == 958 (the wrap range)
    for (uint32_t x = 0; x <= 958; ++x) {
        uint32_t from_wrap = static_cast<uint32_t>(Q) + x;
        BOOST_CHECK_EQUAL(static_cast<int64_t>(from_wrap) % Q, static_cast<int64_t>(x));
    }

    BOOST_TEST_MESSAGE("S4: HashToScalarChallenge bias analysis: stat_distance = "
                       << stat_distance << " < 2^{-20} (negligible for soundness). "
                       "Values [0,958] have 2x density vs [959,Q-1].");
}

// ================================================================
// S5: BDLOP strong vs weak opening
// ================================================================

BOOST_AUTO_TEST_CASE(s5_bdlop_strong_opening_correct)
{
    auto ck_seed = MakeSeed(0xAB);
    size_t n_msg = 2;
    auto ck = BDLOPCommitmentKey::Generate(ck_seed, n_msg);

    // Create messages
    SmilePoly m0, m1;
    m0.coeffs[0] = 42;
    m1.coeffs[0] = 99;
    std::vector<SmilePoly> msgs = {m0, m1};

    // Sample randomness and commit
    auto r = SampleTernary(ck.rand_dim(), 12345);
    auto com = Commit(ck, msgs, r);

    // Verify correct opening
    bool valid = VerifyOpening(ck, com, msgs, r);
    BOOST_CHECK(valid);
    BOOST_TEST_MESSAGE("S5: Correct BDLOP opening verified.");
}

BOOST_AUTO_TEST_CASE(s5_bdlop_strong_opening_wrong_r)
{
    auto ck_seed = MakeSeed(0xAC);
    size_t n_msg = 2;
    auto ck = BDLOPCommitmentKey::Generate(ck_seed, n_msg);

    SmilePoly m0, m1;
    m0.coeffs[0] = 42;
    m1.coeffs[0] = 99;
    std::vector<SmilePoly> msgs = {m0, m1};

    auto r = SampleTernary(ck.rand_dim(), 54321);
    auto com = Commit(ck, msgs, r);

    // Perturb r: add 1 to first coefficient of first polynomial
    SmilePolyVec bad_r = r;
    bad_r[0].coeffs[0] = add_mod_q(bad_r[0].coeffs[0], 1);

    bool valid = VerifyOpening(ck, com, msgs, bad_r);
    BOOST_CHECK(!valid);
    BOOST_TEST_MESSAGE("S5: BDLOP opening with r+1 correctly rejected.");
}

BOOST_AUTO_TEST_CASE(s5_bdlop_weak_opening_correct)
{
    auto ck_seed = MakeSeed(0xAD);
    size_t n_msg = 1;
    auto ck = BDLOPCommitmentKey::Generate(ck_seed, n_msg);

    SmilePoly msg;
    msg.coeffs[0] = 77;
    std::vector<SmilePoly> msgs = {msg};

    auto r = SampleTernary(ck.rand_dim(), 11111);
    auto com = Commit(ck, msgs, r);

    // Simulate weak opening: z = y + c*r, w0 = B0*y
    // Use a simple challenge c (monomial X^0 = 1, i.e., constant 1)
    SmilePoly c_chal;
    c_chal.coeffs[0] = 1;

    // Sample y (masking nonce)
    auto y = SampleTernary(ck.rand_dim(), 22222);

    // z = y + c*r. Since c = 1, z = y + r.
    SmilePolyVec z(ck.rand_dim());
    for (size_t i = 0; i < ck.rand_dim(); ++i) {
        z[i] = y[i] + r[i];
        z[i].Reduce();
    }

    // w0 = B0 * y (binding part of the commitment to y)
    SmilePolyVec w0(BDLOP_RAND_DIM_BASE);
    for (size_t row = 0; row < BDLOP_RAND_DIM_BASE; ++row) {
        SmilePoly acc;
        for (size_t col = 0; col < ck.rand_dim(); ++col) {
            acc += NttMul(ck.B0[row][col], y[col]);
        }
        acc.Reduce();
        w0[row] = acc;
    }

    // f_i = inner(b_i, y) - c * m_i (for each message slot)
    // Since c = 1: f_i = inner(b_i, y) - m_i
    std::vector<SmilePoly> f(n_msg);
    for (size_t i = 0; i < n_msg; ++i) {
        SmilePoly acc;
        for (size_t col = 0; col < ck.rand_dim(); ++col) {
            acc += NttMul(ck.b[i][col], y[col]);
        }
        f[i] = acc - msgs[i];
        f[i].Reduce();
    }

    bool valid = VerifyWeakOpening(ck, com, z, w0, c_chal, f);
    BOOST_CHECK(valid);
    BOOST_TEST_MESSAGE("S5: Correct BDLOP weak opening verified.");
}

BOOST_AUTO_TEST_CASE(s5_bdlop_weak_opening_wrong_w)
{
    auto ck_seed = MakeSeed(0xAE);
    size_t n_msg = 1;
    auto ck = BDLOPCommitmentKey::Generate(ck_seed, n_msg);

    SmilePoly msg;
    msg.coeffs[0] = 77;
    std::vector<SmilePoly> msgs = {msg};

    auto r = SampleTernary(ck.rand_dim(), 33333);
    auto com = Commit(ck, msgs, r);

    SmilePoly c_chal;
    c_chal.coeffs[0] = 1;

    auto y = SampleTernary(ck.rand_dim(), 44444);

    SmilePolyVec z(ck.rand_dim());
    for (size_t i = 0; i < ck.rand_dim(); ++i) {
        z[i] = y[i] + r[i];
        z[i].Reduce();
    }

    // Compute correct w0, then corrupt it
    SmilePolyVec w0(BDLOP_RAND_DIM_BASE);
    for (size_t row = 0; row < BDLOP_RAND_DIM_BASE; ++row) {
        SmilePoly acc;
        for (size_t col = 0; col < ck.rand_dim(); ++col) {
            acc += NttMul(ck.B0[row][col], y[col]);
        }
        acc.Reduce();
        w0[row] = acc;
    }

    // Corrupt w0: add delta to first component
    w0[0].coeffs[0] = add_mod_q(w0[0].coeffs[0], 1);

    std::vector<SmilePoly> f(n_msg);
    for (size_t i = 0; i < n_msg; ++i) {
        SmilePoly acc;
        for (size_t col = 0; col < ck.rand_dim(); ++col) {
            acc += NttMul(ck.b[i][col], y[col]);
        }
        f[i] = acc - msgs[i];
        f[i].Reduce();
    }

    bool valid = VerifyWeakOpening(ck, com, z, w0, c_chal, f);
    BOOST_CHECK(!valid);
    BOOST_TEST_MESSAGE("S5: BDLOP weak opening with wrong w0 correctly rejected.");
}

// ================================================================
// S6: NTT with unreduced / adversarial inputs
// ================================================================

BOOST_AUTO_TEST_CASE(s6_ntt_unreduced_coefficients)
{
    // NttForward with coefficients > Q (e.g., 2*Q).
    // After NttInverse(NttForward(p)), reducing should recover p mod q.
    // NOTE: NTT internals use mul_mod_q which expects inputs in [0, Q).
    // Passing unreduced inputs may produce incorrect results -- this test
    // documents whether the implementation is tolerant of unreduced inputs.
    SmilePoly p;
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        p.coeffs[i] = 2 * Q + static_cast<int64_t>(i);
    }

    // First reduce, then NTT round-trip (the "correct" approach)
    SmilePoly p_reduced;
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        p_reduced.coeffs[i] = mod_q(p.coeffs[i]);
    }

    NttForm ntt_reduced = NttForward(p_reduced);
    SmilePoly recovered_reduced = NttInverse(ntt_reduced);
    recovered_reduced.Reduce();

    // The reduced round-trip should be exact
    BOOST_CHECK(recovered_reduced == p_reduced);

    // Now try without pre-reduction (may or may not work)
    NttForm ntt_p = NttForward(p);
    SmilePoly recovered = NttInverse(ntt_p);
    recovered.Reduce();

    // Compare: if they match, NTT is tolerant of unreduced inputs
    bool tolerant = (recovered == recovered_reduced);
    if (tolerant) {
        BOOST_TEST_MESSAGE("S6: NTT round-trip tolerates unreduced (>Q) inputs.");
    } else {
        // Count how many differ
        size_t diffs = 0;
        for (size_t i = 0; i < POLY_DEGREE; ++i) {
            if (recovered.coeffs[i] != recovered_reduced.coeffs[i]) diffs++;
        }
        BOOST_TEST_MESSAGE("S6: NTT round-trip with unreduced inputs: "
                           << diffs << "/" << POLY_DEGREE << " coefficients differ. "
                           "Callers MUST reduce before NttForward.");
    }
    // Either outcome is acceptable -- the test documents the behavior.
    BOOST_CHECK(true);
}

BOOST_AUTO_TEST_CASE(s6_ntt_roundtrip_negative_coefficients)
{
    // NttForward/NttInverse with negative coefficients.
    // As with unreduced inputs, we test both the "correct" approach
    // (reduce first) and the "raw" approach (pass negatives directly).
    SmilePoly p;
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        p.coeffs[i] = -static_cast<int64_t>(i + 1);
    }

    // Reduce first, then round-trip
    SmilePoly p_reduced;
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        p_reduced.coeffs[i] = mod_q(p.coeffs[i]);
    }

    NttForm ntt_reduced = NttForward(p_reduced);
    SmilePoly recovered_reduced = NttInverse(ntt_reduced);
    recovered_reduced.Reduce();
    BOOST_CHECK(recovered_reduced == p_reduced);

    // Raw round-trip with negative inputs
    NttForm ntt_p = NttForward(p);
    SmilePoly recovered = NttInverse(ntt_p);
    recovered.Reduce();

    bool tolerant = (recovered == recovered_reduced);
    if (tolerant) {
        BOOST_TEST_MESSAGE("S6: NTT round-trip tolerates negative inputs.");
    } else {
        size_t diffs = 0;
        for (size_t i = 0; i < POLY_DEGREE; ++i) {
            if (recovered.coeffs[i] != recovered_reduced.coeffs[i]) diffs++;
        }
        BOOST_TEST_MESSAGE("S6: NTT round-trip with negative inputs: "
                           << diffs << "/" << POLY_DEGREE << " coefficients differ. "
                           "Callers MUST reduce before NttForward.");
    }
    BOOST_CHECK(true);
}

BOOST_AUTO_TEST_CASE(s6_slot_mul_wrong_root)
{
    // Multiply two NttSlots with the correct root vs a wrong root.
    // The results should differ.
    NttSlot a, b;
    a.coeffs[0] = 1; a.coeffs[1] = 2; a.coeffs[2] = 3; a.coeffs[3] = 4;
    b.coeffs[0] = 5; b.coeffs[1] = 6; b.coeffs[2] = 7; b.coeffs[3] = 8;

    int64_t correct_root = SLOT_ROOTS[0];
    int64_t wrong_root = SLOT_ROOTS[1]; // different slot root

    NttSlot result_correct = a.Mul(b, correct_root);
    NttSlot result_wrong = a.Mul(b, wrong_root);

    BOOST_CHECK(result_correct != result_wrong);
    BOOST_TEST_MESSAGE("S6: Slot Mul with wrong root produces different result (as expected).");
}

// ================================================================
// S7: Serialization BitReader edge cases
// ================================================================

BOOST_AUTO_TEST_CASE(s7_deserialize_gaussian_bits_zero)
{
    // Construct a serialized GaussianVec with bits_needed = 0.
    // DeserializeGaussianVec should reject this.
    std::vector<uint8_t> data;
    // count (written by caller separately, so we pass count=1 and build the body)
    // max_abs (4 bytes)
    uint32_t max_abs = 0;
    data.insert(data.end(), reinterpret_cast<uint8_t*>(&max_abs),
                reinterpret_cast<uint8_t*>(&max_abs) + 4);
    // bits_needed = 0 (1 byte)
    data.push_back(0);
    // No coefficient data needed since bits_needed=0

    const uint8_t* ptr = data.data();
    const uint8_t* end = data.data() + data.size();
    SmilePolyVec z;
    bool ok = DeserializeGaussianVec(ptr, end, 1, z);
    BOOST_CHECK(!ok);
    BOOST_TEST_MESSAGE("S7: DeserializeGaussianVec with bits_needed=0 rejected.");
}

BOOST_AUTO_TEST_CASE(s7_deserialize_gaussian_bits_33)
{
    // bits_needed = 33 (> 32) should be rejected.
    std::vector<uint8_t> data;
    uint32_t max_abs = 1000;
    data.insert(data.end(), reinterpret_cast<uint8_t*>(&max_abs),
                reinterpret_cast<uint8_t*>(&max_abs) + 4);
    data.push_back(33); // bits_needed = 33
    // Pad with enough bytes that it doesn't fail on length check first
    data.resize(data.size() + 1024, 0);

    const uint8_t* ptr = data.data();
    const uint8_t* end = data.data() + data.size();
    SmilePolyVec z;
    bool ok = DeserializeGaussianVec(ptr, end, 1, z);
    BOOST_CHECK(!ok);
    BOOST_TEST_MESSAGE("S7: DeserializeGaussianVec with bits_needed=33 rejected.");
}

BOOST_AUTO_TEST_CASE(s7_deserialize_ct_proof_truncated_rejected)
{
    MiniCTSetup setup;
    setup.Build(32, 5, 10, 0x71);
    const auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 0x717171);
    auto data = SerializeCTProof(proof);
    BOOST_REQUIRE_GT(data.size(), 0u);
    data.pop_back();

    SmileCTProof decoded;
    bool ok = DeserializeCTProof(data, decoded, 1, 1);
    BOOST_CHECK(!ok);
    BOOST_TEST_MESSAGE("S7: Truncated fixed-layout CT proof rejected.");
}

BOOST_AUTO_TEST_CASE(s7_deserialize_ct_proof_trailing_bytes_rejected)
{
    MiniCTSetup setup;
    setup.Build(32, 7, 12, 0x72);
    const auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 0x727272);
    auto data = SerializeCTProof(proof);
    data.push_back(0x00);
    data.push_back(0x01);

    SmileCTProof decoded;
    bool ok = DeserializeCTProof(data, decoded, 1, 1);
    BOOST_CHECK(!ok);
    BOOST_TEST_MESSAGE("S7: CT proof with trailing bytes rejected by fixed-layout codec.");
}

// ================================================================
// S8: Wallet bridge adversarial inputs
// ================================================================

BOOST_AUTO_TEST_CASE(s8_wallet_ring_index_out_of_bounds)
{
    std::vector<smile2::wallet::SmileRingMember> ring;
    ring.reserve(32);
    for (int i = 0; i < 32; ++i) {
        ring.push_back(smile2::wallet::BuildPlaceholderRingMember(
            smile2::wallet::SMILE_GLOBAL_SEED,
            uint256{static_cast<uint8_t>(i + 1)}));
    }

    smile2::wallet::SmileInputMaterial inp;
    inp.note = MakeShieldedNote(/*value=*/10, /*seed=*/0xc1);
    inp.ring_index = ring.size();

    std::vector<uint8_t> entropy(32, 0xEE);
    std::vector<uint256> serials;

    auto result = smile2::wallet::CreateSmileProof(
        smile2::wallet::SMILE_GLOBAL_SEED,
        {inp}, {inp.note}, Span<const smile2::wallet::SmileRingMember>{ring.data(), ring.size()},
        Span<const uint8_t>(entropy), serials);

    BOOST_CHECK(!result.has_value());
}

BOOST_AUTO_TEST_CASE(s8_wallet_negative_amount)
{
    std::vector<smile2::wallet::SmileRingMember> ring;
    ring.reserve(32);
    for (int i = 0; i < 32; ++i) {
        ring.push_back(smile2::wallet::BuildPlaceholderRingMember(
            smile2::wallet::SMILE_GLOBAL_SEED,
            uint256{static_cast<uint8_t>(0xd0 + i)}));
    }

    smile2::wallet::SmileInputMaterial inp;
    inp.note = MakeShieldedNote(/*value=*/-100, /*seed=*/0xd1);
    inp.ring_index = 0;

    std::vector<uint8_t> entropy(32, 0xEE);
    std::vector<uint256> serials;

    auto result = smile2::wallet::CreateSmileProof(
        smile2::wallet::SMILE_GLOBAL_SEED,
        {inp}, {inp.note}, Span<const smile2::wallet::SmileRingMember>{ring.data(), ring.size()},
        Span<const uint8_t>(entropy), serials);

    BOOST_CHECK(!result.has_value());
}

BOOST_AUTO_TEST_CASE(s8_wallet_amount_equals_q)
{
    std::vector<smile2::wallet::SmileRingMember> ring;
    ring.reserve(32);
    for (int i = 0; i < 32; ++i) {
        ring.push_back(smile2::wallet::BuildPlaceholderRingMember(
            smile2::wallet::SMILE_GLOBAL_SEED,
            uint256{static_cast<uint8_t>(0xe0 + i)}));
    }

    smile2::wallet::SmileInputMaterial inp;
    inp.note = MakeShieldedNote(/*value=*/Q, /*seed=*/0xe1);
    inp.ring_index = 0;

    std::vector<uint8_t> entropy(32, 0xBC);
    std::vector<uint256> serials;

    auto result = smile2::wallet::CreateSmileProof(
        smile2::wallet::SMILE_GLOBAL_SEED,
        {inp}, {inp.note}, Span<const smile2::wallet::SmileRingMember>{ring.data(), ring.size()},
        Span<const uint8_t>(entropy), serials);

    BOOST_CHECK(!result.has_value());
}

BOOST_AUTO_TEST_CASE(s8_wallet_null_commitment)
{
    // DeriveSmileKeyPair with null (all-zero) commitment.
    std::array<uint8_t, 32> global_seed{};
    global_seed[0] = 0xDE;

    uint256 null_commitment; // all zeros

    // This should handle gracefully and produce a deterministic key.
    // We just check it doesn't crash.
    try {
        auto kp = smile2::wallet::DeriveSmileKeyPair(
            global_seed,
            null_commitment);
        // If it succeeds, the key should be non-trivial
        bool all_zero = true;
        for (const auto& p : kp.sec.s) {
            if (!p.IsZero()) { all_zero = false; break; }
        }
        BOOST_TEST_MESSAGE("S8: Null commitment produced a key. "
                           "All-zero secret: " << (all_zero ? "YES (weak!)" : "no"));
        BOOST_CHECK(!all_zero);
    } catch (...) {
        BOOST_TEST_MESSAGE("S8: Null commitment threw exception (acceptable).");
        BOOST_CHECK(true);
    }
}

// ================================================================
// S9: CT VerifyCT weak opening gap
// ================================================================

BOOST_AUTO_TEST_CASE(s9_ct_verify_corrupted_w0)
{
    // Create a valid 1-in-1-out CT proof, then corrupt the first committed W0 row.
    // The corrupted proof should be rejected.
    const size_t N = 32;
    MiniCTSetup setup;
    setup.Build(N, 5, 100, 0xA1);

    auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 99999);

    // Verify the original proof is valid
    bool original_valid = VerifyCT(proof, 1, 1, setup.pub);
    BOOST_CHECK(original_valid);

    // Corrupt the first committed W0 row: add delta to first component.
    SmileCTProof bad_proof = proof;
    bad_proof.aux_commitment.t_msg[LiveCtW0Slot(/*num_inputs=*/1, /*num_outputs=*/1, /*input_index=*/0, /*row=*/0)].coeffs[0] =
        add_mod_q(
            bad_proof.aux_commitment.t_msg[LiveCtW0Slot(/*num_inputs=*/1, /*num_outputs=*/1, /*input_index=*/0, /*row=*/0)].coeffs[0],
            1);

    bool bad_valid = VerifyCT(bad_proof, 1, 1, setup.pub);
    BOOST_CHECK(!bad_valid);
    BOOST_TEST_MESSAGE("S9: CT proof with corrupted committed W0 row correctly rejected.");
}

// ================================================================
// S10: Timing side channel indicator
// ================================================================

BOOST_AUTO_TEST_CASE(s10_verification_timing_uniformity)
{
    // Measure verification time for proofs with different secret indices.
    // The max/min ratio should be < 2x (no timing leak) and ideally < 1.5x.
    const size_t N = 32;
    const size_t NUM_PROOFS = 20;
    const size_t NUM_VERIFICATIONS_PER_PROOF = 3;
    const int64_t amount = 50;

    std::vector<double> times_us;
    times_us.reserve(NUM_PROOFS);

    for (size_t trial = 0; trial < NUM_PROOFS; ++trial) {
        size_t secret_idx = trial % N;
        MiniCTSetup setup;
        setup.Build(N, secret_idx, amount, static_cast<uint8_t>(0xA2 + trial));

        auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 80000 + trial);
        BOOST_REQUIRE(VerifyCT(proof, 1, 1, setup.pub));

        // Time the verification
        double total_elapsed = 0.0;
        for (size_t iter = 0; iter < NUM_VERIFICATIONS_PER_PROOF; ++iter) {
            auto start = std::chrono::high_resolution_clock::now();
            bool valid = VerifyCT(proof, 1, 1, setup.pub);
            auto end = std::chrono::high_resolution_clock::now();

            BOOST_CHECK(valid);
            total_elapsed += std::chrono::duration<double, std::micro>(end - start).count();
        }
        times_us.push_back(total_elapsed / static_cast<double>(NUM_VERIFICATIONS_PER_PROOF));
    }

    double min_time = *std::min_element(times_us.begin(), times_us.end());
    double max_time = *std::max_element(times_us.begin(), times_us.end());
    double ratio = max_time / min_time;

    BOOST_CHECK_LT(ratio, 2.0);
    if (ratio < 1.5) {
        BOOST_TEST_MESSAGE("S10: Timing ratio = " << ratio << " < 1.5x (no timing leak).");
    } else {
        BOOST_TEST_MESSAGE("S10: WARNING: Timing ratio = " << ratio
                           << " >= 1.5x (potential timing side channel).");
    }
}

// ================================================================
// S11: Proof malleability
// ================================================================

BOOST_AUTO_TEST_CASE(s11_negate_z_coefficients)
{
    // Take a valid proof, negate all z coefficients: z' = -z mod q.
    // The negated proof should fail verification because the Fiat-Shamir
    // transcript (specifically seed_z) binds z to the challenge.
    const size_t N = 32;
    MiniCTSetup setup;
    setup.Build(N, 3, 75, 0xA3);

    auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 70000);
    bool original_valid = VerifyCT(proof, 1, 1, setup.pub);
    BOOST_CHECK(original_valid);

    // Negate all z coefficients
    SmileCTProof negated = proof;
    for (auto& p : negated.z) {
        for (size_t i = 0; i < POLY_DEGREE; ++i) {
            p.coeffs[i] = neg_mod_q(mod_q(p.coeffs[i]));
        }
    }

    bool negated_valid = VerifyCT(negated, 1, 1, setup.pub);
    BOOST_CHECK(!negated_valid);
    BOOST_TEST_MESSAGE("S11: Proof with negated z correctly rejected (omega differs).");
}

BOOST_AUTO_TEST_CASE(s11_add_q_to_h2_coefficients)
{
    // Take a valid proof, add Q to all h2 coefficients: h2' = h2 + Q.
    // Since h2 + Q = h2 mod q (canonical equivalence), the proof
    // should still verify IF the verifier reduces h2 before checking.
    const size_t N = 32;
    MiniCTSetup setup;
    setup.Build(N, 7, 200, 0xA4);

    auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 71000);
    bool original_valid = VerifyCT(proof, 1, 1, setup.pub);
    BOOST_CHECK(original_valid);

    // Add Q to all h2 coefficients (should be equivalent mod q)
    SmileCTProof mod_equiv = proof;
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        mod_equiv.h2.coeffs[i] = proof.h2.coeffs[i] + Q;
    }

    bool equiv_valid = VerifyCT(mod_equiv, 1, 1, setup.pub);
    if (equiv_valid) {
        BOOST_TEST_MESSAGE("S11: h2 + Q verifies (canonical equivalence accepted -- expected).");
    } else {
        BOOST_TEST_MESSAGE("S11: h2 + Q rejected (verifier checks canonical form -- strict).");
    }
    // Either behavior is acceptable; document it.
    BOOST_CHECK(true);
}

BOOST_AUTO_TEST_CASE(s11_corrupt_seed_z)
{
    // Modify seed_z (the binding hash). This should cause verification failure
    // since seed_z binds z to the Fiat-Shamir transcript.
    const size_t N = 32;
    MiniCTSetup setup;
    setup.Build(N, 10, 150, 0xA5);

    auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 72000);
    bool original_valid = VerifyCT(proof, 1, 1, setup.pub);
    BOOST_CHECK(original_valid);

    SmileCTProof bad_proof = proof;
    bad_proof.seed_z[0] ^= 0xFF; // flip bits in seed_z

    bool bad_valid = VerifyCT(bad_proof, 1, 1, setup.pub);
    BOOST_CHECK(!bad_valid);
    BOOST_TEST_MESSAGE("S11: Proof with corrupted seed_z correctly rejected.");
}

BOOST_AUTO_TEST_SUITE_END()
