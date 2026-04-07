// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/smile2/bdlop.h>
#include <shielded/smile2/params.h>
#include <shielded/smile2/poly.h>
#include <shielded/smile2/ntt.h>
#include <shielded/smile2/serialize.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <random>

using namespace smile2;

namespace {

std::array<uint8_t, 32> MakeSeed(uint8_t val) {
    std::array<uint8_t, 32> seed{};
    seed[0] = val;
    return seed;
}

void AppendLsbBits(std::vector<uint8_t>& bits, uint32_t value, uint8_t width)
{
    for (uint8_t bit = 0; bit < width; ++bit) {
        bits.push_back((value >> bit) & 1U);
    }
}

void AppendRiceCodeword(std::vector<uint8_t>& bits, uint32_t encoded, uint8_t k)
{
    const uint32_t q = encoded >> k;
    bits.insert(bits.end(), q, uint8_t{1});
    bits.push_back(0);
    AppendLsbBits(bits, encoded & ((uint32_t{1} << k) - 1), k);
}

std::vector<uint8_t> PackBitsLsbFirst(const std::vector<uint8_t>& bits)
{
    std::vector<uint8_t> packed((bits.size() + 7) / 8, 0);
    for (size_t bit = 0; bit < bits.size(); ++bit) {
        if (bits[bit] != 0) {
            packed[bit / 8] |= static_cast<uint8_t>(1U << (bit % 8));
        }
    }
    return packed;
}

std::vector<uint8_t> BuildAdaptiveRiceWitness(const std::vector<uint32_t>& encoded_coeffs, uint8_t k)
{
    std::vector<uint8_t> bytes;
    bytes.push_back(0);
    bytes.push_back(1);
    bytes.push_back(k);

    std::vector<uint8_t> bits;
    for (uint32_t encoded : encoded_coeffs) {
        AppendRiceCodeword(bits, encoded, k);
    }

    const auto packed = PackBitsLsbFirst(bits);
    bytes.insert(bytes.end(), packed.begin(), packed.end());
    return bytes;
}

SmilePoly RandomPoly(std::mt19937_64& rng) {
    SmilePoly p;
    std::uniform_int_distribution<int64_t> dist(0, Q - 1);
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        p.coeffs[i] = dist(rng);
    }
    return p;
}

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(smile2_bdlop_tests, BasicTestingSetup)

// [P2-G1] Commitment correctness: Commit(m; r) produces valid (t_0, t_1, ..., t_n)
// where B_0·r == t_0 and ⟨b_i, r⟩ + m_i == t_i for all i.
BOOST_AUTO_TEST_CASE(p2_g1_commitment_correctness)
{
    const size_t n_msg = 3;
    auto seed = MakeSeed(1);
    auto ck = BDLOPCommitmentKey::Generate(seed, n_msg);

    // Create messages
    std::mt19937_64 rng(1001);
    std::vector<SmilePoly> messages(n_msg);
    for (auto& m : messages) {
        m = RandomPoly(rng);
        m.Reduce();
    }

    // Sample randomness
    auto r = SampleTernary(ck.rand_dim(), 2001);

    // Commit
    auto com = Commit(ck, messages, r);

    // Verify: B_0·r == t_0
    for (size_t i = 0; i < BDLOP_RAND_DIM_BASE; ++i) {
        SmilePoly acc;
        for (size_t j = 0; j < ck.rand_dim(); ++j) {
            acc += NttMul(ck.B0[i][j], r[j]);
        }
        acc.Reduce();
        SmilePoly expected = com.t0[i];
        expected.Reduce();
        BOOST_CHECK(acc == expected);
    }

    // Verify: ⟨b_i, r⟩ + m_i == t_i
    for (size_t i = 0; i < n_msg; ++i) {
        SmilePoly acc;
        for (size_t j = 0; j < ck.rand_dim(); ++j) {
            acc += NttMul(ck.b[i][j], r[j]);
        }
        acc += messages[i];
        acc.Reduce();
        SmilePoly expected = com.t_msg[i];
        expected.Reduce();
        BOOST_CHECK(acc == expected);
    }

    // Also verify using the built-in VerifyOpening
    BOOST_CHECK(VerifyOpening(ck, com, messages, r));
}

// [P2-G2] Multi-message: commit to n=5 messages under single r,
// verify each message slot independently.
BOOST_AUTO_TEST_CASE(p2_g2_multi_message)
{
    const size_t n_msg = 5;
    auto seed = MakeSeed(2);
    auto ck = BDLOPCommitmentKey::Generate(seed, n_msg);

    std::mt19937_64 rng(2001);
    std::vector<SmilePoly> messages(n_msg);
    for (size_t i = 0; i < n_msg; ++i) {
        messages[i] = RandomPoly(rng);
        messages[i].Reduce();
    }

    auto r = SampleTernary(ck.rand_dim(), 3001);
    auto com = Commit(ck, messages, r);

    // Verify all 5 message slots individually
    for (size_t i = 0; i < n_msg; ++i) {
        SmilePoly inner;
        for (size_t j = 0; j < ck.rand_dim(); ++j) {
            inner += NttMul(ck.b[i][j], r[j]);
        }
        inner += messages[i];
        inner.Reduce();
        SmilePoly expected = com.t_msg[i];
        expected.Reduce();
        BOOST_CHECK_MESSAGE(inner == expected,
            "Message slot " << i << " verification failed");
    }

    // Full verification
    BOOST_CHECK(VerifyOpening(ck, com, messages, r));
}

// [P2-G3] Weak opening: given z = y + c·r, verify:
// B_0·z == w + c·t_0 (where w = B_0·y)
// and ⟨b_i, z⟩ - c·t_i == ⟨b_i, y⟩ - c·m_i
BOOST_AUTO_TEST_CASE(p2_g3_weak_opening)
{
    const size_t n_msg = 3;
    auto seed = MakeSeed(3);
    auto ck = BDLOPCommitmentKey::Generate(seed, n_msg);

    std::mt19937_64 rng(3001);
    std::vector<SmilePoly> messages(n_msg);
    for (auto& m : messages) {
        m = RandomPoly(rng);
        m.Reduce();
    }

    auto r = SampleTernary(ck.rand_dim(), 4001);
    auto com = Commit(ck, messages, r);

    // Sample masking vector y (random polynomials, simulating Gaussian)
    SmilePolyVec y(ck.rand_dim());
    for (auto& yi : y) {
        yi = RandomPoly(rng);
        yi.Reduce();
    }

    // Challenge c (a random polynomial)
    SmilePoly c_chal = RandomPoly(rng);
    c_chal.Reduce();

    // z = y + c·r
    SmilePolyVec z(ck.rand_dim());
    for (size_t j = 0; j < ck.rand_dim(); ++j) {
        z[j] = y[j] + NttMul(c_chal, r[j]);
        z[j].Reduce();
    }

    // w_0 = B_0 · y
    SmilePolyVec w0(BDLOP_RAND_DIM_BASE);
    for (size_t i = 0; i < BDLOP_RAND_DIM_BASE; ++i) {
        SmilePoly acc;
        for (size_t j = 0; j < ck.rand_dim(); ++j) {
            acc += NttMul(ck.B0[i][j], y[j]);
        }
        acc.Reduce();
        w0[i] = acc;
    }

    // Check B_0·z == w_0 + c·t_0
    for (size_t i = 0; i < BDLOP_RAND_DIM_BASE; ++i) {
        SmilePoly lhs;
        for (size_t j = 0; j < ck.rand_dim(); ++j) {
            lhs += NttMul(ck.B0[i][j], z[j]);
        }
        lhs.Reduce();

        SmilePoly rhs = w0[i] + NttMul(c_chal, com.t0[i]);
        rhs.Reduce();

        BOOST_CHECK_MESSAGE(lhs == rhs, "B_0·z != w_0 + c·t_0 at row " << i);
    }

    // f_i = ⟨b_i, y⟩ - c·m_i
    std::vector<SmilePoly> f(n_msg);
    for (size_t i = 0; i < n_msg; ++i) {
        SmilePoly acc;
        for (size_t j = 0; j < ck.rand_dim(); ++j) {
            acc += NttMul(ck.b[i][j], y[j]);
        }
        f[i] = acc - NttMul(c_chal, messages[i]);
        f[i].Reduce();
    }

    // Check ⟨b_i, z⟩ - c·t_i == f_i
    for (size_t i = 0; i < n_msg; ++i) {
        SmilePoly lhs;
        for (size_t j = 0; j < ck.rand_dim(); ++j) {
            lhs += NttMul(ck.b[i][j], z[j]);
        }
        lhs -= NttMul(c_chal, com.t_msg[i]);
        lhs.Reduce();

        SmilePoly expected = f[i];
        expected.Reduce();

        BOOST_CHECK_MESSAGE(lhs == expected,
            "Weak opening check failed for message slot " << i);
    }

    // Also test via VerifyWeakOpening
    BOOST_CHECK(VerifyWeakOpening(ck, com, z, w0, c_chal, f));
}

// [P2-G4] Different messages → different commitments (binding).
BOOST_AUTO_TEST_CASE(p2_g4_binding)
{
    const size_t n_msg = 2;
    auto seed = MakeSeed(4);
    auto ck = BDLOPCommitmentKey::Generate(seed, n_msg);

    std::mt19937_64 rng(5001);

    // Two different message sets
    std::vector<SmilePoly> msg1(n_msg), msg2(n_msg);
    for (size_t i = 0; i < n_msg; ++i) {
        msg1[i] = RandomPoly(rng);
        msg1[i].Reduce();
        msg2[i] = RandomPoly(rng);
        msg2[i].Reduce();
    }

    // Same randomness to isolate the message effect
    auto r = SampleTernary(ck.rand_dim(), 6001);

    auto com1 = Commit(ck, msg1, r);
    auto com2 = Commit(ck, msg2, r);

    // t_0 should be the same (same r, same B_0)
    for (size_t i = 0; i < BDLOP_RAND_DIM_BASE; ++i) {
        BOOST_CHECK(com1.t0[i] == com2.t0[i]);
    }

    // At least one t_msg should differ (messages differ)
    bool any_diff = false;
    for (size_t i = 0; i < n_msg; ++i) {
        SmilePoly t1 = com1.t_msg[i]; t1.Reduce();
        SmilePoly t2 = com2.t_msg[i]; t2.Reduce();
        if (t1 != t2) any_diff = true;
    }
    BOOST_CHECK(any_diff);

    // Different randomness → different t_0
    auto r2 = SampleTernary(ck.rand_dim(), 7001);
    auto com3 = Commit(ck, msg1, r2);

    bool t0_diff = false;
    for (size_t i = 0; i < BDLOP_RAND_DIM_BASE; ++i) {
        SmilePoly a = com1.t0[i]; a.Reduce();
        SmilePoly b = com3.t0[i]; b.Reduce();
        if (a != b) t0_diff = true;
    }
    BOOST_CHECK(t0_diff);
}

// [P2-G5] Key expansion determinism: same seed → same B_0, b_i.
BOOST_AUTO_TEST_CASE(p2_g5_key_determinism)
{
    const size_t n_msg = 4;
    auto seed = MakeSeed(5);

    auto ck1 = BDLOPCommitmentKey::Generate(seed, n_msg);
    auto ck2 = BDLOPCommitmentKey::Generate(seed, n_msg);

    // Check B_0 matrices are identical
    BOOST_REQUIRE_EQUAL(ck1.B0.size(), ck2.B0.size());
    for (size_t i = 0; i < ck1.B0.size(); ++i) {
        BOOST_REQUIRE_EQUAL(ck1.B0[i].size(), ck2.B0[i].size());
        for (size_t j = 0; j < ck1.B0[i].size(); ++j) {
            SmilePoly a = ck1.B0[i][j]; a.Reduce();
            SmilePoly b = ck2.B0[i][j]; b.Reduce();
            BOOST_CHECK_MESSAGE(a == b,
                "B0[" << i << "][" << j << "] differs between expansions");
        }
    }

    // Check b vectors are identical
    BOOST_REQUIRE_EQUAL(ck1.b.size(), ck2.b.size());
    for (size_t i = 0; i < ck1.b.size(); ++i) {
        BOOST_REQUIRE_EQUAL(ck1.b[i].size(), ck2.b[i].size());
        for (size_t j = 0; j < ck1.b[i].size(); ++j) {
            SmilePoly a = ck1.b[i][j]; a.Reduce();
            SmilePoly b = ck2.b[i][j]; b.Reduce();
            BOOST_CHECK_MESSAGE(a == b,
                "b[" << i << "][" << j << "] differs between expansions");
        }
    }

    // Different seed → different key
    auto seed2 = MakeSeed(99);
    auto ck3 = BDLOPCommitmentKey::Generate(seed2, n_msg);

    bool any_diff = false;
    for (size_t i = 0; i < BDLOP_RAND_DIM_BASE && !any_diff; ++i) {
        for (size_t j = 0; j < ck1.rand_dim() && !any_diff; ++j) {
            SmilePoly a = ck1.B0[i][j]; a.Reduce();
            SmilePoly b = ck3.B0[i][j]; b.Reduce();
            if (a != b) any_diff = true;
        }
    }
    BOOST_CHECK(any_diff);
}

BOOST_AUTO_TEST_CASE(sample_ternary_legacy_api_is_deterministic_and_ternary)
{
    const auto sample_a = SampleTernary(/*dim=*/2, /*seed=*/0x12345678ULL);
    const auto sample_b = SampleTernary(/*dim=*/2, /*seed=*/0x12345678ULL);
    const auto sample_c = SampleTernary(/*dim=*/2, /*seed=*/0x12345679ULL);

    BOOST_CHECK(sample_a == sample_b);

    bool any_difference = false;
    for (size_t poly = 0; poly < sample_a.size() && !any_difference; ++poly) {
        for (size_t coeff = 0; coeff < POLY_DEGREE; ++coeff) {
            const int64_t val = sample_a[poly].coeffs[coeff];
            BOOST_CHECK(val == 0 || val == 1 || val == mod_q(-1));
            if (val != sample_c[poly].coeffs[coeff]) {
                any_difference = true;
            }
        }
    }
    BOOST_CHECK(any_difference);
}

BOOST_AUTO_TEST_CASE(canonical_no_rice_witness_encoding_uses_single_centered_codec)
{
    const SmilePolyVec sample = SampleTernary(/*dim=*/2, /*seed=*/0x42424242ULL);
    std::vector<uint8_t> encoded;
    SerializeAdaptiveWitnessPolyVec(sample, encoded, SmileProofCodecPolicy::CANONICAL_NO_RICE);

    BOOST_REQUIRE_GE(encoded.size(), 2U);
    // Witness codec 0 = gaussian vector, inner codec 0 = centered fixed-width.
    BOOST_CHECK_EQUAL(encoded[0], 0U);
    BOOST_CHECK_EQUAL(encoded[1], 0U);

    const uint8_t* ptr = encoded.data();
    const uint8_t* end = ptr + encoded.size();
    SmilePolyVec decoded;
    BOOST_REQUIRE(DeserializeAdaptiveWitnessPolyVec(ptr, end, sample.size(), decoded));
    BOOST_CHECK(decoded == sample);
    BOOST_CHECK(ptr == end);
}

BOOST_AUTO_TEST_CASE(rice_witness_decode_handles_long_unary_runs)
{
    std::vector<uint32_t> encoded_coeffs(POLY_DEGREE, 0);
    encoded_coeffs[0] = 80;
    const auto encoded = BuildAdaptiveRiceWitness(encoded_coeffs, /*k=*/0);

    const uint8_t* ptr = encoded.data();
    const uint8_t* end = ptr + encoded.size();
    SmilePolyVec decoded;
    BOOST_REQUIRE(DeserializeAdaptiveWitnessPolyVec(ptr, end, /*count=*/1, decoded));
    BOOST_REQUIRE_EQUAL(decoded.size(), 1U);
    BOOST_CHECK_EQUAL(decoded[0].coeffs[0], 40);
    for (size_t coeff = 1; coeff < POLY_DEGREE; ++coeff) {
        BOOST_CHECK_EQUAL(decoded[0].coeffs[coeff], 0);
    }
    BOOST_CHECK(ptr == end);
}

BOOST_AUTO_TEST_CASE(rice_witness_decode_rejects_unterminated_unary_stream)
{
    std::vector<uint8_t> encoded{0, 1, 0};
    encoded.insert(encoded.end(), 32, 0xFF);

    const uint8_t* ptr = encoded.data();
    const uint8_t* end = ptr + encoded.size();
    SmilePolyVec decoded;
    BOOST_CHECK(!DeserializeAdaptiveWitnessPolyVec(ptr, end, /*count=*/1, decoded));
}

BOOST_AUTO_TEST_SUITE_END()
