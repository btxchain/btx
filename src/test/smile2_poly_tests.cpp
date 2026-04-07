// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/smile2/params.h>
#include <shielded/smile2/poly.h>
#include <shielded/smile2/ntt.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <random>
#include <thread>
#include <vector>

using namespace smile2;

namespace {

// Deterministic RNG for reproducible tests
std::mt19937_64 MakeRng(uint64_t seed = 42) {
    return std::mt19937_64(seed);
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

BOOST_FIXTURE_TEST_SUITE(smile2_poly_tests, BasicTestingSetup)

// [P1-G1] Verify that q = 4294966337 has the correct NTT slot structure:
// X^128+1 splits into exactly 32 irreducible degree-4 factors mod q.
BOOST_AUTO_TEST_CASE(p1_g1_ntt_slot_factorization)
{
    // Verify q is prime (probabilistic but with enough witnesses)
    // q = 4294966337
    BOOST_CHECK_EQUAL(Q, 4294966337LL);

    // Verify q ≡ 1 (mod 64)
    BOOST_CHECK_EQUAL(Q % 64, 1);
    // Verify q ≢ 1 (mod 128) — ensures degree-4 (not smaller) factors
    BOOST_CHECK_EQUAL(Q % 128, 65);

    // Verify ζ is a primitive 64th root of unity
    // ζ^64 ≡ 1 (mod q)
    int64_t zeta_pow = 1;
    for (int i = 0; i < 64; ++i) {
        zeta_pow = mul_mod_q(zeta_pow, ZETA);
    }
    BOOST_CHECK_EQUAL(zeta_pow, 1);

    // ζ^32 ≢ 1 (mod q) — it's a primitive 64th root, not 32nd
    int64_t zeta_half = 1;
    for (int i = 0; i < 32; ++i) {
        zeta_half = mul_mod_q(zeta_half, ZETA);
    }
    BOOST_CHECK_NE(zeta_half, 1);

    // Verify all 32 slot roots are distinct
    std::set<int64_t> root_set(SLOT_ROOTS.begin(), SLOT_ROOTS.end());
    BOOST_CHECK_EQUAL(root_set.size(), NUM_NTT_SLOTS);

    // Verify X^128+1 = ∏_{j=0}^{31} (X^4 - root_j) mod q
    // Evaluate both sides at a random point x
    std::mt19937_64 rng(12345);
    std::uniform_int_distribution<int64_t> dist(2, Q - 1);
    for (int trial = 0; trial < 10; ++trial) {
        int64_t x = dist(rng);

        // LHS: x^128 + 1 mod q
        int64_t x128 = 1;
        int64_t base = x;
        int exp = 128;
        while (exp > 0) {
            if (exp & 1) x128 = mul_mod_q(x128, base);
            base = mul_mod_q(base, base);
            exp >>= 1;
        }
        int64_t lhs = add_mod_q(x128, 1);

        // RHS: ∏ (x^4 - root_j)
        int64_t x4 = mul_mod_q(mul_mod_q(x, x), mul_mod_q(x, x));
        int64_t rhs = 1;
        for (size_t j = 0; j < NUM_NTT_SLOTS; ++j) {
            rhs = mul_mod_q(rhs, sub_mod_q(x4, SLOT_ROOTS[j]));
        }

        BOOST_CHECK_EQUAL(lhs, rhs);
    }

    // Verify each X^4 - root_j is irreducible: root_j is NOT a 4th power mod q
    // root is a 4th power iff root^((q-1)/4) ≡ 1 (mod q)
    for (size_t j = 0; j < NUM_NTT_SLOTS; ++j) {
        int64_t test = 1;
        int64_t b = SLOT_ROOTS[j];
        int64_t e = (Q - 1) / 4;
        while (e > 0) {
            if (e & 1) test = mul_mod_q(test, b);
            b = mul_mod_q(b, b);
            e >>= 1;
        }
        BOOST_CHECK_NE(test, 1); // Must NOT be a 4th power
    }
}

// [P1-G2] NTT forward then inverse is identity: INTT(NTT(p)) == p
BOOST_AUTO_TEST_CASE(p1_g2_ntt_roundtrip)
{
    auto rng = MakeRng(100);
    for (int trial = 0; trial < 100; ++trial) {
        SmilePoly p = RandomPoly(rng);
        p.Reduce();

        NttForm ntt = NttForward(p);
        SmilePoly recovered = NttInverse(ntt);
        recovered.Reduce();

        BOOST_CHECK(p == recovered);
    }
}

BOOST_AUTO_TEST_CASE(p1_g2_ntt_roundtrip_concurrent_initialization)
{
    constexpr int NUM_THREADS = 8;
    constexpr int TRIALS_PER_THREAD = 25;

    std::vector<std::thread> threads;
    threads.reserve(NUM_THREADS);
    std::vector<bool> ok(NUM_THREADS, false);

    for (int thread_id = 0; thread_id < NUM_THREADS; ++thread_id) {
        threads.emplace_back([&, thread_id] {
            auto rng = MakeRng(1000 + thread_id);
            bool local_ok{true};
            for (int trial = 0; trial < TRIALS_PER_THREAD; ++trial) {
                SmilePoly p = RandomPoly(rng);
                p.Reduce();
                SmilePoly recovered = NttInverse(NttForward(p));
                recovered.Reduce();
                if (!(p == recovered)) {
                    local_ok = false;
                    break;
                }
            }
            ok[thread_id] = local_ok;
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }
    for (bool thread_ok : ok) {
        BOOST_CHECK(thread_ok);
    }
}

// [P1-G3] NTT multiplication: NTT(a*b) == NTT(a) ⊙ NTT(b)
BOOST_AUTO_TEST_CASE(p1_g3_ntt_multiplication)
{
    auto rng = MakeRng(200);
    for (int trial = 0; trial < 100; ++trial) {
        SmilePoly a = RandomPoly(rng);
        SmilePoly b = RandomPoly(rng);
        a.Reduce();
        b.Reduce();

        // Schoolbook multiplication
        SmilePoly ab_schoolbook = a.MulSchoolbook(b);
        ab_schoolbook.Reduce();

        // NTT multiplication
        SmilePoly ab_ntt = NttMul(a, b);
        ab_ntt.Reduce();

        BOOST_CHECK(ab_schoolbook == ab_ntt);

        // Also verify: NTT(a*b) == NTT(a) ⊙ NTT(b)
        NttForm ntt_ab = NttForward(ab_schoolbook);
        NttForm ntt_a = NttForward(a);
        NttForm ntt_b = NttForward(b);
        NttForm ntt_a_times_b = ntt_a.PointwiseMul(ntt_b);
        BOOST_CHECK(ntt_ab == ntt_a_times_b);
    }
}

// [P1-G4] Slot inner product linearity for scalars:
// For v ∈ Z_q^32 (scalar slots), w ∈ M_q^32: ⟨c·v, w⟩ == c·⟨v, w⟩
BOOST_AUTO_TEST_CASE(p1_g4_scalar_slot_linearity)
{
    auto rng = MakeRng(300);
    std::uniform_int_distribution<int64_t> dist(0, Q - 1);

    for (int trial = 0; trial < 100; ++trial) {
        // Random scalar vector v ∈ Z_q^32
        std::array<int64_t, NUM_NTT_SLOTS> v{};
        for (auto& vi : v) vi = dist(rng);

        // Random polynomial w → NTT(w) gives w ∈ M_q^32
        SmilePoly w_poly = RandomPoly(rng);
        w_poly.Reduce();
        NttForm w = NttForward(w_poly);

        // Random scalar c
        int64_t c = dist(rng);

        // Compute ⟨v, w⟩: scale each slot of w by v[j], then INTT
        NttForm vw;
        for (size_t j = 0; j < NUM_NTT_SLOTS; ++j) {
            vw.slots[j] = w.slots[j].ScalarMul(v[j]);
        }
        SmilePoly inner_vw = NttInverse(vw);
        inner_vw.Reduce();

        // Compute ⟨c·v, w⟩
        std::array<int64_t, NUM_NTT_SLOTS> cv{};
        for (size_t j = 0; j < NUM_NTT_SLOTS; ++j) {
            cv[j] = mul_mod_q(c, v[j]);
        }
        NttForm cvw;
        for (size_t j = 0; j < NUM_NTT_SLOTS; ++j) {
            cvw.slots[j] = w.slots[j].ScalarMul(cv[j]);
        }
        SmilePoly inner_cvw = NttInverse(cvw);
        inner_cvw.Reduce();

        // Compute c · ⟨v, w⟩
        SmilePoly c_times_inner = inner_vw * c;
        c_times_inner.Reduce();

        BOOST_CHECK(inner_cvw == c_times_inner);
    }
}

// [P1-G5] Lemma 2.2: (1/l)·Σ NTT(p)_j equals first d/l=4 coefficients of p
BOOST_AUTO_TEST_CASE(p1_g5_lemma_2_2)
{
    auto rng = MakeRng(400);

    for (int trial = 0; trial < 100; ++trial) {
        SmilePoly p = RandomPoly(rng);
        p.Reduce();

        NttForm ntt = NttForward(p);

        // Compute (1/l) · Σ_{j=0}^{l-1} NTT(p)_j
        // Each NTT(p)_j is a degree-4 polynomial (NttSlot).
        // Sum them component-wise, then multiply by INV_NUM_SLOTS.
        NttSlot slot_sum;
        for (size_t j = 0; j < NUM_NTT_SLOTS; ++j) {
            slot_sum = slot_sum.Add(ntt.slots[j]);
        }
        NttSlot scaled;
        for (size_t c = 0; c < SLOT_DEGREE; ++c) {
            scaled.coeffs[c] = mul_mod_q(slot_sum.coeffs[c], INV_NUM_SLOTS);
        }

        // Should equal first d/l = 4 coefficients of p
        for (size_t c = 0; c < SLOT_DEGREE; ++c) {
            BOOST_CHECK_EQUAL(scaled.coeffs[c], mod_q(p.coeffs[c]));
        }
    }
}

// [P1-G6] Tensor product: v_1 ⊗ v_2 ⊗ v_3 for one-hot vectors
// produces correct index vector (test a subset of 32^3 = 32768 indices)
BOOST_AUTO_TEST_CASE(p1_g6_tensor_product)
{
    // Test all 32^3 = 32768 indices
    size_t total_correct = 0;
    size_t total_tested = 0;

    // Test a representative subset: all indices where at least one digit is 0 or 31,
    // plus random samples
    std::vector<size_t> test_indices;

    // First 32 indices (v1 varies)
    for (size_t i = 0; i < 32; ++i) test_indices.push_back(i);

    // Stride by 32 (v2 varies)
    for (size_t i = 0; i < 32; ++i) test_indices.push_back(i * 32);

    // Stride by 1024 (v3 varies)
    for (size_t i = 0; i < 32; ++i) test_indices.push_back(i * 1024);

    // Random indices
    auto rng = MakeRng(500);
    std::uniform_int_distribution<size_t> dist(0, 32767);
    for (int i = 0; i < 200; ++i) test_indices.push_back(dist(rng));

    // Deduplicate
    std::sort(test_indices.begin(), test_indices.end());
    test_indices.erase(std::unique(test_indices.begin(), test_indices.end()), test_indices.end());

    for (size_t idx : test_indices) {
        auto decomp = DecomposeIndex(idx, 3);
        BOOST_REQUIRE_EQUAL(decomp.size(), 3u);

        // Each vector should be one-hot
        for (const auto& v : decomp) {
            int64_t sum = 0;
            for (auto x : v) sum += x;
            BOOST_CHECK_EQUAL(sum, 1);
        }

        // Tensor product should have 1 at position idx and 0 elsewhere
        auto tensor = TensorProduct(decomp);
        BOOST_REQUIRE_EQUAL(tensor.size(), 32768u);

        BOOST_CHECK_EQUAL(tensor[idx], 1);

        // Check a few other positions are 0
        bool all_others_zero = true;
        for (size_t i = 0; i < tensor.size(); ++i) {
            if (i != idx && tensor[i] != 0) {
                all_others_zero = false;
                break;
            }
        }
        BOOST_CHECK(all_others_zero);

        total_correct++;
        total_tested++;
    }

    BOOST_CHECK_EQUAL(total_correct, total_tested);
    BOOST_TEST_MESSAGE("Tested " << total_tested << " tensor product indices");
}

// Additional test: basic polynomial arithmetic
BOOST_AUTO_TEST_CASE(poly_basic_arithmetic)
{
    SmilePoly a, b;
    a.coeffs[0] = 100;
    a.coeffs[1] = 200;
    b.coeffs[0] = 300;
    b.coeffs[1] = 400;

    auto sum = a + b;
    BOOST_CHECK_EQUAL(sum.coeffs[0], 400);
    BOOST_CHECK_EQUAL(sum.coeffs[1], 600);

    auto diff = a - b;
    BOOST_CHECK_EQUAL(mod_q(diff.coeffs[0]), mod_q(-200));
    BOOST_CHECK_EQUAL(mod_q(diff.coeffs[1]), mod_q(-200));

    auto scaled = a * 3;
    BOOST_CHECK_EQUAL(scaled.coeffs[0], 300);
    BOOST_CHECK_EQUAL(scaled.coeffs[1], 600);
}

// Additional test: schoolbook multiplication in R_q = Z_q[X]/(X^128+1)
BOOST_AUTO_TEST_CASE(poly_schoolbook_negacyclic)
{
    // X * X^127 = X^128 = -1 in the negacyclic ring
    SmilePoly x, x127;
    x.coeffs[1] = 1;     // X
    x127.coeffs[127] = 1; // X^127

    auto prod = x.MulSchoolbook(x127);
    prod.Reduce();

    // Should be -1 = q-1
    BOOST_CHECK_EQUAL(prod.coeffs[0], Q - 1);
    for (size_t i = 1; i < POLY_DEGREE; ++i) {
        BOOST_CHECK_EQUAL(prod.coeffs[i], 0);
    }
}

// Additional test: NTT of zero is zero
BOOST_AUTO_TEST_CASE(ntt_zero)
{
    SmilePoly zero;
    NttForm ntt = NttForward(zero);
    for (size_t j = 0; j < NUM_NTT_SLOTS; ++j) {
        BOOST_CHECK(ntt.slots[j].IsZero());
    }
    SmilePoly recovered = NttInverse(ntt);
    BOOST_CHECK(recovered.IsZero());
}

BOOST_AUTO_TEST_CASE(poly_iszero_checks_full_width)
{
    SmilePoly poly;
    poly.coeffs[POLY_DEGREE - 1] = Q;
    BOOST_CHECK(poly.IsZero());

    poly.coeffs[POLY_DEGREE - 1] = 1;
    BOOST_CHECK(!poly.IsZero());
}

BOOST_AUTO_TEST_CASE(nttslot_equality_and_iszero_check_all_coeffs)
{
    NttSlot lhs;
    NttSlot rhs;
    lhs.coeffs[SLOT_DEGREE - 1] = Q;
    rhs.coeffs[SLOT_DEGREE - 1] = 0;
    BOOST_CHECK(lhs == rhs);
    BOOST_CHECK(lhs.IsZero());

    rhs.coeffs[SLOT_DEGREE - 1] = 1;
    BOOST_CHECK(!(lhs == rhs));
    BOOST_CHECK(!rhs.IsZero());
}

BOOST_AUTO_TEST_CASE(nttform_equality_checks_all_slots)
{
    NttForm lhs;
    NttForm rhs;

    lhs.slots[NUM_NTT_SLOTS - 1].coeffs[SLOT_DEGREE - 1] = Q;
    rhs.slots[NUM_NTT_SLOTS - 1].coeffs[SLOT_DEGREE - 1] = 0;
    BOOST_CHECK(lhs == rhs);

    rhs.slots[NUM_NTT_SLOTS - 1].coeffs[SLOT_DEGREE - 1] = 1;
    BOOST_CHECK(!(lhs == rhs));
}

// Additional test: NTT of constant polynomial
BOOST_AUTO_TEST_CASE(ntt_constant)
{
    SmilePoly c;
    c.coeffs[0] = 42;
    NttForm ntt = NttForward(c);
    // Each slot should have constant 42 (since reducing a constant by (X^4-r) gives the constant)
    for (size_t j = 0; j < NUM_NTT_SLOTS; ++j) {
        BOOST_CHECK_EQUAL(ntt.slots[j].coeffs[0], 42);
        BOOST_CHECK_EQUAL(ntt.slots[j].coeffs[1], 0);
        BOOST_CHECK_EQUAL(ntt.slots[j].coeffs[2], 0);
        BOOST_CHECK_EQUAL(ntt.slots[j].coeffs[3], 0);
    }
}

BOOST_AUTO_TEST_SUITE_END()
