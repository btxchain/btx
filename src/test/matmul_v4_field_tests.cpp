// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// MatMul v4 arithmetic tests (design spec §0.7 / §B / §D.3).
//
// The v4 compute path is a single exact-integer s8 x s8 -> s32 GEMM
// (balanced operands in [-125, 125], k = 1) whose product entries are
// exact integers with |C_ij| <= n * 125^2 = 15,625 * n < 2^30 for every
// header-expressible n <= 65,535 (§B.4 / §G.4-#3). Verification lifts
// those exact integers into the independent Mersenne prime field
// q = 2^61 - 1 (§D.3), where any two distinct canonical entries differ
// by |delta| < 2^32 < q and therefore can never alias.
//
// These tests pin the *normative arithmetic* with a self-contained,
// portable reference implementation (no __int128, no vendor paths) so
// that any conforming backend can be cross-checked against the exact
// same numbers. The pure-integer CPU semantics tested here are the
// consensus definition (§N.3-v).

#include <matmul/pow_v4.h>

#include <random.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <vector>

namespace {

//! q = 2^61 - 1, the v4 Freivalds soundness field modulus (§0.7-(2), §D.3).
constexpr uint64_t kMersenne61{(uint64_t{1} << 61) - 1};

//! Maximum magnitude of a balanced-s8 operand entry (§B.4, p = 251 balanced).
constexpr int64_t kOperandMax{125};

//! Per-entry accumulation bound coefficient: 125^2 (§B.4).
constexpr int64_t kEntrySquared{kOperandMax * kOperandMax}; // 15,625

// --- Compile-time encodings of the §G.4 invariants -----------------------

// #3: every header-expressible dimension accumulates exactly in INT32.
static_assert(kEntrySquared == 15'625, "balanced-s8 bound must be 125^2");
static_assert(15'625LL * 65'535LL < (int64_t{1} << 30),
              "header-max dimension must satisfy |C_ij| < 2^30");
static_assert(15'625LL * 137'438LL <= std::numeric_limits<int32_t>::max(),
              "n = 137,438 is the last exactly-representable dimension");
static_assert(15'625LL * 137'439LL > std::numeric_limits<int32_t>::max(),
              "n = 137,439 must overflow INT32 (documents the cliff)");

// #5 (soundness): the aliasing gap. Any two distinct canonical committed
// integers differ by |delta| < 2^32 < q, so a wrong entry can never reduce
// to a matching residue mod q.
static_assert((uint64_t{1} << 32) < kMersenne61,
              "canonical-entry deltas must be smaller than q");

// Round-count invariant: per-round sketch error <= 2/q < 2^-59 (q > 2^60),
// so R rounds give < 2^(-59*R); R = 3 -> < 2^-177 (nominal 2^-180, §E.2),
// comfortably past the 2^-128 requirement. R = 2 is reserved for regtest.
static_assert(kMersenne61 > (uint64_t{1} << 60), "q must exceed 2^60");
static_assert(matmul_v4::kFreivaldsRounds * 59 >= 128,
              "R rounds over q must reach the 2^-128 soundness bar");

// --- Portable reference arithmetic over q = 2^61 - 1 ---------------------

//! Canonical Mersenne fold of an arbitrary 64-bit value into [0, q).
uint64_t Fold61(uint64_t x)
{
    x = (x & kMersenne61) + (x >> 61);
    x = (x & kMersenne61) + (x >> 61);
    if (x >= kMersenne61) x -= kMersenne61;
    return x;
}

uint64_t AddMod61(uint64_t a, uint64_t b)
{
    // a, b canonical -> sum < 2^62, one conditional subtract suffices.
    uint64_t s = a + b;
    if (s >= kMersenne61) s -= kMersenne61;
    return s;
}

//! Portable double-and-add multiply mod q (test-side reference; slow but
//! exact on every platform, including ones without 128-bit integers).
uint64_t MulMod61(uint64_t a, uint64_t b)
{
    a = Fold61(a);
    b = Fold61(b);
    uint64_t result = 0;
    while (b != 0) {
        if (b & 1) result = AddMod61(result, a);
        a <<= 1; // a < 2^61 -> a << 1 < 2^62, no wrap
        a = (a & kMersenne61) + (a >> 61);
        if (a >= kMersenne61) a -= kMersenne61;
        b >>= 1;
    }
    return result;
}

//! Generic double-and-add multiply mod m (m < 2^62), for primality testing.
uint64_t MulModGeneric(uint64_t a, uint64_t b, uint64_t m)
{
    a %= m;
    b %= m;
    uint64_t result = 0;
    while (b != 0) {
        if (b & 1) {
            result += a; // both < m < 2^62 -> sum < 2^63, no wrap
            if (result >= m) result -= m;
        }
        a <<= 1;
        if (a >= m) a -= m;
        b >>= 1;
    }
    return result;
}

uint64_t PowModGeneric(uint64_t base, uint64_t exp, uint64_t m)
{
    uint64_t result = 1 % m;
    base %= m;
    while (exp != 0) {
        if (exp & 1) result = MulModGeneric(result, base, m);
        base = MulModGeneric(base, base, m);
        exp >>= 1;
    }
    return result;
}

//! Deterministic Miller-Rabin: the 12-base set below is a proof of
//! primality for all n < 3.3 * 10^24, far past 2^61 - 1.
bool IsPrime64(uint64_t n)
{
    if (n < 2) return false;
    for (uint64_t p : {2ULL, 3ULL, 5ULL, 7ULL, 11ULL, 13ULL, 17ULL, 19ULL, 23ULL, 29ULL, 31ULL, 37ULL}) {
        if (n == p) return true;
        if (n % p == 0) return false;
    }
    uint64_t d = n - 1;
    int r = 0;
    while ((d & 1) == 0) {
        d >>= 1;
        ++r;
    }
    for (uint64_t a : {2ULL, 3ULL, 5ULL, 7ULL, 11ULL, 13ULL, 17ULL, 19ULL, 23ULL, 29ULL, 31ULL, 37ULL}) {
        uint64_t x = PowModGeneric(a, d, n);
        if (x == 1 || x == n - 1) continue;
        bool composite = true;
        for (int i = 0; i < r - 1; ++i) {
            x = MulModGeneric(x, x, n);
            if (x == n - 1) {
                composite = false;
                break;
            }
        }
        if (composite) return false;
    }
    return true;
}

//! Canonical residue of an exact (signed) integer product entry in F_q.
uint64_t CanonicalResidue(int64_t c)
{
    if (c >= 0) return Fold61(static_cast<uint64_t>(c));
    const uint64_t neg = Fold61(static_cast<uint64_t>(-c));
    return neg == 0 ? 0 : kMersenne61 - neg;
}

// --- Balanced-s8 sampling and exact dot products --------------------------

//! Deterministic balanced-s8 sampler: uniform in [-125, 125] (§B.3/§G.2
//! normative balanced representation; the consensus sampler is seed-derived,
//! this test-side sampler only needs determinism and the correct range).
std::vector<int8_t> BalancedS8Vector(FastRandomContext& rng, size_t len)
{
    std::vector<int8_t> out(len);
    for (auto& v : out) {
        v = static_cast<int8_t>(static_cast<int32_t>(rng.randrange(251)) - 125);
    }
    return out;
}

int32_t DotS32(const std::vector<int8_t>& a, const std::vector<int8_t>& b)
{
    BOOST_REQUIRE_EQUAL(a.size(), b.size());
    int32_t acc = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        acc += static_cast<int32_t>(a[i]) * static_cast<int32_t>(b[i]);
    }
    return acc;
}

int64_t DotS64(const std::vector<int8_t>& a, const std::vector<int8_t>& b)
{
    BOOST_REQUIRE_EQUAL(a.size(), b.size());
    int64_t acc = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        acc += static_cast<int64_t>(a[i]) * static_cast<int64_t>(b[i]);
    }
    return acc;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(matmul_v4_field_tests, BasicTestingSetup)

// --- The soundness field q = 2^61 - 1 -------------------------------------

BOOST_AUTO_TEST_CASE(v4_soundness_modulus_is_the_mersenne_prime_2_61_minus_1)
{
    BOOST_CHECK_EQUAL(kMersenne61, 0x1FFFFFFFFFFFFFFFULL);
    BOOST_CHECK_EQUAL(kMersenne61, 2305843009213693951ULL);
    BOOST_CHECK(IsPrime64(kMersenne61));
}

BOOST_AUTO_TEST_CASE(v4_consensus_constants_match_spec)
{
    // §0.7 normative launch parameters: R = 3, b = 8.
    BOOST_CHECK_EQUAL(matmul_v4::kFreivaldsRounds, 3U);
    BOOST_CHECK_EQUAL(matmul_v4::kTileB, 8U);
}

BOOST_AUTO_TEST_CASE(fold61_edge_cases)
{
    const uint64_t q = kMersenne61;
    BOOST_CHECK_EQUAL(Fold61(0), 0U);
    BOOST_CHECK_EQUAL(Fold61(1), 1U);
    BOOST_CHECK_EQUAL(Fold61(q - 1), q - 1);
    // Dual representation of zero: q itself must reduce to canonical 0.
    BOOST_CHECK_EQUAL(Fold61(q), 0U);
    BOOST_CHECK_EQUAL(Fold61(q + 1), 1U);
    BOOST_CHECK_EQUAL(Fold61(2 * q), 0U);
    BOOST_CHECK_EQUAL(Fold61(2 * q + 5), 5U);
    // 2^61 == q + 1 == 1 (mod q).
    BOOST_CHECK_EQUAL(Fold61(uint64_t{1} << 61), 1U);
    // 2^64 - 1 = 8 * 2^61 - 1 == 8 - 1 == 7 (mod q).
    BOOST_CHECK_EQUAL(Fold61(std::numeric_limits<uint64_t>::max()), 7U);
}

BOOST_AUTO_TEST_CASE(fold61_matches_native_modulo)
{
    FastRandomContext rng{true};
    for (int i = 0; i < 10'000; ++i) {
        const uint64_t x = rng.rand64();
        BOOST_CHECK_EQUAL(Fold61(x), x % kMersenne61);
    }
}

BOOST_AUTO_TEST_CASE(fold61_powers_of_two_cycle_with_period_61)
{
    for (int k = 0; k < 64; ++k) {
        const uint64_t expected = uint64_t{1} << (k % 61);
        BOOST_CHECK_EQUAL(Fold61(uint64_t{1} << k), expected);
    }
}

BOOST_AUTO_TEST_CASE(fold61_output_always_canonical)
{
    FastRandomContext rng{true};
    for (int i = 0; i < 10'000; ++i) {
        BOOST_CHECK_LT(Fold61(rng.rand64()), kMersenne61);
    }
    // Worst-case double-fold inputs.
    BOOST_CHECK_LT(Fold61(std::numeric_limits<uint64_t>::max()), kMersenne61);
    BOOST_CHECK_LT(Fold61(std::numeric_limits<uint64_t>::max() - kMersenne61), kMersenne61);
}

BOOST_AUTO_TEST_CASE(mulmod61_reference_identities)
{
    const uint64_t q = kMersenne61;
    BOOST_CHECK_EQUAL(MulMod61(0, q - 1), 0U);
    BOOST_CHECK_EQUAL(MulMod61(1, q - 1), q - 1);
    // (q-1)^2 = q^2 - 2q + 1 == 1 (mod q): -1 is its own inverse.
    BOOST_CHECK_EQUAL(MulMod61(q - 1, q - 1), 1U);
    // 2^60 * 2 = 2^61 == 1 (mod q).
    BOOST_CHECK_EQUAL(MulMod61(uint64_t{1} << 60, 2), 1U);

    FastRandomContext rng{true};
    for (int i = 0; i < 1'000; ++i) {
        const uint64_t a = Fold61(rng.rand64());
        const uint64_t b = Fold61(rng.rand64());
        BOOST_CHECK_EQUAL(MulMod61(a, b), MulMod61(b, a));
        BOOST_CHECK_EQUAL(MulMod61(a, b), MulModGeneric(a, b, q));
    }
}

BOOST_AUTO_TEST_CASE(mulmod61_distributes_over_addmod61)
{
    FastRandomContext rng{true};
    for (int i = 0; i < 1'000; ++i) {
        const uint64_t a = Fold61(rng.rand64());
        const uint64_t b = Fold61(rng.rand64());
        const uint64_t c = Fold61(rng.rand64());
        BOOST_CHECK_EQUAL(MulMod61(a, AddMod61(b, c)),
                          AddMod61(MulMod61(a, b), MulMod61(a, c)));
    }
}

// --- INT8 exact-integer arithmetic (§B.4 / §B.6) ---------------------------

BOOST_AUTO_TEST_CASE(s8_dot_product_is_exact_in_int32_at_test_dimensions)
{
    FastRandomContext rng{true};
    for (const size_t n : {size_t{256}, size_t{512}}) {
        for (int trial = 0; trial < 8; ++trial) {
            const auto a = BalancedS8Vector(rng, n);
            const auto b = BalancedS8Vector(rng, n);
            // INT32 accumulation must equal the mathematically exact
            // (wide) integer dot product: no wrap ever occurs (§B.4).
            BOOST_CHECK_EQUAL(static_cast<int64_t>(DotS32(a, b)), DotS64(a, b));
        }
    }
}

BOOST_AUTO_TEST_CASE(s8_dot_product_worst_case_hits_the_bound_exactly)
{
    for (const size_t n : {size_t{256}, size_t{512}}) {
        std::vector<int8_t> pos(n, int8_t{125});
        std::vector<int8_t> neg(n, int8_t{-125});
        const int64_t bound = static_cast<int64_t>(n) * kEntrySquared;
        BOOST_CHECK_EQUAL(DotS64(pos, pos), bound);
        BOOST_CHECK_EQUAL(DotS64(neg, neg), bound);
        BOOST_CHECK_EQUAL(DotS64(pos, neg), -bound);
        // Exactness holds at the extremes too.
        BOOST_CHECK_EQUAL(static_cast<int64_t>(DotS32(pos, pos)), bound);
        BOOST_CHECK_EQUAL(static_cast<int64_t>(DotS32(pos, neg)), -bound);
        // And the bound itself is far below 2^30 at test dimensions.
        BOOST_CHECK_LT(bound, int64_t{1} << 30);
    }
}

BOOST_AUTO_TEST_CASE(s8_accumulation_prefix_never_exceeds_bound)
{
    // Every prefix of the reduction dimension obeys |partial| <= i * 125^2,
    // so no intermediate accumulator state can wrap either (§B.4: the whole
    // reduction runs un-reduced in one s32 accumulation).
    FastRandomContext rng{true};
    const size_t n = 512;
    const auto a = BalancedS8Vector(rng, n);
    const auto b = BalancedS8Vector(rng, n);
    int64_t acc = 0;
    for (size_t i = 0; i < n; ++i) {
        acc += static_cast<int64_t>(a[i]) * static_cast<int64_t>(b[i]);
        BOOST_CHECK_LE(std::llabs(acc), static_cast<int64_t>(i + 1) * kEntrySquared);
        BOOST_CHECK_LE(std::llabs(acc), static_cast<int64_t>(std::numeric_limits<int32_t>::max()));
    }
}

BOOST_AUTO_TEST_CASE(s8_dot_product_is_order_independent)
{
    // Integer addition is associative and commutative, so the result is
    // independent of accumulation order, split-K, or fragment shape —
    // the heart of the cross-vendor bit-exactness argument (§B.6).
    FastRandomContext rng{true};
    const size_t n = 512;
    const auto a = BalancedS8Vector(rng, n);
    const auto b = BalancedS8Vector(rng, n);

    const int32_t forward = DotS32(a, b);

    int32_t backward = 0;
    for (size_t i = n; i-- > 0;) {
        backward += static_cast<int32_t>(a[i]) * static_cast<int32_t>(b[i]);
    }
    BOOST_CHECK_EQUAL(forward, backward);

    // Simulated split-K: accumulate in 8 interleaved panels, then combine.
    std::array<int32_t, 8> panels{};
    for (size_t i = 0; i < n; ++i) {
        panels[i % panels.size()] += static_cast<int32_t>(a[i]) * static_cast<int32_t>(b[i]);
    }
    int32_t combined = 0;
    for (const int32_t p : panels) combined += p;
    BOOST_CHECK_EQUAL(forward, combined);
}

BOOST_AUTO_TEST_CASE(header_cap_accumulation_bound_constants)
{
    // §G.4-#3 as runtime checks (mirrors the static_asserts above so the
    // values also appear in test logs).
    BOOST_CHECK_EQUAL(kEntrySquared, 15'625);
    BOOST_CHECK_LT(15'625LL * 65'535LL, int64_t{1} << 30);            // header cap
    BOOST_CHECK_LE(15'625LL * 137'438LL,
                   static_cast<int64_t>(std::numeric_limits<int32_t>::max())); // n_max
    BOOST_CHECK_GT(15'625LL * 137'439LL,
                   static_cast<int64_t>(std::numeric_limits<int32_t>::max())); // n_max + 1
}

// --- Mod-q folding of exact integer entries (§D.3) --------------------------

BOOST_AUTO_TEST_CASE(canonical_residue_of_signed_entries)
{
    const uint64_t q = kMersenne61;
    BOOST_CHECK_EQUAL(CanonicalResidue(0), 0U);
    BOOST_CHECK_EQUAL(CanonicalResidue(1), 1U);
    BOOST_CHECK_EQUAL(CanonicalResidue(-1), q - 1);
    BOOST_CHECK_EQUAL(CanonicalResidue(15'625LL * 65'535LL), 1'024'046'875ULL);
    BOOST_CHECK_EQUAL(CanonicalResidue(-15'625LL * 65'535LL), q - 1'024'046'875ULL);
}

BOOST_AUTO_TEST_CASE(canonical_residue_is_injective_within_the_entry_range)
{
    // Distinct exact entries with |delta| < 2^32 < q can never map to the
    // same residue — the no-aliasing property that restores 1/q-per-round
    // soundness (§D.3-(2)).
    FastRandomContext rng{true};
    for (int i = 0; i < 2'000; ++i) {
        const int64_t bound = 15'625LL * 65'535LL;
        const int64_t c1 = static_cast<int64_t>(rng.randrange(2 * bound + 1)) - bound;
        int64_t c2 = static_cast<int64_t>(rng.randrange(2 * bound + 1)) - bound;
        if (c1 == c2) c2 = (c2 == bound) ? c2 - 1 : c2 + 1;
        BOOST_CHECK_NE(CanonicalResidue(c1), CanonicalResidue(c2));
    }
}

BOOST_AUTO_TEST_CASE(canonical_residue_aliases_only_at_multiples_of_q)
{
    // The first aliasing distance is exactly q, which is unreachable for
    // in-range entry deltas (|delta| < 2^32 << q).
    const int64_t q = static_cast<int64_t>(kMersenne61);
    BOOST_CHECK_EQUAL(CanonicalResidue(5), CanonicalResidue(5 - q));
    BOOST_CHECK_EQUAL(CanonicalResidue(-7), CanonicalResidue(q - 7));
    BOOST_CHECK_NE(CanonicalResidue(5), CanonicalResidue(5 - (q - 1)));
}

BOOST_AUTO_TEST_CASE(exact_dot_matches_residue_dot_mod_q)
{
    // Folding the exact integer dot product into F_q equals performing the
    // whole dot product in F_q on the folded operands: the verifier may
    // work mod q throughout (one multiply-and-fold per MAC, §D.3).
    FastRandomContext rng{true};
    const size_t n = 512;
    const auto a = BalancedS8Vector(rng, n);
    const auto b = BalancedS8Vector(rng, n);

    const uint64_t direct = CanonicalResidue(DotS64(a, b));

    uint64_t modular = 0;
    for (size_t i = 0; i < n; ++i) {
        const uint64_t term = MulMod61(CanonicalResidue(a[i]), CanonicalResidue(b[i]));
        modular = AddMod61(modular, term);
    }
    BOOST_CHECK_EQUAL(direct, modular);
}

BOOST_AUTO_TEST_SUITE_END()
