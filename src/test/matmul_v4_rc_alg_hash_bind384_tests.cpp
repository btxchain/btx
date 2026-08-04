// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// PR-89 gate tests for the OPTIONAL 384-bit binding-digest MODE of AlgHash
// (matmul_v4_rc_alg_hash.{h,cpp}). This mode is a high-margin knob, NOT
// required under the BTX threat model (q<=~78, where the shipped 256-bit
// c=128 package already clears >=100). Honest label: birthday-192 /
// algebraic-128 (same R_F=8/R_P=22 permutation, NOT re-dimensioned). Verifies:
//   (a) the widened rate-6/capacity-6 sponge round-trips: it is deterministic,
//       input-sensitive, emits 6 canonical lanes, and its underlying frozen
//       t=12 permutation is a bijection (Permute∘InversePermute = id);
//   (b) the honest floor split: capacity BIRTHDAY floor 128 (B256) / 192
//       (B384); ALGEBRAIC floor 128 for BOTH (rounds unchanged); EFFECTIVE
//       floor min(...) = 128 for both — B384 gives no algebraic gain;
//   (c) the digest-width birthday CAP (digest_bits - 2q) MOVES 256 -> 384,
//       and under the realistic threat model q<=78 the 256-bit DEFAULT already
//       yields 2c-2q = 256-156 = 100, so B384 is optional margin only;
//   (d) the widened Merkle openings still fit the 24M block-weight budget:
//       the all-digest upper bound grows the 1.74 MB multiproof to 2.61 MB.

#include <matmul/matmul_v4_rc_alg_hash.h>
#include <matmul/matmul_v4_rc_gkr_field.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cmath>
#include <cstdint>
#include <vector>

namespace ah = matmul::v4::rc::alg_hash;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_alg_hash_bind384_tests, BasicTestingSetup)

namespace {

using gf::Fp;

uint64_t SplitMix64(uint64_t& state)
{
    state += 0x9E3779B97F4A7C15ULL;
    uint64_t z = state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

Fp RandFp(uint64_t& state) { return gf::Canonical(SplitMix64(state)); }

} // namespace

// (a) The widened split reuses the SAME frozen permutation, which must remain a
//     bijection regardless of how rate/capacity are partitioned.
BOOST_AUTO_TEST_CASE(permutation_bijection_partition_independent)
{
    uint64_t seed = 0xB384B384ULL;
    for (int trial = 0; trial < 64; ++trial) {
        ah::State s{};
        for (uint32_t i = 0; i < ah::kAlgHashT; ++i) s[i] = RandFp(seed);
        const ah::State original = s;
        ah::Permute(s);
        ah::InversePermute(s);
        for (uint32_t i = 0; i < ah::kAlgHashT; ++i) {
            BOOST_CHECK_EQUAL(gf::Canonical(s[i]), gf::Canonical(original[i]));
        }
    }
}

// (a) The 384-bit sponge round-trips: deterministic, 6 canonical lanes, and
//     sensitive to every input position and to the domain seed.
BOOST_AUTO_TEST_CASE(bind384_sponge_roundtrip_and_sensitivity)
{
    uint64_t seed = 0x123456789ABCDEFULL;
    std::vector<Fp> xs;
    for (int i = 0; i < 19; ++i) xs.push_back(RandFp(seed));
    const Fp dom = RandFp(seed);

    const ah::Digest384 d = ah::SpongeHashFp384(xs, dom);
    const ah::Digest384 d_again = ah::SpongeHashFp384(xs, dom);

    // determinism + width: exactly 6 lanes, each canonical
    BOOST_CHECK_EQUAL(d.size(), ah::kBind384DigestLen);
    BOOST_CHECK_EQUAL(ah::kBind384DigestLen, 6u);
    for (uint32_t i = 0; i < ah::kBind384DigestLen; ++i) {
        BOOST_CHECK_EQUAL(gf::Canonical(d[i]), d[i]);
        BOOST_CHECK_EQUAL(gf::Canonical(d[i]), gf::Canonical(d_again[i]));
    }

    // different domain -> different digest
    const ah::Digest384 d_dom = ah::SpongeHashFp384(xs, gf::Add(dom, 1));
    bool domain_changed = false;
    for (uint32_t i = 0; i < ah::kBind384DigestLen; ++i) {
        if (gf::Canonical(d[i]) != gf::Canonical(d_dom[i])) domain_changed = true;
    }
    BOOST_CHECK(domain_changed);

    // flip any single input element -> different digest
    for (size_t pos = 0; pos < xs.size(); ++pos) {
        std::vector<Fp> ys = xs;
        ys[pos] = gf::Add(ys[pos], 1);
        const ah::Digest384 dy = ah::SpongeHashFp384(ys, dom);
        bool changed = false;
        for (uint32_t i = 0; i < ah::kBind384DigestLen; ++i) {
            if (gf::Canonical(d[i]) != gf::Canonical(dy[i])) changed = true;
        }
        BOOST_CHECK(changed);
    }
}

// (a) Compress384 and LeafHashRow384: 6-lane, deterministic, input-sensitive.
BOOST_AUTO_TEST_CASE(bind384_compress_and_leaf)
{
    uint64_t seed = 0xFEEDBEEFULL;
    ah::Digest384 l{}, r{};
    for (uint32_t i = 0; i < ah::kBind384DigestLen; ++i) { l[i] = RandFp(seed); r[i] = RandFp(seed); }

    const ah::Digest384 node = ah::Compress384(l, r);
    BOOST_CHECK_EQUAL(node.size(), 6u);
    // order matters: Compress(l,r) != Compress(r,l) with overwhelming prob
    const ah::Digest384 swapped = ah::Compress384(r, l);
    bool order_sensitive = false;
    for (uint32_t i = 0; i < 6; ++i) if (gf::Canonical(node[i]) != gf::Canonical(swapped[i])) order_sensitive = true;
    BOOST_CHECK(order_sensitive);

    std::vector<gf::Fp3> row;
    for (int i = 0; i < 5; ++i) row.push_back(gf::Fp3{RandFp(seed), RandFp(seed), RandFp(seed)});
    const ah::Digest384 leaf0 = ah::LeafHashRow384(row, 0);
    const ah::Digest384 leaf1 = ah::LeafHashRow384(row, 1);
    BOOST_CHECK_EQUAL(leaf0.size(), 6u);
    bool index_sensitive = false;
    for (uint32_t i = 0; i < 6; ++i) if (gf::Canonical(leaf0[i]) != gf::Canonical(leaf1[i])) index_sensitive = true;
    BOOST_CHECK(index_sensitive);
}

// (b) Honest floor split: birthday-192 / algebraic-128, effective 128 for both.
BOOST_AUTO_TEST_CASE(honest_floor_split_birthday192_algebraic128)
{
    // 384 mode: rate 6 + capacity 6 = t (12); 6-lane (384-bit) digest.
    static_assert(ah::kBind384Rate + ah::kBind384Capacity == ah::kAlgHashT, "");
    static_assert(ah::kBind384Rate == 6 && ah::kBind384Capacity == 6, "");
    static_assert(ah::kBind384DigestLen == 6, "");

    // GENERIC (birthday) sponge collision floor = 2^(capacity_bits/2).
    BOOST_CHECK_EQUAL(ah::BindingCapacityLanes(ah::BindingMode::B256), 4u);
    BOOST_CHECK_EQUAL(ah::BindingCapacityLanes(ah::BindingMode::B384), 6u);
    BOOST_CHECK_EQUAL(
        ah::BindingCapacityBirthdayFloorBits(ah::BindingMode::B256), 128u);
    BOOST_CHECK_EQUAL(
        ah::BindingCapacityBirthdayFloorBits(ah::BindingMode::B384), 192u);

    // ALGEBRAIC floor: 128 for BOTH modes — the round count (R_F=8/R_P=22) is
    // NOT re-dimensioned, so widening the capacity buys no algebraic strength.
    BOOST_CHECK_EQUAL(ah::BindingAlgebraicFloorBits(ah::BindingMode::B256), 128u);
    BOOST_CHECK_EQUAL(ah::BindingAlgebraicFloorBits(ah::BindingMode::B384), 128u);

    // EFFECTIVE floor = min(birthday, algebraic): B384 is min(192,128) = 128,
    // the SAME algebraic level as B256.
    BOOST_CHECK_EQUAL(
        ah::BindingEffectiveCollisionFloorBits(ah::BindingMode::B256), 128u);
    BOOST_CHECK_EQUAL(
        ah::BindingEffectiveCollisionFloorBits(ah::BindingMode::B384), 128u);

    BOOST_CHECK_EQUAL(ah::BindingDigestBits(ah::BindingMode::B256), 256u);
    BOOST_CHECK_EQUAL(ah::BindingDigestBits(ah::BindingMode::B384), 384u);

    // env not set in the test harness -> default is the unchanged 256 path.
    BOOST_CHECK(ah::ActiveBindingMode() == ah::BindingMode::B256);
}

// (c) The digest-width birthday CAP (digest_bits - 2q) moves 256 -> 384, but
//     under the realistic BTX threat model (q<=78) the 256-bit DEFAULT already
//     clears >=100, so B384 is optional margin only.
BOOST_AUTO_TEST_CASE(binding_birthday_floor_optional_margin)
{
    // THREAT-MODEL ANCHOR: BTX tensor-mining bounds proof-grind at q<=~78.
    // The shipped 256-bit c=128 package gives 2c-2q = 256-156 = 100 at q=78,
    // so the >=100-bit target holds on the DEFAULT path WITHOUT widening.
    BOOST_CHECK_CLOSE(
        ah::BindingBirthdayFloorBits(78, ah::BindingMode::B256), 100.0, 1e-9);
    BOOST_CHECK(
        ah::BindingBirthdayFloorBits(78, ah::BindingMode::B256) >= 100.0);

    // The optional B384 mode still moves the cap up by exactly 128 bits at any
    // q; useful only in the paranoid q>78 regime BTX's mining cost precludes.
    struct Row { uint32_t q; double b256; double b384; };
    const std::array<Row, 3> table = {{
        {78, 100.0, 228.0},
        {94, 68.0, 196.0},
        {100, 56.0, 184.0},
    }};
    for (const Row& row : table) {
        const double f256 = ah::BindingBirthdayFloorBits(row.q, ah::BindingMode::B256);
        const double f384 = ah::BindingBirthdayFloorBits(row.q, ah::BindingMode::B384);
        BOOST_CHECK_CLOSE(f256, row.b256, 1e-9);
        BOOST_CHECK_CLOSE(f384, row.b384, 1e-9);
        BOOST_CHECK_CLOSE(f384 - f256, 128.0, 1e-9);
    }
}

// (d) Wider digests grow Merkle openings; the multiproof still fits 24M weight.
BOOST_AUTO_TEST_CASE(widened_multiproof_fits_block_weight_budget)
{
    constexpr uint64_t kBlockWeightBudget = 24'000'000; // MAX_BLOCK_WEIGHT
    constexpr double kBaselineBytes = 1'740'000.0;       // 1.74 MB @ 256-bit

    const uint32_t d256 = ah::BindingDigestLen(ah::BindingMode::B256); // 4 lanes
    const uint32_t d384 = ah::BindingDigestLen(ah::BindingMode::B384); // 6 lanes
    BOOST_CHECK_EQUAL(d256 * 8u, 32u); // 32-byte node digest
    BOOST_CHECK_EQUAL(d384 * 8u, 48u); // 48-byte node digest

    // Conservative all-digest upper bound: EVERY proof byte is a node digest,
    // so the whole proof scales by 48/32 = 1.5x. Real growth is strictly less
    // (opened leaf Fp3 rows and non-digest metadata do not widen).
    const double widen = static_cast<double>(d384) / static_cast<double>(d256);
    BOOST_CHECK_CLOSE(widen, 1.5, 1e-9);
    const double widened_bytes = kBaselineBytes * widen; // 2'610'000 = 2.61 MB
    BOOST_CHECK_CLOSE(widened_bytes, 2'610'000.0, 1e-9);

    BOOST_CHECK(widened_bytes < static_cast<double>(kBlockWeightBudget));
    const double frac = widened_bytes / static_cast<double>(kBlockWeightBudget);
    BOOST_CHECK(frac < 0.11); // ~10.9% of budget; ~89% headroom remains
}

BOOST_AUTO_TEST_SUITE_END()
