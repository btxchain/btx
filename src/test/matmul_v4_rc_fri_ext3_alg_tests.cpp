// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

// Piece-2 gate tests (Stage-C spec §6): the algebraic-hash batched FRI with
// the ROW-WISE Merkle layout (§2.3) and the Q=148 recursion soundness
// parameters (§5.2). The SHA256d batched FRI keeps its own suite
// (matmul_v4_rc_fri_ext3_tests.cpp) — nothing here touches it.

namespace rc = matmul::v4::rc;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_fri_ext3_alg_tests, BasicTestingSetup)

namespace {

uint256 MakeSeed(uint8_t fill)
{
    uint256 seed;
    for (int i = 0; i < 32; ++i) seed.data()[i] = fill;
    return seed;
}

std::vector<std::vector<rc::Fp3>> MakeColumns()
{
    std::vector<std::vector<rc::Fp3>> columns(3);
    columns[0].resize(5);
    columns[1].resize(8);
    columns[2].resize(3);
    for (size_t c = 0; c < columns.size(); ++c) {
        for (size_t j = 0; j < columns[c].size(); ++j) {
            columns[c][j] = gf::FromSigned3(static_cast<int64_t>(7 * c + 3 * j + 1));
        }
    }
    return columns;
}

} // namespace

// Gate (f): the recursion path ships Q=148, g=40, blowup=16 — statically
// asserted in the header, re-checked here against the spec §5.2 arithmetic.
BOOST_AUTO_TEST_CASE(fra3_constants_and_soundness_bits)
{
    BOOST_CHECK_EQUAL(rc::kRCFri3AlgNumQueries, 148u);
    BOOST_CHECK_EQUAL(rc::kRCFriGrindingBits, 40u);
    BOOST_CHECK_EQUAL(rc::kRCFriBlowup, 16u);
    // floor(148·log2(32/17)) − 40 = 135 − 40 = 95 ≥ 92 per-node target.
    BOOST_CHECK_EQUAL(rc::Fri3AlgSoundnessBoundBits(), 95);
    BOOST_CHECK_GE(rc::Fri3AlgSoundnessBoundBits(), rc::kRCFri3AlgTargetSoundnessBits);
    BOOST_CHECK(rc::Fri3AlgClaimedBitsMeetTarget());
    // Path-local hard cap admits Q=148; the SHA cap kRCFriMaxQueriesHard=128
    // is deliberately NOT raised (it guards the SHA paths only).
    BOOST_CHECK_GE(rc::kRCFri3AlgMaxQueriesHard, rc::kRCFri3AlgNumQueries);
    BOOST_CHECK_EQUAL(rc::kRCFriMaxQueriesHard, 128u);
    BOOST_CHECK(std::string(rc::kRCFri3AlgBatchSoundnessStatement).find("Q=148") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFri3AlgBatchSoundnessStatement).find("blowup=16") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFri3AlgBatchSoundnessStatement).find("ROW-WISE") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFri3AlgBatchSoundnessStatement).find("Poseidon2") !=
                std::string::npos);
}

// Digest packing: 4×Fp ⇆ uint256 (canonical LE64 limbs) is a bijection onto
// its image — round-trips exactly and rejects non-canonical limbs (≥ p).
BOOST_AUTO_TEST_CASE(fra3_digest_packing_round_trip)
{
    const rc::Fri3AlgDigest d{0x0123456789ABCDEFULL, 0xFFFFFFFF00000000ULL, 1, 0};
    const uint256 u = rc::Fri3AlgDigestToUint256(d);
    const auto back = rc::Fri3AlgDigestFromUint256(u);
    BOOST_REQUIRE(back.has_value());
    for (int k = 0; k < 4; ++k) {
        BOOST_CHECK_EQUAL(gf::Canonical((*back)[k]), gf::Canonical(d[k]));
    }
    uint256 bad = u;
    for (int b = 0; b < 8; ++b) bad.data()[b] = 0xFF; // limb0 = 2^64−1 ≥ p
    BOOST_CHECK(!rc::Fri3AlgDigestFromUint256(bad).has_value());
}

// Gate (a): honest commit+verify accepts; serde round-trips byte-exact.
BOOST_AUTO_TEST_CASE(fra3_honest_commit_verify_serde_byte_exact)
{
    const auto columns = MakeColumns();
    const uint256 seed = MakeSeed(0x42);
    const auto c = rc::Fri3AlgBatchCommit(columns, seed, /*pow_grind_nonce=*/9);
    BOOST_REQUIRE_MESSAGE(c.ok, c.note);
    BOOST_CHECK_EQUAL(c.proof.queries.size(), rc::kRCFri3AlgNumQueries);
    BOOST_CHECK_EQUAL(c.proof.n_coeffs, 8u);
    BOOST_CHECK_EQUAL(c.proof.row_commit.n_leaves, 8u * rc::kRCFriBlowup);
    std::string why;
    BOOST_CHECK_MESSAGE(rc::Fri3AlgBatchVerify(c.proof, seed, &why), why);

    std::vector<unsigned char> ser, ser2;
    const size_t n1 = rc::SerializeFri3AlgBatchProof(c.proof, ser);
    const auto de = rc::DeserializeFri3AlgBatchProof(ser);
    BOOST_REQUIRE(de.has_value());
    const size_t n2 = rc::SerializeFri3AlgBatchProof(*de, ser2);
    BOOST_CHECK_EQUAL(n1, n2);
    BOOST_CHECK(ser == ser2);
    BOOST_CHECK(rc::Fri3AlgBatchVerify(*de, seed, nullptr));
    BOOST_CHECK(!rc::Fri3AlgBatchVerify(c.proof, MakeSeed(0x43), nullptr)); // wrong seed
}

// Gate (b): single-eval tamper rejects — both the forge probe (flip one LDE
// eval, recompute only the row root, keep openings) and a direct opened-value
// tamper in one query.
BOOST_AUTO_TEST_CASE(fra3_single_eval_tamper_rejected)
{
    const auto columns = MakeColumns();
    const uint256 seed = MakeSeed(0x42);
    const auto c = rc::Fri3AlgBatchCommit(columns, seed);
    BOOST_REQUIRE(c.ok);
    std::string why;
    BOOST_CHECK_MESSAGE(
        rc::Fri3AlgForgeFlippedEvalMustFail(c, seed, /*flip_col=*/1, /*flip_index=*/17, &why),
        why);

    auto forged = c.proof;
    forged.queries[0].row.values[0].c0 ^= 1;
    BOOST_CHECK(!rc::Fri3AlgBatchVerify(forged, seed, &why));
    BOOST_CHECK_EQUAL(why, "row merkle");
}

// Gate (c): fold-path tamper rejects (opened pair value and fold challenge).
BOOST_AUTO_TEST_CASE(fra3_fold_path_tamper_rejected)
{
    const auto columns = MakeColumns();
    const uint256 seed = MakeSeed(0x42);
    const auto c = rc::Fri3AlgBatchCommit(columns, seed);
    BOOST_REQUIRE(c.ok);
    std::string why;

    auto forged = c.proof;
    forged.queries[0].steps[0].even = gf::Add(forged.queries[0].steps[0].even, gf::Fp3::One());
    BOOST_CHECK(!rc::Fri3AlgBatchVerify(forged, seed, &why));
    BOOST_CHECK_EQUAL(why, "fold even merkle");

    auto forged2 = c.proof;
    forged2.fold_challenges[0] = gf::Add(forged2.fold_challenges[0], gf::Fp3::One());
    BOOST_CHECK(!rc::Fri3AlgBatchVerify(forged2, seed, &why));
    BOOST_CHECK_EQUAL(why, "fold challenge mismatch");
}

// Gate (d): sibling / root tamper rejects (row path, fold path, both roots).
BOOST_AUTO_TEST_CASE(fra3_sibling_and_root_tamper_rejected)
{
    const auto columns = MakeColumns();
    const uint256 seed = MakeSeed(0x42);
    const auto c = rc::Fri3AlgBatchCommit(columns, seed);
    BOOST_REQUIRE(c.ok);
    std::string why;

    auto forged = c.proof;
    forged.queries[0].row.siblings[0][0] = gf::Add(forged.queries[0].row.siblings[0][0], 1);
    BOOST_CHECK(!rc::Fri3AlgBatchVerify(forged, seed, &why));
    BOOST_CHECK_EQUAL(why, "row merkle");

    auto forged2 = c.proof;
    forged2.queries[0].steps[0].even_siblings[0][0] =
        gf::Add(forged2.queries[0].steps[0].even_siblings[0][0], 1);
    BOOST_CHECK(!rc::Fri3AlgBatchVerify(forged2, seed, &why));
    BOOST_CHECK_EQUAL(why, "fold even merkle");

    auto forged3 = c.proof;
    forged3.row_commit.root[0] = gf::Add(forged3.row_commit.root[0], 1);
    BOOST_CHECK(!rc::Fri3AlgBatchVerify(forged3, seed, &why));
    BOOST_CHECK_EQUAL(why, "lambda mismatch"); // row root seeds the FS replay

    auto forged4 = c.proof;
    forged4.fold_layers[0].root[0] = gf::Add(forged4.fold_layers[0].root[0], 1);
    BOOST_CHECK(!rc::Fri3AlgBatchVerify(forged4, seed, &why));
    BOOST_CHECK_EQUAL(why, "fold challenge mismatch");
}

// Gate (e): row-wise commitment equivalence — the standalone row-root helper
// (two-epoch discipline; Fri3BatchColumnRoot analogue for the row-wise
// layout) is limb-identical to the full commit's row root, and distinguishes
// distinct column sets.
BOOST_AUTO_TEST_CASE(fra3_row_root_equivalence)
{
    const auto columns = MakeColumns();
    const uint256 seed = MakeSeed(0x42);
    const auto c = rc::Fri3AlgBatchCommit(columns, seed);
    BOOST_REQUIRE(c.ok);
    const rc::Fri3AlgDigest standalone = rc::Fri3AlgBatchRowRoot(columns, c.proof.n_coeffs);
    for (int k = 0; k < 4; ++k) {
        BOOST_CHECK_EQUAL(gf::Canonical(standalone[k]),
                          gf::Canonical(c.proof.row_commit.root[k]));
    }
    auto columns2 = columns;
    columns2[2][0] = gf::Add(columns2[2][0], gf::Fp3::One());
    const rc::Fri3AlgDigest other = rc::Fri3AlgBatchRowRoot(columns2, c.proof.n_coeffs);
    bool differs = false;
    for (int k = 0; k < 4; ++k) {
        differs = differs || gf::Canonical(other[k]) != gf::Canonical(standalone[k]);
    }
    BOOST_CHECK(differs);
}

BOOST_AUTO_TEST_SUITE_END()
