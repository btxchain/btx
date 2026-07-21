// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_fri.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace rc = matmul::v4::rc;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_fri_tests, BasicTestingSetup)

namespace {

uint256 MakeSeed(uint8_t fill)
{
    uint256 seed;
    for (int i = 0; i < 32; ++i) seed.data()[i] = fill;
    return seed;
}

std::vector<rc::Fp2> MakeCoeffs(size_t n)
{
    std::vector<rc::Fp2> c(n);
    for (size_t i = 0; i < n; ++i) c[i] = gf::FromSigned2(static_cast<int64_t>(i * 3 + 1));
    return c;
}

} // namespace

BOOST_AUTO_TEST_CASE(fri_constants_and_soundness_bits)
{
    // M6 / Fable oracle: k=40 grinding, Fp2, blowup=16, Q=116 unique-decoding.
    BOOST_CHECK_EQUAL(rc::kRCFriBlowup, 16u);
    BOOST_CHECK_EQUAL(rc::kRCFriNumQueries, 116u);
    BOOST_CHECK_EQUAL(rc::kRCFriGrindingBits, 40u);
    BOOST_CHECK_EQUAL(rc::kRCFriProofVersion, 4u);
    BOOST_CHECK(!rc::kRCFriConjecturedBoundEnabled);
    BOOST_CHECK(rc::FriClaimedBitsMeetTarget());
    BOOST_CHECK_EQUAL(rc::FriSoundnessBoundBits(), 65); // floor(116*log2(32/17)-40)
    BOOST_CHECK_GE(rc::FriSoundnessBoundBits(), rc::kRCFriTargetSoundnessBits);
    BOOST_CHECK(std::string(rc::kRCFriSoundnessStatement).find("Q=116") != std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFriSoundnessStatement).find("blowup=16") != std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFriSoundnessStatement).find("UNIQUE-DECODING") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFriSoundnessStatement).find("DEEP/OOD") != std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFriSoundnessStatement).find("NOT conjectured") !=
                std::string::npos);
}

BOOST_AUTO_TEST_CASE(fri_honest_commit_verify)
{
    const auto coeffs = MakeCoeffs(16);
    const uint256 seed = MakeSeed(0x42);
    const auto c = rc::FriCommitAndFold(coeffs, seed, /*pow_grind_nonce=*/7);
    BOOST_REQUIRE(c.ok);
    BOOST_CHECK_EQUAL(c.proof.queries.size(), rc::kRCFriNumQueries);
    BOOST_CHECK_EQUAL(c.proof.pow_grind_nonce, 7u);
    BOOST_CHECK_EQUAL(c.lde_evals.size(), 16u * rc::kRCFriBlowup);
    BOOST_CHECK(c.proof.layers.size() >= 2);
    std::string why;
    BOOST_CHECK_MESSAGE(rc::FriVerify(c.proof, seed, &why), why);

    std::vector<unsigned char> bytes;
    BOOST_CHECK(rc::SerializeFriProof(c.proof, bytes) > 0);
    const auto back = rc::DeserializeFriProof(bytes);
    BOOST_REQUIRE(back.has_value());
    BOOST_CHECK(rc::FriVerify(*back, seed, &why));
}

BOOST_AUTO_TEST_CASE(fri_wrong_leaf_rejected)
{
    const auto c = rc::FriCommitAndFold(MakeCoeffs(8), MakeSeed(0x11));
    BOOST_REQUIRE(c.ok);
    auto bad = c.proof;
    bad.queries[0].steps[0].even.c0 ^= 1;
    std::string why;
    BOOST_CHECK(!rc::FriVerify(bad, MakeSeed(0x11), &why));
}

BOOST_AUTO_TEST_CASE(fri_wrong_sibling_rejected)
{
    const auto c = rc::FriCommitAndFold(MakeCoeffs(8), MakeSeed(0x22));
    BOOST_REQUIRE(c.ok);
    BOOST_REQUIRE(!c.proof.queries[0].steps[0].even_siblings.empty());
    auto bad = c.proof;
    bad.queries[0].steps[0].even_siblings[0].data()[0] ^= 0xff;
    std::string why;
    BOOST_CHECK(!rc::FriVerify(bad, MakeSeed(0x22), &why));
}

BOOST_AUTO_TEST_CASE(fri_wrong_fold_challenge_rejected)
{
    const auto c = rc::FriCommitAndFold(MakeCoeffs(8), MakeSeed(0x33));
    BOOST_REQUIRE(c.ok);
    BOOST_REQUIRE(!c.proof.fold_challenges.empty());
    auto bad = c.proof;
    bad.fold_challenges[0].c0 ^= 1;
    std::string why;
    BOOST_CHECK(!rc::FriVerify(bad, MakeSeed(0x33), &why));
}

BOOST_AUTO_TEST_CASE(fri_truncated_openings_rejected)
{
    const auto c = rc::FriCommitAndFold(MakeCoeffs(8), MakeSeed(0x44));
    BOOST_REQUIRE(c.ok);
    auto bad = c.proof;
    BOOST_REQUIRE(!bad.queries[0].steps.empty());
    bad.queries[0].steps.pop_back();
    std::string why;
    BOOST_CHECK(!rc::FriVerify(bad, MakeSeed(0x44), &why));

    auto bad2 = c.proof;
    bad2.queries.pop_back();
    BOOST_CHECK(!rc::FriVerify(bad2, MakeSeed(0x44), &why));
}

BOOST_AUTO_TEST_CASE(fri_query_count_matches_constant)
{
    const auto c = rc::FriCommitAndFold(MakeCoeffs(4), MakeSeed(0x55));
    BOOST_REQUIRE(c.ok);
    BOOST_CHECK_EQUAL(c.proof.queries.size(), rc::kRCFriNumQueries);
}

BOOST_AUTO_TEST_CASE(fri_proof_much_smaller_than_lde_for_large_n)
{
    // With DEEP (nested quot FRI) openings grow; still ≪ shipping full LDE at large N.
    const size_t n = 65536;
    const auto c = rc::FriCommitAndFold(MakeCoeffs(n), MakeSeed(0x66));
    BOOST_REQUIRE(c.ok);
    BOOST_REQUIRE(c.proof.has_deep);
    const size_t lde_bytes = c.lde_evals.size() * sizeof(rc::Fp2);
    BOOST_CHECK_LT(c.proof_bytes, lde_bytes);
    BOOST_CHECK_EQUAL(c.proof.queries.size(), rc::kRCFriNumQueries);
}

BOOST_AUTO_TEST_CASE(fri_deep_ood_tamper_rejects)
{
    const auto c = rc::FriCommitAndFold(MakeCoeffs(16), MakeSeed(0x71));
    BOOST_REQUIRE(c.ok);
    BOOST_REQUIRE(c.proof.has_deep);
    auto bad = c.proof;
    bad.deep_eval.c0 ^= 1;
    std::string why;
    BOOST_CHECK(!rc::FriVerify(bad, MakeSeed(0x71), &why));
}

BOOST_AUTO_TEST_CASE(fri_forge_flipped_eval_rejected)
{
    const uint256 seed = MakeSeed(0x77);
    const auto c = rc::FriCommitAndFold(MakeCoeffs(16), seed);
    BOOST_REQUIRE(c.ok);
    std::string why;
    BOOST_CHECK_MESSAGE(rc::FriForgeFlippedEvalMustFail(c, seed, /*flip_index=*/3, &why), why);
}

BOOST_AUTO_TEST_CASE(fri_bad_seed_rejected)
{
    const auto c = rc::FriCommitAndFold(MakeCoeffs(8), MakeSeed(0x88));
    BOOST_REQUIRE(c.ok);
    std::string why;
    BOOST_CHECK(!rc::FriVerify(c.proof, MakeSeed(0x99), &why));
}

// ============================================================================
// Batched FRI (v7 substrate): single instance + dual-OOD DEEP.
// ============================================================================

namespace {

std::vector<std::vector<rc::Fp2>> MakeBatchColumns()
{
    // Mixed lengths incl. non-pow2 (5) and a singleton — exercises the
    // degree-shift (maximal-degree enforcement) path.
    std::vector<std::vector<rc::Fp2>> cols;
    cols.push_back(MakeCoeffs(16));
    std::vector<rc::Fp2> c2(5);
    for (size_t i = 0; i < c2.size(); ++i) c2[i] = gf::FromSigned2(-static_cast<int64_t>(i) - 9);
    cols.push_back(std::move(c2));
    cols.push_back(MakeCoeffs(32));
    cols.push_back({gf::FromSigned2(424242)});
    return cols;
}

} // namespace

BOOST_AUTO_TEST_CASE(frib_constants_and_soundness_bits)
{
    // Soundness table 2026-07-21: the 7 separate v6 FRI instances union to
    // 7·2^-65.85 ≈ 2^-63.05 — FAILING the 2^-64 target. One batched instance
    // is mandatory. ceil(log2 7) = 3 bits of union loss documents the failure:
    BOOST_CHECK_LT(rc::FriSoundnessBoundBits() - 3, rc::kRCFriTargetSoundnessBits);
    // Named batched query constant: Q=128 (blueprint hardening; Q=116 clears
    // 2^-64 with <1 bit margin, 128 gives floor(128·log2(32/17))−40 = 76).
    BOOST_CHECK_EQUAL(rc::kRCFriBatchNumQueries, 128u);
    BOOST_CHECK_EQUAL(rc::FriBatchSoundnessBoundBits(), 76);
    BOOST_CHECK_GE(rc::FriBatchSoundnessBoundBits(), rc::kRCFriTargetSoundnessBits);
    BOOST_CHECK(rc::FriBatchClaimedBitsMeetTarget());
    // κ: 2-adicity wall — blowup·κ = 2^32 = max power-of-two subgroup of Fp^×.
    BOOST_CHECK_EQUAL(rc::kRCFriMaxColumnLog2, 28u);
    BOOST_CHECK(std::string(rc::kRCFriBatchSoundnessStatement).find("Q=128") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFriBatchSoundnessStatement).find("DUAL-OOD") !=
                std::string::npos);
}

BOOST_AUTO_TEST_CASE(frib_honest_commit_verify_serde_byte_exact)
{
    const auto cols = MakeBatchColumns();
    const uint256 seed = MakeSeed(0xB1);
    const auto c = rc::FriBatchCommit(cols, seed, /*pow_grind_nonce=*/11);
    BOOST_REQUIRE_MESSAGE(c.ok, c.note);
    const auto& p = c.proof;
    BOOST_CHECK_EQUAL(p.n_coeffs, 32u); // max column len 32 (canonical pow2)
    BOOST_CHECK_EQUAL(p.queries.size(), rc::kRCFriBatchNumQueries);
    BOOST_CHECK_EQUAL(p.columns.size(), cols.size());
    // Dual OOD: two distinct points, both off the LDE domain (c1 != 0 suffices
    // for off-domain; distinctness is checked structurally by the verifier).
    BOOST_CHECK(!gf::Eq(p.z1, p.z2));
    std::string why;
    BOOST_CHECK_MESSAGE(rc::FriBatchVerify(p, seed, &why), why);

    // The opening primitive: bound per-column evaluations at BOTH OOD points
    // are byte-exact against direct polynomial evaluation.
    for (size_t i = 0; i < cols.size(); ++i) {
        BOOST_CHECK(gf::Eq(p.evals_z1[i], rc::FriEvalPoly(cols[i], p.z1)));
        BOOST_CHECK(gf::Eq(p.evals_z2[i], rc::FriEvalPoly(cols[i], p.z2)));
    }

    // Column-root helper (two-epoch discipline) matches the committed roots.
    for (size_t i = 0; i < cols.size(); ++i) {
        BOOST_CHECK(rc::FriBatchColumnRoot(cols[i], p.n_coeffs) == p.columns[i].root);
    }

    // Serialization is byte-exact round-trip and still verifies.
    std::vector<unsigned char> bytes;
    BOOST_REQUIRE(rc::SerializeFriBatchProof(p, bytes) > 0);
    const auto back = rc::DeserializeFriBatchProof(bytes);
    BOOST_REQUIRE(back.has_value());
    std::vector<unsigned char> bytes2;
    BOOST_REQUIRE(rc::SerializeFriBatchProof(*back, bytes2) > 0);
    BOOST_CHECK(bytes == bytes2);
    BOOST_CHECK(rc::FriBatchVerify(*back, seed, &why));
}

BOOST_AUTO_TEST_CASE(frib_forged_ood_opening_rejected)
{
    // (b) A forged column opening at an OOD point must be rejected: the
    // dual-OOD DEEP identity at the query sites catches it.
    const auto cols = MakeBatchColumns();
    const uint256 seed = MakeSeed(0xB2);
    const auto c = rc::FriBatchCommit(cols, seed);
    BOOST_REQUIRE(c.ok);
    std::string why;
    auto bad = c.proof;
    bad.evals_z1[1].c0 ^= 1;
    BOOST_CHECK(!rc::FriBatchVerify(bad, seed, &why));
    auto bad2 = c.proof;
    bad2.evals_z2[2].c1 ^= 1;
    BOOST_CHECK(!rc::FriBatchVerify(bad2, seed, &why));
}

BOOST_AUTO_TEST_CASE(frib_forged_column_or_path_rejected)
{
    const auto cols = MakeBatchColumns();
    const uint256 seed = MakeSeed(0xB3);
    const auto c = rc::FriBatchCommit(cols, seed);
    BOOST_REQUIRE(c.ok);
    std::string why;

    auto bad = c.proof; // query-site column value forged
    bad.queries[0].columns[0].value.c0 ^= 1;
    BOOST_CHECK(!rc::FriBatchVerify(bad, seed, &why));

    auto bad2 = c.proof; // Merkle sibling forged
    BOOST_REQUIRE(!bad2.queries[0].columns[0].siblings.empty());
    bad2.queries[0].columns[0].siblings[0].data()[0] ^= 0xff;
    BOOST_CHECK(!rc::FriBatchVerify(bad2, seed, &why));

    auto bad3 = c.proof; // column commitment forged → FS challenges shift
    bad3.columns[0].root.data()[0] ^= 0xff;
    BOOST_CHECK(!rc::FriBatchVerify(bad3, seed, &why));

    auto bad4 = c.proof; // fold challenge forged
    BOOST_REQUIRE(!bad4.fold_challenges.empty());
    bad4.fold_challenges[0].c0 ^= 1;
    BOOST_CHECK(!rc::FriBatchVerify(bad4, seed, &why));

    auto bad5 = c.proof; // final value forged
    bad5.final_value.c0 ^= 1;
    BOOST_CHECK(!rc::FriBatchVerify(bad5, seed, &why));

    auto bad6 = c.proof; // truncated queries
    bad6.queries.pop_back();
    BOOST_CHECK(!rc::FriBatchVerify(bad6, seed, &why));

    auto bad7 = c.proof; // degree-bound (len) forged → shift/v recompute breaks
    bad7.column_len[1] = 4;
    BOOST_CHECK(!rc::FriBatchVerify(bad7, seed, &why));

    // Wrong FS seed → every challenge differs.
    BOOST_CHECK(!rc::FriBatchVerify(c.proof, MakeSeed(0xB4), &why));
}

BOOST_AUTO_TEST_CASE(frib_column_exceeding_kappa_or_empty_rejected)
{
    const uint256 seed = MakeSeed(0xB5);
    // Empty column list / empty column rejected.
    BOOST_CHECK(!rc::FriBatchCommit({}, seed).ok);
    BOOST_CHECK(!rc::FriBatchCommit({std::vector<rc::Fp2>{}}, seed).ok);
    // CPU LDE guard (protocol κ cap is 2^28; CPU soft guard is LDE 2^24).
    std::vector<std::vector<rc::Fp2>> big;
    big.push_back(std::vector<rc::Fp2>((1u << 20) + 1, gf::FromSigned2(1)));
    const auto r = rc::FriBatchCommit(big, seed);
    BOOST_CHECK(!r.ok);
}

BOOST_AUTO_TEST_SUITE_END()
