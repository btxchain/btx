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
    BOOST_CHECK_EQUAL(rc::kRCFriProofVersion, 2u);
    BOOST_CHECK(!rc::kRCFriConjecturedBoundEnabled);
    BOOST_CHECK(rc::FriClaimedBitsMeetTarget());
    BOOST_CHECK_EQUAL(rc::FriSoundnessBoundBits(), 65); // floor(116*log2(32/17)-40)
    BOOST_CHECK_GE(rc::FriSoundnessBoundBits(), rc::kRCFriTargetSoundnessBits);
    BOOST_CHECK(std::string(rc::kRCFriSoundnessStatement).find("Q=116") != std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFriSoundnessStatement).find("blowup=16") != std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFriSoundnessStatement).find("UNIQUE-DECODING") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFriSoundnessStatement).find("NOT conjectured") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFriSoundnessStatement).find("DEEP/OOD") != std::string::npos);
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
    // Large enough that O(Q · log² N) openings ≪ N · blowup · sizeof(Fp2) LDE.
    // Blowup=16 grows the LDE; n=16384 keeps the check CI-safe.
    const size_t n = 16384;
    const auto c = rc::FriCommitAndFold(MakeCoeffs(n), MakeSeed(0x66));
    BOOST_REQUIRE(c.ok);
    const size_t lde_bytes = c.lde_evals.size() * sizeof(rc::Fp2);
    BOOST_CHECK_LT(c.proof_bytes, lde_bytes / 2);
    BOOST_CHECK_EQUAL(c.proof.queries.size(), rc::kRCFriNumQueries);
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

BOOST_AUTO_TEST_SUITE_END()
