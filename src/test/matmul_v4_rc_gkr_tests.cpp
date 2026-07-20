// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/params.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_fri.h>
#include <matmul/matmul_v4_rc_gkr.h>
#include <matmul/matmul_v4_rc_gkr_field_ext.h>
#include <matmul/matmul_v4_rc_verify_bakeoff.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <limits>
#include <string>

namespace rc = matmul::v4::rc;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_gkr_tests, BasicTestingSetup)

namespace {

CBlockHeader MakeRCHeader(uint64_t nonce)
{
    CBlockHeader header;
    header.nVersion = 0x20000004;
    header.nTime = 1'770'000'000;
    header.nBits = 0x207fffff;
    header.nNonce64 = nonce;
    header.nNonce = static_cast<uint32_t>(nonce);
    for (int i = 0; i < 32; ++i) {
        header.hashPrevBlock.data()[i] = static_cast<unsigned char>(0x51);
        header.hashMerkleRoot.data()[i] = static_cast<unsigned char>(0xa3);
        header.seed_a.data()[i] = static_cast<unsigned char>(0x11);
        header.seed_b.data()[i] = static_cast<unsigned char>(0x22);
    }
    return header;
}

uint256 MakeSeed(uint8_t fill)
{
    uint256 seed;
    for (int i = 0; i < 32; ++i) seed.data()[i] = fill;
    return seed;
}

} // namespace

BOOST_AUTO_TEST_CASE(gkr_soundness_and_height_inert)
{
    BOOST_CHECK(std::string(rc::kRCGkrSoundnessStatement).find("COMPUTATIONAL") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCGkrRealityGuardrail).find("REJECT") != std::string::npos);
    BOOST_CHECK(std::string(rc::kRCGkrRealityGuardrail).find("NOT production-complete") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCGkrHbmParkStatement).find("NOT production-complete") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCGkrE5Decision).find("winner-only") != std::string::npos);
    BOOST_CHECK(std::string(rc::kRCGkrShadowStatement).find("SHADOW") != std::string::npos);
    BOOST_CHECK_EQUAL(Consensus::Params{}.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
}

BOOST_AUTO_TEST_CASE(gkr_fp2_smoke)
{
    const gf::Fp2 a = gf::Fp2::FromFp(3);
    const gf::Fp2 b{5, 7};
    const gf::Fp2 c = gf::Mul(a, b);
    BOOST_CHECK(gf::Eq(c, gf::Fp2{15, 21}));
    const gf::Fp2 inv = gf::Inv(b);
    BOOST_CHECK(gf::Eq(gf::Mul(b, inv), gf::Fp2::One()));
    // x^2 = 7 in the extension
    const gf::Fp2 x{0, 1};
    BOOST_CHECK(gf::Eq(gf::Mul(x, x), gf::Fp2::FromFp(gf::kFp2W)));
}

BOOST_AUTO_TEST_CASE(gkr_fri_smoke)
{
    std::vector<rc::Fp2> evals;
    for (int i = 0; i < 8; ++i) evals.push_back(gf::FromSigned2(i * 3 + 1));
    const uint256 seed = MakeSeed(0x42);
    const auto c = rc::FriCommitAndFold(evals, seed, /*n_openings=*/2);
    BOOST_REQUIRE(c.ok);
    BOOST_CHECK(!c.proof.layers.empty());
    BOOST_CHECK(c.proof_bytes > 0);
    BOOST_CHECK(c.proof_bytes < evals.size() * 64); // succinct vs raw witness
    std::string why;
    BOOST_CHECK(rc::FriVerify(c.proof, seed, &why));

    auto bad = c.proof;
    bad.openings[0].leaf.c0 ^= 1;
    BOOST_CHECK(!rc::FriVerify(bad, seed, &why));
}

BOOST_AUTO_TEST_CASE(gkr_honest_real_episode_toy_verifies)
{
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    const auto pr = rc::ProveWinnerEpisode(header, params, 0, dig);
    BOOST_CHECK(pr.timing.ok);
    BOOST_CHECK(!pr.proof.layers.empty());
    BOOST_CHECK(!pr.proof.trace_fri.layers.empty());
    BOOST_CHECK(!pr.proof.lookup_fri.layers.empty());
    // Succinct: FRI openings are O(log n), not every Extract tile.
    BOOST_CHECK(pr.proof.lookup_fri.openings.size() <= 8);
    rc::RCGkrTiming vt;
    BOOST_CHECK(rc::VerifyWinnerProof(pr.proof, &vt));
    BOOST_CHECK(vt.ok);
    BOOST_CHECK(pr.timing.proof_bytes > 0);
}

BOOST_AUTO_TEST_CASE(gkr_malformed_proof_rejects)
{
    BOOST_CHECK(!rc::DeserializeRCGkrProof({}).has_value());
    BOOST_CHECK(!rc::DeserializeRCGkrProof(std::vector<unsigned char>(7, 0x00)).has_value());
    std::vector<unsigned char> junk(64, 0xff);
    BOOST_CHECK(!rc::DeserializeRCGkrProof(junk).has_value());

    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    const auto pr = rc::ProveWinnerEpisode(header, params, 0, dig);
    std::vector<unsigned char> bytes;
    BOOST_REQUIRE(rc::SerializeRCGkrProof(pr.proof, bytes) > 0);
    const auto back = rc::DeserializeRCGkrProof(bytes);
    BOOST_REQUIRE(back.has_value());
    BOOST_CHECK(rc::VerifyWinnerProof(*back));

    bytes[bytes.size() / 2] ^= 0x5a;
    const auto broken = rc::DeserializeRCGkrProof(bytes);
    if (broken.has_value()) {
        BOOST_CHECK(!rc::VerifyWinnerProof(*broken));
    } else {
        BOOST_CHECK(!broken.has_value());
    }
}

BOOST_AUTO_TEST_CASE(gkr_wrong_witness_rejects)
{
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    auto pr = rc::ProveWinnerEpisode(header, params, 0, dig);
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    pr.proof.layers[0].sumcheck[0].eval0.c0 ^= 1;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_wrong_digest_rejects)
{
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    auto pr = rc::ProveWinnerEpisode(header, params, 0, dig);
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    pr.proof.claimed_digest.data()[0] ^= 0xff;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_pow_bind_mismatch_rejects)
{
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    auto pr = rc::ProveWinnerEpisode(header, params, 0, dig);
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    pr.proof.pow_bind.data()[0] ^= 0xff;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_shadow_never_blocks_consensus)
{
    // Unit-level: ExactReplay ok + shadow observe with bad proof must not flip
    // the consensus result helper (VerifyRCWinnerOrExactReplay with arbiter OFF).
    unsetenv("BTX_RC_GKR_ARBITER");
    unsetenv("BTX_RC_VERIFY_GKR");
    setenv("BTX_RC_GKR_SHADOW", "1", 1);

    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    CBlockHeader h2 = header;
    h2.matmul_digest = dig;

    std::vector<unsigned char> junk(32, 0xab);
    rc::RCGkrProofCachePut(h2.GetHash(), junk);
    rc::RCGkrShadowObserve(h2, params, 0, nullptr, &junk);

    const auto dual = rc::VerifyRCWinnerOrExactReplay(h2, params, 0, nullptr, &junk);
    BOOST_CHECK(dual.ok); // ExactReplay decides; malformed GKR does not reject
    BOOST_CHECK(dual.path == rc::RCProdVerifyPath::ExactReplay ||
                dual.path == rc::RCProdVerifyPath::GkrFallbackExactReplay);

    unsetenv("BTX_RC_GKR_SHADOW");
    rc::RCGkrProofCacheClear();
}

BOOST_AUTO_TEST_CASE(gkr_deprecated_synth_still_succinct)
{
    const uint256 seed = MakeSeed(0x5a);
    rc::DistSynthShape shape{32, 32, 128, 32};
    const auto ep = rc::RunSyntheticDistributed(seed, shape, 1, rc::DistReduceOrder::TreeLeftToRight);
    const auto pr = rc::ProveWinnerSynth(seed, shape, ep.digest);
    BOOST_CHECK(pr.timing.ok);
    BOOST_CHECK(!pr.proof.trace_fri.layers.empty());
    BOOST_CHECK(pr.proof.lookup_fri.openings.size() <= 8);
    BOOST_CHECK(rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_bakeoff_b_educational_still_present)
{
    const uint256 seed = MakeSeed(0x5a);
    const auto b = rc::BakeoffB_ToyGkrSumcheck(seed, {32, 32, 128, 32});
    BOOST_CHECK(b.prove.ok);
    BOOST_CHECK(b.verify.ok);
}

BOOST_AUTO_TEST_SUITE_END()
