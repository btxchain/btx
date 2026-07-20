// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/params.h>
#include <matmul/matmul_v4_rc_distributed.h>
#include <matmul/matmul_v4_rc_gkr.h>
#include <matmul/matmul_v4_rc_verify_bakeoff.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <limits>
#include <string>

namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_gkr_tests, BasicTestingSetup)

namespace {

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
    BOOST_CHECK_EQUAL(Consensus::Params{}.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
}

BOOST_AUTO_TEST_CASE(gkr_honest_proof_verifies_toy)
{
    const uint256 seed = MakeSeed(0x5a);
    rc::DistSynthShape shape{32, 32, 128, 32};
    const auto ep = rc::RunSyntheticDistributed(seed, shape, 1, rc::DistReduceOrder::TreeLeftToRight);
    const auto pr = rc::ProveWinnerSynth(seed, shape, ep.digest);
    BOOST_CHECK(pr.timing.ok);
    BOOST_CHECK(!pr.proof.sumcheck.empty());
    BOOST_CHECK(!pr.proof.gemm_sumcheck.empty());
    BOOST_CHECK(!pr.proof.lookups.empty());
    rc::RCGkrTiming vt;
    BOOST_CHECK(rc::VerifyWinnerProofPublic(pr.proof, seed, shape, &vt));
    BOOST_CHECK(vt.ok);
}

BOOST_AUTO_TEST_CASE(gkr_tampered_sumcheck_fails)
{
    const uint256 seed = MakeSeed(0x5a);
    rc::DistSynthShape shape{32, 32, 128, 32};
    const auto ep = rc::RunSyntheticDistributed(seed, shape, 1, rc::DistReduceOrder::TreeLeftToRight);
    auto pr = rc::ProveWinnerSynth(seed, shape, ep.digest);
    BOOST_REQUIRE(rc::VerifyWinnerProofPublic(pr.proof, seed, shape));
    pr.proof.gemm_sumcheck[0].eval0 ^= 1;
    BOOST_CHECK(!rc::VerifyWinnerProofPublic(pr.proof, seed, shape));
}

BOOST_AUTO_TEST_CASE(gkr_tampered_extract_opening_fails)
{
    const uint256 seed = MakeSeed(0x5a);
    rc::DistSynthShape shape{32, 32, 128, 32};
    const auto ep = rc::RunSyntheticDistributed(seed, shape, 1, rc::DistReduceOrder::TreeLeftToRight);
    auto pr = rc::ProveWinnerSynth(seed, shape, ep.digest);
    BOOST_REQUIRE(rc::VerifyWinnerProofPublic(pr.proof, seed, shape));
    pr.proof.lookups[0].out8[0] = static_cast<int8_t>(pr.proof.lookups[0].out8[0] + 1);
    pr.proof.claimed_extract[0] = pr.proof.lookups[0].out8[0];
    BOOST_CHECK(!rc::VerifyWinnerProofPublic(pr.proof, seed, shape));
}

BOOST_AUTO_TEST_CASE(gkr_wrong_digest_fails)
{
    const uint256 seed = MakeSeed(0x5a);
    rc::DistSynthShape shape{32, 32, 128, 32};
    const auto ep = rc::RunSyntheticDistributed(seed, shape, 1, rc::DistReduceOrder::TreeLeftToRight);
    auto pr = rc::ProveWinnerSynth(seed, shape, ep.digest);
    BOOST_REQUIRE(rc::VerifyWinnerProofPublic(pr.proof, seed, shape));
    pr.proof.claimed_digest.data()[0] ^= 0xff;
    BOOST_CHECK(!rc::VerifyWinnerProofPublic(pr.proof, seed, shape));
}

BOOST_AUTO_TEST_CASE(gkr_toy_and_medium_timings)
{
    const uint256 seed = MakeSeed(0xa1);

    rc::DistSynthShape toy{32, 32, 128, 32};
    const auto ep_toy =
        rc::RunSyntheticDistributed(seed, toy, 1, rc::DistReduceOrder::TreeLeftToRight);
    const auto pr_toy = rc::ProveWinnerSynth(seed, toy, ep_toy.digest);
    rc::RCGkrTiming vt_toy;
    BOOST_CHECK(rc::VerifyWinnerProofPublic(pr_toy.proof, seed, toy, &vt_toy));
    BOOST_TEST_MESSAGE("GKR toy: prove_s=" << pr_toy.timing.prove_s
                                           << " verify_s=" << vt_toy.verify_s
                                           << " proof_bytes=" << pr_toy.timing.proof_bytes);

    rc::DistSynthShape medium{64, 64, 256, 64};
    const auto ep_med =
        rc::RunSyntheticDistributed(seed, medium, 1, rc::DistReduceOrder::TreeLeftToRight);
    const auto pr_med = rc::ProveWinnerSynth(seed, medium, ep_med.digest);
    rc::RCGkrTiming vt_med;
    BOOST_CHECK(rc::VerifyWinnerProofPublic(pr_med.proof, seed, medium, &vt_med));
    BOOST_TEST_MESSAGE("GKR medium: prove_s=" << pr_med.timing.prove_s
                                              << " verify_s=" << vt_med.verify_s
                                              << " proof_bytes=" << pr_med.timing.proof_bytes);

    BOOST_CHECK(pr_toy.timing.proof_bytes > 0);
    BOOST_CHECK(pr_med.timing.proof_bytes > pr_toy.timing.proof_bytes);
}

BOOST_AUTO_TEST_CASE(gkr_malformed_deserialize_fails)
{
    // Empty / truncated / bad-magic payloads must not deserialize.
    BOOST_CHECK(!rc::DeserializeRCGkrProof({}).has_value());
    BOOST_CHECK(!rc::DeserializeRCGkrProof(std::vector<unsigned char>(7, 0x00)).has_value());
    std::vector<unsigned char> junk(64, 0xff);
    BOOST_CHECK(!rc::DeserializeRCGkrProof(junk).has_value());

    // Honest proof round-trips; flipping a mid-byte breaks deserialize or verify.
    const uint256 seed = MakeSeed(0x5a);
    rc::DistSynthShape shape{32, 32, 128, 32};
    const auto ep = rc::RunSyntheticDistributed(seed, shape, 1, rc::DistReduceOrder::TreeLeftToRight);
    const auto pr = rc::ProveWinnerSynth(seed, shape, ep.digest);
    std::vector<unsigned char> bytes;
    BOOST_REQUIRE(rc::SerializeRCGkrProof(pr.proof, bytes) > 0);
    const auto back = rc::DeserializeRCGkrProof(bytes);
    BOOST_REQUIRE(back.has_value());
    BOOST_CHECK(rc::VerifyWinnerProofPublic(*back, seed, shape));

    bytes[bytes.size() / 2] ^= 0x5a;
    const auto broken = rc::DeserializeRCGkrProof(bytes);
    if (broken.has_value()) {
        BOOST_CHECK(!rc::VerifyWinnerProofPublic(*broken, seed, shape));
    } else {
        BOOST_CHECK(!broken.has_value());
    }
}

BOOST_AUTO_TEST_CASE(gkr_bakeoff_b_educational_still_present)
{
    const uint256 seed = MakeSeed(0x5a);
    const auto b = rc::BakeoffB_ToyGkrSumcheck(seed, {32, 32, 128, 32});
    BOOST_CHECK(b.prove.ok);
    BOOST_CHECK(b.verify.ok);
}

BOOST_AUTO_TEST_SUITE_END()
