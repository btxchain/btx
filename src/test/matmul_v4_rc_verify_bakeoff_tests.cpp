// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_verify_bakeoff.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_verify_bakeoff_tests, BasicTestingSetup)

namespace {

CBlockHeader MakeHeader(uint64_t nonce)
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

} // namespace

BOOST_AUTO_TEST_CASE(bakeoff_e1_e2_statements_present)
{
    BOOST_CHECK(std::string(rc::kBakeoffE1Statement).find("ε=0") != std::string::npos ||
                std::string(rc::kBakeoffE1Statement).find("eps") != std::string::npos ||
                std::string(rc::kBakeoffE1Statement).find("STREAMED") != std::string::npos);
    BOOST_CHECK(std::string(rc::kBakeoffE2Statement).find("PREFILTER") != std::string::npos);
    BOOST_CHECK(std::string(rc::kBakeoffE2Statement).find("O(1)") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(bakeoff_a_exact_replay_ok)
{
    const auto a = rc::BakeoffA_ExactReplay(MakeHeader(42), rc::MakeToyRCEpisodeParams(), 0);
    BOOST_CHECK(a.timing.ok);
    BOOST_CHECK(!a.digest.IsNull());
    BOOST_CHECK_EQUAL(a.timing.proof_bytes, 0u);
}

BOOST_AUTO_TEST_CASE(bakeoff_b_toy_gkr_verify)
{
    uint256 seed;
    for (int i = 0; i < 32; ++i) seed.data()[i] = 0x5a;
    rc::DistSynthShape shape{32, 32, 128, 32};
    const auto b = rc::BakeoffB_ToyGkrSumcheck(seed, shape);
    BOOST_CHECK(b.prove.ok);
    BOOST_CHECK(b.verify.ok);
    BOOST_CHECK(b.proof.extract_in_table);
    BOOST_CHECK(b.prove.proof_bytes > 0);
}

BOOST_AUTO_TEST_CASE(bakeoff_c_stark_stub_not_implemented)
{
    const auto c = rc::BakeoffC_StarkStub();
    BOOST_CHECK(!c.implemented);
    BOOST_CHECK(!c.reason.empty());
}

BOOST_AUTO_TEST_CASE(bakeoff_d_fraud_sketch_detects_fault)
{
    uint256 seed;
    for (int i = 0; i < 32; ++i) seed.data()[i] = 0x5a;
    rc::DistSynthShape shape{32, 32, 128, 32};
    const auto ok = rc::BakeoffD_FraudProofSketch(seed, shape, 2, false);
    const auto bad = rc::BakeoffD_FraudProofSketch(seed, shape, 2, true);
    BOOST_CHECK(ok.timing.ok);
    BOOST_CHECK(!ok.sketch.mismatch);
    BOOST_CHECK(bad.sketch.mismatch);
    BOOST_CHECK(bad.timing.ok);
    BOOST_CHECK(ok.sketch.fork_requirements.find("fork") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
