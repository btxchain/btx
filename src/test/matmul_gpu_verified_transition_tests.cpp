// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chainparams.h>
#include <common/args.h>
#include <consensus/params.h>
#include <node/matmul_trusted_attestations.h>
#include <pow.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(matmul_gpu_verified_transition_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(mainnet_dump_floor_is_191714)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& c = params->GetConsensus();

    BOOST_CHECK_EQUAL(c.nMatMulPowLimitUpgradeHeight, 191714);
    BOOST_CHECK_EQUAL(c.nMatMulAsertHalfLifeUpgradeHeight, 191715);
    BOOST_CHECK_EQUAL(UintToArith256(c.powLimitUpgrade).GetCompact(), 0x1f0a3d70U);
    BOOST_CHECK(MatMulAsertPowLimitForNextHeight(c, 191713) == UintToArith256(c.powLimit));
    BOOST_CHECK(MatMulAsertPowLimitForNextHeight(c, 191714) == UintToArith256(c.powLimitUpgrade));
}

BOOST_AUTO_TEST_CASE(may_serve_getheaders_quorum_or_work_or_download)
{
    using node::matmul_trusted::MayServeGetHeaders;

    BOOST_CHECK(MayServeGetHeaders(
        /*download_permission=*/true, /*tip_has_quorum=*/false,
        /*chain_work_meets_minimum=*/false));
    BOOST_CHECK(MayServeGetHeaders(
        /*download_permission=*/false, /*tip_has_quorum=*/true,
        /*chain_work_meets_minimum=*/false));
    BOOST_CHECK(MayServeGetHeaders(
        /*download_permission=*/false, /*tip_has_quorum=*/false,
        /*chain_work_meets_minimum=*/true));
    BOOST_CHECK(!MayServeGetHeaders(
        /*download_permission=*/false, /*tip_has_quorum=*/false,
        /*chain_work_meets_minimum=*/false));
}

BOOST_AUTO_TEST_CASE(authority_headers_keep_polling_gpu_after_version)
{
    using node::matmul_trusted::TrustedMirrorShouldRequestAuthorityHeaders;

    BOOST_CHECK(!TrustedMirrorShouldRequestAuthorityHeaders(false, 191713, 191713));
    BOOST_CHECK(TrustedMirrorShouldRequestAuthorityHeaders(true, 191713, 191713));
    BOOST_CHECK(TrustedMirrorShouldRequestAuthorityHeaders(false, 191690, 191713));
}

BOOST_AUTO_TEST_CASE(attestor_and_mirror_ignore_inbound_miners)
{
    using node::matmul_trusted::TrustedMirrorIgnoreNonAuthorityInboundBlock;
    using node::matmul_trusted::TrustedMirrorMayAcceptPeerBlockBody;

    BOOST_CHECK(TrustedMirrorIgnoreNonAuthorityInboundBlock(true, false, true, true));
    BOOST_CHECK(!TrustedMirrorIgnoreNonAuthorityInboundBlock(true, true, true, true));
    BOOST_CHECK(!TrustedMirrorIgnoreNonAuthorityInboundBlock(true, false, true, false));
    BOOST_CHECK(!TrustedMirrorIgnoreNonAuthorityInboundBlock(false, false, true, true));
    // GPU attestors pass trusted_mirror=true into the ignore helper. Miner
    // INV/BLOCK is dropped unless MayAccept (GPU or our outbound archive).
    const bool ignore_miner{
        TrustedMirrorIgnoreNonAuthorityInboundBlock(true, false, true, true)};
    BOOST_CHECK(ignore_miner);
    BOOST_CHECK(!TrustedMirrorMayAcceptPeerBlockBody(
        /*this_gpu=*/false, /*this_inbound=*/true, /*this_archive_or_mirror=*/false));
}

BOOST_AUTO_TEST_SUITE_END()
