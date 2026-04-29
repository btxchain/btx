// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <chainparamsbase.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <pow.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>
#include <cstdint>

namespace {

bool IsPrime(uint32_t n)
{
    if (n < 2) return false;
    if ((n & 1U) == 0) return n == 2;
    for (uint32_t d = 3; static_cast<uint64_t>(d) * d <= n; d += 2) {
        if (n % d == 0) return false;
    }
    return true;
}

ArgsManager EmptyArgs()
{
    return ArgsManager{};
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(matmul_params_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(matmul_params_defaults_mainnet)
{
    auto params = CreateChainParams(EmptyArgs(), ChainType::MAIN);
    const auto& c = params->GetConsensus();

    BOOST_CHECK(c.fMatMulPOW);
    BOOST_CHECK_EQUAL(c.nMatMulDimension, 512U);
    BOOST_CHECK_EQUAL(c.nMatMulTranscriptBlockSize, 16U);
    BOOST_CHECK_EQUAL(c.nMatMulNoiseRank, 8U);
    BOOST_CHECK_EQUAL(c.nMatMulFieldModulus, 0x7FFFFFFFU);
    BOOST_CHECK_EQUAL(c.nMatMulValidationWindow, 1000U);
}

BOOST_AUTO_TEST_CASE(matmul_product_payload_requirement_matches_live_network_policy)
{
    const auto main_params = CreateChainParams(EmptyArgs(), ChainType::MAIN);
    const auto& main_consensus = main_params->GetConsensus();
    BOOST_CHECK(!main_consensus.fMatMulRequireProductPayload);
    BOOST_CHECK(!main_consensus.IsMatMulProductPayloadRequired(60'999));
    BOOST_CHECK(main_consensus.IsMatMulProductPayloadRequired(61'000));

    const auto regtest_params = CreateChainParams(EmptyArgs(), ChainType::REGTEST);
    const auto& regtest_consensus = regtest_params->GetConsensus();
    BOOST_CHECK(regtest_consensus.fMatMulRequireProductPayload);
    BOOST_CHECK(regtest_consensus.IsMatMulProductPayloadRequired(0));
    BOOST_CHECK(regtest_consensus.IsMatMulProductPayloadRequired(1));
}

BOOST_AUTO_TEST_CASE(matmul_freivalds_binding_upgrade_schedule_matches_network_policy)
{
    const auto main_params = CreateChainParams(EmptyArgs(), ChainType::MAIN);
    const auto& main_consensus = main_params->GetConsensus();
    BOOST_CHECK(!main_consensus.IsMatMulFreivaldsBindingActive(60'999));
    BOOST_CHECK(main_consensus.IsMatMulFreivaldsBindingActive(61'000));

    const auto regtest_params = CreateChainParams(EmptyArgs(), ChainType::REGTEST);
    const auto& regtest_consensus = regtest_params->GetConsensus();
    BOOST_CHECK(regtest_consensus.IsMatMulFreivaldsBindingActive(0));
    BOOST_CHECK(regtest_consensus.IsMatMulFreivaldsBindingActive(1));
}

BOOST_AUTO_TEST_CASE(matmul_mainnet_prehash_fairness_upgrade_matches_asert_upgrade_window)
{
    const auto main_params = CreateChainParams(EmptyArgs(), ChainType::MAIN);
    const auto& main_consensus = main_params->GetConsensus();

    BOOST_CHECK_EQUAL(main_consensus.nMatMulAsertHalfLifeUpgradeHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(main_consensus.nMatMulPreHashEpsilonBitsUpgradeHeight, 50'000);
    BOOST_CHECK_EQUAL(GetMatMulPreHashEpsilonBitsForHeight(main_consensus, 49'999), 10U);
    BOOST_CHECK_EQUAL(GetMatMulPreHashEpsilonBitsForHeight(main_consensus, 50'000), 18U);
}

BOOST_AUTO_TEST_CASE(matmul_freivalds_payload_mining_policy_matches_network_policy)
{
    const auto main_params = CreateChainParams(EmptyArgs(), ChainType::MAIN);
    const auto& main_consensus = main_params->GetConsensus();
    BOOST_CHECK(!ShouldIncludeMatMulFreivaldsPayloadForMining(60'999, main_consensus));
    BOOST_CHECK(ShouldIncludeMatMulFreivaldsPayloadForMining(61'000, main_consensus));

    const auto regtest_params = CreateChainParams(EmptyArgs(), ChainType::REGTEST);
    const auto& regtest_consensus = regtest_params->GetConsensus();
    BOOST_CHECK(ShouldIncludeMatMulFreivaldsPayloadForMining(0, regtest_consensus));
    BOOST_CHECK(ShouldIncludeMatMulFreivaldsPayloadForMining(1, regtest_consensus));

    auto disabled = main_consensus;
    disabled.fMatMulFreivaldsEnabled = false;
    BOOST_CHECK(!ShouldIncludeMatMulFreivaldsPayloadForMining(61'000, disabled));
}

BOOST_AUTO_TEST_CASE(matmul_params_regtest)
{
    auto params = CreateChainParams(EmptyArgs(), ChainType::REGTEST);
    const auto& c = params->GetConsensus();

    BOOST_CHECK(c.fMatMulPOW);
    BOOST_CHECK_EQUAL(c.nMatMulDimension, 64U);
    BOOST_CHECK_EQUAL(c.nMatMulTranscriptBlockSize, 8U);
    BOOST_CHECK_EQUAL(c.nMatMulNoiseRank, 4U);
}

BOOST_AUTO_TEST_CASE(matmul_params_shieldedv2dev)
{
    const auto base_params = CreateBaseChainParams(ChainType::SHIELDEDV2DEV);
    BOOST_CHECK_EQUAL(base_params->DataDir(), "shieldedv2dev");
    BOOST_CHECK_EQUAL(base_params->RPCPort(), 19443);

    const auto params = CreateChainParams(EmptyArgs(), ChainType::SHIELDEDV2DEV);
    const auto& c = params->GetConsensus();

    BOOST_CHECK(params->IsTestChain());
    BOOST_CHECK(c.fMatMulPOW);
    BOOST_CHECK(c.fPowAllowMinDifficultyBlocks);
    BOOST_CHECK(c.fPowNoRetargeting);
    BOOST_CHECK(c.fSkipMatMulValidation);
    BOOST_CHECK_EQUAL(c.nMatMulDimension, 64U);
    BOOST_CHECK_EQUAL(c.nFastMineHeight, 0);
    BOOST_CHECK_EQUAL(c.nShieldedSpendPathRecoveryActivationHeight, 88'000);
    BOOST_CHECK_EQUAL(params->GetDefaultPort(), 19444);
    BOOST_CHECK_EQUAL(params->Bech32HRP(), "btxv2");
    BOOST_CHECK_EQUAL(params->GenesisBlock().GetHash().GetHex(), "4ed72f2a7db044ff555197cddde63b1f50b74d750674316f75c3571ade9c80a3");
    BOOST_CHECK_EQUAL(GetNetworkForMagic(params->MessageStart()).value(), ChainType::SHIELDEDV2DEV);
}

BOOST_AUTO_TEST_CASE(matmul_params_invariants)
{
    for (const auto chain_type : {ChainType::MAIN, ChainType::TESTNET, ChainType::REGTEST, ChainType::SHIELDEDV2DEV}) {
        auto params = CreateChainParams(EmptyArgs(), chain_type);
        const auto& c = params->GetConsensus();

        BOOST_CHECK_EQUAL(c.nMatMulDimension % c.nMatMulTranscriptBlockSize, 0U);
        BOOST_CHECK(c.nMatMulNoiseRank <= c.nMatMulTranscriptBlockSize);
        BOOST_CHECK(c.nMatMulMinDimension <= c.nMatMulDimension);
        BOOST_CHECK(c.nMatMulDimension <= c.nMatMulMaxDimension);
        BOOST_CHECK(IsPrime(c.nMatMulFieldModulus));
        BOOST_CHECK(c.nMatMulFieldModulus > c.nMatMulDimension);
    }
}

BOOST_AUTO_TEST_CASE(matmul_params_b_and_r_independent)
{
    auto params = CreateChainParams(EmptyArgs(), ChainType::MAIN);
    const auto& c = params->GetConsensus();

    const uint64_t n = c.nMatMulDimension;
    const uint64_t b = c.nMatMulTranscriptBlockSize;
    const uint64_t r = c.nMatMulNoiseRank;
    const uint64_t blocks = n / b;

    BOOST_CHECK_NE(b, r);
    BOOST_CHECK_EQUAL(blocks * blocks * blocks, 32768U);
    BOOST_CHECK_EQUAL(n * n * r, 2097152U);
}

BOOST_AUTO_TEST_CASE(monetary_params_defaults)
{
    auto params = CreateChainParams(EmptyArgs(), ChainType::MAIN);
    const auto& c = params->GetConsensus();

    BOOST_CHECK_EQUAL(c.nInitialSubsidy, 20 * COIN);
    BOOST_CHECK_EQUAL(c.nSubsidyHalvingInterval, 525000);
    BOOST_CHECK_EQUAL(c.nMaxMoney, 21'000'000 * COIN);
}

BOOST_AUTO_TEST_CASE(monetary_params_cap_identity)
{
    auto params = CreateChainParams(EmptyArgs(), ChainType::MAIN);
    const auto& c = params->GetConsensus();

    const int64_t lhs = (c.nInitialSubsidy / COIN) * c.nSubsidyHalvingInterval * 2;
    const int64_t rhs = c.nMaxMoney / COIN;
    BOOST_CHECK_EQUAL(lhs, rhs);
}

BOOST_AUTO_TEST_CASE(target_spacing_fast_phase)
{
    auto params = CreateChainParams(EmptyArgs(), ChainType::MAIN);
    const auto& c = params->GetConsensus();

    BOOST_CHECK_EQUAL(c.nPowTargetSpacingFastMs, 250);
    BOOST_CHECK_EQUAL(c.nFastMineHeight, 50'000);
    BOOST_CHECK_CLOSE(c.GetTargetSpacing(0), 0.25, 1e-12);
    BOOST_CHECK_CLOSE(c.GetTargetSpacing(1), 0.25, 1e-12);
    BOOST_CHECK_CLOSE(c.GetTargetSpacing(49'999), 0.25, 1e-12);
}

BOOST_AUTO_TEST_CASE(target_spacing_normal_phase)
{
    auto params = CreateChainParams(EmptyArgs(), ChainType::MAIN);
    const auto& c = params->GetConsensus();

    BOOST_CHECK_CLOSE(c.GetTargetSpacing(50'000), 90.0, 1e-12);
    BOOST_CHECK_CLOSE(c.GetTargetSpacing(1'000'000), 90.0, 1e-12);
}

BOOST_AUTO_TEST_CASE(target_spacing_regtest_no_fast_phase)
{
    auto params = CreateChainParams(EmptyArgs(), ChainType::REGTEST);
    const auto& c = params->GetConsensus();

    BOOST_CHECK_EQUAL(c.nFastMineHeight, 0);
    BOOST_CHECK_CLOSE(c.GetTargetSpacing(0), 90.0, 1e-12);
    BOOST_CHECK_CLOSE(c.GetTargetSpacing(1), 90.0, 1e-12);
}

BOOST_AUTO_TEST_CASE(block_capacity_params_defaults)
{
    auto main_params = CreateChainParams(EmptyArgs(), ChainType::MAIN);
    const auto& main_c = main_params->GetConsensus();

    BOOST_CHECK_EQUAL(main_c.nMaxBlockWeight, 24'000'000U);
    BOOST_CHECK_EQUAL(main_c.nDefaultBlockMaxWeight, 24'000'000U);
    BOOST_CHECK_EQUAL(main_c.nMaxBlockSerializedSize, 24'000'000U);
    BOOST_CHECK_EQUAL(main_c.nMaxBlockSigOpsCost, 480'000U);
    BOOST_CHECK(main_c.nMaxBlockWeight >= main_c.nDefaultBlockMaxWeight);

    auto regtest_params = CreateChainParams(EmptyArgs(), ChainType::REGTEST);
    const auto& regtest_c = regtest_params->GetConsensus();
    BOOST_CHECK_EQUAL(regtest_c.nDefaultBlockMaxWeight, 24'000'000U);
}

BOOST_AUTO_TEST_SUITE_END()
