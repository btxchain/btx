// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>

BOOST_FIXTURE_TEST_SUITE(matmul_subsidy_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(subsidy_height_0_is_20)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN)->GetConsensus();
    BOOST_CHECK_EQUAL(GetBlockSubsidy(0, params), 20 * COIN);
}

BOOST_AUTO_TEST_CASE(subsidy_halves_at_525k)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN)->GetConsensus();
    BOOST_CHECK_EQUAL(GetBlockSubsidy(524'999, params), 20 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(525'000, params), 10 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1'049'999, params), 10 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1'050'000, params), 5 * COIN);
}

BOOST_AUTO_TEST_CASE(subsidy_zero_after_64_halvings)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN)->GetConsensus();
    BOOST_CHECK_EQUAL(GetBlockSubsidy(525'000 * 64, params), 0);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(525'000 * 100, params), 0);
}

BOOST_AUTO_TEST_CASE(subsidy_fast_phase_total_is_1m)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN)->GetConsensus();
    CAmount total{0};
    for (int h = 0; h < 50'000; ++h) {
        total += GetBlockSubsidy(h, params);
    }
    BOOST_CHECK_EQUAL(total, 1'000'000 * COIN);
}

BOOST_AUTO_TEST_CASE(max_supply_never_exceeded)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN)->GetConsensus();
    CAmount total{0};
    for (int halving = 0; halving < 64; ++halving) {
        total += (params.nInitialSubsidy >> halving) * params.nSubsidyHalvingInterval;
    }
    BOOST_CHECK(total <= 21'000'000 * COIN);
    BOOST_CHECK(total > 20'999'999 * COIN);
}

BOOST_AUTO_TEST_CASE(empty_block_subsidy_caps_activate_at_130k_strict_at_130500_and_end_at_132k)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN)->GetConsensus();
    BOOST_CHECK_EQUAL(params.nEmptyBlockSubsidyPenaltyHeight, 130'000);
    BOOST_CHECK_EQUAL(params.nEmptyBlockSubsidyStrictPenaltyHeight, 130'500);
    BOOST_CHECK_EQUAL(params.nEmptyBlockSubsidyPenaltyEndHeight, 132'000);
    BOOST_CHECK_EQUAL(params.nEmptyBlockSubsidyMaxHalvings, 2);

    CBlock empty_block;
    empty_block.vtx.resize(1);
    CBlock non_empty_block;
    non_empty_block.vtx.resize(2);

    CBlockIndex non_empty_prev;
    non_empty_prev.nTx = 2;
    BOOST_CHECK_EQUAL(GetBlockSubsidyForBlock(129'999, empty_block, &non_empty_prev, params), 20 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidyForBlock(130'000, non_empty_block, &non_empty_prev, params), 20 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidyForBlock(130'000, empty_block, &non_empty_prev, params), 10 * COIN);

    CBlockIndex first_empty_prev;
    first_empty_prev.nTx = 1;
    first_empty_prev.pprev = &non_empty_prev;
    BOOST_CHECK_EQUAL(GetBlockSubsidyForBlock(130'001, empty_block, &first_empty_prev, params), 5 * COIN);

    CBlockIndex second_empty_prev;
    second_empty_prev.nTx = 1;
    second_empty_prev.pprev = &first_empty_prev;
    BOOST_CHECK_EQUAL(GetBlockSubsidyForBlock(130'002, empty_block, &second_empty_prev, params), 5 * COIN);

    CBlockIndex third_empty_prev;
    third_empty_prev.nTx = 1;
    third_empty_prev.pprev = &second_empty_prev;
    BOOST_CHECK_EQUAL(GetBlockSubsidyForBlock(130'003, empty_block, &third_empty_prev, params), 5 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidyForBlock(130'004, non_empty_block, &third_empty_prev, params), 20 * COIN);

    BOOST_CHECK_EQUAL(GetBlockSubsidyForBlock(130'500, empty_block, &non_empty_prev, params), 10 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidyForBlock(130'501, empty_block, &first_empty_prev, params), 5 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidyForBlock(130'502, empty_block, &second_empty_prev, params), 5 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidyForBlock(130'503, empty_block, &third_empty_prev, params), 5 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidyForBlock(130'504, non_empty_block, &third_empty_prev, params), 20 * COIN);

    BOOST_CHECK_EQUAL(GetBlockSubsidyForBlock(131'999, empty_block, &third_empty_prev, params), 5 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidyForBlock(132'000, empty_block, &third_empty_prev, params), 20 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidyForBlock(132'000, empty_block, &non_empty_prev, params), 20 * COIN);
}

BOOST_AUTO_TEST_CASE(money_range_enforces_cap)
{
    BOOST_CHECK(MoneyRange(21'000'000 * COIN));
    BOOST_CHECK(!MoneyRange(21'000'001 * COIN));
    BOOST_CHECK(!MoneyRange(-1));
    BOOST_CHECK(MoneyRange(0));
}

BOOST_AUTO_TEST_SUITE_END()
