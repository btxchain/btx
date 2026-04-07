// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <common/args.h>
#include <consensus/amount.h>
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

BOOST_AUTO_TEST_CASE(money_range_enforces_cap)
{
    BOOST_CHECK(MoneyRange(21'000'000 * COIN));
    BOOST_CHECK(!MoneyRange(21'000'001 * COIN));
    BOOST_CHECK(!MoneyRange(-1));
    BOOST_CHECK(MoneyRange(0));
}

BOOST_AUTO_TEST_SUITE_END()
