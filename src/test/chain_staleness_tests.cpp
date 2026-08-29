// Copyright (c) 2026 The BTX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chain.h>
#include <node/chain_staleness.h>
#include <uint256.h>

#include <array>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(chain_staleness_tests)

BOOST_AUTO_TEST_CASE(equal_tip_and_header_is_not_stale)
{
    CBlockIndex tip;
    uint256 hash{uint256{uint8_t{1}}};
    tip.phashBlock = &hash;
    tip.nHeight = 10;
    tip.nChainWork = arith_uint256{10};

    const auto stale = node::ComputeChainTipStaleness(&tip, &tip);
    BOOST_CHECK_EQUAL(stale.blocks, 10);
    BOOST_CHECK_EQUAL(stale.headers, 10);
    BOOST_CHECK_EQUAL(stale.behind_best_header, 0);
    BOOST_CHECK(stale.header_extends_tip);
    BOOST_CHECK(!stale.competing_heavier_header);
    BOOST_CHECK(!stale.is_stale);
}

BOOST_AUTO_TEST_CASE(linear_header_gap_at_park_depth_is_not_stale)
{
    std::array<CBlockIndex, 7> chain;
    std::array<uint256, 7> hashes;
    for (int i = 0; i < 7; ++i) {
        hashes[i] = uint256{static_cast<uint8_t>(i + 1)};
        chain[i].phashBlock = &hashes[i];
        chain[i].nHeight = i;
        chain[i].nChainWork = arith_uint256{static_cast<uint64_t>(i + 1)};
        if (i > 0) chain[i].pprev = &chain[i - 1];
    }

    const auto catch_up = node::ComputeChainTipStaleness(&chain[0], &chain[3]);
    BOOST_CHECK_EQUAL(catch_up.behind_best_header, 3);
    BOOST_CHECK(catch_up.header_extends_tip);
    BOOST_CHECK(!catch_up.competing_heavier_header);
    BOOST_CHECK(!catch_up.is_stale);

    const auto at_park = node::ComputeChainTipStaleness(&chain[0], &chain[6]);
    BOOST_CHECK_EQUAL(at_park.behind_best_header, 6);
    BOOST_CHECK(at_park.header_extends_tip);
    BOOST_CHECK(!at_park.is_stale);
}

BOOST_AUTO_TEST_CASE(linear_header_gap_beyond_park_depth_is_stale)
{
    std::array<CBlockIndex, 8> chain;
    std::array<uint256, 8> hashes;
    for (int i = 0; i < 8; ++i) {
        hashes[i] = uint256{static_cast<uint8_t>(i + 1)};
        chain[i].phashBlock = &hashes[i];
        chain[i].nHeight = i;
        chain[i].nChainWork = arith_uint256{static_cast<uint64_t>(i + 1)};
        if (i > 0) chain[i].pprev = &chain[i - 1];
    }

    const auto stale = node::ComputeChainTipStaleness(&chain[0], &chain[7]);
    BOOST_CHECK_EQUAL(stale.behind_best_header, 7);
    BOOST_CHECK(stale.header_extends_tip);
    BOOST_CHECK(!stale.competing_heavier_header);
    BOOST_CHECK(stale.is_stale);
}

BOOST_AUTO_TEST_CASE(competing_heavier_header_is_stale_even_at_same_height)
{
    CBlockIndex tip;
    uint256 tip_hash{uint256{uint8_t{1}}};
    tip.phashBlock = &tip_hash;
    tip.nHeight = 12;
    tip.nChainWork = arith_uint256{100};

    CBlockIndex fork;
    uint256 fork_hash{uint256{uint8_t{2}}};
    fork.phashBlock = &fork_hash;
    fork.nHeight = 12;
    fork.nChainWork = arith_uint256{200};

    const auto stale = node::ComputeChainTipStaleness(&tip, &fork);
    BOOST_CHECK_EQUAL(stale.behind_best_header, 0);
    BOOST_CHECK(!stale.header_extends_tip);
    BOOST_CHECK(stale.competing_heavier_header);
    BOOST_CHECK(stale.is_stale);
}

BOOST_AUTO_TEST_SUITE_END()
