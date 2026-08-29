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
    // V6/RB-13: a REAL competing heavier fork carries authenticated work (or
    // we hold its body). Here it is authenticated beyond the tip -> stale.
    fork.nAuthenticatedChainWork = arith_uint256{200};

    const auto stale = node::ComputeChainTipStaleness(&tip, &fork);
    BOOST_CHECK_EQUAL(stale.behind_best_header, 0);
    BOOST_CHECK(!stale.header_extends_tip);
    BOOST_CHECK(stale.competing_heavier_header);
    BOOST_CHECK(stale.is_stale);
}

BOOST_AUTO_TEST_CASE(forged_competing_header_only_tower_is_not_stale)
{
    // V6/RB-13 regression: a cheaply-forged, header-only competing tower
    // (heavier CLAIMED work, but no authenticated work and no body) must NOT
    // flip is_stale -- otherwise an attacker freezes a current merchant's
    // settlement for free on public nets (spam gate off, header PoW is a
    // self-declared digest<=target check).
    CBlockIndex tip;
    uint256 tip_hash{uint256{uint8_t{1}}};
    tip.phashBlock = &tip_hash;
    tip.nHeight = 12;
    tip.nChainWork = arith_uint256{100};
    tip.nAuthenticatedChainWork = arith_uint256{100};

    CBlockIndex forged;
    uint256 forged_hash{uint256{uint8_t{2}}};
    forged.phashBlock = &forged_hash;
    forged.nHeight = 12;
    forged.nChainWork = arith_uint256{200};      // heavier CLAIMED work
    forged.nAuthenticatedChainWork = arith_uint256{0}; // but unauthenticated
    forged.nStatus = 0;                           // and no body (no HAVE_DATA)

    const auto stale = node::ComputeChainTipStaleness(&tip, &forged);
    BOOST_CHECK(!stale.header_extends_tip);
    BOOST_CHECK(!stale.competing_heavier_header);
    BOOST_CHECK(!stale.is_stale);

    // The SAME forged tower once we actually hold its body (a reorg we are
    // genuinely evaluating) IS reported stale.
    forged.nStatus = BLOCK_HAVE_DATA;
    const auto with_body = node::ComputeChainTipStaleness(&tip, &forged);
    BOOST_CHECK(with_body.competing_heavier_header);
    BOOST_CHECK(with_body.is_stale);
}

BOOST_AUTO_TEST_CASE(honest_far_behind_extending_catchup_stays_stale)
{
    // V6/RB-13: the EXTENDING far-behind path must keep reporting stale even
    // with an unauthenticated header lead, so an honest node catching up does
    // not credit deposits while behind (safe over-report; the double-spend-
    // blinding barrier must not be suppressed).
    std::array<CBlockIndex, 8> chain;
    std::array<uint256, 8> hashes;
    for (int i = 0; i < 8; ++i) {
        hashes[i] = uint256{static_cast<uint8_t>(i + 1)};
        chain[i].phashBlock = &hashes[i];
        chain[i].nHeight = i;
        chain[i].nChainWork = arith_uint256{static_cast<uint64_t>(i + 1)};
        // Unauthenticated lead (header-only, as during real catch-up).
        chain[i].nAuthenticatedChainWork = arith_uint256{1};
        chain[i].nStatus = 0;
        if (i > 0) chain[i].pprev = &chain[i - 1];
    }
    const auto stale = node::ComputeChainTipStaleness(&chain[0], &chain[7]);
    BOOST_CHECK_EQUAL(stale.behind_best_header, 7);
    BOOST_CHECK(stale.header_extends_tip);
    BOOST_CHECK(stale.is_stale);
}

BOOST_AUTO_TEST_SUITE_END()
