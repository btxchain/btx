// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mining_guard.h>

#include <boost/test/unit_test.hpp>

#include <vector>

BOOST_AUTO_TEST_SUITE(mining_chain_guard_tests)

BOOST_AUTO_TEST_CASE(disabled_guard_does_not_pause_mining)
{
    node::MiningChainGuardOptions options;
    options.enabled = false;

    const auto status = node::EvaluateMiningChainGuard(
        /*local_tip_height=*/100,
        /*initial_block_download=*/false,
        /*network_active=*/true,
        std::vector<int>{90, 95, 100},
        options);

    BOOST_CHECK(status.healthy);
    BOOST_CHECK_EQUAL(status.reason, "disabled");
}

BOOST_AUTO_TEST_CASE(initial_block_download_pauses_mining)
{
    node::MiningChainGuardOptions options;
    options.enabled = true;

    const auto status = node::EvaluateMiningChainGuard(
        /*local_tip_height=*/100,
        /*initial_block_download=*/true,
        /*network_active=*/true,
        std::vector<int>{100, 100},
        options);

    BOOST_CHECK(!status.healthy);
    BOOST_CHECK_EQUAL(status.reason, "initial_block_download");
}

BOOST_AUTO_TEST_CASE(insufficient_peer_consensus_pauses_mining)
{
    node::MiningChainGuardOptions options;
    options.enabled = true;
    options.min_peer_count = 2;

    const auto status = node::EvaluateMiningChainGuard(
        /*local_tip_height=*/100,
        /*initial_block_download=*/false,
        /*network_active=*/true,
        std::vector<int>{100},
        options);

    BOOST_CHECK(!status.healthy);
    BOOST_CHECK_EQUAL(status.reason, "insufficient_peer_consensus");
}

BOOST_AUTO_TEST_CASE(local_tip_ahead_of_peer_median_pauses_mining)
{
    node::MiningChainGuardOptions options;
    options.enabled = true;
    options.max_median_tip_gap = 6;

    const auto status = node::EvaluateMiningChainGuard(
        /*local_tip_height=*/125,
        /*initial_block_download=*/false,
        /*network_active=*/true,
        std::vector<int>{100, 101, 102, 103, 104},
        options);

    BOOST_CHECK(!status.healthy);
    BOOST_CHECK_EQUAL(status.reason, "local_tip_ahead_of_peer_median");
}

BOOST_AUTO_TEST_CASE(local_tip_behind_peer_median_pauses_mining)
{
    node::MiningChainGuardOptions options;
    options.enabled = true;
    options.max_median_tip_gap = 6;

    const auto status = node::EvaluateMiningChainGuard(
        /*local_tip_height=*/100,
        /*initial_block_download=*/false,
        /*network_active=*/true,
        std::vector<int>{108, 109, 110},
        options);

    BOOST_CHECK(!status.healthy);
    BOOST_CHECK_EQUAL(status.reason, "local_tip_behind_peer_median");
}

BOOST_AUTO_TEST_CASE(median_majority_close_to_tip_keeps_mining_enabled)
{
    node::MiningChainGuardOptions options;
    options.enabled = true;
    options.max_median_tip_gap = 6;

    const auto status = node::EvaluateMiningChainGuard(
        /*local_tip_height=*/120,
        /*initial_block_download=*/false,
        /*network_active=*/true,
        std::vector<int>{118, 120, 120, 121, 110},
        options);

    BOOST_CHECK(status.healthy);
    BOOST_CHECK_EQUAL(status.reason, "healthy");
    BOOST_CHECK_EQUAL(status.median_peer_tip, 120);
    BOOST_CHECK_EQUAL(status.near_tip_peers, 4);
}

BOOST_AUTO_TEST_CASE(stale_lagging_peers_are_filtered_out_before_median_check)
{
    node::MiningChainGuardOptions options;
    options.enabled = true;
    options.max_median_tip_gap = 6;
    options.stale_peer_seconds = 30;

    const std::vector<node::MiningChainGuardPeerSample> peers{
        {120, 995, 995},
        {120, 995, 995},
        {120, 995, 995},
        {110, 900, 900},
        {110, 900, 900},
        {110, 900, 900},
        {110, 900, 900},
        {110, 900, 900},
    };

    const auto filtered = node::FilterMiningChainGuardPeerHeights(
        /*local_tip_height=*/120,
        /*now=*/1000,
        peers,
        options);

    BOOST_CHECK_EQUAL(filtered.size(), 3U);
    BOOST_CHECK_EQUAL(filtered[0], 120);
    BOOST_CHECK_EQUAL(filtered[1], 120);
    BOOST_CHECK_EQUAL(filtered[2], 120);

    const auto status = node::EvaluateMiningChainGuard(
        /*local_tip_height=*/120,
        /*initial_block_download=*/false,
        /*network_active=*/true,
        filtered,
        options);

    BOOST_CHECK(status.healthy);
    BOOST_CHECK_EQUAL(status.reason, "healthy");
}

BOOST_AUTO_TEST_CASE(recently_active_lagging_peers_still_count_for_fork_safety)
{
    node::MiningChainGuardOptions options;
    options.enabled = true;
    options.max_median_tip_gap = 6;
    options.stale_peer_seconds = 30;

    const std::vector<node::MiningChainGuardPeerSample> peers{
        {120, 995, 995},
        {120, 995, 995},
        {120, 995, 995},
        {110, 995, 995},
        {110, 995, 995},
        {110, 995, 995},
        {110, 995, 995},
        {110, 995, 995},
    };

    const auto filtered = node::FilterMiningChainGuardPeerHeights(
        /*local_tip_height=*/120,
        /*now=*/1000,
        peers,
        options);

    BOOST_CHECK_EQUAL(filtered.size(), peers.size());

    const auto status = node::EvaluateMiningChainGuard(
        /*local_tip_height=*/120,
        /*initial_block_download=*/false,
        /*network_active=*/true,
        filtered,
        options);

    BOOST_CHECK(!status.healthy);
    BOOST_CHECK_EQUAL(status.reason, "local_tip_ahead_of_peer_median");
}

BOOST_AUTO_TEST_SUITE_END()
