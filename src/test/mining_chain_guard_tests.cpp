// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mining_guard.h>

#include <net.h>
#include <rpc/server.h>
#include <test/util/setup_common.h>
#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <set>
#include <string>
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
    BOOST_CHECK(!node::ShouldPauseMiningByChainGuard(status));
    BOOST_CHECK_EQUAL(node::GetMiningChainGuardRecommendedAction(status), "continue");
}

BOOST_AUTO_TEST_CASE(initial_block_download_keeps_mining_with_recovery_warning)
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
    BOOST_CHECK(!node::ShouldPauseMiningByChainGuard(status));
    BOOST_CHECK_EQUAL(node::GetMiningChainGuardRecommendedAction(status), "mine_current_tip_and_catch_up");
}

BOOST_AUTO_TEST_CASE(insufficient_peer_consensus_keeps_mining_with_recovery_warning)
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
    BOOST_CHECK(!node::ShouldPauseMiningByChainGuard(status));
    BOOST_CHECK_EQUAL(node::GetMiningChainGuardRecommendedAction(status), "add_outbound_peers");
}

BOOST_AUTO_TEST_CASE(default_guard_requires_three_peers)
{
    node::MiningChainGuardOptions options;
    options.enabled = true;

    BOOST_CHECK_EQUAL(options.min_peer_count, 3);
    BOOST_CHECK_EQUAL(options.max_median_tip_gap, 2);
    BOOST_CHECK_EQUAL(options.stale_peer_seconds, 120);

    const auto status = node::EvaluateMiningChainGuard(
        /*local_tip_height=*/100,
        /*initial_block_download=*/false,
        /*network_active=*/true,
        std::vector<int>{100, 100},
        options);

    BOOST_CHECK(!status.healthy);
    BOOST_CHECK_EQUAL(status.reason, "insufficient_peer_consensus");
    BOOST_CHECK_EQUAL(status.min_peer_count, 3);
    BOOST_CHECK(!node::ShouldPauseMiningByChainGuard(status));
    BOOST_CHECK_EQUAL(node::GetMiningChainGuardRecommendedAction(status), "add_outbound_peers");
}

BOOST_AUTO_TEST_CASE(local_tip_ahead_of_peer_median_keeps_mining_to_propagate_tip)
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
    BOOST_CHECK(!node::ShouldPauseMiningByChainGuard(status));
    BOOST_CHECK_EQUAL(node::GetMiningChainGuardRecommendedAction(status), "propagate_tip");
}

BOOST_AUTO_TEST_CASE(local_tip_behind_peer_median_keeps_mining_with_recovery_warning)
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
    BOOST_CHECK(!node::ShouldPauseMiningByChainGuard(status));
    BOOST_CHECK_EQUAL(node::GetMiningChainGuardRecommendedAction(status), "mine_current_tip_and_catch_up");
}

BOOST_AUTO_TEST_CASE(near_tip_peer_quorum_keeps_mining_with_recovery_warning)
{
    node::MiningChainGuardOptions options;
    options.enabled = true;
    options.max_median_tip_gap = 4;

    BOOST_CHECK_EQUAL(options.min_near_tip_peers, 2);
    BOOST_CHECK_EQUAL(options.near_tip_window, 2);

    const auto status = node::EvaluateMiningChainGuard(
        /*local_tip_height=*/100,
        /*initial_block_download=*/false,
        /*network_active=*/true,
        std::vector<int>{100, 103, 103},
        options);

    BOOST_CHECK(!status.healthy);
    BOOST_CHECK_EQUAL(status.reason, "insufficient_near_tip_peers");
    BOOST_CHECK_EQUAL(status.near_tip_peers, 1);
    BOOST_CHECK_EQUAL(status.min_near_tip_peers, 2);
    BOOST_CHECK(!node::ShouldPauseMiningByChainGuard(status));
    BOOST_CHECK_EQUAL(node::GetMiningChainGuardRecommendedAction(status), "add_outbound_peers");
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
    BOOST_CHECK(!node::ShouldPauseMiningByChainGuard(status));
    BOOST_CHECK_EQUAL(node::GetMiningChainGuardRecommendedAction(status), "continue");
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
    BOOST_CHECK(!node::ShouldPauseMiningByChainGuard(status));
    BOOST_CHECK_EQUAL(node::GetMiningChainGuardRecommendedAction(status), "continue");
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
    BOOST_CHECK(!node::ShouldPauseMiningByChainGuard(status));
    BOOST_CHECK_EQUAL(node::GetMiningChainGuardRecommendedAction(status), "propagate_tip");
}

BOOST_AUTO_TEST_CASE(network_inactive_keeps_mining_with_recovery_warning)
{
    node::MiningChainGuardOptions options;
    options.enabled = true;

    const auto status = node::EvaluateMiningChainGuard(
        /*local_tip_height=*/100,
        /*initial_block_download=*/false,
        /*network_active=*/false,
        std::vector<int>{100, 100, 100},
        options);

    BOOST_CHECK(!status.healthy);
    BOOST_CHECK_EQUAL(status.reason, "network_inactive");
    BOOST_CHECK(!node::ShouldPauseMiningByChainGuard(status));
    BOOST_CHECK_EQUAL(node::GetMiningChainGuardRecommendedAction(status), "mine_current_tip_and_enable_network");
}

BOOST_AUTO_TEST_CASE(same_height_hash_split_marks_island_suspect)
{
    node::MiningChainGuardOptions options;
    options.enabled = true;

    auto status = node::EvaluateMiningChainGuard(
        /*local_tip_height=*/187661,
        /*initial_block_download=*/false,
        /*network_active=*/true,
        std::vector<int>{187661, 187661, 187661},
        options);
    BOOST_CHECK(status.healthy);
    BOOST_CHECK_EQUAL(status.reason, "healthy");

    const std::vector<node::MiningChainGuardPeerSample> peers{
        {187661, 1000, 1000, "2d85ef534ab6ae21c5981d85b38bbbc9daf4e402b084774bdbf65a967474aad1"},
        {187661, 1000, 1000, "ad62b638c0ac1b15870bfd8fa949c8d154e9d0dc27c99b64c740f315870120ac"},
        {187661, 1000, 1000, "ad62b638c0ac1b15870bfd8fa949c8d154e9d0dc27c99b64c740f315870120ac"},
    };
    node::ApplyPeerTipHashCheck(
        status,
        /*local_tip_height=*/187661,
        /*local_tip_hash=*/"2d85ef534ab6ae21c5981d85b38bbbc9daf4e402b084774bdbf65a967474aad1",
        peers);

    BOOST_CHECK(!status.healthy);
    BOOST_CHECK(status.island_suspect);
    BOOST_CHECK_EQUAL(status.reason, "peer_tip_hash_mismatch");
    BOOST_CHECK_EQUAL(status.same_tip_hash_peers, 1);
    BOOST_CHECK_EQUAL(status.conflicting_tip_hash_peers, 2);
    BOOST_CHECK_EQUAL(node::GetMiningChainGuardRecommendedAction(status), "check_attested_tip");
}

BOOST_AUTO_TEST_CASE(matching_tip_hashes_keep_guard_healthy)
{
    node::MiningChainGuardOptions options;
    options.enabled = true;

    auto status = node::EvaluateMiningChainGuard(
        /*local_tip_height=*/187661,
        /*initial_block_download=*/false,
        /*network_active=*/true,
        std::vector<int>{187661, 187661, 187661},
        options);

    const std::vector<node::MiningChainGuardPeerSample> peers{
        {187661, 1000, 1000, "ad62b638c0ac1b15870bfd8fa949c8d154e9d0dc27c99b64c740f315870120ac"},
        {187661, 1000, 1000, "ad62b638c0ac1b15870bfd8fa949c8d154e9d0dc27c99b64c740f315870120ac"},
        {187661, 1000, 1000, "ad62b638c0ac1b15870bfd8fa949c8d154e9d0dc27c99b64c740f315870120ac"},
    };
    node::ApplyPeerTipHashCheck(
        status,
        /*local_tip_height=*/187661,
        /*local_tip_hash=*/"ad62b638c0ac1b15870bfd8fa949c8d154e9d0dc27c99b64c740f315870120ac",
        peers);

    BOOST_CHECK(status.healthy);
    BOOST_CHECK(!status.island_suspect);
    BOOST_CHECK_EQUAL(status.reason, "healthy");
    BOOST_CHECK_EQUAL(status.same_tip_hash_peers, 3);
    BOOST_CHECK_EQUAL(status.conflicting_tip_hash_peers, 0);
}

BOOST_AUTO_TEST_CASE(insufficient_peers_marks_island_suspect_without_hash_split)
{
    node::MiningChainGuardOptions options;
    options.enabled = true;
    options.min_peer_count = 3;

    auto status = node::EvaluateMiningChainGuard(
        /*local_tip_height=*/100,
        /*initial_block_download=*/false,
        /*network_active=*/true,
        std::vector<int>{100},
        options);
    BOOST_CHECK_EQUAL(status.reason, "insufficient_peer_consensus");

    node::ApplyPeerTipHashCheck(
        status,
        /*local_tip_height=*/100,
        /*local_tip_hash=*/"aa",
        {});
    BOOST_CHECK(status.island_suspect);
    BOOST_CHECK_EQUAL(status.reason, "insufficient_peer_consensus");
}

BOOST_AUTO_TEST_CASE(far_behind_headers_are_catch_up_not_insufficient_peer_consensus)
{
    // Live rtx6000 2026-08-29: blocks=199378 headers=199801, 23 peers
    // above tip. Evaluating insufficient_peer_consensus before median
    // behind made "healthy" unreachable by construction: peers above the
    // local tip cannot produce same-hash-at-our-height. Catch-up is not
    // isolation. The mining guard still never pauses mining.
    node::MiningChainGuardOptions options;
    options.enabled = true;
    BOOST_CHECK_EQUAL(options.min_peer_count, 3);
    BOOST_CHECK_EQUAL(options.max_median_tip_gap, 2);

    std::vector<int> rtx6000_peers(23, 199801);
    const auto many = node::EvaluateMiningChainGuard(
        /*local_tip_height=*/199378,
        /*initial_block_download=*/false,
        /*network_active=*/true,
        rtx6000_peers,
        options);
    BOOST_CHECK(!many.healthy);
    BOOST_CHECK_EQUAL(many.reason, "local_tip_behind_peer_median");
    BOOST_CHECK_EQUAL(many.peer_count, 23);
    BOOST_CHECK_EQUAL(many.median_peer_tip, 199801);
    BOOST_CHECK(!node::ShouldPauseMiningByChainGuard(many));
    BOOST_CHECK_EQUAL(node::GetMiningChainGuardRecommendedAction(many),
                      "mine_current_tip_and_catch_up");

    auto few_ahead = node::EvaluateMiningChainGuard(
        /*local_tip_height=*/199378,
        /*initial_block_download=*/false,
        /*network_active=*/true,
        std::vector<int>{199801, 199801},
        options);
    BOOST_CHECK(!few_ahead.healthy);
    BOOST_CHECK_EQUAL(few_ahead.reason, "local_tip_behind_peer_median");
    BOOST_CHECK_EQUAL(few_ahead.peer_count, 2);
    BOOST_CHECK(!node::ShouldPauseMiningByChainGuard(few_ahead));

    node::ApplyPeerTipHashCheck(
        few_ahead,
        /*local_tip_height=*/199378,
        /*local_tip_hash=*/"aa",
        {{199801, 0, 0, "bb"}, {199801, 0, 0, "cc"}});
    BOOST_CHECK(!few_ahead.island_suspect);
    BOOST_CHECK_EQUAL(few_ahead.reason, "local_tip_behind_peer_median");
    BOOST_CHECK_EQUAL(few_ahead.same_tip_hash_peers, 0);
}

BOOST_AUTO_TEST_CASE(insufficient_peer_consensus_still_applies_at_same_height)
{
    node::MiningChainGuardOptions options;
    options.enabled = true;
    options.min_peer_count = 3;

    const auto status = node::EvaluateMiningChainGuard(
        /*local_tip_height=*/199378,
        /*initial_block_download=*/false,
        /*network_active=*/true,
        std::vector<int>{199378, 199378},
        options);
    BOOST_CHECK(!status.healthy);
    BOOST_CHECK_EQUAL(status.reason, "insufficient_peer_consensus");
    BOOST_CHECK_EQUAL(status.peer_count, 2);
    BOOST_CHECK(!node::ShouldPauseMiningByChainGuard(status));
}

BOOST_FIXTURE_TEST_CASE(miningpeermesh_replaces_defaults_and_rpc_reports_it, TestingSetup)
{
    node::ResetMiningChainGuardMeshRefreshForTest();

    UniValue mesh{UniValue::VARR};
    mesh.push_back("fork.example:19335");
    mesh.push_back("other.example:19335");
    m_node.args->ForceSetArg("-miningchainguard", "1");
    m_node.args->ForceSetArg("-miningchainguarddefaultmesh", "1");
    m_node.args->ForceSetArg("-miningchainguardmeshrefreshseconds", "1");
    m_node.args->ForceSetArgV("-miningpeermesh", mesh);

    const auto options = node::GetMiningChainGuardOptions(m_node);
    BOOST_REQUIRE_EQUAL(options.peer_mesh.size(), 2U);
    BOOST_CHECK_EQUAL(options.peer_mesh[0], "fork.example:19335");
    BOOST_CHECK_EQUAL(options.peer_mesh[1], "other.example:19335");
    for (const auto& def : node::DefaultMiningPeerMesh()) {
        BOOST_CHECK(std::find(options.peer_mesh.begin(), options.peer_mesh.end(), def) ==
                    options.peer_mesh.end());
    }

    node::MiningChainGuardStatus status;
    status.enabled = true;
    status.healthy = false;
    status.network_active = true;
    status.reason = "insufficient_peer_consensus";
    node::MaybeRequestMiningChainGuardRecovery(status, m_node);

    std::set<std::string> added;
    for (const auto& info : m_node.connman->GetAddedNodeInfo(/*include_connected=*/true)) {
        added.insert(info.m_params.m_added_node);
    }
    BOOST_CHECK(added.count("fork.example:19335"));
    BOOST_CHECK(added.count("other.example:19335"));
    for (const auto& def : node::DefaultMiningPeerMesh()) {
        BOOST_CHECK_MESSAGE(!added.count(def),
                            "override must not enroll compiled operator domain " + def);
    }

    JSONRPCRequest request;
    request.context = &m_node;
    request.strMethod = "getminingpeermesh";
    request.params = UniValue(UniValue::VARR);
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    const UniValue result = tableRPC.execute(request);
    const UniValue& reported = result.find_value("default_nodes");
    BOOST_REQUIRE(reported.isArray());
    BOOST_REQUIRE_EQUAL(reported.size(), 2U);
    BOOST_CHECK_EQUAL(reported[0].get_str(), "fork.example:19335");
    BOOST_CHECK_EQUAL(reported[1].get_str(), "other.example:19335");
}

BOOST_AUTO_TEST_SUITE_END()
