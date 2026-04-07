// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <node/miner.h>
#include <node/transaction.h>
#include <net_processing.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(peerman_tests, RegTestingSetup)

/** Window, in blocks, for connecting to NODE_NETWORK_LIMITED peers */
static constexpr int64_t NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS = 144;

static void mineBlock(const node::NodeContext& node, std::chrono::seconds block_time)
{
    auto curr_time = GetTime<std::chrono::seconds>();
    SetMockTime(block_time); // update time so the block is created with it
    CBlock block = node::BlockAssembler{node.chainman->ActiveChainstate(), nullptr, {}, node}.CreateNewBlock()->block;
    const uint32_t block_height{WITH_LOCK(::cs_main, return static_cast<uint32_t>(node.chainman->ActiveChain().Height() + 1))};
    BOOST_REQUIRE(MineHeaderForConsensus(block, block_height, node.chainman->GetConsensus()));
    block.fChecked = true; // little speedup
    SetMockTime(curr_time); // process block at current time
    Assert(node.chainman->ProcessNewBlock(std::make_shared<const CBlock>(block), /*force_processing=*/true, /*min_pow_checked=*/true, nullptr));
    node.validation_signals->SyncWithValidationInterfaceQueue(); // drain events queue
}

// Verifying when network-limited peer connections are desirable based on the node's proximity to the tip
BOOST_AUTO_TEST_CASE(connections_desirable_service_flags)
{
    std::unique_ptr<PeerManager> peerman = PeerManager::make(*m_node.connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool, *m_node.warnings, {});
    auto consensus = m_node.chainman->GetParams().GetConsensus();
    const ServiceFlags desirable_full{
        ServiceFlags(NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    const ServiceFlags desirable_limited{
        ServiceFlags(NODE_NETWORK_LIMITED | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};

    // Check we start connecting to full nodes
    ServiceFlags peer_flags{NODE_WITNESS | NODE_NETWORK_LIMITED};
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == desirable_full);

    // Make peerman aware of the initial best block and verify we accept limited peers when we start close to the tip time.
    auto tip = WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip());
    uint64_t tip_block_time = tip->GetBlockTime();
    int tip_block_height = tip->nHeight;
    peerman->SetBestBlock(tip_block_height, std::chrono::seconds{tip_block_time});

    SetMockTime(tip_block_time + 1); // Set node time to tip time
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == desirable_limited);

    // Check we don't disallow limited peers connections when we are behind but still recoverable (below the connection safety window)
    SetMockTime(GetTime<std::chrono::seconds>() + std::chrono::seconds{consensus.nPowTargetSpacing * (NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS - 1)});
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == desirable_limited);

    // Check we disallow limited peers connections when we are further than the limited peers safety window
    SetMockTime(GetTime<std::chrono::seconds>() + std::chrono::seconds{consensus.nPowTargetSpacing * 2});
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == desirable_full);

    // By now, we tested that the connections desirable services flags change based on the node's time proximity to the tip.
    // Now, perform the same tests for when the node receives a block.
    m_node.validation_signals->RegisterValidationInterface(peerman.get());

    // First, verify a block in the past doesn't enable limited peers connections
    // At this point, our time is (NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS + 1) * 10 minutes ahead the tip's time.
    mineBlock(m_node, /*block_time=*/std::chrono::seconds{tip_block_time + 1});
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == desirable_full);

    // Verify a block close to the tip enables limited peers connections
    mineBlock(m_node, /*block_time=*/GetTime<std::chrono::seconds>());
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == desirable_limited);

    // Lastly, verify the stale tip checks can disallow limited peers connections after not receiving blocks for a prolonged period.
    SetMockTime(GetTime<std::chrono::seconds>() + std::chrono::seconds{consensus.nPowTargetSpacing * NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS + 1});
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == desirable_full);
}

BOOST_AUTO_TEST_CASE(matmul_consensus_tier_desirable_service_flags)
{
    std::unique_ptr<PeerManager> peerman = PeerManager::make(*m_node.connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool, *m_node.warnings, {});

    const ServiceFlags base{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    const ServiceFlags consensus_peer{ServiceFlags(base | NODE_MATMUL_CONSENSUS)};
    const ServiceFlags economic_peer{ServiceFlags(base | NODE_MATMUL_ECONOMIC)};

    BOOST_CHECK(peerman->GetDesirableServiceFlags(base) == ServiceFlags(base | NODE_MATMUL_CONSENSUS));
    BOOST_CHECK(peerman->HasAllDesirableServiceFlags(consensus_peer));
    BOOST_CHECK(!peerman->HasAllDesirableServiceFlags(base));
    BOOST_CHECK(!peerman->HasAllDesirableServiceFlags(economic_peer));
}

BOOST_AUTO_TEST_CASE(broadcast_transaction_fails_closed_without_peerman)
{
    std::unique_ptr<PeerManager> saved_peerman = std::move(m_node.peerman);
    BOOST_REQUIRE(saved_peerman);

    std::string err_string;
    CMutableTransaction mtx;
    const auto tx = MakeTransactionRef(mtx);
    const auto err = node::BroadcastTransaction(m_node, tx, err_string, CAmount{0}, /*relay=*/true, /*wait_callback=*/false);

    BOOST_CHECK(err == node::TransactionError::MEMPOOL_ERROR);
    BOOST_CHECK_EQUAL(err_string, "node shutting down or networking unavailable");

    m_node.peerman = std::move(saved_peerman);
}

BOOST_AUTO_TEST_SUITE_END()
