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
    const CBlockIndex* prev_index{WITH_LOCK(::cs_main, return node.chainman->ActiveChain().Tip())};
    const uint32_t block_height{prev_index ? static_cast<uint32_t>(prev_index->nHeight + 1) : 0};
    BOOST_REQUIRE(MineHeaderForConsensus(
        block,
        block_height,
        node.chainman->GetConsensus(),
        5'000'000,
        prev_index ? std::optional<int64_t>{prev_index->GetMedianTimePast()} : std::nullopt));
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
    // Pre-RC tip: do not require NODE_MATMUL_CONSENSUS (production canary may
    // still be unpublished). After RC activation the MatMul-specific case
    // below covers the consensus-tier preference.
    const ServiceFlags desirable_full{
        ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    const ServiceFlags desirable_limited{
        ServiceFlags(NODE_NETWORK_LIMITED | NODE_WITNESS)};

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

    // Default regtest tip is below nMatMulRCHeight, so consensus-mode sync must
    // still treat ordinary NODE_NETWORK peers as desirable. Otherwise two
    // self-qualified CUDA nodes with an empty production golden manifest can
    // never sync the pre-activation parent chain.
    BOOST_REQUIRE(!m_node.chainman->GetParams().GetConsensus().IsMatMulRCActive(
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Height())));
    BOOST_CHECK(peerman->GetDesirableServiceFlags(base) == base);
    BOOST_CHECK(peerman->HasAllDesirableServiceFlags(base));
    BOOST_CHECK(peerman->HasAllDesirableServiceFlags(consensus_peer));
    BOOST_CHECK(peerman->HasAllDesirableServiceFlags(economic_peer));

    // Force RC-active height identity for the preference gate without mining a
    // full activation window. Restore immediately so later tests stay hermetic.
    Consensus::Params& consensus = const_cast<Consensus::Params&>(
        m_node.chainman->GetParams().GetConsensus());
    const int32_t saved_rc = consensus.nMatMulRCHeight;
    const int32_t saved_v4 = consensus.nMatMulV4Height;
    struct RestoreHeights {
        Consensus::Params& params;
        int32_t rc;
        int32_t v4;
        ~RestoreHeights()
        {
            params.nMatMulRCHeight = rc;
            params.nMatMulV4Height = v4;
        }
    } restore{consensus, saved_rc, saved_v4};
    consensus.nMatMulV4Height = 0;
    consensus.nMatMulRCHeight = 0;
    BOOST_REQUIRE(consensus.IsMatMulRCActive(
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Height())));
    BOOST_CHECK(peerman->GetDesirableServiceFlags(base) ==
                ServiceFlags(base | NODE_MATMUL_CONSENSUS));
    BOOST_CHECK(peerman->HasAllDesirableServiceFlags(consensus_peer));
    BOOST_CHECK(!peerman->HasAllDesirableServiceFlags(base));
    BOOST_CHECK(!peerman->HasAllDesirableServiceFlags(economic_peer));
}

BOOST_AUTO_TEST_CASE(matmul_consensus_tier_sync_eligibility_tracks_activation)
{
    const ServiceFlags base{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    const ServiceFlags consensus_peer{
        ServiceFlags(base | NODE_MATMUL_CONSENSUS)};

    // A peer selected before activation remains eligible while the tier is
    // optional, but is dynamically disqualified once the tier is required.
    BOOST_CHECK(IsMatMulPeerEligibleForSync(
        /*require_matmul_consensus=*/false, base,
        /*has_noban_permission=*/false));
    BOOST_CHECK(!IsMatMulPeerEligibleForSync(
        /*require_matmul_consensus=*/true, base,
        /*has_noban_permission=*/false));
    BOOST_CHECK(IsMatMulPeerEligibleForSync(
        /*require_matmul_consensus=*/true, consensus_peer,
        /*has_noban_permission=*/false));
    BOOST_CHECK(IsMatMulPeerEligibleForSync(
        /*require_matmul_consensus=*/true, base,
        /*has_noban_permission=*/true));
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
