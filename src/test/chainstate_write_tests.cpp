// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/blockstorage.h>
#include <test/util/setup_common.h>
#include <util/fs.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>

// Taken from validation.cpp
static constexpr auto DATABASE_WRITE_INTERVAL_MIN{50min};
static constexpr auto DATABASE_WRITE_INTERVAL_MAX{70min};

BOOST_AUTO_TEST_SUITE(chainstate_write_tests)

BOOST_FIXTURE_TEST_CASE(chainstate_write_interval, TestingSetup)
{
    struct TestSubscriber final : CValidationInterface {
        bool m_did_flush{false};
        void ChainStateFlushed(ChainstateRole, const CBlockLocator&) override
        {
            m_did_flush = true;
        }
    };

    const auto sub{std::make_shared<TestSubscriber>()};
    m_node.validation_signals->RegisterSharedValidationInterface(sub);
    auto& chainstate{Assert(m_node.chainman)->ActiveChainstate()};
    BlockValidationState state_dummy{};

    // The first periodic flush sets m_next_write and does not flush
    chainstate.FlushStateToDisk(state_dummy, FlushStateMode::PERIODIC);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK(!sub->m_did_flush);

    // The periodic flush interval is between 50 and 70 minutes (inclusive)
    SetMockTime(GetTime<std::chrono::minutes>() + DATABASE_WRITE_INTERVAL_MIN - 1min);
    chainstate.FlushStateToDisk(state_dummy, FlushStateMode::PERIODIC);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK(!sub->m_did_flush);

    SetMockTime(GetTime<std::chrono::minutes>() + DATABASE_WRITE_INTERVAL_MAX);
    chainstate.FlushStateToDisk(state_dummy, FlushStateMode::PERIODIC);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK(sub->m_did_flush);
}

// Test that we do PERIODIC flushes inside ActivateBestChain.
// This is necessary for reindex-chainstate to be able to periodically flush
// before reaching chain tip.
BOOST_FIXTURE_TEST_CASE(write_during_multiblock_activation, TestChain100Setup)
{
    struct TestSubscriber final : CValidationInterface
    {
        const CBlockIndex* m_tip{nullptr};
        const CBlockIndex* m_flushed_at_block{nullptr};
        void ChainStateFlushed(ChainstateRole, const CBlockLocator&) override
        {
            m_flushed_at_block = m_tip;
        }
        void UpdatedBlockTip(const CBlockIndex* block_index, const CBlockIndex*, bool) override {
            m_tip = block_index;
        }
    };

    auto& chainstate{Assert(m_node.chainman)->ActiveChainstate()};
    BlockValidationState state_dummy{};

    // Pop two blocks from the tip
    const CBlockIndex* tip{chainstate.m_chain.Tip()};
    CBlockIndex* second_from_tip{tip->pprev};

    {
        LOCK2(m_node.chainman->GetMutex(), chainstate.MempoolMutex());
        chainstate.DisconnectTip(state_dummy, nullptr);
        chainstate.DisconnectTip(state_dummy, nullptr);
    }

    BOOST_CHECK_EQUAL(second_from_tip->pprev, chainstate.m_chain.Tip());

    // Set m_next_write to current time
    chainstate.FlushStateToDisk(state_dummy, FlushStateMode::FORCE_FLUSH);
    BOOST_CHECK_EQUAL(WITH_LOCK(::cs_main, return chainstate.GetLastFlushedBlock()), second_from_tip->pprev);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    // The periodic flush interval is between 50 and 70 minutes (inclusive)
    // The next call to a PERIODIC write will flush
    SetMockTime(GetMockTime() + DATABASE_WRITE_INTERVAL_MAX);

    const auto sub{std::make_shared<TestSubscriber>()};
    m_node.validation_signals->RegisterSharedValidationInterface(sub);

    // ActivateBestChain back to tip
    chainstate.ActivateBestChain(state_dummy, nullptr);
    BOOST_CHECK_EQUAL(tip, chainstate.m_chain.Tip());
    // Check that we flushed inside ActivateBestChain while we were at the
    // second block from tip, since FlushStateToDisk is called with PERIODIC
    // inside the outer loop.
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK_EQUAL(sub->m_flushed_at_block, second_from_tip);
    BOOST_CHECK_EQUAL(WITH_LOCK(::cs_main, return chainstate.GetLastFlushedBlock()), second_from_tip);
}

BOOST_FIXTURE_TEST_CASE(chainstate_stops_after_block_flush_failure, TestChain100Setup)
{
    auto& chainstate{Assert(m_node.chainman)->ActiveChainstate()};
    BlockValidationState state;
    BOOST_REQUIRE(chainstate.FlushStateToDisk(state, FlushStateMode::FORCE_FLUSH));

    mineBlocks(1);
    const CBlockIndex* tip{WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    const fs::path block_file{WITH_LOCK(::cs_main, return chainstate.m_blockman.GetBlockPosFilename(tip->GetBlockPos()))};

    // Replacing the block file with a directory makes the file flush fail.
    BOOST_REQUIRE(fs::remove(block_file));
    BOOST_REQUIRE(fs::create_directory(block_file));

    state = BlockValidationState{};
    BOOST_CHECK(!chainstate.FlushStateToDisk(state, FlushStateMode::FORCE_FLUSH));
    BOOST_CHECK(state.IsError());
    BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_FAILURE);
}

BOOST_FIXTURE_TEST_CASE(force_sync_retains_utxo_cache, TestChain100Setup)
{
    auto& chainstate{Assert(m_node.chainman)->ActiveChainstate()};
    BlockValidationState state;

    BOOST_REQUIRE(chainstate.FlushStateToDisk(state, FlushStateMode::FORCE_FLUSH));
    BOOST_CHECK_EQUAL(WITH_LOCK(::cs_main, return chainstate.CoinsTip().GetCacheSize()), 0U);

    mineBlocks(1);
    const size_t cache_size{WITH_LOCK(::cs_main, return chainstate.CoinsTip().GetCacheSize())};
    BOOST_REQUIRE_GT(cache_size, 0U);
    BOOST_REQUIRE_GT(WITH_LOCK(::cs_main, return chainstate.CoinsTip().GetDirtyCount()), 0U);

    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.FlushStateToDisk(state, FlushStateMode::FORCE_SYNC));
    BOOST_CHECK_EQUAL(WITH_LOCK(::cs_main, return chainstate.CoinsTip().GetCacheSize()), cache_size);
    BOOST_CHECK_EQUAL(WITH_LOCK(::cs_main, return chainstate.CoinsTip().GetDirtyCount()), 0U);

    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.FlushStateToDisk(state, FlushStateMode::FORCE_FLUSH));
    BOOST_CHECK_EQUAL(WITH_LOCK(::cs_main, return chainstate.CoinsTip().GetCacheSize()), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
