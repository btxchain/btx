// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <index/coinstatsindex.h>
#include <interfaces/chain.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <util/byte_units.h>
#include <util/check.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

// Tests of generic BaseIndex functionality that is independent of which
// concrete index is being used. CoinStatsIndex is used here merely as a
// convenient instantiation of BaseIndex.
BOOST_AUTO_TEST_SUITE(baseindex_tests)

// An index must not commit ahead of the durable UTXO tip. Otherwise an
// unclean restart could leave it unable to rewind through unflushed blocks.
BOOST_FIXTURE_TEST_CASE(baseindex_no_commit_ahead_of_flush, TestChain100Setup)
{
    Chainstate& chainstate{Assert(m_node.chainman)->ActiveChainstate()};
    auto sync_index = [&](bool do_flush, int expected_sync_height, int expected_commit_height) {
        CoinStatsIndex index{interfaces::MakeChain(m_node), /*n_cache_size=*/1_MiB};
        BOOST_REQUIRE(index.Init());
        index.Sync();
        if (do_flush) {
            chainstate.ForceFlushStateToDisk();
            m_node.chain->context()->validation_signals->SyncWithValidationInterfaceQueue();
        }
        BOOST_CHECK_EQUAL(index.GetSummary().best_block_height, expected_sync_height);
        index.Stop();

        // Reinitialize to observe only the state that actually reached disk.
        BOOST_REQUIRE(index.Init());
        BOOST_CHECK_EQUAL(index.GetSummary().best_block_height, expected_commit_height);
        index.Stop();
    };

    // Syncing alone must not commit beyond the never-flushed chainstate.
    sync_index(/*do_flush=*/false, /*expected_sync_height=*/100, /*expected_commit_height=*/0);

    // Once the chainstate flush and its callback complete, the index can commit.
    sync_index(/*do_flush=*/true, /*expected_sync_height=*/100, /*expected_commit_height=*/100);

    // A newly connected but unflushed block remains in memory only.
    CreateAndProcessBlock({}, CScript() << OP_TRUE);
    sync_index(/*do_flush=*/false, /*expected_sync_height=*/101, /*expected_commit_height=*/100);
}

BOOST_AUTO_TEST_SUITE_END()
