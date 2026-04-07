// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <addresstype.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <node/kernel_notifications.h>
#include <random.h>
#include <rpc/blockchain.h>
#include <sync.h>
#include <test/util/chainstate.h>
#include <test/util/coins.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/check.h>
#include <util/mempressure.h>
#include <validation.h>

#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(validation_chainstate_tests, ChainTestingSetup)

//! Test resizing coins-related Chainstate caches during runtime.
//!
BOOST_AUTO_TEST_CASE(validation_chainstate_resize_caches)
{
    g_low_memory_threshold = 0;  // disable to get deterministic flushing

    ChainstateManager& manager = *Assert(m_node.chainman);
    CTxMemPool& mempool = *Assert(m_node.mempool);
    Chainstate& c1 = WITH_LOCK(cs_main, return manager.InitializeChainstate(&mempool));
    c1.InitCoinsDB(
        /*cache_size_bytes=*/1 << 23, /*in_memory=*/true, /*should_wipe=*/false);
    WITH_LOCK(::cs_main, c1.InitCoinsCache(1 << 23));
    BOOST_REQUIRE(c1.LoadGenesisBlock()); // Need at least one block loaded to be able to flush caches

    // Add a coin to the in-memory cache, upsize once, then downsize.
    {
        LOCK(::cs_main);
        const auto outpoint = AddTestCoin(m_rng, c1.CoinsTip());

        // Set a meaningless bestblock value in the coinsview cache - otherwise we won't
        // flush during ResizecoinsCaches() and will subsequently hit an assertion.
        c1.CoinsTip().SetBestBlock(m_rng.rand256());

        BOOST_CHECK(c1.CoinsTip().HaveCoinInCache(outpoint));

        c1.ResizeCoinsCaches(
            1 << 24,  // upsizing the coinsview cache
            1 << 22  // downsizing the coinsdb cache
        );

        // View should still have the coin cached, since we haven't destructed the cache on upsize.
        BOOST_CHECK(c1.CoinsTip().HaveCoinInCache(outpoint));

        c1.ResizeCoinsCaches(
            1 << 22,  // downsizing the coinsview cache
            1 << 23  // upsizing the coinsdb cache
        );

        // The view cache should be empty since we had to destruct to downsize.
        BOOST_CHECK(!c1.CoinsTip().HaveCoinInCache(outpoint));
    }
}

//! Test UpdateTip behavior for both active and background chainstates.
//!
//! When run on the background chainstate, UpdateTip should do a subset
//! of what it does for the active chainstate.
BOOST_FIXTURE_TEST_CASE(chainstate_update_tip, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const auto get_notify_tip{[&]() {
        LOCK(m_node.notifications->m_tip_block_mutex);
        BOOST_REQUIRE(m_node.notifications->TipBlock());
        return *m_node.notifications->TipBlock();
    }};
    uint256 curr_tip = get_notify_tip();

    // Mine 10 more blocks, putting at us height 110 where a valid assumeutxo value can
    // be found.
    mineBlocks(10);

    // After adding some blocks to the tip, best block should have changed.
    BOOST_CHECK(get_notify_tip() != curr_tip);

    // Grab block 1 from disk; we'll add it to the background chain later.
    std::shared_ptr<CBlock> pblockone = std::make_shared<CBlock>();
    {
        LOCK(::cs_main);
        chainman.m_blockman.ReadBlock(*pblockone, *chainman.ActiveChain()[1]);
    }

    BOOST_REQUIRE(CreateAndActivateUTXOSnapshot(
        this, NoMalleation, /*reset_chainstate=*/ true));

    // Ensure our active chain is the snapshot chainstate.
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.IsSnapshotActive()));

    curr_tip = get_notify_tip();

    // Mine a new block on top of the activated snapshot chainstate.
    mineBlocks(1);  // Defined in TestChain100Setup.

    // After adding some blocks to the snapshot tip, best block should have changed.
    BOOST_CHECK(get_notify_tip() != curr_tip);

    curr_tip = get_notify_tip();

    BOOST_CHECK_EQUAL(chainman.GetAll().size(), 2);

    Chainstate& background_cs{*Assert([&]() -> Chainstate* {
        for (Chainstate* cs : chainman.GetAll()) {
            if (cs != &chainman.ActiveChainstate()) {
                return cs;
            }
        }
        return nullptr;
    }())};

    // Append the first block to the background chain.
    BlockValidationState state;
    CBlockIndex* pindex = nullptr;
    const CChainParams& chainparams = Params();
    bool newblock = false;

    // NOTE: much of this is inlined from ProcessNewBlock(); just reuse PNB()
    // once it is changed to support multiple chainstates.
    {
        LOCK(::cs_main);
        bool checked = CheckBlock(*pblockone, state, chainparams.GetConsensus());
        BOOST_CHECK(checked);
        bool accepted = chainman.AcceptBlock(
            pblockone, state, &pindex, true, nullptr, &newblock, true);
        BOOST_CHECK(accepted);
    }

    // UpdateTip is called here
    bool block_added = background_cs.ActivateBestChain(state, pblockone);

    // Ensure tip is as expected
    BOOST_CHECK_EQUAL(background_cs.m_chain.Tip()->GetBlockHash(), pblockone->GetHash());

    // get_notify_tip() should be unchanged after adding a block to the background
    // validation chain.
    BOOST_CHECK(block_added);
    BOOST_CHECK_EQUAL(curr_tip, get_notify_tip());
}

BOOST_FIXTURE_TEST_CASE(chainstate_deep_reorg_rejection_prunes_candidate_branch, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();

    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    struct RestoreConsensusParams
    {
        Consensus::Params& consensus;
        uint32_t max_reorg_depth;
        int32_t reorg_start_height;
        ~RestoreConsensusParams()
        {
            consensus.nMaxReorgDepth = max_reorg_depth;
            consensus.nReorgProtectionStartHeight = reorg_start_height;
        }
    } restore{consensus, consensus.nMaxReorgDepth, consensus.nReorgProtectionStartHeight};

    consensus.nMaxReorgDepth = 2;
    consensus.nReorgProtectionStartHeight = 10;

    std::vector<std::unique_ptr<CBlockIndex>> rejected_branch;
    std::vector<uint256> rejected_hashes;
    rejected_branch.reserve(6);
    rejected_hashes.reserve(6);

    CBlockIndex* rejected_tip{nullptr};
    CBlockIndex* active_tip_before{nullptr};
    {
        LOCK(::cs_main);
        active_tip_before = chainstate.m_chain.Tip();
        BOOST_REQUIRE(active_tip_before != nullptr);
        BOOST_REQUIRE(active_tip_before->nHeight >= 100);

        CBlockIndex* fork = chainstate.m_chain[95];
        BOOST_REQUIRE(fork != nullptr);

        chainstate.setBlockIndexCandidates.clear();
        chainstate.setBlockIndexCandidates.insert(active_tip_before);

        CBlockIndex* prev = fork;
        arith_uint256 next_work = active_tip_before->nChainWork;
        for (int i = 0; i < 6; ++i) {
            CBlockHeader header;
            header.hashPrevBlock = prev->GetBlockHash();
            header.nVersion = prev->nVersion;
            header.nTime = prev->nTime + 1 + i;
            header.nBits = prev->nBits;
            header.nNonce64 = prev->nNonce64 + 1 + i;
            rejected_branch.emplace_back(std::make_unique<CBlockIndex>(header));
            rejected_hashes.push_back(m_rng.rand256());

            CBlockIndex& idx = *rejected_branch.back();
            idx.phashBlock = &rejected_hashes.back();
            idx.pprev = prev;
            idx.nHeight = prev->nHeight + 1;
            idx.nStatus = BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
            idx.nTx = 1;
            idx.m_chain_tx_count = prev->m_chain_tx_count + 1;
            idx.nSequenceId = prev->nSequenceId + 1 + i;
            idx.nChainWork = ++next_work;
            idx.nTimeMax = idx.nTime;
            idx.BuildSkip();
            prev = &idx;
        }

        rejected_tip = rejected_branch.back().get();
        chainstate.setBlockIndexCandidates.insert(rejected_tip);
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(rejected_tip), 1);
    }

    BlockValidationState state;
    BOOST_CHECK(chainstate.ActivateBestChain(state));

    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip(), active_tip_before);
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(rejected_tip), 0);
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(active_tip_before), 1);
    }

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({}, script_pub_key);

    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Height(), active_tip_before->nHeight + 1);
        BOOST_CHECK(chainstate.m_chain.Tip()->pprev == active_tip_before);
    }
}

BOOST_AUTO_TEST_SUITE_END()
