// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <addresstype.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <node/kernel_notifications.h>
#include <node/warnings.h>
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

#include <optional>
#include <string>
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

    // PARK is an explicit local-finality action, so a deep reorg is refused
    // only when the operator opts into parking. The default WARN behavior is
    // covered by the companion default/follow-most-work test below.
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    auto& deep_reorg_action = const_cast<kernel::DeepReorgAction&>(chainman.m_options.deep_reorg_action);
    auto& max_reorg_depth_park = const_cast<std::optional<uint32_t>&>(chainman.m_options.max_reorg_depth_park);
    struct RestoreDeepReorgOptions
    {
        Consensus::Params& consensus;
        int32_t reorg_start_height;
        kernel::DeepReorgAction& action;
        kernel::DeepReorgAction saved_action;
        std::optional<uint32_t>& park_depth;
        std::optional<uint32_t> saved_park_depth;
        ~RestoreDeepReorgOptions()
        {
            consensus.nReorgProtectionStartHeight = reorg_start_height;
            action = saved_action;
            park_depth = saved_park_depth;
        }
    } restore{consensus, consensus.nReorgProtectionStartHeight,
              deep_reorg_action, deep_reorg_action,
              max_reorg_depth_park, max_reorg_depth_park};

    consensus.nReorgProtectionStartHeight = 10;
    deep_reorg_action = kernel::DeepReorgAction::PARK;
    max_reorg_depth_park = 2;

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));

    CBlockIndex* fork{nullptr};
    CBlockIndex* original_branch_first{nullptr};
    CBlockIndex* original_tip{nullptr};
    {
        LOCK(::cs_main);
        original_tip = chainstate.m_chain.Tip();
        BOOST_REQUIRE(original_tip != nullptr);
        BOOST_REQUIRE(original_tip->nHeight >= 100);
        fork = chainstate.m_chain[95];
        BOOST_REQUIRE(fork != nullptr);
        original_branch_first = chainstate.m_chain[fork->nHeight + 1];
        BOOST_REQUIRE(original_branch_first != nullptr);
    }
    const uint256 original_tip_hash = original_tip->GetBlockHash();
    const int original_height = original_tip->nHeight;

    BlockValidationState original_inval_state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(original_inval_state, original_branch_first));
    {
        LOCK(::cs_main);
        BOOST_REQUIRE_EQUAL(chainstate.m_chain.Tip(), fork);
    }

    CBlockIndex* competing_root{nullptr};
    CBlockIndex* competing_tip{nullptr};
    for (int i = 0; i < 6; ++i) {
        const CBlock competing_block = CreateAndProcessBlock({}, script_pub_key);
        LOCK(::cs_main);
        CBlockIndex* tip = chainstate.m_chain.Tip();
        BOOST_REQUIRE(tip != nullptr);
        BOOST_REQUIRE_EQUAL(tip->GetBlockHash(), competing_block.GetHash());
        if (i == 0) competing_root = tip;
        if (i == 5) competing_tip = tip;
    }
    BOOST_REQUIRE(competing_root != nullptr);
    BOOST_REQUIRE(competing_tip != nullptr);
    BOOST_REQUIRE_EQUAL(competing_tip->nHeight, fork->nHeight + 6);

    BlockValidationState competing_inval_state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(competing_inval_state, competing_root));
    {
        LOCK(::cs_main);
        BOOST_REQUIRE_EQUAL(chainstate.m_chain.Tip(), fork);
        chainstate.ResetBlockFailureFlags(original_branch_first);
    }
    BlockValidationState restore_original_state;
    BOOST_REQUIRE(chainstate.ActivateBestChain(restore_original_state));
    {
        LOCK(::cs_main);
        BOOST_REQUIRE_EQUAL(chainstate.m_chain.Tip()->GetBlockHash(), original_tip_hash);
        BOOST_REQUIRE_EQUAL(chainstate.m_chain.Height(), original_height);
    }

    ResetReorgProtectionRuntimeStats();
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(competing_root);
        BOOST_REQUIRE_EQUAL(chainstate.setBlockIndexCandidates.count(competing_tip), 1);
    }
    BlockValidationState state;
    BOOST_CHECK(chainstate.ActivateBestChain(state));

    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip()->GetBlockHash(), original_tip_hash);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Height(), original_height);
        BOOST_CHECK(chainman.IsOnParkedReorgBranch(competing_tip));
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(competing_tip), 0);
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(original_tip), 1);
    }

    const auto stats = ProbeReorgProtectionRuntimeStats();
    BOOST_CHECK_EQUAL(stats.rejected_reorgs, 1U);
    BOOST_CHECK_EQUAL(stats.last_rejected_max_reorg_depth, 2U);

    CreateAndProcessBlock({}, script_pub_key);

    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Height(), original_height + 1);
        BOOST_CHECK(chainstate.m_chain.Tip()->pprev == original_tip);
    }
}

//! Explicit WARN deep-reorg handling must follow the most-work chain -- a deep
//! reorg is NOT refused, so the node stays Nakamoto-consistent when an operator
//! deliberately selects a warn-only profile. The deep reorg must still be loudly
//! surfaced as an operator warning.
//!
//! This drives a REAL reorg (real blocks, so disconnect/connect succeed): we
//! invalidate a block a few back to fork the active chain, mine a shorter
//! competing branch across that fork, then reconsider the heavier original
//! branch. With the threshold lowered so the cross-fork switch counts as "deep",
//! WARN must raise the operator alarm and still adopt the most-work tip.
BOOST_FIXTURE_TEST_CASE(chainstate_warn_profile_deep_reorg_follows_most_work, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));

    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    auto& deep_reorg_action = const_cast<kernel::DeepReorgAction&>(chainman.m_options.deep_reorg_action);
    auto& max_reorg_depth_warn = const_cast<std::optional<uint32_t>&>(chainman.m_options.max_reorg_depth_warn);
    auto& max_reorg_depth_park = const_cast<std::optional<uint32_t>&>(chainman.m_options.max_reorg_depth_park);
    struct RestoreParams
    {
        Consensus::Params& consensus;
        int32_t reorg_start_height;
        kernel::DeepReorgAction& deep_reorg_action;
        kernel::DeepReorgAction saved_deep_reorg_action;
        std::optional<uint32_t>& warn_depth;
        std::optional<uint32_t> saved_warn_depth;
        std::optional<uint32_t>& park_depth;
        std::optional<uint32_t> saved_park_depth;
        ~RestoreParams()
        {
            consensus.nReorgProtectionStartHeight = reorg_start_height;
            deep_reorg_action = saved_deep_reorg_action;
            warn_depth = saved_warn_depth;
            park_depth = saved_park_depth;
        }
    } restore{consensus, consensus.nReorgProtectionStartHeight,
              deep_reorg_action, deep_reorg_action,
              max_reorg_depth_warn, max_reorg_depth_warn,
              max_reorg_depth_park, max_reorg_depth_park};
    deep_reorg_action = kernel::DeepReorgAction::WARN;
    BOOST_REQUIRE(chainman.m_options.deep_reorg_action == kernel::DeepReorgAction::WARN);

    // Any cross-fork switch deeper than one block trips the warning; tip is already >= 10.
    consensus.nReorgProtectionStartHeight = 10;
    max_reorg_depth_warn = 1;
    max_reorg_depth_park = 1;

    // Fork point: three blocks below the current tip. The ORIGINAL branch
    // (fork+1, fork+2, fork+3) stays our reference heavier branch.
    CBlockIndex* fork{nullptr};
    CBlockIndex* original_tip{nullptr};
    {
        LOCK(::cs_main);
        original_tip = chainstate.m_chain.Tip();
        BOOST_REQUIRE(original_tip != nullptr);
        fork = original_tip->pprev->pprev->pprev; // tip-3
        BOOST_REQUIRE(fork != nullptr);
    }
    const uint256 original_tip_hash = original_tip->GetBlockHash();
    const int original_height = original_tip->nHeight;

    // Disconnect the original branch back to the fork by invalidating fork+1.
    CBlockIndex* invalidate_at{nullptr};
    {
        LOCK(::cs_main);
        invalidate_at = chainstate.m_chain[fork->nHeight + 1];
        BOOST_REQUIRE(invalidate_at != nullptr);
    }
    BlockValidationState inval_state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(inval_state, invalidate_at));
    {
        LOCK(::cs_main);
        BOOST_REQUIRE_EQUAL(chainstate.m_chain.Tip(), fork);
    }

    // Mine a SHORTER competing branch (two blocks on the fork). Active tip becomes
    // the competing branch; the (invalidated) original branch is heavier (3 blocks).
    CreateAndProcessBlock({}, script_pub_key);
    const CBlock competing = CreateAndProcessBlock({}, script_pub_key);
    CBlockIndex* competing_tip{nullptr};
    {
        LOCK(::cs_main);
        competing_tip = chainstate.m_chain.Tip();
        BOOST_REQUIRE(competing_tip != nullptr);
        BOOST_REQUIRE_EQUAL(competing_tip->GetBlockHash(), competing.GetHash());
        BOOST_REQUIRE_EQUAL(competing_tip->nHeight, fork->nHeight + 2);
    }

    // Re-enable the heavier original branch. The node must switch ACROSS the fork
    // from the competing tip back to the original tip -- a real cross-fork reorg
    // (disconnect competing, connect fork+1..fork+3). This trips the deep-reorg
    // warning (depth 2 > warn threshold 1). In WARN mode it follows the
    // most-work chain and records the operator alarm with the warning depth.
    ResetReorgProtectionRuntimeStats();
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(invalidate_at);
    }
    BlockValidationState reactivate_state;
    BOOST_CHECK(chainstate.ActivateBestChain(reactivate_state));

    {
        LOCK(::cs_main);
        // WARN never parks: node adopts the heavier original branch across the
        // fork rather than staying pinned to the shorter competing tip.
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip()->GetBlockHash(), original_tip_hash);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Height(), original_height);
    }

    // The cross-fork switch must have fired the operator alarm.
    const auto stats = ProbeReorgProtectionRuntimeStats();
    BOOST_CHECK_EQUAL(stats.rejected_reorgs, 1U);
    BOOST_CHECK_GE(stats.deepest_rejected_reorg_depth, 2U);
    BOOST_CHECK_EQUAL(stats.last_rejected_max_reorg_depth, 1U);
    bool saw_deep_reorg_warning{false};
    for (const bilingual_str& warning : m_node.warnings->GetMessages()) {
        saw_deep_reorg_warning |=
            warning.original.find("Deep reorg detected") != std::string::npos &&
            warning.original.find("Following the most-work chain") != std::string::npos;
    }
    BOOST_CHECK(saw_deep_reorg_warning);
}

BOOST_AUTO_TEST_SUITE_END()
