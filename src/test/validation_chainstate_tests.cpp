// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <addresstype.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <node/kernel_notifications.h>
#include <node/matmul_trusted_attestations.h>
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
#include <chrono>
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
struct AssumeutxoTestChain100Setup : TestChain100Setup {
    AssumeutxoTestChain100Setup()
        : TestChain100Setup(
              ChainType::REGTEST,
              {.defer_expensive_matmul = false})
    {
    }
};

BOOST_FIXTURE_TEST_CASE(chainstate_update_tip, AssumeutxoTestChain100Setup)
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
        BOOST_CHECK(!chainman.GetReorgRecoveryRecord().has_value());
    }
}

BOOST_FIXTURE_TEST_CASE(chainstate_authenticated_shallow_race_auto_unparks_with_data_and_survives_reload, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    auto& action = const_cast<kernel::DeepReorgAction&>(chainman.m_options.deep_reorg_action);
    auto& park_depth = const_cast<std::optional<uint32_t>&>(chainman.m_options.max_reorg_depth_park);
    auto& hysteresis_depth = const_cast<std::optional<uint32_t>&>(chainman.m_options.reorg_hysteresis_depth);
    auto& hysteresis_work_margin = const_cast<std::optional<uint32_t>&>(chainman.m_options.reorg_hysteresis_work_margin);
    struct Restore {
        Consensus::Params& consensus;
        int32_t start;
        kernel::DeepReorgAction& action;
        kernel::DeepReorgAction saved_action;
        std::optional<uint32_t>& park_depth;
        std::optional<uint32_t> saved_park_depth;
        std::optional<uint32_t>& hysteresis_depth;
        std::optional<uint32_t> saved_hysteresis_depth;
        std::optional<uint32_t>& hysteresis_work_margin;
        std::optional<uint32_t> saved_hysteresis_work_margin;
        ~Restore()
        {
            consensus.nReorgProtectionStartHeight = start;
            action = saved_action;
            park_depth = saved_park_depth;
            hysteresis_depth = saved_hysteresis_depth;
            hysteresis_work_margin = saved_hysteresis_work_margin;
        }
    } restore{consensus, consensus.nReorgProtectionStartHeight,
              action, action, park_depth, park_depth,
              hysteresis_depth, hysteresis_depth,
              hysteresis_work_margin, hysteresis_work_margin};
    consensus.nReorgProtectionStartHeight = 10;
    action = kernel::DeepReorgAction::PARK;
    park_depth = 2;
    // Exercise the production mechanism rather than disabling hysteresis for
    // the test.  This margin is deliberately impossible for the four-block
    // recovery branch to satisfy, so only authenticated recovery bypass can
    // make activation progress.
    hysteresis_depth = 1;
    hysteresis_work_margin = 64;

    const CScript script = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CBlockIndex* fork;
    CBlockIndex* original_root;
    CBlockIndex* original_tip;
    {
        LOCK(::cs_main);
        original_tip = chainstate.m_chain.Tip();
        fork = chainstate.m_chain[98];
        original_root = chainstate.m_chain[99];
    }
    BOOST_REQUIRE(fork && original_root && original_tip);
    const uint256 original_hash{original_tip->GetBlockHash()};

    BlockValidationState state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, original_root));
    CBlockIndex* recovery_root{nullptr};
    CBlockIndex* recovery_tip{nullptr};
    for (int i = 0; i < 4; ++i) {
        const CBlock block{CreateAndProcessBlock({}, script)};
        LOCK(::cs_main);
        recovery_tip = chainman.m_blockman.LookupBlockIndex(block.GetHash());
        if (i == 0) recovery_root = recovery_tip;
    }
    BOOST_REQUIRE(recovery_root && recovery_tip);
    BOOST_REQUIRE_EQUAL(recovery_tip->nHeight, 102);

    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, recovery_root));
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(original_root);
    }
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()->GetBlockHash()) == original_hash);

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.ParkReorgBranch(recovery_root));
        chainstate.ResetBlockFailureFlags(recovery_root);
        BOOST_REQUIRE(chainman.MaybeTrackReorgRecovery(recovery_tip));
        BOOST_REQUIRE(chainman.GetReorgRecoveryRecord().has_value());
        BOOST_CHECK_EQUAL(chainman.GetReorgRecoveryRecord()->initial_reorg_depth, 2U);
        BOOST_CHECK(!chainman.IsOnParkedReorgBranch(recovery_tip));

        // Exercise the same durable decode and provenance validation used by a
        // restart before activation.
        BOOST_REQUIRE(chainman.LoadReorgRecoveryRecord());
        BOOST_REQUIRE(chainman.NormalizeReorgRecovery(chainstate.m_chain.Tip()));
        BOOST_CHECK(chainman.GetReorgRecoveryRecord().has_value());
    }

    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip(), recovery_tip);
        BOOST_CHECK(!chainman.GetReorgRecoveryRecord().has_value());
        BOOST_CHECK(!chainman.IsOnParkedReorgBranch(recovery_tip));
    }
}

BOOST_FIXTURE_TEST_CASE(chainstate_equal_authenticated_sibling_cannot_freeze_tip_growth, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    auto& action = const_cast<kernel::DeepReorgAction&>(chainman.m_options.deep_reorg_action);
    auto& park_depth = const_cast<std::optional<uint32_t>&>(chainman.m_options.max_reorg_depth_park);
    auto& mode = const_cast<kernel::MatMulValidationMode&>(chainman.m_options.matmul_validation_mode);
    const int32_t saved_start{consensus.nReorgProtectionStartHeight};
    const auto saved_action{action};
    const auto saved_depth{park_depth};
    const auto saved_mode{mode};
    struct Restore {
        Consensus::Params& consensus;
        int32_t start;
        kernel::DeepReorgAction& action;
        kernel::DeepReorgAction saved_action;
        std::optional<uint32_t>& depth;
        std::optional<uint32_t> saved_depth;
        kernel::MatMulValidationMode& mode;
        kernel::MatMulValidationMode saved_mode;
        ~Restore()
        {
            node::matmul_trusted::ResetForTest();
            consensus.nReorgProtectionStartHeight = start;
            action = saved_action;
            depth = saved_depth;
            mode = saved_mode;
        }
    } restore{consensus, saved_start, action, saved_action, park_depth, saved_depth, mode, saved_mode};
    consensus.nReorgProtectionStartHeight = 10;
    action = kernel::DeepReorgAction::PARK;
    park_depth = 2;

    const CScript script = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CBlockIndex* original_root;
    CBlockIndex* original_tip;
    {
        LOCK(::cs_main);
        original_tip = chainstate.m_chain.Tip();
        original_root = original_tip;
    }
    const uint256 original_hash{original_tip->GetBlockHash()};
    BlockValidationState state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, original_root));
    const CBlock sibling_block{CreateAndProcessBlock({}, script)};
    CBlockIndex* sibling;
    {
        LOCK(::cs_main);
        sibling = chainman.m_blockman.LookupBlockIndex(sibling_block.GetHash());
    }
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, sibling));
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(original_root);
    }
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()->GetBlockHash()) == original_hash);

    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::ONE;
    config.replay_authority_context = uint256::FromHex(std::string(64, 'b')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    mode = kernel::MatMulValidationMode::TRUSTED;
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      sibling->GetBlockHash(), sibling->nHeight) ==
                  matmul::trusted::AddResult::Accepted);
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(sibling);
        BOOST_REQUIRE(chainman.MaybeTrackReorgRecovery(sibling));
        BOOST_CHECK(!chainman.GetReorgRecoveryRecord().has_value());
    }

    const CBlock extension{CreateAndProcessBlock({}, script)};
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()->GetBlockHash()) == extension.GetHash());
}

BOOST_FIXTURE_TEST_CASE(chainstate_current_authority_recovers_long_shallow_race_with_existing_data, TestChain100Setup)
{
    using namespace std::chrono_literals;
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    auto& action = const_cast<kernel::DeepReorgAction&>(chainman.m_options.deep_reorg_action);
    auto& park_depth = const_cast<std::optional<uint32_t>&>(chainman.m_options.max_reorg_depth_park);
    auto& mode = const_cast<kernel::MatMulValidationMode&>(chainman.m_options.matmul_validation_mode);
    struct Restore {
        Consensus::Params& consensus;
        int32_t start;
        kernel::DeepReorgAction& action;
        kernel::DeepReorgAction saved_action;
        std::optional<uint32_t>& depth;
        std::optional<uint32_t> saved_depth;
        kernel::MatMulValidationMode& mode;
        kernel::MatMulValidationMode saved_mode;
        ~Restore()
        {
            node::matmul_trusted::ResetForTest();
            consensus.nReorgProtectionStartHeight = start;
            action = saved_action;
            depth = saved_depth;
            mode = saved_mode;
        }
    } restore{consensus, consensus.nReorgProtectionStartHeight,
              action, action, park_depth, park_depth, mode, mode};
    consensus.nReorgProtectionStartHeight = 10;
    action = kernel::DeepReorgAction::PARK;
    park_depth = 2;

    const CScript script = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CBlockIndex* original_root;
    CBlockIndex* original_tip;
    {
        LOCK(::cs_main);
        original_tip = chainstate.m_chain.Tip();
        original_root = chainstate.m_chain[99];
    }
    const uint256 original_hash{original_tip->GetBlockHash()};
    BlockValidationState state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, original_root));
    CBlockIndex* recovery_root{nullptr};
    CBlockIndex* recovery_tip{nullptr};
    for (int i = 0; i < 10; ++i) {
        const CBlock block{CreateAndProcessBlock({}, script)};
        LOCK(::cs_main);
        recovery_tip = chainman.m_blockman.LookupBlockIndex(block.GetHash());
        if (i == 0) recovery_root = recovery_tip;
    }
    BOOST_REQUIRE(recovery_root && recovery_tip);
    BOOST_REQUIRE_GT(recovery_tip->nHeight - original_tip->nHeight,
                     static_cast<int>(TRUST_ADJUSTED_WORK_ALLOWANCE_BLOCKS));

    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, recovery_root));
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(original_root);
    }
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()->GetBlockHash()) == original_hash);

    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::ONE;
    config.replay_authority_context = uint256::FromHex(std::string(64, 'a')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true, /*serve=*/false, 50ms, error));
    mode = kernel::MatMulValidationMode::TRUSTED;
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      recovery_tip->GetBlockHash(), recovery_tip->nHeight) ==
                  matmul::trusted::AddResult::Accepted);

    uint32_t saved_recovery_status;
    int64_t saved_recovery_chain_txs;
    {
        LOCK(::cs_main);
        saved_recovery_status = recovery_tip->nStatus;
        saved_recovery_chain_txs = recovery_tip->m_chain_tx_count;
        // Quorum can arrive before this mirror has the body. Arming must not
        // wait for HAVE_DATA or the losing tip can grow beyond PARK depth while
        // the authority branch is still downloading.
        recovery_tip->nStatus =
            (recovery_tip->nStatus & ~(BLOCK_VALID_MASK | BLOCK_HAVE_DATA)) |
            BLOCK_VALID_TREE;
        recovery_tip->m_chain_tx_count = 0;
        chainman.SetBestHeader(original_tip);
        BOOST_CHECK(chainman.m_best_header != recovery_tip);
        BOOST_REQUIRE(chainman.ParkReorgBranch(recovery_root));
        BOOST_REQUIRE(chainman.MaybeTrackReorgRecovery(recovery_tip));
        BOOST_CHECK_EQUAL(chainman.m_best_header, recovery_tip);
        BOOST_CHECK_EQUAL(chainman.BestFollowedHeaderHeight(),
                          recovery_tip->nHeight);
        const auto record{chainman.GetReorgRecoveryRecord()};
        BOOST_REQUIRE(record.has_value());
        BOOST_CHECK_EQUAL(record->mode, static_cast<uint8_t>(
            node::ReorgRecoveryRecord::Mode::TRUSTED_AUTHORITY));
        BOOST_CHECK_EQUAL(record->initial_reorg_depth, 2U);
        BOOST_CHECK(chainman.IsOnParkedReorgBranch(recovery_tip));
        BOOST_REQUIRE(chainman.LoadReorgRecoveryRecord());
        chainman.SetBestHeader(original_tip);
        BOOST_REQUIRE(chainman.NormalizeReorgRecovery(chainstate.m_chain.Tip()));
        BOOST_CHECK(chainman.GetReorgRecoveryRecord().has_value());
        BOOST_CHECK_EQUAL(chainman.m_best_header, recovery_tip);
        BOOST_CHECK_EQUAL(chainman.BestFollowedHeaderHeight(),
                          recovery_tip->nHeight);

        // Candidate filtering must freeze activation on the losing side while
        // the authority body is still unavailable.
        CBlockIndex losing_extension;
        losing_extension.pprev = original_tip;
        losing_extension.nHeight = original_tip->nHeight + 1;
        losing_extension.BuildSkip();
        BOOST_CHECK(chainman.ShouldDeferLosingTipExtension(&losing_extension));

        recovery_tip->nStatus = saved_recovery_status |
                                BLOCK_TRUSTED_REPLAY_ATTESTED;
        recovery_tip->m_chain_tx_count = saved_recovery_chain_txs;
        chainstate.ResetBlockFailureFlags(recovery_root);
        BOOST_REQUIRE(chainman.MaybeTrackReorgRecovery(recovery_tip));
        BOOST_CHECK(!chainman.IsOnParkedReorgBranch(recovery_tip));

        // Invalidation/reconsider and startup both rebuild best-header state.
        // With peer provenance unavailable, current-config quorum ancestry is
        // the authoritative predicate and publication must move with it.
        chainman.SetBestHeader(original_tip);
        chainman.RecalculateBestHeader();
        BOOST_CHECK_EQUAL(chainman.m_best_header, recovery_tip);
        BOOST_CHECK_EQUAL(chainman.BestFollowedHeaderHeight(),
                          recovery_tip->nHeight);
    }

    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip(), recovery_tip);
        BOOST_CHECK(!chainman.GetReorgRecoveryRecord().has_value());
    }
}

BOOST_FIXTURE_TEST_CASE(chainstate_normalizes_park_roots_against_active_tip_and_policy, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    auto& action =
        const_cast<kernel::DeepReorgAction&>(chainman.m_options.deep_reorg_action);
    const kernel::DeepReorgAction saved_action = action;
    struct RestoreAction {
        kernel::DeepReorgAction& action;
        kernel::DeepReorgAction saved;
        ~RestoreAction() { action = saved; }
    } restore{action, saved_action};

    LOCK(::cs_main);
    CBlockIndex* const active_tip = chainman.ActiveChainstate().m_chain.Tip();
    BOOST_REQUIRE(active_tip != nullptr);

    action = kernel::DeepReorgAction::PARK;
    BOOST_CHECK(!chainman.ParkReorgBranch(active_tip));
    BOOST_CHECK(chainman.GetParkedReorgBranchRoots().empty());
    BOOST_CHECK(!chainman.IsOnParkedReorgBranch(active_tip));

    // A root left by a prior PARK profile must also be retired atomically when
    // the operator restarts under a warn-only profile, or PARK -> WARN -> PARK
    // can resurrect a stale refusal later. Active-chain roots are now refused
    // at insert time; Normalize of an empty set under WARN stays empty.
    action = kernel::DeepReorgAction::WARN;
    BOOST_REQUIRE(chainman.NormalizeParkedReorgBranches(active_tip));
    BOOST_CHECK(chainman.GetParkedReorgBranchRoots().empty());
}

BOOST_FIXTURE_TEST_CASE(chainstate_reports_shared_recovery_phase, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    LOCK(::cs_main);
    CBlockIndex* const active_tip = chainman.ActiveChainstate().m_chain.Tip();
    BOOST_REQUIRE(active_tip != nullptr);
    CBlockIndex* const saved_best_header = chainman.m_best_header;
    struct RestoreBestHeader {
        ChainstateManager& chainman;
        CBlockIndex* saved;
        ~RestoreBestHeader() { chainman.SetBestHeader(saved); }
    } restore{chainman, saved_best_header};

    chainman.SetBestHeader(active_tip);
    BOOST_CHECK_EQUAL(chainman.BestFollowedHeaderHeight(), active_tip->nHeight);
    auto state = chainman.GetChainRecoveryState();
    BOOST_CHECK(state.phase == ChainRecoveryPhase::CONVERGED);
    BOOST_CHECK_EQUAL(state.followed_target, active_tip);

    CBlockIndex extension;
    extension.pprev = active_tip;
    extension.nHeight = active_tip->nHeight + 1;
    extension.BuildSkip();
    chainman.SetBestHeader(&extension);
    BOOST_CHECK_EQUAL(chainman.BestFollowedHeaderHeight(), extension.nHeight);
    state = chainman.GetChainRecoveryState();
    BOOST_CHECK(state.phase == ChainRecoveryPhase::CHASING);
    BOOST_CHECK_EQUAL(state.fork, active_tip);

    CBlockIndex* const fork = chainman.ActiveChain()[active_tip->nHeight - 2];
    BOOST_REQUIRE(fork != nullptr);
    CBlockIndex alternative[3];
    CBlockIndex* parent = fork;
    for (CBlockIndex& index : alternative) {
        index.pprev = parent;
        index.nHeight = parent->nHeight + 1;
        index.BuildSkip();
        parent = &index;
    }
    chainman.SetBestHeader(&alternative[2]);
    BOOST_CHECK_EQUAL(chainman.BestFollowedHeaderHeight(), alternative[2].nHeight);
    state = chainman.GetChainRecoveryState();
    BOOST_CHECK(state.phase == ChainRecoveryPhase::RECOVERING_REORG);
    BOOST_CHECK_EQUAL(state.followed_target, &alternative[2]);
    BOOST_CHECK_EQUAL(state.fork, fork);
    BOOST_CHECK_EQUAL(state.reorg_depth, 2U);
}

BOOST_FIXTURE_TEST_CASE(chainstate_shallow_reorg_hysteresis_defers_until_work_margin, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));

    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    auto& deep_reorg_action = const_cast<kernel::DeepReorgAction&>(chainman.m_options.deep_reorg_action);
    auto& max_reorg_depth_park = const_cast<std::optional<uint32_t>&>(chainman.m_options.max_reorg_depth_park);
    auto& hysteresis_depth = const_cast<std::optional<uint32_t>&>(chainman.m_options.reorg_hysteresis_depth);
    auto& hysteresis_work_margin = const_cast<std::optional<uint32_t>&>(chainman.m_options.reorg_hysteresis_work_margin);
    struct RestoreReorgOptions
    {
        Consensus::Params& consensus;
        int32_t saved_reorg_start_height;
        kernel::DeepReorgAction& action;
        kernel::DeepReorgAction saved_action;
        std::optional<uint32_t>& park_depth;
        std::optional<uint32_t> saved_park_depth;
        std::optional<uint32_t>& hysteresis_depth;
        std::optional<uint32_t> saved_hysteresis_depth;
        std::optional<uint32_t>& hysteresis_work_margin;
        std::optional<uint32_t> saved_hysteresis_work_margin;
        ~RestoreReorgOptions()
        {
            consensus.nReorgProtectionStartHeight = saved_reorg_start_height;
            action = saved_action;
            park_depth = saved_park_depth;
            hysteresis_depth = saved_hysteresis_depth;
            hysteresis_work_margin = saved_hysteresis_work_margin;
        }
    } restore{
        consensus,
        consensus.nReorgProtectionStartHeight,
        deep_reorg_action,
        deep_reorg_action,
        max_reorg_depth_park,
        max_reorg_depth_park,
        hysteresis_depth,
        hysteresis_depth,
        hysteresis_work_margin,
        hysteresis_work_margin};

    consensus.nReorgProtectionStartHeight = 10;
    deep_reorg_action = kernel::DeepReorgAction::PARK;
    max_reorg_depth_park = 12;
    hysteresis_depth = 0;
    hysteresis_work_margin = 2;

    CBlockIndex* fork{nullptr};
    CBlockIndex* original_branch_first{nullptr};
    CBlockIndex* original_tip{nullptr};
    {
        LOCK(::cs_main);
        original_tip = chainstate.m_chain.Tip();
        BOOST_REQUIRE(original_tip != nullptr);
        fork = original_tip->pprev;
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
    for (int i = 0; i < 2; ++i) {
        const CBlock competing_block = CreateAndProcessBlock({}, script_pub_key);
        LOCK(::cs_main);
        CBlockIndex* tip = chainstate.m_chain.Tip();
        BOOST_REQUIRE(tip != nullptr);
        BOOST_REQUIRE_EQUAL(tip->GetBlockHash(), competing_block.GetHash());
        if (i == 0) competing_root = tip;
        if (i == 1) competing_tip = tip;
    }
    BOOST_REQUIRE(competing_root != nullptr);
    BOOST_REQUIRE(competing_tip != nullptr);
    BOOST_REQUIRE_EQUAL(competing_tip->nHeight, original_height + 1);

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
        chainstate.ResetBlockFailureFlags(competing_root);
        BOOST_REQUIRE_EQUAL(chainstate.setBlockIndexCandidates.count(competing_tip), 1);
    }

    ResetReorgProtectionRuntimeStats();
    BlockValidationState deferred_state;
    BOOST_CHECK(chainstate.ActivateBestChain(deferred_state));
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip()->GetBlockHash(), original_tip_hash);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Height(), original_height);
        BOOST_CHECK(!chainman.IsOnParkedReorgBranch(competing_tip));
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(competing_tip), 1);
    }
    auto stats = ProbeReorgProtectionRuntimeStats();
    BOOST_CHECK_EQUAL(stats.deferred_reorgs, 1U);
    BOOST_CHECK_EQUAL(stats.last_deferred_reorg_depth, 1U);
    BOOST_CHECK_EQUAL(stats.last_deferred_required_work_margin, 2U);
    BOOST_CHECK_EQUAL(stats.rejected_reorgs, 0U);

    hysteresis_work_margin = 1;
    ResetReorgProtectionRuntimeStats();
    BlockValidationState adopted_state;
    BOOST_CHECK(chainstate.ActivateBestChain(adopted_state));
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip()->GetBlockHash(), competing_tip->GetBlockHash());
        BOOST_CHECK_EQUAL(chainstate.m_chain.Height(), original_height + 1);
    }
    stats = ProbeReorgProtectionRuntimeStats();
    BOOST_CHECK_EQUAL(stats.deferred_reorgs, 0U);
    BOOST_CHECK_EQUAL(stats.observed_reorgs, 1U);
    BOOST_CHECK_EQUAL(stats.last_observed_reorg_depth, 1U);
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
    auto& hysteresis_work_margin = const_cast<std::optional<uint32_t>&>(chainman.m_options.reorg_hysteresis_work_margin);
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
        std::optional<uint32_t>& hysteresis_work_margin;
        std::optional<uint32_t> saved_hysteresis_work_margin;
        ~RestoreParams()
        {
            consensus.nReorgProtectionStartHeight = reorg_start_height;
            deep_reorg_action = saved_deep_reorg_action;
            warn_depth = saved_warn_depth;
            park_depth = saved_park_depth;
            hysteresis_work_margin = saved_hysteresis_work_margin;
        }
    } restore{consensus, consensus.nReorgProtectionStartHeight,
              deep_reorg_action, deep_reorg_action,
              max_reorg_depth_warn, max_reorg_depth_warn,
              max_reorg_depth_park, max_reorg_depth_park,
              hysteresis_work_margin, hysteresis_work_margin};
    deep_reorg_action = kernel::DeepReorgAction::WARN;
    BOOST_REQUIRE(chainman.m_options.deep_reorg_action == kernel::DeepReorgAction::WARN);

    // Any cross-fork switch deeper than one block trips the warning; tip is already >= 10.
    consensus.nReorgProtectionStartHeight = 10;
    max_reorg_depth_warn = 1;
    max_reorg_depth_park = 1;
    // This test isolates WARN-mode deep-reorg behavior. Production defaults
    // keep hysteresis on so shallow late branches need extra work first.
    hysteresis_work_margin = 0;

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

//! FindMostWorkChain erases unattested competing HAVE_DATA tips from
//! setBlockIndexCandidates on a trusted mirror (intentional gate). CheckBlockIndex
//! must not require those blocks back into the set. Parked branches stay exempt,
//! and a tip-extending child remains a candidate.
BOOST_FIXTURE_TEST_CASE(chainstate_trusted_mirror_gate_evicted_candidate_survives_checkblockindex, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    auto& action = const_cast<kernel::DeepReorgAction&>(chainman.m_options.deep_reorg_action);
    auto& park_depth = const_cast<std::optional<uint32_t>&>(chainman.m_options.max_reorg_depth_park);
    auto& hysteresis_work_margin = const_cast<std::optional<uint32_t>&>(chainman.m_options.reorg_hysteresis_work_margin);
    struct Restore {
        Consensus::Params& consensus;
        int32_t start;
        kernel::DeepReorgAction& action;
        kernel::DeepReorgAction saved_action;
        std::optional<uint32_t>& park_depth;
        std::optional<uint32_t> saved_park_depth;
        std::optional<uint32_t>& hysteresis_work_margin;
        std::optional<uint32_t> saved_hysteresis_work_margin;
        ~Restore()
        {
            node::matmul_trusted::ResetForTest();
            consensus.nReorgProtectionStartHeight = start;
            action = saved_action;
            park_depth = saved_park_depth;
            hysteresis_work_margin = saved_hysteresis_work_margin;
        }
    } restore{consensus, consensus.nReorgProtectionStartHeight,
              action, action, park_depth, park_depth,
              hysteresis_work_margin, hysteresis_work_margin};
    consensus.nReorgProtectionStartHeight = 10;
    action = kernel::DeepReorgAction::PARK;
    // Keep park deeper than this short competing fork so the trusted-mirror
    // most-work gate is what evicts the candidate, not PARK.
    park_depth = 100;
    hysteresis_work_margin = 0;

    const CScript script = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CBlockIndex* original_tip{nullptr};
    CBlockIndex* original_root{nullptr};
    {
        LOCK(::cs_main);
        original_tip = chainstate.m_chain.Tip();
        original_root = original_tip;
    }
    BOOST_REQUIRE(original_tip != nullptr);
    const uint256 original_hash{original_tip->GetBlockHash()};
    const int original_height{original_tip->nHeight};

    BlockValidationState state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, original_root));
    CBlockIndex* competing_root{nullptr};
    CBlockIndex* competing_tip{nullptr};
    for (int i = 0; i < 2; ++i) {
        const CBlock block{CreateAndProcessBlock({}, script)};
        LOCK(::cs_main);
        competing_tip = chainman.m_blockman.LookupBlockIndex(block.GetHash());
        if (i == 0) competing_root = competing_tip;
    }
    BOOST_REQUIRE(competing_root && competing_tip);
    BOOST_REQUIRE_EQUAL(competing_tip->nHeight, original_height + 1);

    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, competing_root));
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(original_root);
    }
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()->GetBlockHash()) == original_hash);

    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(competing_root);
        BOOST_REQUIRE_EQUAL(chainstate.setBlockIndexCandidates.count(competing_tip), 1);
        BOOST_REQUIRE(competing_tip->nStatus & BLOCK_HAVE_DATA);
        BOOST_REQUIRE(competing_tip->nChainWork > original_tip->nChainWork);
    }

    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::ONE;
    config.replay_authority_context = uint256::FromHex(std::string(64, 'c')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::IsTrustedMirror());
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      original_hash, original_height) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_REQUIRE(node::matmul_trusted::HasQuorum(original_hash, original_height));

    state = BlockValidationState{};
    BOOST_CHECK(chainstate.ActivateBestChain(state));
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip()->GetBlockHash(), original_hash);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Height(), original_height);
        BOOST_CHECK(!chainman.IsOnParkedReorgBranch(competing_tip));
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(competing_tip), 0);
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(original_tip), 1);
        BOOST_CHECK(!chainman.ShouldDeferLosingTipExtension(competing_tip));
    }
    chainman.CheckBlockIndex();

    const CBlock child{CreateAndProcessBlock({}, script)};
    CBlockIndex* child_index{nullptr};
    {
        LOCK(::cs_main);
        child_index = chainman.m_blockman.LookupBlockIndex(child.GetHash());
        BOOST_REQUIRE(child_index != nullptr);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip(), child_index);
        BOOST_CHECK_EQUAL(child_index->pprev, original_tip);
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(child_index), 1);
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(competing_tip), 0);
    }
    const auto child_attested{node::matmul_trusted::SignAuthoritative(
        child.GetHash(), child_index->nHeight)};
    BOOST_REQUIRE(child_attested == matmul::trusted::AddResult::Accepted ||
                  child_attested == matmul::trusted::AddResult::Duplicate);
    BOOST_CHECK(node::matmul_trusted::HasQuorum(
        child.GetHash(), child_index->nHeight));
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(child_index), 1);
    }
    chainman.CheckBlockIndex();

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.ParkReorgBranch(competing_root));
        BOOST_CHECK(chainman.IsOnParkedReorgBranch(competing_tip));
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(competing_tip), 0);
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(child_index), 1);
    }
    chainman.CheckBlockIndex();

    // Parked exemption must still apply when the trusted-mirror gate is off.
    node::matmul_trusted::ResetForTest();
    {
        LOCK(::cs_main);
        BOOST_CHECK(chainman.IsOnParkedReorgBranch(competing_tip));
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(competing_tip), 0);
    }
    chainman.CheckBlockIndex();
}

BOOST_AUTO_TEST_SUITE_END()
