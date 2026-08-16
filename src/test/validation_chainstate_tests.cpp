// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <addresstype.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <node/kernel_notifications.h>
#include <matmul/trusted_exact_replay_attestation.h>
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

#include <memory>
#include <optional>
#include <chrono>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {
//! Ingest a signature that already exists (historical dual-attest). This is
//! Add(), not SignAuthoritative: the local signer must not mint a second
//! hash at a height it already signed.
[[nodiscard]] matmul::trusted::AddResult InjectHistoricalAttestation(
    const CKey& signer,
    const uint256& chain_id,
    const uint256& replay_authority_context,
    const uint256& block_hash,
    int32_t height)
{
    matmul::trusted::ExactReplayStatement statement;
    statement.chain_id = chain_id;
    statement.block_hash = block_hash;
    statement.block_height = height;
    statement.replay_authority_context = replay_authority_context;
    const auto attestation{
        matmul::trusted::SignStatement(statement, signer)};
    if (!attestation.has_value()) {
        return matmul::trusted::AddResult::InvalidSigner;
    }
    return node::matmul_trusted::Add(*attestation, block_hash, height);
}
} // namespace

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
    // Live miner report: lost a same-height race, stayed on the unattested
    // sibling, attested chain advanced, node never reorged. An equal-work
    // attested HAVE_DATA sibling must become tip; growth then continues on
    // that chain (this is not a freeze — it is race-loss convergence).
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
    // Production mining path: consensus + pubkey, not a trusted mirror.
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/false, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    mode = kernel::MatMulValidationMode::CONSENSUS;
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      sibling->GetBlockHash(), sibling->nHeight) ==
                  matmul::trusted::AddResult::Accepted);
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(sibling);
        BOOST_REQUIRE(sibling->nChainWork == original_tip->nChainWork);
        BOOST_CHECK_EQUAL(chainman.FindUniqueCompetingAttestedIndex(), sibling);
        BOOST_CHECK(chainman.IsAttestedAbandonForkCandidate(sibling));
        BOOST_REQUIRE(chainman.MaybeTrackReorgRecovery(sibling));
        BOOST_CHECK(!chainman.GetReorgRecoveryRecord().has_value());
    }

    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == sibling);

    const CBlock extension{CreateAndProcessBlock({}, script)};
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip()->GetBlockHash(), extension.GetHash());
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip()->pprev, sibling);
        BOOST_CHECK(chainman.FindUniqueCompetingAttestedIndex() == nullptr);
    }
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
        // A followed validator-chain child of the live tip must not be frozen
        // (live 2026-08-15: 2fd67f18). A competing sibling still is.
        CBlockIndex followed_child;
        followed_child.pprev = original_tip;
        followed_child.nHeight = original_tip->nHeight + 1;
        followed_child.nStatus = BLOCK_VALID_TREE;
        followed_child.BuildSkip();
        chainman.SetBestHeader(&followed_child);
        BOOST_CHECK(chainman.IndexIsFollowedTipChild(original_tip, &followed_child));
        BOOST_CHECK(!chainman.ShouldDeferLosingTipExtension(&followed_child));
        BOOST_CHECK(chainman.ShouldDeferLosingTipExtension(&losing_extension));
        chainman.SetBestHeader(recovery_tip);

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

BOOST_FIXTURE_TEST_CASE(chainstate_unattested_heavier_tip_abandons_for_attested, TestChain100Setup)
{
    // Operator report: a node already sitting on a heavier unattested fork
    // did not reorg back; they had to invalidateblock the fork by hand.
    // With a unique competing attested HAVE_DATA chain, ActivateBestChain
    // must abandon the unattested tip even when it has more work.
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
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == competing_tip);

    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(original_root);
        BOOST_REQUIRE(original_tip->nStatus & BLOCK_HAVE_DATA);
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
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      original_hash, original_height) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_REQUIRE(node::matmul_trusted::HasQuorum(original_hash, original_height));
    BOOST_CHECK(!node::matmul_trusted::HasQuorum(
        competing_tip->GetBlockHash(), competing_tip->nHeight));

    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(
            chainman.FindUniqueCompetingAttestedIndex(), original_tip);
        BOOST_CHECK(chainman.IsAttestedAbandonForkCandidate(original_tip));
        BOOST_CHECK_EQUAL(chainman.FindBestKnownAttestedIndex(), original_tip);
    }

    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip()->GetBlockHash(), original_hash);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Height(), original_height);
        BOOST_CHECK(!chainman.IsOnParkedReorgBranch(original_tip));
        // Live 2026-08-14: after snapshot / ABC recovery, m_best_header can
        // still sit on the heavier unattested flood. RecalculateBestHeader
        // must snap download onto the active attested tip-chain.
        BOOST_REQUIRE(competing_tip->nChainWork > original_tip->nChainWork);
        chainman.SetBestHeader(competing_tip);
        BOOST_CHECK_EQUAL(chainman.m_best_header, competing_tip);
        chainman.RecalculateBestHeader();
        BOOST_REQUIRE(chainman.m_best_header != nullptr);
        BOOST_CHECK_EQUAL(
            chainman.m_best_header->GetAncestor(original_height), original_tip);
        BOOST_CHECK(chainman.m_best_header != competing_tip);
    }
    chainman.CheckBlockIndex();
}

BOOST_FIXTURE_TEST_CASE(chainstate_trusted_mirror_persists_unattested_tip_child_without_connecting, TestChain100Setup)
{
    // Production chicken-egg: trusted archives dropped miner tip-children
    // before HAVE_DATA because ContextualCheckBlock failed closed without
    // quorum, so a consensus signer peered only with archives never saw the
    // bodies and never attested. Persist the tip-child body; ConnectTip must
    // still refuse until HasQuorum (via TrustedMirrorMustDeferUnattestedConnect).
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    auto& mode = const_cast<kernel::MatMulValidationMode&>(chainman.m_options.matmul_validation_mode);
    const int32_t saved_v4{consensus.nMatMulV4Height};
    const int32_t saved_bmx{consensus.nMatMulBMX4CHeight};
    const int32_t saved_rc{consensus.nMatMulRCHeight};
    const auto saved_mode{mode};
    struct Restore {
        Consensus::Params& consensus;
        int32_t v4;
        int32_t bmx;
        int32_t rc;
        kernel::MatMulValidationMode& mode;
        kernel::MatMulValidationMode saved_mode;
        ~Restore()
        {
            node::matmul_trusted::ResetForTest();
            consensus.nMatMulV4Height = v4;
            consensus.nMatMulBMX4CHeight = bmx;
            consensus.nMatMulRCHeight = rc;
            mode = saved_mode;
        }
    } restore{consensus, saved_v4, saved_bmx, saved_rc, mode, saved_mode};

    const CScript script = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CBlockIndex* parent_tip{WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE(parent_tip != nullptr);
    const uint256 parent_hash{parent_tip->GetBlockHash()};
    const int parent_height{parent_tip->nHeight};
    const int32_t child_height{parent_height + 1};

    consensus.nMatMulV4Height = child_height;
    consensus.nMatMulBMX4CHeight = child_height;
    consensus.nMatMulRCHeight = child_height;
    BOOST_REQUIRE(consensus.IsMatMulTrustedReplayAttestationActive(child_height));

    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::ONE;
    config.replay_authority_context = uint256::FromHex(std::string(64, 'e')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    mode = kernel::MatMulValidationMode::TRUSTED;
    BOOST_REQUIRE(node::matmul_trusted::IsTrustedMirror());
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      parent_hash, parent_height) ==
                  matmul::trusted::AddResult::Accepted);

    const auto pblock{std::make_shared<const CBlock>(CreateBlock({}, script, chainstate))};
    const uint256 child_hash{pblock->GetHash()};
    BOOST_CHECK(!node::matmul_trusted::HasQuorum(child_hash, child_height));

    bool new_block{false};
    BOOST_REQUIRE(chainman.ProcessNewBlock(pblock, /*force_processing=*/true,
                                           /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(new_block);
    CBlockIndex* child_index{nullptr};
    {
        LOCK(::cs_main);
        child_index = chainman.m_blockman.LookupBlockIndex(child_hash);
        BOOST_REQUIRE(child_index != nullptr);
        BOOST_CHECK(child_index->nStatus & BLOCK_HAVE_DATA);
        BOOST_CHECK(child_index->IsValid(BLOCK_VALID_TRANSACTIONS));
        BOOST_CHECK(!(child_index->nStatus & BLOCK_FAILED_MASK));
        BOOST_CHECK_EQUAL(child_index->pprev, parent_tip);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip(), parent_tip);
        BOOST_CHECK(!chainstate.m_chain.Contains(child_index));
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(child_index), 1);
        // Qualifier 3ed2619c follow-up: candidate set is exactly the attested
        // active tip plus this sole linear child (getchaintips height 11
        // active / height 12 valid-headers, same parent, no competing
        // branch). The tip must not count as an attested sibling.
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(parent_tip), 1);
        BOOST_CHECK_EQUAL(chainstate.FindMostWorkChainForTest(), child_index);
        BOOST_CHECK_EQUAL(chainstate.FindMostWorkChainForTest(), child_index);
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(child_index), 1);
        {
            const auto stalled{chainman.GetSignedFrontierStatus()};
            BOOST_REQUIRE(stalled.available);
            BOOST_CHECK(stalled.on_active_chain);
            BOOST_CHECK_EQUAL(stalled.blocks_behind, 0);
        }
        BOOST_CHECK(node::matmul_trusted::TrustedMirrorMustDeferUnattestedConnect(
            /*trusted_mirror_profile1=*/true, /*has_quorum=*/false));
    }
    chainman.CheckBlockIndex();

    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      child_hash, child_height) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(node::matmul_trusted::HasQuorum(child_hash, child_height));

    BlockValidationState state;
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip(), child_index);
        BOOST_CHECK(chainstate.m_chain.Contains(child_index));
    }
    chainman.CheckBlockIndex();
}

BOOST_FIXTURE_TEST_CASE(chainstate_trusted_mirror_connects_attested_sibling_not_heavier_unattested, TestChain100Setup)
{
    // Live 2026-08-14 fra1: two tip-children of 187931. Attested a18786b0
    // sat in the candidate set while FindMostWorkChain kept returning
    // unattested 39c12144. ConnectTip deferred that one, ABC stopped, and
    // the advertised seed height froze at the parent.
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    auto& mode = const_cast<kernel::MatMulValidationMode&>(chainman.m_options.matmul_validation_mode);
    const int32_t saved_v4{consensus.nMatMulV4Height};
    const int32_t saved_bmx{consensus.nMatMulBMX4CHeight};
    const int32_t saved_rc{consensus.nMatMulRCHeight};
    const auto saved_mode{mode};
    struct Restore {
        Consensus::Params& consensus;
        int32_t v4;
        int32_t bmx;
        int32_t rc;
        kernel::MatMulValidationMode& mode;
        kernel::MatMulValidationMode saved_mode;
        ~Restore()
        {
            node::matmul_trusted::ResetForTest();
            consensus.nMatMulV4Height = v4;
            consensus.nMatMulBMX4CHeight = bmx;
            consensus.nMatMulRCHeight = rc;
            mode = saved_mode;
        }
    } restore{consensus, saved_v4, saved_bmx, saved_rc, mode, saved_mode};

    const CScript script = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CKey other;
    other.MakeNewKey(/*fCompressed=*/true);
    const CScript script_alt = GetScriptForDestination(PKHash(other.GetPubKey()));
    CBlockIndex* parent_tip{WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE(parent_tip != nullptr);
    const uint256 parent_hash{parent_tip->GetBlockHash()};
    const int parent_height{parent_tip->nHeight};
    const int32_t child_height{parent_height + 1};

    consensus.nMatMulV4Height = child_height;
    consensus.nMatMulBMX4CHeight = child_height;
    consensus.nMatMulRCHeight = child_height;

    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::ONE;
    config.replay_authority_context = uint256::FromHex(std::string(64, 'f')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    mode = kernel::MatMulValidationMode::TRUSTED;
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      parent_hash, parent_height) ==
                  matmul::trusted::AddResult::Accepted);

    const auto unattested{std::make_shared<const CBlock>(
        CreateBlock({}, script, chainstate))};
    bool new_block{false};
    BOOST_REQUIRE(chainman.ProcessNewBlock(
        unattested, /*force_processing=*/true, /*min_pow_checked=*/true,
        &new_block));
    const auto attested{std::make_shared<const CBlock>(
        CreateBlock({}, script_alt, chainstate))};
    BOOST_REQUIRE(attested->GetHash() != unattested->GetHash());
    BOOST_REQUIRE(chainman.ProcessNewBlock(
        attested, /*force_processing=*/true, /*min_pow_checked=*/true,
        &new_block));

    CBlockIndex* unattested_index{nullptr};
    CBlockIndex* attested_index{nullptr};
    {
        LOCK(::cs_main);
        unattested_index =
            chainman.m_blockman.LookupBlockIndex(unattested->GetHash());
        attested_index =
            chainman.m_blockman.LookupBlockIndex(attested->GetHash());
        BOOST_REQUIRE(unattested_index && attested_index);
        BOOST_CHECK_EQUAL(unattested_index->pprev, parent_tip);
        BOOST_CHECK_EQUAL(attested_index->pprev, parent_tip);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip(), parent_tip);
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(unattested_index), 1);
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(attested_index), 1);
    }

    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      attested->GetHash(), child_height) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(node::matmul_trusted::HasQuorum(
        attested->GetHash(), child_height));
    BOOST_CHECK(!node::matmul_trusted::HasQuorum(
        unattested->GetHash(), child_height));
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainstate.FindMostWorkChainForTest(), attested_index);
    }

    BlockValidationState state;
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip(), attested_index);
        BOOST_CHECK(!chainstate.m_chain.Contains(unattested_index));
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(unattested_index), 1);
    }
    chainman.CheckBlockIndex();
}

BOOST_FIXTURE_TEST_CASE(chainstate_trusted_mirror_defers_unattested_twin_for_headers_only_attested_sibling, TestChain100Setup)
{
    // Mirror of chainstate_trusted_mirror_connects_attested_sibling_not_heavier_unattested
    // with the attested twin headers-only. Live fra1: MMATTEST can land before
    // the body, so the sibling is absent from setBlockIndexCandidates.
    // FindMostWorkChain must still defer the unattested HAVE_DATA twin rather
    // than ConnectTip-timeout it and freeze the advertised height.
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    auto& mode = const_cast<kernel::MatMulValidationMode&>(chainman.m_options.matmul_validation_mode);
    const int32_t saved_v4{consensus.nMatMulV4Height};
    const int32_t saved_bmx{consensus.nMatMulBMX4CHeight};
    const int32_t saved_rc{consensus.nMatMulRCHeight};
    const auto saved_mode{mode};
    struct Restore {
        Consensus::Params& consensus;
        int32_t v4;
        int32_t bmx;
        int32_t rc;
        kernel::MatMulValidationMode& mode;
        kernel::MatMulValidationMode saved_mode;
        ~Restore()
        {
            node::matmul_trusted::ResetForTest();
            consensus.nMatMulV4Height = v4;
            consensus.nMatMulBMX4CHeight = bmx;
            consensus.nMatMulRCHeight = rc;
            mode = saved_mode;
        }
    } restore{consensus, saved_v4, saved_bmx, saved_rc, mode, saved_mode};

    const CScript script = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CKey other;
    other.MakeNewKey(/*fCompressed=*/true);
    const CScript script_alt = GetScriptForDestination(PKHash(other.GetPubKey()));
    CBlockIndex* parent_tip{WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE(parent_tip != nullptr);
    const uint256 parent_hash{parent_tip->GetBlockHash()};
    const int parent_height{parent_tip->nHeight};
    const int32_t child_height{parent_height + 1};

    consensus.nMatMulV4Height = child_height;
    consensus.nMatMulBMX4CHeight = child_height;
    consensus.nMatMulRCHeight = child_height;

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
        std::move(config), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    mode = kernel::MatMulValidationMode::TRUSTED;
    BOOST_REQUIRE(node::matmul_trusted::IsTrustedMirror());
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      parent_hash, parent_height) ==
                  matmul::trusted::AddResult::Accepted);

    const auto unattested{std::make_shared<const CBlock>(
        CreateBlock({}, script, chainstate))};
    bool new_block{false};
    BOOST_REQUIRE(chainman.ProcessNewBlock(
        unattested, /*force_processing=*/true, /*min_pow_checked=*/true,
        &new_block));
    const auto attested{std::make_shared<const CBlock>(
        CreateBlock({}, script_alt, chainstate))};
    BOOST_REQUIRE(attested->GetHash() != unattested->GetHash());
    BlockValidationState header_state;
    BOOST_REQUIRE(chainman.ProcessNewBlockHeaders(
        {{attested->GetBlockHeader()}}, /*min_pow_checked=*/true, header_state));

    CBlockIndex* unattested_index{nullptr};
    CBlockIndex* attested_index{nullptr};
    {
        LOCK(::cs_main);
        unattested_index =
            chainman.m_blockman.LookupBlockIndex(unattested->GetHash());
        attested_index =
            chainman.m_blockman.LookupBlockIndex(attested->GetHash());
        BOOST_REQUIRE(unattested_index && attested_index);
        BOOST_CHECK_EQUAL(unattested_index->pprev, parent_tip);
        BOOST_CHECK_EQUAL(attested_index->pprev, parent_tip);
        BOOST_CHECK(unattested_index->nStatus & BLOCK_HAVE_DATA);
        BOOST_CHECK(!(attested_index->nStatus & BLOCK_HAVE_DATA));
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip(), parent_tip);
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(unattested_index), 1);
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(attested_index), 0);
        BOOST_CHECK(chainman.FindUniqueCompetingAttestedIndex() == nullptr);
    }

    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      attested->GetHash(), child_height) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(node::matmul_trusted::HasQuorum(
        attested->GetHash(), child_height));
    BOOST_CHECK(!node::matmul_trusted::HasQuorum(
        unattested->GetHash(), child_height));
    {
        LOCK(::cs_main);
        // TRUSTED mirrors must keep proposing parent_tip here. 5e6df697
        // briefly let the unattested HAVE_DATA twin win most-work because
        // it was also m_best_header ("followed"). ABC still refused to
        // connect it; FindMostWorkChain must not propose it (PR 105
        // comment 5301061876).
        BOOST_CHECK_EQUAL(chainstate.FindMostWorkChainForTest(), parent_tip);
        BOOST_CHECK(chainman.IndexLeadsToSignedFrontier(parent_tip));
        BOOST_CHECK(chainman.IndexLeadsToSignedFrontier(attested_index));
        BOOST_CHECK(!chainman.GetSignedFrontierStatus().on_active_chain);
        // HEADER_ONLY attested child + unattested HAVE_DATA twin must not
        // put FMWC into a skip-budget spin (live 2026-08-16 miner wedge).
        for (int i = 0; i < 64; ++i) {
            BOOST_CHECK_EQUAL(chainstate.FindMostWorkChainForTest(), parent_tip);
        }
    }

    BlockValidationState state;
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip(), parent_tip);
        BOOST_CHECK(!chainstate.m_chain.Contains(unattested_index));
        BOOST_CHECK(!chainstate.m_chain.Contains(attested_index));
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(unattested_index), 1);
        BOOST_CHECK(!(attested_index->nStatus & BLOCK_HAVE_DATA));
        // HAVE_DATA gate on abandon-fork switch must stay in place.
        BOOST_CHECK(chainman.FindUniqueCompetingAttestedIndex() == nullptr);
    }
    chainman.CheckBlockIndex();

    BOOST_REQUIRE(chainman.ProcessNewBlock(
        attested, /*force_processing=*/true, /*min_pow_checked=*/true,
        &new_block));
    {
        LOCK(::cs_main);
        BOOST_CHECK(attested_index->nStatus & BLOCK_HAVE_DATA);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip(), attested_index);
        BOOST_CHECK(!chainstate.m_chain.Contains(unattested_index));
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(unattested_index), 1);
    }
    chainman.CheckBlockIndex();
}

BOOST_FIXTURE_TEST_CASE(chainstate_signed_frontier_lag_detects_off_chain_quorum, TestChain100Setup)
{
    // Live miner misread: getmatmulattestedtip.hash/on_active_chain stay
    // healthy on a stranded fork because they only see HAVE_DATA on this
    // chain. An off-chain stored quorum must raise blocks_behind.
    ChainstateManager& chainman = *Assert(m_node.chainman);
    CBlockIndex* tip{WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    const uint256 tip_hash{tip->GetBlockHash()};
    const int tip_height{tip->nHeight};

    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::ONE;
    config.replay_authority_context = uint256::FromHex(std::string(64, '7')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/false, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    struct Reset {
        ~Reset() { node::matmul_trusted::ResetForTest(); }
    } reset;

    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      tip_hash, tip_height) ==
                  matmul::trusted::AddResult::Accepted);
    {
        LOCK(::cs_main);
        const auto on_chain{chainman.GetSignedFrontierStatus()};
        BOOST_REQUIRE(on_chain.available);
        BOOST_CHECK_EQUAL(on_chain.height, tip_height);
        BOOST_CHECK(on_chain.on_active_chain);
        BOOST_CHECK_EQUAL(on_chain.on_chain_attested_height, tip_height);
        BOOST_CHECK_EQUAL(on_chain.blocks_behind, 0);
    }

    const uint256 off_chain{uint256::FromHex(std::string(64, '8')).value()};
    const int32_t frontier_height{tip_height + 50};
    node::matmul_trusted::NoteAcceptedAttestationHeight(
        frontier_height, off_chain);
    {
        LOCK(::cs_main);
        const auto stranded{chainman.GetSignedFrontierStatus()};
        BOOST_REQUIRE(stranded.available);
        BOOST_CHECK_EQUAL(stranded.height, frontier_height);
        BOOST_CHECK(stranded.hash_known);
        BOOST_CHECK_EQUAL(stranded.hash, off_chain);
        BOOST_CHECK(!stranded.on_active_chain);
        BOOST_CHECK_EQUAL(stranded.on_chain_attested_height, tip_height);
        BOOST_CHECK_EQUAL(stranded.blocks_behind, 50);
        const auto have_data{chainman.FindBestKnownAttestedIndex()};
        BOOST_REQUIRE(have_data != nullptr);
        BOOST_CHECK_EQUAL(have_data, tip);
    }
}

BOOST_FIXTURE_TEST_CASE(chainstate_retryable_matmul_error_does_not_spin_activatebestchain, TestChain100Setup)
{
    // Control flow: ContextualCheckBlock reports ExactReplay cancelled /
    // trusted quorum timeout as state.Error("matmul RC ExactReplay local
    // execution incomplete: …"). ActivateBestChainStep used to treat that
    // as a fatal system error (return false) or, if returned as success,
    // the inner ABC comparator would retry the same pindexMostWork forever
    // after a reorg disconnect left the tip worse than starting_tip.
    // One retryable failure must break inner+outer ABC, leave the candidate
    // in setBlockIndexCandidates, and return success so invalidateblock RPC
    // can complete. Net/scheduler retries later. Injected here without a GPU.
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
        ChainstateManager& chainman;
        ~Restore()
        {
            chainman.SetRetryableMatMulConnectFailureForTest(false);
            node::matmul_trusted::ResetForTest();
            consensus.nReorgProtectionStartHeight = start;
            action = saved_action;
            park_depth = saved_park_depth;
            hysteresis_work_margin = saved_hysteresis_work_margin;
        }
    } restore{consensus, consensus.nReorgProtectionStartHeight,
              action, action, park_depth, park_depth,
              hysteresis_work_margin, hysteresis_work_margin, chainman};
    consensus.nReorgProtectionStartHeight = 10;
    action = kernel::DeepReorgAction::PARK;
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
    CBlockIndex* competing_tip{nullptr};
    for (int i = 0; i < 2; ++i) {
        const CBlock block{CreateAndProcessBlock({}, script)};
        LOCK(::cs_main);
        competing_tip = chainman.m_blockman.LookupBlockIndex(block.GetHash());
    }
    BOOST_REQUIRE(competing_tip);
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == competing_tip);

    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(original_root);
        BOOST_REQUIRE(original_tip->nStatus & BLOCK_HAVE_DATA);
        BOOST_REQUIRE(competing_tip->nChainWork > original_tip->nChainWork);
    }

    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::ONE;
    config.replay_authority_context = uint256::FromHex(std::string(64, 'd')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      original_hash, original_height) ==
                  matmul::trusted::AddResult::Accepted);

    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(
            chainman.FindUniqueCompetingAttestedIndex(), original_tip);
        BOOST_CHECK(chainman.IsAttestedAbandonForkCandidate(original_tip));
    }

    chainman.SetRetryableMatMulConnectFailureForTest(true);
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_CHECK(state.IsValid());
    BOOST_CHECK_EQUAL(chainman.RetryableMatMulConnectFailureAttemptsForTest(), 1);
    {
        LOCK(::cs_main);
        BOOST_CHECK(chainstate.m_chain.Tip() != original_tip);
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(original_tip), 1);
        BOOST_CHECK(chainman.IsAttestedAbandonForkCandidate(original_tip));
    }
    chainman.CheckBlockIndex();

    chainman.SetRetryableMatMulConnectFailureForTest(false);
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip()->GetBlockHash(), original_hash);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Height(), original_height);
    }
    chainman.CheckBlockIndex();
}

BOOST_FIXTURE_TEST_CASE(chainstate_shutdown_interrupt_does_not_spin_activatebestchain, TestChain100Setup)
{
    // PR 105 comments 5301483741 / follow-up: initload ABC held cs_main
    // on a pending attested child so peers never attached. ConnectTip must
    // honor m_interrupt (height > 0) as retryable, and ABC must not retry
    // the same target. The signer peer is not required for this path.
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
        util::SignalInterrupt& interrupt;
        ~Restore()
        {
            node::matmul_trusted::ResetForTest();
            consensus.nReorgProtectionStartHeight = start;
            action = saved_action;
            park_depth = saved_park_depth;
            hysteresis_work_margin = saved_hysteresis_work_margin;
            if (interrupt) {
                (void)interrupt.reset();
            }
        }
    } restore{consensus, consensus.nReorgProtectionStartHeight,
              action, action, park_depth, park_depth,
              hysteresis_work_margin, hysteresis_work_margin, m_interrupt};
    consensus.nReorgProtectionStartHeight = 10;
    action = kernel::DeepReorgAction::PARK;
    park_depth = 100;
    hysteresis_work_margin = 0;

    const CScript script = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CBlockIndex* original_tip{WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE(original_tip != nullptr);
    const uint256 original_hash{original_tip->GetBlockHash()};
    const int original_height{original_tip->nHeight};
    CBlockIndex* const original_root{original_tip};

    BlockValidationState state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, original_root));
    CBlockIndex* competing_tip{nullptr};
    for (int i = 0; i < 2; ++i) {
        const CBlock block{CreateAndProcessBlock({}, script)};
        LOCK(::cs_main);
        competing_tip = chainman.m_blockman.LookupBlockIndex(block.GetHash());
    }
    BOOST_REQUIRE(competing_tip);
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == competing_tip);

    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(original_root);
        BOOST_REQUIRE(original_tip->nStatus & BLOCK_HAVE_DATA);
        BOOST_REQUIRE(competing_tip->nChainWork > original_tip->nChainWork);
    }

    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::ONE;
    config.replay_authority_context = uint256::FromHex(std::string(64, 'e')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      original_hash, original_height) ==
                  matmul::trusted::AddResult::Accepted);

    BOOST_REQUIRE(m_interrupt());
    state = BlockValidationState{};
    const auto t0{std::chrono::steady_clock::now()};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds{2});
    BOOST_CHECK(state.IsValid());
    BOOST_REQUIRE(m_interrupt.reset());
    {
        LOCK(::cs_main);
        BOOST_CHECK(chainstate.m_chain.Tip() != original_tip);
        BOOST_CHECK_EQUAL(original_tip->nStatus & BLOCK_FAILED_MASK, 0);
        BOOST_CHECK(original_tip->IsValid(BLOCK_VALID_TRANSACTIONS));
        // Lesser-work forks are not kept in setBlockIndexCandidates
        // (TryAddBlockIndexCandidate). The restart livelock was a pending
        // same-or-more-work child: ConnectTip honors m_interrupt as
        // retryable, and ABC must not hold cs_main retrying that target.
    }
    state = BlockValidationState{};
    const auto t1{std::chrono::steady_clock::now()};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_CHECK(std::chrono::steady_clock::now() - t1 < std::chrono::seconds{2});
    BOOST_CHECK(state.IsValid());
    chainman.CheckBlockIndex();
}

BOOST_FIXTURE_TEST_CASE(chainstate_dual_quorum_sibling_follows_signed_frontier, TestChain100Setup)
{
    // Live 2026-08-15: signer attested both 189489 siblings; trusted
    // mirrors connected the loser (it had quorum) and then refused to
    // reorg because FindUniqueCompetingAttestedIndex bailed on a quorum
    // tip. The signed frontier's short-reorg fork-child must still win.
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
        std::optional<uint32_t>& park_depth;
        std::optional<uint32_t> saved_park_depth;
        kernel::MatMulValidationMode& mode;
        kernel::MatMulValidationMode saved_mode;
        ~Restore()
        {
            node::matmul_trusted::ResetForTest();
            consensus.nReorgProtectionStartHeight = start;
            action = saved_action;
            park_depth = saved_park_depth;
            mode = saved_mode;
        }
    } restore{consensus, consensus.nReorgProtectionStartHeight,
              action, action, park_depth, park_depth, mode, mode};
    consensus.nReorgProtectionStartHeight = 10;
    action = kernel::DeepReorgAction::PARK;
    park_depth = 2;
    mode = kernel::MatMulValidationMode::TRUSTED;

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
    const uint256 chain_id{uint256::ONE};
    const uint256 replay_ctx{
        uint256::FromHex(std::string(64, 'e')).value()};
    matmul::trusted::StoreConfig config;
    config.chain_id = chain_id;
    config.replay_authority_context = replay_ctx;
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    // Sign the competing sibling first. The connected loser already has a
    // historical dual-attest on the network (live 2026-08-15); ingest it
    // rather than minting a second local signature at the same height.
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      sibling->GetBlockHash(), sibling->nHeight) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_REQUIRE(InjectHistoricalAttestation(
                      signer, chain_id, replay_ctx, original_hash,
                      original_tip->nHeight) ==
                  matmul::trusted::AddResult::Accepted);
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(sibling);
        BOOST_REQUIRE(sibling->nChainWork == original_tip->nChainWork);
        BOOST_REQUIRE(node::matmul_trusted::HasQuorum(
            original_hash, original_tip->nHeight));
        BOOST_REQUIRE(node::matmul_trusted::HasQuorum(
            sibling->GetBlockHash(), sibling->nHeight));
        BOOST_CHECK_EQUAL(chainman.FindUniqueCompetingAttestedIndex(), sibling);
        BOOST_CHECK(chainman.IsAttestedAbandonForkCandidate(sibling));
    }

    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == sibling);
}

BOOST_FIXTURE_TEST_CASE(chainstate_attested_tip_suffix_catchup_is_unique_competing, TestChain100Setup)
{
    // Live 2026-08-15: signer tip already had quorum; the unique attested
    // HAVE_DATA child (189676) sat unconnected while GBT mined a competing
    // sibling. FindUniqueCompetingAttestedIndex used to drop LCA depth 0.
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    auto& mode = const_cast<kernel::MatMulValidationMode&>(
        chainman.m_options.matmul_validation_mode);
    const auto saved_mode{mode};
    struct Restore {
        kernel::MatMulValidationMode& mode;
        kernel::MatMulValidationMode saved_mode;
        ~Restore()
        {
            node::matmul_trusted::ResetForTest();
            mode = saved_mode;
        }
    } restore{mode, saved_mode};
    mode = kernel::MatMulValidationMode::CONSENSUS;

    const CScript script = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CBlockIndex* parent{WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE(parent != nullptr);
    const uint256 parent_hash{parent->GetBlockHash()};
    const int parent_height{parent->nHeight};

    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::ONE;
    config.replay_authority_context = uint256::FromHex(std::string(64, 'f')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/false, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      parent_hash, parent_height) ==
                  matmul::trusted::AddResult::Accepted);

    const CBlock child_block{CreateAndProcessBlock({}, script)};
    CBlockIndex* child{
        WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(
                                       child_block.GetHash()))};
    BOOST_REQUIRE(child != nullptr);
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == child);

    BlockValidationState state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, child));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()->GetBlockHash()) ==
                  parent_hash);
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(child);
        BOOST_REQUIRE(child->nStatus & BLOCK_HAVE_DATA);
        BOOST_REQUIRE(child->IsValid(BLOCK_VALID_TRANSACTIONS));
        BOOST_REQUIRE(child->HaveNumChainTxs());
        BOOST_REQUIRE(child->pprev == chainstate.m_chain.Tip());
    }
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      child->GetBlockHash(), child->nHeight) ==
                  matmul::trusted::AddResult::Accepted);

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(node::matmul_trusted::HasQuorum(
            parent_hash, parent_height));
        BOOST_REQUIRE(node::matmul_trusted::HasQuorum(
            child->GetBlockHash(), child->nHeight));
        BOOST_CHECK_EQUAL(chainman.FindUniqueCompetingAttestedIndex(), child);
        BOOST_CHECK(chainman.IsAttestedAbandonForkCandidate(child));
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip()->GetBlockHash(), parent_hash);
    }

    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == child);
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.FindUniqueCompetingAttestedIndex()) ==
                nullptr);
}

BOOST_FIXTURE_TEST_CASE(chainstate_fmwc_yields_on_attested_suffix_with_header_only_hole, TestChain100Setup)
{
    // Live 2026-08-15 (PR 105 comment 5302572644): an attested HAVE_DATA
    // frontier whose path still had HEADER_ONLY holes was re-inserted by
    // FindUniqueCompetingAttestedIndex after FindMostWorkChain erased it
    // for missing data — b-msghand 100% in FindMostWorkChain, cs_main held.
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    auto& mode = const_cast<kernel::MatMulValidationMode&>(
        chainman.m_options.matmul_validation_mode);
    const auto saved_mode{mode};
    struct Restore {
        kernel::MatMulValidationMode& mode;
        kernel::MatMulValidationMode saved_mode;
        ~Restore()
        {
            node::matmul_trusted::ResetForTest();
            mode = saved_mode;
        }
    } restore{mode, saved_mode};
    mode = kernel::MatMulValidationMode::CONSENSUS;

    const CScript script = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CBlockIndex* parent{WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE(parent != nullptr);
    const uint256 parent_hash{parent->GetBlockHash()};
    const int parent_height{parent->nHeight};

    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::ONE;
    config.replay_authority_context = uint256::FromHex(std::string(64, 'e')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/false, /*serve=*/false,
        std::chrono::milliseconds{50}, error));

    const CBlock child_block{CreateAndProcessBlock({}, script)};
    const CBlock grand_block{CreateAndProcessBlock({}, script)};
    CBlockIndex* child{
        WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(
                                       child_block.GetHash()))};
    CBlockIndex* grandchild{
        WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(
                                       grand_block.GetHash()))};
    BOOST_REQUIRE(child != nullptr && grandchild != nullptr);
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == grandchild);

    BlockValidationState state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, grandchild));
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, child));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()->GetBlockHash()) ==
                  parent_hash);
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(grandchild);
        chainstate.ResetBlockFailureFlags(child);
        BOOST_REQUIRE(grandchild->nStatus & BLOCK_HAVE_DATA);
        grandchild->nStatus &= ~BLOCK_FAILED_MASK;
        child->nStatus &= ~BLOCK_FAILED_MASK;
        child->nStatus &= ~BLOCK_HAVE_DATA;
        child->nDataPos = 0;
        chainstate.setBlockIndexCandidates.insert(grandchild);
    }

    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      parent_hash, parent_height) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      grandchild->GetBlockHash(), grandchild->nHeight) ==
                  matmul::trusted::AddResult::Accepted);

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(node::matmul_trusted::HasQuorum(
            parent_hash, parent_height));
        BOOST_REQUIRE(node::matmul_trusted::HasQuorum(
            grandchild->GetBlockHash(), grandchild->nHeight));
        BOOST_CHECK(chainman.FindUniqueCompetingAttestedIndex() == nullptr);
        const CBlockIndex* most_work{chainstate.FindMostWorkChainForTest()};
        BOOST_REQUIRE(most_work != nullptr);
        BOOST_CHECK(most_work == parent || most_work == chainstate.m_chain.Tip());
        for (int i = 0; i < 32; ++i) {
            BOOST_REQUIRE(chainstate.FindMostWorkChainForTest() != nullptr);
        }
    }
}

BOOST_FIXTURE_TEST_CASE(chainstate_reconsiders_complete_child_when_parent_becomes_tip, TestChain100Setup)
{
    // A configured node only admits an unattested immediate tip-child. If a
    // complete grandchild arrives while its parent is still pending, it is
    // intentionally omitted from the candidate set. Advancing to the parent
    // must re-evaluate that child or catch-up stops with HAVE_DATA at H+1.
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    Chainstate& chainstate{chainman.ActiveChainstate()};
    auto& mode = const_cast<kernel::MatMulValidationMode&>(
        chainman.m_options.matmul_validation_mode);
    const auto saved_mode{mode};
    struct Restore {
        kernel::MatMulValidationMode& mode;
        kernel::MatMulValidationMode saved_mode;
        ~Restore()
        {
            node::matmul_trusted::ResetForTest();
            mode = saved_mode;
        }
    } restore{mode, saved_mode};

    const CScript script{
        GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()))};
    CBlockIndex* const parent{
        WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE(parent != nullptr);
    const CBlock child_block{CreateAndProcessBlock({}, script)};
    const CBlock grandchild_block{CreateAndProcessBlock({}, script)};
    CBlockIndex* const child{WITH_LOCK(
        ::cs_main, return chainman.m_blockman.LookupBlockIndex(
                           child_block.GetHash()))};
    CBlockIndex* const grandchild{WITH_LOCK(
        ::cs_main, return chainman.m_blockman.LookupBlockIndex(
                           grandchild_block.GetHash()))};
    BOOST_REQUIRE(child != nullptr && grandchild != nullptr);

    BlockValidationState state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, child));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == parent);
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(child);
        BOOST_REQUIRE(child->IsValid(BLOCK_VALID_TRANSACTIONS));
        BOOST_REQUIRE(grandchild->IsValid(BLOCK_VALID_TRANSACTIONS));
        BOOST_REQUIRE(child->HaveNumChainTxs());
        BOOST_REQUIRE(grandchild->HaveNumChainTxs());
    }

    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::ONE;
    config.replay_authority_context =
        uint256::FromHex(std::string(64, '9')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/false, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    mode = kernel::MatMulValidationMode::CONSENSUS;
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      parent->GetBlockHash(), parent->nHeight) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      child->GetBlockHash(), child->nHeight) ==
                  matmul::trusted::AddResult::Accepted);

    {
        LOCK(::cs_main);
        chainstate.ClearBlockIndexCandidates();
        chainstate.TryAddBlockIndexCandidate(parent);
        chainstate.TryAddBlockIndexCandidate(child);
        chainstate.TryAddBlockIndexCandidate(grandchild);
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(child), 1U);
        BOOST_CHECK_EQUAL(
            chainstate.setBlockIndexCandidates.count(grandchild), 0U);
    }

    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip(), child);
        BOOST_CHECK_EQUAL(
            chainstate.setBlockIndexCandidates.count(grandchild), 1U);
    }
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == grandchild);
    chainman.CheckBlockIndex();
}

BOOST_FIXTURE_TEST_CASE(chainstate_attested_tip_suffix_catchup_beats_short_reorg_competitor, TestChain100Setup)
{
    // Live 2026-08-15 after 62721364: FindUniqueCompetingAttestedIndex
    // saw both the attested suffix of the quorum tip and an attested
    // HAVE_DATA short-reorg twin, then uniqueness returned nullptr.
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    auto& mode = const_cast<kernel::MatMulValidationMode&>(
        chainman.m_options.matmul_validation_mode);
    const auto saved_mode{mode};
    struct Restore {
        kernel::MatMulValidationMode& mode;
        kernel::MatMulValidationMode saved_mode;
        ~Restore()
        {
            node::matmul_trusted::ResetForTest();
            mode = saved_mode;
        }
    } restore{mode, saved_mode};
    mode = kernel::MatMulValidationMode::CONSENSUS;

    const CScript script = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CBlockIndex* parent{WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE(parent != nullptr);
    const uint256 parent_hash{parent->GetBlockHash()};
    const int parent_height{parent->nHeight};

    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    const uint256 chain_id{uint256::ONE};
    const uint256 replay_ctx{
        uint256::FromHex(std::string(64, 'd')).value()};
    matmul::trusted::StoreConfig config;
    config.chain_id = chain_id;
    config.replay_authority_context = replay_ctx;
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/false, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      parent_hash, parent_height) ==
                  matmul::trusted::AddResult::Accepted);

    BlockValidationState state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, parent));
    const CBlock sibling_block{CreateAndProcessBlock({}, script)};
    CBlockIndex* sibling{
        WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(
                                       sibling_block.GetHash()))};
    BOOST_REQUIRE(sibling != nullptr);
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, sibling));
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(parent);
    }
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()->GetBlockHash()) ==
                  parent_hash);
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(sibling);
        BOOST_REQUIRE(sibling->nStatus & BLOCK_HAVE_DATA);
        BOOST_REQUIRE(sibling->IsValid(BLOCK_VALID_TRANSACTIONS));
        BOOST_REQUIRE(sibling->HaveNumChainTxs());
    }
    // Do not attest the short-reorg twin until the suffix child exists.
    // Signing it first makes FindUnique select the sibling, so ABC reorgs
    // away from the parent before CreateAndProcessBlock can connect the
    // catch-up child.

    const CBlock child_block{CreateAndProcessBlock({}, script)};
    CBlockIndex* child{
        WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(
                                       child_block.GetHash()))};
    BOOST_REQUIRE(child != nullptr);
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == child);
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, child));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()->GetBlockHash()) ==
                  parent_hash);
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(child);
        BOOST_REQUIRE(child->nStatus & BLOCK_HAVE_DATA);
        BOOST_REQUIRE(child->pprev == chainstate.m_chain.Tip());
    }
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      child->GetBlockHash(), child->nHeight) ==
                  matmul::trusted::AddResult::Accepted);
    // Sibling shares the parent's height, which already has quorum. Ingest
    // the historical dual-attest rather than minting a second local signature.
    BOOST_REQUIRE(InjectHistoricalAttestation(
                      signer, chain_id, replay_ctx, sibling->GetBlockHash(),
                      sibling->nHeight) ==
                  matmul::trusted::AddResult::Accepted);

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(node::matmul_trusted::HasQuorum(
            parent_hash, parent_height));
        BOOST_REQUIRE(node::matmul_trusted::HasQuorum(
            sibling->GetBlockHash(), sibling->nHeight));
        BOOST_REQUIRE(node::matmul_trusted::HasQuorum(
            child->GetBlockHash(), child->nHeight));
        BOOST_CHECK_EQUAL(chainman.FindUniqueCompetingAttestedIndex(), child);
        BOOST_CHECK(chainman.IsAttestedAbandonForkCandidate(child));
        BOOST_CHECK(!chainman.ShouldDeferLosingTipExtension(child));
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip()->GetBlockHash(), parent_hash);
    }

    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == child);
}

BOOST_FIXTURE_TEST_CASE(chainstate_competing_attested_scan_skips_active_ancestors_before_path_walk, TestChain100Setup)
{
    // Live 2026-08-16: the bounded frontier window was mostly active-chain
    // ancestors. FindUniqueCompetingAttestedIndex computed LCA==ancestor, then
    // started at ancestor->pprev and walked to genesis before checking
    // ActiveChain.Contains(). At production height/window this was about 97M
    // ancestry visits with cs_main held per scan.
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::ONE;
    config.replay_authority_context =
        uint256::FromHex(std::string(64, '7')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    struct ResetTrustedStore {
        ~ResetTrustedStore() { node::matmul_trusted::ResetForTest(); }
    } reset_trusted_store;

    const int tip_height{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Height())};
    for (int height = 0; height <= tip_height; ++height) {
        const CBlockIndex* const index{WITH_LOCK(
            ::cs_main, return chainman.ActiveChain()[height])};
        BOOST_REQUIRE(index != nullptr);
        BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                          index->GetBlockHash(), index->nHeight) ==
                      matmul::trusted::AddResult::Accepted);
    }

    size_t path_visits{std::numeric_limits<size_t>::max()};
    const CBlockIndex* selected{WITH_LOCK(
        ::cs_main,
        return chainman.FindUniqueCompetingAttestedIndex(&path_visits))};
    BOOST_CHECK(selected == nullptr);
    BOOST_CHECK_EQUAL(path_visits, 0U);
}

BOOST_FIXTURE_TEST_CASE(chainstate_trusted_candidate_scan_skips_active_ancestors_and_stops_at_activation, TestChain100Setup)
{
    // Live 2026-08-16: changing a trusted mirror from 1-of-1 to 1-of-2
    // selected an empty authority namespace. Startup then called
    // TryAddBlockIndexCandidate for every active-chain index. The trusted
    // policy walked from tip to each ancestor looking for quorum, including
    // pre-activation history, producing O(height^2) work while the RPC only
    // reported "Loading block index".
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    Chainstate& chainstate{chainman.ActiveChainstate()};
    auto& consensus{const_cast<Consensus::Params&>(Params().GetConsensus())};
    auto& mode{const_cast<kernel::MatMulValidationMode&>(
        chainman.m_options.matmul_validation_mode)};
    struct Restore {
        Consensus::Params& consensus;
        int32_t v4_height;
        int32_t rc_height;
        int32_t coupled_height;
        uint32_t rc_profile;
        kernel::MatMulValidationMode& mode;
        kernel::MatMulValidationMode saved_mode;
        ~Restore()
        {
            node::matmul_trusted::ResetForTest();
            consensus.nMatMulV4Height = v4_height;
            consensus.nMatMulRCHeight = rc_height;
            consensus.nMatMulRCCoupledHeight = coupled_height;
            consensus.nMatMulRCProfile = rc_profile;
            mode = saved_mode;
        }
    } restore{consensus, consensus.nMatMulV4Height,
              consensus.nMatMulRCHeight,
              consensus.nMatMulRCCoupledHeight,
              consensus.nMatMulRCProfile, mode, mode};

    CBlockIndex* const original_tip{
        WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE(original_tip != nullptr);
    BOOST_REQUIRE(original_tip->nHeight >= 10);
    CBlockIndex* const original_fork_child{WITH_LOCK(
        ::cs_main,
        return chainstate.m_chain[original_tip->nHeight - 4])};
    CBlockIndex* const fork_point{original_fork_child->pprev};
    BOOST_REQUIRE(fork_point != nullptr);

    BlockValidationState state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, original_fork_child));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) ==
                  fork_point);
    const CScript script{
        GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()))};
    for (int i = 0; i < 5; ++i) {
        (void)CreateAndProcessBlock({}, script);
    }
    CBlockIndex* const alternate_tip{
        WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE(alternate_tip != nullptr);
    BOOST_REQUIRE_EQUAL(alternate_tip->nHeight, original_tip->nHeight);
    BOOST_REQUIRE(alternate_tip != original_tip);
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(original_fork_child);
        BOOST_REQUIRE_EQUAL(chainstate.m_chain.Tip(), alternate_tip);
        BOOST_REQUIRE_EQUAL(
            LastCommonAncestor(alternate_tip, original_tip), fork_point);
    }

    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::ONE;
    config.replay_authority_context =
        uint256::FromHex(std::string(64, '8')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    mode = kernel::MatMulValidationMode::TRUSTED;
    consensus.nMatMulRCCoupledHeight =
        std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCProfile = 1;

    // Active ancestors require no competing-suffix audit, even when they are
    // inside the attestation regime and the store contains no quorum records.
    consensus.nMatMulV4Height = 1;
    consensus.nMatMulRCHeight = 1;
    size_t path_visits{std::numeric_limits<size_t>::max()};
    {
        LOCK(::cs_main);
        chainstate.TryAddBlockIndexCandidate(
            chainstate.m_chain[1], &path_visits);
    }
    BOOST_CHECK_EQUAL(path_visits, 0U);

    // A genuinely competing candidate below activation does not scan the
    // active suffix for governing quorum records.
    const int32_t after_candidate{original_tip->nHeight + 1};
    consensus.nMatMulV4Height = after_candidate;
    consensus.nMatMulRCHeight = after_candidate;
    path_visits = std::numeric_limits<size_t>::max();
    {
        LOCK(::cs_main);
        chainstate.TryAddBlockIndexCandidate(original_tip, &path_visits);
    }
    BOOST_CHECK_EQUAL(path_visits, 0U);

    // Once the candidate is in the Profile-1 regime, inspect only the active
    // suffix at or above activation. The fork point is deliberately older.
    const int32_t activation{alternate_tip->nHeight - 2};
    BOOST_REQUIRE(fork_point->nHeight < activation);
    consensus.nMatMulV4Height = activation;
    consensus.nMatMulRCHeight = activation;
    path_visits = std::numeric_limits<size_t>::max();
    {
        LOCK(::cs_main);
        chainstate.TryAddBlockIndexCandidate(original_tip, &path_visits);
    }
    BOOST_CHECK_EQUAL(
        path_visits,
        static_cast<size_t>(alternate_tip->nHeight - activation + 1));
}

BOOST_FIXTURE_TEST_CASE(chainstate_already_active_unattested_recovers_unique_attested_after_reload, TestChain100Setup)
{
    // Issue #106: the competing unattested branch is already the active tip
    // (pre-finality datadir). Recovery must switch to the uniquely attested
    // original after a simulated restart, without invalidateblock /
    // reconsiderblock / preciousblock / reindex as the recovery path.
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
        std::optional<uint32_t>& park_depth;
        std::optional<uint32_t> saved_park_depth;
        kernel::MatMulValidationMode& mode;
        kernel::MatMulValidationMode saved_mode;
        ~Restore()
        {
            node::matmul_trusted::ResetForTest();
            consensus.nReorgProtectionStartHeight = start;
            action = saved_action;
            park_depth = saved_park_depth;
            mode = saved_mode;
        }
    } restore{consensus, consensus.nReorgProtectionStartHeight,
              action, action, park_depth, park_depth, mode, mode};
    consensus.nReorgProtectionStartHeight = 10;
    action = kernel::DeepReorgAction::PARK;
    park_depth = 10;
    mode = kernel::MatMulValidationMode::TRUSTED;

    const CScript script = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CBlockIndex* original_tip{WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE(original_tip != nullptr);
    const uint256 original_hash{original_tip->GetBlockHash()};
    const int original_height{original_tip->nHeight};
    CBlockIndex* const original_root{original_tip};

    BlockValidationState state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, original_root));
    const CBlock competing_block{CreateAndProcessBlock({}, script)};
    CBlockIndex* competing{WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(competing_block.GetHash()))};
    BOOST_REQUIRE(competing != nullptr);
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == competing);

    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(original_root);
        BOOST_REQUIRE(original_tip->nStatus & BLOCK_HAVE_DATA);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip(), competing);
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
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      original_hash, original_height) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(node::matmul_trusted::HasQuorum(original_hash, original_height));
    BOOST_CHECK(!node::matmul_trusted::HasQuorum(
        competing->GetBlockHash(), competing->nHeight));

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.LoadReorgRecoveryRecord());
        BOOST_CHECK_EQUAL(
            chainman.FindUniqueCompetingAttestedIndex(), original_tip);
        BOOST_CHECK(chainman.IsAttestedAbandonForkCandidate(original_tip));
    }

    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip(), original_tip);
        BOOST_CHECK(chainman.m_blockman.LookupBlockIndex(competing->GetBlockHash()) !=
                    nullptr);
        BOOST_CHECK(!chainstate.m_chain.Contains(competing));
        BOOST_REQUIRE(chainman.LoadReorgRecoveryRecord());
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip(), original_tip);
    }

    const CBlock next{CreateAndProcessBlock({}, script)};
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      next.GetHash(), original_height + 1) ==
                  matmul::trusted::AddResult::Accepted);
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Height(), original_height + 1);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip()->pprev, original_tip);
    }
    chainman.CheckBlockIndex();
}

BOOST_FIXTURE_TEST_CASE(chainstate_consensus_does_not_propose_unattested_when_height_attested, TestChain100Setup)
{
    // Live 2026-08-15: signer ExactReplayed the followed unattested twin
    // (m_best_header) and re-signed a height that already had quorum
    // (94f70747 then a9590c15 at 190354). Configured CONSENSUS — with or
    // without a local signer — must not propose that unattested HAVE_DATA
    // twin once another hash at the height is attested.
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    auto& mode = const_cast<kernel::MatMulValidationMode&>(
        chainman.m_options.matmul_validation_mode);
    const int32_t saved_v4{consensus.nMatMulV4Height};
    const int32_t saved_bmx{consensus.nMatMulBMX4CHeight};
    const int32_t saved_rc{consensus.nMatMulRCHeight};
    const auto saved_mode{mode};
    struct Restore {
        Consensus::Params& consensus;
        int32_t v4;
        int32_t bmx;
        int32_t rc;
        kernel::MatMulValidationMode& mode;
        kernel::MatMulValidationMode saved_mode;
        ~Restore()
        {
            node::matmul_trusted::ResetForTest();
            consensus.nMatMulV4Height = v4;
            consensus.nMatMulBMX4CHeight = bmx;
            consensus.nMatMulRCHeight = rc;
            mode = saved_mode;
        }
    } restore{consensus, saved_v4, saved_bmx, saved_rc, mode, saved_mode};

    const CScript script = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CKey other;
    other.MakeNewKey(/*fCompressed=*/true);
    const CScript script_alt = GetScriptForDestination(PKHash(other.GetPubKey()));
    CBlockIndex* parent_tip{WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE(parent_tip != nullptr);
    const uint256 parent_hash{parent_tip->GetBlockHash()};
    const int parent_height{parent_tip->nHeight};
    const int32_t child_height{parent_height + 1};

    consensus.nMatMulV4Height = child_height;
    consensus.nMatMulBMX4CHeight = child_height;
    consensus.nMatMulRCHeight = child_height;

    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig persist_config;
    persist_config.chain_id = uint256::ONE;
    persist_config.replay_authority_context =
        uint256::FromHex(std::string(64, 'a')).value();
    persist_config.trusted_signers = {signer.GetPubKey()};
    persist_config.threshold = 1;
    persist_config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(persist_config), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    mode = kernel::MatMulValidationMode::TRUSTED;
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      parent_hash, parent_height) ==
                  matmul::trusted::AddResult::Accepted);

    const auto unattested{std::make_shared<const CBlock>(
        CreateBlock({}, script, chainstate))};
    bool new_block{false};
    BOOST_REQUIRE(chainman.ProcessNewBlock(
        unattested, /*force_processing=*/true, /*min_pow_checked=*/true,
        &new_block));
    const auto attested{std::make_shared<const CBlock>(
        CreateBlock({}, script_alt, chainstate))};
    BOOST_REQUIRE(attested->GetHash() != unattested->GetHash());
    BlockValidationState header_state;
    BOOST_REQUIRE(chainman.ProcessNewBlockHeaders(
        {{attested->GetBlockHeader()}}, /*min_pow_checked=*/true, header_state));
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      attested->GetHash(), child_height) ==
                  matmul::trusted::AddResult::Accepted);

    CBlockIndex* unattested_index{nullptr};
    {
        LOCK(::cs_main);
        unattested_index =
            chainman.m_blockman.LookupBlockIndex(unattested->GetHash());
        BOOST_REQUIRE(unattested_index != nullptr);
        BOOST_CHECK(unattested_index->nStatus & BLOCK_HAVE_DATA);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip(), parent_tip);
        BOOST_CHECK_EQUAL(chainstate.FindMostWorkChainForTest(), parent_tip);
    }

    node::matmul_trusted::ResetForTest();
    matmul::trusted::StoreConfig verifier_config;
    verifier_config.chain_id = uint256::ONE;
    verifier_config.replay_authority_context =
        uint256::FromHex(std::string(64, 'a')).value();
    verifier_config.trusted_signers = {signer.GetPubKey()};
    verifier_config.threshold = 1;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(verifier_config), /*trusted_mirror=*/false, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    mode = kernel::MatMulValidationMode::CONSENSUS;
    BOOST_REQUIRE(!node::matmul_trusted::HasLocalSigner());
    BOOST_REQUIRE(!node::matmul_trusted::IsTrustedMirror());
    auto add_quorum = [&](const uint256& hash, int32_t height) {
        matmul::trusted::ExactReplayStatement statement;
        statement.chain_id = uint256::ONE;
        statement.block_hash = hash;
        statement.block_height = height;
        statement.replay_authority_context =
            uint256::FromHex(std::string(64, 'a')).value();
        const auto attestation{matmul::trusted::SignStatement(statement, signer)};
        BOOST_REQUIRE(attestation.has_value());
        const auto added{node::matmul_trusted::Add(*attestation, hash, height)};
        BOOST_REQUIRE(added == matmul::trusted::AddResult::Accepted ||
                      added == matmul::trusted::AddResult::Duplicate);
    };
    add_quorum(parent_hash, parent_height);
    add_quorum(attested->GetHash(), child_height);

    {
        LOCK(::cs_main);
        chainman.SetBestHeader(unattested_index);
        BOOST_CHECK(chainman.IndexIsFollowedTipChild(parent_tip, unattested_index));
        BOOST_CHECK(!chainman.IndexIsAttestedChainTipChild(
            parent_tip, unattested_index));
        BOOST_CHECK_EQUAL(chainstate.FindMostWorkChainForTest(), parent_tip);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip(), parent_tip);
    }
    chainman.CheckBlockIndex();
}

BOOST_FIXTURE_TEST_CASE(chainstate_signer_progress_child_when_best_header_is_competing_fork, TestChain100Setup)
{
    // Live 2026-08-15 190376 stall: m_best_header sat on a heavier unattested
    // tower that did not extend the attested tip, so the attested-chain
    // tip-child was never "followed" and HEADER_ONLY skip starved getdata.
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    auto& mode = const_cast<kernel::MatMulValidationMode&>(
        chainman.m_options.matmul_validation_mode);
    auto& action = const_cast<kernel::DeepReorgAction&>(
        chainman.m_options.deep_reorg_action);
    auto& park_depth = const_cast<std::optional<uint32_t>&>(
        chainman.m_options.max_reorg_depth_park);
    auto& hysteresis_work_margin = const_cast<std::optional<uint32_t>&>(
        chainman.m_options.reorg_hysteresis_work_margin);
    const int32_t saved_v4{consensus.nMatMulV4Height};
    const int32_t saved_bmx{consensus.nMatMulBMX4CHeight};
    const int32_t saved_rc{consensus.nMatMulRCHeight};
    const int32_t saved_reorg_start{consensus.nReorgProtectionStartHeight};
    const auto saved_mode{mode};
    struct Restore {
        Consensus::Params& consensus;
        int32_t v4;
        int32_t bmx;
        int32_t rc;
        int32_t reorg_start;
        kernel::MatMulValidationMode& mode;
        kernel::MatMulValidationMode saved_mode;
        kernel::DeepReorgAction& action;
        kernel::DeepReorgAction saved_action;
        std::optional<uint32_t>& park_depth;
        std::optional<uint32_t> saved_park_depth;
        std::optional<uint32_t>& hysteresis_work_margin;
        std::optional<uint32_t> saved_hysteresis_work_margin;
        ~Restore()
        {
            node::matmul_trusted::ResetForTest();
            consensus.nMatMulV4Height = v4;
            consensus.nMatMulBMX4CHeight = bmx;
            consensus.nMatMulRCHeight = rc;
            consensus.nReorgProtectionStartHeight = reorg_start;
            mode = saved_mode;
            action = saved_action;
            park_depth = saved_park_depth;
            hysteresis_work_margin = saved_hysteresis_work_margin;
        }
    } restore{consensus, saved_v4, saved_bmx, saved_rc, saved_reorg_start, mode,
              saved_mode, action, action, park_depth, park_depth,
              hysteresis_work_margin, hysteresis_work_margin};
    action = kernel::DeepReorgAction::PARK;
    park_depth = 100;
    hysteresis_work_margin = 0;
    consensus.nReorgProtectionStartHeight = 10;

    const CScript script =
        GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CKey other;
    other.MakeNewKey(/*fCompressed=*/true);
    const CScript script_alt = GetScriptForDestination(PKHash(other.GetPubKey()));

    CBlockIndex* original_tip{
        WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE(original_tip != nullptr);
    const uint256 original_hash{original_tip->GetBlockHash()};
    const int original_height{original_tip->nHeight};

    BlockValidationState state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, original_tip));
    CBlockIndex* fork_tip{nullptr};
    for (int i = 0; i < 2; ++i) {
        const CBlock block{CreateAndProcessBlock({}, script)};
        LOCK(::cs_main);
        fork_tip = chainman.m_blockman.LookupBlockIndex(block.GetHash());
    }
    BOOST_REQUIRE(fork_tip != nullptr);
    BOOST_REQUIRE_EQUAL(fork_tip->nHeight, original_height + 1);
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(original_tip);
        BOOST_REQUIRE(original_tip->nStatus & BLOCK_HAVE_DATA);
        BOOST_REQUIRE(fork_tip->nChainWork > original_tip->nChainWork);
    }

    consensus.nMatMulV4Height = original_height;
    consensus.nMatMulBMX4CHeight = original_height;
    consensus.nMatMulRCHeight = original_height;
    mode = kernel::MatMulValidationMode::CONSENSUS;

    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::ONE;
    config.replay_authority_context =
        uint256::FromHex(std::string(64, 'a')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/false, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::HasLocalSigner());
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      original_hash, original_height) ==
                  matmul::trusted::AddResult::Accepted);

    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) ==
                  original_tip);

    const auto ours{std::make_shared<const CBlock>(
        CreateBlock({}, script_alt, chainstate))};
    BlockValidationState header_state;
    BOOST_REQUIRE(chainman.ProcessNewBlockHeaders(
        {{ours->GetBlockHeader()}}, /*min_pow_checked=*/true, header_state));
    CBlockIndex* ours_index{WITH_LOCK(::cs_main, {
        return chainman.m_blockman.LookupBlockIndex(ours->GetHash());
    })};
    BOOST_REQUIRE(ours_index != nullptr);
    BOOST_CHECK_EQUAL(ours_index->pprev, original_tip);

    {
        LOCK(::cs_main);
        chainman.SetBestHeader(fork_tip);
        BOOST_CHECK(!chainman.BestHeaderExtendsTip(original_tip));
        BOOST_CHECK(!chainman.IndexIsFollowedTipChild(original_tip, ours_index));
        BOOST_CHECK(chainman.IndexIsAttestedChainTipChild(
            original_tip, ours_index));
        const CBlockIndex* most_work{chainstate.FindMostWorkChainForTest()};
        BOOST_REQUIRE(most_work != nullptr);
        BOOST_CHECK(most_work != fork_tip);
        BOOST_CHECK(most_work == original_tip || most_work == ours_index);
        BOOST_CHECK(chainman.FindUniqueCompetingAttestedIndex() == nullptr);
        BOOST_REQUIRE(fork_tip->pprev != nullptr);
        BOOST_CHECK_EQUAL(
            node::matmul_trusted::SignAuthoritative(
                fork_tip->pprev->GetBlockHash(), original_height),
            matmul::trusted::AddResult::HeightOccupied);
    }
    chainman.CheckBlockIndex();
}

BOOST_FIXTURE_TEST_CASE(chainstate_signer_does_not_abandon_attested_tip_for_dual_quorum_twin, TestChain100Setup)
{
    // CONSENSUS signer must not follow FindUnique onto a dual-attested
    // same-height twin (live 190354). Trusted mirrors still recover
    // (chainstate_dual_quorum_sibling_follows_signed_frontier).
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    auto& mode = const_cast<kernel::MatMulValidationMode&>(
        chainman.m_options.matmul_validation_mode);
    auto& action = const_cast<kernel::DeepReorgAction&>(
        chainman.m_options.deep_reorg_action);
    auto& park_depth = const_cast<std::optional<uint32_t>&>(
        chainman.m_options.max_reorg_depth_park);
    const int32_t saved_reorg_start{consensus.nReorgProtectionStartHeight};
    struct Restore {
        Consensus::Params& consensus;
        int32_t reorg_start;
        kernel::MatMulValidationMode& mode;
        kernel::MatMulValidationMode saved_mode;
        kernel::DeepReorgAction& action;
        kernel::DeepReorgAction saved_action;
        std::optional<uint32_t>& park_depth;
        std::optional<uint32_t> saved_park_depth;
        ~Restore()
        {
            node::matmul_trusted::ResetForTest();
            consensus.nReorgProtectionStartHeight = reorg_start;
            mode = saved_mode;
            action = saved_action;
            park_depth = saved_park_depth;
        }
    } restore{consensus, saved_reorg_start, mode, mode, action, action,
              park_depth, park_depth};
    consensus.nReorgProtectionStartHeight = 10;
    action = kernel::DeepReorgAction::PARK;
    park_depth = 2;
    mode = kernel::MatMulValidationMode::CONSENSUS;

    const CScript script =
        GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
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
    const CBlock sibling_child_block{CreateAndProcessBlock({}, script)};
    CBlockIndex* sibling_child;
    {
        LOCK(::cs_main);
        sibling_child = chainman.m_blockman.LookupBlockIndex(
            sibling_child_block.GetHash());
    }
    BOOST_REQUIRE(sibling_child != nullptr);
    BOOST_REQUIRE_EQUAL(sibling_child->pprev, sibling);
    const CBlock sibling_grandchild_block{CreateAndProcessBlock({}, script)};
    CBlockIndex* sibling_grandchild;
    {
        LOCK(::cs_main);
        sibling_grandchild = chainman.m_blockman.LookupBlockIndex(
            sibling_grandchild_block.GetHash());
    }
    const CBlock sibling_tip_block{CreateAndProcessBlock({}, script)};
    CBlockIndex* sibling_tip;
    {
        LOCK(::cs_main);
        sibling_tip = chainman.m_blockman.LookupBlockIndex(
            sibling_tip_block.GetHash());
    }
    BOOST_REQUIRE(sibling_grandchild != nullptr);
    BOOST_REQUIRE(sibling_tip != nullptr);
    BOOST_REQUIRE_EQUAL(sibling_grandchild->pprev, sibling_child);
    BOOST_REQUIRE_EQUAL(sibling_tip->pprev, sibling_grandchild);
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, sibling));
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(original_root);
    }
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()->GetBlockHash()) ==
                  original_hash);

    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    const uint256 chain_id{uint256::ONE};
    const uint256 replay_ctx{
        uint256::FromHex(std::string(64, 'f')).value()};
    matmul::trusted::StoreConfig config;
    config.chain_id = chain_id;
    config.replay_authority_context = replay_ctx;
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/false, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::HasLocalSigner());
    BOOST_REQUIRE(!node::matmul_trusted::IsTrustedMirror());
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      sibling->GetBlockHash(), sibling->nHeight) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_REQUIRE(InjectHistoricalAttestation(
                      signer, chain_id, replay_ctx, original_hash,
                      original_tip->nHeight) ==
                  matmul::trusted::AddResult::Accepted);
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(sibling);
        BOOST_REQUIRE(sibling->nChainWork == original_tip->nChainWork);
        BOOST_REQUIRE(node::matmul_trusted::HasQuorum(
            original_hash, original_tip->nHeight));
        BOOST_REQUIRE(node::matmul_trusted::HasQuorum(
            sibling->GetBlockHash(), sibling->nHeight));
        BOOST_CHECK(chainman.FindUniqueCompetingAttestedIndex() == nullptr);
        BOOST_CHECK_EQUAL(chainstate.FindMostWorkChainForTest(), original_tip);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip()->GetBlockHash(), original_hash);
    }

    // Equal-work equivocation is ambiguous, but it must not permanently pin a
    // consensus signer once one fully authenticated branch has accumulated
    // strictly more work. This also covers old/cloned signer deployments that
    // predate the durable local height-occupancy protection.
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      sibling_child->GetBlockHash(), sibling_child->nHeight) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      sibling_grandchild->GetBlockHash(),
                      sibling_grandchild->nHeight) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      sibling_tip->GetBlockHash(), sibling_tip->nHeight) ==
                  matmul::trusted::AddResult::Accepted);
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(sibling_tip);
        BOOST_REQUIRE(chainman.MaybeTrackReorgRecovery(sibling_child));
        BOOST_REQUIRE(chainman.MaybeTrackReorgRecovery(sibling_grandchild));
        BOOST_REQUIRE(chainman.MaybeTrackReorgRecovery(sibling_tip));
        BOOST_REQUIRE(sibling_tip->nChainWork > original_tip->nChainWork);
        BOOST_REQUIRE(node::matmul_trusted::HasQuorum(
            sibling_tip->GetBlockHash(), sibling_tip->nHeight));
        BOOST_REQUIRE(node::matmul_trusted::HasQuorumInMemory(
            sibling_child->GetBlockHash(), sibling_child->nHeight));
        BOOST_REQUIRE(node::matmul_trusted::HasQuorumInMemory(
            sibling_grandchild->GetBlockHash(), sibling_grandchild->nHeight));
        BOOST_CHECK_EQUAL(chainman.FindUniqueCompetingAttestedIndex(), sibling_tip);
        BOOST_REQUIRE(!chainman.IsOnParkedReorgBranch(sibling_child));
        BOOST_REQUIRE(!chainman.ShouldDeferLosingTipExtension(sibling_child));
    }
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip()->nHeight,
                          sibling_tip->nHeight);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip(), sibling_tip);
    }
    chainman.CheckBlockIndex();
}

BOOST_FIXTURE_TEST_CASE(chainstate_signer_exact_replays_unsigned_fork_root_to_signed_frontier, TestChain100Setup)
{
    // Reproduced by the convergence fixture on 2026-08-16: the signer had
    // already signed its losing active block at the fork height, so durable
    // anti-equivocation correctly refused to sign the authority fork root.
    // It nevertheless had every body and a unique signed, higher frontier.
    // The old scheduler never selected the unsigned root for ExactReplay and
    // FindUnique required root quorum, permanently pinning the node.
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    Chainstate& chainstate{chainman.ActiveChainstate()};
    auto& consensus{const_cast<Consensus::Params&>(Params().GetConsensus())};
    auto& mode{const_cast<kernel::MatMulValidationMode&>(
        chainman.m_options.matmul_validation_mode)};
    auto& action{const_cast<kernel::DeepReorgAction&>(
        chainman.m_options.deep_reorg_action)};
    auto& hysteresis_work_margin{const_cast<std::optional<uint32_t>&>(
        chainman.m_options.reorg_hysteresis_work_margin)};
    struct Restore {
        Consensus::Params& consensus;
        int32_t v4;
        int32_t bmx;
        int32_t rc;
        kernel::MatMulValidationMode& mode;
        kernel::MatMulValidationMode saved_mode;
        kernel::DeepReorgAction& action;
        kernel::DeepReorgAction saved_action;
        std::optional<uint32_t>& hysteresis_work_margin;
        std::optional<uint32_t> saved_hysteresis_work_margin;
        ~Restore()
        {
            node::matmul_trusted::ResetForTest();
            consensus.nMatMulV4Height = v4;
            consensus.nMatMulBMX4CHeight = bmx;
            consensus.nMatMulRCHeight = rc;
            mode = saved_mode;
            action = saved_action;
            hysteresis_work_margin = saved_hysteresis_work_margin;
        }
    } restore{consensus,
              consensus.nMatMulV4Height,
              consensus.nMatMulBMX4CHeight,
              consensus.nMatMulRCHeight,
              mode,
              mode,
              action,
              action,
              hysteresis_work_margin,
              hysteresis_work_margin};
    mode = kernel::MatMulValidationMode::CONSENSUS;
    action = kernel::DeepReorgAction::WARN;
    hysteresis_work_margin = 0;

    const CScript script{
        GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()))};
    CKey competing_key;
    competing_key.MakeNewKey(/*fCompressed=*/true);
    const CScript competing_script{
        GetScriptForDestination(PKHash(competing_key.GetPubKey()))};
    CBlockIndex* const losing_tip{
        WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE(losing_tip != nullptr);
    CBlockIndex* const lca{losing_tip->pprev};
    BOOST_REQUIRE(lca != nullptr);

    BlockValidationState state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, losing_tip));
    std::vector<CBlockIndex*> competing;
    for (int i = 0; i < 4; ++i) {
        const CBlock block{CreateAndProcessBlock({}, competing_script)};
        CBlockIndex* const index{WITH_LOCK(
            ::cs_main,
            return chainman.m_blockman.LookupBlockIndex(block.GetHash()))};
        BOOST_REQUIRE(index != nullptr);
        competing.push_back(index);
    }
    BOOST_REQUIRE_EQUAL(competing.front()->pprev, lca);
    BOOST_REQUIRE(competing.back()->nChainWork > losing_tip->nChainWork);
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, competing.front()));
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(losing_tip);
    }
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) ==
                  losing_tip);
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(competing.front());
    }

    // Reclassify these already-stored test bodies as post-v4 data. Neither
    // branch initially has local ExactReplay provenance at those heights.
    consensus.nMatMulV4Height = losing_tip->nHeight;
    consensus.nMatMulBMX4CHeight = losing_tip->nHeight;
    consensus.nMatMulRCHeight = losing_tip->nHeight;
    {
        LOCK(::cs_main);
        losing_tip->nStatus &= ~BLOCK_EXACT_REPLAY_VERIFIED;
        UpdateAuthenticatedChainWork(*losing_tip, consensus);
        for (CBlockIndex* index : competing) {
            index->nStatus &= ~BLOCK_EXACT_REPLAY_VERIFIED;
            UpdateAuthenticatedChainWork(*index, consensus);
        }
    }

    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    const uint256 chain_id{uint256::ONE};
    const uint256 replay_ctx{
        uint256::FromHex(std::string(64, '8')).value()};
    matmul::trusted::StoreConfig config;
    config.chain_id = chain_id;
    config.replay_authority_context = replay_ctx;
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/false, /*serve=*/true,
        std::chrono::milliseconds{50}, error));

    // Persist on the active loser first: this models the occupied fork height.
    BOOST_REQUIRE(WITH_LOCK(
        ::cs_main,
        return chainman.PersistMatMulExactReplayVerdict(
            losing_tip->GetBlockHash())));
    BOOST_REQUIRE(node::matmul_trusted::HasQuorum(
        losing_tip->GetBlockHash(), losing_tip->nHeight));
    BOOST_REQUIRE(InjectHistoricalAttestation(
                      signer, chain_id, replay_ctx,
                      competing.back()->GetBlockHash(),
                      competing.back()->nHeight) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_REQUIRE(!node::matmul_trusted::HasQuorum(
        competing.front()->GetBlockHash(), competing.front()->nHeight));

    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(
            chainman.FindNextSignedFrontierExactReplayIndex(),
            competing.front());
        BOOST_CHECK(chainman.FindUniqueCompetingAttestedIndex() == nullptr);
    }

    // Recovery is root-first. Each late verdict promotes authenticated work
    // immediately; no restart/reindex is needed to expose the next block.
    for (size_t i = 0; i < competing.size(); ++i) {
        BOOST_REQUIRE(WITH_LOCK(
            ::cs_main,
            return chainman.PersistMatMulExactReplayVerdict(
                competing[i]->GetBlockHash())));
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(competing[i]->nAuthenticatedChainWork,
                          competing[i]->nChainWork);
        const CBlockIndex* const expected{
            i + 1 < competing.size() ? competing[i + 1]
                                     : competing.back()};
        BOOST_CHECK_EQUAL(
            chainman.FindNextSignedFrontierExactReplayIndex(), expected);
    }

    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainman.FindUniqueCompetingAttestedIndex(),
                          competing.back());
        BOOST_CHECK(chainman.IsAttestedAbandonForkCandidate(
            competing.back()));
        BOOST_CHECK(!node::matmul_trusted::HasQuorumInMemory(
            competing.front()->GetBlockHash(), competing.front()->nHeight));
    }
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) ==
                competing.back());
    chainman.CheckBlockIndex();
}

BOOST_FIXTURE_TEST_CASE(chainstate_trusted_mirror_rejoins_deep_signed_frontier, TestChain100Setup)
{
    // Live 2026-08-16: trusted archives crawled 13–180 unattested HAVE_DATA
    // blocks while the attested suffix was HEADER_ONLY. Short-reorg (1–6)
    // FindUnique adoption then refused the attested chain forever.
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
        std::optional<uint32_t>& park_depth;
        std::optional<uint32_t> saved_park_depth;
        kernel::MatMulValidationMode& mode;
        kernel::MatMulValidationMode saved_mode;
        ~Restore()
        {
            node::matmul_trusted::ResetForTest();
            consensus.nReorgProtectionStartHeight = start;
            action = saved_action;
            park_depth = saved_park_depth;
            mode = saved_mode;
        }
    } restore{consensus, consensus.nReorgProtectionStartHeight,
              action, action, park_depth, park_depth, mode, mode};
    consensus.nReorgProtectionStartHeight = 10;
    action = kernel::DeepReorgAction::PARK;
    park_depth = 32;
    mode = kernel::MatMulValidationMode::TRUSTED;

    const CScript script_unattested =
        GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CKey attested_dest;
    attested_dest.MakeNewKey(/*fCompressed=*/true);
    const CScript script_attested =
        GetScriptForDestination(PKHash(attested_dest.GetPubKey()));
    CBlockIndex* lca{WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE(lca != nullptr);
    constexpr int kDepth{node::matmul_trusted::TRUSTED_MIRROR_SHORT_REORG_DEPTH + 2};
    BOOST_REQUIRE_GT(kDepth, node::matmul_trusted::TRUSTED_MIRROR_SHORT_REORG_DEPTH);

    std::vector<CBlockIndex*> unattested;
    unattested.reserve(kDepth);
    for (int i = 0; i < kDepth; ++i) {
        const CBlock block{CreateAndProcessBlock({}, script_unattested)};
        CBlockIndex* idx{WITH_LOCK(::cs_main, {
            return chainman.m_blockman.LookupBlockIndex(block.GetHash());
        })};
        BOOST_REQUIRE(idx != nullptr);
        unattested.push_back(idx);
    }
    CBlockIndex* const unattested_tip{unattested.back()};
    BlockValidationState state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, unattested.front()));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == lca);

    std::vector<CBlockIndex*> attested;
    attested.reserve(kDepth);
    for (int i = 0; i < kDepth; ++i) {
        const CBlock block{CreateAndProcessBlock({}, script_attested)};
        CBlockIndex* idx{WITH_LOCK(::cs_main, {
            return chainman.m_blockman.LookupBlockIndex(block.GetHash());
        })};
        BOOST_REQUIRE(idx != nullptr);
        attested.push_back(idx);
    }
    CBlockIndex* const attested_tip{attested.back()};
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, attested.front()));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == lca);
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(unattested.front());
    }
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == unattested_tip);

    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    const uint256 chain_id{uint256::ONE};
    const uint256 replay_ctx{
        uint256::FromHex(std::string(64, 'c')).value()};
    matmul::trusted::StoreConfig config;
    config.chain_id = chain_id;
    config.replay_authority_context = replay_ctx;
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    for (CBlockIndex* idx : attested) {
        BOOST_REQUIRE(InjectHistoricalAttestation(
                          signer, chain_id, replay_ctx, idx->GetBlockHash(),
                          idx->nHeight) ==
                      matmul::trusted::AddResult::Accepted);
    }
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(attested.front());
        BOOST_REQUIRE(node::matmul_trusted::HasQuorum(
            attested_tip->GetBlockHash(), attested_tip->nHeight));
        BOOST_CHECK(!chainman.GetSignedFrontierStatus().on_active_chain);
        BOOST_CHECK(chainman.IndexLeadsToSignedFrontier(attested_tip));
        BOOST_CHECK(chainman.IndexLeadsToSignedFrontier(attested.front()));
        BOOST_CHECK(!chainman.IndexLeadsToSignedFrontier(unattested_tip));
        BOOST_CHECK(chainman.IndexIsOnSignedFrontierChain(attested_tip));
        BOOST_CHECK(chainman.IndexIsOnSignedFrontierChain(attested.front()));
        BOOST_CHECK(!chainman.IndexIsOnSignedFrontierChain(unattested_tip));
        BOOST_CHECK_EQUAL(chainman.FindUniqueCompetingAttestedIndex(),
                          attested_tip);
        BOOST_CHECK(chainman.IsAttestedAbandonForkCandidate(attested_tip));
        BOOST_CHECK(!node::matmul_trusted::TrustedMirrorMaySelectMostWorkCandidate(
            /*extends_active_tip_chain=*/true, /*short_tip_reorg=*/false,
            /*has_quorum=*/false, /*active_tip_has_quorum=*/false,
            /*immediate_tip_child=*/true, /*would_abandon_attested=*/false,
            /*competing_attested_height=*/false,
            /*signed_frontier_on_competing_fork=*/true));
    }

    // An explicit PARK boundary remains operator finality even for a newly
    // discovered signed branch. This also guards against an unpark/repark loop
    // in FindMostWorkChain when a 1-of-1 signer is cloned or compromised.
    park_depth = kDepth - 1;
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) ==
                unattested_tip);
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.IsOnParkedReorgBranch(
                                             attested_tip)));

    // Raising the explicit boundary makes the same unique frontier eligible;
    // no invalidation or restart is required.
    park_depth = 32;
    {
        LOCK(::cs_main);
        chainstate.TryAddBlockIndexCandidate(attested_tip);
    }
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == attested_tip);
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.GetSignedFrontierStatus().on_active_chain));
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.FindUniqueCompetingAttestedIndex()) ==
                nullptr);
}

BOOST_AUTO_TEST_SUITE_END()
