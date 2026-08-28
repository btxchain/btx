// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <addresstype.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <kernel/chainstatemanager_opts.h>
#include <node/blockstorage.h>
#include <node/kernel_notifications.h>
#include <node/miner.h>
#include <matmul/trusted_exact_replay_attestation.h>
#include <node/matmul_trusted_attestations.h>
#include <node/warnings.h>
#include <primitives/transaction.h>
#include <random.h>
#include <rpc/blockchain.h>
#include <sync.h>
#include <test/util/chainstate.h>
#include <test/util/coins.h>
#include <test/util/mining.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/check.h>
#include <util/mempressure.h>
#include <util/time.h>
#include <validation.h>

#include <array>
#include <atomic>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <chrono>
#include <set>
#include <string>
#include <thread>
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

//! Unindexed dump headers (not in BlockManager). GetAncestor walks pprev.
//! Hijack 2.2: attacker-chosen nTime + nTimeReceived==0 must not become extra.
CBlockIndex* BuildUnindexedDump(std::array<CBlockIndex, 40>& nodes, CBlockIndex* tip,
                                int64_t attacker_nTime)
{
    CBlockIndex* prev = tip;
    for (auto& node : nodes) {
        node.pprev = prev;
        node.nHeight = prev->nHeight + 1;
        node.nTime = static_cast<unsigned int>(attacker_nTime);
        node.nTimeReceived = 0;
        node.nTimeBodyReceived = 0;
        prev = &node;
    }
    return prev;
}

//! Gold-standard litmus (doc/design/0.34-ai-native-bitcoin.md): clearing
//! every attestation must not change consensus fork choice or ExactReplay
//! bits. Capture is the production ChainstateManager result, not a helper
//! predicate.
struct ConsensusGoldStandardChoice {
    uint256 tip{};
    uint256 fmwc{};
    std::set<uint256> connected;
    std::map<uint256, bool> exact_replay_verified;
};

ConsensusGoldStandardChoice CaptureConsensusGoldStandardChoice(
    ChainstateManager& chainman,
    Chainstate& chainstate,
    const std::vector<CBlockIndex*>& watch)
{
    AssertLockHeld(::cs_main);
    ConsensusGoldStandardChoice out;
    CBlockIndex* const tip{chainstate.m_chain.Tip()};
    BOOST_REQUIRE(tip != nullptr);
    out.tip = tip->GetBlockHash();
    for (int h = 0; h <= tip->nHeight; ++h) {
        const CBlockIndex* p{chainstate.m_chain[h]};
        BOOST_REQUIRE(p != nullptr);
        out.connected.insert(p->GetBlockHash());
    }
    CBlockIndex* const fmwc{chainstate.FindMostWorkChainForTest()};
    if (fmwc != nullptr) out.fmwc = fmwc->GetBlockHash();
    for (CBlockIndex* p : watch) {
        if (p == nullptr) continue;
        out.exact_replay_verified[p->GetBlockHash()] =
            (p->nStatus & BLOCK_EXACT_REPLAY_VERIFIED) != 0;
    }
    (void)chainman;
    return out;
}

void RewindToParentAndActivate(Chainstate& chainstate, CBlockIndex* parent,
                               const std::vector<CBlockIndex*>& branch_roots)
{
    CBlockIndex* tip{WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    if (tip != parent) {
        CBlockIndex* child{
            WITH_LOCK(::cs_main, return chainstate.m_chain[parent->nHeight + 1])};
        BOOST_REQUIRE(child != nullptr);
        BlockValidationState state;
        BOOST_REQUIRE(chainstate.InvalidateBlock(state, child));
    }
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == parent);
    {
        LOCK(::cs_main);
        for (CBlockIndex* root : branch_roots) {
            if (root != nullptr) chainstate.ResetBlockFailureFlags(root);
        }
    }
    BlockValidationState state;
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
}

void CheckGoldStandardUnchanged(const ConsensusGoldStandardChoice& with_attestations,
                                const ConsensusGoldStandardChoice& without_attestations)
{
    BOOST_CHECK_MESSAGE(
        with_attestations.tip == without_attestations.tip,
        "gold-standard tip changed after clearing attestations with=" +
            with_attestations.tip.ToString() + " without=" +
            without_attestations.tip.ToString());
    BOOST_CHECK_MESSAGE(
        with_attestations.fmwc == without_attestations.fmwc,
        "gold-standard FindMostWorkChain changed after clearing attestations with=" +
            with_attestations.fmwc.ToString() + " without=" +
            without_attestations.fmwc.ToString());
    BOOST_CHECK_MESSAGE(
        with_attestations.connected == without_attestations.connected,
        "gold-standard connected set changed after clearing attestations");
    BOOST_CHECK_MESSAGE(
        with_attestations.exact_replay_verified ==
            without_attestations.exact_replay_verified,
        "gold-standard BLOCK_EXACT_REPLAY_VERIFIED bits changed after clearing attestations");
}

//! Live 2026-08-17 miner: a node that SignAuthoritative'd its own losing
//! twin stays pinned at H while the signed frontier is already downloaded
//! N blocks up the other fork. CONSENSUS hits the 190354 quorum-tip guard;
//! flipping `-matmulvalidation=trusted` used to stay pinned too because
//! FindUnique nominated the same-height fork-child (dual-quorum flip)
//! instead of the frontier. Cover both store states.
void SelfSignedLosingTwinRejoinsSignedFrontier(TestChain100Setup& t,
                                               bool trusted_mirror)
{
    ChainstateManager& chainman = *Assert(t.m_node.chainman);
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
    mode = trusted_mirror ? kernel::MatMulValidationMode::TRUSTED
                          : kernel::MatMulValidationMode::CONSENSUS;

    const CScript script_losing =
        GetScriptForDestination(PKHash(t.coinbaseKey.GetPubKey()));
    CKey attested_dest;
    attested_dest.MakeNewKey(/*fCompressed=*/true);
    const CScript script_attested =
        GetScriptForDestination(PKHash(attested_dest.GetPubKey()));
    CBlockIndex* lca{WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE(lca != nullptr);
    constexpr int kFrontierAhead{node::matmul_trusted::TRUSTED_MIRROR_SHORT_REORG_DEPTH + 2};

    const CBlock losing_block{t.CreateAndProcessBlock({}, script_losing)};
    CBlockIndex* const losing_tip{WITH_LOCK(::cs_main, {
        return chainman.m_blockman.LookupBlockIndex(losing_block.GetHash());
    })};
    BOOST_REQUIRE(losing_tip != nullptr);
    BlockValidationState state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, losing_tip));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == lca);

    std::vector<CBlockIndex*> attested;
    attested.reserve(kFrontierAhead);
    for (int i = 0; i < kFrontierAhead; ++i) {
        const CBlock block{t.CreateAndProcessBlock({}, script_attested)};
        CBlockIndex* idx{WITH_LOCK(::cs_main, {
            return chainman.m_blockman.LookupBlockIndex(block.GetHash());
        })};
        BOOST_REQUIRE(idx != nullptr);
        attested.push_back(idx);
    }
    CBlockIndex* const attested_tip{attested.back()};
    BOOST_REQUIRE_GT(attested_tip->nHeight, losing_tip->nHeight);
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, attested.front()));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == lca);
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(losing_tip);
    }
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == losing_tip);

    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    const uint256 chain_id{uint256::ONE};
    const uint256 replay_ctx{
        uint256::FromHex(std::string(64, trusted_mirror ? 'b' : 'd')).value()};
    matmul::trusted::StoreConfig config;
    config.chain_id = chain_id;
    config.replay_authority_context = replay_ctx;
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), trusted_mirror, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::HasLocalSigner());
    BOOST_REQUIRE(node::matmul_trusted::IsTrustedMirror() == trusted_mirror);
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      losing_tip->GetBlockHash(), losing_tip->nHeight) ==
                  matmul::trusted::AddResult::Accepted);
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
            losing_tip->GetBlockHash(), losing_tip->nHeight));
        BOOST_REQUIRE(node::matmul_trusted::HasQuorum(
            attested_tip->GetBlockHash(), attested_tip->nHeight));
        BOOST_CHECK(!chainman.GetSignedFrontierStatus().on_active_chain);
        BOOST_CHECK(chainman.IndexIsOnSignedFrontierChain(attested_tip));
        BOOST_CHECK(!chainman.IndexIsOnSignedFrontierChain(losing_tip));
        BOOST_CHECK(node::matmul_trusted::
                        ConsensusSignerMayAbandonQuorumTipForSignedFrontier(
                            /*unique_on_signed_frontier_chain=*/true,
                            attested_tip->nHeight, losing_tip->nHeight));
        BOOST_CHECK_EQUAL(chainman.FindUniqueCompetingAttestedIndex(),
                          attested_tip);
        BOOST_CHECK(chainman.IsAttestedAbandonForkCandidate(attested_tip));
    }

    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == attested_tip);
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.GetSignedFrontierStatus().on_active_chain));
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.FindUniqueCompetingAttestedIndex()) ==
                nullptr);
    chainman.CheckBlockIndex();
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
//!
//! Keep the default regtest MatMul schedule (`defer_expensive_matmul=false`).
//! Cheap-matmul injects `-regtestmatmul*` heights, which is custom_consensus
//! and clears `m_assumeutxo_data` — this case needs the Phase-B canned
//! assumeutxo@110 metadata. It tests UpdateTip notifications, not ExactReplay.
struct AssumeutxoTestChain100Setup : TestChain100Setup {
    AssumeutxoTestChain100Setup()
        : TestChain100Setup(
              ChainType::REGTEST,
              {.defer_expensive_matmul = false,
               .freeze_coinbase_extra_nonce = true})
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
    // Live 2026-08-14 archive-A: two tip-children of 187931. Attested a18786b0
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
    // with the attested twin headers-only. Live archive-A: MMATTEST can land before
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

BOOST_FIXTURE_TEST_CASE(chainstate_consensus_does_not_skip_unattested_when_height_attested, TestChain100Setup)
{
    // Gold standard: CONSENSUS — with or without a local signer — still
    // ExactReplays a followed unattested HAVE_DATA twin. Pin quorum on a
    // sibling is telemetry, not FindMostWorkChain refusal. Trusted mirrors
    // keep the overlay (ConnectTip would otherwise timeout). The 2026-08-15
    // dual-sign stall is HeightOccupied / SignAuthoritative, not FMWC.
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
        BOOST_CHECK_EQUAL(chainstate.FindMostWorkChainForTest(), unattested_index);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip(), parent_tip);
        BOOST_CHECK(chainman.FindUniqueCompetingAttestedIndex() == nullptr);
        BOOST_CHECK(!chainman.IsAttestedAbandonForkCandidate(unattested_index));
    }
    chainman.CheckBlockIndex();
}

BOOST_FIXTURE_TEST_CASE(chainstate_consensus_pin_without_signer_does_not_findunique, TestChain100Setup)
{
    // Gold standard: consensus+pin with no local WIF must not let a
    // foreign pin steer FindUniqueCompetingAttestedIndex. Local signers
    // still recover a lost twin.
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
    CKey other;
    other.MakeNewKey(/*fCompressed=*/true);
    const CScript script_alt = GetScriptForDestination(PKHash(other.GetPubKey()));
    CBlockIndex* parent_tip{
        WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE(parent_tip != nullptr);

    const auto first{std::make_shared<const CBlock>(
        CreateBlock({}, script, chainstate))};
    const auto sibling{std::make_shared<const CBlock>(
        CreateBlock({}, script_alt, chainstate))};
    BOOST_REQUIRE(first->GetHash() != sibling->GetHash());
    bool new_block{false};
    BOOST_REQUIRE(chainman.ProcessNewBlock(
        first, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_REQUIRE(chainman.ProcessNewBlock(
        sibling, /*force_processing=*/true, /*min_pow_checked=*/true,
        &new_block));

    CBlockIndex* first_index{nullptr};
    CBlockIndex* sibling_index{nullptr};
    {
        LOCK(::cs_main);
        first_index = chainman.m_blockman.LookupBlockIndex(first->GetHash());
        sibling_index =
            chainman.m_blockman.LookupBlockIndex(sibling->GetHash());
        BOOST_REQUIRE(first_index && sibling_index);
        BOOST_CHECK(first_index->nStatus & BLOCK_HAVE_DATA);
        BOOST_CHECK(sibling_index->nStatus & BLOCK_HAVE_DATA);
    }

    CKey pin;
    pin.MakeNewKey(/*fCompressed=*/true);
    const uint256 chain_id{uint256::ONE};
    const uint256 replay_ctx{
        uint256::FromHex(std::string(64, 'b')).value()};
    auto add_quorum = [&](const uint256& hash, int32_t height) {
        matmul::trusted::ExactReplayStatement statement;
        statement.chain_id = chain_id;
        statement.block_hash = hash;
        statement.block_height = height;
        statement.replay_authority_context = replay_ctx;
        const auto attestation{matmul::trusted::SignStatement(statement, pin)};
        BOOST_REQUIRE(attestation.has_value());
        const auto added{node::matmul_trusted::Add(*attestation, hash, height)};
        BOOST_REQUIRE(added == matmul::trusted::AddResult::Accepted ||
                      added == matmul::trusted::AddResult::Duplicate);
    };

    matmul::trusted::StoreConfig no_wif;
    no_wif.chain_id = chain_id;
    no_wif.replay_authority_context = replay_ctx;
    no_wif.trusted_signers = {pin.GetPubKey()};
    no_wif.threshold = 1;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(no_wif), /*trusted_mirror=*/false, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(!node::matmul_trusted::HasLocalSigner());
    BOOST_REQUIRE(!node::matmul_trusted::IsTrustedMirror());
    CBlockIndex* const loser{
        WITH_LOCK(::cs_main, return chainstate.m_chain.Contains(sibling_index) ?
                                    first_index : sibling_index)};
    add_quorum(loser->GetBlockHash(), loser->nHeight);
    BOOST_CHECK(node::matmul_trusted::HasQuorum(
        loser->GetBlockHash(), loser->nHeight));
    BOOST_CHECK(WITH_LOCK(::cs_main,
                          return chainman.FindUniqueCompetingAttestedIndex()) ==
                nullptr);

    node::matmul_trusted::ResetForTest();
    matmul::trusted::StoreConfig with_wif;
    with_wif.chain_id = chain_id;
    with_wif.replay_authority_context = replay_ctx;
    with_wif.trusted_signers = {pin.GetPubKey()};
    with_wif.threshold = 1;
    with_wif.local_signer = pin;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(with_wif), /*trusted_mirror=*/false, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::HasLocalSigner());
    add_quorum(loser->GetBlockHash(), loser->nHeight);
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainman.FindUniqueCompetingAttestedIndex(), loser);
        BOOST_CHECK(chainman.IsAttestedAbandonForkCandidate(loser));
    }
}

BOOST_FIXTURE_TEST_CASE(chainstate_consensus_does_not_persist_trusted_replay_from_pin, TestChain100Setup)
{
    // GETMMATTEST serve-budget skip and Heard open-WIF must not mint
    // BLOCK_TRUSTED_REPLAY_ATTESTED on consensus: that bit authenticates
    // chainwork. Trusted mirrors may persist it only when the pin covers
    // this hash.
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

    CBlockIndex* tip{WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE(tip != nullptr);
    consensus.nMatMulV4Height = tip->nHeight;
    consensus.nMatMulBMX4CHeight = tip->nHeight;
    consensus.nMatMulRCHeight = tip->nHeight;
    BOOST_REQUIRE(consensus.IsMatMulTrustedReplayAttestationActive(tip->nHeight));

    CKey pin;
    pin.MakeNewKey(/*fCompressed=*/true);
    const uint256 chain_id{uint256::ONE};
    const uint256 replay_ctx{uint256::FromHex(std::string(64, 'f')).value()};
    std::string error;
    matmul::trusted::StoreConfig consensus_wif;
    consensus_wif.chain_id = chain_id;
    consensus_wif.replay_authority_context = replay_ctx;
    consensus_wif.trusted_signers = {pin.GetPubKey()};
    consensus_wif.threshold = 1;
    consensus_wif.local_signer = pin;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(consensus_wif), /*trusted_mirror=*/false, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    mode = kernel::MatMulValidationMode::CONSENSUS;
    BOOST_REQUIRE(node::matmul_trusted::HasLocalSigner());
    BOOST_REQUIRE(!node::matmul_trusted::IsTrustedMirror());
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      tip->GetBlockHash(), tip->nHeight) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(node::matmul_trusted::HasQuorum(
        tip->GetBlockHash(), tip->nHeight));
    {
        LOCK(::cs_main);
        const uint32_t before{tip->nStatus};
        BOOST_CHECK(!chainman.PersistMatMulTrustedReplayAttestation(
            tip->GetBlockHash()));
        BOOST_CHECK_EQUAL(tip->nStatus, before);
        BOOST_CHECK((tip->nStatus & BLOCK_TRUSTED_REPLAY_ATTESTED) == 0);
        // Stale 0.33-era trusted bit on a consensus datadir with pin
        // coverage must not keep nAuthenticatedChainWork.
        tip->nStatus |= BLOCK_TRUSTED_REPLAY_ATTESTED;
        std::array<CBlockIndex*, 1> indices{tip};
        std::set<CBlockIndex*> dirty;
        const uint256 ctx{1};
        const auto migration{node::ReconcileMatMulReplayAuthorityContext(
            indices, ctx, ctx, dirty)};
        BOOST_CHECK_EQUAL(migration.cleared_trusted_status, 1U);
        BOOST_CHECK((tip->nStatus & BLOCK_TRUSTED_REPLAY_ATTESTED) == 0);
    }

    node::matmul_trusted::ResetForTest();
    matmul::trusted::StoreConfig mirror_no_quorum;
    mirror_no_quorum.chain_id = chain_id;
    mirror_no_quorum.replay_authority_context = replay_ctx;
    mirror_no_quorum.trusted_signers = {pin.GetPubKey()};
    mirror_no_quorum.threshold = 1;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(mirror_no_quorum), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    mode = kernel::MatMulValidationMode::TRUSTED;
    BOOST_REQUIRE(node::matmul_trusted::IsTrustedMirror());
    BOOST_CHECK(!node::matmul_trusted::HasQuorum(
        tip->GetBlockHash(), tip->nHeight));
    {
        LOCK(::cs_main);
        BOOST_CHECK(!chainman.IndexHasTrustedMatMulAuthority(tip));
        BOOST_CHECK(!chainman.PersistMatMulTrustedReplayAttestation(
            tip->GetBlockHash()));
        BOOST_CHECK((tip->nStatus & BLOCK_TRUSTED_REPLAY_ATTESTED) == 0);
    }

    matmul::trusted::ExactReplayStatement statement;
    statement.chain_id = chain_id;
    statement.block_hash = tip->GetBlockHash();
    statement.block_height = tip->nHeight;
    statement.replay_authority_context = replay_ctx;
    const auto attestation{matmul::trusted::SignStatement(statement, pin)};
    BOOST_REQUIRE(attestation.has_value());
    BOOST_REQUIRE(node::matmul_trusted::Add(
                      *attestation, tip->GetBlockHash(), tip->nHeight) ==
                  matmul::trusted::AddResult::Accepted);
    {
        LOCK(::cs_main);
        BOOST_CHECK(chainman.IndexHasTrustedMatMulAuthority(tip));
        BOOST_CHECK(chainman.PersistMatMulTrustedReplayAttestation(
            tip->GetBlockHash()));
        BOOST_CHECK((tip->nStatus & BLOCK_TRUSTED_REPLAY_ATTESTED) != 0);
        std::array<CBlockIndex*, 1> indices{tip};
        std::set<CBlockIndex*> dirty;
        const uint256 ctx{1};
        const auto migration{node::ReconcileMatMulReplayAuthorityContext(
            indices, ctx, ctx, dirty)};
        BOOST_CHECK_EQUAL(migration.cleared_trusted_status, 0U);
        BOOST_CHECK((tip->nStatus & BLOCK_TRUSTED_REPLAY_ATTESTED) != 0);
    }
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
        // Gold standard: consensus FMWC is most authenticated work, not the
        // pin. A heavier unattested HAVE_DATA fork may win here; trusted
        // mirrors still skip that tower. The 190376 stall was GETDATA
        // follow (IndexIsFollowedTipChild vs IndexIsAttestedChainTipChild),
        // not pin-steered FindMostWorkChain.
        BOOST_CHECK(most_work == fork_tip || most_work == original_tip ||
                    most_work == ours_index);
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
    chainman.CheckBlockIndex();
}

BOOST_FIXTURE_TEST_CASE(chainstate_consensus_signer_rejoins_signed_frontier_from_losing_twin, TestChain100Setup)
{
    // CONSENSUS GPU miner attested its own losing twin; signed frontier
    // already HAVE_DATA on the other fork. Must reorg without
    // invalidateblock. Same-height dual-quorum twins still stay put
    // (chainstate_signer_does_not_abandon_attested_tip_for_dual_quorum_twin).
    SelfSignedLosingTwinRejoinsSignedFrontier(*this, /*trusted_mirror=*/false);
}

BOOST_FIXTURE_TEST_CASE(chainstate_trusted_follow_rejoins_signed_frontier_from_self_signed_twin, TestChain100Setup)
{
    // Same local attestation store as the consensus miner (self-signed
    // losing twin still in quorum). Flipping to trusted used to stay
    // pinned at H with on_active_chain=false (live 2026-08-17, H=191397,
    // blocks_behind=7) until matmul_attestations.{dat,db,wal} was moved
    // aside. Must recover without wiping the store.
    SelfSignedLosingTwinRejoinsSignedFrontier(*this, /*trusted_mirror=*/true);
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

    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == attested_tip);
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.GetSignedFrontierStatus().on_active_chain));
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.FindUniqueCompetingAttestedIndex()) ==
                nullptr);
}

BOOST_FIXTURE_TEST_CASE(chainstate_trusted_mirror_connects_frontier_suffix_without_per_block_quorum, TestChain100Setup)
{
    // Dumb-mirror catch-up: the GPU attests only the frontier hash. Archives
    // must ConnectTip the ancestor suffix without per-block MMATTEST or
    // ExactReplay (live 2026-08-16: 60–90s/block waiting for signatures
    // already implied by the signed frontier).
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
    CBlockIndex* const parent{WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE(parent != nullptr);

    constexpr int kSuffix{8};
    std::vector<CBlockIndex*> suffix;
    suffix.reserve(kSuffix);
    for (int i = 0; i < kSuffix; ++i) {
        const CBlock block{CreateAndProcessBlock({}, script)};
        CBlockIndex* idx{WITH_LOCK(::cs_main, {
            return chainman.m_blockman.LookupBlockIndex(block.GetHash());
        })};
        BOOST_REQUIRE(idx != nullptr);
        suffix.push_back(idx);
    }
    CBlockIndex* const first{suffix.front()};
    CBlockIndex* const last{suffix.back()};
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == last);

    consensus.nMatMulV4Height = first->nHeight;
    consensus.nMatMulBMX4CHeight = first->nHeight;
    consensus.nMatMulRCHeight = first->nHeight;
    BOOST_REQUIRE(consensus.IsMatMulTrustedReplayAttestationActive(first->nHeight));
    BOOST_REQUIRE(consensus.IsMatMulTrustedReplayAttestationActive(last->nHeight));

    BlockValidationState state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, first));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == parent);

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
    mode = kernel::MatMulValidationMode::TRUSTED;
    BOOST_REQUIRE(node::matmul_trusted::IsTrustedMirror());
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      last->GetBlockHash(), last->nHeight) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(node::matmul_trusted::HasQuorum(last->GetBlockHash(), last->nHeight));
    for (size_t i = 0; i + 1 < suffix.size(); ++i) {
        BOOST_CHECK(!node::matmul_trusted::HasQuorum(
            suffix[i]->GetBlockHash(), suffix[i]->nHeight));
    }
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(first);
        BOOST_CHECK(chainman.IndexIsCoveredBySignedFrontier(first));
        BOOST_CHECK(chainman.IndexIsCoveredBySignedFrontier(last));
        BOOST_CHECK(chainman.IndexHasTrustedMatMulAuthority(first));
        BOOST_CHECK(chainman.IndexHasTrustedMatMulAuthority(last));
        BOOST_CHECK(!node::matmul_trusted::TrustedMirrorMustDeferUnattestedConnect(
            /*trusted_mirror_profile1=*/true, /*has_quorum=*/false,
            /*covered_by_signed_frontier=*/true));
        BOOST_CHECK(!node::matmul_trusted::MustDeferConflictingAttestedHeight(
            /*trusted_mirror=*/true, /*candidate_has_quorum=*/false,
            /*competing_attested_height=*/true,
            /*covered_by_signed_frontier=*/true));
    }

    const auto t0{std::chrono::steady_clock::now()};
    chainman.ResetTrustedMirrorExactReplayInvocationsForTest();
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    const auto elapsed{std::chrono::steady_clock::now() - t0};
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == last);
    for (CBlockIndex* idx : suffix) {
        BOOST_CHECK(WITH_LOCK(::cs_main, return chainstate.m_chain.Contains(idx)));
    }
    BOOST_CHECK_EQUAL(chainman.TrustedMirrorExactReplayInvocationsForTest(), 0);
    BOOST_CHECK_LT(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(), 60);
    chainman.CheckBlockIndex();
}

BOOST_FIXTURE_TEST_CASE(chainstate_recalculate_best_header_follows_unattested_tip_suffix, TestChain100Setup)
{
    // Live archives 2026-08-17 after e2c92315: RecalculateBestHeader required
    // in-memory quorum on the active tip before walking HEADER_ONLY
    // descendants. Restart empties that store, so m_best_header stayed at
    // the connected tip while a 98-block GPU suffix sat headers-only and
    // sent_getdata stayed 0. Follow the unique suffix of the active tip
    // even without quorum; competing forks still need current-config quorum.
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
    CBlockIndex* const parent{WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE(parent != nullptr);

    std::vector<CBlockIndex*> suffix;
    for (int i = 0; i < 3; ++i) {
        const CBlock block{CreateAndProcessBlock({}, script)};
        CBlockIndex* idx{WITH_LOCK(::cs_main, {
            return chainman.m_blockman.LookupBlockIndex(block.GetHash());
        })};
        BOOST_REQUIRE(idx != nullptr);
        suffix.push_back(idx);
    }
    CBlockIndex* const first{suffix.front()};
    CBlockIndex* const last{suffix.back()};

    consensus.nMatMulV4Height = first->nHeight;
    consensus.nMatMulBMX4CHeight = first->nHeight;
    consensus.nMatMulRCHeight = first->nHeight;

    BlockValidationState state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, first));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == parent);

    CKey gpu;
    gpu.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::ONE;
    config.replay_authority_context = uint256::FromHex(std::string(64, 'a')).value();
    config.trusted_signers = {gpu.GetPubKey()};
    config.threshold = 1;
    config.local_signer = gpu;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    mode = kernel::MatMulValidationMode::TRUSTED;

    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(first);
        BOOST_CHECK(!chainman.IndexHasTrustedMatMulAuthority(parent));
        BOOST_CHECK(!chainman.IndexHasTrustedMatMulAuthority(last));
        chainman.SetBestHeader(parent);
        chainman.RecalculateBestHeader();
        BOOST_REQUIRE(chainman.m_best_header != nullptr);
        BOOST_CHECK_EQUAL(chainman.m_best_header, last);
        BOOST_CHECK_EQUAL(chainman.m_best_header->GetAncestor(parent->nHeight), parent);
    }
    chainman.CheckBlockIndex();
}

BOOST_FIXTURE_TEST_CASE(chainstate_trusted_mirror_frontier_coverage_fail_closed, TestChain100Setup)
{
    // Coverage is not a skip of signatures: no quorum, a key outside the
    // configured GPU set, and a block above the signed frontier must all
    // stay disconnected (infinite-mint). Off-path hashes are not covered
    // (TrustedMirrorFrontierCoversBlock requires frontier ancestry).
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
    CBlockIndex* const parent{WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE(parent != nullptr);

    std::vector<CBlockIndex*> suffix;
    for (int i = 0; i < 3; ++i) {
        const CBlock block{CreateAndProcessBlock({}, script)};
        CBlockIndex* idx{WITH_LOCK(::cs_main, {
            return chainman.m_blockman.LookupBlockIndex(block.GetHash());
        })};
        BOOST_REQUIRE(idx != nullptr);
        suffix.push_back(idx);
    }
    CBlockIndex* const first{suffix.front()};
    CBlockIndex* const last{suffix.back()};

    consensus.nMatMulV4Height = first->nHeight;
    consensus.nMatMulBMX4CHeight = first->nHeight;
    consensus.nMatMulRCHeight = first->nHeight;

    BlockValidationState state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, first));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == parent);

    CKey gpu;
    gpu.MakeNewKey(/*fCompressed=*/true);
    const uint256 chain_id{uint256::ONE};
    const uint256 replay_ctx{
        uint256::FromHex(std::string(64, 'e')).value()};
    matmul::trusted::StoreConfig config;
    config.chain_id = chain_id;
    config.replay_authority_context = replay_ctx;
    config.trusted_signers = {gpu.GetPubKey()};
    config.threshold = 1;
    config.local_signer = gpu;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    mode = kernel::MatMulValidationMode::TRUSTED;

    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(first);
        BOOST_CHECK(!chainman.IndexIsCoveredBySignedFrontier(first));
        BOOST_CHECK(!chainman.IndexHasTrustedMatMulAuthority(first));
        BOOST_CHECK(!chainman.IndexHasTrustedMatMulAuthority(last));
    }
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == parent);

    CKey fake;
    fake.MakeNewKey(/*fCompressed=*/true);
    BOOST_CHECK_EQUAL(
        InjectHistoricalAttestation(
            fake, chain_id, replay_ctx, last->GetBlockHash(), last->nHeight),
        matmul::trusted::AddResult::UntrustedSigner);
    BOOST_CHECK(!node::matmul_trusted::HasQuorum(last->GetBlockHash(), last->nHeight));
    BOOST_CHECK(WITH_LOCK(::cs_main, return !chainman.IndexIsCoveredBySignedFrontier(first)));
    BOOST_CHECK(WITH_LOCK(::cs_main, return !chainman.IndexHasTrustedMatMulAuthority(last)));
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == parent);

    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      last->GetBlockHash(), last->nHeight) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(node::matmul_trusted::HasQuorum(last->GetBlockHash(), last->nHeight));
    {
        LOCK(::cs_main);
        BOOST_CHECK(chainman.IndexIsCoveredBySignedFrontier(first));
        BOOST_CHECK(chainman.IndexHasTrustedMatMulAuthority(first));
        BOOST_CHECK(chainman.IndexHasTrustedMatMulAuthority(last));
        for (CBlockIndex* idx : suffix) {
            chainstate.TryAddBlockIndexCandidate(idx);
        }
    }

    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == last);
    for (CBlockIndex* idx : suffix) {
        BOOST_CHECK(WITH_LOCK(::cs_main, return chainstate.m_chain.Contains(idx)));
    }

    const CBlock above{CreateAndProcessBlock({}, script)};
    CBlockIndex* const above_idx{WITH_LOCK(::cs_main, {
        return chainman.m_blockman.LookupBlockIndex(above.GetHash());
    })};
    BOOST_REQUIRE(above_idx != nullptr);
    BOOST_CHECK(WITH_LOCK(::cs_main, return !chainman.IndexIsCoveredBySignedFrontier(above_idx)));
    BOOST_CHECK(WITH_LOCK(::cs_main, return !chainman.IndexHasTrustedMatMulAuthority(above_idx)));
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == last);
    chainman.CheckBlockIndex();
}

BOOST_FIXTURE_TEST_CASE(chainstate_trusted_mirror_covered_connecttip_skips_exact_replay, TestChain100Setup)
{
    // Covered ConnectTip must not invoke ExactReplay. Live public CPU archive 2026-08-17:
    // accept-path path=frontier already skipped MatMul; ConnectTip of a
    // 1-tx suffix block must stay script/UTXO-only.
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
    CBlockIndex* const parent{WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE(parent != nullptr);

    const CBlock block{CreateAndProcessBlock({}, script)};
    CBlockIndex* const child{WITH_LOCK(::cs_main, {
        return chainman.m_blockman.LookupBlockIndex(block.GetHash());
    })};
    BOOST_REQUIRE(child != nullptr);
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == child);

    consensus.nMatMulV4Height = child->nHeight;
    consensus.nMatMulBMX4CHeight = child->nHeight;
    consensus.nMatMulRCHeight = child->nHeight;
    BOOST_REQUIRE(consensus.IsMatMulTrustedReplayAttestationActive(child->nHeight));

    BlockValidationState state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, child));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == parent);

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
    BOOST_REQUIRE(node::matmul_trusted::IsTrustedMirror());
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      child->GetBlockHash(), child->nHeight) ==
                  matmul::trusted::AddResult::Accepted);
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(child);
        BOOST_CHECK(chainman.IndexHasTrustedMatMulAuthority(child));
        BOOST_CHECK(!node::matmul_trusted::TrustedMirrorMustDeferUnattestedConnect(
            /*trusted_mirror_profile1=*/true, /*has_quorum=*/true,
            /*covered_by_signed_frontier=*/true));
    }

    chainman.ResetTrustedMirrorExactReplayInvocationsForTest();
    state = BlockValidationState{};
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == child);
    BOOST_CHECK_EQUAL(chainman.TrustedMirrorExactReplayInvocationsForTest(), 0);
    chainman.CheckBlockIndex();
}

BOOST_FIXTURE_TEST_CASE(chainstate_exact_replay_drops_cs_main_for_recompute, TestChain100Setup)
{
    // TestBlockValidity ExactReplay must drop cs_main for the whole CUDA wait
    // so an archive GETDATA serve thread can TRY_LOCK(cs_main) during it.
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t saved_v4{consensus.nMatMulV4Height};
    const int32_t saved_bmx{consensus.nMatMulBMX4CHeight};
    const int32_t saved_rc{consensus.nMatMulRCHeight};
    const int32_t saved_lt{consensus.nMatMulDRLTHeight};
    struct Restore {
        Consensus::Params& consensus;
        int32_t v4;
        int32_t bmx;
        int32_t rc;
        int32_t lt;
        ~Restore()
        {
            SetMatMulExactReplayUnderReleasedCsMainHookForTest(nullptr);
            consensus.nMatMulV4Height = v4;
            consensus.nMatMulBMX4CHeight = bmx;
            consensus.nMatMulRCHeight = rc;
            consensus.nMatMulDRLTHeight = lt;
        }
    } restore{consensus, saved_v4, saved_bmx, saved_rc, saved_lt};

    const int next_height{
        WITH_LOCK(::cs_main, return chainstate.m_chain.Height()) + 1};
    consensus.nMatMulV4Height = next_height;
    consensus.nMatMulBMX4CHeight = next_height;
    consensus.nMatMulDRLTHeight = next_height;
    consensus.nMatMulRCHeight = next_height;

    node::BlockAssembler::Options options;
    options.coinbase_output_script = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    options.test_block_validity = false;
    const CBlock block{
        node::BlockAssembler{chainstate, nullptr, options, m_node}.CreateNewBlock()->block};

    std::atomic<bool> waiter_got_lock{false};
    std::atomic<bool> hook_saw_unlocked{false};
    SetMatMulExactReplayUnderReleasedCsMainHookForTest([&]() -> std::optional<bool> {
        AssertLockNotHeld(::cs_main);
        hook_saw_unlocked.store(true, std::memory_order_release);
        BOOST_CHECK(IsCsMainReleasedForMatMulRecompute());
        for (int i = 0; i < 200 && !waiter_got_lock.load(std::memory_order_acquire); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
        return true;
    });

    std::thread waiter([&] {
        BOOST_CHECK(WaitCsMainReleasedForMatMulRecompute(std::chrono::seconds{5}));
        TRY_LOCK(::cs_main, lock);
        if (lock) {
            waiter_got_lock.store(true, std::memory_order_release);
        }
    });

    BlockValidationState state;
    {
        LOCK(::cs_main);
        (void)TestBlockValidity(state, Params(), chainstate, block,
                                chainstate.m_chain.Tip(),
                                /*fCheckPOW=*/true, /*fCheckMerkleRoot=*/false);
    }
    waiter.join();
    BOOST_CHECK(hook_saw_unlocked.load(std::memory_order_acquire));
    BOOST_CHECK(waiter_got_lock.load(std::memory_order_acquire));
}

//! Production cadence extra is last ConnectTip / hold-anchor / now,now — not
//! dump-header nTime or nTimeReceived. Helper arithmetic in
//! matmul_gpu_verified_transition_tests does not select origin_time.
BOOST_FIXTURE_TEST_CASE(chainstate_cadence_hold_production_origin_selection, TestChain100Setup)
{
    using kernel::DEFAULT_CADENCE_BURST_MAX;
    using kernel::CadenceHoldIdleAllowedIsBounded;

    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    auto& burst_max = const_cast<uint32_t&>(chainman.m_options.cadence_burst_max);
    const int64_t saved_mock{GetMockTime().count()};
    struct Restore {
        Consensus::Params& consensus;
        int32_t reorg_start;
        uint32_t& burst_max;
        uint32_t saved_burst;
        ChainstateManager& chainman;
        CBlockIndex* saved_best_header;
        CBlockIndex* tip;
        uint32_t saved_nTime;
        int64_t saved_nTimeReceived;
        int64_t saved_nTimeBodyReceived;
        int64_t saved_mock;
        ~Restore()
        {
            consensus.nReorgProtectionStartHeight = reorg_start;
            burst_max = saved_burst;
            chainman.m_best_header = saved_best_header;
            if (tip != nullptr) {
                tip->nTime = saved_nTime;
                tip->nTimeReceived = saved_nTimeReceived;
                tip->nTimeBodyReceived = saved_nTimeBodyReceived;
            }
            SetMockTime(saved_mock);
        }
    };

    LOCK(::cs_main);
    CBlockIndex* tip = chainstate.m_chain.Tip();
    BOOST_REQUIRE(tip != nullptr);
    Restore restore{consensus, consensus.nReorgProtectionStartHeight,
                    burst_max, burst_max, chainman, chainman.m_best_header, tip,
                    tip->nTime, tip->nTimeReceived, tip->nTimeBodyReceived,
                    saved_mock};

    consensus.nReorgProtectionStartHeight = 10;
    burst_max = DEFAULT_CADENCE_BURST_MAX;
    SetMockTime(static_cast<int64_t>(tip->nTime) + 1);
    BOOST_REQUIRE(!chainman.IsInitialBlockDownload());
    const int64_t spacing{consensus.nPowTargetSpacing};
    BOOST_REQUIRE(spacing > 0);
    const int tip_h{tip->nHeight};
    const int extra0{tip_h + static_cast<int>(DEFAULT_CADENCE_BURST_MAX)};

    std::array<CBlockIndex, 40> dump_nodes{};
    const int64_t now0{GetTime()};
    const int64_t attacker_nTime{now0 - 80 * spacing};
    CBlockIndex* const dump{BuildUnindexedDump(dump_nodes, tip, attacker_nTime)};
    BOOST_REQUIRE_EQUAL(dump->nHeight, tip_h + 40);
    BOOST_REQUIRE_EQUAL(dump->GetAncestor(tip_h), tip);

    // Default first-look: extra=0 (now,now). ConnectTip history is cleared so
    // mining the fixture chain cannot leak last-connect into this branch.
    chainman.ResetCadenceHoldStateForTest();
    chainman.m_best_header = tip;
    BOOST_CHECK_EQUAL(chainman.GetCadenceHoldAllowedHeight(tip, now0), extra0);
    BOOST_CHECK_EQUAL(dump_nodes[2].nHeight, extra0);
    BOOST_CHECK(!chainman.CadenceHoldShouldHold(tip, &dump_nodes[2], now0, /*fork_depth=*/0, false));
    BOOST_CHECK(chainman.CadenceHoldShouldHold(tip, &dump_nodes[3], now0, 0, false));
    BOOST_CHECK(!chainman.CadenceHoldShouldHold(tip, tip, now0, 0, false));
    BOOST_CHECK(chainman.CadenceHoldShouldHold(tip, dump, now0, 0, false));
    BOOST_CHECK(!chainman.CadenceHoldShouldHold(tip, dump, now0, 0, /*recovery_escape=*/true));

    // (c) Idle > 2×spacing: bounded extra from last ConnectTip, never INT_MAX.
    chainman.NoteTipConnected(now0);
    const int64_t idle_now{now0 + 2 * spacing + 1};
    SetMockTime(idle_now);
    const int idle_allowed{chainman.GetCadenceHoldAllowedHeight(tip, idle_now)};
    BOOST_CHECK_NE(idle_allowed, std::numeric_limits<int>::max());
    BOOST_CHECK(CadenceHoldIdleAllowedIsBounded(
        idle_allowed, tip_h, DEFAULT_CADENCE_BURST_MAX, /*extra_spacings=*/2));
    BOOST_CHECK(chainman.CadenceHoldShouldHold(tip, dump, idle_now, 0, false));

    // Idle just inside 2×spacing stays extra=0 (now,now), not the idle branch.
    SetMockTime(now0 + 2 * spacing);
    BOOST_CHECK_EQUAL(chainman.GetCadenceHoldAllowedHeight(tip, now0 + 2 * spacing), extra0);

    // (b) Restart: empty last-connect stays extra=0 even after a long pause.
    // Attacker-chosen tip nTime must not be credited as origin.
    chainman.ResetCadenceHoldStateForTest();
    tip->nTime = static_cast<unsigned int>(attacker_nTime);
    tip->nTimeReceived = 0;
    tip->nTimeBodyReceived = 0;
    const int64_t restart_now{now0 + 10'000};
    SetMockTime(restart_now);
    BOOST_CHECK_EQUAL(chainman.GetCadenceHoldAllowedHeight(tip, restart_now), extra0);
    BOOST_CHECK(chainman.CadenceHoldShouldHold(tip, dump, restart_now, 0, false));

    // (a) Dump header with attacker nTime and nTimeReceived==0 must not widen
    // allowed height. Production extra does not read m_best_header times.
    chainman.m_best_header = dump;
    BOOST_CHECK_EQUAL(dump->nTimeReceived, 0);
    BOOST_CHECK_EQUAL(chainman.GetCadenceHoldAllowedHeight(tip, restart_now), extra0);
    BOOST_CHECK(chainman.CadenceHoldShouldHold(tip, dump, restart_now, 0, false));

    // Snapshot catch-up: production reads m_from_snapshot_blockhash on the
    // active chainstate (set at construction), not a test-only disarm flag.
    Chainstate snapshot_stub(/*mempool=*/nullptr, chainman.m_blockman, chainman,
                             tip->GetBlockHash());
    BOOST_REQUIRE(snapshot_stub.m_from_snapshot_blockhash.has_value());
    snapshot_stub.m_chain.SetTip(*tip);
    {
        ChainstateManager::UseChainstateAsActiveForTest active_snapshot{chainman, snapshot_stub};
        BOOST_REQUIRE(chainman.ActiveChainstate().m_from_snapshot_blockhash.has_value());
        BOOST_REQUIRE(dump->GetAncestor(tip_h) == tip);
        BOOST_CHECK_EQUAL(chainman.GetCadenceHoldAllowedHeight(tip, restart_now),
                          std::numeric_limits<int>::max());
        BOOST_CHECK(!chainman.CadenceHoldShouldHold(tip, dump, restart_now, 0, false));
        dump->nTimeReceived = restart_now;
        BOOST_CHECK_EQUAL(chainman.GetCadenceHoldAllowedHeight(tip, restart_now), extra0);
        BOOST_CHECK(chainman.CadenceHoldShouldHold(tip, dump, restart_now, 0, false));
        dump->nTimeReceived = 0;
    }

    // Anchor monotonic: off-chain best-header must not fold; extra from arm.
    chainman.ResetCadenceHoldStateForTest();
    SetMockTime(now0);
    chainman.m_best_header = dump;
    chainman.ArmCadenceHoldAnchor(tip, now0);
    SetMockTime(now0 + spacing);
    BOOST_CHECK_EQUAL(chainman.GetCadenceHoldAllowedHeight(tip, now0 + spacing),
                      extra0 + 1);

    // Anchor fold: followed header on the active chain drops the pin so the
    // next burst re-arms from the live tip (extra=0 while last-connect is fresh).
    chainman.ResetCadenceHoldStateForTest();
    SetMockTime(now0);
    chainman.m_best_header = tip;
    chainman.NoteTipConnected(now0);
    chainman.ArmCadenceHoldAnchor(tip, now0);
    BOOST_CHECK_EQUAL(chainman.GetCadenceHoldAllowedHeight(tip, now0), extra0);
    SetMockTime(now0 + spacing);
    BOOST_CHECK_EQUAL(chainman.GetCadenceHoldAllowedHeight(tip, now0 + spacing), extra0);

    chainman.m_best_header = restore.saved_best_header;
}

//! Gold-standard hard test: removing every attestation signature must not
//! change which blocks a -matmulvalidation=consensus node connects, which
//! tip FindMostWorkChain returns, or BLOCK_EXACT_REPLAY_VERIFIED bits.
//! If this fails, HasQuorum leaked into consensus validity or fork choice.
//!
//! Live 2026-08-26: the authority signer signed nothing past 199300, yet
//! the network tip advanced to 199328. Twenty-eight blocks were mined,
//! propagated, and accepted with zero attestations from the authority
//! key. This case encodes that property so it stays true.
BOOST_FIXTURE_TEST_CASE(chainstate_consensus_gold_standard_ignores_cleared_attestations,
                        TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    auto& mode = const_cast<kernel::MatMulValidationMode&>(
        chainman.m_options.matmul_validation_mode);
    auto& action = const_cast<kernel::DeepReorgAction&>(
        chainman.m_options.deep_reorg_action);
    auto& park_depth = const_cast<std::optional<uint32_t>&>(
        chainman.m_options.max_reorg_depth_park);
    auto& hysteresis = const_cast<std::optional<uint32_t>&>(
        chainman.m_options.reorg_hysteresis_work_margin);

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
        std::optional<uint32_t> saved_park;
        std::optional<uint32_t>& hysteresis;
        std::optional<uint32_t> saved_hysteresis;
        ~Restore()
        {
            node::matmul_trusted::ResetForTest();
            consensus.nMatMulV4Height = v4;
            consensus.nMatMulBMX4CHeight = bmx;
            consensus.nMatMulRCHeight = rc;
            consensus.nReorgProtectionStartHeight = reorg_start;
            mode = saved_mode;
            action = saved_action;
            park_depth = saved_park;
            hysteresis = saved_hysteresis;
        }
    } restore{consensus, consensus.nMatMulV4Height, consensus.nMatMulBMX4CHeight,
              consensus.nMatMulRCHeight, consensus.nReorgProtectionStartHeight,
              mode, mode, action, action, park_depth, park_depth, hysteresis,
              hysteresis};

    CBlockIndex* parent{WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE(parent != nullptr);
    const int parent_height{parent->nHeight};
    consensus.nMatMulV4Height = parent_height;
    consensus.nMatMulBMX4CHeight = parent_height;
    consensus.nMatMulRCHeight = parent_height;
    consensus.nReorgProtectionStartHeight = 10;
    BOOST_REQUIRE(consensus.IsMatMulTrustedReplayAttestationActive(parent_height + 1));
    mode = kernel::MatMulValidationMode::CONSENSUS;
    action = kernel::DeepReorgAction::WARN;
    park_depth = kernel::REORG_PROTECTION_DEPTH_DISABLED;
    hysteresis = 0;

    const CScript script = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CKey alt_key;
    alt_key.MakeNewKey(/*fCompressed=*/true);
    const CScript script_alt = GetScriptForDestination(PKHash(alt_key.GetPubKey()));
    CKey pin;
    pin.MakeNewKey(/*fCompressed=*/true);
    const uint256 chain_id{uint256::ONE};
    const uint256 replay_ctx{uint256::FromHex(std::string(64, 'f')).value()};
    auto configure_unprivileged_pin = [&] {
        matmul::trusted::StoreConfig cfg;
        cfg.chain_id = chain_id;
        cfg.replay_authority_context = replay_ctx;
        cfg.trusted_signers = {pin.GetPubKey()};
        cfg.threshold = 1;
        std::string error;
        BOOST_REQUIRE(node::matmul_trusted::Configure(
            std::move(cfg), /*trusted_mirror=*/false, /*serve=*/false,
            std::chrono::milliseconds{50}, error));
        BOOST_REQUIRE(!node::matmul_trusted::IsTrustedMirror());
        BOOST_REQUIRE(!node::matmul_trusted::HasLocalSigner());
        BOOST_REQUIRE(node::matmul_trusted::UnprivilegedNodeIgnoresDualQuorumPin(
            node::matmul_trusted::IsTrustedMirror(),
            node::matmul_trusted::HasLocalSigner()));
    };
    auto add_quorum = [&](const uint256& hash, int32_t height) {
        matmul::trusted::ExactReplayStatement statement;
        statement.chain_id = chain_id;
        statement.block_hash = hash;
        statement.block_height = height;
        statement.replay_authority_context = replay_ctx;
        const auto attestation{matmul::trusted::SignStatement(statement, pin)};
        BOOST_REQUIRE(attestation.has_value());
        const auto added{node::matmul_trusted::Add(*attestation, hash, height)};
        BOOST_REQUIRE(added == matmul::trusted::AddResult::Accepted ||
                      added == matmul::trusted::AddResult::Duplicate);
        BOOST_REQUIRE(node::matmul_trusted::HasQuorum(hash, height));
    };

    // --- Same-height twins, only the losing sibling is attested ---
    const auto twin_a{std::make_shared<const CBlock>(
        CreateBlock({}, script, chainstate))};
    const auto twin_b{std::make_shared<const CBlock>(
        CreateBlock({}, script_alt, chainstate))};
    BOOST_REQUIRE(twin_a->GetHash() != twin_b->GetHash());
    bool new_block{false};
    BOOST_REQUIRE(chainman.ProcessNewBlock(
        twin_a, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_REQUIRE(chainman.ProcessNewBlock(
        twin_b, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    CBlockIndex* twin_a_index{nullptr};
    CBlockIndex* twin_b_index{nullptr};
    {
        LOCK(::cs_main);
        twin_a_index = chainman.m_blockman.LookupBlockIndex(twin_a->GetHash());
        twin_b_index = chainman.m_blockman.LookupBlockIndex(twin_b->GetHash());
        BOOST_REQUIRE(twin_a_index && twin_b_index);
        BOOST_CHECK(twin_a_index->nStatus & BLOCK_HAVE_DATA);
        BOOST_CHECK(twin_b_index->nStatus & BLOCK_HAVE_DATA);
    }
    CBlockIndex* const twin_loser{
        WITH_LOCK(::cs_main, return chainstate.m_chain.Contains(twin_a_index) ?
                                    twin_b_index : twin_a_index)};
    const std::vector<CBlockIndex*> twin_watch{parent, twin_a_index, twin_b_index};

    configure_unprivileged_pin();
    add_quorum(twin_loser->GetBlockHash(), twin_loser->nHeight);
    {
        LOCK(::cs_main);
        BOOST_CHECK(chainman.FindUniqueCompetingAttestedIndex() == nullptr);
    }
    RewindToParentAndActivate(chainstate, parent, {twin_a_index, twin_b_index});
    const ConsensusGoldStandardChoice twins_with{WITH_LOCK(::cs_main, {
        return CaptureConsensusGoldStandardChoice(chainman, chainstate, twin_watch);
    })};

    RewindToParentAndActivate(chainstate, parent, {twin_a_index, twin_b_index});
    {
        LOCK(::cs_main);
        // Invalidate the connected child so WITHOUT starts from the same parent
        // without re-applying the just-activated twin before ResetForTest.
        CBlockIndex* child{chainstate.m_chain[parent->nHeight + 1]};
        BOOST_REQUIRE(child != nullptr);
        BlockValidationState inv;
        BOOST_REQUIRE(chainstate.InvalidateBlock(inv, child));
        BOOST_REQUIRE(chainstate.m_chain.Tip() == parent);
    }
    node::matmul_trusted::ResetForTest();
    BOOST_REQUIRE(!node::matmul_trusted::IsConfigured());
    RewindToParentAndActivate(chainstate, parent, {twin_a_index, twin_b_index});
    const ConsensusGoldStandardChoice twins_without{WITH_LOCK(::cs_main, {
        return CaptureConsensusGoldStandardChoice(chainman, chainstate, twin_watch);
    })};
    CheckGoldStandardUnchanged(twins_with, twins_without);

    // Fail both leftover twins so ActivateBestChain cannot reconnect a
    // same-height HAVE_DATA sibling when later geometries rewind to parent.
    // Harness only: the gold-standard asserts above already compared the
    // twin capture.
    {
        CBlockIndex* connected = WITH_LOCK(::cs_main, {
            return chainstate.m_chain.Tip() == parent ? nullptr :
                   chainstate.m_chain[parent->nHeight + 1];
        });
        if (connected != nullptr) {
            BlockValidationState inv;
            BOOST_REQUIRE(chainstate.InvalidateBlock(inv, connected));
        }
        for (CBlockIndex* leftover : {twin_a_index, twin_b_index}) {
            if (leftover == nullptr) continue;
            if (WITH_LOCK(::cs_main, return (leftover->nStatus & BLOCK_FAILED_MASK) != 0)) {
                continue;
            }
            BlockValidationState inv;
            BOOST_REQUIRE(chainstate.InvalidateBlock(inv, leftover));
        }
        BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == parent);
    }

    // --- Longer attested HAVE_DATA fork vs shorter unattested HAVE_DATA fork ---
    CBlockIndex* long_root{nullptr};
    CBlockIndex* long_tip{nullptr};
    for (int i = 0; i < 3; ++i) {
        const CBlock block{CreateAndProcessBlock({}, script)};
        LOCK(::cs_main);
        CBlockIndex* idx{chainman.m_blockman.LookupBlockIndex(block.GetHash())};
        BOOST_REQUIRE(idx != nullptr);
        if (i == 0) long_root = idx;
        long_tip = idx;
    }
    BOOST_REQUIRE(long_root && long_tip);
    BOOST_REQUIRE_EQUAL(long_tip->nHeight, parent_height + 3);
    {
        BlockValidationState inv;
        BOOST_REQUIRE(chainstate.InvalidateBlock(inv, long_root));
    }
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()) == parent);

    CBlockIndex* short_root{nullptr};
    CBlockIndex* short_tip{nullptr};
    for (int i = 0; i < 2; ++i) {
        const CBlock block{CreateAndProcessBlock({}, script_alt)};
        LOCK(::cs_main);
        CBlockIndex* idx{chainman.m_blockman.LookupBlockIndex(block.GetHash())};
        BOOST_REQUIRE(idx != nullptr);
        if (i == 0) short_root = idx;
        short_tip = idx;
    }
    BOOST_REQUIRE(short_root && short_tip);
    BOOST_REQUIRE_EQUAL(short_tip->nHeight, parent_height + 2);
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(long_tip->nChainWork > short_tip->nChainWork);
        BOOST_REQUIRE(long_tip->nAuthenticatedChainWork >=
                      short_tip->nAuthenticatedChainWork);
    }
    const std::vector<CBlockIndex*> fork_watch{
        parent, long_root, long_tip, short_root, short_tip};

    // User geometry: longer fork is attested. Most work still belongs to it,
    // so gold-standard and Liquid agree on the winner — the differential
    // still fails if clearing signatures moves the tip.
    configure_unprivileged_pin();
    for (CBlockIndex* walk{long_tip}; walk != nullptr && walk != parent;
         walk = walk->pprev) {
        add_quorum(walk->GetBlockHash(), walk->nHeight);
    }
    RewindToParentAndActivate(chainstate, parent, {long_root, short_root});
    const ConsensusGoldStandardChoice long_attested_with{WITH_LOCK(::cs_main, {
        return CaptureConsensusGoldStandardChoice(chainman, chainstate, fork_watch);
    })};
    {
        CBlockIndex* child{
            WITH_LOCK(::cs_main, return chainstate.m_chain[parent->nHeight + 1])};
        BOOST_REQUIRE(child != nullptr);
        BlockValidationState inv;
        BOOST_REQUIRE(chainstate.InvalidateBlock(inv, child));
    }
    node::matmul_trusted::ResetForTest();
    RewindToParentAndActivate(chainstate, parent, {long_root, short_root});
    const ConsensusGoldStandardChoice long_attested_without{WITH_LOCK(::cs_main, {
        return CaptureConsensusGoldStandardChoice(chainman, chainstate, fork_watch);
    })};
    CheckGoldStandardUnchanged(long_attested_with, long_attested_without);

    // Liquid trap: attest only the shorter fork. Gold-standard consensus
    // must still follow most work (the longer unattested fork) both with
    // signatures present and after they are cleared.
    {
        CBlockIndex* child{
            WITH_LOCK(::cs_main, return chainstate.m_chain[parent->nHeight + 1])};
        if (child != nullptr) {
            BlockValidationState inv;
            BOOST_REQUIRE(chainstate.InvalidateBlock(inv, child));
        }
    }
    configure_unprivileged_pin();
    for (CBlockIndex* walk{short_tip}; walk != nullptr && walk != parent;
         walk = walk->pprev) {
        add_quorum(walk->GetBlockHash(), walk->nHeight);
    }
    BOOST_CHECK(!node::matmul_trusted::HasQuorum(
        long_tip->GetBlockHash(), long_tip->nHeight));
    RewindToParentAndActivate(chainstate, parent, {long_root, short_root});
    const ConsensusGoldStandardChoice short_attested_with{WITH_LOCK(::cs_main, {
        return CaptureConsensusGoldStandardChoice(chainman, chainstate, fork_watch);
    })};
    BOOST_CHECK_MESSAGE(
        short_attested_with.tip == long_tip->GetBlockHash(),
        "gold-standard consensus followed attested shorter fork over more work; with tip=" +
            short_attested_with.tip.ToString());
    {
        CBlockIndex* child{
            WITH_LOCK(::cs_main, return chainstate.m_chain[parent->nHeight + 1])};
        BOOST_REQUIRE(child != nullptr);
        BlockValidationState inv;
        BOOST_REQUIRE(chainstate.InvalidateBlock(inv, child));
    }
    node::matmul_trusted::ResetForTest();
    RewindToParentAndActivate(chainstate, parent, {long_root, short_root});
    const ConsensusGoldStandardChoice short_attested_without{WITH_LOCK(::cs_main, {
        return CaptureConsensusGoldStandardChoice(chainman, chainstate, fork_watch);
    })};
    CheckGoldStandardUnchanged(short_attested_with, short_attested_without);
}

BOOST_FIXTURE_TEST_CASE(validation_epoch_clears_poisoned_valid_marks, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    const CScript script = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    auto& hysteresis = const_cast<std::optional<uint32_t>&>(
        chainman.m_options.reorg_hysteresis_work_margin);
    hysteresis = 0;

    const CBlockIndex* original_tip{nullptr};
    for (int i = 0; i < 3; ++i) {
        CreateAndProcessBlock({}, script);
    }
    {
        LOCK(::cs_main);
        original_tip = chainstate.m_chain.Tip();
        BOOST_REQUIRE(original_tip != nullptr);
    }
    const uint256 original_hash = original_tip->GetBlockHash();
    const int original_height = original_tip->nHeight;
    CBlockIndex* invalidate_at{WITH_LOCK(::cs_main, {
        return chainstate.m_chain[original_height - 2];
    })};
    BOOST_REQUIRE(invalidate_at != nullptr);

    BlockValidationState inval;
    BOOST_REQUIRE(chainstate.InvalidateBlock(inval, invalidate_at));
    CreateAndProcessBlock({}, script);
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainstate.m_chain.Tip() != nullptr);
        BOOST_CHECK_NE(chainstate.m_chain.Tip()->GetBlockHash(), original_hash);
        BOOST_CHECK(invalidate_at->nStatus & BLOCK_FAILED_MASK);
        BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->WriteValidationEpoch(0));
        chainman.MaybeClearStaleInvalidMarksForValidationEpoch();
        BOOST_CHECK_EQUAL(invalidate_at->nStatus & BLOCK_FAILED_MASK, 0U);
        BOOST_CHECK_GE(chainman.InvalidMarksClearedOnUpgrade(), 1U);
        uint32_t stored{0};
        BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->ReadValidationEpoch(stored));
        BOOST_CHECK_EQUAL(stored, BLOCK_VALIDATION_EPOCH);
    }
    BlockValidationState abc;
    BOOST_REQUIRE(chainstate.ActivateBestChain(abc));
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip()->GetBlockHash(), original_hash);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Height(), original_height);
        BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->WriteValidationEpoch(0));
        chainman.MaybeClearStaleInvalidMarksForValidationEpoch();
        BlockValidationState again;
        BOOST_REQUIRE(chainstate.InvalidateBlock(again, invalidate_at));
        BOOST_CHECK(invalidate_at->nStatus & BLOCK_FAILED_MASK);
        chainman.MaybeClearStaleInvalidMarksForValidationEpoch();
        BOOST_CHECK(invalidate_at->nStatus & BLOCK_FAILED_MASK);
    }
}

BOOST_FIXTURE_TEST_CASE(validation_epoch_rerejects_genuinely_invalid, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    const CScript script = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const CBlockIndex* const tip{
        WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE(tip != nullptr);
    const uint256 tip_hash = tip->GetBlockHash();

    CBlock bad = CreateBlock({}, script, chainstate);
    {
        CMutableTransaction cb{*bad.vtx[0]};
        cb.vout[0].nValue += 50 * COIN;
        bad.vtx[0] = MakeTransactionRef(std::move(cb));
    }
    RegenerateCommitments(bad, chainman);
    BOOST_REQUIRE(MineHeaderForConsensus(
        bad, static_cast<uint32_t>(tip->nHeight + 1),
        Params().GetConsensus(), 5'000'000,
        std::optional<int64_t>{tip->GetMedianTimePast()}));

    bool new_block{false};
    (void)chainman.ProcessNewBlock(
        std::make_shared<const CBlock>(bad), /*force_processing=*/true,
        /*min_pow_checked=*/true, &new_block);
    CBlockIndex* bad_index{WITH_LOCK(::cs_main, {
        return chainman.m_blockman.LookupBlockIndex(bad.GetHash());
    })};
    BOOST_REQUIRE(bad_index != nullptr);
    {
        LOCK(::cs_main);
        BOOST_CHECK(bad_index->nStatus & BLOCK_FAILED_MASK);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip()->GetBlockHash(), tip_hash);
        BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->WriteValidationEpoch(0));
        chainman.MaybeClearStaleInvalidMarksForValidationEpoch();
        BOOST_CHECK_EQUAL(bad_index->nStatus & BLOCK_FAILED_MASK, 0U);
    }
    BlockValidationState abc;
    BOOST_REQUIRE(chainstate.ActivateBestChain(abc));
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip()->GetBlockHash(), tip_hash);
        BOOST_CHECK(bad_index->nStatus & BLOCK_FAILED_MASK);
    }
}

BOOST_FIXTURE_TEST_CASE(validation_epoch_heals_poisoned_fork_shape, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    const CScript script = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    auto& hysteresis = const_cast<std::optional<uint32_t>&>(
        chainman.m_options.reorg_hysteresis_work_margin);
    hysteresis = 0;

    std::vector<uint256> canonical;
    for (int i = 0; i < 8; ++i) {
        canonical.push_back(CreateAndProcessBlock({}, script).GetHash());
    }
    const uint256 heavy_hash = canonical.back();
    CBlockIndex* heavy_tip{WITH_LOCK(::cs_main, {
        return chainman.m_blockman.LookupBlockIndex(heavy_hash);
    })};
    BOOST_REQUIRE(heavy_tip != nullptr);
    CBlockIndex* poison_root{WITH_LOCK(::cs_main, {
        return chainstate.m_chain[heavy_tip->nHeight - 7];
    })};
    BOOST_REQUIRE(poison_root != nullptr);

    BlockValidationState inval;
    BOOST_REQUIRE(chainstate.InvalidateBlock(inval, poison_root));
    CreateAndProcessBlock({}, script);
    CreateAndProcessBlock({}, script);
    CBlock decoy = CreateAndProcessBlock({}, script);
    CBlockIndex* decoy_index{WITH_LOCK(::cs_main, {
        return chainman.m_blockman.LookupBlockIndex(decoy.GetHash());
    })};
    BOOST_REQUIRE(decoy_index != nullptr);
    BlockValidationState decoy_inval;
    BOOST_REQUIRE(chainstate.InvalidateBlock(decoy_inval, decoy_index));
    CreateAndProcessBlock({}, script);

    {
        LOCK(::cs_main);
        BOOST_CHECK_NE(chainstate.m_chain.Tip()->GetBlockHash(), heavy_hash);
        BOOST_CHECK(poison_root->nStatus & BLOCK_FAILED_MASK);
        BOOST_CHECK(decoy_index->nStatus & BLOCK_FAILED_MASK);
        BOOST_CHECK(heavy_tip->nStatus & BLOCK_FAILED_MASK);
        BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->WriteValidationEpoch(0));
        chainman.MaybeClearStaleInvalidMarksForValidationEpoch();
        BOOST_CHECK_EQUAL(poison_root->nStatus & BLOCK_FAILED_MASK, 0U);
        BOOST_CHECK_EQUAL(heavy_tip->nStatus & BLOCK_FAILED_MASK, 0U);
        chainman.RecalculateBestHeader();
        BOOST_REQUIRE(chainman.m_best_header != nullptr);
        BOOST_CHECK(PreferMostWorkHeader(*chainstate.m_chain.Tip(),
                                         *chainman.m_best_header) ||
                    chainman.m_best_header == heavy_tip ||
                    chainman.m_best_header->GetAncestor(heavy_tip->nHeight) ==
                        heavy_tip);
    }
    BlockValidationState abc;
    BOOST_REQUIRE(chainstate.ActivateBestChain(abc));
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip()->GetBlockHash(), heavy_hash);
        BOOST_CHECK_GE(chainman.m_best_header->nHeight, heavy_tip->nHeight);
    }
}

BOOST_AUTO_TEST_SUITE_END()
