// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <chain.h>
#include <chainparams.h>
#include <clientversion.h>
#include <consensus/params.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_scale.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <node/kernel_notifications.h>
#include <arith_uint256.h>
#include <script/solver.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>
#include <test/util/logging.h>
#include <test/util/setup_common.h>

#include <array>
#include <cstdint>
#include <limits>
#include <string>
#include <type_traits>

using node::BLOCK_SERIALIZATION_HEADER_SIZE;
using node::BlockManager;
using node::KernelNotifications;
using node::MAX_BLOCKFILE_SIZE;

// use BasicTestingSetup here for the data directory configuration, setup, and cleanup
BOOST_FIXTURE_TEST_SUITE(blockmanager_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(matmul_replay_authority_context_clean_migration)
{
    LOCK(cs_main);
    CBlockIndex clean;
    clean.nStatus = BLOCK_VALID_TREE;
    std::array<CBlockIndex*, 1> indices{&clean};
    std::set<CBlockIndex*> dirty;
    const uint256 context{1};

    const auto migration{node::ReconcileMatMulReplayAuthorityContext(
        indices, std::nullopt, context, dirty)};
    BOOST_CHECK(migration.disposition ==
                node::MatMulReplayContextDisposition::MIGRATED);
    BOOST_CHECK_EQUAL(migration.cleared_trusted_status, 0U);
    BOOST_CHECK(dirty.empty());
    BOOST_CHECK(clean.nStatus & BLOCK_VALID_TREE);
}

BOOST_AUTO_TEST_CASE(matmul_replay_authority_context_matching_preserves_exact)
{
    LOCK(cs_main);
    CBlockIndex exact;
    CBlockIndex trusted;
    exact.nStatus = BLOCK_VALID_TREE | BLOCK_EXACT_REPLAY_VERIFIED;
    trusted.nStatus = BLOCK_VALID_TREE | BLOCK_TRUSTED_REPLAY_ATTESTED;
    std::array<CBlockIndex*, 2> indices{&exact, &trusted};
    std::set<CBlockIndex*> dirty;
    const uint256 context{1};

    const auto migration{node::ReconcileMatMulReplayAuthorityContext(
        indices, context, context, dirty)};
    BOOST_CHECK(migration.disposition ==
                node::MatMulReplayContextDisposition::MATCHED);
    BOOST_CHECK_EQUAL(migration.cleared_trusted_status, 1U);
    BOOST_CHECK(exact.nStatus & BLOCK_EXACT_REPLAY_VERIFIED);
    BOOST_CHECK(!(trusted.nStatus & BLOCK_TRUSTED_REPLAY_ATTESTED));
    BOOST_CHECK_EQUAL(dirty.size(), 1U);
    BOOST_CHECK(dirty.count(&trusted));
}

BOOST_AUTO_TEST_CASE(matmul_replay_authority_context_mismatch_clears_exact_replay)
{
    LOCK(cs_main);
    CBlockIndex exact;
    CBlockIndex trusted;
    exact.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_EXACT_REPLAY_VERIFIED;
    trusted.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_TRUSTED_REPLAY_ATTESTED;
    std::array<CBlockIndex*, 2> indices{&exact, &trusted};
    std::set<CBlockIndex*> dirty;

    const auto migration{node::ReconcileMatMulReplayAuthorityContext(
        indices, uint256{2}, uint256{1}, dirty)};
    BOOST_CHECK(migration.disposition ==
                node::MatMulReplayContextDisposition::MIGRATED);
    BOOST_CHECK_EQUAL(migration.cleared_exact_replay_status, 1U);
    BOOST_CHECK_EQUAL(migration.cleared_trusted_status, 1U);
    BOOST_CHECK(!(exact.nStatus & BLOCK_EXACT_REPLAY_VERIFIED));
    BOOST_CHECK(exact.nStatus & BLOCK_VALID_SCRIPTS);
    BOOST_CHECK(!(trusted.nStatus & BLOCK_TRUSTED_REPLAY_ATTESTED));
    BOOST_CHECK_EQUAL(dirty.size(), 2U);
    BOOST_CHECK(dirty.count(&exact));
    BOOST_CHECK(dirty.count(&trusted));
}

BOOST_AUTO_TEST_CASE(matmul_replay_authority_context_mismatch_without_authority_migrates)
{
    LOCK(cs_main);
    CBlockIndex clean;
    clean.nStatus = BLOCK_VALID_SCRIPTS;
    std::array<CBlockIndex*, 1> indices{&clean};
    std::set<CBlockIndex*> dirty;

    const auto migration{node::ReconcileMatMulReplayAuthorityContext(
        indices, uint256{2}, uint256{1}, dirty)};
    BOOST_CHECK(migration.disposition ==
                node::MatMulReplayContextDisposition::MIGRATED);
    BOOST_CHECK_EQUAL(migration.cleared_trusted_status, 0U);
    BOOST_CHECK_EQUAL(clean.nStatus, BLOCK_VALID_SCRIPTS);
    BOOST_CHECK(dirty.empty());
}

BOOST_AUTO_TEST_CASE(matmul_replay_authority_context_mismatch_clears_trusted_only)
{
    LOCK(cs_main);
    CBlockIndex trusted;
    trusted.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_TRUSTED_REPLAY_ATTESTED;
    std::array<CBlockIndex*, 1> indices{&trusted};
    std::set<CBlockIndex*> dirty;

    const auto migration{node::ReconcileMatMulReplayAuthorityContext(
        indices, uint256{2}, uint256{1}, dirty)};
    BOOST_CHECK(migration.disposition ==
                node::MatMulReplayContextDisposition::MIGRATED);
    BOOST_CHECK_EQUAL(migration.cleared_trusted_status, 1U);
    BOOST_CHECK(!(trusted.nStatus & BLOCK_TRUSTED_REPLAY_ATTESTED));
    BOOST_CHECK(trusted.nStatus & BLOCK_VALID_SCRIPTS);
    BOOST_CHECK_EQUAL(dirty.size(), 1U);
    BOOST_CHECK(dirty.count(&trusted));
}

BOOST_AUTO_TEST_CASE(matmul_replay_authority_context_full_reindex_seeds_database)
{
    KernelNotifications notifications{
        Assert(m_node.shutdown_request), m_node.exit_status,
        *Assert(m_node.warnings)};
    const BlockManager::Options blockman_opts{
        .chainparams = Params(),
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = m_args.GetDataDirNet() / "blocks" / "index",
            .cache_bytes = 0,
            .wipe_data = true,
        },
    };
    BlockManager blockman{*Assert(m_node.shutdown_signal), blockman_opts};
    const uint256 expected{node::ComputeMatMulReplayAuthorityContext(Params())};

    LOCK(cs_main);
    uint256 persisted;
    BOOST_REQUIRE(blockman.m_block_tree_db->ReadMatMulReplayContext(persisted));
    BOOST_CHECK(persisted == expected);
}

BOOST_AUTO_TEST_CASE(matmul_replay_authority_context_binds_profile_and_height)
{
    auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};
    auto& consensus{const_cast<Consensus::Params&>(params->GetConsensus())};
    const uint256 baseline{node::ComputeMatMulReplayAuthorityContext(*params)};

    ++consensus.nMatMulRCProfile;
    const uint256 changed_profile{
        node::ComputeMatMulReplayAuthorityContext(*params)};
    BOOST_CHECK(changed_profile != baseline);

    --consensus.nMatMulRCProfile;
    --consensus.nMatMulRCHeight;
    const uint256 changed_height{
        node::ComputeMatMulReplayAuthorityContext(*params)};
    BOOST_CHECK(changed_height != baseline);

    ++consensus.nMatMulRCHeight;
    ++consensus.nMatMulRCAsertRescaleNum;
    const uint256 changed_rc_asert{
        node::ComputeMatMulReplayAuthorityContext(*params)};
    BOOST_CHECK(changed_rc_asert != baseline);

    --consensus.nMatMulRCAsertRescaleNum;
    --consensus.nMatMulAsertHeight;
    const uint256 changed_asert_activation{
        node::ComputeMatMulReplayAuthorityContext(*params)};
    BOOST_CHECK(changed_asert_activation != baseline);

    ++consensus.nMatMulAsertHeight;
    {
        // Regtest default is INT32_MAX; do not ++ a disabled height.
        const auto saved_h{consensus.nMatMulPowLimitUpgradeHeight};
        consensus.nMatMulPowLimitUpgradeHeight = 1;
        const uint256 changed_powlimit_upgrade_height{
            node::ComputeMatMulReplayAuthorityContext(*params)};
        BOOST_CHECK(changed_powlimit_upgrade_height != baseline);
        consensus.nMatMulPowLimitUpgradeHeight = saved_h;
    }
    const auto saved_limit{consensus.powLimitUpgrade};
    consensus.powLimitUpgrade = uint256{1};
    const uint256 changed_powlimit_upgrade{
        node::ComputeMatMulReplayAuthorityContext(*params)};
    BOOST_CHECK(changed_powlimit_upgrade != baseline);
    consensus.powLimitUpgrade = saved_limit;

    ++consensus.nMatMulProductDigestHeight;
    const uint256 changed_legacy_digest_activation{
        node::ComputeMatMulReplayAuthorityContext(*params)};
    BOOST_CHECK(changed_legacy_digest_activation != baseline);
}

//! Every ENC_RC §R.7 scheduled-scaling knob feeding
//! ConsensusRCEpisodeParamsForHeight selects the replay episode SHAPE, i.e. the
//! PoW predicate. Each one must move the replay authority context, otherwise a
//! retuned node would keep trusting persisted BLOCK_EXACT_REPLAY_VERIFIED
//! verdicts computed under a different episode shape.
BOOST_AUTO_TEST_CASE(matmul_replay_authority_context_binds_rc_scale_schedule)
{
    auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};
    auto& consensus{const_cast<Consensus::Params&>(params->GetConsensus())};
    const uint256 baseline{node::ComputeMatMulReplayAuthorityContext(*params)};
    // Determinism: the derived-shape probe ladder must not make this stateful.
    BOOST_CHECK(node::ComputeMatMulReplayAuthorityContext(*params) == baseline);

    const auto check_field_bound{[&](const char* what, auto& field, auto delta) {
        const auto saved{field};
        field = static_cast<std::remove_reference_t<decltype(field)>>(field + delta);
        BOOST_CHECK_MESSAGE(
            node::ComputeMatMulReplayAuthorityContext(*params) != baseline,
            std::string{"replay authority context ignores predicate-relevant field: "} + what);
        field = saved;
        BOOST_CHECK(node::ComputeMatMulReplayAuthorityContext(*params) == baseline);
    }};

    check_field_bound("nRCScaleEpochBlocks", consensus.nRCScaleEpochBlocks, 1);
    check_field_bound("nRCScaleHardCapResBytes", consensus.nRCScaleHardCapResBytes, -1);
    check_field_bound("nRCScaleHardCapCapBytes", consensus.nRCScaleHardCapCapBytes, -1);
    // Currently unread (chainwork brake OMITTED, A3/F6) but bound so that
    // reintroducing the brake cannot silently become an unbound predicate input.
    check_field_bound("nRCBrakeDeltaPct", consensus.nRCBrakeDeltaPct, 1);

    // Whole-table coverage: an off-by-one in the hashing loop must be caught.
    for (size_t i = 0; i < Consensus::Params::kRCGrowthTableLen; ++i) {
        check_field_bound("nRCGrowthResTableQ16[i]", consensus.nRCGrowthResTableQ16[i], 1);
        check_field_bound("nRCGrowthCapTableQ16[i]", consensus.nRCGrowthCapTableQ16[i], 1);
    }
}

//! The derived-shape fingerprint binds the OUTPUT of the episode-shape
//! derivation, not just its Consensus::Params inputs, so a change to the
//! derivation code (epoch-0 dials, frozen dim ratios, fallback rules, coupled
//! shape constructors) also invalidates cached replay verdicts.
BOOST_AUTO_TEST_CASE(matmul_replay_episode_shape_fingerprint_tracks_resolved_shape)
{
    auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};
    auto& consensus{const_cast<Consensus::Params&>(params->GetConsensus())};
    const uint256 baseline_shape{
        node::ComputeMatMulReplayEpisodeShapeFingerprint(*params)};
    const uint256 baseline_context{
        node::ComputeMatMulReplayAuthorityContext(*params)};
    BOOST_CHECK(node::ComputeMatMulReplayEpisodeShapeFingerprint(*params) ==
                baseline_shape);

    // Sanity: the probe ladder resolves a valid episode at every sampled height
    // and never runs away (bounded epoch index) even at INT32_MAX activation.
    const auto epoch0{matmul::v4::rc::ResolveRCEpisodeParams(consensus, 0)};
    BOOST_CHECK(matmul::v4::rc::ValidateRCEpisodeParams(epoch0));

    // Toy-dims flips the resolved episode shape without touching any scheduled
    // scaling knob; both the fingerprint and the context must move.
    const bool saved_toy{consensus.fMatMulRCUseToyDims};
    consensus.fMatMulRCUseToyDims = !saved_toy;
    BOOST_CHECK(node::ComputeMatMulReplayEpisodeShapeFingerprint(*params) !=
                baseline_shape);
    BOOST_CHECK(node::ComputeMatMulReplayAuthorityContext(*params) !=
                baseline_context);
    BOOST_CHECK(matmul::v4::rc::ResolveRCEpisodeParams(consensus, 0).n_ctx !=
                epoch0.n_ctx);
    consensus.fMatMulRCUseToyDims = saved_toy;
    BOOST_CHECK(node::ComputeMatMulReplayEpisodeShapeFingerprint(*params) ==
                baseline_shape);

    // The resolved ENC_RC_COUPLED shape is part of the same fingerprint.
    const uint32_t saved_coupled_profile{consensus.nMatMulRCCoupledProfile};
    consensus.nMatMulRCCoupledProfile =
        saved_coupled_profile == 4 ? 3 : saved_coupled_profile + 1;
    BOOST_CHECK(node::ComputeMatMulReplayEpisodeShapeFingerprint(*params) !=
                baseline_shape);
    consensus.nMatMulRCCoupledProfile = saved_coupled_profile;
    BOOST_CHECK(node::ComputeMatMulReplayEpisodeShapeFingerprint(*params) ==
                baseline_shape);

    // Activation height moves the probe ladder, so the fingerprint tracks it too.
    const int32_t saved_rc_height{consensus.nMatMulRCHeight};
    consensus.nMatMulRCHeight =
        saved_rc_height == std::numeric_limits<int32_t>::max() ? 1000 : saved_rc_height + 1;
    BOOST_CHECK(node::ComputeMatMulReplayEpisodeShapeFingerprint(*params) !=
                baseline_shape);
    consensus.nMatMulRCHeight = saved_rc_height;
    BOOST_CHECK(node::ComputeMatMulReplayEpisodeShapeFingerprint(*params) ==
                baseline_shape);
}

//! EncDr stall-recovery knobs select nBits and the per-block nTime cap after
//! a flag day. Each must move replay_authority_context so a node with the
//! height set and a node without it cannot report the same context.
BOOST_AUTO_TEST_CASE(matmul_replay_authority_context_binds_encdr_stall_recovery)
{
    auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};
    auto& consensus{const_cast<Consensus::Params&>(params->GetConsensus())};
    const uint256 baseline{node::ComputeMatMulReplayAuthorityContext(*params)};

    const auto check_field_bound{[&](const char* what, auto& field, auto delta) {
        const auto saved{field};
        field = static_cast<std::remove_reference_t<decltype(field)>>(field + delta);
        BOOST_CHECK_MESSAGE(
            node::ComputeMatMulReplayAuthorityContext(*params) != baseline,
            std::string{"replay authority context ignores predicate-relevant field: "} + what);
        field = saved;
        BOOST_CHECK(node::ComputeMatMulReplayAuthorityContext(*params) == baseline);
    }};

    {
        const auto saved{consensus.nMatMulStallRecoveryHeight};
        consensus.nMatMulStallRecoveryHeight = 199299;
        BOOST_CHECK_MESSAGE(
            node::ComputeMatMulReplayAuthorityContext(*params) != baseline,
            "replay authority context ignores nMatMulStallRecoveryHeight");
        consensus.nMatMulStallRecoveryHeight = saved;
        BOOST_CHECK(node::ComputeMatMulReplayAuthorityContext(*params) == baseline);
    }
    check_field_bound("nMatMulStallRecoveryAsertNum", consensus.nMatMulStallRecoveryAsertNum, 1);
    check_field_bound("nMatMulStallRecoveryAsertDen", consensus.nMatMulStallRecoveryAsertDen, 1);
    check_field_bound("nMatMulMaxBlockTimeAdvance", consensus.nMatMulMaxBlockTimeAdvance, 1);
    check_field_bound("nMatMulAsertClampedMinInterval", consensus.nMatMulAsertClampedMinInterval, 1);
}

BOOST_AUTO_TEST_CASE(blockmanager_find_block_pos)
{
    const auto params {CreateChainParams(ArgsManager{}, ChainType::MAIN)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    const BlockManager::Options blockman_opts{
        .chainparams = *params,
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = m_args.GetDataDirNet() / "blocks" / "index",
            .cache_bytes = 0,
        },
    };
    BlockManager blockman{*Assert(m_node.shutdown_signal), blockman_opts};
    // simulate adding a genesis block normally
    BOOST_CHECK_EQUAL(blockman.WriteBlock(params->GenesisBlock(), 0).nPos, BLOCK_SERIALIZATION_HEADER_SIZE);
    // simulate what happens during reindex
    // simulate a well-formed genesis block being found at offset 8 in the blk00000.dat file
    // the block is found at offset 8 because there is an 8 byte serialization header
    // consisting of 4 magic bytes + 4 length bytes before each block in a well-formed blk file.
    const FlatFilePos pos{0, BLOCK_SERIALIZATION_HEADER_SIZE};
    blockman.UpdateBlockInfo(params->GenesisBlock(), 0, pos);
    // now simulate what happens after reindex for the first new block processed
    // the actual block contents don't matter, just that it's a block.
    // verify that the write position is at offset 0x12d.
    // this is a check to make sure that https://github.com/bitcoin/bitcoin/issues/21379 does not recur
    // 8 bytes (for serialization header) + 285 (for serialized genesis block) = 293
    // add another 8 bytes for the second block's serialization header and we get 293 + 8 = 301
    FlatFilePos actual{blockman.WriteBlock(params->GenesisBlock(), 1)};
    BOOST_CHECK_EQUAL(actual.nPos, BLOCK_SERIALIZATION_HEADER_SIZE + ::GetSerializeSize(TX_WITH_WITNESS(params->GenesisBlock())) + BLOCK_SERIALIZATION_HEADER_SIZE);
}

BOOST_FIXTURE_TEST_CASE(blockmanager_scan_unlink_already_pruned_files, TestChain100Setup)
{
    // Cap last block file size, and mine new block in a new block file.
    const auto& chainman = Assert(m_node.chainman);
    auto& blockman = chainman->m_blockman;
    const CBlockIndex* old_tip{WITH_LOCK(chainman->GetMutex(), return chainman->ActiveChain().Tip())};
    WITH_LOCK(chainman->GetMutex(), blockman.GetBlockFileInfo(old_tip->GetBlockPos().nFile)->nSize = MAX_BLOCKFILE_SIZE);
    CreateAndProcessBlock({}, GetScriptForDestination(PKHash(coinbaseKey.GetPubKey())));

    // Prune the older block file, but don't unlink it
    int file_number;
    {
        LOCK(chainman->GetMutex());
        file_number = old_tip->GetBlockPos().nFile;
        blockman.PruneOneBlockFile(file_number);
    }

    const FlatFilePos pos(file_number, 0);

    // Check that the file is not unlinked after ScanAndUnlinkAlreadyPrunedFiles
    // if m_have_pruned is not yet set
    WITH_LOCK(chainman->GetMutex(), blockman.ScanAndUnlinkAlreadyPrunedFiles());
    BOOST_CHECK(!blockman.OpenBlockFile(pos, true).IsNull());

    // Check that the file is unlinked after ScanAndUnlinkAlreadyPrunedFiles
    // once m_have_pruned is set
    blockman.m_have_pruned = true;
    WITH_LOCK(chainman->GetMutex(), blockman.ScanAndUnlinkAlreadyPrunedFiles());
    BOOST_CHECK(blockman.OpenBlockFile(pos, true).IsNull());

    // Check that calling with already pruned files doesn't cause an error
    WITH_LOCK(chainman->GetMutex(), blockman.ScanAndUnlinkAlreadyPrunedFiles());

    // Check that the new tip file has not been removed
    const CBlockIndex* new_tip{WITH_LOCK(chainman->GetMutex(), return chainman->ActiveChain().Tip())};
    BOOST_CHECK_NE(old_tip, new_tip);
    const int new_file_number{WITH_LOCK(chainman->GetMutex(), return new_tip->GetBlockPos().nFile)};
    const FlatFilePos new_pos(new_file_number, 0);
    BOOST_CHECK(!blockman.OpenBlockFile(new_pos, true).IsNull());
}

BOOST_FIXTURE_TEST_CASE(blockmanager_block_data_availability, TestChain100Setup)
{
    // The goal of the function is to return the first not pruned block in the range [upper_block, lower_block].
    LOCK(::cs_main);
    auto& chainman = m_node.chainman;
    auto& blockman = chainman->m_blockman;
    const CBlockIndex& tip = *chainman->ActiveTip();

    // Function to prune all blocks from 'last_pruned_block' down to the genesis block
    const auto& func_prune_blocks = [&](CBlockIndex* last_pruned_block)
    {
        LOCK(::cs_main);
        CBlockIndex* it = last_pruned_block;
        while (it != nullptr && it->nStatus & BLOCK_HAVE_DATA) {
            it->nStatus &= ~BLOCK_HAVE_DATA;
            it = it->pprev;
        }
    };

    // 1) Return genesis block when all blocks are available
    BOOST_CHECK_EQUAL(blockman.GetFirstBlock(tip, BLOCK_HAVE_DATA), chainman->ActiveChain()[0]);
    BOOST_CHECK(blockman.CheckBlockDataAvailability(tip, *chainman->ActiveChain()[0]));

    // 2) Check lower_block when all blocks are available
    CBlockIndex* lower_block = chainman->ActiveChain()[tip.nHeight / 2];
    BOOST_CHECK(blockman.CheckBlockDataAvailability(tip, *lower_block));

    // Prune half of the blocks
    int height_to_prune = tip.nHeight / 2;
    CBlockIndex* first_available_block = chainman->ActiveChain()[height_to_prune + 1];
    CBlockIndex* last_pruned_block = first_available_block->pprev;
    func_prune_blocks(last_pruned_block);

    // 3) The last block not pruned is in-between upper-block and the genesis block
    BOOST_CHECK_EQUAL(blockman.GetFirstBlock(tip, BLOCK_HAVE_DATA), first_available_block);
    BOOST_CHECK(blockman.CheckBlockDataAvailability(tip, *first_available_block));
    BOOST_CHECK(!blockman.CheckBlockDataAvailability(tip, *last_pruned_block));
}

BOOST_FIXTURE_TEST_CASE(blockmanager_readblock_hash_mismatch, TestingSetup)
{
    CBlockIndex* fake_index{WITH_LOCK(m_node.chainman->GetMutex(), return m_node.chainman->ActiveChain().Tip())};
    fake_index->phashBlock = &uint256::ONE; // invalid block hash

    ASSERT_DEBUG_LOG("GetHash() doesn't match index");
    CBlock dummy;
    BOOST_CHECK(!m_node.chainman->m_blockman.ReadBlock(dummy, *fake_index));
}

BOOST_AUTO_TEST_CASE(blockmanager_flush_block_file)
{
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    node::BlockManager::Options blockman_opts{
        .chainparams = Params(),
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = m_args.GetDataDirNet() / "blocks" / "index",
            .cache_bytes = 0,
        },
    };
    BlockManager blockman{*Assert(m_node.shutdown_signal), blockman_opts};
    const auto& consensus = Params().GetConsensus();
    const uint32_t compact_pow_limit = UintToArith256(consensus.powLimit).GetCompact();

    const auto make_test_block = [&](int32_t version, uint32_t nonce, uint8_t prev_byte) {
        CBlock block;
        block.nVersion = version;
        block.hashPrevBlock = uint256{prev_byte};
        block.nBits = compact_pow_limit;
        block.nNonce = nonce;
        block.nTime = nonce;
        block.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
        block.seed_a = uint256{1};
        block.seed_b = uint256{2};
        block.matmul_digest = uint256{1};
        return block;
    };

    // Keep blocks transaction-free, but make headers valid for current PoW checks.
    CBlock block1 = make_test_block(/*version=*/1, /*nonce=*/1, /*prev_byte=*/3);
    CBlock block2 = make_test_block(/*version=*/2, /*nonce=*/2, /*prev_byte=*/4);
    CBlock block3 = make_test_block(/*version=*/3, /*nonce=*/3, /*prev_byte=*/5);

    const auto test_block_size = static_cast<int>(::GetSerializeSize(TX_WITH_WITNESS(block1)));

    // Blockstore is empty
    BOOST_CHECK_EQUAL(blockman.CalculateCurrentUsage(), 0);

    // Write the first block to a new location.
    FlatFilePos pos1{blockman.WriteBlock(block1, /*nHeight=*/1)};

    // Write second block
    FlatFilePos pos2{blockman.WriteBlock(block2, /*nHeight=*/2)};

    // Two blocks in the file
    BOOST_CHECK_EQUAL(blockman.CalculateCurrentUsage(), (test_block_size + BLOCK_SERIALIZATION_HEADER_SIZE) * 2);

    // First two blocks are written as expected.
    // Under KAWPOW consensus, ReadBlock no longer enforces PoW in this code path.
    CBlock read_block;
    BOOST_CHECK_EQUAL(read_block.nVersion, 0);
    BOOST_CHECK(blockman.ReadBlock(read_block, pos1));
    BOOST_CHECK_EQUAL(read_block.nVersion, 1);
    BOOST_CHECK(blockman.ReadBlock(read_block, pos2));
    BOOST_CHECK_EQUAL(read_block.nVersion, 2);

    // During reindex, the flat file block storage will not be written to.
    // UpdateBlockInfo will, however, update the blockfile metadata.
    // Verify this behavior by attempting (and failing) to write block 3 data
    // to block 2 location.
    CBlockFileInfo* block_data = blockman.GetBlockFileInfo(0);
    BOOST_CHECK_EQUAL(block_data->nBlocks, 2);
    blockman.UpdateBlockInfo(block3, /*nHeight=*/3, /*pos=*/pos2);
    // Metadata is updated...
    BOOST_CHECK_EQUAL(block_data->nBlocks, 3);
    // ...but there are still only two blocks in the file
    BOOST_CHECK_EQUAL(blockman.CalculateCurrentUsage(), (test_block_size + BLOCK_SERIALIZATION_HEADER_SIZE) * 2);

    // Block 2 was not overwritten:
    BOOST_CHECK(blockman.ReadBlock(read_block, pos2));
    BOOST_CHECK_EQUAL(read_block.nVersion, 2);
}

BOOST_AUTO_TEST_SUITE_END()
