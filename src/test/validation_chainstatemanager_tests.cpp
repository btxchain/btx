// Copyright (c) 2019-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <chainparams.h>
#include <addresstype.h>
#include <consensus/validation.h>
#include <crypto/chacha20poly1305.h>
#include <dbwrapper.h>
#include <kernel/disconnected_transactions.h>
#include <node/chainstate.h>
#include <node/chainstatemanager_args.h>
#include <node/kernel_notifications.h>
#include <node/utxo_snapshot.h>
#include <random.h>
#include <rpc/blockchain.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <shielded/account_registry.h>
#include <shielded/validation.h>
#include <sync.h>
#include <test/util/chainstate.h>
#include <test/util/logging.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/shielded_account_registry_test_util.h>
#include <test/util/shielded_smile_test_util.h>
#include <test/util/shielded_v2_egress_fixture.h>
#include <test/util/validation.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/result.h>
#include <util/vector.h>
#include <validation.h>
#include <validationinterface.h>
#include <streams.h>

#include <tinyformat.h>

#include <map>
#include <vector>

#include <boost/test/unit_test.hpp>

using node::BlockManager;
using node::KernelNotifications;
using node::SnapshotMetadata;

namespace {

constexpr CAmount CHAINSTATE_REBALANCE_FEE{40'000};
constexpr CAmount CHAINSTATE_SHIELD_ONLY_FEE{100'000};

int32_t NextShieldedFixtureHeight(const ChainstateManager& chainman)
{
    return WITH_LOCK(::cs_main, return chainman.ActiveTip() != nullptr ? chainman.ActiveTip()->nHeight + 1 : 0;);
}

const Consensus::Params& ShieldedFixtureConsensus()
{
    return Params().GetConsensus();
}

void ReSignCoinbaseSpend(TestChain100Setup& setup,
                         CMutableTransaction& tx,
                         const CTransactionRef& funding_tx)
{
    FillableSigningProvider keystore;
    BOOST_REQUIRE(keystore.AddKey(setup.coinbaseKey));
    BOOST_REQUIRE_LT(0U, funding_tx->vout.size());

    std::map<COutPoint, Coin> input_coins;
    input_coins.emplace(COutPoint{funding_tx->GetHash(), 0},
                        Coin{funding_tx->vout[0], /*nHeight=*/0, /*fCoinBase=*/true});

    std::map<int, bilingual_str> input_errors;
    BOOST_REQUIRE(SignTransaction(tx, &keystore, input_coins, SIGHASH_ALL, input_errors));
}

void AttachCoinbaseFeeCarrier(TestChain100Setup& setup,
                              CMutableTransaction& tx,
                              const CTransactionRef& funding_tx,
                              CAmount fee = CHAINSTATE_REBALANCE_FEE)
{
    BOOST_REQUIRE_LT(0U, funding_tx->vout.size());
    BOOST_REQUIRE_GT(funding_tx->vout[0].nValue, fee);

    tx.vin = {CTxIn{COutPoint{funding_tx->GetHash(), 0}}};
    tx.vout = {CTxOut{funding_tx->vout[0].nValue - fee,
                      GetScriptForDestination(WitnessV2P2MR(uint256::ONE))}};

    ReSignCoinbaseSpend(setup, tx, funding_tx);
}

CMutableTransaction BuildLegacyShieldOnlyTx(TestChain100Setup& setup,
                                            const CTransactionRef& funding_tx,
                                            const uint256& merkle_anchor,
                                            CAmount fee = CHAINSTATE_SHIELD_ONLY_FEE)
{
    BOOST_REQUIRE_GT(funding_tx->vout.size(), 0U);
    BOOST_REQUIRE_GT(funding_tx->vout[0].nValue, fee);
    BOOST_REQUIRE(!merkle_anchor.IsNull());

    CMutableTransaction tx;
    tx.vin = {CTxIn{COutPoint{funding_tx->GetHash(), 0}}};

    CShieldedOutput output;
    output.note_commitment = GetRandHash();
    output.merkle_anchor = merkle_anchor;
    output.encrypted_note.aead_ciphertext.assign(AEADChaCha20Poly1305::EXPANSION, 0x00);
    tx.shielded_bundle.shielded_outputs.push_back(output);
    tx.shielded_bundle.value_balance = -(funding_tx->vout[0].nValue - fee);

    ReSignCoinbaseSpend(setup, tx, funding_tx);
    return tx;
}

auto BuildChainstateRebalanceFixture(TestChain100Setup& setup,
                                     const ChainstateManager& chainman,
                                     size_t reserve_output_count = 1,
                                     uint32_t settlement_window = 144)
{
    BOOST_REQUIRE_GT(setup.m_coinbase_txns.size(), 0U);

    auto fixture = test::shielded::BuildV2RebalanceFixture(
        reserve_output_count,
        settlement_window,
        &ShieldedFixtureConsensus(),
        NextShieldedFixtureHeight(chainman));
    AttachCoinbaseFeeCarrier(setup, fixture.tx, setup.m_coinbase_txns[0]);
    return fixture;
}

auto BuildChainstateSettlementAnchorReceiptFixture(const ChainstateManager& chainman,
                                                   size_t output_count = 2,
                                                   size_t proof_receipt_count = 1,
                                                   size_t required_receipts = 1)
{
    return test::shielded::BuildV2SettlementAnchorReceiptFixture(
        output_count,
        proof_receipt_count,
        required_receipts,
        &ShieldedFixtureConsensus(),
        NextShieldedFixtureHeight(chainman));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(validation_chainstatemanager_tests, TestingSetup)

//! Basic tests for ChainstateManager.
//!
//! First create a legacy (IBD) chainstate, then create a snapshot chainstate.
BOOST_FIXTURE_TEST_CASE(chainstatemanager, TestChain100Setup)
{
    ChainstateManager& manager = *m_node.chainman;
    std::vector<Chainstate*> chainstates;

    BOOST_CHECK(!manager.SnapshotBlockhash().has_value());

    // Create a legacy (IBD) chainstate.
    //
    Chainstate& c1 = manager.ActiveChainstate();
    chainstates.push_back(&c1);

    BOOST_CHECK(!manager.IsSnapshotActive());
    BOOST_CHECK(WITH_LOCK(::cs_main, return !manager.IsSnapshotValidated()));
    auto all = manager.GetAll();
    BOOST_CHECK_EQUAL_COLLECTIONS(all.begin(), all.end(), chainstates.begin(), chainstates.end());

    auto& active_chain = WITH_LOCK(manager.GetMutex(), return manager.ActiveChain());
    BOOST_CHECK_EQUAL(&active_chain, &c1.m_chain);

    // Get to a valid assumeutxo tip (per chainparams);
    mineBlocks(10);
    BOOST_CHECK_EQUAL(WITH_LOCK(manager.GetMutex(), return manager.ActiveHeight()), 110);
    auto active_tip = WITH_LOCK(manager.GetMutex(), return manager.ActiveTip());
    auto exp_tip = c1.m_chain.Tip();
    BOOST_CHECK_EQUAL(active_tip, exp_tip);

    BOOST_CHECK(!manager.SnapshotBlockhash().has_value());

    // Create a snapshot-based chainstate.
    //
    const uint256 snapshot_blockhash = active_tip->GetBlockHash();
    Chainstate& c2 = WITH_LOCK(::cs_main, return manager.ActivateExistingSnapshot(snapshot_blockhash));
    chainstates.push_back(&c2);
    c2.InitCoinsDB(
        /*cache_size_bytes=*/1 << 23, /*in_memory=*/true, /*should_wipe=*/false);
    {
        LOCK(::cs_main);
        c2.InitCoinsCache(1 << 23);
        c2.CoinsTip().SetBestBlock(active_tip->GetBlockHash());
        c2.setBlockIndexCandidates.insert(manager.m_blockman.LookupBlockIndex(active_tip->GetBlockHash()));
        c2.LoadChainTip();
    }
    BlockValidationState _;
    BOOST_CHECK(c2.ActivateBestChain(_, nullptr));

    BOOST_CHECK_EQUAL(manager.SnapshotBlockhash().value(), snapshot_blockhash);
    BOOST_CHECK(manager.IsSnapshotActive());
    BOOST_CHECK(WITH_LOCK(::cs_main, return !manager.IsSnapshotValidated()));
    BOOST_CHECK_EQUAL(&c2, &manager.ActiveChainstate());
    BOOST_CHECK(&c1 != &manager.ActiveChainstate());
    auto all2 = manager.GetAll();
    BOOST_CHECK_EQUAL_COLLECTIONS(all2.begin(), all2.end(), chainstates.begin(), chainstates.end());

    auto& active_chain2 = WITH_LOCK(manager.GetMutex(), return manager.ActiveChain());
    BOOST_CHECK_EQUAL(&active_chain2, &c2.m_chain);

    BOOST_CHECK_EQUAL(WITH_LOCK(manager.GetMutex(), return manager.ActiveHeight()), 110);
    mineBlocks(1);
    BOOST_CHECK_EQUAL(WITH_LOCK(manager.GetMutex(), return manager.ActiveHeight()), 111);
    BOOST_CHECK_EQUAL(WITH_LOCK(manager.GetMutex(), return c1.m_chain.Height()), 110);

    auto active_tip2 = WITH_LOCK(manager.GetMutex(), return manager.ActiveTip());
    BOOST_CHECK_EQUAL(active_tip, active_tip2->pprev);
    BOOST_CHECK_EQUAL(active_tip, c1.m_chain.Tip());
    BOOST_CHECK_EQUAL(active_tip2, c2.m_chain.Tip());

    // Let scheduler events finish running to avoid accessing memory that is going to be unloaded
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
}

//! Test rebalancing the caches associated with each chainstate.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_rebalance_caches, TestChain100Setup)
{
    ChainstateManager& manager = *m_node.chainman;

    size_t max_cache = 10000;
    manager.m_total_coinsdb_cache = max_cache;
    manager.m_total_coinstip_cache = max_cache;

    std::vector<Chainstate*> chainstates;

    // Create a legacy (IBD) chainstate.
    //
    Chainstate& c1 = manager.ActiveChainstate();
    chainstates.push_back(&c1);
    {
        LOCK(::cs_main);
        c1.InitCoinsCache(1 << 23);
        manager.MaybeRebalanceCaches();
    }

    BOOST_CHECK_EQUAL(c1.m_coinstip_cache_size_bytes, max_cache);
    BOOST_CHECK_EQUAL(c1.m_coinsdb_cache_size_bytes, max_cache);

    // Create a snapshot-based chainstate.
    //
    CBlockIndex* snapshot_base{WITH_LOCK(manager.GetMutex(), return manager.ActiveChain()[manager.ActiveChain().Height() / 2])};
    Chainstate& c2 = WITH_LOCK(cs_main, return manager.ActivateExistingSnapshot(*snapshot_base->phashBlock));
    chainstates.push_back(&c2);
    c2.InitCoinsDB(
        /*cache_size_bytes=*/1 << 23, /*in_memory=*/true, /*should_wipe=*/false);

    // Reset IBD state so IsInitialBlockDownload() returns true and causes
    // MaybeRebalancesCaches() to prioritize the snapshot chainstate, giving it
    // more cache space than the snapshot chainstate. Calling ResetIbd() is
    // necessary because m_cached_finished_ibd is already latched to true before
    // the test starts due to the test setup. After ResetIbd() is called.
    // IsInitialBlockDownload will return true because at this point the active
    // chainstate has a null chain tip.
    static_cast<TestChainstateManager&>(manager).ResetIbd();

    {
        LOCK(::cs_main);
        c2.InitCoinsCache(1 << 23);
        manager.MaybeRebalanceCaches();
    }

    BOOST_CHECK_CLOSE(double(c1.m_coinstip_cache_size_bytes), max_cache * 0.05, 1);
    BOOST_CHECK_CLOSE(double(c1.m_coinsdb_cache_size_bytes), max_cache * 0.05, 1);
    BOOST_CHECK_CLOSE(double(c2.m_coinstip_cache_size_bytes), max_cache * 0.95, 1);
    BOOST_CHECK_CLOSE(double(c2.m_coinsdb_cache_size_bytes), max_cache * 0.95, 1);
}

struct SnapshotTestSetup : TestChain100Setup {
    // Run with coinsdb on the filesystem to support, e.g., moving invalidated
    // chainstate dirs to "*_invalid".
    //
    // Note that this means the tests run considerably slower than in-memory DB
    // tests, but we can't otherwise test this functionality since it relies on
    // destructive filesystem operations.
    SnapshotTestSetup() : TestChain100Setup{
                              {},
                              {
                                  .coins_db_in_memory = false,
                                  .block_tree_db_in_memory = false,
                              },
                          }
    {
    }

    std::tuple<Chainstate*, Chainstate*> SetupSnapshot()
    {
        ChainstateManager& chainman = *Assert(m_node.chainman);

        BOOST_CHECK(!chainman.IsSnapshotActive());

        {
            LOCK(::cs_main);
            BOOST_CHECK(!chainman.IsSnapshotValidated());
            BOOST_CHECK(!node::FindSnapshotChainstateDir(chainman.m_options.datadir));
        }

        size_t initial_size;
        size_t initial_total_coins{m_coinbase_txns.size() + 1};

        // Make some initial assertions about the contents of the chainstate.
        {
            LOCK(::cs_main);
            CCoinsViewCache& ibd_coinscache = chainman.ActiveChainstate().CoinsTip();
            initial_size = ibd_coinscache.GetCacheSize();
            size_t total_coins{0};

            for (CTransactionRef& txn : m_coinbase_txns) {
                COutPoint op{txn->GetHash(), 0};
                BOOST_CHECK(ibd_coinscache.HaveCoin(op));
                total_coins++;
            }

            const CTransactionRef& genesis_tx{chainman.GetParams().GenesisBlock().vtx.at(0)};
            const COutPoint genesis_op{genesis_tx->GetHash(), 0};
            BOOST_CHECK(ibd_coinscache.HaveCoin(genesis_op));
            total_coins++;

            BOOST_CHECK_EQUAL(total_coins, initial_total_coins);
            BOOST_CHECK_EQUAL(initial_size, initial_total_coins);
        }

        Chainstate& validation_chainstate = chainman.ActiveChainstate();

        // Snapshot should refuse to load at this height.
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(this));
        BOOST_CHECK(!chainman.ActiveChainstate().m_from_snapshot_blockhash);
        BOOST_CHECK(!chainman.SnapshotBlockhash());

        // Mine 10 more blocks, putting at us height 110 where a valid assumeutxo value can
        // be found.
        constexpr int snapshot_height = 110;
        mineBlocks(10);
        initial_size += 10;
        initial_total_coins += 10;

        // Should not load malleated snapshots
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
            this, [](AutoFile& auto_infile, SnapshotMetadata& metadata) {
                // A UTXO is missing but count is correct
                metadata.m_coins_count -= 1;

                Txid txid;
                auto_infile >> txid;
                // coins size
                (void)ReadCompactSize(auto_infile);
                // vout index
                (void)ReadCompactSize(auto_infile);
                Coin coin;
                auto_infile >> coin;
        }));

        BOOST_CHECK(!node::FindSnapshotChainstateDir(chainman.m_options.datadir));

        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
            this, [](AutoFile& auto_infile, SnapshotMetadata& metadata) {
                // Coins count is larger than coins in file
                metadata.m_coins_count += 1;
        }));
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
            this, [](AutoFile& auto_infile, SnapshotMetadata& metadata) {
                // Coins count is smaller than coins in file
                metadata.m_coins_count -= 1;
        }));
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
            this, [](AutoFile& auto_infile, SnapshotMetadata& metadata) {
                // Wrong hash
                metadata.m_base_blockhash = uint256::ZERO;
        }));
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
            this, [](AutoFile& auto_infile, SnapshotMetadata& metadata) {
                // Wrong hash
                metadata.m_base_blockhash = uint256::ONE;
        }));

        BOOST_REQUIRE(CreateAndActivateUTXOSnapshot(this));
        BOOST_CHECK(fs::exists(*node::FindSnapshotChainstateDir(chainman.m_options.datadir)));

        // Ensure our active chain is the snapshot chainstate.
        BOOST_CHECK(!chainman.ActiveChainstate().m_from_snapshot_blockhash->IsNull());
        BOOST_CHECK_EQUAL(
            *chainman.ActiveChainstate().m_from_snapshot_blockhash,
            *chainman.SnapshotBlockhash());

        Chainstate& snapshot_chainstate = chainman.ActiveChainstate();

        {
            LOCK(::cs_main);

            fs::path found = *node::FindSnapshotChainstateDir(chainman.m_options.datadir);

            // Note: WriteSnapshotBaseBlockhash() is implicitly tested above.
            BOOST_CHECK_EQUAL(
                *node::ReadSnapshotBaseBlockhash(found),
                *chainman.SnapshotBlockhash());
        }

        const auto& au_data = ::Params().AssumeutxoForHeight(snapshot_height);
        const CBlockIndex* tip = WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());

        BOOST_CHECK_EQUAL(tip->m_chain_tx_count, au_data->m_chain_tx_count);

        // To be checked against later when we try loading a subsequent snapshot.
        uint256 loaded_snapshot_blockhash{*chainman.SnapshotBlockhash()};

        // Make some assertions about the both chainstates. These checks ensure the
        // legacy chainstate hasn't changed and that the newly created chainstate
        // reflects the expected content.
        {
            LOCK(::cs_main);
            int chains_tested{0};

            for (Chainstate* chainstate : chainman.GetAll()) {
                BOOST_TEST_MESSAGE("Checking coins in " << chainstate->ToString());
                CCoinsViewCache& coinscache = chainstate->CoinsTip();

                // Both caches will be empty initially.
                BOOST_CHECK_EQUAL((unsigned int)0, coinscache.GetCacheSize());

                size_t total_coins{0};

                for (CTransactionRef& txn : m_coinbase_txns) {
                    COutPoint op{txn->GetHash(), 0};
                    BOOST_CHECK(coinscache.HaveCoin(op));
                    total_coins++;
                }

                const CTransactionRef& genesis_tx{chainman.GetParams().GenesisBlock().vtx.at(0)};
                const COutPoint genesis_op{genesis_tx->GetHash(), 0};
                BOOST_CHECK(coinscache.HaveCoin(genesis_op));
                total_coins++;

                BOOST_CHECK_EQUAL(initial_size , coinscache.GetCacheSize());
                BOOST_CHECK_EQUAL(total_coins, initial_total_coins);
                chains_tested++;
            }

            BOOST_CHECK_EQUAL(chains_tested, 2);
        }

        // Mine some new blocks on top of the activated snapshot chainstate.
        constexpr size_t new_coins{100};
        mineBlocks(new_coins);  // Defined in TestChain100Setup.

        {
            LOCK(::cs_main);
            size_t coins_in_active{0};
            size_t coins_in_background{0};
            size_t coins_missing_from_background{0};

            for (Chainstate* chainstate : chainman.GetAll()) {
                BOOST_TEST_MESSAGE("Checking coins in " << chainstate->ToString());
                CCoinsViewCache& coinscache = chainstate->CoinsTip();
                bool is_background = chainstate != &chainman.ActiveChainstate();

                for (CTransactionRef& txn : m_coinbase_txns) {
                    COutPoint op{txn->GetHash(), 0};
                    if (coinscache.HaveCoin(op)) {
                        (is_background ? coins_in_background : coins_in_active)++;
                    } else if (is_background) {
                        coins_missing_from_background++;
                    }
                }

                const CTransactionRef& genesis_tx{chainman.GetParams().GenesisBlock().vtx.at(0)};
                const COutPoint genesis_op{genesis_tx->GetHash(), 0};
                if (coinscache.HaveCoin(genesis_op)) {
                    (is_background ? coins_in_background : coins_in_active)++;
                } else if (is_background) {
                    coins_missing_from_background++;
                }
            }

            BOOST_CHECK_EQUAL(coins_in_active, initial_total_coins + new_coins);
            BOOST_CHECK_EQUAL(coins_in_background, initial_total_coins);
            BOOST_CHECK_EQUAL(coins_missing_from_background, new_coins);
        }

        // Snapshot should refuse to load after one has already loaded.
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(this));

        // Snapshot blockhash should be unchanged.
        BOOST_CHECK_EQUAL(
            *chainman.ActiveChainstate().m_from_snapshot_blockhash,
            loaded_snapshot_blockhash);
        return std::make_tuple(&validation_chainstate, &snapshot_chainstate);
    }

    // Simulate a restart of the node by flushing all state to disk, clearing the
    // existing ChainstateManager, and unloading the block index.
    //
    // @returns a reference to the "restarted" ChainstateManager
    ChainstateManager& SimulateNodeRestart()
    {
        ChainstateManager& chainman = *Assert(m_node.chainman);

        BOOST_TEST_MESSAGE("Simulating node restart");
        {
            for (Chainstate* cs : chainman.GetAll()) {
                LOCK(::cs_main);
                cs->ForceFlushStateToDisk();
            }
            // Process all callbacks referring to the old manager before wiping it.
            m_node.validation_signals->SyncWithValidationInterfaceQueue();
            LOCK(::cs_main);
            chainman.ResetChainstates();
            BOOST_CHECK_EQUAL(chainman.GetAll().size(), 0);
            m_node.notifications = std::make_unique<KernelNotifications>(Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
            const ChainstateManager::Options chainman_opts{
                .chainparams = ::Params(),
                .datadir = chainman.m_options.datadir,
                .notifications = *m_node.notifications,
                .signals = m_node.validation_signals.get(),
            };
            const BlockManager::Options blockman_opts{
                .chainparams = chainman_opts.chainparams,
                .blocks_dir = m_args.GetBlocksDirPath(),
                .notifications = chainman_opts.notifications,
                .block_tree_db_params = DBParams{
                    .path = chainman.m_options.datadir / "blocks" / "index",
                    .cache_bytes = m_kernel_cache_sizes.block_tree_db,
                    .memory_only = m_block_tree_db_in_memory,
                },
            };
            // For robustness, ensure the old manager is destroyed before creating a
            // new one.
            m_node.chainman.reset();
            m_node.chainman = std::make_unique<ChainstateManager>(*Assert(m_node.shutdown_signal), chainman_opts, blockman_opts);
        }
        return *Assert(m_node.chainman);
    }
};

//! Test basic snapshot activation.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_activate_snapshot, SnapshotTestSetup)
{
    this->SetupSnapshot();
}

//! Test LoadBlockIndex behavior when multiple chainstates are in use.
//!
//! - First, verify that setBlockIndexCandidates is as expected when using a single,
//!   fully-validating chainstate.
//!
//! - Then mark a region of the chain as missing data and introduce a second chainstate
//!   that will tolerate assumed-valid blocks. Run LoadBlockIndex() and ensure that the first
//!   chainstate only contains fully validated blocks and the other chainstate contains all blocks,
//!   except those marked assume-valid, because those entries don't HAVE_DATA.
//!
BOOST_FIXTURE_TEST_CASE(chainstatemanager_loadblockindex, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& cs1 = chainman.ActiveChainstate();

    int num_indexes{0};
    // Blocks in range [assumed_valid_start_idx, last_assumed_valid_idx) will be
    // marked as assumed-valid and not having data.
    const int expected_assumed_valid{20};
    const int last_assumed_valid_idx{111};
    const int assumed_valid_start_idx = last_assumed_valid_idx - expected_assumed_valid;

    // Mine to height 120, past the hardcoded regtest assumeutxo snapshot at
    // height 110
    mineBlocks(20);

    CBlockIndex* validated_tip{nullptr};
    CBlockIndex* assumed_base{nullptr};
    CBlockIndex* assumed_tip{WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Tip())};
    BOOST_CHECK_EQUAL(assumed_tip->nHeight, 120);

    auto reload_all_block_indexes = [&]() {
        // For completeness, we also reset the block sequence counters to
        // ensure that no state which affects the ranking of tip-candidates is
        // retained (even though this isn't strictly necessary).
        WITH_LOCK(::cs_main, return chainman.ResetBlockSequenceCounters());
        for (Chainstate* cs : chainman.GetAll()) {
            LOCK(::cs_main);
            cs->ClearBlockIndexCandidates();
            BOOST_CHECK(cs->setBlockIndexCandidates.empty());
        }

        WITH_LOCK(::cs_main, chainman.LoadBlockIndex());
    };

    // Ensure that without any assumed-valid BlockIndex entries, only the current tip is
    // considered as a candidate.
    reload_all_block_indexes();
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.size(), 1);

    // Reset some region of the chain's nStatus, removing the HAVE_DATA flag.
    for (int i = 0; i <= cs1.m_chain.Height(); ++i) {
        LOCK(::cs_main);
        auto index = cs1.m_chain[i];

        // Blocks with heights in range [91, 110] are marked as missing data.
        if (i < last_assumed_valid_idx && i >= assumed_valid_start_idx) {
            index->nStatus = BlockStatus::BLOCK_VALID_TREE;
            index->nTx = 0;
            index->m_chain_tx_count = 0;
        }

        ++num_indexes;

        // Note the last fully-validated block as the expected validated tip.
        if (i == (assumed_valid_start_idx - 1)) {
            validated_tip = index;
        }
        // Note the last assumed valid block as the snapshot base
        if (i == last_assumed_valid_idx - 1) {
            assumed_base = index;
        }
    }

    // Note: cs2's tip is not set when ActivateExistingSnapshot is called.
    Chainstate& cs2 = WITH_LOCK(::cs_main,
        return chainman.ActivateExistingSnapshot(*assumed_base->phashBlock));

    // Set tip of the fully validated chain to be the validated tip
    cs1.m_chain.SetTip(*validated_tip);

    // Set tip of the assume-valid-based chain to the assume-valid block
    cs2.m_chain.SetTip(*assumed_base);

    // Sanity check test variables.
    BOOST_CHECK_EQUAL(num_indexes, 121); // 121 total blocks, including genesis
    BOOST_CHECK_EQUAL(assumed_tip->nHeight, 120);  // original chain has height 120
    BOOST_CHECK_EQUAL(validated_tip->nHeight, 90); // current cs1 chain has height 90
    BOOST_CHECK_EQUAL(assumed_base->nHeight, 110); // current cs2 chain has height 110

    // Regenerate cs1.setBlockIndexCandidates and cs2.setBlockIndexCandidate and
    // check contents below.
    reload_all_block_indexes();

    // The fully validated chain should only have the current validated tip and
    // the assumed valid base as candidates, blocks 90 and 110. Specifically:
    //
    // - It does not have blocks 0-89 because they contain less work than the
    //   chain tip.
    //
    // - It has block 90 because it has data and equal work to the chain tip,
    //   (since it is the chain tip).
    //
    // - It does not have blocks 91-109 because they do not contain data.
    //
    // - It has block 110 even though it does not have data, because
    //   LoadBlockIndex has a special case to always add the snapshot block as a
    //   candidate. The special case is only actually intended to apply to the
    //   snapshot chainstate cs2, not the background chainstate cs1, but it is
    //   written broadly and applies to both.
    //
    // - It does not have any blocks after height 110 because cs1 is a background
    //   chainstate, and only blocks where are ancestors of the snapshot block
    //   are added as candidates for the background chainstate.
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.size(), 2);
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.count(validated_tip), 1);
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.count(assumed_base), 1);

    // The assumed-valid tolerant chain has the assumed valid base as a
    // candidate, but otherwise has none of the assumed-valid (which do not
    // HAVE_DATA) blocks as candidates.
    //
    // Specifically:
    // - All blocks below height 110 are not candidates, because cs2 chain tip
    //   has height 110 and they have less work than it does.
    //
    // - Block 110 is a candidate even though it does not have data, because it
    //   is the snapshot block, which is assumed valid.
    //
    // - Blocks 111-120 are added because they have data.

    // Check that block 90 is absent
    BOOST_CHECK_EQUAL(cs2.setBlockIndexCandidates.count(validated_tip), 0);
    // Check that block 109 is absent
    BOOST_CHECK_EQUAL(cs2.setBlockIndexCandidates.count(assumed_base->pprev), 0);
    // Check that block 110 is present
    BOOST_CHECK_EQUAL(cs2.setBlockIndexCandidates.count(assumed_base), 1);
    // Check that block 120 is present
    BOOST_CHECK_EQUAL(cs2.setBlockIndexCandidates.count(assumed_tip), 1);
    // Check that 11 blocks total are present.
    BOOST_CHECK_EQUAL(cs2.setBlockIndexCandidates.size(), num_indexes - last_assumed_valid_idx + 1);
}

//! Ensure that snapshot chainstates initialize properly when found on disk.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_snapshot_init, SnapshotTestSetup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& bg_chainstate = chainman.ActiveChainstate();

    this->SetupSnapshot();

    fs::path snapshot_chainstate_dir = *node::FindSnapshotChainstateDir(chainman.m_options.datadir);
    BOOST_CHECK(fs::exists(snapshot_chainstate_dir));
    BOOST_CHECK_EQUAL(snapshot_chainstate_dir, gArgs.GetDataDirNet() / "chainstate_snapshot");

    BOOST_CHECK(chainman.IsSnapshotActive());
    const uint256 snapshot_tip_hash = WITH_LOCK(chainman.GetMutex(),
        return chainman.ActiveTip()->GetBlockHash());

    auto all_chainstates = chainman.GetAll();
    BOOST_CHECK_EQUAL(all_chainstates.size(), 2);

    // "Rewind" the background chainstate so that its tip is not at the
    // base block of the snapshot - this is so after simulating a node restart,
    // it will initialize instead of attempting to complete validation.
    //
    // Note that this is not a realistic use of DisconnectTip().
    DisconnectedBlockTransactions unused_pool{MAX_DISCONNECTED_TX_POOL_BYTES};
    BlockValidationState unused_state;
    {
        LOCK2(::cs_main, bg_chainstate.MempoolMutex());
        BOOST_CHECK(bg_chainstate.DisconnectTip(unused_state, &unused_pool));
        unused_pool.clear();  // to avoid queuedTx assertion errors on teardown
    }
    BOOST_CHECK_EQUAL(bg_chainstate.m_chain.Height(), 109);

    // Test that simulating a shutdown (resetting ChainstateManager) and then performing
    // chainstate reinitializing successfully cleans up the background-validation
    // chainstate data, and we end up with a single chainstate that is at tip.
    ChainstateManager& chainman_restarted = this->SimulateNodeRestart();

    BOOST_TEST_MESSAGE("Performing Load/Verify/Activate of chainstate");

    // This call reinitializes the chainstates.
    this->LoadVerifyActivateChainstate();

    {
        LOCK(chainman_restarted.GetMutex());
        BOOST_CHECK_EQUAL(chainman_restarted.GetAll().size(), 2);
        BOOST_CHECK(chainman_restarted.IsSnapshotActive());
        BOOST_CHECK(!chainman_restarted.IsSnapshotValidated());

        BOOST_CHECK_EQUAL(chainman_restarted.ActiveTip()->GetBlockHash(), snapshot_tip_hash);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 210);
    }

    BOOST_TEST_MESSAGE(
        "Ensure we can mine blocks on top of the initialized snapshot chainstate");
    mineBlocks(10);
    {
        LOCK(chainman_restarted.GetMutex());
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 220);

        // Background chainstate should be unaware of new blocks on the snapshot
        // chainstate.
        for (Chainstate* cs : chainman_restarted.GetAll()) {
            if (cs != &chainman_restarted.ActiveChainstate()) {
                BOOST_CHECK_EQUAL(cs->m_chain.Height(), 109);
            }
        }
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_snapshot_completion, SnapshotTestSetup)
{
    this->SetupSnapshot();

    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& active_cs = chainman.ActiveChainstate();
    auto tip_cache_before_complete = active_cs.m_coinstip_cache_size_bytes;
    auto db_cache_before_complete = active_cs.m_coinsdb_cache_size_bytes;

    SnapshotCompletionResult res;
    m_node.notifications->m_shutdown_on_fatal_error = false;

    fs::path snapshot_chainstate_dir = *node::FindSnapshotChainstateDir(chainman.m_options.datadir);
    BOOST_CHECK(fs::exists(snapshot_chainstate_dir));
    BOOST_CHECK_EQUAL(snapshot_chainstate_dir, gArgs.GetDataDirNet() / "chainstate_snapshot");

    BOOST_CHECK(chainman.IsSnapshotActive());
    const uint256 snapshot_tip_hash = WITH_LOCK(chainman.GetMutex(),
        return chainman.ActiveTip()->GetBlockHash());

    res = WITH_LOCK(::cs_main, return chainman.MaybeCompleteSnapshotValidation());
    BOOST_CHECK_EQUAL(res, SnapshotCompletionResult::SUCCESS);

    WITH_LOCK(::cs_main, BOOST_CHECK(chainman.IsSnapshotValidated()));
    BOOST_CHECK(chainman.IsSnapshotActive());

    // Cache should have been rebalanced and reallocated to the "only" remaining
    // chainstate.
    BOOST_CHECK(active_cs.m_coinstip_cache_size_bytes > tip_cache_before_complete);
    BOOST_CHECK(active_cs.m_coinsdb_cache_size_bytes > db_cache_before_complete);

    auto all_chainstates = chainman.GetAll();
    BOOST_CHECK_EQUAL(all_chainstates.size(), 1);
    BOOST_CHECK_EQUAL(all_chainstates[0], &active_cs);

    // Trying completion again should return false.
    res = WITH_LOCK(::cs_main, return chainman.MaybeCompleteSnapshotValidation());
    BOOST_CHECK_EQUAL(res, SnapshotCompletionResult::SKIPPED);

    // The invalid snapshot path should not have been used.
    fs::path snapshot_invalid_dir = gArgs.GetDataDirNet() / "chainstate_snapshot_INVALID";
    BOOST_CHECK(!fs::exists(snapshot_invalid_dir));
    // chainstate_snapshot should still exist.
    BOOST_CHECK(fs::exists(snapshot_chainstate_dir));

    // Test that simulating a shutdown (resetting ChainstateManager) and then performing
    // chainstate reinitializing successfully cleans up the background-validation
    // chainstate data, and we end up with a single chainstate that is at tip.
    ChainstateManager& chainman_restarted = this->SimulateNodeRestart();

    BOOST_TEST_MESSAGE("Performing Load/Verify/Activate of chainstate");

    // This call reinitializes the chainstates, and should clean up the now unnecessary
    // background-validation leveldb contents.
    this->LoadVerifyActivateChainstate();

    BOOST_CHECK(!fs::exists(snapshot_invalid_dir));
    // chainstate_snapshot should now *not* exist.
    BOOST_CHECK(!fs::exists(snapshot_chainstate_dir));

    const Chainstate& active_cs2 = chainman_restarted.ActiveChainstate();

    {
        LOCK(chainman_restarted.GetMutex());
        BOOST_CHECK_EQUAL(chainman_restarted.GetAll().size(), 1);
        BOOST_CHECK(!chainman_restarted.IsSnapshotActive());
        BOOST_CHECK(!chainman_restarted.IsSnapshotValidated());
        BOOST_CHECK(active_cs2.m_coinstip_cache_size_bytes > tip_cache_before_complete);
        BOOST_CHECK(active_cs2.m_coinsdb_cache_size_bytes > db_cache_before_complete);

        BOOST_CHECK_EQUAL(chainman_restarted.ActiveTip()->GetBlockHash(), snapshot_tip_hash);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 210);
    }

    BOOST_TEST_MESSAGE(
        "Ensure we can mine blocks on top of the \"new\" IBD chainstate");
    mineBlocks(10);
    {
        LOCK(chainman_restarted.GetMutex());
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 220);
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_snapshot_completion_hash_mismatch, SnapshotTestSetup)
{
    auto chainstates = this->SetupSnapshot();
    Chainstate& validation_chainstate = *std::get<0>(chainstates);
    ChainstateManager& chainman = *Assert(m_node.chainman);
    SnapshotCompletionResult res;
    m_node.notifications->m_shutdown_on_fatal_error = false;

    // Test tampering with the IBD UTXO set with an extra coin to ensure it causes
    // snapshot completion to fail.
    CCoinsViewCache& ibd_coins = WITH_LOCK(::cs_main,
        return validation_chainstate.CoinsTip());
    Coin badcoin;
    badcoin.out.nValue = m_rng.rand32();
    badcoin.nHeight = 1;
    badcoin.out.scriptPubKey.assign(m_rng.randbits(6), 0);
    Txid txid = Txid::FromUint256(m_rng.rand256());
    ibd_coins.AddCoin(COutPoint(txid, 0), std::move(badcoin), false);

    fs::path snapshot_chainstate_dir = gArgs.GetDataDirNet() / "chainstate_snapshot";
    BOOST_CHECK(fs::exists(snapshot_chainstate_dir));

    {
        ASSERT_DEBUG_LOG("failed to validate the -assumeutxo snapshot state");
        res = WITH_LOCK(::cs_main, return chainman.MaybeCompleteSnapshotValidation());
        BOOST_CHECK_EQUAL(res, SnapshotCompletionResult::HASH_MISMATCH);
    }

    auto all_chainstates = chainman.GetAll();
    BOOST_CHECK_EQUAL(all_chainstates.size(), 1);
    BOOST_CHECK_EQUAL(all_chainstates[0], &validation_chainstate);
    BOOST_CHECK_EQUAL(&chainman.ActiveChainstate(), &validation_chainstate);

    fs::path snapshot_invalid_dir = gArgs.GetDataDirNet() / "chainstate_snapshot_INVALID";
    BOOST_CHECK(fs::exists(snapshot_invalid_dir));

    // Test that simulating a shutdown (resetting ChainstateManager) and then performing
    // chainstate reinitializing successfully loads only the fully-validated
    // chainstate data, and we end up with a single chainstate that is at tip.
    ChainstateManager& chainman_restarted = this->SimulateNodeRestart();

    BOOST_TEST_MESSAGE("Performing Load/Verify/Activate of chainstate");

    // This call reinitializes the chainstates, and should clean up the now unnecessary
    // background-validation leveldb contents.
    this->LoadVerifyActivateChainstate();

    BOOST_CHECK(fs::exists(snapshot_invalid_dir));
    BOOST_CHECK(!fs::exists(snapshot_chainstate_dir));

    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainman_restarted.GetAll().size(), 1);
        BOOST_CHECK(!chainman_restarted.IsSnapshotActive());
        BOOST_CHECK(!chainman_restarted.IsSnapshotValidated());
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 210);
    }

    BOOST_TEST_MESSAGE(
        "Ensure we can mine blocks on top of the \"new\" IBD chainstate");
    mineBlocks(10);
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 220);
    }
}

struct PersistedTestChain100Setup : TestChain100Setup
{
    PersistedTestChain100Setup()
        : TestChain100Setup(ChainType::REGTEST,
                            {.coins_db_in_memory = false, .block_tree_db_in_memory = false})
    {
    }
};

BOOST_FIXTURE_TEST_CASE(chainstatemanager_rebuilds_shielded_state_when_commitment_index_missing, PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const uint256 fake_commitment = GetRandHash();
    const auto settlement_anchor_fixture = BuildChainstateSettlementAnchorReceiptFixture(chainman);
    const fs::path shielded_section_path = m_args.GetDataDirNet() / "shielded_section.dat";
    auto simulate_node_restart = [&]() -> ChainstateManager& {
        ChainstateManager& current_chainman = *Assert(m_node.chainman);

        for (Chainstate* cs : current_chainman.GetAll()) {
            LOCK(::cs_main);
            cs->ForceFlushStateToDisk();
        }
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        {
            LOCK(::cs_main);
            current_chainman.ResetChainstates();
            BOOST_CHECK_EQUAL(current_chainman.GetAll().size(), 0);
            m_node.notifications = std::make_unique<KernelNotifications>(
                Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
            const ChainstateManager::Options chainman_opts{
                .chainparams = ::Params(),
                .datadir = current_chainman.m_options.datadir,
                .notifications = *m_node.notifications,
                .signals = m_node.validation_signals.get(),
            };
            const BlockManager::Options blockman_opts{
                .chainparams = chainman_opts.chainparams,
                .blocks_dir = m_args.GetBlocksDirPath(),
                .notifications = chainman_opts.notifications,
                .block_tree_db_params = DBParams{
                    .path = current_chainman.m_options.datadir / "blocks" / "index",
                    .cache_bytes = m_kernel_cache_sizes.block_tree_db,
                    .memory_only = m_block_tree_db_in_memory,
                },
            };
            m_node.chainman.reset();
            m_node.chainman = std::make_unique<ChainstateManager>(
                *Assert(m_node.shutdown_signal), chainman_opts, blockman_opts);
        }
        return *Assert(m_node.chainman);
    };

    {
        const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
        CreateAndProcessBlock({settlement_anchor_fixture.tx}, script_pub_key);

        AutoFile outfile{fsbridge::fopen(shielded_section_path, "wb")};
        BOOST_REQUIRE(!outfile.IsNull());
        outfile << fake_commitment;
        BOOST_REQUIRE_EQUAL(outfile.fclose(), 0);
    }

    node::ShieldedSnapshotSectionHeader header;
    header.m_snapshot_version = 3;
    header.m_commitment_count = 1;
    header.m_recent_output_counts = {1};

    {
        LOCK(::cs_main);
        const CBlockIndex* const tip = chainman.ActiveTip();
        BOOST_REQUIRE(tip != nullptr);

        AutoFile infile{fsbridge::fopen(shielded_section_path, "rb")};
        BOOST_REQUIRE(!infile.IsNull());
        BOOST_REQUIRE(chainman.LoadShieldedSnapshotSection(infile, header, tip));
        BOOST_REQUIRE(chainman.HasShieldedState());
        BOOST_CHECK_EQUAL(chainman.GetShieldedMerkleTree().Size(), 1U);
        BOOST_CHECK(chainman.GetShieldedMerkleTree().HasCommitmentIndex());
        BOOST_CHECK(chainman.IsShieldedSettlementAnchorValid(
            settlement_anchor_fixture.settlement_anchor_digest));

        const auto restored_commitment = chainman.GetShieldedMerkleTree().CommitmentAt(0);
        BOOST_REQUIRE(restored_commitment.has_value());
        BOOST_CHECK_EQUAL(*restored_commitment, fake_commitment);
    }

    ChainstateManager& chainman_restarted = simulate_node_restart();
    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman_restarted.EnsureShieldedStateInitialized());
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedMerkleTree().Size(), 0U);
        BOOST_CHECK(chainman_restarted.GetShieldedMerkleTree().HasCommitmentIndex());
        BOOST_CHECK(!chainman_restarted.GetShieldedMerkleTree().CommitmentAt(0).has_value());
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedNullifierCount(), 0U);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedPoolBalance(), 0);
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_reloads_version4_snapshot_settlement_anchor_state, PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const auto settlement_anchor_fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture();
    const fs::path shielded_section_path = m_args.GetDataDirNet() / "shielded_section_v4.dat";
    auto simulate_node_restart = [&]() -> ChainstateManager& {
        ChainstateManager& current_chainman = *Assert(m_node.chainman);

        for (Chainstate* cs : current_chainman.GetAll()) {
            LOCK(::cs_main);
            cs->ForceFlushStateToDisk();
        }
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        {
            LOCK(::cs_main);
            current_chainman.ResetChainstates();
            BOOST_CHECK_EQUAL(current_chainman.GetAll().size(), 0);
            m_node.notifications = std::make_unique<KernelNotifications>(
                Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
            const ChainstateManager::Options chainman_opts{
                .chainparams = ::Params(),
                .datadir = current_chainman.m_options.datadir,
                .notifications = *m_node.notifications,
                .signals = m_node.validation_signals.get(),
            };
            const BlockManager::Options blockman_opts{
                .chainparams = chainman_opts.chainparams,
                .blocks_dir = m_args.GetBlocksDirPath(),
                .notifications = chainman_opts.notifications,
                .block_tree_db_params = DBParams{
                    .path = current_chainman.m_options.datadir / "blocks" / "index",
                    .cache_bytes = m_kernel_cache_sizes.block_tree_db,
                    .memory_only = m_block_tree_db_in_memory,
                },
            };
            m_node.chainman.reset();
            m_node.chainman = std::make_unique<ChainstateManager>(
                *Assert(m_node.shutdown_signal), chainman_opts, blockman_opts);
        }
        return *Assert(m_node.chainman);
    };

    {
        AutoFile outfile{fsbridge::fopen(shielded_section_path, "wb")};
        BOOST_REQUIRE(!outfile.IsNull());
        outfile << settlement_anchor_fixture.settlement_anchor_digest;
        BOOST_REQUIRE_EQUAL(outfile.fclose(), 0);
    }

    node::ShieldedSnapshotSectionHeader header;
    header.m_snapshot_version = 4;
    header.m_settlement_anchor_count = 1;

    {
        LOCK(::cs_main);
        const CBlockIndex* const tip = chainman.ActiveTip();
        BOOST_REQUIRE(tip != nullptr);

        AutoFile infile{fsbridge::fopen(shielded_section_path, "rb")};
        BOOST_REQUIRE(!infile.IsNull());
        BOOST_REQUIRE(chainman.LoadShieldedSnapshotSection(infile, header, tip));
        BOOST_REQUIRE(chainman.HasShieldedState());
        BOOST_CHECK_EQUAL(chainman.GetShieldedMerkleTree().Size(), 0U);
        BOOST_CHECK(chainman.GetShieldedMerkleTree().HasCommitmentIndex());
        BOOST_CHECK(chainman.IsShieldedSettlementAnchorValid(
            settlement_anchor_fixture.settlement_anchor_digest));
    }

    ChainstateManager& chainman_restarted = simulate_node_restart();
    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman_restarted.EnsureShieldedStateInitialized());
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedMerkleTree().Size(), 0U);
        BOOST_CHECK(chainman_restarted.GetShieldedMerkleTree().HasCommitmentIndex());
        BOOST_CHECK(!chainman_restarted.GetShieldedMerkleTree().CommitmentAt(0).has_value());
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedNullifierCount(), 0U);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedPoolBalance(), 0);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedAccountRegistryEntryCount(), 0U);
        BOOST_CHECK(chainman_restarted.IsShieldedSettlementAnchorValid(
            settlement_anchor_fixture.settlement_anchor_digest));
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_reloads_chain_equivalent_snapshot_account_registry_state,
                        PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const fs::path shielded_section_path = m_args.GetDataDirNet() / "shielded_section_v5_registry.dat";
    auto simulate_node_restart = [&]() -> ChainstateManager& {
        ChainstateManager& current_chainman = *Assert(m_node.chainman);

        for (Chainstate* cs : current_chainman.GetAll()) {
            LOCK(::cs_main);
            cs->ForceFlushStateToDisk();
        }
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        {
            LOCK(::cs_main);
            current_chainman.ResetChainstates();
            BOOST_CHECK_EQUAL(current_chainman.GetAll().size(), 0);
            m_node.notifications = std::make_unique<KernelNotifications>(
                Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
            const ChainstateManager::Options chainman_opts{
                .chainparams = ::Params(),
                .datadir = current_chainman.m_options.datadir,
                .notifications = *m_node.notifications,
                .signals = m_node.validation_signals.get(),
            };
            const BlockManager::Options blockman_opts{
                .chainparams = chainman_opts.chainparams,
                .blocks_dir = m_args.GetBlocksDirPath(),
                .notifications = chainman_opts.notifications,
                .block_tree_db_params = DBParams{
                    .path = current_chainman.m_options.datadir / "blocks" / "index",
                    .cache_bytes = m_kernel_cache_sizes.block_tree_db,
                    .memory_only = m_block_tree_db_in_memory,
                },
            };
            m_node.chainman.reset();
            m_node.chainman = std::make_unique<ChainstateManager>(
                *Assert(m_node.shutdown_signal), chainman_opts, blockman_opts);
        }
        return *Assert(m_node.chainman);
    };

    const auto rebalance_fixture = BuildChainstateRebalanceFixture(*this, chainman, /*reserve_output_count=*/3);
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({rebalance_fixture.tx}, script_pub_key);

    shielded::registry::ShieldedAccountRegistrySnapshot snapshot;
    uint256 expected_registry_root;
    size_t expected_registry_size{0};
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        const CBlockIndex* const tip = chainman.ActiveTip();
        BOOST_REQUIRE(tip != nullptr);
        const auto exported_snapshot =
            chainman.ExportShieldedAccountRegistrySnapshot(chainman.ActiveChainstate(), tip);
        BOOST_REQUIRE(exported_snapshot.has_value());
        snapshot = *exported_snapshot;
        BOOST_REQUIRE(snapshot.IsValid());
        expected_registry_root = chainman.GetShieldedAccountRegistryRoot();
        expected_registry_size = chainman.GetShieldedAccountRegistryEntryCount();
    }

    {
        AutoFile outfile{fsbridge::fopen(shielded_section_path, "wb")};
        BOOST_REQUIRE(!outfile.IsNull());
        for (const auto& entry : snapshot.entries) {
            outfile << entry;
        }
        BOOST_REQUIRE_EQUAL(outfile.fclose(), 0);
    }

    node::ShieldedSnapshotSectionHeader header;
    header.m_snapshot_version = node::SnapshotMetadata::CURRENT_VERSION;
    header.m_account_registry_entry_count = snapshot.entries.size();

    {
        LOCK(::cs_main);
        const CBlockIndex* const tip = chainman.ActiveTip();
        BOOST_REQUIRE(tip != nullptr);

        AutoFile infile{fsbridge::fopen(shielded_section_path, "rb")};
        BOOST_REQUIRE(!infile.IsNull());
        BOOST_REQUIRE(chainman.LoadShieldedSnapshotSection(infile, header, tip));
        BOOST_REQUIRE(chainman.HasShieldedState());
        BOOST_CHECK_EQUAL(chainman.GetShieldedAccountRegistryEntryCount(), expected_registry_size);
        BOOST_CHECK_EQUAL(chainman.GetShieldedAccountRegistryRoot(), expected_registry_root);
        const auto state_commitment = chainman.GetShieldedStateCommitment();
        BOOST_REQUIRE(state_commitment.has_value());
        BOOST_CHECK_EQUAL(state_commitment->account_registry_root, expected_registry_root);
    }

    ChainstateManager& chainman_restarted = simulate_node_restart();

    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman_restarted.EnsureShieldedStateInitialized());
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedAccountRegistryEntryCount(),
                          expected_registry_size);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedAccountRegistryRoot(),
                          expected_registry_root);
        const auto state_commitment = chainman_restarted.GetShieldedStateCommitment();
        BOOST_REQUIRE(state_commitment.has_value());
        BOOST_CHECK_EQUAL(state_commitment->account_registry_root, expected_registry_root);
    }
}

BOOST_FIXTURE_TEST_CASE(
    chainstatemanager_rebuilds_non_chain_equivalent_snapshot_account_registry_state_on_restart,
    PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const fs::path shielded_section_path =
        m_args.GetDataDirNet() / "shielded_section_non_chain_registry.dat";
    auto simulate_node_restart = [&]() -> ChainstateManager& {
        ChainstateManager& current_chainman = *Assert(m_node.chainman);

        for (Chainstate* cs : current_chainman.GetAll()) {
            LOCK(::cs_main);
            cs->ForceFlushStateToDisk();
        }
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        {
            LOCK(::cs_main);
            current_chainman.ResetChainstates();
            BOOST_CHECK_EQUAL(current_chainman.GetAll().size(), 0);
            m_node.notifications = std::make_unique<KernelNotifications>(
                Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
            const ChainstateManager::Options chainman_opts{
                .chainparams = ::Params(),
                .datadir = current_chainman.m_options.datadir,
                .notifications = *m_node.notifications,
                .signals = m_node.validation_signals.get(),
            };
            const BlockManager::Options blockman_opts{
                .chainparams = chainman_opts.chainparams,
                .blocks_dir = m_args.GetBlocksDirPath(),
                .notifications = chainman_opts.notifications,
                .block_tree_db_params = DBParams{
                    .path = current_chainman.m_options.datadir / "blocks" / "index",
                    .cache_bytes = m_kernel_cache_sizes.block_tree_db,
                    .memory_only = m_block_tree_db_in_memory,
                },
            };
            m_node.chainman.reset();
            m_node.chainman = std::make_unique<ChainstateManager>(
                *Assert(m_node.shutdown_signal), chainman_opts, blockman_opts);
        }
        return *Assert(m_node.chainman);
    };

    shielded::registry::ShieldedAccountRegistryState synthetic_registry;
    const auto account_a =
        test::shielded::MakeDeterministicCompactPublicAccount(/*seed=*/0x41, /*value=*/5100);
    const auto account_b =
        test::shielded::MakeDeterministicCompactPublicAccount(/*seed=*/0x42, /*value=*/5200);
    const auto account_c =
        test::shielded::MakeDeterministicCompactPublicAccount(/*seed=*/0x43, /*value=*/5300);
    const std::vector<shielded::registry::ShieldedAccountLeaf> account_leaves{
        *test::shielded::BuildDirectAccountLeaf(smile2::ComputeCompactPublicAccountHash(account_a),
                                                account_a),
        *test::shielded::BuildDirectAccountLeaf(smile2::ComputeCompactPublicAccountHash(account_b),
                                                account_b),
        *test::shielded::BuildDirectAccountLeaf(smile2::ComputeCompactPublicAccountHash(account_c),
                                                account_c),
    };
    BOOST_REQUIRE(synthetic_registry.Append(
        Span<const shielded::registry::ShieldedAccountLeaf>{account_leaves.data(), account_leaves.size()}));
    const auto snapshot = synthetic_registry.ExportSnapshot();
    BOOST_REQUIRE(snapshot.IsValid());

    {
        AutoFile outfile{fsbridge::fopen(shielded_section_path, "wb")};
        BOOST_REQUIRE(!outfile.IsNull());
        for (const auto& entry : snapshot.entries) {
            outfile << entry;
        }
        BOOST_REQUIRE_EQUAL(outfile.fclose(), 0);
    }

    node::ShieldedSnapshotSectionHeader header;
    header.m_snapshot_version = node::SnapshotMetadata::CURRENT_VERSION;
    header.m_account_registry_entry_count = snapshot.entries.size();

    {
        LOCK(::cs_main);
        const CBlockIndex* const tip = chainman.ActiveTip();
        BOOST_REQUIRE(tip != nullptr);

        AutoFile infile{fsbridge::fopen(shielded_section_path, "rb")};
        BOOST_REQUIRE(!infile.IsNull());
        BOOST_REQUIRE(chainman.LoadShieldedSnapshotSection(infile, header, tip));
        BOOST_REQUIRE(chainman.HasShieldedState());
        BOOST_CHECK_EQUAL(chainman.GetShieldedAccountRegistryEntryCount(), snapshot.entries.size());
        BOOST_CHECK_EQUAL(chainman.GetShieldedAccountRegistryRoot(), synthetic_registry.Root());
    }

    ChainstateManager& chainman_restarted = simulate_node_restart();

    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman_restarted.EnsureShieldedStateInitialized());
        shielded::registry::ShieldedAccountRegistryState expected_registry;
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedAccountRegistryEntryCount(), 0U);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedAccountRegistryRoot(),
                          expected_registry.Root());
        const auto state_commitment = chainman_restarted.GetShieldedStateCommitment();
        BOOST_REQUIRE(state_commitment.has_value());
        BOOST_CHECK_EQUAL(state_commitment->account_registry_root, expected_registry.Root());
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_retains_commitment_index_when_configured, PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const auto rebalance_fixture = BuildChainstateRebalanceFixture(*this, chainman);
    const fs::path commitment_index_db_path = m_args.GetDataDirNet() / "shielded_state" / "commitments";
    auto simulate_node_restart = [&](bool retain_commitment_index) -> ChainstateManager& {
        ChainstateManager& current_chainman = *Assert(m_node.chainman);

        for (Chainstate* cs : current_chainman.GetAll()) {
            LOCK(::cs_main);
            cs->ForceFlushStateToDisk();
        }
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        {
            LOCK(::cs_main);
            current_chainman.ResetChainstates();
            BOOST_CHECK_EQUAL(current_chainman.GetAll().size(), 0);
            m_node.notifications = std::make_unique<KernelNotifications>(
                Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
            const ChainstateManager::Options chainman_opts{
                .chainparams = ::Params(),
                .datadir = current_chainman.m_options.datadir,
                .retain_shielded_commitment_index = retain_commitment_index,
                .notifications = *m_node.notifications,
                .signals = m_node.validation_signals.get(),
            };
            const BlockManager::Options blockman_opts{
                .chainparams = chainman_opts.chainparams,
                .blocks_dir = m_args.GetBlocksDirPath(),
                .notifications = chainman_opts.notifications,
                .block_tree_db_params = DBParams{
                    .path = current_chainman.m_options.datadir / "blocks" / "index",
                    .cache_bytes = m_kernel_cache_sizes.block_tree_db,
                    .memory_only = m_block_tree_db_in_memory,
                },
            };
            m_node.chainman.reset();
            m_node.chainman = std::make_unique<ChainstateManager>(
                *Assert(m_node.shutdown_signal), chainman_opts, blockman_opts);
        }
        return *Assert(m_node.chainman);
    };

    {
        const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
        CreateAndProcessBlock({rebalance_fixture.tx}, script_pub_key);
    }

    ChainstateManager& chainman_restarted = simulate_node_restart(/*retain_commitment_index=*/true);

    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman_restarted.EnsureShieldedStateInitialized());
        BOOST_CHECK(chainman_restarted.RetainShieldedCommitmentIndex());
        BOOST_CHECK(fs::exists(commitment_index_db_path));
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedMerkleTree().Size(), rebalance_fixture.reserve_outputs.size());
        BOOST_CHECK(chainman_restarted.GetShieldedMerkleTree().HasCommitmentIndex());
        const auto restored_commitment = chainman_restarted.GetShieldedMerkleTree().CommitmentAt(0);
        BOOST_REQUIRE(restored_commitment.has_value());
        BOOST_CHECK_EQUAL(*restored_commitment, rebalance_fixture.reserve_outputs.front().note_commitment);
        BOOST_CHECK(chainman_restarted.IsShieldedNettingManifestValid(rebalance_fixture.manifest_id));
    }

    ChainstateManager& chainman_restarted_twice = simulate_node_restart(/*retain_commitment_index=*/true);
    BOOST_CHECK(fs::exists(commitment_index_db_path));

    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman_restarted_twice.EnsureShieldedStateInitialized());
        BOOST_CHECK(chainman_restarted_twice.RetainShieldedCommitmentIndex());
        BOOST_CHECK(fs::exists(commitment_index_db_path));
        BOOST_CHECK_EQUAL(chainman_restarted_twice.GetShieldedMerkleTree().Size(), rebalance_fixture.reserve_outputs.size());
        BOOST_CHECK(chainman_restarted_twice.GetShieldedMerkleTree().HasCommitmentIndex());
        const auto restored_commitment = chainman_restarted_twice.GetShieldedMerkleTree().CommitmentAt(0);
        BOOST_REQUIRE(restored_commitment.has_value());
        BOOST_CHECK_EQUAL(*restored_commitment, rebalance_fixture.reserve_outputs.front().note_commitment);
        BOOST_CHECK(chainman_restarted_twice.IsShieldedNettingManifestValid(rebalance_fixture.manifest_id));
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_reloads_persisted_netting_manifest_state, PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const auto rebalance_fixture = BuildChainstateRebalanceFixture(*this, chainman);
    auto simulate_node_restart = [&]() -> ChainstateManager& {
        ChainstateManager& current_chainman = *Assert(m_node.chainman);

        for (Chainstate* cs : current_chainman.GetAll()) {
            LOCK(::cs_main);
            cs->ForceFlushStateToDisk();
        }
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        {
            LOCK(::cs_main);
            current_chainman.ResetChainstates();
            BOOST_CHECK_EQUAL(current_chainman.GetAll().size(), 0);
            m_node.notifications = std::make_unique<KernelNotifications>(
                Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
            const ChainstateManager::Options chainman_opts{
                .chainparams = ::Params(),
                .datadir = current_chainman.m_options.datadir,
                .notifications = *m_node.notifications,
                .signals = m_node.validation_signals.get(),
            };
            const BlockManager::Options blockman_opts{
                .chainparams = chainman_opts.chainparams,
                .blocks_dir = m_args.GetBlocksDirPath(),
                .notifications = chainman_opts.notifications,
                .block_tree_db_params = DBParams{
                    .path = current_chainman.m_options.datadir / "blocks" / "index",
                    .cache_bytes = m_kernel_cache_sizes.block_tree_db,
                    .memory_only = m_block_tree_db_in_memory,
                },
            };
            m_node.chainman.reset();
            m_node.chainman = std::make_unique<ChainstateManager>(
                *Assert(m_node.shutdown_signal), chainman_opts, blockman_opts);
        }
        return *Assert(m_node.chainman);
    };

    {
        const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
        CreateAndProcessBlock({rebalance_fixture.tx}, script_pub_key);
    }

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        BOOST_CHECK_EQUAL(chainman.GetShieldedMerkleTree().Size(), rebalance_fixture.reserve_outputs.size());
        BOOST_CHECK(chainman.GetShieldedMerkleTree().HasCommitmentIndex());
        const auto restored_commitment = chainman.GetShieldedMerkleTree().CommitmentAt(0);
        BOOST_REQUIRE(restored_commitment.has_value());
        BOOST_CHECK_EQUAL(*restored_commitment, rebalance_fixture.reserve_outputs.front().note_commitment);
        BOOST_CHECK(chainman.IsShieldedNettingManifestValid(rebalance_fixture.manifest_id));
        const auto manifest_state = chainman.GetShieldedNettingManifestState(rebalance_fixture.manifest_id);
        BOOST_REQUIRE(manifest_state.has_value());
        BOOST_CHECK_EQUAL(manifest_state->created_height, chainman.ActiveTip()->nHeight);
        BOOST_CHECK_EQUAL(manifest_state->settlement_window, rebalance_fixture.manifest.settlement_window);
    }

    ChainstateManager& chainman_restarted = simulate_node_restart();
    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman_restarted.EnsureShieldedStateInitialized());
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedMerkleTree().Size(), rebalance_fixture.reserve_outputs.size());
        BOOST_CHECK(chainman_restarted.GetShieldedMerkleTree().HasCommitmentIndex());
        const auto restored_commitment = chainman_restarted.GetShieldedMerkleTree().CommitmentAt(0);
        BOOST_REQUIRE(restored_commitment.has_value());
        BOOST_CHECK_EQUAL(*restored_commitment, rebalance_fixture.reserve_outputs.front().note_commitment);
        BOOST_CHECK(chainman_restarted.IsShieldedNettingManifestValid(rebalance_fixture.manifest_id));
        const auto manifest_state =
            chainman_restarted.GetShieldedNettingManifestState(rebalance_fixture.manifest_id);
        BOOST_REQUIRE(manifest_state.has_value());
        BOOST_CHECK_EQUAL(manifest_state->created_height, chainman_restarted.ActiveTip()->nHeight);
        BOOST_CHECK_EQUAL(manifest_state->settlement_window, rebalance_fixture.manifest.settlement_window);
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_reloads_persisted_account_registry_state, PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const auto rebalance_fixture = BuildChainstateRebalanceFixture(*this, chainman);
    const fs::path datadir = chainman.m_options.datadir;
    auto simulate_node_restart = [&]() -> ChainstateManager& {
        ChainstateManager& current_chainman = *Assert(m_node.chainman);

        for (Chainstate* cs : current_chainman.GetAll()) {
            LOCK(::cs_main);
            cs->ForceFlushStateToDisk();
        }
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        {
            LOCK(::cs_main);
            current_chainman.ResetChainstates();
            BOOST_CHECK_EQUAL(current_chainman.GetAll().size(), 0);
            m_node.notifications = std::make_unique<KernelNotifications>(
                Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
            const ChainstateManager::Options chainman_opts{
                .chainparams = ::Params(),
                .datadir = current_chainman.m_options.datadir,
                .notifications = *m_node.notifications,
                .signals = m_node.validation_signals.get(),
            };
            const BlockManager::Options blockman_opts{
                .chainparams = chainman_opts.chainparams,
                .blocks_dir = m_args.GetBlocksDirPath(),
                .notifications = chainman_opts.notifications,
                .block_tree_db_params = DBParams{
                    .path = current_chainman.m_options.datadir / "blocks" / "index",
                    .cache_bytes = m_kernel_cache_sizes.block_tree_db,
                    .memory_only = m_block_tree_db_in_memory,
                },
            };
            m_node.chainman.reset();
            m_node.chainman = std::make_unique<ChainstateManager>(
                *Assert(m_node.shutdown_signal), chainman_opts, blockman_opts);
        }
        return *Assert(m_node.chainman);
    };

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({rebalance_fixture.tx}, script_pub_key);

    uint256 expected_registry_root;
    uint64_t expected_registry_size{0};
    uint256 expected_state_commitment_hash;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        expected_registry_size = chainman.GetShieldedAccountRegistryEntryCount();
        expected_registry_root = chainman.GetShieldedAccountRegistryRoot();
        BOOST_CHECK_EQUAL(expected_registry_size, rebalance_fixture.reserve_outputs.size());
        const auto state_commitment = chainman.GetShieldedStateCommitment();
        BOOST_REQUIRE(state_commitment.has_value());
        expected_state_commitment_hash =
            shielded::registry::ComputeShieldedStateCommitmentHash(*state_commitment);
    }

    ChainstateManager& chainman_restarted = simulate_node_restart();

    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman_restarted.EnsureShieldedStateInitialized());
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedAccountRegistryEntryCount(),
                          expected_registry_size);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedAccountRegistryRoot(), expected_registry_root);
        const auto state_commitment = chainman_restarted.GetShieldedStateCommitment();
        BOOST_REQUIRE(state_commitment.has_value());
        BOOST_CHECK_EQUAL(shielded::registry::ComputeShieldedStateCommitmentHash(*state_commitment),
                          expected_state_commitment_hash);
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_rebuilds_anchor_history_when_commitment_index_is_restored,
                        PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const auto rebalance_fixture = BuildChainstateRebalanceFixture(*this, chainman);
    auto simulate_node_restart = [&]() -> ChainstateManager& {
        ChainstateManager& current_chainman = *Assert(m_node.chainman);

        for (Chainstate* cs : current_chainman.GetAll()) {
            LOCK(::cs_main);
            cs->ForceFlushStateToDisk();
        }
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        {
            LOCK(::cs_main);
            current_chainman.ResetChainstates();
            BOOST_CHECK_EQUAL(current_chainman.GetAll().size(), 0);
            m_node.notifications = std::make_unique<KernelNotifications>(
                Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
            const ChainstateManager::Options chainman_opts{
                .chainparams = ::Params(),
                .datadir = current_chainman.m_options.datadir,
                .notifications = *m_node.notifications,
                .signals = m_node.validation_signals.get(),
            };
            const BlockManager::Options blockman_opts{
                .chainparams = chainman_opts.chainparams,
                .blocks_dir = m_args.GetBlocksDirPath(),
                .notifications = chainman_opts.notifications,
                .block_tree_db_params = DBParams{
                    .path = current_chainman.m_options.datadir / "blocks" / "index",
                    .cache_bytes = m_kernel_cache_sizes.block_tree_db,
                    .memory_only = m_block_tree_db_in_memory,
                },
            };
            m_node.chainman.reset();
            m_node.chainman = std::make_unique<ChainstateManager>(
                *Assert(m_node.shutdown_signal), chainman_opts, blockman_opts);
        }
        return *Assert(m_node.chainman);
    };

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({rebalance_fixture.tx}, script_pub_key);

    uint256 expected_current_root;
    uint256 expected_previous_root;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());

        shielded::ShieldedMerkleTree persisted_tree;
        std::vector<uint256> persisted_anchor_roots;
        uint256 persisted_tip_hash;
        int32_t persisted_tip_height{-1};
        CAmount persisted_pool_balance{0};
        std::optional<uint256> persisted_commitment_index_digest;
        std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
            persisted_account_registry_snapshot;
        BOOST_REQUIRE(chainman.ReadPersistedShieldedState(persisted_tree,
                                                          persisted_anchor_roots,
                                                          persisted_tip_hash,
                                                          persisted_tip_height,
                                                          persisted_pool_balance,
                                                          persisted_commitment_index_digest,
                                                          persisted_account_registry_snapshot));
        BOOST_REQUIRE_GE(persisted_anchor_roots.size(), 2U);
        expected_current_root = persisted_tree.Root();
        BOOST_REQUIRE(!expected_current_root.IsNull());
        const auto previous_root_it = std::find_if(
            persisted_anchor_roots.begin(),
            persisted_anchor_roots.end(),
            [&](const uint256& candidate) { return candidate != expected_current_root; });
        BOOST_REQUIRE(previous_root_it != persisted_anchor_roots.end());
        expected_previous_root = *previous_root_it;
        BOOST_CHECK(chainman.IsShieldedAnchorValid(expected_current_root));
        BOOST_CHECK(chainman.IsShieldedAnchorValid(expected_previous_root));

        const std::vector<uint256> stale_anchor_roots{expected_current_root};
        BOOST_REQUIRE(chainman.WritePersistedShieldedState(persisted_tree,
                                                           stale_anchor_roots,
                                                           persisted_tip_hash,
                                                           persisted_tip_height,
                                                           persisted_pool_balance,
                                                           persisted_commitment_index_digest,
                                                           persisted_account_registry_snapshot));
    }

    ChainstateManager& chainman_restarted = simulate_node_restart();

    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman_restarted.EnsureShieldedStateInitialized());
        BOOST_CHECK(chainman_restarted.GetShieldedMerkleTree().HasCommitmentIndex());
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedMerkleTree().Root(), expected_current_root);
        BOOST_CHECK(chainman_restarted.IsShieldedAnchorValid(expected_current_root));
        BOOST_CHECK(chainman_restarted.IsShieldedAnchorValid(expected_previous_root));

        shielded::ShieldedMerkleTree restored_tree;
        std::vector<uint256> restored_anchor_roots;
        uint256 restored_tip_hash;
        int32_t restored_tip_height{-1};
        CAmount restored_pool_balance{0};
        std::optional<uint256> restored_commitment_index_digest;
        std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
            restored_account_registry_snapshot;
        BOOST_REQUIRE(chainman_restarted.ReadPersistedShieldedState(
            restored_tree,
            restored_anchor_roots,
            restored_tip_hash,
            restored_tip_height,
            restored_pool_balance,
            restored_commitment_index_digest,
            restored_account_registry_snapshot));
        BOOST_CHECK_EQUAL(restored_tree.Root(), expected_current_root);
        BOOST_REQUIRE_GE(restored_anchor_roots.size(), 2U);
        BOOST_CHECK_EQUAL(restored_anchor_roots[0], expected_current_root);
        BOOST_CHECK_EQUAL(restored_anchor_roots[1], expected_previous_root);
        const auto restored_commitment = chainman_restarted.GetShieldedMerkleTree().CommitmentAt(0);
        BOOST_REQUIRE(restored_commitment.has_value());
        BOOST_CHECK_EQUAL(*restored_commitment, rebalance_fixture.reserve_outputs.front().note_commitment);
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_repairs_in_memory_anchor_history_from_active_chain,
                        PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const auto rebalance_fixture = BuildChainstateRebalanceFixture(*this, chainman);

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({rebalance_fixture.tx}, script_pub_key);

    uint256 expected_current_root;
    uint256 expected_previous_root;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());

        shielded::ShieldedMerkleTree persisted_tree;
        std::vector<uint256> persisted_anchor_roots;
        uint256 persisted_tip_hash;
        int32_t persisted_tip_height{-1};
        CAmount persisted_pool_balance{0};
        std::optional<uint256> persisted_commitment_index_digest;
        std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
            persisted_account_registry_snapshot;
        BOOST_REQUIRE(chainman.ReadPersistedShieldedState(persisted_tree,
                                                          persisted_anchor_roots,
                                                          persisted_tip_hash,
                                                          persisted_tip_height,
                                                          persisted_pool_balance,
                                                          persisted_commitment_index_digest,
                                                          persisted_account_registry_snapshot));
        BOOST_REQUIRE_GE(persisted_anchor_roots.size(), 2U);
        expected_current_root = persisted_tree.Root();
        BOOST_REQUIRE(!expected_current_root.IsNull());
        const auto previous_root_it = std::find_if(
            persisted_anchor_roots.begin(),
            persisted_anchor_roots.end(),
            [&](const uint256& candidate) { return candidate != expected_current_root; });
        BOOST_REQUIRE(previous_root_it != persisted_anchor_roots.end());
        expected_previous_root = *previous_root_it;

        chainman.SetShieldedAnchorRootsForTest({expected_current_root});
        BOOST_CHECK(!chainman.IsShieldedAnchorValid(expected_previous_root));

        BOOST_REQUIRE(chainman.RepairShieldedAnchorHistoryFromActiveChain());
        BOOST_CHECK(chainman.IsShieldedAnchorValid(expected_current_root));
        BOOST_CHECK(chainman.IsShieldedAnchorValid(expected_previous_root));

        std::vector<uint256> repaired_anchor_roots;
        BOOST_REQUIRE(chainman.ReadPersistedShieldedState(persisted_tree,
                                                          repaired_anchor_roots,
                                                          persisted_tip_hash,
                                                          persisted_tip_height,
                                                          persisted_pool_balance,
                                                          persisted_commitment_index_digest,
                                                          persisted_account_registry_snapshot));
        BOOST_REQUIRE_GE(repaired_anchor_roots.size(), 2U);
        BOOST_CHECK_EQUAL(repaired_anchor_roots[0], expected_current_root);
        BOOST_CHECK_EQUAL(repaired_anchor_roots[1], expected_previous_root);
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_limits_auto_repair_attempts_to_once_per_shielded_state_generation,
                        TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const auto rebalance_fixture = BuildChainstateRebalanceFixture(*this, chainman);

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        BOOST_CHECK(chainman.MarkShieldedAutoRepairAttempt(ShieldedAutoRepairKind::ANCHOR_HISTORY));
        BOOST_CHECK(!chainman.MarkShieldedAutoRepairAttempt(ShieldedAutoRepairKind::ANCHOR_HISTORY));
        BOOST_CHECK(chainman.MarkShieldedAutoRepairAttempt(ShieldedAutoRepairKind::STATE_REBUILD));
        BOOST_CHECK(!chainman.MarkShieldedAutoRepairAttempt(ShieldedAutoRepairKind::STATE_REBUILD));
        BOOST_CHECK_EQUAL(
            chainman.GetShieldedAutoRepairAttemptCountForTest(ShieldedAutoRepairKind::ANCHOR_HISTORY),
            1U);
        BOOST_CHECK_EQUAL(
            chainman.GetShieldedAutoRepairAttemptCountForTest(ShieldedAutoRepairKind::STATE_REBUILD),
            1U);
    }

    CreateAndProcessBlock({}, script_pub_key);

    {
        LOCK(::cs_main);
        BOOST_CHECK(!chainman.MarkShieldedAutoRepairAttempt(ShieldedAutoRepairKind::ANCHOR_HISTORY));
        BOOST_CHECK(!chainman.MarkShieldedAutoRepairAttempt(ShieldedAutoRepairKind::STATE_REBUILD));
        BOOST_CHECK_EQUAL(
            chainman.GetShieldedAutoRepairAttemptCountForTest(ShieldedAutoRepairKind::ANCHOR_HISTORY),
            1U);
        BOOST_CHECK_EQUAL(
            chainman.GetShieldedAutoRepairAttemptCountForTest(ShieldedAutoRepairKind::STATE_REBUILD),
            1U);
    }

    CreateAndProcessBlock({rebalance_fixture.tx}, script_pub_key);

    {
        LOCK(::cs_main);
        BOOST_CHECK(chainman.MarkShieldedAutoRepairAttempt(ShieldedAutoRepairKind::ANCHOR_HISTORY));
        BOOST_CHECK(chainman.MarkShieldedAutoRepairAttempt(ShieldedAutoRepairKind::STATE_REBUILD));
        BOOST_CHECK_EQUAL(
            chainman.GetShieldedAutoRepairAttemptCountForTest(ShieldedAutoRepairKind::ANCHOR_HISTORY),
            2U);
        BOOST_CHECK_EQUAL(
            chainman.GetShieldedAutoRepairAttemptCountForTest(ShieldedAutoRepairKind::STATE_REBUILD),
            2U);
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_auto_repairs_stale_anchor_history_for_mempool_accept,
                        TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const auto rebalance_fixture = BuildChainstateRebalanceFixture(*this, chainman);
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({rebalance_fixture.tx}, script_pub_key);

    uint256 current_root;
    uint256 previous_root;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        const auto& anchor_roots = chainman.GetShieldedAnchorRoots();
        BOOST_REQUIRE_GE(anchor_roots.size(), 2U);
        current_root = anchor_roots[0];
        previous_root = anchor_roots[1];
        BOOST_REQUIRE(!previous_root.IsNull());
        chainman.SetShieldedAnchorRootsForTest({current_root});
        BOOST_CHECK(!chainman.IsShieldedAnchorValid(previous_root));
    }

    const auto tx_ref = MakeTransactionRef(
        BuildLegacyShieldOnlyTx(*this, m_coinbase_txns[1], previous_root));
    const auto result = WITH_LOCK(
        ::cs_main,
        return AcceptToMemoryPool(
            chainman.ActiveChainstate(), tx_ref, GetTime(), /*bypass_limits=*/true, /*test_accept=*/true));
    BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::VALID);

    {
        LOCK(::cs_main);
        BOOST_CHECK(chainman.IsShieldedAnchorValid(previous_root));
        BOOST_CHECK_EQUAL(
            chainman.GetShieldedAutoRepairAttemptCountForTest(ShieldedAutoRepairKind::ANCHOR_HISTORY),
            1U);
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_auto_repairs_stale_anchor_history_for_block_connect,
                        TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const auto rebalance_fixture = BuildChainstateRebalanceFixture(*this, chainman);
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({rebalance_fixture.tx}, script_pub_key);

    uint256 current_root;
    uint256 previous_root;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        const auto& anchor_roots = chainman.GetShieldedAnchorRoots();
        BOOST_REQUIRE_GE(anchor_roots.size(), 2U);
        current_root = anchor_roots[0];
        previous_root = anchor_roots[1];
        BOOST_REQUIRE(!previous_root.IsNull());
        chainman.SetShieldedAnchorRootsForTest({current_root});
        BOOST_CHECK(!chainman.IsShieldedAnchorValid(previous_root));
    }

    const CMutableTransaction shield_only_tx =
        BuildLegacyShieldOnlyTx(*this, m_coinbase_txns[1], previous_root);
    const CBlock accepted_block = CreateAndProcessBlock({shield_only_tx}, script_pub_key);

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.ActiveTip() != nullptr);
        BOOST_CHECK_EQUAL(chainman.ActiveTip()->GetBlockHash(), accepted_block.GetHash());
        BOOST_CHECK(chainman.IsShieldedAnchorValid(previous_root));
        BOOST_CHECK_EQUAL(
            chainman.GetShieldedAutoRepairAttemptCountForTest(ShieldedAutoRepairKind::ANCHOR_HISTORY),
            1U);
    }
}

BOOST_FIXTURE_TEST_CASE(
    chainstatemanager_startup_repairs_stale_anchor_history_and_auto_reconsiders_failed_shielded_block,
    PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const auto rebalance_fixture = BuildChainstateRebalanceFixture(*this, chainman);
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({rebalance_fixture.tx}, script_pub_key);

    uint256 previous_root;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        const auto& anchor_roots = chainman.GetShieldedAnchorRoots();
        BOOST_REQUIRE_GE(anchor_roots.size(), 2U);
        previous_root = anchor_roots[1];
        BOOST_REQUIRE(!previous_root.IsNull());
    }

    const CMutableTransaction shield_only_tx =
        BuildLegacyShieldOnlyTx(*this, m_coinbase_txns[1], previous_root);
    const CBlock invalid_block =
        CreateBlock({shield_only_tx}, script_pub_key, chainman.ActiveChainstate(), /*use_mempool=*/false);
    const uint256 invalid_hash = invalid_block.GetHash();
    CBlockIndex* accepted_index{nullptr};

    {
        LOCK(::cs_main);
        BlockValidationState accept_state;
        bool new_block{false};
        BOOST_REQUIRE(chainman.AcceptBlock(std::make_shared<const CBlock>(invalid_block),
                                           accept_state,
                                           &accepted_index,
                                           /*fRequested=*/true,
                                           /*dbp=*/nullptr,
                                           &new_block,
                                           /*min_pow_checked=*/true));
        BOOST_REQUIRE(new_block);
        BOOST_REQUIRE(accept_state.IsValid());
        BOOST_REQUIRE(accepted_index != nullptr);
        BOOST_REQUIRE(chainman.ActiveTip() != nullptr);
        BOOST_CHECK_NE(chainman.ActiveTip()->GetBlockHash(), invalid_hash);

        shielded::ShieldedMerkleTree persisted_tree;
        std::vector<uint256> persisted_anchor_roots;
        uint256 persisted_tip_hash;
        int32_t persisted_tip_height{-1};
        CAmount persisted_pool_balance{0};
        std::optional<uint256> persisted_commitment_index_digest;
        std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
            persisted_account_registry_snapshot;
        BOOST_REQUIRE(chainman.ReadPersistedShieldedState(persisted_tree,
                                                          persisted_anchor_roots,
                                                          persisted_tip_hash,
                                                          persisted_tip_height,
                                                          persisted_pool_balance,
                                                          persisted_commitment_index_digest,
                                                          persisted_account_registry_snapshot));
        BOOST_REQUIRE_GE(persisted_anchor_roots.size(), 2U);
        persisted_anchor_roots.resize(1);
        BOOST_REQUIRE(chainman.WritePersistedShieldedState(
            persisted_tree,
            persisted_anchor_roots,
            persisted_tip_hash,
            persisted_tip_height,
            persisted_pool_balance,
            persisted_commitment_index_digest,
            persisted_account_registry_snapshot));
    }

    BlockValidationState invalidate_state;
    BOOST_REQUIRE(chainman.ActiveChainstate().InvalidateBlock(invalidate_state, accepted_index));
    BOOST_REQUIRE(invalidate_state.IsValid());

    {
        LOCK(::cs_main);
        CBlockIndex* invalid_index = chainman.m_blockman.LookupBlockIndex(invalid_hash);
        BOOST_REQUIRE(invalid_index != nullptr);
        BOOST_CHECK(invalid_index->nStatus & BLOCK_FAILED_VALID);
        BOOST_REQUIRE(chainman.ActiveTip() != nullptr);
        BOOST_CHECK_NE(chainman.ActiveTip()->GetBlockHash(), invalid_hash);
    }

    auto restart_node = [&]() -> ChainstateManager& {
        ChainstateManager& current_chainman = *Assert(m_node.chainman);

        for (Chainstate* cs : current_chainman.GetAll()) {
            LOCK(::cs_main);
            cs->ForceFlushStateToDisk();
        }
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        {
            LOCK(::cs_main);
            current_chainman.ResetChainstates();
            BOOST_CHECK_EQUAL(current_chainman.GetAll().size(), 0);
            m_node.notifications = std::make_unique<KernelNotifications>(
                Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
            const ChainstateManager::Options chainman_opts{
                .chainparams = ::Params(),
                .datadir = current_chainman.m_options.datadir,
                .notifications = *m_node.notifications,
                .signals = m_node.validation_signals.get(),
            };
            const BlockManager::Options blockman_opts{
                .chainparams = chainman_opts.chainparams,
                .blocks_dir = m_args.GetBlocksDirPath(),
                .notifications = chainman_opts.notifications,
                .block_tree_db_params = DBParams{
                    .path = current_chainman.m_options.datadir / "blocks" / "index",
                    .cache_bytes = m_kernel_cache_sizes.block_tree_db,
                    .memory_only = m_block_tree_db_in_memory,
                },
            };
            m_node.chainman.reset();
            m_node.chainman = std::make_unique<ChainstateManager>(
                *Assert(m_node.shutdown_signal), chainman_opts, blockman_opts);
        }
        return *Assert(m_node.chainman);
    };

    ChainstateManager& chainman_restarted = restart_node();
    node::ChainstateLoadOptions options;
    options.mempool = Assert(m_node.mempool.get());
    options.coins_db_in_memory = m_coins_db_in_memory;
    options.wipe_chainstate_db = false;
    options.prune = chainman_restarted.m_blockman.IsPruneMode();
    options.check_blocks = m_args.GetIntArg("-checkblocks", DEFAULT_CHECKBLOCKS);
    options.check_level = m_args.GetIntArg("-checklevel", DEFAULT_CHECKLEVEL);
    options.require_full_verification =
        m_args.IsArgSet("-checkblocks") || m_args.IsArgSet("-checklevel");
    const auto load_result = node::LoadChainstate(chainman_restarted, m_kernel_cache_sizes, options);
    BOOST_REQUIRE(std::get<0>(load_result) == node::ChainstateLoadStatus::SUCCESS);
    const auto verify_result = node::VerifyLoadedChainstate(chainman_restarted, options);
    BOOST_REQUIRE(std::get<0>(verify_result) == node::ChainstateLoadStatus::SUCCESS);

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman_restarted.EnsureShieldedStateInitialized());
        BOOST_CHECK(chainman_restarted.IsShieldedAnchorValid(previous_root));
        CBlockIndex* reconsidered_index = chainman_restarted.m_blockman.LookupBlockIndex(invalid_hash);
        BOOST_REQUIRE(reconsidered_index != nullptr);
        BOOST_CHECK_EQUAL(reconsidered_index->nStatus & BLOCK_FAILED_MASK, 0U);
    }

    BlockValidationState state;
    BOOST_REQUIRE(chainman_restarted.ActiveChainstate().ActivateBestChain(state));
    BOOST_CHECK(state.IsValid());

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman_restarted.ActiveTip() != nullptr);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveTip()->GetBlockHash(), invalid_hash);
        CBlockIndex* reconsidered_index = chainman_restarted.m_blockman.LookupBlockIndex(invalid_hash);
        BOOST_REQUIRE(reconsidered_index != nullptr);
        BOOST_CHECK_EQUAL(reconsidered_index->nStatus & BLOCK_FAILED_MASK, 0U);
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_rebuilds_truncated_persisted_account_registry_snapshot,
                        PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const auto rebalance_fixture = BuildChainstateRebalanceFixture(*this, chainman);

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({rebalance_fixture.tx}, script_pub_key);

    uint256 expected_registry_root;
    uint64_t expected_registry_size{0};
    uint256 expected_state_commitment_hash;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        expected_registry_size = chainman.GetShieldedAccountRegistryEntryCount();
        expected_registry_root = chainman.GetShieldedAccountRegistryRoot();
        BOOST_CHECK_EQUAL(expected_registry_size, rebalance_fixture.reserve_outputs.size());
        const auto state_commitment = chainman.GetShieldedStateCommitment();
        BOOST_REQUIRE(state_commitment.has_value());
        expected_state_commitment_hash =
            shielded::registry::ComputeShieldedStateCommitmentHash(*state_commitment);
    }

    {
        LOCK(::cs_main);
        shielded::ShieldedMerkleTree persisted_tree;
        std::vector<uint256> persisted_anchor_roots;
        uint256 persisted_tip_hash;
        int32_t persisted_tip_height{-1};
        CAmount persisted_pool_balance{0};
        std::optional<uint256> persisted_commitment_index_digest;
        std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
            persisted_account_registry_snapshot;
        BOOST_REQUIRE(chainman.ReadPersistedShieldedState(persisted_tree,
                                                          persisted_anchor_roots,
                                                          persisted_tip_hash,
                                                          persisted_tip_height,
                                                          persisted_pool_balance,
                                                          persisted_commitment_index_digest,
                                                          persisted_account_registry_snapshot));
        BOOST_REQUIRE(persisted_account_registry_snapshot.has_value());
        BOOST_REQUIRE_GT(persisted_account_registry_snapshot->entries.size(), 0U);
        persisted_account_registry_snapshot->entries.pop_back();
        BOOST_REQUIRE(persisted_account_registry_snapshot->IsValid());
        BOOST_REQUIRE(chainman.WritePersistedShieldedState(persisted_tree,
                                                           persisted_anchor_roots,
                                                           persisted_tip_hash,
                                                           persisted_tip_height,
                                                           persisted_pool_balance,
                                                           persisted_commitment_index_digest,
                                                           persisted_account_registry_snapshot));
    }

    const fs::path datadir = chainman.m_options.datadir;
    for (Chainstate* cs : chainman.GetAll()) {
        LOCK(::cs_main);
        cs->ForceFlushStateToDisk();
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    {
        LOCK(::cs_main);
        chainman.ResetChainstates();
        BOOST_CHECK_EQUAL(chainman.GetAll().size(), 0);
        m_node.chainman.reset();
    }

    {
        LOCK(::cs_main);
        m_node.notifications = std::make_unique<KernelNotifications>(
            Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
        const ChainstateManager::Options chainman_opts{
            .chainparams = ::Params(),
            .datadir = datadir,
            .notifications = *m_node.notifications,
            .signals = m_node.validation_signals.get(),
        };
        const BlockManager::Options blockman_opts{
            .chainparams = chainman_opts.chainparams,
            .blocks_dir = m_args.GetBlocksDirPath(),
            .notifications = chainman_opts.notifications,
            .block_tree_db_params = DBParams{
                .path = datadir / "blocks" / "index",
                .cache_bytes = m_kernel_cache_sizes.block_tree_db,
                .memory_only = m_block_tree_db_in_memory,
            },
        };
        m_node.chainman = std::make_unique<ChainstateManager>(
            *Assert(m_node.shutdown_signal), chainman_opts, blockman_opts);
    }

    ChainstateManager& chainman_restarted = *Assert(m_node.chainman);
    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman_restarted.EnsureShieldedStateInitialized());
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedAccountRegistryEntryCount(),
                          expected_registry_size);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedAccountRegistryRoot(),
                          expected_registry_root);
        const auto state_commitment = chainman_restarted.GetShieldedStateCommitment();
        BOOST_REQUIRE(state_commitment.has_value());
        BOOST_CHECK_EQUAL(shielded::registry::ComputeShieldedStateCommitmentHash(*state_commitment),
                          expected_state_commitment_hash);
    }

    {
        LOCK(::cs_main);
        shielded::ShieldedMerkleTree persisted_tree;
        std::vector<uint256> persisted_anchor_roots;
        uint256 persisted_tip_hash;
        int32_t persisted_tip_height{-1};
        CAmount persisted_pool_balance{0};
        std::optional<uint256> persisted_commitment_index_digest;
        std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
            persisted_account_registry_snapshot;
        BOOST_REQUIRE(chainman_restarted.ReadPersistedShieldedState(persisted_tree,
                                                                    persisted_anchor_roots,
                                                                    persisted_tip_hash,
                                                                    persisted_tip_height,
                                                                    persisted_pool_balance,
                                                                    persisted_commitment_index_digest,
                                                                    persisted_account_registry_snapshot));
        BOOST_REQUIRE(persisted_account_registry_snapshot.has_value());
        const auto restored_registry =
            shielded::registry::ShieldedAccountRegistryState::RestorePersisted(
            *persisted_account_registry_snapshot);
        BOOST_REQUIRE(restored_registry.has_value());
        BOOST_CHECK_EQUAL(restored_registry->Size(), expected_registry_size);
        BOOST_CHECK_EQUAL(restored_registry->Root(), expected_registry_root);
    }
}

BOOST_FIXTURE_TEST_CASE(
    chainstatemanager_rebuilds_account_registry_when_payload_store_is_incomplete,
    PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const auto rebalance_fixture = BuildChainstateRebalanceFixture(*this, chainman);
    const fs::path datadir = chainman.m_options.datadir;
    auto shutdown_node = [&]() {
        ChainstateManager& current_chainman = *Assert(m_node.chainman);

        for (Chainstate* cs : current_chainman.GetAll()) {
            LOCK(::cs_main);
            cs->ForceFlushStateToDisk();
        }
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        {
            LOCK(::cs_main);
            current_chainman.ResetChainstates();
            BOOST_CHECK_EQUAL(current_chainman.GetAll().size(), 0);
            m_node.chainman.reset();
        }
    };
    auto restart_node = [&]() -> ChainstateManager& {
        {
            LOCK(::cs_main);
            m_node.notifications = std::make_unique<KernelNotifications>(
                Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
            const ChainstateManager::Options chainman_opts{
                .chainparams = ::Params(),
                .datadir = datadir,
                .notifications = *m_node.notifications,
                .signals = m_node.validation_signals.get(),
            };
            const BlockManager::Options blockman_opts{
                .chainparams = chainman_opts.chainparams,
                .blocks_dir = m_args.GetBlocksDirPath(),
                .notifications = chainman_opts.notifications,
                .block_tree_db_params = DBParams{
                    .path = datadir / "blocks" / "index",
                    .cache_bytes = m_kernel_cache_sizes.block_tree_db,
                    .memory_only = m_block_tree_db_in_memory,
                },
            };
            m_node.chainman = std::make_unique<ChainstateManager>(
                *Assert(m_node.shutdown_signal), chainman_opts, blockman_opts);
        }
        return *Assert(m_node.chainman);
    };

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({rebalance_fixture.tx}, script_pub_key);

    uint64_t expected_registry_size{0};
    uint256 expected_registry_root;
    std::optional<uint64_t> erased_leaf_index;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        expected_registry_size = chainman.GetShieldedAccountRegistryEntryCount();
        expected_registry_root = chainman.GetShieldedAccountRegistryRoot();
        BOOST_CHECK_EQUAL(expected_registry_size, rebalance_fixture.reserve_outputs.size());

        shielded::ShieldedMerkleTree persisted_tree;
        std::vector<uint256> persisted_anchor_roots;
        uint256 persisted_tip_hash;
        int32_t persisted_tip_height{-1};
        CAmount persisted_pool_balance{0};
        std::optional<uint256> persisted_commitment_index_digest;
        std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
            persisted_account_registry_snapshot;
        BOOST_REQUIRE(chainman.ReadPersistedShieldedState(persisted_tree,
                                                          persisted_anchor_roots,
                                                          persisted_tip_hash,
                                                          persisted_tip_height,
                                                          persisted_pool_balance,
                                                          persisted_commitment_index_digest,
                                                          persisted_account_registry_snapshot));
        BOOST_REQUIRE(persisted_account_registry_snapshot.has_value());
        BOOST_REQUIRE_GT(persisted_account_registry_snapshot->entries.size(), 0U);
        erased_leaf_index = persisted_account_registry_snapshot->entries.back().leaf_index;
        BOOST_CHECK_EQUAL(*erased_leaf_index, expected_registry_size - 1);
    }

    shutdown_node();

    const fs::path account_registry_db_path = datadir / "shielded_state" / "account_registry";
    {
        constexpr uint8_t DB_ACCOUNT_REGISTRY_PAYLOAD{static_cast<uint8_t>('P')};
        CDBWrapper db({.path = account_registry_db_path,
                       .cache_bytes = 1 << 20,
                       .memory_only = false,
                       .wipe_data = false,
                       .obfuscate = true});
        BOOST_REQUIRE(erased_leaf_index.has_value());
        BOOST_REQUIRE(db.Erase(std::make_pair(DB_ACCOUNT_REGISTRY_PAYLOAD, *erased_leaf_index)));
    }

    ChainstateManager& chainman_restarted = restart_node();
    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman_restarted.EnsureShieldedStateInitialized());
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedAccountRegistryEntryCount(),
                          expected_registry_size);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedAccountRegistryRoot(),
                          expected_registry_root);

        shielded::ShieldedMerkleTree persisted_tree;
        std::vector<uint256> persisted_anchor_roots;
        uint256 persisted_tip_hash;
        int32_t persisted_tip_height{-1};
        CAmount persisted_pool_balance{0};
        std::optional<uint256> persisted_commitment_index_digest;
        std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
            persisted_account_registry_snapshot;
        BOOST_REQUIRE(chainman_restarted.ReadPersistedShieldedState(persisted_tree,
                                                                    persisted_anchor_roots,
                                                                    persisted_tip_hash,
                                                                    persisted_tip_height,
                                                                    persisted_pool_balance,
                                                                    persisted_commitment_index_digest,
                                                                    persisted_account_registry_snapshot));
        BOOST_REQUIRE(persisted_account_registry_snapshot.has_value());
        BOOST_CHECK_EQUAL(persisted_account_registry_snapshot->entries.size(), expected_registry_size);
        BOOST_CHECK(chainman_restarted.GetShieldedAccountRegistry().CanMaterializeAllEntries());
        BOOST_REQUIRE(chainman_restarted.GetShieldedAccountRegistry().MaterializeEntry(
            expected_registry_size - 1).has_value());
    }
}

BOOST_FIXTURE_TEST_CASE(
    chainstatemanager_rebuilds_from_chain_when_persisted_account_registry_snapshot_semantically_drifts,
    PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const auto rebalance_fixture = BuildChainstateRebalanceFixture(*this, chainman);
    const fs::path datadir = chainman.m_options.datadir;
    auto shutdown_node = [&]() {
        ChainstateManager& current_chainman = *Assert(m_node.chainman);

        for (Chainstate* cs : current_chainman.GetAll()) {
            LOCK(::cs_main);
            cs->ForceFlushStateToDisk();
        }
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        {
            LOCK(::cs_main);
            current_chainman.ResetChainstates();
            BOOST_CHECK_EQUAL(current_chainman.GetAll().size(), 0);
            m_node.chainman.reset();
        }
    };
    auto restart_node = [&]() -> ChainstateManager& {
        {
            LOCK(::cs_main);
            m_node.notifications = std::make_unique<KernelNotifications>(
                Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
            const ChainstateManager::Options chainman_opts{
                .chainparams = ::Params(),
                .datadir = datadir,
                .notifications = *m_node.notifications,
                .signals = m_node.validation_signals.get(),
            };
            const BlockManager::Options blockman_opts{
                .chainparams = chainman_opts.chainparams,
                .blocks_dir = m_args.GetBlocksDirPath(),
                .notifications = chainman_opts.notifications,
                .block_tree_db_params = DBParams{
                    .path = datadir / "blocks" / "index",
                    .cache_bytes = m_kernel_cache_sizes.block_tree_db,
                    .memory_only = m_block_tree_db_in_memory,
                },
            };
            m_node.chainman = std::make_unique<ChainstateManager>(
                *Assert(m_node.shutdown_signal), chainman_opts, blockman_opts);
        }
        return *Assert(m_node.chainman);
    };

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({rebalance_fixture.tx}, script_pub_key);

    uint256 expected_registry_root;
    uint64_t expected_registry_size{0};
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        expected_registry_root = chainman.GetShieldedAccountRegistryRoot();
        expected_registry_size = chainman.GetShieldedAccountRegistryEntryCount();
        BOOST_REQUIRE_GT(expected_registry_size, 0U);

        shielded::ShieldedMerkleTree persisted_tree;
        std::vector<uint256> persisted_anchor_roots;
        uint256 persisted_tip_hash;
        int32_t persisted_tip_height{-1};
        CAmount persisted_pool_balance{0};
        std::optional<uint256> persisted_commitment_index_digest;
        std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
            persisted_account_registry_snapshot;
        BOOST_REQUIRE(chainman.ReadPersistedShieldedState(persisted_tree,
                                                          persisted_anchor_roots,
                                                          persisted_tip_hash,
                                                          persisted_tip_height,
                                                          persisted_pool_balance,
                                                          persisted_commitment_index_digest,
                                                          persisted_account_registry_snapshot));
        BOOST_REQUIRE(persisted_account_registry_snapshot.has_value());
        BOOST_REQUIRE_GT(persisted_account_registry_snapshot->entries.size(), 0U);

        uint256 tampered_account_leaf_commitment;
        uint256 tampered_entry_commitment;
        const auto& persisted_entries = persisted_account_registry_snapshot->entries;
        const auto& persisted_entry = persisted_entries.back();
        do {
            tampered_account_leaf_commitment = GetRandHash();
        } while (tampered_account_leaf_commitment.IsNull() ||
                 tampered_account_leaf_commitment ==
                     persisted_entry.account_leaf_commitment ||
                 std::any_of(persisted_entries.begin(),
                             persisted_entries.end() - 1,
                             [&](const auto& entry) {
                                 return entry.account_leaf_commitment ==
                                     tampered_account_leaf_commitment;
                             }));
        do {
            tampered_entry_commitment = GetRandHash();
        } while (tampered_entry_commitment.IsNull() ||
                 tampered_entry_commitment == persisted_entry.entry_commitment ||
                 std::any_of(persisted_entries.begin(),
                             persisted_entries.end() - 1,
                             [&](const auto& entry) {
                                 return entry.entry_commitment == tampered_entry_commitment;
                             }));

        persisted_account_registry_snapshot->entries.back().account_leaf_commitment =
            tampered_account_leaf_commitment;
        persisted_account_registry_snapshot->entries.back().entry_commitment =
            tampered_entry_commitment;
        BOOST_REQUIRE(persisted_account_registry_snapshot->IsValid());

        BOOST_REQUIRE(chainman.WritePersistedShieldedState(persisted_tree,
                                                           persisted_anchor_roots,
                                                           persisted_tip_hash,
                                                           persisted_tip_height,
                                                           persisted_pool_balance,
                                                           persisted_commitment_index_digest,
                                                           persisted_account_registry_snapshot));
    }

    shutdown_node();

    ChainstateManager& chainman_restarted = restart_node();
    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman_restarted.EnsureShieldedStateInitialized());
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedAccountRegistryRoot(),
                          expected_registry_root);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedAccountRegistryEntryCount(),
                          expected_registry_size);

        shielded::ShieldedMerkleTree persisted_tree;
        std::vector<uint256> persisted_anchor_roots;
        uint256 persisted_tip_hash;
        int32_t persisted_tip_height{-1};
        CAmount persisted_pool_balance{0};
        std::optional<uint256> persisted_commitment_index_digest;
        std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
            persisted_account_registry_snapshot;
        BOOST_REQUIRE(chainman_restarted.ReadPersistedShieldedState(persisted_tree,
                                                                    persisted_anchor_roots,
                                                                    persisted_tip_hash,
                                                                    persisted_tip_height,
                                                                    persisted_pool_balance,
                                                                    persisted_commitment_index_digest,
                                                                    persisted_account_registry_snapshot));
        BOOST_REQUIRE(persisted_account_registry_snapshot.has_value());
        const auto restored_registry =
            shielded::registry::ShieldedAccountRegistryState::RestorePersisted(
                *persisted_account_registry_snapshot);
        BOOST_REQUIRE(restored_registry.has_value());
        BOOST_CHECK_EQUAL(restored_registry->Root(), expected_registry_root);
        BOOST_CHECK_EQUAL(restored_registry->Size(), expected_registry_size);
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_prunes_disconnected_account_registry_payloads_on_restart,
                        PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const auto rebalance_fixture = BuildChainstateRebalanceFixture(*this, chainman);
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));

    CreateAndProcessBlock({rebalance_fixture.tx}, script_pub_key);

    shielded::registry::ShieldedAccountRegistryPersistedSnapshot full_registry_snapshot;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        BOOST_CHECK_GT(chainman.GetShieldedAccountRegistryEntryCount(), 0U);

        shielded::ShieldedMerkleTree persisted_tree;
        std::vector<uint256> persisted_anchor_roots;
        uint256 persisted_tip_hash;
        int32_t persisted_tip_height{-1};
        CAmount persisted_pool_balance{0};
        std::optional<uint256> persisted_commitment_index_digest;
        std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
            persisted_account_registry_snapshot;
        BOOST_REQUIRE(chainman.ReadPersistedShieldedState(persisted_tree,
                                                          persisted_anchor_roots,
                                                          persisted_tip_hash,
                                                          persisted_tip_height,
                                                          persisted_pool_balance,
                                                          persisted_commitment_index_digest,
                                                          persisted_account_registry_snapshot));
        BOOST_REQUIRE(persisted_account_registry_snapshot.has_value());
        full_registry_snapshot = *persisted_account_registry_snapshot;
        BOOST_REQUIRE_GT(full_registry_snapshot.entries.size(), 0U);
    }

    BlockValidationState invalidate_state;
    BOOST_REQUIRE(chainman.ActiveChainstate().InvalidateBlock(
        invalidate_state,
        WITH_LOCK(cs_main, return chainman.ActiveChain().Tip())));
    BOOST_CHECK(invalidate_state.IsValid());
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return chainman.GetShieldedAccountRegistryEntryCount()), 0U);

    const fs::path datadir = chainman.m_options.datadir;
    for (Chainstate* cs : chainman.GetAll()) {
        LOCK(::cs_main);
        cs->ForceFlushStateToDisk();
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    {
        LOCK(::cs_main);
        chainman.ResetChainstates();
        BOOST_CHECK_EQUAL(chainman.GetAll().size(), 0);
        m_node.chainman.reset();
    }

    {
        LOCK(::cs_main);
        m_node.notifications = std::make_unique<KernelNotifications>(
            Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
        const ChainstateManager::Options chainman_opts{
            .chainparams = ::Params(),
            .datadir = datadir,
            .notifications = *m_node.notifications,
            .signals = m_node.validation_signals.get(),
        };
        const BlockManager::Options blockman_opts{
            .chainparams = chainman_opts.chainparams,
            .blocks_dir = m_args.GetBlocksDirPath(),
            .notifications = chainman_opts.notifications,
            .block_tree_db_params = DBParams{
                .path = datadir / "blocks" / "index",
                .cache_bytes = m_kernel_cache_sizes.block_tree_db,
                .memory_only = m_block_tree_db_in_memory,
            },
        };
        m_node.chainman = std::make_unique<ChainstateManager>(
            *Assert(m_node.shutdown_signal), chainman_opts, blockman_opts);
    }

    ChainstateManager& chainman_restarted = *Assert(m_node.chainman);
    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman_restarted.EnsureShieldedStateInitialized());
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedAccountRegistryEntryCount(), 0U);
    }

    auto stale_restored =
        shielded::registry::ShieldedAccountRegistryState::RestorePersisted(full_registry_snapshot);
    BOOST_REQUIRE(stale_restored.has_value());
    BOOST_CHECK(!stale_restored->MaterializeEntry(
        full_registry_snapshot.entries.back().leaf_index).has_value());
    const auto stale_witness = stale_restored->BuildSpendWitnessByCommitment(
        full_registry_snapshot.entries.back().account_leaf_commitment);
    BOOST_REQUIRE(stale_witness.has_value());
    BOOST_CHECK_EQUAL(stale_witness->leaf_index, full_registry_snapshot.entries.back().leaf_index);
    BOOST_CHECK_EQUAL(stale_witness->account_leaf_commitment,
                      full_registry_snapshot.entries.back().account_leaf_commitment);
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_rebuilds_missing_account_registry_payload_store_on_restart,
                        PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const auto rebalance_fixture = BuildChainstateRebalanceFixture(*this, chainman);
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({rebalance_fixture.tx}, script_pub_key);

    fs::path datadir;
    uint256 expected_registry_root;
    uint64_t expected_registry_size{0};
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        datadir = chainman.m_options.datadir;
        expected_registry_root = chainman.GetShieldedAccountRegistryRoot();
        expected_registry_size = chainman.GetShieldedAccountRegistryEntryCount();
        BOOST_REQUIRE_GT(expected_registry_size, 0U);
    }

    auto simulate_node_restart = [&](bool wipe_account_registry_payloads) -> ChainstateManager& {
        ChainstateManager& current_chainman = *Assert(m_node.chainman);

        for (Chainstate* cs : current_chainman.GetAll()) {
            LOCK(::cs_main);
            cs->ForceFlushStateToDisk();
        }
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        {
            LOCK(::cs_main);
            current_chainman.ResetChainstates();
            BOOST_CHECK_EQUAL(current_chainman.GetAll().size(), 0);
            m_node.chainman.reset();
        }

        if (wipe_account_registry_payloads) {
            fs::remove_all(datadir / "shielded_state" / "account_registry");
        }

        {
            LOCK(::cs_main);
            m_node.notifications = std::make_unique<KernelNotifications>(
                Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
            const ChainstateManager::Options chainman_opts{
                .chainparams = ::Params(),
                .datadir = datadir,
                .notifications = *m_node.notifications,
                .signals = m_node.validation_signals.get(),
            };
            const BlockManager::Options blockman_opts{
                .chainparams = chainman_opts.chainparams,
                .blocks_dir = m_args.GetBlocksDirPath(),
                .notifications = chainman_opts.notifications,
                .block_tree_db_params = DBParams{
                    .path = datadir / "blocks" / "index",
                    .cache_bytes = m_kernel_cache_sizes.block_tree_db,
                    .memory_only = m_block_tree_db_in_memory,
                },
            };
            m_node.chainman = std::make_unique<ChainstateManager>(
                *Assert(m_node.shutdown_signal), chainman_opts, blockman_opts);
        }
        return *Assert(m_node.chainman);
    };

    ChainstateManager& chainman_restarted = simulate_node_restart(/*wipe_account_registry_payloads=*/true);
    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman_restarted.EnsureShieldedStateInitialized());
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedAccountRegistryRoot(), expected_registry_root);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedAccountRegistryEntryCount(), expected_registry_size);
        BOOST_REQUIRE(chainman_restarted.GetShieldedAccountRegistry().MaterializeEntry(
            expected_registry_size - 1).has_value());

        const auto exported = chainman_restarted.ExportShieldedAccountRegistrySnapshot(
            chainman_restarted.ActiveChainstate(),
            chainman_restarted.ActiveTip());
        BOOST_REQUIRE(exported.has_value());
        BOOST_CHECK(exported->IsValid());
        BOOST_CHECK_EQUAL(exported->entries.size(), expected_registry_size);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedAccountRegistryRoot(), expected_registry_root);
        BOOST_REQUIRE(chainman_restarted.GetShieldedAccountRegistry().MaterializeEntry(
            expected_registry_size - 1).has_value());
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_rebuilds_from_chain_when_mutation_marker_is_present,
                        PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    auto simulate_node_restart = [&]() -> ChainstateManager& {
        ChainstateManager& current_chainman = *Assert(m_node.chainman);

        for (Chainstate* cs : current_chainman.GetAll()) {
            LOCK(::cs_main);
            cs->ForceFlushStateToDisk();
        }
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        {
            LOCK(::cs_main);
            current_chainman.ResetChainstates();
            BOOST_CHECK_EQUAL(current_chainman.GetAll().size(), 0);
            m_node.notifications = std::make_unique<KernelNotifications>(
                Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
            const ChainstateManager::Options chainman_opts{
                .chainparams = ::Params(),
                .datadir = current_chainman.m_options.datadir,
                .notifications = *m_node.notifications,
                .signals = m_node.validation_signals.get(),
            };
            const BlockManager::Options blockman_opts{
                .chainparams = chainman_opts.chainparams,
                .blocks_dir = m_args.GetBlocksDirPath(),
                .notifications = chainman_opts.notifications,
                .block_tree_db_params = DBParams{
                    .path = current_chainman.m_options.datadir / "blocks" / "index",
                    .cache_bytes = m_kernel_cache_sizes.block_tree_db,
                    .memory_only = m_block_tree_db_in_memory,
                },
            };
            m_node.chainman.reset();
            m_node.chainman = std::make_unique<ChainstateManager>(
                *Assert(m_node.shutdown_signal), chainman_opts, blockman_opts);
        }
        return *Assert(m_node.chainman);
    };

    const Nullifier bogus_nullifier = GetRandHash();
    uint256 expected_tip_hash;
    int32_t expected_tip_height{-1};
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        expected_tip_hash = chainman.ActiveTip()->GetBlockHash();
        expected_tip_height = chainman.ActiveTip()->nHeight;
        BOOST_REQUIRE(chainman.InsertShieldedNullifiersForTest({bogus_nullifier}));
        BOOST_CHECK(chainman.IsShieldedNullifierSpent(bogus_nullifier));
        ShieldedStateMutationMarker marker;
        marker.version = ShieldedStateMutationMarker::LEGACY_VERSION;
        marker.target_tip_hash = expected_tip_hash;
        marker.target_tip_height = expected_tip_height;
        BOOST_REQUIRE(chainman.WriteShieldedMutationMarker(marker));
        BOOST_REQUIRE(chainman.ReadShieldedMutationMarker().has_value());
        BOOST_CHECK_EQUAL(chainman.GetShieldedNullifierCount(), 1U);
    }

    ChainstateManager& chainman_restarted = simulate_node_restart();
    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman_restarted.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman_restarted.ActiveTip() != nullptr);
        BOOST_CHECK(chainman_restarted.ActiveTip()->GetBlockHash() == expected_tip_hash);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveTip()->nHeight, expected_tip_height);
        BOOST_CHECK(!chainman_restarted.IsShieldedNullifierSpent(bogus_nullifier));
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedNullifierCount(), 0U);
        BOOST_CHECK(!chainman_restarted.ReadShieldedMutationMarker().has_value());
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_rebuilds_full_shielded_state_from_chain_when_mutation_marker_is_present,
                        PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    auto simulate_node_restart = [&]() -> ChainstateManager& {
        ChainstateManager& current_chainman = *Assert(m_node.chainman);

        for (Chainstate* cs : current_chainman.GetAll()) {
            LOCK(::cs_main);
            cs->ForceFlushStateToDisk();
        }
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        {
            LOCK(::cs_main);
            current_chainman.ResetChainstates();
            BOOST_CHECK_EQUAL(current_chainman.GetAll().size(), 0);
            m_node.notifications = std::make_unique<KernelNotifications>(
                Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
            const ChainstateManager::Options chainman_opts{
                .chainparams = ::Params(),
                .datadir = current_chainman.m_options.datadir,
                .notifications = *m_node.notifications,
                .signals = m_node.validation_signals.get(),
            };
            const BlockManager::Options blockman_opts{
                .chainparams = chainman_opts.chainparams,
                .blocks_dir = m_args.GetBlocksDirPath(),
                .notifications = chainman_opts.notifications,
                .block_tree_db_params = DBParams{
                    .path = current_chainman.m_options.datadir / "blocks" / "index",
                    .cache_bytes = m_kernel_cache_sizes.block_tree_db,
                    .memory_only = m_block_tree_db_in_memory,
                },
            };
            m_node.chainman.reset();
            m_node.chainman = std::make_unique<ChainstateManager>(
                *Assert(m_node.shutdown_signal), chainman_opts, blockman_opts);
        }
        return *Assert(m_node.chainman);
    };

    const auto rebalance_fixture = BuildChainstateRebalanceFixture(*this, chainman);
    const auto settlement_fixture = BuildChainstateSettlementAnchorReceiptFixture(chainman);
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({rebalance_fixture.tx}, script_pub_key);
    CreateAndProcessBlock({settlement_fixture.tx}, script_pub_key);

    const Nullifier bogus_nullifier = GetRandHash();
    const uint256 bogus_settlement_anchor = uint256{0xb1};
    const ConfirmedNettingManifestState bogus_manifest_state{
        /*manifest_id=*/uint256{0xb2},
        /*created_height=*/1,
        /*settlement_window=*/144,
    };

    uint256 expected_tip_hash;
    int32_t expected_tip_height{-1};
    size_t expected_tree_size{0};
    uint256 expected_tree_root;
    uint64_t expected_nullifier_count{0};
    CAmount expected_pool_balance{0};
    uint256 expected_registry_root;
    size_t expected_registry_size{0};
    uint256 expected_state_commitment_hash;
    ConfirmedNettingManifestState expected_manifest_state;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman.ActiveTip() != nullptr);
        expected_tip_hash = chainman.ActiveTip()->GetBlockHash();
        expected_tip_height = chainman.ActiveTip()->nHeight;
        expected_tree_size = chainman.GetShieldedMerkleTree().Size();
        expected_tree_root = chainman.GetShieldedMerkleTree().Root();
        expected_nullifier_count = chainman.GetShieldedNullifierCount();
        expected_pool_balance = chainman.GetShieldedPoolBalance();
        expected_registry_root = chainman.GetShieldedAccountRegistryRoot();
        expected_registry_size = chainman.GetShieldedAccountRegistryEntryCount();
        const auto manifest_state = chainman.GetShieldedNettingManifestState(rebalance_fixture.manifest_id);
        BOOST_REQUIRE(manifest_state.has_value());
        expected_manifest_state = *manifest_state;
        const auto state_commitment = chainman.GetShieldedStateCommitment();
        BOOST_REQUIRE(state_commitment.has_value());
        expected_state_commitment_hash =
            shielded::registry::ComputeShieldedStateCommitmentHash(*state_commitment);
        BOOST_CHECK(chainman.IsShieldedNettingManifestValid(rebalance_fixture.manifest_id));
        BOOST_CHECK(chainman.IsShieldedSettlementAnchorValid(settlement_fixture.settlement_anchor_digest));

        shielded::ShieldedMerkleTree persisted_tree;
        std::vector<uint256> persisted_anchor_roots;
        uint256 persisted_tip_hash;
        int32_t persisted_tip_height{-1};
        CAmount persisted_pool_balance{0};
        std::optional<uint256> persisted_commitment_index_digest;
        std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
            persisted_account_registry_snapshot;
        BOOST_REQUIRE(chainman.ReadPersistedShieldedState(persisted_tree,
                                                          persisted_anchor_roots,
                                                          persisted_tip_hash,
                                                          persisted_tip_height,
                                                          persisted_pool_balance,
                                                          persisted_commitment_index_digest,
                                                          persisted_account_registry_snapshot));
        BOOST_REQUIRE(chainman.InsertShieldedNullifiersForTest({bogus_nullifier}));
        BOOST_REQUIRE(chainman.InsertShieldedSettlementAnchorsForTest({bogus_settlement_anchor}));
        BOOST_REQUIRE(chainman.InsertShieldedNettingManifestsForTest({bogus_manifest_state}));
        BOOST_REQUIRE(chainman.WriteShieldedPoolBalanceForTest(/*balance=*/1));
        BOOST_REQUIRE(chainman.WritePersistedShieldedState(persisted_tree,
                                                           persisted_anchor_roots,
                                                           persisted_tip_hash,
                                                           persisted_tip_height,
                                                           /*balance=*/1,
                                                           persisted_commitment_index_digest,
                                                           persisted_account_registry_snapshot));
        ShieldedStateMutationMarker marker;
        marker.version = ShieldedStateMutationMarker::LEGACY_VERSION;
        marker.target_tip_hash = expected_tip_hash;
        marker.target_tip_height = expected_tip_height;
        BOOST_REQUIRE(chainman.WriteShieldedMutationMarker(marker));
        BOOST_REQUIRE(chainman.ReadShieldedMutationMarker().has_value());
        BOOST_CHECK(chainman.IsShieldedNullifierSpent(bogus_nullifier));
        BOOST_CHECK(chainman.IsShieldedSettlementAnchorValid(bogus_settlement_anchor));
        BOOST_CHECK(chainman.IsShieldedNettingManifestValid(bogus_manifest_state.manifest_id));
    }

    ChainstateManager& chainman_restarted = simulate_node_restart();
    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman_restarted.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman_restarted.ActiveTip() != nullptr);
        BOOST_CHECK(chainman_restarted.ActiveTip()->GetBlockHash() == expected_tip_hash);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveTip()->nHeight, expected_tip_height);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedMerkleTree().Size(), expected_tree_size);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedMerkleTree().Root(), expected_tree_root);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedNullifierCount(), expected_nullifier_count);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedPoolBalance(), expected_pool_balance);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedAccountRegistryRoot(), expected_registry_root);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedAccountRegistryEntryCount(), expected_registry_size);
        BOOST_CHECK(!chainman_restarted.IsShieldedNullifierSpent(bogus_nullifier));
        BOOST_CHECK(!chainman_restarted.IsShieldedSettlementAnchorValid(bogus_settlement_anchor));
        BOOST_CHECK(!chainman_restarted.IsShieldedNettingManifestValid(bogus_manifest_state.manifest_id));
        BOOST_CHECK(chainman_restarted.IsShieldedNettingManifestValid(rebalance_fixture.manifest_id));
        BOOST_CHECK(chainman_restarted.IsShieldedSettlementAnchorValid(settlement_fixture.settlement_anchor_digest));
        const auto rebuilt_manifest_state =
            chainman_restarted.GetShieldedNettingManifestState(rebalance_fixture.manifest_id);
        BOOST_REQUIRE(rebuilt_manifest_state.has_value());
        BOOST_CHECK(*rebuilt_manifest_state == expected_manifest_state);
        const auto rebuilt_state_commitment = chainman_restarted.GetShieldedStateCommitment();
        BOOST_REQUIRE(rebuilt_state_commitment.has_value());
        BOOST_CHECK_EQUAL(shielded::registry::ComputeShieldedStateCommitmentHash(*rebuilt_state_commitment),
                          expected_state_commitment_hash);
        BOOST_CHECK(!chainman_restarted.ReadShieldedMutationMarker().has_value());
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_restores_prepared_shielded_transition_from_journal,
                        PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    auto simulate_node_restart = [&]() -> ChainstateManager& {
        ChainstateManager& current_chainman = *Assert(m_node.chainman);

        for (Chainstate* cs : current_chainman.GetAll()) {
            LOCK(::cs_main);
            cs->ForceFlushStateToDisk();
        }
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        {
            LOCK(::cs_main);
            current_chainman.ResetChainstates();
            BOOST_CHECK_EQUAL(current_chainman.GetAll().size(), 0);
            m_node.notifications = std::make_unique<KernelNotifications>(
                Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
            const ChainstateManager::Options chainman_opts{
                .chainparams = ::Params(),
                .datadir = current_chainman.m_options.datadir,
                .notifications = *m_node.notifications,
                .signals = m_node.validation_signals.get(),
            };
            const BlockManager::Options blockman_opts{
                .chainparams = chainman_opts.chainparams,
                .blocks_dir = m_args.GetBlocksDirPath(),
                .notifications = chainman_opts.notifications,
                .block_tree_db_params = DBParams{
                    .path = current_chainman.m_options.datadir / "blocks" / "index",
                    .cache_bytes = m_kernel_cache_sizes.block_tree_db,
                    .memory_only = m_block_tree_db_in_memory,
                },
            };
            m_node.chainman.reset();
            m_node.chainman = std::make_unique<ChainstateManager>(
                *Assert(m_node.shutdown_signal), chainman_opts, blockman_opts);
        }
        return *Assert(m_node.chainman);
    };

    shielded::ShieldedMerkleTree source_tree;
    std::vector<uint256> source_anchor_roots;
    uint256 source_tip_hash;
    int32_t source_tip_height{-1};
    CAmount source_pool_balance{0};
    std::optional<uint256> source_commitment_index_digest;
    std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
        source_account_registry_snapshot;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman.ReadPersistedShieldedState(source_tree,
                                                          source_anchor_roots,
                                                          source_tip_hash,
                                                          source_tip_height,
                                                          source_pool_balance,
                                                          source_commitment_index_digest,
                                                          source_account_registry_snapshot));
    }

    const auto rebalance_fixture = BuildChainstateRebalanceFixture(*this, chainman);
    const auto settlement_fixture = BuildChainstateSettlementAnchorReceiptFixture(chainman);
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({rebalance_fixture.tx}, script_pub_key);
    CreateAndProcessBlock({settlement_fixture.tx}, script_pub_key);

    uint256 expected_tip_hash;
    int32_t expected_tip_height{-1};
    size_t expected_tree_size{0};
    uint256 expected_tree_root;
    uint64_t expected_nullifier_count{0};
    CAmount expected_pool_balance{0};
    uint256 expected_registry_root;
    size_t expected_registry_size{0};
    {
        ShieldedStateMutationMarker prepared_marker;
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman.ActiveTip() != nullptr);
        expected_tip_hash = chainman.ActiveTip()->GetBlockHash();
        expected_tip_height = chainman.ActiveTip()->nHeight;
        expected_tree_size = chainman.GetShieldedMerkleTree().Size();
        expected_tree_root = chainman.GetShieldedMerkleTree().Root();
        expected_nullifier_count = chainman.GetShieldedNullifierCount();
        expected_pool_balance = chainman.GetShieldedPoolBalance();
        expected_registry_root = chainman.GetShieldedAccountRegistryRoot();
        expected_registry_size = chainman.GetShieldedAccountRegistryEntryCount();

        prepared_marker.version = ShieldedStateMutationMarker::PREPARED_TRANSITION_VERSION;
        prepared_marker.stage = ShieldedStateMutationMarker::PREPARED_STAGE;
        prepared_marker.source_tip_hash = source_tip_hash;
        prepared_marker.source_tip_height = source_tip_height;
        prepared_marker.target_tip_hash = expected_tip_hash;
        prepared_marker.target_tip_height = expected_tip_height;
        prepared_marker.prepared_target_snapshot.tree = chainman.GetShieldedMerkleTree();
        prepared_marker.prepared_target_snapshot.pool_balance = chainman.GetShieldedPoolBalance();
        const auto target_commitment_index_digest =
            chainman.GetShieldedMerkleTree().CommitmentIndexDigest();
        BOOST_REQUIRE(target_commitment_index_digest.has_value());
        prepared_marker.prepared_target_snapshot.commitment_index_digest =
            *target_commitment_index_digest;
        prepared_marker.prepared_target_snapshot.account_registry_snapshot =
            chainman.GetShieldedAccountRegistry().ExportPersistedSnapshot();
        BOOST_REQUIRE(prepared_marker.IsPreparedTransitionJournal());

        BOOST_REQUIRE(chainman.WritePersistedShieldedState(source_tree,
                                                           source_anchor_roots,
                                                           expected_tip_hash,
                                                           expected_tip_height,
                                                           source_pool_balance,
                                                           source_commitment_index_digest,
                                                           source_account_registry_snapshot));
        BOOST_REQUIRE(chainman.WriteShieldedMutationMarker(prepared_marker));
    }

    source_tree = shielded::ShieldedMerkleTree{
        shielded::ShieldedMerkleTree::IndexStorageMode::MEMORY_ONLY};

    ChainstateManager& chainman_restarted = simulate_node_restart();
    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman_restarted.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman_restarted.ActiveTip() != nullptr);
        BOOST_CHECK(chainman_restarted.ActiveTip()->GetBlockHash() == expected_tip_hash);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveTip()->nHeight, expected_tip_height);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedMerkleTree().Size(), expected_tree_size);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedMerkleTree().Root(), expected_tree_root);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedNullifierCount(), expected_nullifier_count);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedPoolBalance(), expected_pool_balance);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedAccountRegistryRoot(), expected_registry_root);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedAccountRegistryEntryCount(), expected_registry_size);
        BOOST_CHECK(!chainman_restarted.ReadShieldedMutationMarker().has_value());
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_rebuilds_from_chain_when_persisted_nullifier_state_drifts_without_marker,
                        PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    auto simulate_node_restart = [&]() -> ChainstateManager& {
        ChainstateManager& current_chainman = *Assert(m_node.chainman);

        for (Chainstate* cs : current_chainman.GetAll()) {
            LOCK(::cs_main);
            cs->ForceFlushStateToDisk();
        }
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        {
            LOCK(::cs_main);
            current_chainman.ResetChainstates();
            BOOST_CHECK_EQUAL(current_chainman.GetAll().size(), 0);
            m_node.notifications = std::make_unique<KernelNotifications>(
                Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
            const ChainstateManager::Options chainman_opts{
                .chainparams = ::Params(),
                .datadir = current_chainman.m_options.datadir,
                .notifications = *m_node.notifications,
                .signals = m_node.validation_signals.get(),
            };
            const BlockManager::Options blockman_opts{
                .chainparams = chainman_opts.chainparams,
                .blocks_dir = m_args.GetBlocksDirPath(),
                .notifications = chainman_opts.notifications,
                .block_tree_db_params = DBParams{
                    .path = current_chainman.m_options.datadir / "blocks" / "index",
                    .cache_bytes = m_kernel_cache_sizes.block_tree_db,
                    .memory_only = m_block_tree_db_in_memory,
                },
            };
            m_node.chainman.reset();
            m_node.chainman = std::make_unique<ChainstateManager>(
                *Assert(m_node.shutdown_signal), chainman_opts, blockman_opts);
        }
        return *Assert(m_node.chainman);
    };

    const auto rebalance_fixture = BuildChainstateRebalanceFixture(*this, chainman);
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({rebalance_fixture.tx}, script_pub_key);

    const Nullifier bogus_nullifier = GetRandHash();

    uint256 expected_tip_hash;
    int32_t expected_tip_height{-1};
    size_t expected_tree_size{0};
    uint256 expected_tree_root;
    uint64_t expected_nullifier_count{0};
    CAmount expected_pool_balance{0};
    uint256 expected_registry_root;
    size_t expected_registry_size{0};
    uint256 expected_state_commitment_hash;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman.ActiveTip() != nullptr);
        expected_tip_hash = chainman.ActiveTip()->GetBlockHash();
        expected_tip_height = chainman.ActiveTip()->nHeight;
        expected_tree_size = chainman.GetShieldedMerkleTree().Size();
        expected_tree_root = chainman.GetShieldedMerkleTree().Root();
        expected_nullifier_count = chainman.GetShieldedNullifierCount();
        expected_pool_balance = chainman.GetShieldedPoolBalance();
        expected_registry_root = chainman.GetShieldedAccountRegistryRoot();
        expected_registry_size = chainman.GetShieldedAccountRegistryEntryCount();
        const auto state_commitment = chainman.GetShieldedStateCommitment();
        BOOST_REQUIRE(state_commitment.has_value());
        expected_state_commitment_hash =
            shielded::registry::ComputeShieldedStateCommitmentHash(*state_commitment);

        BOOST_CHECK(!chainman.ReadShieldedMutationMarker().has_value());
        BOOST_REQUIRE(chainman.InsertShieldedNullifiersForTest({bogus_nullifier}));
        BOOST_CHECK(chainman.IsShieldedNullifierSpent(bogus_nullifier));
        BOOST_CHECK_EQUAL(chainman.GetShieldedNullifierCount(), expected_nullifier_count + 1);
    }

    ChainstateManager& chainman_restarted = simulate_node_restart();
    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman_restarted.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman_restarted.ActiveTip() != nullptr);
        BOOST_CHECK(chainman_restarted.ActiveTip()->GetBlockHash() == expected_tip_hash);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveTip()->nHeight, expected_tip_height);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedMerkleTree().Size(), expected_tree_size);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedMerkleTree().Root(), expected_tree_root);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedNullifierCount(), expected_nullifier_count);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedPoolBalance(), expected_pool_balance);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedAccountRegistryRoot(), expected_registry_root);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedAccountRegistryEntryCount(), expected_registry_size);
        BOOST_CHECK(!chainman_restarted.IsShieldedNullifierSpent(bogus_nullifier));
        const auto rebuilt_state_commitment = chainman_restarted.GetShieldedStateCommitment();
        BOOST_REQUIRE(rebuilt_state_commitment.has_value());
        BOOST_CHECK_EQUAL(shielded::registry::ComputeShieldedStateCommitmentHash(*rebuilt_state_commitment),
                          expected_state_commitment_hash);
        BOOST_CHECK(!chainman_restarted.ReadShieldedMutationMarker().has_value());
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_rebuilds_from_chain_when_persisted_bridge_state_drifts_without_marker,
                        PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    auto simulate_node_restart = [&]() -> ChainstateManager& {
        ChainstateManager& current_chainman = *Assert(m_node.chainman);

        for (Chainstate* cs : current_chainman.GetAll()) {
            LOCK(::cs_main);
            cs->ForceFlushStateToDisk();
        }
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        {
            LOCK(::cs_main);
            current_chainman.ResetChainstates();
            BOOST_CHECK_EQUAL(current_chainman.GetAll().size(), 0);
            m_node.notifications = std::make_unique<KernelNotifications>(
                Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
            const ChainstateManager::Options chainman_opts{
                .chainparams = ::Params(),
                .datadir = current_chainman.m_options.datadir,
                .notifications = *m_node.notifications,
                .signals = m_node.validation_signals.get(),
            };
            const BlockManager::Options blockman_opts{
                .chainparams = chainman_opts.chainparams,
                .blocks_dir = m_args.GetBlocksDirPath(),
                .notifications = chainman_opts.notifications,
                .block_tree_db_params = DBParams{
                    .path = current_chainman.m_options.datadir / "blocks" / "index",
                    .cache_bytes = m_kernel_cache_sizes.block_tree_db,
                    .memory_only = m_block_tree_db_in_memory,
                },
            };
            m_node.chainman.reset();
            m_node.chainman = std::make_unique<ChainstateManager>(
                *Assert(m_node.shutdown_signal), chainman_opts, blockman_opts);
        }
        return *Assert(m_node.chainman);
    };

    const auto rebalance_fixture = BuildChainstateRebalanceFixture(*this, chainman);
    const auto settlement_fixture = BuildChainstateSettlementAnchorReceiptFixture(chainman);
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({rebalance_fixture.tx}, script_pub_key);
    CreateAndProcessBlock({settlement_fixture.tx}, script_pub_key);

    const uint256 bogus_settlement_anchor = uint256{0xb1};
    const ConfirmedNettingManifestState bogus_manifest_state{
        /*manifest_id=*/uint256{0xb2},
        /*created_height=*/1,
        /*settlement_window=*/144,
    };

    uint256 expected_tip_hash;
    int32_t expected_tip_height{-1};
    uint256 expected_state_commitment_hash;
    ConfirmedNettingManifestState expected_manifest_state;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman.ActiveTip() != nullptr);
        expected_tip_hash = chainman.ActiveTip()->GetBlockHash();
        expected_tip_height = chainman.ActiveTip()->nHeight;
        const auto state_commitment = chainman.GetShieldedStateCommitment();
        BOOST_REQUIRE(state_commitment.has_value());
        expected_state_commitment_hash =
            shielded::registry::ComputeShieldedStateCommitmentHash(*state_commitment);
        const auto manifest_state = chainman.GetShieldedNettingManifestState(rebalance_fixture.manifest_id);
        BOOST_REQUIRE(manifest_state.has_value());
        expected_manifest_state = *manifest_state;

        BOOST_CHECK(!chainman.ReadShieldedMutationMarker().has_value());
        BOOST_REQUIRE(chainman.InsertShieldedSettlementAnchorsForTest({bogus_settlement_anchor}));
        BOOST_REQUIRE(chainman.InsertShieldedNettingManifestsForTest({bogus_manifest_state}));
        BOOST_CHECK(chainman.IsShieldedSettlementAnchorValid(bogus_settlement_anchor));
        BOOST_CHECK(chainman.IsShieldedNettingManifestValid(bogus_manifest_state.manifest_id));
    }

    ChainstateManager& chainman_restarted = simulate_node_restart();
    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman_restarted.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman_restarted.ActiveTip() != nullptr);
        BOOST_CHECK(chainman_restarted.ActiveTip()->GetBlockHash() == expected_tip_hash);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveTip()->nHeight, expected_tip_height);
        BOOST_CHECK(!chainman_restarted.IsShieldedSettlementAnchorValid(bogus_settlement_anchor));
        BOOST_CHECK(!chainman_restarted.IsShieldedNettingManifestValid(bogus_manifest_state.manifest_id));
        BOOST_CHECK(chainman_restarted.IsShieldedSettlementAnchorValid(
            settlement_fixture.settlement_anchor_digest));
        BOOST_CHECK(chainman_restarted.IsShieldedNettingManifestValid(rebalance_fixture.manifest_id));
        const auto rebuilt_manifest_state =
            chainman_restarted.GetShieldedNettingManifestState(rebalance_fixture.manifest_id);
        BOOST_REQUIRE(rebuilt_manifest_state.has_value());
        BOOST_CHECK(*rebuilt_manifest_state == expected_manifest_state);
        const auto rebuilt_state_commitment = chainman_restarted.GetShieldedStateCommitment();
        BOOST_REQUIRE(rebuilt_state_commitment.has_value());
        BOOST_CHECK_EQUAL(shielded::registry::ComputeShieldedStateCommitmentHash(*rebuilt_state_commitment),
                          expected_state_commitment_hash);
        BOOST_CHECK(!chainman_restarted.ReadShieldedMutationMarker().has_value());
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_builds_shielded_proof_audit_archive, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);

    const auto rebalance_fixture = BuildChainstateRebalanceFixture(*this, chainman);
    const auto settlement_fixture = BuildChainstateSettlementAnchorReceiptFixture(chainman);
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({rebalance_fixture.tx}, script_pub_key);
    CreateAndProcessBlock({settlement_fixture.tx}, script_pub_key);

    LOCK(::cs_main);
    shielded::audit::ProofAuditArchive archive;
    std::string error;
    BOOST_REQUIRE_MESSAGE(BuildShieldedProofAuditArchive(chainman.ActiveChainstate(),
                                                         chainman.ActiveChainstate().m_chain.Tip(),
                                                         archive,
                                                         error),
                          error);
    BOOST_CHECK_EQUAL(archive.failed_count, 0U);
    BOOST_CHECK_GE(archive.verified_count, 2U);
    BOOST_CHECK(std::all_of(archive.entries.begin(),
                            archive.entries.end(),
                            [](const shielded::audit::ProofAuditEntry& entry) {
                                return entry.verified && entry.reject_reason.empty();
                            }));
    BOOST_CHECK(std::any_of(archive.entries.begin(),
                            archive.entries.end(),
                            [&](const shielded::audit::ProofAuditEntry& entry) {
                                return entry.txid == rebalance_fixture.tx.GetHash();
                            }));
    BOOST_CHECK(std::any_of(archive.entries.begin(),
                            archive.entries.end(),
                            [&](const shielded::audit::ProofAuditEntry& entry) {
                                return entry.txid == settlement_fixture.tx.GetHash();
                            }));
}

/** Helper function to parse args into args_man and return the result of applying them to opts */
template <typename Options>
util::Result<Options> SetOptsFromArgs(ArgsManager& args_man, Options opts,
                                      const std::vector<const char*>& args)
{
    const auto argv{Cat({"ignore"}, args)};
    std::string error{};
    if (!args_man.ParseParameters(argv.size(), argv.data(), error)) {
        return util::Error{Untranslated("ParseParameters failed with error: " + error)};
    }
    const auto result{node::ApplyArgsManOptions(args_man, opts)};
    if (!result) return util::Error{util::ErrorString(result)};
    return opts;
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_args, BasicTestingSetup)
{
    //! Try to apply the provided args to a ChainstateManager::Options
    auto get_opts = [&](const std::vector<const char*>& args) {
        static kernel::Notifications notifications{};
        static const ChainstateManager::Options options{
            .chainparams = ::Params(),
            .datadir = {},
            .notifications = notifications};
        return SetOptsFromArgs(*this->m_node.args, options, args);
    };
    //! Like get_opts, but requires the provided args to be valid and unwraps the result
    auto get_valid_opts = [&](const std::vector<const char*>& args) {
        const auto result{get_opts(args)};
        BOOST_REQUIRE_MESSAGE(result, util::ErrorString(result).original);
        return *result;
    };

    // test -assumevalid
    BOOST_CHECK(!get_valid_opts({}).assumed_valid_block);
    BOOST_CHECK_EQUAL(get_valid_opts({"-assumevalid="}).assumed_valid_block, uint256::ZERO);
    BOOST_CHECK_EQUAL(get_valid_opts({"-assumevalid=0"}).assumed_valid_block, uint256::ZERO);
    BOOST_CHECK_EQUAL(get_valid_opts({"-noassumevalid"}).assumed_valid_block, uint256::ZERO);
    BOOST_CHECK_EQUAL(get_valid_opts({"-assumevalid=0x12"}).assumed_valid_block, uint256{0x12});

    std::string assume_valid{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"};
    BOOST_CHECK_EQUAL(get_valid_opts({("-assumevalid=" + assume_valid).c_str()}).assumed_valid_block, uint256::FromHex(assume_valid));

    BOOST_CHECK(!get_opts({"-assumevalid=xyz"}));                                                               // invalid hex characters
    BOOST_CHECK(!get_opts({"-assumevalid=01234567890123456789012345678901234567890123456789012345678901234"})); // > 64 hex chars

    // test -minimumchainwork
    BOOST_CHECK(!get_valid_opts({}).minimum_chain_work);
    BOOST_CHECK_EQUAL(get_valid_opts({"-minimumchainwork=0"}).minimum_chain_work, arith_uint256());
    BOOST_CHECK_EQUAL(get_valid_opts({"-nominimumchainwork"}).minimum_chain_work, arith_uint256());
    BOOST_CHECK_EQUAL(get_valid_opts({"-minimumchainwork=0x1234"}).minimum_chain_work, arith_uint256{0x1234});

    std::string minimum_chainwork{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"};
    BOOST_CHECK_EQUAL(get_valid_opts({("-minimumchainwork=" + minimum_chainwork).c_str()}).minimum_chain_work, UintToArith256(uint256::FromHex(minimum_chainwork).value()));

    BOOST_CHECK(!get_opts({"-minimumchainwork=xyz"}));                                                               // invalid hex characters
    BOOST_CHECK(!get_opts({"-minimumchainwork=01234567890123456789012345678901234567890123456789012345678901234"})); // > 64 hex chars

    // TEST: tier_config_flag_sets_behavior
    // TEST: mining_node_implicitly_tier0
    // test -matmulvalidation
    BOOST_CHECK_EQUAL(get_valid_opts({}).matmul_validation_mode, kernel::MatMulValidationMode::CONSENSUS);
    BOOST_CHECK_EQUAL(get_valid_opts({"-matmulvalidation=consensus"}).matmul_validation_mode, kernel::MatMulValidationMode::CONSENSUS);
    BOOST_CHECK_EQUAL(get_valid_opts({"-matmulvalidation=economic"}).matmul_validation_mode, kernel::MatMulValidationMode::ECONOMIC);
    BOOST_CHECK_EQUAL(get_valid_opts({"-matmulvalidation=spv"}).matmul_validation_mode, kernel::MatMulValidationMode::SPV);
    BOOST_CHECK(!get_opts({"-matmulvalidation=invalid"}));

    BOOST_CHECK_EQUAL(get_valid_opts({}).retain_shielded_commitment_index, true);
    BOOST_CHECK_EQUAL(get_valid_opts({"-retainshieldedcommitmentindex"}).retain_shielded_commitment_index, true);
    BOOST_CHECK_EQUAL(get_valid_opts({"-retainshieldedcommitmentindex=1"}).retain_shielded_commitment_index, true);
    BOOST_CHECK_EQUAL(get_valid_opts({"-retainshieldedcommitmentindex=0"}).retain_shielded_commitment_index, false);
}

BOOST_AUTO_TEST_SUITE_END()
