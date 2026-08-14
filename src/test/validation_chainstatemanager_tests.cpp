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
#include <util/readwritefile.h>
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
        for (Chainstate* cs : manager.GetAll()) {
            cs->ClearBlockIndexCandidates();
        }
        c2.LoadChainTip();
        for (Chainstate* cs : manager.GetAll()) {
            cs->PopulateBlockIndexCandidates();
        }
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
    //
    // Keep the default regtest MatMul activation schedule (and therefore the
    // canned assumeutxo@110 metadata). Any -regtestmatmul* height override
    // clears m_assumeutxo_data, and Debug mining across v4/RC@100/101 is slow,
    // so these cases are opt-in via BTX_EXTENDED_CHAINSTATE_TESTS=1.
    static bool ExtendedSnapshotTestsEnabled()
    {
        const char* env = std::getenv("BTX_EXTENDED_CHAINSTATE_TESTS");
        return env != nullptr && env[0] != '\0' && env[0] != '0';
    }

    // When the extended suite is off, keep the cheap MatMul deferral so Boost
    // still constructs the fixture quickly before SkipUnlessExtended returns.
    // When extended is on, use the real regtest schedule (assumeutxo@110).
    SnapshotTestSetup() : TestChain100Setup{
                              {},
                              {
                                  .coins_db_in_memory = false,
                                  .block_tree_db_in_memory = false,
                                  .defer_expensive_matmul = !ExtendedSnapshotTestsEnabled(),
                              },
                          }
    {
    }

    //! Returns true when the caller should return early (extended suite off).
    bool SkipUnlessExtendedSnapshotTests()
    {
        if (ExtendedSnapshotTestsEnabled()) {
            return false;
        }
        BOOST_TEST_MESSAGE(
            "Skipping SnapshotTestSetup case (Debug MatMul@v4/RC mining is too "
            "slow for the default suite). Set BTX_EXTENDED_CHAINSTATE_TESTS=1 "
            "to opt in.");
        return true;
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
    if (SkipUnlessExtendedSnapshotTests()) return;
    this->SetupSnapshot();
}

//! Candidate sets must stay empty while a live snapshot's chain tip is loaded,
//! then be rebuilt after the snapshot/background roles become final.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_activate_snapshot_candidate_lifecycle, SnapshotTestSetup)
{
    if (SkipUnlessExtendedSnapshotTests()) return;
    ChainstateManager& chainman = *Assert(m_node.chainman);

    // Reach the regtest assumeutxo height, then simulate the normal case where
    // historical validation has only reached genesis when the snapshot loads.
    mineBlocks(10);
    BOOST_REQUIRE(CreateAndActivateUTXOSnapshot(
        this, NoMalleation, /*reset_chainstate=*/true));

    LOCK(::cs_main);
    CBlockIndex* snapshot_base{chainman.ActiveTip()};
    BOOST_REQUIRE(snapshot_base != nullptr);
    BOOST_CHECK_EQUAL(snapshot_base, chainman.GetSnapshotBaseBlock());
    BOOST_CHECK(chainman.IsSnapshotActive());
    BOOST_CHECK_EQUAL(chainman.GetAll().size(), 2);
    BOOST_CHECK_EQUAL(
        chainman.ActiveChainstate().setBlockIndexCandidates.count(snapshot_base), 1);

    for (Chainstate* chainstate : chainman.GetAll()) {
        BOOST_CHECK(!chainstate->setBlockIndexCandidates.empty());
        if (chainstate != &chainman.ActiveChainstate()) {
            // The background chainstate must validate its way to the base; it
            // cannot inherit the snapshot chainstate's assumed-valid shortcut.
            BOOST_CHECK_EQUAL(chainstate->setBlockIndexCandidates.count(snapshot_base), 0);
        }
    }
}

//! A BTX shielded-section rejection happens after the snapshot Chainstate is
//! managed but before it becomes active. The old active chainstate must retain
//! a usable candidate set, including for an in-memory snapshot with no DB dir.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_failed_snapshot_restores_candidates, SnapshotTestSetup)
{
    if (SkipUnlessExtendedSnapshotTests()) return;
    mineBlocks(10);

    // SimulateNodeRestart reconstructs the manager with the production
    // fail-closed default for unpinned shielded snapshots.
    this->SimulateNodeRestart();
    this->LoadVerifyActivateChainstate();
    ChainstateManager& chainman = *Assert(m_node.chainman);
    BOOST_CHECK(!chainman.m_options.allow_unpinned_shielded_snapshot);

    BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
        this, NoMalleation, /*reset_chainstate=*/false,
        /*in_memory_chainstate=*/true));

    {
        LOCK(::cs_main);
        BOOST_CHECK(!chainman.IsSnapshotActive());
        BOOST_CHECK_EQUAL(chainman.GetAll().size(), 1);
        Chainstate& active{chainman.ActiveChainstate()};
        BOOST_REQUIRE(active.m_chain.Tip() != nullptr);
        BOOST_CHECK(!active.setBlockIndexCandidates.empty());
        BOOST_CHECK_EQUAL(active.setBlockIndexCandidates.count(active.m_chain.Tip()), 1);
        BOOST_CHECK(!node::FindSnapshotChainstateDir(chainman.m_options.datadir));
    }

    // Candidate restoration is operational, not just structural.
    mineBlocks(1);
    BOOST_CHECK_EQUAL(WITH_LOCK(::cs_main, return chainman.ActiveHeight()), 111);
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
//! Requires the canned regtest assumeutxo@110 metadata (and therefore the default MatMul
//! activation schedule). Opt in with BTX_EXTENDED_CHAINSTATE_TESTS=1.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_loadblockindex, SnapshotTestSetup)
{
    if (SkipUnlessExtendedSnapshotTests()) return;

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

        WITH_LOCK(::cs_main, {
            chainman.LoadBlockIndex();
            for (Chainstate* cs : chainman.GetAll()) {
                cs->PopulateBlockIndexCandidates();
            }
        });
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

    // The fully validated chain should only have the current validated tip
    // as a candidate (block 90). Specifically:
    //
    // - It does not have blocks 0-89 because they contain less work than the
    //   chain tip.
    //
    // - It has block 90 because it has data and equal work to the chain tip,
    //   (since it is the chain tip).
    //
    // - It does not have blocks 91-110 because they do not contain data.
    //
    // - It does not have any blocks after height 110 because cs1 is a background
    //   chainstate, and only blocks where are ancestors of the snapshot block
    //   are added as candidates for the background chainstate.
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.size(), 1);
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.count(validated_tip), 1);

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
    if (SkipUnlessExtendedSnapshotTests()) return;
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
    if (SkipUnlessExtendedSnapshotTests()) return;
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
    if (SkipUnlessExtendedSnapshotTests()) return;
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

struct PoolCreditRetunePersistedTestChain100Setup : TestChain100Setup
{
    PoolCreditRetunePersistedTestChain100Setup()
        : TestChain100Setup(
              ChainType::REGTEST,
              {.extra_args = {"-regtestshieldedpoolcreditdisableheight=125"},
               .coins_db_in_memory = false,
               .block_tree_db_in_memory = false})
    {
    }
};

struct RecoveryExitFastStartupPersistedTestChain100Setup : TestChain100Setup
{
    RecoveryExitFastStartupPersistedTestChain100Setup()
        : TestChain100Setup(
              ChainType::REGTEST,
              {.extra_args = {"-regtestshieldedsunsetheight=100",
                              "-regtestshieldedpoolcreditdisableheight=100",
                              "-regtestshieldedrecoveryexitactivationheight=100",
                              "-fastshieldedstartup=1",
                              "-shieldedstartupaudit=0"},
               .coins_db_in_memory = false,
               .block_tree_db_in_memory = false})
    {
    }
};

struct RecoveryExitVelocityFastStartupPersistedTestChain100Setup : TestChain100Setup
{
    RecoveryExitVelocityFastStartupPersistedTestChain100Setup()
        : TestChain100Setup(
              ChainType::REGTEST,
              {.extra_args = {"-regtestshieldedsunsetheight=100",
                              "-regtestshieldedpoolcreditdisableheight=100",
                              "-regtestshieldedrecoveryexitactivationheight=100",
                              "-regtestshieldedunshieldvelocityactivationheight=100",
                              "-fastshieldedstartup=1",
                              "-shieldedstartupaudit=0"},
               .coins_db_in_memory = false,
               .block_tree_db_in_memory = false})
    {
    }
};

struct ShieldedWriteFaultPersistedTestChain100Setup : TestChain100Setup
{
    ShieldedWriteFaultPersistedTestChain100Setup()
        : TestChain100Setup(
              ChainType::REGTEST,
              {.extra_args = {"-regtestshieldedunshieldvelocityactivationheight=100",
                              "-fastshieldedstartup=1",
                              "-shieldedstartupaudit=0"},
               .coins_db_in_memory = false,
               .block_tree_db_in_memory = false})
    {
    }

    void ExerciseWriteFailure(ShieldedTransitionWriteSeam seam,
                              bool settlement_transaction = false)
    {
        ChainstateManager& chainman = *Assert(m_node.chainman);
        const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
        CMutableTransaction tx;
        if (settlement_transaction) {
            tx = BuildChainstateSettlementAnchorReceiptFixture(chainman).tx;
        } else {
            tx = BuildChainstateRebalanceFixture(*this, chainman).tx;
        }
        const CBlock block = CreateBlock({tx}, script_pub_key,
                                         chainman.ActiveChainstate(),
                                         /*use_mempool=*/false);
        const uint256 target_hash = block.GetHash();
        CBlockIndex* target_index{nullptr};
        {
            LOCK(::cs_main);
            BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
            BlockValidationState accept_state;
            bool new_block{false};
            BOOST_REQUIRE(chainman.AcceptBlock(std::make_shared<const CBlock>(block),
                                               accept_state,
                                               &target_index,
                                               /*fRequested=*/true,
                                               /*dbp=*/nullptr,
                                               &new_block,
                                               /*min_pow_checked=*/true));
            BOOST_REQUIRE(accept_state.IsValid());
            BOOST_REQUIRE(new_block);
            BOOST_REQUIRE(target_index != nullptr);
            // Make the candidate body/index and the old committed state
            // durable before modelling a process crash during ConnectBlock.
            for (Chainstate* cs : chainman.GetAll()) cs->ForceFlushStateToDisk();
        }

        bool injected{false};
        {
            LOCK(::cs_main);
            chainman.SetShieldedTransitionWriteFaultHookForTest(
                [&](ShieldedTransitionWriteSeam current) {
                    if (!injected && current == seam) {
                        injected = true;
                        return true;
                    }
                    return false;
                });
        }
        // Exercise the production fail-stop path without interrupting the unit
        // test process; KernelNotifications still records the fatal warning.
        Assert(m_node.notifications)->m_shutdown_on_fatal_error = false;
        BlockValidationState activation_state;
        BOOST_CHECK(!chainman.ActiveChainstate().ActivateBestChain(
            activation_state, std::make_shared<const CBlock>(block)));
        BOOST_REQUIRE(injected);
        BOOST_CHECK(activation_state.IsError());
        {
            LOCK(::cs_main);
            chainman.SetShieldedTransitionWriteFaultHookForTest({});
            BOOST_CHECK_EQUAL(target_index->nStatus & BLOCK_FAILED_MASK, 0U);
            const bool marker_must_exist =
                seam != ShieldedTransitionWriteSeam::ACCOUNT_PAYLOAD &&
                seam != ShieldedTransitionWriteSeam::PREPARED_MARKER;
            BOOST_CHECK_EQUAL(chainman.ReadShieldedMutationMarker().has_value(),
                              marker_must_exist);
        }

        // Drop handles without a clean-state flush: this is the exact crash
        // boundary under test. Startup must use PREPARED redo or bounded gap
        // recovery and must never poison the candidate as consensus-invalid.
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        const fs::path datadir = chainman.m_options.datadir;
        {
            LOCK(::cs_main);
            chainman.ResetChainstates();
            m_node.chainman.reset();
            m_node.notifications = std::make_unique<KernelNotifications>(
                Assert(m_node.shutdown_request), m_node.exit_status,
                *Assert(m_node.warnings));
            const ChainstateManager::Options chainman_opts{
                .chainparams = ::Params(),
                .datadir = datadir,
                .shielded_startup_audit = false,
                .fast_shielded_startup = true,
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
        ChainstateManager& restarted = *Assert(m_node.chainman);
        LoadVerifyActivateChainstate();
        {
            LOCK(::cs_main);
            BOOST_REQUIRE(restarted.EnsureShieldedStateInitialized());
            BOOST_REQUIRE(restarted.ActiveTip() != nullptr);
            BOOST_CHECK_EQUAL(restarted.ActiveTip()->GetBlockHash(), target_hash);
            CBlockIndex* restarted_target =
                restarted.m_blockman.LookupBlockIndex(target_hash);
            BOOST_REQUIRE(restarted_target != nullptr);
            BOOST_CHECK_EQUAL(restarted_target->nStatus & BLOCK_FAILED_MASK, 0U);
            BOOST_CHECK(!restarted.ReadShieldedMutationMarker().has_value());
        }
    }
};

#define SHIELDED_REBALANCE_WRITE_FAULT_TEST(test_name, seam_name)                  \
    BOOST_FIXTURE_TEST_CASE(test_name, ShieldedWriteFaultPersistedTestChain100Setup) \
    {                                                                              \
        ExerciseWriteFailure(ShieldedTransitionWriteSeam::seam_name);              \
    }

SHIELDED_REBALANCE_WRITE_FAULT_TEST(shielded_write_failure_payload_is_fatal_and_restart_safe,
                                    ACCOUNT_PAYLOAD)
SHIELDED_REBALANCE_WRITE_FAULT_TEST(shielded_write_failure_prepared_marker_is_fatal_and_restart_safe,
                                    PREPARED_MARKER)
SHIELDED_REBALANCE_WRITE_FAULT_TEST(shielded_write_failure_manifest_is_fatal_and_restart_safe,
                                    NETTING_MANIFESTS)
SHIELDED_REBALANCE_WRITE_FAULT_TEST(shielded_write_failure_velocity_is_fatal_and_restart_safe,
                                    UNSHIELD_VELOCITY)
SHIELDED_REBALANCE_WRITE_FAULT_TEST(shielded_write_failure_pool_is_fatal_and_restart_safe,
                                    POOL_BALANCE)
SHIELDED_REBALANCE_WRITE_FAULT_TEST(shielded_write_failure_final_state_is_fatal_and_restart_safe,
                                    PERSISTED_STATE)
SHIELDED_REBALANCE_WRITE_FAULT_TEST(shielded_write_failure_accumulator_is_fatal_and_restart_safe,
                                    NULLIFIER_ACCUMULATOR)
SHIELDED_REBALANCE_WRITE_FAULT_TEST(shielded_write_failure_state_pin_is_fatal_and_restart_safe,
                                    STATE_PIN)
SHIELDED_REBALANCE_WRITE_FAULT_TEST(shielded_write_failure_marker_clear_is_fatal_and_restart_safe,
                                    MARKER_CLEAR)

#undef SHIELDED_REBALANCE_WRITE_FAULT_TEST

BOOST_FIXTURE_TEST_CASE(shielded_write_failure_settlement_is_fatal_and_restart_safe,
                        ShieldedWriteFaultPersistedTestChain100Setup)
{
    ExerciseWriteFailure(ShieldedTransitionWriteSeam::SETTLEMENT_ANCHORS,
                         /*settlement_transaction=*/true);
}

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
    const auto settlement_anchor_fixture = BuildChainstateSettlementAnchorReceiptFixture(chainman);
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
        const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
        CreateAndProcessBlock({settlement_anchor_fixture.tx}, script_pub_key);

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
    const fs::path shielded_section_path = m_args.GetDataDirNet() / "shielded_section_v6_registry.dat";
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
    header.m_snapshot_version = node::SHIELDED_SNAPSHOT_ACCOUNT_REGISTRY_VERSION;
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
    header.m_snapshot_version = node::SHIELDED_SNAPSHOT_ACCOUNT_REGISTRY_VERSION;
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

BOOST_FIXTURE_TEST_CASE(chainstatemanager_restores_persisted_shielded_state_after_failed_snapshot_section_load,
                        PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const auto rebalance_fixture = BuildChainstateRebalanceFixture(*this, chainman);
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({rebalance_fixture.tx}, script_pub_key);

    const fs::path invalid_section_path = m_args.GetDataDirNet() / "invalid_shielded_section.dat";
    {
        AutoFile outfile{fsbridge::fopen(invalid_section_path, "wb")};
        BOOST_REQUIRE(!outfile.IsNull());
        BOOST_REQUIRE_EQUAL(outfile.fclose(), 0);
    }

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
        const CBlockIndex* const tip = chainman.ActiveTip();
        BOOST_REQUIRE(tip != nullptr);
        BOOST_REQUIRE(chainman.PersistShieldedState(tip));

        expected_tip_hash = tip->GetBlockHash();
        expected_tip_height = tip->nHeight;
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

        node::ShieldedSnapshotSectionHeader header;
        header.m_snapshot_version = node::SHIELDED_SNAPSHOT_ACCOUNT_REGISTRY_VERSION;
        header.m_account_registry_entry_count = 1;
        AutoFile infile{fsbridge::fopen(invalid_section_path, "rb")};
        BOOST_REQUIRE(!infile.IsNull());
        auto result{chainman.LoadShieldedSnapshotSection(infile, header, tip)};
        BOOST_CHECK(!result);
        BOOST_CHECK_EQUAL(util::ErrorString(result).original,
                          "truncated or malformed BTX shielded snapshot section");
        // Snapshot rollback now restores and reopens the previous durable
        // state before returning, so callers never observe a half-initialized
        // consensus view after a rejected section.
        BOOST_REQUIRE(chainman.HasShieldedState());

        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman.ActiveTip() != nullptr);
        BOOST_CHECK(chainman.ActiveTip()->GetBlockHash() == expected_tip_hash);
        BOOST_CHECK_EQUAL(chainman.ActiveTip()->nHeight, expected_tip_height);
        BOOST_CHECK_EQUAL(chainman.GetShieldedMerkleTree().Size(), expected_tree_size);
        BOOST_CHECK_EQUAL(chainman.GetShieldedMerkleTree().Root(), expected_tree_root);
        BOOST_CHECK_EQUAL(chainman.GetShieldedNullifierCount(), expected_nullifier_count);
        BOOST_CHECK_EQUAL(chainman.GetShieldedPoolBalance(), expected_pool_balance);
        BOOST_CHECK_EQUAL(chainman.GetShieldedAccountRegistryRoot(), expected_registry_root);
        BOOST_CHECK_EQUAL(chainman.GetShieldedAccountRegistryEntryCount(), expected_registry_size);
        const auto restored_state_commitment = chainman.GetShieldedStateCommitment();
        BOOST_REQUIRE(restored_state_commitment.has_value());
        BOOST_CHECK_EQUAL(shielded::registry::ComputeShieldedStateCommitmentHash(*restored_state_commitment),
                          expected_state_commitment_hash);
        BOOST_CHECK(!chainman.ReadShieldedMutationMarker().has_value());
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

BOOST_FIXTURE_TEST_CASE(chainstatemanager_rejects_stale_anchor_history_for_mempool_accept,
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
    BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "bad-shielded-anchor");

    {
        LOCK(::cs_main);
        BOOST_CHECK(!chainman.IsShieldedAnchorValid(previous_root));
        BOOST_CHECK_EQUAL(
            chainman.GetShieldedAutoRepairAttemptCountForTest(ShieldedAutoRepairKind::ANCHOR_HISTORY),
            0U);
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

BOOST_FIXTURE_TEST_CASE(
    chainstatemanager_startup_reconsiders_failed_pre_pool_credit_disable_shielded_block_after_consensus_retune,
    PoolCreditRetunePersistedTestChain100Setup)
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
        BOOST_REQUIRE_LT(accepted_index->nHeight,
                         chainman.GetConsensus().nShieldedPoolCreditDisableHeight);
        BOOST_REQUIRE(chainman.ActiveTip() != nullptr);
        BOOST_CHECK_NE(chainman.ActiveTip()->GetBlockHash(), invalid_hash);
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
        CBlockIndex* reconsidered_index = chainman_restarted.m_blockman.LookupBlockIndex(invalid_hash);
        BOOST_REQUIRE(reconsidered_index != nullptr);
        BOOST_CHECK_EQUAL(reconsidered_index->nStatus & BLOCK_FAILED_MASK, 0U);
        BOOST_REQUIRE(chainman_restarted.ActiveTip() != nullptr);
        BOOST_CHECK_NE(chainman_restarted.ActiveTip()->GetBlockHash(), invalid_hash);
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
        // Mutation-marker full rebuild must use the fused single genesis->tip walk rather than
        // four independent block-store passes (state / registry / settlement / netting).
        ASSERT_DEBUG_LOG("RebuildShieldedChainDerivedState: replaying");
        ASSERT_DEBUG_LOG("RebuildShieldedChainDerivedState: replayed");
        DebugLogHelper no_separate_state(
            "RebuildShieldedState: replaying",
            [](const std::string* line) {
                if (line != nullptr) {
                    throw std::runtime_error("unexpected separate RebuildShieldedState pass during fused rebuild");
                }
                return false;
            });
        DebugLogHelper no_separate_registry(
            "RebuildShieldedAccountRegistryState: replaying",
            [](const std::string* line) {
                if (line != nullptr) {
                    throw std::runtime_error("unexpected separate account-registry pass during fused rebuild");
                }
                return false;
            });
        DebugLogHelper no_separate_settlement(
            "RebuildShieldedSettlementAnchorState: scanning",
            [](const std::string* line) {
                if (line != nullptr) {
                    throw std::runtime_error("unexpected separate settlement-anchor pass during fused rebuild");
                }
                return false;
            });
        DebugLogHelper no_separate_netting(
            "RebuildShieldedNettingManifestState: scanning",
            [](const std::string* line) {
                if (line != nullptr) {
                    throw std::runtime_error("unexpected separate netting-manifest pass during fused rebuild");
                }
                return false;
            });
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

// A stale in-flight marker plus missing rebuild blocks is ambiguous: some
// auxiliary stores may contain source state while others contain target state.
// Preserve the journal and fail closed instead of exposing that mixed view.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_fails_closed_when_marker_rebuild_needs_pruned_block,
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

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({}, script_pub_key);

    uint256 expected_tip_hash;
    int32_t expected_tip_height{-1};
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman.ActiveTip() != nullptr);
        expected_tip_hash = chainman.ActiveTip()->GetBlockHash();
        expected_tip_height = chainman.ActiveTip()->nHeight;

        // EnsureShieldedStateInitialized() above persisted a complete shielded snapshot (frontier,
        // anchor roots, account-registry root window, etc). Plant a stale LEGACY mutation marker on
        // top of it -- a LEGACY marker is not a prepared-transition journal, so on restart it forces
        // the full rebuild_from_chain path that the pruned block would break.
        ShieldedStateMutationMarker marker;
        marker.version = ShieldedStateMutationMarker::LEGACY_VERSION;
        marker.target_tip_hash = expected_tip_hash;
        marker.target_tip_height = expected_tip_height;
        BOOST_REQUIRE(chainman.WriteShieldedMutationMarker(marker));
        BOOST_REQUIRE(chainman.ReadShieldedMutationMarker().has_value());
    }

    ChainstateManager& chainman_restarted = simulate_node_restart();
    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        // Simulate pruning: mark an ancestor block's data as unavailable so a full shielded rebuild
        // from chain (which the stale marker would trigger) cannot read it.
        CBlockIndex* pruned = chainman_restarted.ActiveChain()[10];
        BOOST_REQUIRE(pruned != nullptr);
        pruned->nStatus &= ~BLOCK_HAVE_DATA;
        pruned->nDataPos = 0;
        pruned->nFile = -1;

        BOOST_CHECK(!chainman_restarted.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman_restarted.ActiveTip() != nullptr);
        BOOST_CHECK(chainman_restarted.ActiveTip()->GetBlockHash() == expected_tip_hash);
        const auto retained_marker = chainman_restarted.ReadShieldedMutationMarker();
        BOOST_REQUIRE(retained_marker.has_value());
        BOOST_CHECK_EQUAL(retained_marker->target_tip_hash, expected_tip_hash);
        BOOST_CHECK_EQUAL(retained_marker->target_tip_height, expected_tip_height);
        BOOST_CHECK(!chainman_restarted.HasShieldedState());
    }
}

// §11: a tip-matched PREPARED journal whose prepared redo cannot run (e.g. bogus
// source tip) must not force a from-genesis rebuild when the durable tip snapshot
// already carries a verifying pin+accumulator. Production clean-stop leftovers of
// this shape were the multi-hour restart tax.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_skips_genesis_rebuild_for_stale_tip_matched_prepared_marker,
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

    uint256 expected_tip_hash;
    int32_t expected_tip_height{-1};
    size_t expected_tree_size{0};
    uint256 expected_tree_root;
    uint64_t expected_nullifier_count{0};
    CAmount expected_pool_balance{0};
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
        BOOST_REQUIRE(chainman.ComputeShieldedSnapshotStatePin().has_value());
        // Ensure tip pin/accumulator are sealed on disk before planting the stale marker.
        BOOST_REQUIRE(chainman.PersistShieldedState(chainman.ActiveTip()));

        ShieldedStateMutationMarker prepared_marker;
        prepared_marker.version = ShieldedStateMutationMarker::PREPARED_TRANSITION_VERSION;
        prepared_marker.stage = ShieldedStateMutationMarker::PREPARED_STAGE;
        // Tip-matched target, but a nonexistent source tip so prepared redo fails
        // and would previously fall through to rebuild_from_chain.
        prepared_marker.source_tip_hash = GetRandHash();
        prepared_marker.source_tip_height = std::max(0, expected_tip_height - 1);
        prepared_marker.target_tip_hash = expected_tip_hash;
        prepared_marker.target_tip_height = expected_tip_height;
        prepared_marker.prepared_target_snapshot.tree = chainman.GetShieldedMerkleTree();
        prepared_marker.prepared_target_snapshot.pool_balance = expected_pool_balance;
        const auto target_commitment_index_digest =
            chainman.GetShieldedMerkleTree().CommitmentIndexDigest();
        BOOST_REQUIRE(target_commitment_index_digest.has_value());
        prepared_marker.prepared_target_snapshot.commitment_index_digest =
            *target_commitment_index_digest;
        prepared_marker.prepared_target_snapshot.account_registry_snapshot =
            chainman.GetShieldedAccountRegistry().ExportPersistedSnapshot();
        prepared_marker.prepared_target_snapshot.journaled_account_payloads =
            chainman.GetShieldedAccountRegistry().ExportSnapshot().entries;
        BOOST_REQUIRE(prepared_marker.IsPreparedTransitionJournal());
        BOOST_REQUIRE(chainman.WriteShieldedMutationMarker(prepared_marker));
        BOOST_REQUIRE(chainman.ReadShieldedMutationMarker().has_value());
    }

    ChainstateManager& chainman_restarted = simulate_node_restart();
    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        ASSERT_DEBUG_LOG("clearing stale tip-matched PREPARED mutation marker");
        DebugLogHelper no_full_rebuild(
            "rebuilding full shielded state from chain",
            [](const std::string* line) {
                if (line != nullptr) {
                    throw std::runtime_error(
                        "unexpected from-genesis rebuild for tip-matched PREPARED marker");
                }
                return false;
            });
        DebugLogHelper no_genesis_replay(
            "replaying",
            [](const std::string* line) {
                if (line != nullptr && line->find("genesis") != std::string::npos) {
                    throw std::runtime_error(
                        "unexpected genesis replay for tip-matched PREPARED marker");
                }
                return false;
            });
        BOOST_REQUIRE(chainman_restarted.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman_restarted.ActiveTip() != nullptr);
        BOOST_CHECK(chainman_restarted.ActiveTip()->GetBlockHash() == expected_tip_hash);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveTip()->nHeight, expected_tip_height);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedMerkleTree().Size(), expected_tree_size);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedMerkleTree().Root(), expected_tree_root);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedNullifierCount(), expected_nullifier_count);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedPoolBalance(), expected_pool_balance);
        BOOST_CHECK(!chainman_restarted.ReadShieldedMutationMarker().has_value());
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_restores_prepared_shielded_transition_from_journal,
                        PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    auto simulate_node_restart = [&](bool drop_account_payload_store = false) -> ChainstateManager& {
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
            if (drop_account_payload_store) {
                shielded::registry::ShieldedAccountRegistryState::ResetPayloadStore();
                fs::remove_all(chainman_opts.datadir /
                               "shielded_state" / "account_registry");
            }
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
        prepared_marker.prepared_target_snapshot.journaled_account_payloads =
            chainman.GetShieldedAccountRegistry().ExportSnapshot().entries;
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

    // Model crash after PREPARED but before the account payload batch. The
    // journal must contain enough data to recreate the missing payload store
    // and finish without a genesis replay.
    ChainstateManager& chainman_restarted = simulate_node_restart(
        /*drop_account_payload_store=*/true);
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

BOOST_FIXTURE_TEST_CASE(chainstatemanager_gap_only_catches_up_persisted_shielded_ancestor,
                        PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    shielded::ShieldedMerkleTree persisted_tree;
    std::vector<uint256> persisted_anchor_roots;
    uint256 persisted_tip_hash;
    int32_t persisted_tip_height{-1};
    CAmount persisted_balance{0};
    std::optional<uint256> persisted_commitment_digest;
    std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
        persisted_registry;
    std::vector<uint256> persisted_registry_roots;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman.ReadPersistedShieldedState(
            persisted_tree,
            persisted_anchor_roots,
            persisted_tip_hash,
            persisted_tip_height,
            persisted_balance,
            persisted_commitment_digest,
            persisted_registry,
            &persisted_registry_roots));
    }

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    for (int i = 0; i < 4; ++i) CreateAndProcessBlock({}, script_pub_key);
    uint256 expected_tip_hash;
    int32_t expected_tip_height{-1};
    {
        LOCK(::cs_main);
        expected_tip_hash = Assert(chainman.ActiveTip())->GetBlockHash();
        expected_tip_height = chainman.ActiveTip()->nHeight;
        // Simulate a cleanly durable shielded base followed by block-index
        // progress that did not yet publish the newer shielded tip record.
        BOOST_REQUIRE(chainman.WritePersistedShieldedState(
            persisted_tree,
            persisted_anchor_roots,
            persisted_tip_hash,
            persisted_tip_height,
            persisted_balance,
            persisted_commitment_digest,
            persisted_registry,
            persisted_registry_roots));
        for (Chainstate* cs : chainman.GetAll()) cs->ForceFlushStateToDisk();
        // ForceFlush may republish the current tip; restore the simulated
        // ancestor record after the block index is fully durable.
        BOOST_REQUIRE(chainman.WritePersistedShieldedState(
            persisted_tree,
            persisted_anchor_roots,
            persisted_tip_hash,
            persisted_tip_height,
            persisted_balance,
            persisted_commitment_digest,
            persisted_registry,
            persisted_registry_roots));
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    const fs::path datadir = chainman.m_options.datadir;
    {
        LOCK(::cs_main);
        // Drop all tree/nullifier/payload-store handles before reopening the
        // same LevelDB paths in-process, exactly as a real process exit does.
        chainman.ResetChainstates();
        persisted_tree = shielded::ShieldedMerkleTree{
            shielded::ShieldedMerkleTree::IndexStorageMode::MEMORY_ONLY};
        m_node.chainman.reset();
        m_node.notifications = std::make_unique<KernelNotifications>(
            Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
        const ChainstateManager::Options chainman_opts{
            .chainparams = ::Params(),
            .datadir = datadir,
            .shielded_startup_audit = false,
            .fast_shielded_startup = true,
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
    ChainstateManager& restarted = *Assert(m_node.chainman);
    this->LoadVerifyActivateChainstate();
    {
        LOCK(::cs_main);
        ASSERT_DEBUG_LOG("completed gap-only shielded catch-up of 4 block(s)");
        BOOST_REQUIRE(restarted.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(restarted.ActiveTip() != nullptr);
        BOOST_CHECK_EQUAL(restarted.ActiveTip()->GetBlockHash(), expected_tip_hash);
        BOOST_CHECK_EQUAL(restarted.ActiveTip()->nHeight, expected_tip_height);
        BOOST_CHECK(!restarted.ReadShieldedMutationMarker().has_value());
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_gap_only_unwinds_persisted_shielded_descendant,
                        PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({}, script_pub_key);

    shielded::ShieldedMerkleTree ahead_tree;
    std::vector<uint256> ahead_anchor_roots;
    uint256 ahead_tip_hash;
    int32_t ahead_tip_height{-1};
    CAmount ahead_balance{0};
    std::optional<uint256> ahead_digest;
    std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot> ahead_registry;
    std::vector<uint256> ahead_registry_roots;
    CBlockIndex* ahead_index{nullptr};
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman.ReadPersistedShieldedState(
            ahead_tree, ahead_anchor_roots, ahead_tip_hash, ahead_tip_height,
            ahead_balance, ahead_digest, ahead_registry, &ahead_registry_roots));
        ahead_index = chainman.m_blockman.LookupBlockIndex(ahead_tip_hash);
        BOOST_REQUIRE(ahead_index != nullptr);
    }
    BlockValidationState invalidate_state;
    BOOST_REQUIRE(chainman.ActiveChainstate().InvalidateBlock(
        invalidate_state, ahead_index));
    BOOST_REQUIRE(invalidate_state.IsValid());
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.ActiveTip() != nullptr);
        BOOST_REQUIRE_EQUAL(chainman.ActiveTip()->nHeight, ahead_tip_height - 1);
        for (Chainstate* cs : chainman.GetAll()) cs->ForceFlushStateToDisk();
        BOOST_REQUIRE(chainman.WritePersistedShieldedState(
            ahead_tree, ahead_anchor_roots, ahead_tip_hash, ahead_tip_height,
            ahead_balance, ahead_digest, ahead_registry, ahead_registry_roots));
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    const fs::path datadir = chainman.m_options.datadir;
    {
        LOCK(::cs_main);
        chainman.ResetChainstates();
        ahead_tree = shielded::ShieldedMerkleTree{
            shielded::ShieldedMerkleTree::IndexStorageMode::MEMORY_ONLY};
        m_node.chainman.reset();
        m_node.notifications = std::make_unique<KernelNotifications>(
            Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
        const ChainstateManager::Options chainman_opts{
            .chainparams = ::Params(),
            .datadir = datadir,
            .shielded_startup_audit = false,
            .fast_shielded_startup = true,
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
    ChainstateManager& restarted = *Assert(m_node.chainman);
    this->LoadVerifyActivateChainstate();
    {
        LOCK(::cs_main);
        ASSERT_DEBUG_LOG("completed gap-only shielded unwind of 1 block(s)");
        BOOST_REQUIRE(restarted.EnsureShieldedStateInitialized());
        BOOST_CHECK(!restarted.ReadShieldedMutationMarker().has_value());
    }
}

// Unclean stop after snapshot catch-up: shielded tip is ahead of the active
// snapshot-base tip, gap-only unwind cannot read the missing post-snapshot
// bodies, and fused rebuild would walk genesis. Never wipe shielded_state
// on that already-unavoidable failure (assumeutxo brick).
BOOST_FIXTURE_TEST_CASE(chainstatemanager_refuses_genesis_rebuild_wipe_when_ahead_tip_blocks_missing,
                        PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({}, script_pub_key);

    shielded::ShieldedMerkleTree ahead_tree;
    std::vector<uint256> ahead_anchor_roots;
    uint256 ahead_tip_hash;
    int32_t ahead_tip_height{-1};
    CAmount ahead_balance{0};
    std::optional<uint256> ahead_digest;
    std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot> ahead_registry;
    std::vector<uint256> ahead_registry_roots;
    CBlockIndex* ahead_index{nullptr};
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman.ReadPersistedShieldedState(
            ahead_tree, ahead_anchor_roots, ahead_tip_hash, ahead_tip_height,
            ahead_balance, ahead_digest, ahead_registry, &ahead_registry_roots));
        ahead_index = chainman.m_blockman.LookupBlockIndex(ahead_tip_hash);
        BOOST_REQUIRE(ahead_index != nullptr);
    }
    BlockValidationState invalidate_state;
    BOOST_REQUIRE(chainman.ActiveChainstate().InvalidateBlock(
        invalidate_state, ahead_index));
    BOOST_REQUIRE(invalidate_state.IsValid());
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.ActiveTip() != nullptr);
        BOOST_REQUIRE_EQUAL(chainman.ActiveTip()->nHeight, ahead_tip_height - 1);
        for (Chainstate* cs : chainman.GetAll()) cs->ForceFlushStateToDisk();
        BOOST_REQUIRE(chainman.WritePersistedShieldedState(
            ahead_tree, ahead_anchor_roots, ahead_tip_hash, ahead_tip_height,
            ahead_balance, ahead_digest, ahead_registry, ahead_registry_roots));
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    const fs::path datadir = chainman.m_options.datadir;
    {
        LOCK(::cs_main);
        chainman.ResetChainstates();
        ahead_tree = shielded::ShieldedMerkleTree{
            shielded::ShieldedMerkleTree::IndexStorageMode::MEMORY_ONLY};
        m_node.chainman.reset();
        m_node.notifications = std::make_unique<KernelNotifications>(
            Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
        const ChainstateManager::Options chainman_opts{
            .chainparams = ::Params(),
            .datadir = datadir,
            .shielded_startup_audit = false,
            .fast_shielded_startup = true,
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
    ChainstateManager& restarted = *Assert(m_node.chainman);
    this->LoadVerifyActivateChainstate();
    {
        LOCK(::cs_main);
        CBlockIndex* ahead = restarted.m_blockman.LookupBlockIndex(ahead_tip_hash);
        BOOST_REQUIRE(ahead != nullptr);
        ahead->nStatus &= ~BLOCK_HAVE_DATA;
        ahead->nDataPos = 0;
        ahead->nFile = -1;
        CBlockIndex* pruned = restarted.ActiveChain()[10];
        BOOST_REQUIRE(pruned != nullptr);
        pruned->nStatus &= ~BLOCK_HAVE_DATA;
        pruned->nDataPos = 0;
        pruned->nFile = -1;

        ASSERT_DEBUG_LOG("Refusing to wipe shielded_state");
        BOOST_CHECK(!restarted.EnsureShieldedStateInitialized());
        BOOST_CHECK(!restarted.HasShieldedState());

        shielded::ShieldedMerkleTree retained_tree;
        std::vector<uint256> retained_anchors;
        uint256 retained_hash;
        int32_t retained_height{-1};
        CAmount retained_balance{0};
        std::optional<uint256> retained_digest;
        std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
            retained_registry;
        std::vector<uint256> retained_registry_roots;
        BOOST_REQUIRE(restarted.ReadPersistedShieldedState(
            retained_tree, retained_anchors, retained_hash, retained_height,
            retained_balance, retained_digest, retained_registry,
            &retained_registry_roots));
        BOOST_CHECK_EQUAL(retained_hash, ahead_tip_hash);
        BOOST_CHECK_EQUAL(retained_height, ahead_tip_height);
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_gap_only_recovers_persisted_shielded_short_fork,
                        PersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    shielded::ShieldedMerkleTree old_tree;
    std::vector<uint256> old_anchor_roots;
    uint256 old_tip_hash;
    int32_t old_tip_height{-1};
    CAmount old_balance{0};
    std::optional<uint256> old_digest;
    std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
        old_registry;
    std::vector<uint256> old_registry_roots;
    CBlockIndex* old_tip{nullptr};
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman.ReadPersistedShieldedState(
            old_tree, old_anchor_roots, old_tip_hash, old_tip_height,
            old_balance, old_digest, old_registry, &old_registry_roots));
        old_tip = chainman.m_blockman.LookupBlockIndex(old_tip_hash);
        BOOST_REQUIRE(old_tip != nullptr);
    }

    BlockValidationState invalidate_state;
    BOOST_REQUIRE(chainman.ActiveChainstate().InvalidateBlock(
        invalidate_state, old_tip));
    BOOST_REQUIRE(invalidate_state.IsValid());
    const auto script_pub_key =
        GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const CBlock alternate{CreateAndProcessBlock({}, script_pub_key)};
    BOOST_REQUIRE_NE(alternate.GetHash(), old_tip_hash);

    uint256 expected_tip_hash;
    const fs::path datadir = chainman.m_options.datadir;
    {
        LOCK(::cs_main);
        expected_tip_hash = Assert(chainman.ActiveTip())->GetBlockHash();
        BOOST_REQUIRE_EQUAL(chainman.ActiveTip()->nHeight, old_tip_height);
        for (Chainstate* cs : chainman.GetAll()) cs->ForceFlushStateToDisk();
        // Simulate a crash after the block-index reorg committed but before
        // the old shielded tip record was transactionally advanced.
        BOOST_REQUIRE(chainman.WritePersistedShieldedState(
            old_tree, old_anchor_roots, old_tip_hash, old_tip_height,
            old_balance, old_digest, old_registry, old_registry_roots));
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    {
        LOCK(::cs_main);
        chainman.ResetChainstates();
        old_tree = shielded::ShieldedMerkleTree{
            shielded::ShieldedMerkleTree::IndexStorageMode::MEMORY_ONLY};
        m_node.chainman.reset();
        m_node.notifications = std::make_unique<KernelNotifications>(
            Assert(m_node.shutdown_request), m_node.exit_status,
            *Assert(m_node.warnings));
        const ChainstateManager::Options chainman_opts{
            .chainparams = ::Params(),
            .datadir = datadir,
            .shielded_startup_audit = false,
            .fast_shielded_startup = true,
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
    ChainstateManager& restarted = *Assert(m_node.chainman);
    this->LoadVerifyActivateChainstate();
    {
        LOCK(::cs_main);
        ASSERT_DEBUG_LOG(
            "completed gap-only shielded short-reorg transition (disconnect=1 connect=1)");
        BOOST_REQUIRE(restarted.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(restarted.ActiveTip() != nullptr);
        BOOST_CHECK_EQUAL(restarted.ActiveTip()->GetBlockHash(), expected_tip_hash);
        BOOST_CHECK(!restarted.ReadShieldedMutationMarker().has_value());
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

BOOST_FIXTURE_TEST_CASE(chainstatemanager_fast_startup_rebuilds_stale_recovery_exit_commitment_state,
                        RecoveryExitFastStartupPersistedTestChain100Setup)
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
                .shielded_startup_audit = false,
                .fast_shielded_startup = true,
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

    const uint256 bogus_recovery_commitment = GetRandHash();
    uint256 expected_tip_hash;
    int32_t expected_tip_height{-1};
    uint256 expected_state_pin;
    uint256 expected_state_commitment_hash;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman.ActiveTip() != nullptr);
        BOOST_REQUIRE(chainman.GetConsensus().IsShieldedRecoveryExitActive(chainman.ActiveTip()->nHeight));
        expected_tip_hash = chainman.ActiveTip()->GetBlockHash();
        expected_tip_height = chainman.ActiveTip()->nHeight;
        const auto state_pin = chainman.ComputeShieldedSnapshotStatePin();
        BOOST_REQUIRE(state_pin.has_value());
        expected_state_pin = *state_pin;
        const auto state_commitment = chainman.GetShieldedStateCommitment();
        BOOST_REQUIRE(state_commitment.has_value());
        expected_state_commitment_hash =
            shielded::registry::ComputeShieldedStateCommitmentHash(*state_commitment);

        BOOST_REQUIRE(chainman.InsertShieldedRecoveryExitCommitmentsForTest({bogus_recovery_commitment}));
        BOOST_CHECK(chainman.IsShieldedRecoveryExitCommitmentRetired(bogus_recovery_commitment));
    }

    ChainstateManager& chainman_restarted = simulate_node_restart();
    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman_restarted.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman_restarted.ActiveTip() != nullptr);
        BOOST_CHECK(chainman_restarted.ActiveTip()->GetBlockHash() == expected_tip_hash);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveTip()->nHeight, expected_tip_height);
        BOOST_CHECK(!chainman_restarted.IsShieldedRecoveryExitCommitmentRetired(
            bogus_recovery_commitment));
        const auto restored_state_pin = chainman_restarted.ComputeShieldedSnapshotStatePin();
        BOOST_REQUIRE(restored_state_pin.has_value());
        BOOST_CHECK_EQUAL(*restored_state_pin, expected_state_pin);
        const auto rebuilt_state_commitment = chainman_restarted.GetShieldedStateCommitment();
        BOOST_REQUIRE(rebuilt_state_commitment.has_value());
        BOOST_CHECK_EQUAL(shielded::registry::ComputeShieldedStateCommitmentHash(*rebuilt_state_commitment),
                          expected_state_commitment_hash);
        BOOST_CHECK(!chainman_restarted.ReadShieldedMutationMarker().has_value());
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_fast_startup_skips_recovery_exit_audit_with_verified_state_pin,
                        RecoveryExitFastStartupPersistedTestChain100Setup)
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
                .shielded_startup_audit = false,
                .fast_shielded_startup = true,
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

    uint256 expected_tip_hash;
    int32_t expected_tip_height{-1};
    size_t expected_tree_size{0};
    uint256 expected_tree_root;
    uint64_t expected_nullifier_count{0};
    CAmount expected_pool_balance{0};
    uint256 expected_registry_root;
    size_t expected_registry_size{0};
    uint256 expected_state_pin;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman.ActiveTip() != nullptr);
        BOOST_REQUIRE(chainman.GetConsensus().IsShieldedRecoveryExitActive(chainman.ActiveTip()->nHeight));
        expected_tip_hash = chainman.ActiveTip()->GetBlockHash();
        expected_tip_height = chainman.ActiveTip()->nHeight;
        expected_tree_size = chainman.GetShieldedMerkleTree().Size();
        expected_tree_root = chainman.GetShieldedMerkleTree().Root();
        expected_nullifier_count = chainman.GetShieldedNullifierCount();
        expected_pool_balance = chainman.GetShieldedPoolBalance();
        expected_registry_root = chainman.GetShieldedAccountRegistryRoot();
        expected_registry_size = chainman.GetShieldedAccountRegistryEntryCount();
        const auto state_pin = chainman.ComputeShieldedSnapshotStatePin();
        BOOST_REQUIRE(state_pin.has_value());
        expected_state_pin = *state_pin;
    }

    ChainstateManager& chainman_restarted = simulate_node_restart();
    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        ASSERT_DEBUG_LOG("-fastshieldedstartup verified persisted full shielded state pin");
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
        const auto restored_state_pin = chainman_restarted.ComputeShieldedSnapshotStatePin();
        BOOST_REQUIRE(restored_state_pin.has_value());
        BOOST_CHECK_EQUAL(*restored_state_pin, expected_state_pin);
        BOOST_CHECK(!chainman_restarted.ReadShieldedMutationMarker().has_value());
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_fast_startup_verifies_pin_after_nonempty_registry_restore,
                        RecoveryExitFastStartupPersistedTestChain100Setup)
{
    // Production: V3 pin covers account_registry_root. Hashing it before the
    // persisted registry is restored (empty default root vs 32k-entry archive)
    // caches a mismatch and forces a recovery-exit genesis audit.
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
                .shielded_startup_audit = false,
                .fast_shielded_startup = true,
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

    uint256 expected_tip_hash;
    int32_t expected_tip_height{-1};
    uint256 expected_registry_root;
    size_t expected_registry_size{0};
    uint256 expected_state_pin;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman.ActiveTip() != nullptr);
        BOOST_REQUIRE(chainman.GetConsensus().IsShieldedRecoveryExitActive(chainman.ActiveTip()->nHeight));
        const auto account = test::shielded::MakeDeterministicCompactPublicAccount(/*seed=*/0x51u);
        const uint256 note_commitment = test::shielded::MakeDeterministicTestUint256(/*seed=*/0x51u, /*domain=*/0x44);
        const auto leaf = test::shielded::BuildDirectAccountLeaf(note_commitment, account);
        BOOST_REQUIRE(leaf.has_value());
        BOOST_REQUIRE(chainman.AppendShieldedAccountRegistryForTest(
            Span<const shielded::registry::ShieldedAccountLeaf>{&*leaf, 1}));
        expected_tip_hash = chainman.ActiveTip()->GetBlockHash();
        expected_tip_height = chainman.ActiveTip()->nHeight;
        expected_registry_root = chainman.GetShieldedAccountRegistryRoot();
        expected_registry_size = chainman.GetShieldedAccountRegistryEntryCount();
        BOOST_REQUIRE_GT(expected_registry_size, 0U);
        const auto state_pin = chainman.ComputeShieldedSnapshotStatePin();
        BOOST_REQUIRE(state_pin.has_value());
        expected_state_pin = *state_pin;
    }

    ChainstateManager& chainman_restarted = simulate_node_restart();
    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        ASSERT_DEBUG_LOG("-fastshieldedstartup verified persisted full shielded state pin");
        DebugLogHelper no_pin_mismatch(
            "full shielded state pin mismatch",
            [](const std::string* line) {
                if (line != nullptr) {
                    throw std::runtime_error(
                        "unexpected pin mismatch after restoring a non-empty account registry");
                }
                return false;
            });
        DebugLogHelper no_genesis_replay(
            "replaying",
            [](const std::string* line) {
                if (line != nullptr && line->find("genesis") != std::string::npos) {
                    throw std::runtime_error(
                        "unexpected genesis replay after restoring a non-empty account registry");
                }
                return false;
            });
        BOOST_REQUIRE(chainman_restarted.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman_restarted.ActiveTip() != nullptr);
        BOOST_CHECK(chainman_restarted.ActiveTip()->GetBlockHash() == expected_tip_hash);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveTip()->nHeight, expected_tip_height);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedAccountRegistryRoot(), expected_registry_root);
        BOOST_CHECK_EQUAL(chainman_restarted.GetShieldedAccountRegistryEntryCount(), expected_registry_size);
        const auto restored_state_pin = chainman_restarted.ComputeShieldedSnapshotStatePin();
        BOOST_REQUIRE(restored_state_pin.has_value());
        BOOST_CHECK_EQUAL(*restored_state_pin, expected_state_pin);
        BOOST_CHECK(!chainman_restarted.ReadShieldedMutationMarker().has_value());
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_fast_startup_keeps_fast_path_after_history_window_refresh,
                        RecoveryExitFastStartupPersistedTestChain100Setup)
{
    // Production incident: refreshing the recent SHIELDED_ANCHOR_DEPTH history windows used to
    // set startup_shielded_repair_performed, which disabled -fastshieldedstartup and forced a
    // silent full-chain SyncShieldedSettlementAnchorState / SyncShieldedNettingManifestState
    // scan (~224 GB). History-window refresh must remain a cheap fast-path repair.
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
                .shielded_startup_audit = false,
                .fast_shielded_startup = true,
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

    uint256 expected_tip_hash;
    int32_t expected_tip_height{-1};
    size_t expected_tree_size{0};
    uint256 expected_tree_root;
    uint64_t expected_nullifier_count{0};
    CAmount expected_pool_balance{0};
    uint256 expected_registry_root;
    size_t expected_registry_size{0};
    uint256 expected_state_pin;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman.ActiveTip() != nullptr);
        BOOST_REQUIRE(chainman.GetConsensus().IsShieldedRecoveryExitActive(chainman.ActiveTip()->nHeight));
        expected_tip_hash = chainman.ActiveTip()->GetBlockHash();
        expected_tip_height = chainman.ActiveTip()->nHeight;
        expected_tree_size = chainman.GetShieldedMerkleTree().Size();
        expected_tree_root = chainman.GetShieldedMerkleTree().Root();
        expected_nullifier_count = chainman.GetShieldedNullifierCount();
        expected_pool_balance = chainman.GetShieldedPoolBalance();
        expected_registry_root = chainman.GetShieldedAccountRegistryRoot();
        expected_registry_size = chainman.GetShieldedAccountRegistryEntryCount();
        const auto state_pin = chainman.ComputeShieldedSnapshotStatePin();
        BOOST_REQUIRE(state_pin.has_value());
        expected_state_pin = *state_pin;

        shielded::ShieldedMerkleTree persisted_tree;
        std::vector<uint256> persisted_anchor_roots;
        uint256 persisted_tip_hash;
        int32_t persisted_tip_height{-1};
        CAmount persisted_pool_balance{0};
        std::optional<uint256> persisted_commitment_index_digest;
        std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
            persisted_account_registry_snapshot;
        std::vector<uint256> persisted_account_registry_roots;
        BOOST_REQUIRE(chainman.ReadPersistedShieldedState(persisted_tree,
                                                          persisted_anchor_roots,
                                                          persisted_tip_hash,
                                                          persisted_tip_height,
                                                          persisted_pool_balance,
                                                          persisted_commitment_index_digest,
                                                          persisted_account_registry_snapshot,
                                                          &persisted_account_registry_roots));
        BOOST_REQUIRE_GE(persisted_anchor_roots.size(), 2U);
        persisted_anchor_roots.resize(1);
        if (persisted_account_registry_roots.size() > 1U) {
            persisted_account_registry_roots.resize(1);
        }
        BOOST_REQUIRE(chainman.WritePersistedShieldedState(
            persisted_tree,
            persisted_anchor_roots,
            persisted_tip_hash,
            persisted_tip_height,
            persisted_pool_balance,
            persisted_commitment_index_digest,
            persisted_account_registry_snapshot,
            persisted_account_registry_roots));
        // Truncating history windows must not disturb the previously persisted full-state pin /
        // nullifier accumulator that authorize -fastshieldedstartup.
    }

    ChainstateManager& chainman_restarted = simulate_node_restart();
    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        ASSERT_DEBUG_LOG("rebuilt shielded anchor history");
        ASSERT_DEBUG_LOG("without disabling -fastshieldedstartup");
        ASSERT_DEBUG_LOG("-fastshieldedstartup verified persisted full shielded state pin");
        ASSERT_DEBUG_LOG("preserving persisted settlement-anchor and netting-manifest metadata");
        DebugLogHelper no_settlement_scan(
            "RebuildShieldedSettlementAnchorState: scanning",
            [](const std::string* line) {
                if (line != nullptr) {
                    throw std::runtime_error(
                        "unexpected full-chain settlement-anchor scan after history-window-only refresh");
                }
                return false;
            });
        DebugLogHelper no_netting_scan(
            "RebuildShieldedNettingManifestState: scanning",
            [](const std::string* line) {
                if (line != nullptr) {
                    throw std::runtime_error(
                        "unexpected full-chain netting-manifest scan after history-window-only refresh");
                }
                return false;
            });
        DebugLogHelper no_full_replay(
            "RebuildShieldedState: replaying",
            [](const std::string* line) {
                if (line != nullptr) {
                    throw std::runtime_error(
                        "unexpected full shielded-state replay after history-window-only refresh");
                }
                return false;
            });
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
        BOOST_CHECK_GE(chainman_restarted.GetShieldedAnchorRoots().size(), 2U);
        const auto restored_state_pin = chainman_restarted.ComputeShieldedSnapshotStatePin();
        BOOST_REQUIRE(restored_state_pin.has_value());
        BOOST_CHECK_EQUAL(*restored_state_pin, expected_state_pin);
        BOOST_CHECK(!chainman_restarted.ReadShieldedMutationMarker().has_value());
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_fast_startup_repairs_stale_unshield_velocity,
                        RecoveryExitVelocityFastStartupPersistedTestChain100Setup)
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
                .shielded_startup_audit = false,
                .fast_shielded_startup = true,
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

    uint256 expected_tip_hash;
    int32_t expected_tip_height{-1};
    uint256 expected_state_pin;
    uint32_t window_blocks{0};
    int32_t next_block_height{-1};
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman.ActiveTip() != nullptr);
        BOOST_REQUIRE(chainman.GetConsensus().IsShieldedRecoveryExitActive(chainman.ActiveTip()->nHeight));
        next_block_height = chainman.ActiveTip()->nHeight == std::numeric_limits<int32_t>::max()
            ? chainman.ActiveTip()->nHeight
            : chainman.ActiveTip()->nHeight + 1;
        BOOST_REQUIRE(chainman.GetConsensus().IsShieldedUnshieldVelocityCapActive(next_block_height));
        expected_tip_hash = chainman.ActiveTip()->GetBlockHash();
        expected_tip_height = chainman.ActiveTip()->nHeight;
        window_blocks = chainman.GetConsensus().nShieldedUnshieldVelocityWindowBlocks;
        ShieldedUnshieldVelocity expected_velocity;
        expected_velocity.RecordBlock(chainman.ActiveTip()->nHeight, 0);
        expected_velocity.Prune(
            chainman.ActiveTip()->nHeight -
            2 * static_cast<int32_t>(window_blocks));
        BOOST_REQUIRE(chainman.WriteShieldedUnshieldVelocityForTest(expected_velocity));
        const auto state_pin = chainman.ComputeShieldedSnapshotStatePin();
        BOOST_REQUIRE(state_pin.has_value());
        expected_state_pin = *state_pin;

        ShieldedUnshieldVelocity bogus_velocity;
        bogus_velocity.RecordBlock(chainman.ActiveTip()->nHeight, 123 * COIN);
        BOOST_REQUIRE(chainman.WriteShieldedUnshieldVelocityForTest(bogus_velocity));
        ShieldedUnshieldVelocity persisted_velocity;
        BOOST_REQUIRE(chainman.ReadShieldedUnshieldVelocity(persisted_velocity));
        BOOST_CHECK_EQUAL(persisted_velocity.WindowTotal(next_block_height, window_blocks), 123 * COIN);
    }

    ChainstateManager& chainman_restarted = simulate_node_restart();
    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        ASSERT_DEBUG_LOG("repaired persisted unshield velocity");
        BOOST_REQUIRE(chainman_restarted.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman_restarted.ActiveTip() != nullptr);
        BOOST_CHECK(chainman_restarted.ActiveTip()->GetBlockHash() == expected_tip_hash);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveTip()->nHeight, expected_tip_height);
        ShieldedUnshieldVelocity restored_velocity;
        BOOST_REQUIRE(chainman_restarted.ReadShieldedUnshieldVelocity(restored_velocity));
        BOOST_CHECK_EQUAL(restored_velocity.WindowTotal(next_block_height, window_blocks), 0);
        const auto restored_state_pin = chainman_restarted.ComputeShieldedSnapshotStatePin();
        BOOST_REQUIRE(restored_state_pin.has_value());
        BOOST_CHECK_EQUAL(*restored_state_pin, expected_state_pin);
        BOOST_CHECK(!chainman_restarted.ReadShieldedMutationMarker().has_value());
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_loads_v9_snapshot_unshield_velocity,
                        RecoveryExitVelocityFastStartupPersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const fs::path shielded_section_path = m_args.GetDataDirNet() / "shielded_v9_velocity.dat";

    node::ShieldedSnapshotSectionHeader header;
    int32_t next_block_height{-1};
    uint32_t window_blocks{0};
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        const CBlockIndex* const tip = chainman.ActiveTip();
        BOOST_REQUIRE(tip != nullptr);
        next_block_height = tip->nHeight == std::numeric_limits<int32_t>::max()
            ? tip->nHeight
            : tip->nHeight + 1;
        BOOST_REQUIRE(chainman.GetConsensus().IsShieldedUnshieldVelocityCapActive(next_block_height));
        window_blocks = chainman.GetConsensus().nShieldedUnshieldVelocityWindowBlocks;
        header = chainman.GetShieldedSnapshotSectionHeader(chainman.ActiveChainstate(), tip);
        BOOST_CHECK_EQUAL(header.m_snapshot_version,
                          node::SHIELDED_SNAPSHOT_UNSHIELD_VELOCITY_VERSION);
        header.m_unshield_velocity.RecordBlock(tip->nHeight, 123 * COIN);
    }

    {
        AutoFile outfile{fsbridge::fopen(shielded_section_path, "wb")};
        BOOST_REQUIRE(!outfile.IsNull());
        BOOST_REQUIRE_EQUAL(outfile.fclose(), 0);
    }

    {
        LOCK(::cs_main);
        const CBlockIndex* const tip = chainman.ActiveTip();
        BOOST_REQUIRE(tip != nullptr);
        AutoFile infile{fsbridge::fopen(shielded_section_path, "rb")};
        BOOST_REQUIRE(!infile.IsNull());
        BOOST_REQUIRE(chainman.LoadShieldedSnapshotSection(infile, header, tip));

        ShieldedUnshieldVelocity loaded_velocity;
        BOOST_REQUIRE(chainman.ReadShieldedUnshieldVelocity(loaded_velocity));
        BOOST_CHECK_EQUAL(loaded_velocity.WindowTotal(next_block_height, window_blocks), 123 * COIN);
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_wrong_snapshot_pin_restores_previous_state,
                        RecoveryExitVelocityFastStartupPersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const fs::path shielded_section_path =
        m_args.GetDataDirNet() / "shielded_wrong_pin_rollback.dat";

    node::ShieldedSnapshotSectionHeader header;
    uint256 original_pin;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        const CBlockIndex* const tip = chainman.ActiveTip();
        BOOST_REQUIRE(tip != nullptr);
        const auto pin{chainman.ComputeShieldedSnapshotStatePin()};
        BOOST_REQUIRE(pin.has_value());
        original_pin = *pin;
        header = chainman.GetShieldedSnapshotSectionHeader(
            chainman.ActiveChainstate(), tip);
        BOOST_CHECK_EQUAL(header.m_commitment_count, 0U);
        BOOST_CHECK_EQUAL(header.m_nullifier_count, 0U);
        BOOST_CHECK_EQUAL(header.m_recovery_exit_commitment_count, 0U);
        BOOST_CHECK_EQUAL(header.m_settlement_anchor_count, 0U);
        BOOST_CHECK_EQUAL(header.m_netting_manifest_count, 0U);
        BOOST_CHECK_EQUAL(header.m_account_registry_entry_count, 0U);
    }
    {
        AutoFile outfile{fsbridge::fopen(shielded_section_path, "wb")};
        BOOST_REQUIRE(!outfile.IsNull());
        BOOST_REQUIRE_EQUAL(outfile.fclose(), 0);
    }

    {
        LOCK(::cs_main);
        const CBlockIndex* const tip = chainman.ActiveTip();
        BOOST_REQUIRE(tip != nullptr);
        uint256 wrong_pin{*uint256::FromHex(std::string(64, 'f'))};
        if (wrong_pin == original_pin) {
            wrong_pin = *uint256::FromHex(std::string(64, 'e'));
        }
        AutoFile infile{fsbridge::fopen(shielded_section_path, "rb")};
        BOOST_REQUIRE(!infile.IsNull());
        auto result{chainman.LoadShieldedSnapshotSection(
            infile, header, tip,
            ChainstateManager::ShieldedSnapshotPinPolicy{
                .required_pin = wrong_pin,
                .persist_accepted_pin = true,
            })};
        BOOST_CHECK(!result);
        BOOST_CHECK(util::ErrorString(result).original.find(
                        "does not match the consensus-pinned commitment") !=
                    std::string::npos);

        // The failing import closed the staging stores and restored the old
        // directories. Reinitialization must recover the exact previous pin.
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        const auto restored_pin{chainman.ComputeShieldedSnapshotStatePin()};
        BOOST_REQUIRE(restored_pin.has_value());
        BOOST_CHECK_EQUAL(*restored_pin, original_pin);
    }

    // A later sidecar/base-blockhash failure exercises the same deferred
    // completion with commit=false. The old state must remain live, not merely
    // have its directories put back on disk.
    {
        LOCK(::cs_main);
        const CBlockIndex* const tip = chainman.ActiveTip();
        BOOST_REQUIRE(tip != nullptr);
        std::function<bool(bool)> finish_snapshot;
        AutoFile infile{fsbridge::fopen(shielded_section_path, "rb")};
        BOOST_REQUIRE(!infile.IsNull());
        auto result{chainman.LoadShieldedSnapshotSection(
            infile, header, tip,
            ChainstateManager::ShieldedSnapshotPinPolicy{
                .required_pin = original_pin,
                .persist_accepted_pin = true,
                .deferred_completion = &finish_snapshot,
            })};
        BOOST_REQUIRE(result);
        BOOST_REQUIRE(finish_snapshot);
        BOOST_REQUIRE(finish_snapshot(false));
        const auto restored_pin{chainman.ComputeShieldedSnapshotStatePin()};
        BOOST_REQUIRE(restored_pin.has_value());
        BOOST_CHECK_EQUAL(*restored_pin, original_pin);
        BOOST_CHECK(chainman.HasShieldedState());
    }

    // Operational proof that the restored in-memory handles can still advance.
    mineBlocks(1);
}

BOOST_FIXTURE_TEST_CASE(shielded_snapshot_transaction_crash_recovery,
                        BasicTestingSetup)
{
    const fs::path datadir{m_args.GetDataDirNet()};
    const fs::path live_root{datadir / "shielded_state"};
    const fs::path live_nullifiers{live_root / "nullifiers"};
    const std::string backup_name{
        "shielded_state_snapshot_backup_" + std::string(64, 'a')};
    const fs::path backup_root{
        datadir / fs::PathFromString(backup_name)};
    const fs::path marker_path{datadir /
                               "shielded_state_snapshot_transaction"};
    constexpr uint8_t BACKUP_COMPLETE{2};
    constexpr uint8_t ROLLING_BACK{3};

    auto write_marker = [&](uint8_t phase) {
        DataStream marker;
        marker << uint32_t{1} << phase << backup_name;
        BOOST_REQUIRE(WriteBinaryFile(
            marker_path,
            std::string{reinterpret_cast<const char*>(marker.data()),
                        marker.size()}));
    };
    auto write_payload = [](const fs::path& path, std::string_view payload) {
        fs::create_directories(path);
        BOOST_REQUIRE(WriteBinaryFile(path / "identity", std::string{payload}));
    };

    // Pre-base crash: old data is in backup, imported partial data occupies
    // live paths, and no discoverable snapshot commit exists. Recovery must
    // remove partial live state and restore the old directory atomically.
    write_payload(backup_root / "nullifiers", "old-state");
    write_payload(live_nullifiers, "partial-new-state");
    write_marker(BACKUP_COMPLETE);
    BOOST_REQUIRE(
        ChainstateManager::RecoverInterruptedShieldedSnapshotForTest(datadir));
    const auto [old_ok, old_bytes]{ReadBinaryFile(live_nullifiers / "identity")};
    BOOST_REQUIRE(old_ok);
    BOOST_CHECK_EQUAL(old_bytes, "old-state");
    BOOST_CHECK(!fs::exists(backup_root));
    BOOST_CHECK(!fs::exists(marker_path));

    // Mid-rollback crash: nullifiers were already restored and removed from
    // the backup, while commitments remain backed up. ROLLING_BACK recovery
    // must not erase the already-restored live directory when completing the
    // remaining rename.
    const fs::path live_commitments{live_root / "commitments"};
    write_payload(backup_root / "commitments", "old-commitments");
    write_payload(live_commitments, "partial-new-commitments");
    write_marker(ROLLING_BACK);
    BOOST_REQUIRE(
        ChainstateManager::RecoverInterruptedShieldedSnapshotForTest(datadir));
    const auto [resumed_nullifiers_ok, resumed_nullifiers]{
        ReadBinaryFile(live_nullifiers / "identity")};
    const auto [resumed_commitments_ok, resumed_commitments]{
        ReadBinaryFile(live_commitments / "identity")};
    BOOST_REQUIRE(resumed_nullifiers_ok);
    BOOST_REQUIRE(resumed_commitments_ok);
    BOOST_CHECK_EQUAL(resumed_nullifiers, "old-state");
    BOOST_CHECK_EQUAL(resumed_commitments, "old-commitments");
    BOOST_CHECK(!fs::exists(backup_root));
    BOOST_CHECK(!fs::exists(marker_path));

    // A malformed backup fails closed without deleting the only old copy or
    // its retry marker. Once the unexpected entry is removed, recovery can
    // safely resume the same transaction.
    write_payload(backup_root / "nullifiers", "retry-old-state");
    write_payload(backup_root / "unexpected", "do-not-delete-backup");
    write_payload(live_nullifiers, "retry-partial-new-state");
    write_marker(BACKUP_COMPLETE);
    BOOST_CHECK(
        !ChainstateManager::RecoverInterruptedShieldedSnapshotForTest(datadir));
    BOOST_CHECK(fs::exists(backup_root / "nullifiers" / "identity"));
    BOOST_CHECK(fs::exists(marker_path));
    fs::remove_all(backup_root / "unexpected");
    BOOST_REQUIRE(
        ChainstateManager::RecoverInterruptedShieldedSnapshotForTest(datadir));
    const auto [retry_ok, retry_bytes]{
        ReadBinaryFile(live_nullifiers / "identity")};
    BOOST_REQUIRE(retry_ok);
    BOOST_CHECK_EQUAL(retry_bytes, "retry-old-state");

    // Post-base crash: base_blockhash is the final snapshot discovery commit,
    // so recovery keeps new live state and discards only the stale backup.
    write_payload(backup_root / "nullifiers", "old-state-2");
    BOOST_REQUIRE(WriteBinaryFile(live_nullifiers / "identity",
                                  "committed-new-state"));
    write_marker(BACKUP_COMPLETE);
    const fs::path snapshot_dir{datadir / "chainstate_snapshot"};
    write_payload(snapshot_dir, "unused");
    BOOST_REQUIRE(WriteBinaryFile(snapshot_dir /
                                      node::SNAPSHOT_BLOCKHASH_FILENAME,
                                  std::string(32, '\x01')));
    BOOST_REQUIRE(
        ChainstateManager::RecoverInterruptedShieldedSnapshotForTest(datadir));
    const auto [new_ok, new_bytes]{ReadBinaryFile(live_nullifiers / "identity")};
    BOOST_REQUIRE(new_ok);
    BOOST_CHECK_EQUAL(new_bytes, "committed-new-state");
    BOOST_CHECK(!fs::exists(backup_root));
    BOOST_CHECK(!fs::exists(marker_path));
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_loads_legacy_snapshot_rebuilds_unshield_velocity,
                        RecoveryExitVelocityFastStartupPersistedTestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const fs::path shielded_section_path = m_args.GetDataDirNet() / "shielded_v8_velocity.dat";

    node::ShieldedSnapshotSectionHeader header;
    int32_t next_block_height{-1};
    uint32_t window_blocks{0};
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        const CBlockIndex* const tip = chainman.ActiveTip();
        BOOST_REQUIRE(tip != nullptr);
        next_block_height = tip->nHeight == std::numeric_limits<int32_t>::max()
            ? tip->nHeight
            : tip->nHeight + 1;
        BOOST_REQUIRE(chainman.GetConsensus().IsShieldedUnshieldVelocityCapActive(next_block_height));
        window_blocks = chainman.GetConsensus().nShieldedUnshieldVelocityWindowBlocks;
        header = chainman.GetShieldedSnapshotSectionHeader(chainman.ActiveChainstate(), tip);
        header.m_snapshot_version = node::SHIELDED_SNAPSHOT_RECOVERY_EXIT_COMMITMENTS_VERSION;
        header.m_unshield_velocity.RecordBlock(tip->nHeight, 123 * COIN);
    }

    {
        AutoFile outfile{fsbridge::fopen(shielded_section_path, "wb")};
        BOOST_REQUIRE(!outfile.IsNull());
        BOOST_REQUIRE_EQUAL(outfile.fclose(), 0);
    }

    {
        LOCK(::cs_main);
        const CBlockIndex* const tip = chainman.ActiveTip();
        BOOST_REQUIRE(tip != nullptr);
        AutoFile infile{fsbridge::fopen(shielded_section_path, "rb")};
        BOOST_REQUIRE(!infile.IsNull());
        BOOST_REQUIRE(chainman.LoadShieldedSnapshotSection(infile, header, tip));

        ShieldedUnshieldVelocity loaded_velocity;
        BOOST_REQUIRE(chainman.ReadShieldedUnshieldVelocity(loaded_velocity));
        BOOST_CHECK_EQUAL(loaded_velocity.WindowTotal(next_block_height, window_blocks), 0);
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
        BOOST_REQUIRE(chainman.WriteSnapshotBridgeMetadataHintForTest(true));
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

    BOOST_CHECK_EQUAL(get_valid_opts({}).prevoutfetch_threads_num, DEFAULT_PREVOUTFETCH_THREADS);
    BOOST_CHECK_EQUAL(get_valid_opts({"-prevoutfetchthreads=0"}).prevoutfetch_threads_num, 0);
    BOOST_CHECK_EQUAL(get_valid_opts({"-prevoutfetchthreads=3"}).prevoutfetch_threads_num, 3);
    BOOST_CHECK_EQUAL(get_valid_opts({"-prevoutfetchthreads=100"}).prevoutfetch_threads_num, MAX_PREVOUTFETCH_THREADS);
    BOOST_CHECK(!get_opts({"-prevoutfetchthreads=-1"}));

    // test deep-reorg defense profiles, defaults, and overrides
    const auto default_reorg_opts = get_valid_opts({});
    BOOST_CHECK(default_reorg_opts.reorg_protection_profile == kernel::ReorgProtectionProfile::EMERGENCY);
    BOOST_CHECK(default_reorg_opts.deep_reorg_action == kernel::DeepReorgAction::PARK);
    const auto default_profile = kernel::GetReorgProtectionProfileSettings(default_reorg_opts.reorg_protection_profile);
    BOOST_CHECK_EQUAL(default_profile.warn_depth, 3U);
    BOOST_CHECK_EQUAL(default_profile.park_depth, 6U);
    BOOST_CHECK_EQUAL(default_profile.finality_depth, 72U);
    BOOST_CHECK_EQUAL(default_profile.hysteresis_depth, 0U);
    BOOST_CHECK_EQUAL(default_profile.hysteresis_work_margin, 2U);

    const auto standard_opts = get_valid_opts({"-reorgprotectionprofile=standard"});
    BOOST_CHECK(standard_opts.reorg_protection_profile == kernel::ReorgProtectionProfile::STANDARD);
    BOOST_CHECK(standard_opts.deep_reorg_action == kernel::DeepReorgAction::WARN);
    const auto miner_opts = get_valid_opts({"-reorgprotectionprofile=MINER"});
    BOOST_CHECK(miner_opts.reorg_protection_profile == kernel::ReorgProtectionProfile::STANDARD);
    BOOST_CHECK(miner_opts.deep_reorg_action == kernel::DeepReorgAction::WARN);

    const auto archive_opts = get_valid_opts({"-reorgprotectionprofile=archive"});
    BOOST_CHECK(archive_opts.reorg_protection_profile == kernel::ReorgProtectionProfile::ARCHIVE);
    BOOST_CHECK(archive_opts.deep_reorg_action == kernel::DeepReorgAction::WARN);
    const auto archive_profile = kernel::GetReorgProtectionProfileSettings(archive_opts.reorg_protection_profile);
    BOOST_CHECK_EQUAL(archive_profile.warn_depth, 72U);
    BOOST_CHECK_EQUAL(archive_profile.park_depth, kernel::REORG_PROTECTION_DEPTH_DISABLED);
    BOOST_CHECK_EQUAL(archive_profile.finality_depth, 72U);
    BOOST_CHECK_EQUAL(archive_profile.hysteresis_depth, 0U);
    BOOST_CHECK_EQUAL(archive_profile.hysteresis_work_margin, 2U);

    const auto balanced_opts = get_valid_opts({"-reorgprotectionprofile=balanced"});
    BOOST_CHECK(balanced_opts.reorg_protection_profile == kernel::ReorgProtectionProfile::BALANCED);
    BOOST_CHECK(balanced_opts.deep_reorg_action == kernel::DeepReorgAction::WARN);
    const auto balanced_profile = kernel::GetReorgProtectionProfileSettings(balanced_opts.reorg_protection_profile);
    BOOST_CHECK_EQUAL(balanced_profile.warn_depth, 12U);
    BOOST_CHECK_EQUAL(balanced_profile.park_depth, kernel::REORG_PROTECTION_DEPTH_DISABLED);
    BOOST_CHECK_EQUAL(balanced_profile.finality_depth, 48U);
    BOOST_CHECK_EQUAL(balanced_profile.hysteresis_depth, 0U);
    BOOST_CHECK_EQUAL(balanced_profile.hysteresis_work_margin, 2U);

    const auto strict_opts = get_valid_opts({"-reorgprotectionprofile=STRICT"});
    BOOST_CHECK(strict_opts.reorg_protection_profile == kernel::ReorgProtectionProfile::STRICT);
    BOOST_CHECK(strict_opts.deep_reorg_action == kernel::DeepReorgAction::WARN);
    const auto strict_profile = kernel::GetReorgProtectionProfileSettings(strict_opts.reorg_protection_profile);
    BOOST_CHECK_EQUAL(strict_profile.warn_depth, 3U);
    BOOST_CHECK_EQUAL(strict_profile.park_depth, kernel::REORG_PROTECTION_DEPTH_DISABLED);
    BOOST_CHECK_EQUAL(strict_profile.finality_depth, 12U);
    BOOST_CHECK_EQUAL(strict_profile.hysteresis_depth, 0U);
    BOOST_CHECK_EQUAL(strict_profile.hysteresis_work_margin, 2U);

    const auto emergency_opts = get_valid_opts({"-reorgprotectionprofile=emergency"});
    BOOST_CHECK(emergency_opts.reorg_protection_profile == kernel::ReorgProtectionProfile::EMERGENCY);
    BOOST_CHECK(emergency_opts.deep_reorg_action == kernel::DeepReorgAction::PARK);
    const auto emergency_profile = kernel::GetReorgProtectionProfileSettings(emergency_opts.reorg_protection_profile);
    BOOST_CHECK_EQUAL(emergency_profile.warn_depth, 3U);
    BOOST_CHECK_EQUAL(emergency_profile.park_depth, 6U);
    BOOST_CHECK_EQUAL(emergency_profile.finality_depth, 72U);
    BOOST_CHECK_EQUAL(emergency_profile.hysteresis_depth, 0U);
    BOOST_CHECK_EQUAL(emergency_profile.hysteresis_work_margin, 2U);

    BOOST_CHECK(get_valid_opts({"-reorgprotectionprofile=archive", "-parkdeepreorg=1"}).deep_reorg_action == kernel::DeepReorgAction::PARK);
    BOOST_CHECK(get_valid_opts({"-parkdeepreorg=1"}).deep_reorg_action == kernel::DeepReorgAction::PARK);
    BOOST_CHECK(get_valid_opts({"-parkdeepreorg=0"}).deep_reorg_action == kernel::DeepReorgAction::WARN);
    BOOST_CHECK(get_valid_opts({"-noparkdeepreorg"}).deep_reorg_action == kernel::DeepReorgAction::WARN);
    BOOST_CHECK(!default_reorg_opts.max_reorg_depth_warn.has_value());
    BOOST_CHECK(!default_reorg_opts.max_reorg_depth_park.has_value());
    BOOST_CHECK(!default_reorg_opts.local_finality_depth.has_value());
    BOOST_CHECK(!default_reorg_opts.reorg_hysteresis_depth.has_value());
    BOOST_CHECK(!default_reorg_opts.reorg_hysteresis_work_margin.has_value());
    const auto max_reorg_opts = get_valid_opts({
        "-maxreorgdepthwarn=48",
        "-maxreorgdepthpark=96",
        "-localfinalitydepth=120",
        "-reorghysteresisdepth=4",
        "-reorghysteresisworkmargin=3",
    });
    BOOST_REQUIRE(max_reorg_opts.max_reorg_depth_warn.has_value());
    BOOST_REQUIRE(max_reorg_opts.max_reorg_depth_park.has_value());
    BOOST_REQUIRE(max_reorg_opts.local_finality_depth.has_value());
    BOOST_REQUIRE(max_reorg_opts.reorg_hysteresis_depth.has_value());
    BOOST_REQUIRE(max_reorg_opts.reorg_hysteresis_work_margin.has_value());
    BOOST_CHECK_EQUAL(*max_reorg_opts.max_reorg_depth_warn, 48U);
    BOOST_CHECK_EQUAL(*max_reorg_opts.max_reorg_depth_park, 96U);
    BOOST_CHECK_EQUAL(*max_reorg_opts.local_finality_depth, 120U);
    BOOST_CHECK_EQUAL(*max_reorg_opts.reorg_hysteresis_depth, 4U);
    BOOST_CHECK_EQUAL(*max_reorg_opts.reorg_hysteresis_work_margin, 3U);
    BOOST_CHECK(!get_opts({"-reorgprotectionprofile=invalid"}));
    BOOST_CHECK(!get_opts({"-maxreorgdepthwarn=0"}));
    BOOST_CHECK(!get_opts({"-maxreorgdepthwarn=-1"}));
    BOOST_CHECK(!get_opts({"-maxreorgdepthpark=0"}));
    BOOST_CHECK(!get_opts({"-maxreorgdepthpark=-1"}));
    BOOST_CHECK(!get_opts({"-localfinalitydepth=0"}));
    BOOST_CHECK(!get_opts({"-localfinalitydepth=-1"}));
    BOOST_REQUIRE(get_valid_opts({"-reorghysteresisdepth=0"}).reorg_hysteresis_depth.has_value());
    BOOST_CHECK_EQUAL(
        *get_valid_opts({"-reorghysteresisdepth=0"}).reorg_hysteresis_depth,
        0U);
    BOOST_CHECK(!get_opts({"-reorghysteresisdepth=-1"}));
    BOOST_CHECK(get_valid_opts({"-reorghysteresisworkmargin=0"}).reorg_hysteresis_work_margin.has_value());
    BOOST_CHECK(!get_opts({"-reorghysteresisworkmargin=-1"}));

    // TEST: tier_config_flag_sets_behavior
    // TEST: mining_node_implicitly_tier0
    // test -matmulvalidation
    BOOST_CHECK_EQUAL(get_valid_opts({}).matmul_validation_mode, kernel::MatMulValidationMode::CONSENSUS);
    BOOST_CHECK_EQUAL(get_valid_opts({"-matmulvalidation=consensus"}).matmul_validation_mode, kernel::MatMulValidationMode::CONSENSUS);
    BOOST_CHECK_EQUAL(get_valid_opts({"-matmulvalidation=trusted"}).matmul_validation_mode, kernel::MatMulValidationMode::TRUSTED);
    BOOST_CHECK_EQUAL(get_valid_opts({"-matmulvalidation=economic"}).matmul_validation_mode, kernel::MatMulValidationMode::ECONOMIC);
    BOOST_CHECK_EQUAL(get_valid_opts({"-matmulvalidation=spv"}).matmul_validation_mode, kernel::MatMulValidationMode::SPV);
    BOOST_CHECK(!get_opts({"-matmulvalidation=invalid"}));

    BOOST_CHECK_EQUAL(get_valid_opts({}).retain_shielded_commitment_index, true);
    BOOST_CHECK_EQUAL(get_valid_opts({"-retainshieldedcommitmentindex"}).retain_shielded_commitment_index, true);
    BOOST_CHECK_EQUAL(get_valid_opts({"-retainshieldedcommitmentindex=1"}).retain_shielded_commitment_index, true);
    BOOST_CHECK_EQUAL(get_valid_opts({"-retainshieldedcommitmentindex=0"}).retain_shielded_commitment_index, false);

    // Zero-downtime fast restart is the default; -fastshieldedstartup=0 is the thorough opt-out.
    BOOST_CHECK_EQUAL(get_valid_opts({}).fast_shielded_startup, true);
    BOOST_CHECK_EQUAL(get_valid_opts({"-fastshieldedstartup"}).fast_shielded_startup, true);
    BOOST_CHECK_EQUAL(get_valid_opts({"-fastshieldedstartup=1"}).fast_shielded_startup, true);
    BOOST_CHECK_EQUAL(get_valid_opts({"-fastshieldedstartup=0"}).fast_shielded_startup, false);

    // -resetshieldedstate is a one-shot repair flag, off by default, opt-in to force a clean rebuild.
    BOOST_CHECK_EQUAL(get_valid_opts({}).reset_shielded_state, false);
    BOOST_CHECK_EQUAL(get_valid_opts({"-resetshieldedstate"}).reset_shielded_state, true);
    BOOST_CHECK_EQUAL(get_valid_opts({"-resetshieldedstate=1"}).reset_shielded_state, true);
    BOOST_CHECK_EQUAL(get_valid_opts({"-resetshieldedstate=0"}).reset_shielded_state, false);

    // The cross-chain startup audit is on by default (applies on the non-fast path).
    BOOST_CHECK_EQUAL(get_valid_opts({}).shielded_startup_audit, true);
    BOOST_CHECK_EQUAL(get_valid_opts({"-shieldedstartupaudit"}).shielded_startup_audit, true);
    BOOST_CHECK_EQUAL(get_valid_opts({"-shieldedstartupaudit=1"}).shielded_startup_audit, true);
    BOOST_CHECK_EQUAL(get_valid_opts({"-shieldedstartupaudit=0"}).shielded_startup_audit, false);
}

BOOST_AUTO_TEST_SUITE_END()
