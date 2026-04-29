// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <random.h>
#include <kernel/mempool_entry.h>
#include <shielded/lattice/params.h>
#include <shielded/v2_bundle.h>
#include <test/util/shielded_account_registry_test_util.h>
#include <test/util/setup_common.h>
#include <test/util/shielded_smile_test_util.h>
#include <test/util/shielded_v2_egress_fixture.h>
#include <test/util/txmempool.h>
#include <txmempool.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

namespace {

smile2::CompactPublicAccount MakeSmileAccount(uint32_t seed)
{
    return test::shielded::MakeDeterministicCompactPublicAccount(seed);
}

CMutableTransaction BuildShieldedTx(const Nullifier& nf)
{
    CMutableTransaction mtx;
    CShieldedInput in;
    in.nullifier = nf;
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        in.ring_positions.push_back(i);
    }
    mtx.shielded_bundle.shielded_inputs.push_back(in);
    mtx.shielded_bundle.proof = {0x01};

    CShieldedOutput out;
    out.note_commitment = GetRandHash();
    out.merkle_anchor = GetRandHash();
    mtx.shielded_bundle.shielded_outputs.push_back(out);
    return mtx;
}

CMutableTransaction BuildShieldedV2SendTx(const Nullifier& nf,
                                          const uint256& spend_anchor,
                                          const uint256& account_registry_anchor = uint256{})
{
    using namespace shielded::v2;

    const auto spend_account = MakeSmileAccount(0x60);
    const uint256 spend_note_commitment = uint256{0x61};
    const auto registry_witness =
        test::shielded::MakeSingleLeafRegistryWitness(spend_note_commitment, spend_account);
    BOOST_REQUIRE(registry_witness.has_value());

    EncryptedNotePayload encrypted_note;
    encrypted_note.scan_domain = ScanDomain::USER;
    encrypted_note.scan_hint.fill(0x31);
    encrypted_note.ciphertext = {0x51, 0x52};
    encrypted_note.ephemeral_key = ComputeLegacyPayloadEphemeralKey(
        Span<const uint8_t>{encrypted_note.ciphertext.data(), encrypted_note.ciphertext.size()});

    SpendDescription spend;
    spend.nullifier = nf;
    spend.merkle_anchor = spend_anchor;
    spend.account_leaf_commitment = registry_witness->second.account_leaf_commitment;
    spend.account_registry_proof = registry_witness->second;
    spend.note_commitment = spend_note_commitment;
    spend.value_commitment = uint256{0x62};

    OutputDescription output;
    output.note_class = NoteClass::USER;
    output.smile_account = MakeSmileAccount(0x63);
    output.note_commitment = smile2::ComputeCompactPublicAccountHash(*output.smile_account);
    output.value_commitment = uint256{0x64};
    output.encrypted_note = encrypted_note;

    SendPayload payload;
    payload.spend_anchor = spend_anchor;
    payload.account_registry_anchor =
        account_registry_anchor.IsNull() ? registry_witness->first : account_registry_anchor;
    payload.spends = {spend};
    payload.outputs = {output};
    payload.fee = 1;
    payload.value_balance = payload.fee;

    ProofEnvelope envelope;
    envelope.proof_kind = ProofKind::DIRECT_SMILE;
    envelope.membership_proof_kind = ProofComponentKind::SMILE_MEMBERSHIP;
    envelope.amount_proof_kind = ProofComponentKind::SMILE_BALANCE;
    envelope.balance_proof_kind = ProofComponentKind::SMILE_BALANCE;
    envelope.settlement_binding_kind = SettlementBindingKind::NONE;
    envelope.statement_digest = uint256{0x65};

    TransactionBundle tx_bundle;
    tx_bundle.header.family_id = TransactionFamily::V2_SEND;
    tx_bundle.header.proof_envelope = envelope;
    tx_bundle.header.payload_digest = ComputeSendPayloadDigest(payload);
    tx_bundle.payload = payload;
    tx_bundle.proof_payload = {0x71, 0x72};

    CMutableTransaction mtx;
    mtx.shielded_bundle.v2_bundle = tx_bundle;
    return mtx;
}

CMutableTransaction BuildShieldedV2SpendPathRecoveryTx(
    const Nullifier& nf,
    const uint256& spend_anchor)
{
    using namespace shielded::v2;

    const auto spend_account = MakeSmileAccount(0x70);
    const uint256 spend_note_commitment = uint256{0x71};
    const auto registry_witness =
        test::shielded::MakeSingleLeafRegistryWitness(spend_note_commitment, spend_account);
    BOOST_REQUIRE(registry_witness.has_value());

    EncryptedNotePayload encrypted_note;
    encrypted_note.scan_domain = ScanDomain::OPAQUE;
    encrypted_note.scan_hint.fill(0x41);
    encrypted_note.ciphertext = {0x61, 0x62};
    encrypted_note.ephemeral_key = ComputeLegacyPayloadEphemeralKey(
        Span<const uint8_t>{encrypted_note.ciphertext.data(), encrypted_note.ciphertext.size()});

    SpendDescription spend;
    spend.nullifier = nf;
    spend.merkle_anchor = spend_anchor;
    spend.account_leaf_commitment = registry_witness->second.account_leaf_commitment;
    spend.account_registry_proof = registry_witness->second;
    spend.note_commitment = spend_note_commitment;
    spend.value_commitment = uint256{0x72};

    OutputDescription output;
    output.note_class = NoteClass::USER;
    output.smile_account = MakeSmileAccount(0x73);
    output.note_commitment = smile2::ComputeCompactPublicAccountHash(*output.smile_account);
    output.value_commitment = uint256{0x74};
    output.encrypted_note = encrypted_note;

    SpendPathRecoveryPayload payload;
    payload.spend_anchor = spend_anchor;
    payload.spends = {spend};
    payload.outputs = {output};
    payload.fee = 1;

    ProofEnvelope envelope;
    envelope.proof_kind = ProofKind::DIRECT_SMILE;
    envelope.membership_proof_kind = ProofComponentKind::SMILE_MEMBERSHIP;
    envelope.amount_proof_kind = ProofComponentKind::SMILE_BALANCE;
    envelope.balance_proof_kind = ProofComponentKind::SMILE_BALANCE;
    envelope.settlement_binding_kind = SettlementBindingKind::NONE;
    envelope.statement_digest = uint256{0x75};

    TransactionBundle tx_bundle;
    tx_bundle.header.family_id = V2_SPEND_PATH_RECOVERY;
    tx_bundle.header.proof_envelope = envelope;
    tx_bundle.header.payload_digest = ComputeSpendPathRecoveryPayloadDigest(payload);
    tx_bundle.payload = payload;
    tx_bundle.proof_payload = {0x81, 0x82};

    CMutableTransaction mtx;
    mtx.shielded_bundle.v2_bundle = tx_bundle;
    return mtx;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(shielded_mempool_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(shielded_nullifier_conflict_detected)
{
    bilingual_str error;
    CTxMemPool pool{MemPoolOptionsForTest(m_node), error};
    BOOST_REQUIRE(error.empty());

    const Nullifier nf = GetRandHash();
    const CTransaction tx{BuildShieldedTx(nf)};

    LOCK(pool.cs);
    pool.m_shielded_nullifiers.emplace(nf, Txid::FromUint256(GetRandHash()));
    BOOST_CHECK(pool.HasShieldedNullifierConflict(tx));
}

BOOST_AUTO_TEST_CASE(shielded_nullifier_conflict_not_detected)
{
    bilingual_str error;
    CTxMemPool pool{MemPoolOptionsForTest(m_node), error};
    BOOST_REQUIRE(error.empty());

    const CTransaction tx{BuildShieldedTx(GetRandHash())};
    LOCK(pool.cs);
    BOOST_CHECK(!pool.HasShieldedNullifierConflict(tx));
}

BOOST_AUTO_TEST_CASE(shielded_v2_nullifier_conflict_detected)
{
    bilingual_str error;
    CTxMemPool pool{MemPoolOptionsForTest(m_node), error};
    BOOST_REQUIRE(error.empty());

    const Nullifier nf = GetRandHash();
    const CTransaction tx{BuildShieldedV2SendTx(nf, GetRandHash())};

    LOCK(pool.cs);
    pool.m_shielded_nullifiers.emplace(nf, Txid::FromUint256(GetRandHash()));
    BOOST_CHECK(pool.HasShieldedNullifierConflict(tx));
}

BOOST_AUTO_TEST_CASE(shielded_v2_spend_path_recovery_nullifier_conflict_detected)
{
    bilingual_str error;
    CTxMemPool pool{MemPoolOptionsForTest(m_node), error};
    BOOST_REQUIRE(error.empty());

    const Nullifier nf = GetRandHash();
    const CTransaction tx{BuildShieldedV2SpendPathRecoveryTx(nf, GetRandHash())};

    LOCK(pool.cs);
    pool.m_shielded_nullifiers.emplace(nf, Txid::FromUint256(GetRandHash()));
    BOOST_CHECK(pool.HasShieldedNullifierConflict(tx));
}

BOOST_AUTO_TEST_CASE(shielded_nullifier_conflict_reports_direct_conflict_txid)
{
    bilingual_str error;
    CTxMemPool pool{MemPoolOptionsForTest(m_node), error};
    BOOST_REQUIRE(error.empty());

    const Nullifier nf = GetRandHash();
    const Txid conflicting_txid = Txid::FromUint256(GetRandHash());
    const CTransaction tx{BuildShieldedTx(nf)};

    LOCK(pool.cs);
    pool.m_shielded_nullifiers.emplace(nf, conflicting_txid);
    const auto conflicts = pool.GetShieldedNullifierConflicts(tx);
    BOOST_CHECK(!conflicts.invalid_in_tx);
    BOOST_CHECK_EQUAL(conflicts.txids.size(), 1U);
    BOOST_CHECK(conflicts.txids.count(conflicting_txid));
}

BOOST_AUTO_TEST_CASE(shielded_nullifier_duplicate_within_tx_detected)
{
    bilingual_str error;
    CTxMemPool pool{MemPoolOptionsForTest(m_node), error};
    BOOST_REQUIRE(error.empty());

    const Nullifier nf = GetRandHash();
    CMutableTransaction mtx = BuildShieldedTx(nf);
    CShieldedInput dup = mtx.shielded_bundle.shielded_inputs.front();
    mtx.shielded_bundle.shielded_inputs.push_back(dup);

    LOCK(pool.cs);
    BOOST_CHECK(pool.HasShieldedNullifierConflict(CTransaction{mtx}));
}

BOOST_AUTO_TEST_CASE(shielded_v2_spend_path_recovery_duplicate_within_tx_detected)
{
    bilingual_str error;
    CTxMemPool pool{MemPoolOptionsForTest(m_node), error};
    BOOST_REQUIRE(error.empty());

    const Nullifier nf = GetRandHash();
    CMutableTransaction mtx = BuildShieldedV2SpendPathRecoveryTx(nf, GetRandHash());
    auto& payload = std::get<shielded::v2::SpendPathRecoveryPayload>(
        mtx.shielded_bundle.v2_bundle->payload);
    auto dup = payload.spends.front();
    payload.spends.push_back(dup);
    mtx.shielded_bundle.v2_bundle->header.payload_digest =
        shielded::v2::ComputeSpendPathRecoveryPayloadDigest(payload);

    LOCK(pool.cs);
    BOOST_CHECK(pool.HasShieldedNullifierConflict(CTransaction{mtx}));
}

BOOST_AUTO_TEST_CASE(shielded_entry_allows_negative_value_balance_fee_accounting)
{
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.shielded_bundle.value_balance = -999'999'000; // 10 BTC transparent in minus 1000 sat fee.

    CTransactionRef tx = MakeTransactionRef(mtx);
    CoinAgeCache coin_age{COIN_AGE_CACHE_ZERO};
    coin_age.in_chain_input_value = 10 * COIN;

    const CAmount fee = 1000;
    CTxMemPoolEntry entry(tx, fee, /*time=*/0, /*entry_height=*/1, /*entry_sequence=*/1,
                          coin_age, /*spends_coinbase=*/false, /*extra_weight=*/0,
                          /*sigops_cost=*/0, LockPoints{});

    BOOST_CHECK_EQUAL(entry.GetFee(), fee);
    BOOST_CHECK_EQUAL(entry.GetInternalCoinAgeCache().in_chain_input_value, 10 * COIN);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_CASE(shielded_anchor_cleanup_evicts_only_stale_transactions, TestingSetup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    CTxMemPool& pool = *Assert(m_node.mempool);

    LOCK2(::cs_main, pool.cs);
    BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());

    const uint256 stale_anchor = chainman.GetShieldedMerkleTree().Root();
    BOOST_REQUIRE(!stale_anchor.IsNull());

    CMutableTransaction stale_mtx;
    CShieldedOutput stale_out;
    stale_out.note_commitment = GetRandHash();
    stale_out.merkle_anchor = stale_anchor;
    stale_mtx.shielded_bundle.shielded_outputs.push_back(stale_out);
    const auto stale_tx = MakeTransactionRef(stale_mtx);

    TestMemPoolEntryHelper entry;
    AddToMempool(pool, entry.FromTx(stale_tx));
    BOOST_REQUIRE(pool.exists(GenTxid::Txid(stale_tx->GetHash())));
    BOOST_CHECK(!HasInvalidShieldedAnchors(*stale_tx, chainman));

    for (int i = 0; i <= SHIELDED_ANCHOR_DEPTH; ++i) {
        chainman.RecordShieldedAnchorRoot(GetRandHash());
    }
    BOOST_CHECK(!chainman.IsShieldedAnchorValid(stale_anchor));
    BOOST_CHECK(HasInvalidShieldedAnchors(*stale_tx, chainman));

    const uint256 fresh_anchor = GetRandHash();
    BOOST_REQUIRE(!fresh_anchor.IsNull());
    chainman.RecordShieldedAnchorRoot(fresh_anchor);
    BOOST_CHECK(chainman.IsShieldedAnchorValid(fresh_anchor));

    CMutableTransaction fresh_mtx;
    CShieldedOutput fresh_out;
    fresh_out.note_commitment = GetRandHash();
    fresh_out.merkle_anchor = fresh_anchor;
    fresh_mtx.shielded_bundle.shielded_outputs.push_back(fresh_out);
    const auto fresh_tx = MakeTransactionRef(fresh_mtx);
    AddToMempool(pool, entry.FromTx(fresh_tx));
    BOOST_REQUIRE(pool.exists(GenTxid::Txid(fresh_tx->GetHash())));
    BOOST_CHECK(!HasInvalidShieldedAnchors(*fresh_tx, chainman));

    RemoveStaleShieldedAnchorMempoolTransactions(pool, chainman.ActiveChain(), chainman);

    BOOST_CHECK(!pool.exists(GenTxid::Txid(stale_tx->GetHash())));
    BOOST_CHECK(pool.exists(GenTxid::Txid(fresh_tx->GetHash())));
}

BOOST_FIXTURE_TEST_CASE(shielded_v2_anchor_cleanup_evicts_stale_transactions, TestingSetup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    CTxMemPool& pool = *Assert(m_node.mempool);

    LOCK2(::cs_main, pool.cs);
    BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());

    const uint256 stale_anchor = chainman.GetShieldedMerkleTree().Root();
    const uint256 current_registry_anchor = chainman.GetShieldedAccountRegistryRoot();
    BOOST_REQUIRE(!stale_anchor.IsNull());
    BOOST_REQUIRE(!current_registry_anchor.IsNull());

    const auto stale_tx = MakeTransactionRef(
        BuildShieldedV2SendTx(GetRandHash(), stale_anchor, current_registry_anchor));

    TestMemPoolEntryHelper entry;
    AddToMempool(pool, entry.FromTx(stale_tx));
    BOOST_REQUIRE(pool.exists(GenTxid::Txid(stale_tx->GetHash())));
    BOOST_CHECK(!HasInvalidShieldedAnchors(*stale_tx, chainman));

    for (int i = 0; i <= SHIELDED_ANCHOR_DEPTH; ++i) {
        chainman.RecordShieldedAnchorRoot(GetRandHash());
    }
    BOOST_CHECK(!chainman.IsShieldedAnchorValid(stale_anchor));
    BOOST_CHECK(HasInvalidShieldedAnchors(*stale_tx, chainman));

    RemoveStaleShieldedAnchorMempoolTransactions(pool, chainman.ActiveChain(), chainman);
    BOOST_CHECK(!pool.exists(GenTxid::Txid(stale_tx->GetHash())));
}

BOOST_FIXTURE_TEST_CASE(shielded_v2_registry_anchor_cleanup_evicts_stale_transactions, TestingSetup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    CTxMemPool& pool = *Assert(m_node.mempool);

    LOCK2(::cs_main, pool.cs);
    BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());

    const uint256 spend_anchor = chainman.GetShieldedMerkleTree().Root();
    const uint256 stale_registry_anchor = chainman.GetShieldedAccountRegistryRoot();
    BOOST_REQUIRE(!spend_anchor.IsNull());
    BOOST_REQUIRE(!stale_registry_anchor.IsNull());

    const auto stale_tx = MakeTransactionRef(
        BuildShieldedV2SendTx(GetRandHash(), spend_anchor, stale_registry_anchor));
    const auto stale_txid = GenTxid::Txid(stale_tx->GetHash());

    TestMemPoolEntryHelper entry;
    AddToMempool(pool, entry.FromTx(stale_tx));
    BOOST_REQUIRE(pool.exists(stale_txid));
    BOOST_CHECK(!HasInvalidShieldedAnchors(*stale_tx, chainman));

    for (int i = 0; i <= SHIELDED_ANCHOR_DEPTH; ++i) {
        chainman.RecordShieldedAccountRegistryRoot(GetRandHash());
    }
    BOOST_CHECK(!chainman.IsShieldedAccountRegistryRootValid(stale_registry_anchor));
    BOOST_CHECK(HasInvalidShieldedAnchors(*stale_tx, chainman));

    const uint256 fresh_registry_anchor = GetRandHash();
    BOOST_REQUIRE(!fresh_registry_anchor.IsNull());
    chainman.RecordShieldedAccountRegistryRoot(fresh_registry_anchor);
    BOOST_CHECK(chainman.IsShieldedAccountRegistryRootValid(fresh_registry_anchor));

    const auto fresh_tx = MakeTransactionRef(
        BuildShieldedV2SendTx(GetRandHash(), spend_anchor, fresh_registry_anchor));
    const auto fresh_txid = GenTxid::Txid(fresh_tx->GetHash());
    AddToMempool(pool, entry.FromTx(fresh_tx));
    BOOST_REQUIRE(pool.exists(fresh_txid));
    BOOST_CHECK(!HasInvalidShieldedAnchors(*fresh_tx, chainman));

    RemoveStaleShieldedAnchorMempoolTransactions(pool, chainman.ActiveChain(), chainman);

    BOOST_CHECK(!pool.exists(stale_txid));
    BOOST_CHECK(pool.exists(fresh_txid));
}

BOOST_FIXTURE_TEST_CASE(shielded_v2_egress_cleanup_preserves_valid_anchor_refs_and_evicts_missing_ones, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    CTxMemPool& pool = *Assert(m_node.mempool);

    const auto valid_egress_fixture = test::shielded::BuildV2EgressReceiptFixture(/*output_count=*/2);
    const auto valid_settlement_anchor_fixture =
        test::shielded::BuildV2SettlementAnchorReceiptFixture(/*output_count=*/2);
    const auto invalid_egress_fixture = test::shielded::BuildV2EgressReceiptFixture(/*output_count=*/3);
    const auto invalid_settlement_anchor_fixture =
        test::shielded::BuildV2SettlementAnchorReceiptFixture(/*output_count=*/3);

    const auto valid_egress_tx = MakeTransactionRef(valid_egress_fixture.tx);
    const auto invalid_egress_tx = MakeTransactionRef(invalid_egress_fixture.tx);
    const auto valid_egress_txid = GenTxid::Txid(valid_egress_tx->GetHash());
    const auto invalid_egress_txid = GenTxid::Txid(invalid_egress_tx->GetHash());
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));

    CreateAndProcessBlock({valid_settlement_anchor_fixture.tx}, script_pub_key);
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return chainman.IsShieldedSettlementAnchorValid(
                              valid_settlement_anchor_fixture.settlement_anchor_digest)));
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return !chainman.IsShieldedSettlementAnchorValid(
                              invalid_settlement_anchor_fixture.settlement_anchor_digest)));

    TestMemPoolEntryHelper entry;
    AddToMempool(pool, entry.FromTx(valid_egress_tx));
    AddToMempool(pool, entry.FromTx(invalid_egress_tx));

    LOCK2(cs_main, pool.cs);
    BOOST_CHECK(pool.exists(valid_egress_txid));
    BOOST_CHECK(pool.exists(invalid_egress_txid));
    BOOST_CHECK(!HasInvalidShieldedAnchors(*valid_egress_tx, chainman));
    BOOST_CHECK(HasInvalidShieldedAnchors(*invalid_egress_tx, chainman));

    RemoveStaleShieldedAnchorMempoolTransactions(pool, chainman.ActiveChain(), chainman);

    BOOST_CHECK(pool.exists(valid_egress_txid));
    BOOST_CHECK(!pool.exists(invalid_egress_txid));
}

BOOST_FIXTURE_TEST_CASE(shielded_v2_settlement_anchor_cleanup_preserves_valid_manifest_refs_and_evicts_missing_ones, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    CTxMemPool& pool = *Assert(m_node.mempool);

    const auto valid_rebalance_fixture = test::shielded::BuildV2RebalanceFixture();

    auto valid_settlement_anchor_fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture();
    test::shielded::AttachSettlementAnchorReserveBinding(
        valid_settlement_anchor_fixture.tx,
        valid_rebalance_fixture.reserve_deltas,
        valid_rebalance_fixture.manifest_id);

    auto invalid_settlement_anchor_fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture();
    test::shielded::AttachSettlementAnchorReserveBinding(invalid_settlement_anchor_fixture.tx);

    const auto valid_settlement_anchor_tx = MakeTransactionRef(valid_settlement_anchor_fixture.tx);
    const auto invalid_settlement_anchor_tx = MakeTransactionRef(invalid_settlement_anchor_fixture.tx);
    const auto valid_settlement_anchor_txid =
        GenTxid::Txid(valid_settlement_anchor_tx->GetHash());
    const auto invalid_settlement_anchor_txid =
        GenTxid::Txid(invalid_settlement_anchor_tx->GetHash());
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));

    CreateAndProcessBlock({valid_rebalance_fixture.tx}, script_pub_key);
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return chainman.IsShieldedNettingManifestValid(
                              valid_rebalance_fixture.manifest_id)));
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return !chainman.IsShieldedNettingManifestValid(uint256{0xf2})));

    TestMemPoolEntryHelper entry;
    AddToMempool(pool, entry.FromTx(valid_settlement_anchor_tx));
    AddToMempool(pool, entry.FromTx(invalid_settlement_anchor_tx));

    LOCK2(cs_main, pool.cs);
    BOOST_CHECK(pool.exists(valid_settlement_anchor_txid));
    BOOST_CHECK(pool.exists(invalid_settlement_anchor_txid));
    BOOST_CHECK(!HasInvalidShieldedAnchors(*valid_settlement_anchor_tx, chainman));
    BOOST_CHECK(HasInvalidShieldedAnchors(*invalid_settlement_anchor_tx, chainman));

    RemoveStaleShieldedAnchorMempoolTransactions(pool, chainman.ActiveChain(), chainman);

    BOOST_CHECK(pool.exists(valid_settlement_anchor_txid));
    BOOST_CHECK(!pool.exists(invalid_settlement_anchor_txid));
}
