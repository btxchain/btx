// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// RECOVERY_EXIT mined-block end-to-end test: with the fork enabled via regtest overrides, a real
// V2_RECOVERY_EXIT transaction is mined through ConnectBlock and asserted to (a) debit the shielded pool
// by the recovered value, and (b) atomically retire BOTH the revealed commitment and the derived
// canonical nullifier. Uses a DETERMINISTIC note + ML-DSA-44 key so the consensus-pinned frozen membership
// root can be supplied as a regtest override that matches the note the transaction reveals.

#include <consensus/amount.h>
#include <coins.h>
#include <crypto/chacha20poly1305.h>
#include <hash.h>
#include <key_io.h>
#include <policy/policy.h>
#include <pqkey.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <shielded/bundle.h>
#include <shielded/merkle_tree.h>
#include <shielded/note.h>
#include <shielded/nullifier.h>
#include <shielded/recovery_exit.h>
#include <shielded/smile2/wallet_bridge.h>
#include <shielded/v2_bundle.h>
#include <span.h>
#include <streams.h>
#include <sync.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <uint256.h>
#include <util/translation.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <map>
#include <string>
#include <vector>

using namespace shielded::recovery;

namespace {

constexpr int kSunsetHeight = 101;          // chain is at 100 after TestChain100Setup; recovery mined at 101
constexpr int kRebuildSunsetHeight = 104;   // leaves room for a real pre-sunset pool-credit block
constexpr CAmount kRecoverValue = 50 * COIN;
constexpr CAmount kRecoverFee = 1000;

uint256 Sha256Of(const std::vector<unsigned char>& b)
{
    HashWriter hw; hw.write(AsBytes(Span<const unsigned char>{b.data(), b.size()})); return hw.GetSHA256();
}

std::vector<unsigned char> ToBytes(const uint256& hash)
{
    return std::vector<unsigned char>(hash.begin(), hash.end());
}

CScript BuildP2MROutput(const uint256& merkle_root)
{
    CScript script;
    script << OP_2 << ToBytes(merkle_root);
    return script;
}

// Deterministic test vectors: same note/key/witness every run, so the frozen root passed as a regtest
// override (fixed before the chain is built) is exactly the root the recovery transaction proves against.
struct ReVectors {
    CPQKey key;
    std::vector<unsigned char> pubkey;
    ShieldedNote note;
    uint256 cm;
    uint256 nullifier;
    uint256 frozen_root;
    shielded::ShieldedMerkleWitness witness;
};

const ReVectors& Vectors()
{
    static const ReVectors v = [] {
        ReVectors r;
        const std::array<unsigned char, 32> seed{{'B','T','X','-','R','E','C','O','V','E','R','Y','-','E','X','I','T',
                                                  '-','E','2','E','-','S','E','E','D','-','v','1','!','!','!'}};
        const bool ok = r.key.MakeDeterministicKey(PQAlgorithm::ML_DSA_44,
                            Span<const unsigned char>{seed.data(), seed.size()});
        assert(ok);
        r.pubkey = r.key.GetPubKey();
        r.note.value = kRecoverValue;
        r.note.recipient_pk_hash = Sha256Of(r.pubkey);
        // Deterministically pick SMILE2-eligible rho/rcm from the fixed seed.
        FastRandomContext rng(uint256{Sha256Of(r.pubkey)});
        for (int i = 0; i < 16; ++i) {
            r.note.rho = rng.rand256();
            r.note.rcm = rng.rand256();
            const auto nf = smile2::wallet::ComputeSmileNullifierFromNote(
                smile2::wallet::SMILE_GLOBAL_SEED, r.note);
            if (nf.has_value() && !nf->IsNull()) { r.nullifier = *nf; break; }
        }
        assert(!r.nullifier.IsNull());
        const auto account = smile2::wallet::BuildCompactPublicAccountFromNote(
            smile2::wallet::SMILE_GLOBAL_SEED,
            r.note);
        assert(account.has_value());
        r.cm = smile2::ComputeCompactPublicAccountHash(*account);
        // Frozen tree: one fixed decoy then the note appended last so Witness() targets the note.
        shielded::ShieldedMerkleTree tree;
        tree.Append(uint256::ONE);
        tree.Append(r.cm);
        r.witness = tree.Witness();
        r.frozen_root = tree.Root();
        return r;
    }();
    return v;
}

// Fork-enabling regtest args. The frozen-root hex is stored in a function-static string so its c_str()
// stays valid for the lifetime of the chain setup.
TestOpts MakeRecoveryOpts()
{
    static const std::string sunset_arg = "-regtestshieldedsunsetheight=" + std::to_string(kSunsetHeight);
    static const std::string credit_arg = "-regtestshieldedpoolcreditdisableheight=" + std::to_string(kSunsetHeight);
    static const std::string activ_arg = "-regtestshieldedrecoveryexitactivationheight=" + std::to_string(kSunsetHeight);
    static const std::string root_arg = "-regtestshieldedrecoveryexitfrozenroot=" + Vectors().frozen_root.GetHex();
    TestOpts opts;
    opts.extra_args = {sunset_arg.c_str(), credit_arg.c_str(), activ_arg.c_str(), root_arg.c_str()};
    return opts;
}

TestOpts MakeRecoveryRebuildOpts()
{
    static const std::string sunset_arg = "-regtestshieldedsunsetheight=" + std::to_string(kRebuildSunsetHeight);
    static const std::string credit_arg = "-regtestshieldedpoolcreditdisableheight=" + std::to_string(kRebuildSunsetHeight);
    static const std::string activ_arg = "-regtestshieldedrecoveryexitactivationheight=" + std::to_string(kRebuildSunsetHeight);
    static const std::string root_arg = "-regtestshieldedrecoveryexitfrozenroot=" + Vectors().frozen_root.GetHex();
    TestOpts opts;
    opts.extra_args = {sunset_arg.c_str(), credit_arg.c_str(), activ_arg.c_str(), root_arg.c_str()};
    return opts;
}

struct RecoveryExitChainSetup : public TestChain100Setup {
    RecoveryExitChainSetup() : TestChain100Setup(ChainType::REGTEST, MakeRecoveryOpts()) {}
};

struct RecoveryExitRebuildSetup : public TestChain100Setup {
    RecoveryExitRebuildSetup() : TestChain100Setup(ChainType::REGTEST, MakeRecoveryRebuildOpts()) {}
};

CScript RecoveryExitDefaultScript()
{
    return CScript() << OP_TRUE;
}

// Build a fully-valid V2_RECOVERY_EXIT transaction (empty vin; one transparent output = value - fee).
CMutableTransaction BuildRecoveryExitTx(CAmount fee = kRecoverFee,
                                        CScript script_pub_key = RecoveryExitDefaultScript())
{
    using namespace shielded::v2;
    const ReVectors& v = Vectors();
    BOOST_REQUIRE_GT(v.note.value, fee);

    RecoveryExitPayload payload;
    payload.value = v.note.value;
    payload.note_commitment = v.cm;
    payload.recipient_pk_hash = v.note.recipient_pk_hash;
    payload.rho = v.note.rho;
    payload.rcm = v.note.rcm;
    payload.spend_pubkey = v.pubkey;
    { DataStream ws; ws << v.witness; const auto sp = MakeUCharSpan(ws); payload.membership_proof.assign(sp.begin(), sp.end()); }

    CMutableTransaction mtx;
    mtx.vout.emplace_back(v.note.value - fee, script_pub_key);

    const uint256 tx_binding = ComputeRecoveryExitTransparentBinding(Span<const CTxOut>{mtx.vout});
    const uint256 binding = ComputeRecoveryExitBindingHash(v.cm, v.nullifier, payload.value, tx_binding);
    BOOST_REQUIRE(v.key.Sign(binding, payload.ownership_sig));

    TransactionBundle bundle;
    bundle.header.family_id = TransactionFamily::V2_RECOVERY_EXIT;
    bundle.header.proof_envelope.proof_kind = ProofKind::NONE;
    bundle.header.proof_envelope.settlement_binding_kind = SettlementBindingKind::NONE;
    bundle.header.proof_envelope.statement_digest = uint256::ZERO;
    bundle.header.payload_digest = ComputeRecoveryExitPayloadDigest(payload);
    bundle.payload = payload;
    mtx.shielded_bundle.v2_bundle = bundle;
    return mtx;
}

void AddRecoveryExitToMempool(CTxMemPool& pool, const CTransactionRef& tx, CAmount fee = kRecoverFee)
{
    TestMemPoolEntryHelper entry;
    AddToMempool(pool, entry.Fee(fee).Height(kSunsetHeight).FromTx(tx));
}

CMutableTransaction BuildLegacyShieldOnlyTx(TestChain100Setup& setup,
                                            const std::vector<CTransactionRef>& funding_txs,
                                            CAmount fee)
{
    BOOST_REQUIRE(!funding_txs.empty());

    CMutableTransaction tx;
    CAmount total_in{0};
    FillableSigningProvider keystore;
    BOOST_REQUIRE(keystore.AddKey(setup.coinbaseKey));
    std::map<COutPoint, Coin> input_coins;

    for (const auto& funding_tx : funding_txs) {
        BOOST_REQUIRE(funding_tx);
        BOOST_REQUIRE_GT(funding_tx->vout.size(), 0U);
        const COutPoint prevout{funding_tx->GetHash(), 0};
        tx.vin.emplace_back(prevout);
        total_in += funding_tx->vout[0].nValue;
        input_coins.emplace(prevout, Coin{funding_tx->vout[0], /*nHeight=*/0, /*fCoinBase=*/true});
    }
    BOOST_REQUIRE_GT(total_in, fee);

    CShieldedOutput output;
    output.note_commitment = GetRandHash();
    output.merkle_anchor = WITH_LOCK(cs_main, return setup.m_node.chainman->GetShieldedMerkleTree().Root());
    output.encrypted_note.aead_ciphertext.assign(AEADChaCha20Poly1305::EXPANSION, 0x00);
    tx.shielded_bundle.shielded_outputs.push_back(output);
    tx.shielded_bundle.value_balance = -(total_in - fee);

    std::map<int, bilingual_str> input_errors;
    BOOST_REQUIRE(SignTransaction(tx, &keystore, input_coins, SIGHASH_ALL, input_errors));
    return tx;
}

} // namespace

BOOST_AUTO_TEST_SUITE(recovery_exit_chain_tests)

BOOST_AUTO_TEST_CASE(recovery_exit_charges_policy_verify_units)
{
    CTransaction tx{BuildRecoveryExitTx()};

    BOOST_CHECK_GT(GetShieldedPolicyWeight(tx), GetTransactionWeight(tx));
}

BOOST_FIXTURE_TEST_CASE(recovery_exit_mined_block_debits_pool_and_retires_identifiers, RecoveryExitChainSetup)
{
    const ReVectors& v = Vectors();
    ChainstateManager& chainman = *Assert(m_node.chainman);

    // Seed the frozen pool with twice the recovered value, so the debit leaves a positive remainder.
    const CAmount initial_pool = 2 * v.note.value;
    {
        LOCK(cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman.SetShieldedPoolBalanceForTest(initial_pool));
        BOOST_CHECK(!chainman.IsShieldedNullifierSpent(v.nullifier));
        BOOST_CHECK(!chainman.IsShieldedRecoveryExitCommitmentRetired(v.cm));
    }

    // Mine a block (height 101 == sunset + recovery activation) containing the recovery transaction.
    const CMutableTransaction rtx = BuildRecoveryExitTx();
    CreateAndProcessBlock({rtx}, CScript() << OP_TRUE, /*chainstate=*/nullptr, /*use_mempool=*/false);

    LOCK(cs_main);
    // The block connected and advanced the tip past the activation height.
    BOOST_CHECK_GE(chainman.ActiveChain().Height(), kSunsetHeight);
    // The pool was debited by exactly the recovered value.
    BOOST_CHECK_EQUAL(chainman.GetShieldedPoolBalance(), initial_pool - v.note.value);
    // BOTH identifiers retired: the nullifier (shared set) and the commitment (spent-commitment set).
    BOOST_CHECK(chainman.IsShieldedNullifierSpent(v.nullifier));
    BOOST_CHECK(chainman.IsShieldedRecoveryExitCommitmentRetired(v.cm));
}

BOOST_FIXTURE_TEST_CASE(recovery_exit_rebuild_preserves_retired_identifiers, RecoveryExitRebuildSetup)
{
    const ReVectors& v = Vectors();
    ChainstateManager& chainman = *Assert(m_node.chainman);

    // Advance to height 102 so coinbases at heights 1, 2, and 3 are mature in the next block.
    CreateAndProcessBlock({}, CScript() << OP_TRUE, /*chainstate=*/nullptr, /*use_mempool=*/false);
    CreateAndProcessBlock({}, CScript() << OP_TRUE, /*chainstate=*/nullptr, /*use_mempool=*/false);
    BOOST_REQUIRE_EQUAL(WITH_LOCK(cs_main, return chainman.ActiveChain().Height()), kRebuildSunsetHeight - 2);

    const std::vector<CTransactionRef> funding_txs{m_coinbase_txns[0], m_coinbase_txns[1], m_coinbase_txns[2]};
    CAmount seeded_pool{0};
    for (const auto& funding_tx : funding_txs) {
        seeded_pool += funding_tx->vout[0].nValue;
    }
    seeded_pool -= kRecoverFee;
    BOOST_REQUIRE_GT(seeded_pool, v.note.value);

    const CMutableTransaction shield_tx = BuildLegacyShieldOnlyTx(*this, funding_txs, kRecoverFee);
    CreateAndProcessBlock({shield_tx}, CScript() << OP_TRUE, /*chainstate=*/nullptr, /*use_mempool=*/false);
    BOOST_REQUIRE_EQUAL(WITH_LOCK(cs_main, return chainman.ActiveChain().Height()), kRebuildSunsetHeight - 1);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return chainman.GetShieldedPoolBalance()), seeded_pool);

    const CMutableTransaction rtx = BuildRecoveryExitTx();
    CreateAndProcessBlock({rtx}, CScript() << OP_TRUE, /*chainstate=*/nullptr, /*use_mempool=*/false);

    {
        LOCK(cs_main);
        BOOST_REQUIRE_EQUAL(chainman.ActiveChain().Height(), kRebuildSunsetHeight);
        BOOST_CHECK_EQUAL(chainman.GetShieldedPoolBalance(), seeded_pool - v.note.value);
        BOOST_REQUIRE(chainman.IsShieldedNullifierSpent(v.nullifier));
        BOOST_REQUIRE(chainman.IsShieldedRecoveryExitCommitmentRetired(v.cm));

        BOOST_REQUIRE(chainman.RebuildShieldedStateFromActiveChain());
        BOOST_CHECK_EQUAL(chainman.GetShieldedPoolBalance(), seeded_pool - v.note.value);
        BOOST_CHECK(chainman.IsShieldedNullifierSpent(v.nullifier));
        BOOST_CHECK(chainman.IsShieldedRecoveryExitCommitmentRetired(v.cm));
    }
}

BOOST_FIXTURE_TEST_CASE(recovery_exit_mempool_cleanup_evicts_spent_nullifier, RecoveryExitChainSetup)
{
    const ReVectors& v = Vectors();
    ChainstateManager& chainman = *Assert(m_node.chainman);
    CTxMemPool& pool = *Assert(m_node.mempool);
    const auto tx = MakeTransactionRef(BuildRecoveryExitTx());
    const auto txid = GenTxid::Txid(tx->GetHash());

    AddRecoveryExitToMempool(pool, tx);
    LOCK2(cs_main, pool.cs);
    BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
    BOOST_REQUIRE(pool.exists(txid));
    BOOST_CHECK(!HasInvalidShieldedRecoveryExitMempoolState(*tx, chainman));
    BOOST_REQUIRE(chainman.InsertShieldedNullifiersForTest({v.nullifier}));
    BOOST_CHECK(HasInvalidShieldedRecoveryExitMempoolState(*tx, chainman));
    RemoveStaleShieldedAnchorMempoolTransactions(pool, chainman.ActiveChain(), chainman);
    BOOST_CHECK(!pool.exists(txid));
}

BOOST_FIXTURE_TEST_CASE(recovery_exit_mempool_cleanup_evicts_retired_commitment, RecoveryExitChainSetup)
{
    const ReVectors& v = Vectors();
    ChainstateManager& chainman = *Assert(m_node.chainman);
    CTxMemPool& pool = *Assert(m_node.mempool);
    const auto tx = MakeTransactionRef(BuildRecoveryExitTx());
    const auto txid = GenTxid::Txid(tx->GetHash());

    AddRecoveryExitToMempool(pool, tx);
    LOCK2(cs_main, pool.cs);
    BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
    BOOST_REQUIRE(pool.exists(txid));
    BOOST_CHECK(!HasInvalidShieldedRecoveryExitMempoolState(*tx, chainman));
    BOOST_REQUIRE(chainman.InsertShieldedRecoveryExitCommitmentsForTest({v.cm}));
    BOOST_CHECK(HasInvalidShieldedRecoveryExitMempoolState(*tx, chainman));
    RemoveStaleShieldedAnchorMempoolTransactions(pool, chainman.ActiveChain(), chainman);
    BOOST_CHECK(!pool.exists(txid));
}

BOOST_FIXTURE_TEST_CASE(recovery_exit_mempool_cleanup_evicts_missing_cached_retirements, RecoveryExitChainSetup)
{
    const ReVectors& v = Vectors();
    ChainstateManager& chainman = *Assert(m_node.chainman);
    CTxMemPool& pool = *Assert(m_node.mempool);
    const auto tx = MakeTransactionRef(BuildRecoveryExitTx());
    const auto txid = GenTxid::Txid(tx->GetHash());

    AddRecoveryExitToMempool(pool, tx);
    LOCK2(cs_main, pool.cs);
    BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
    BOOST_REQUIRE(pool.exists(txid));
    BOOST_REQUIRE(pool.m_shielded_nullifiers.erase(v.nullifier) == 1U);
    BOOST_REQUIRE(pool.m_shielded_recovery_commitments.erase(v.cm) == 1U);

    RemoveStaleShieldedAnchorMempoolTransactions(pool, chainman.ActiveChain(), chainman);
    BOOST_CHECK(!pool.exists(txid));
}

BOOST_FIXTURE_TEST_CASE(recovery_exit_targeted_block_cleanup_evicts_conflicting_entry, RecoveryExitChainSetup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    CTxMemPool& pool = *Assert(m_node.mempool);
    const auto recovery_tx = MakeTransactionRef(BuildRecoveryExitTx());
    const auto recovery_txid = GenTxid::Txid(recovery_tx->GetHash());

    CMutableTransaction unrelated_mtx;
    unrelated_mtx.vout.emplace_back(1 * COIN, CScript() << OP_TRUE);
    const auto unrelated_tx = MakeTransactionRef(unrelated_mtx);
    const auto unrelated_txid = GenTxid::Txid(unrelated_tx->GetHash());

    AddRecoveryExitToMempool(pool, recovery_tx);
    TestMemPoolEntryHelper entry;
    AddToMempool(pool, entry.FromTx(unrelated_tx));

    LOCK2(cs_main, pool.cs);
    BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
    BOOST_REQUIRE(pool.exists(recovery_txid));
    BOOST_REQUIRE(pool.exists(unrelated_txid));

    RemoveShieldedMempoolConflictsForBlock(pool,
                                           chainman.ActiveChain(),
                                           chainman,
                                           nullptr,
                                           {recovery_tx});

    BOOST_CHECK(!pool.exists(recovery_txid));
    BOOST_CHECK(pool.exists(unrelated_txid));
}

BOOST_FIXTURE_TEST_CASE(recovery_exit_same_note_replacement_under_optin_rbf, RecoveryExitChainSetup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    CTxMemPool& pool = *Assert(m_node.mempool);
    const RBFPolicy saved_rbf_policy = pool.m_opts.rbf_policy;
    pool.m_opts.rbf_policy = RBFPolicy::OptIn;

    const CScript script_pub_key = BuildP2MROutput(uint256::ONE);
    const CAmount low_fee = 200'000;
    const CAmount high_fee = 500'000;
    const auto low_tx = MakeTransactionRef(BuildRecoveryExitTx(low_fee, script_pub_key));
    const auto high_tx = MakeTransactionRef(BuildRecoveryExitTx(high_fee, script_pub_key));
    const auto low_txid = GenTxid::Txid(low_tx->GetHash());
    const auto high_txid = GenTxid::Txid(high_tx->GetHash());
    BOOST_REQUIRE(low_tx->GetHash() != high_tx->GetHash());

    {
        LOCK(cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman.SetShieldedPoolBalanceForTest(2 * kRecoverValue));
    }

    const auto low_accept = WITH_LOCK(cs_main, return chainman.ProcessTransaction(low_tx));
    if (low_accept.m_result_type != MempoolAcceptResult::ResultType::VALID) {
        pool.m_opts.rbf_policy = saved_rbf_policy;
        BOOST_FAIL(strprintf("low-fee recovery-exit rejected: reason=%s debug=%s",
                             low_accept.m_state.GetRejectReason(),
                             low_accept.m_state.GetDebugMessage()));
    }
    BOOST_CHECK(WITH_LOCK(pool.cs, return pool.exists(low_txid)));

    const auto high_accept = WITH_LOCK(cs_main, return chainman.ProcessTransaction(high_tx));
    pool.m_opts.rbf_policy = saved_rbf_policy;
    BOOST_REQUIRE_MESSAGE(high_accept.m_result_type == MempoolAcceptResult::ResultType::VALID,
                          strprintf("replacement recovery-exit rejected: reason=%s debug=%s",
                                    high_accept.m_state.GetRejectReason(),
                                    high_accept.m_state.GetDebugMessage()));
    BOOST_CHECK(WITH_LOCK(pool.cs, return !pool.exists(low_txid)));
    BOOST_CHECK(WITH_LOCK(pool.cs, return pool.exists(high_txid)));
}

BOOST_FIXTURE_TEST_CASE(recovery_exit_template_selection_excludes_spent_nullifier, RecoveryExitChainSetup)
{
    const ReVectors& v = Vectors();
    ChainstateManager& chainman = *Assert(m_node.chainman);
    CTxMemPool& pool = *Assert(m_node.mempool);
    const auto tx = MakeTransactionRef(BuildRecoveryExitTx());
    const auto txid = GenTxid::Txid(tx->GetHash());

    AddRecoveryExitToMempool(pool, tx);
    {
        LOCK(cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman.InsertShieldedNullifiersForTest({v.nullifier}));
    }

    node::BlockAssembler::Options options;
    options.coinbase_output_script = CScript() << OP_TRUE;
    const auto block = PrepareBlock(m_node, options);
    BOOST_REQUIRE(block);
    for (const auto& block_tx : block->vtx) {
        BOOST_CHECK(block_tx->GetHash() != tx->GetHash());
    }
    BOOST_CHECK(WITH_LOCK(pool.cs, return pool.exists(txid)));
}

BOOST_FIXTURE_TEST_CASE(recovery_exit_template_selection_excludes_retired_commitment, RecoveryExitChainSetup)
{
    const ReVectors& v = Vectors();
    ChainstateManager& chainman = *Assert(m_node.chainman);
    CTxMemPool& pool = *Assert(m_node.mempool);
    const auto tx = MakeTransactionRef(BuildRecoveryExitTx());
    const auto txid = GenTxid::Txid(tx->GetHash());

    AddRecoveryExitToMempool(pool, tx);
    {
        LOCK(cs_main);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        BOOST_REQUIRE(chainman.InsertShieldedRecoveryExitCommitmentsForTest({v.cm}));
    }

    node::BlockAssembler::Options options;
    options.coinbase_output_script = CScript() << OP_TRUE;
    const auto block = PrepareBlock(m_node, options);
    BOOST_REQUIRE(block);
    for (const auto& block_tx : block->vtx) {
        BOOST_CHECK(block_tx->GetHash() != tx->GetHash());
    }
    BOOST_CHECK(WITH_LOCK(pool.cs, return pool.exists(txid)));
}

BOOST_AUTO_TEST_SUITE_END()
