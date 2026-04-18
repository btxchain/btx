// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <coins.h>
#include <common/system.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <hash.h>
#include <interfaces/mining.h>
#include <node/miner.h>
#include <policy/policy.h>
#include <pow.h>
#include <rpc/server_util.h>
#include <shielded/v2_bundle.h>
#include <test/util/mining.h>
#include <test/util/random.h>
#include <test/util/shielded_account_registry_test_util.h>
#include <test/util/shielded_smile_test_util.h>
#include <test/util/shielded_v2_egress_fixture.h>
#include <test/util/transaction_utils.h>
#include <test/util/txmempool.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/check.h>
#include <util/feefrac.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>
#include <versionbits.h>

#include <test/util/setup_common.h>

#include <algorithm>
#include <chrono>
#include <map>
#include <memory>
#include <limits>
#include <vector>

#include <boost/test/unit_test.hpp>

using namespace util::hex_literals;
using interfaces::BlockTemplate;
using interfaces::Mining;
using node::BlockAssembler;

namespace miner_tests {
struct MinerTestingSetup : public TestingSetup {
    static TestOpts BuildOpts()
    {
        TestOpts opts;
        opts.extra_args = {"-test=matmulstrict"};
        return opts;
    }
    MinerTestingSetup()
        : TestingSetup{ChainType::REGTEST, BuildOpts()} {}

    void TestPackageSelection(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    void TestBasicMining(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst, int baseheight) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    void TestConsensusSerializedSizeLimit(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    void TestPrioritisedMining(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    void TestShieldedAnchorTemplateCleanup(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst);
    bool TestSequenceLocks(const CTransaction& tx, CTxMemPool& tx_mempool) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        CCoinsViewMemPool view_mempool{&m_node.chainman->ActiveChainstate().CoinsTip(), tx_mempool};
        CBlockIndex* tip{m_node.chainman->ActiveChain().Tip()};
        const std::optional<LockPoints> lock_points{CalculateLockPointsAtTip(tip, view_mempool, tx)};
        return lock_points.has_value() && CheckSequenceLocksAtTip(tip, *lock_points);
    }
    CTxMemPool& MakeMempool()
    {
        // Delete the previous mempool to ensure with valgrind that the old
        // pointer is not accessed, when the new one should be accessed
        // instead.
        m_node.mempool.reset();
        bilingual_str error;
        m_node.mempool = std::make_unique<CTxMemPool>(MemPoolOptionsForTest(m_node), error);
        Assert(error.empty());
        return *m_node.mempool;
    }
    std::unique_ptr<Mining> MakeMining()
    {
        return interfaces::MakeMining(m_node);
    }
};

struct ShieldedMinerTestingSetup : public TestChain100Setup {
    static TestOpts BuildOpts()
    {
        TestOpts opts;
        opts.extra_args = {"-test=matmulstrict"};
        return opts;
    }
    ShieldedMinerTestingSetup()
        : TestChain100Setup{ChainType::REGTEST, BuildOpts()} {}

    CTxMemPool& MakeMempool()
    {
        m_node.mempool.reset();
        bilingual_str error;
        m_node.mempool = std::make_unique<CTxMemPool>(MemPoolOptionsForTest(m_node), error);
        Assert(error.empty());
        return *m_node.mempool;
    }
};
} // namespace miner_tests

namespace {
constexpr size_t SCARCITY_TEST_FILLER_COUNT{77};
constexpr size_t SCARCITY_TEST_OUTPUT_CHUNKS{128};
constexpr size_t SCARCITY_TEST_RESOURCE_UNITS{128};

uint256 DeterministicHash(uint32_t seed)
{
    HashWriter hw{};
    hw << seed;
    return hw.GetSHA256();
}

smile2::CompactPublicAccount MakeSyntheticSmileAccount(uint32_t seed)
{
    return test::shielded::MakeDeterministicCompactPublicAccount(
        seed,
        1 + static_cast<CAmount>(seed));
}

shielded::v2::OutputDescription MakeSyntheticOutputDescription(uint32_t seed)
{
    shielded::v2::OutputDescription output;
    output.smile_account = MakeSyntheticSmileAccount(seed);
    output.note_commitment = smile2::ComputeCompactPublicAccountHash(*output.smile_account);
    output.value_commitment = DeterministicHash(seed * 17 + 2);
    output.encrypted_note.ephemeral_key = DeterministicHash(seed * 17 + 3);
    return output;
}

shielded::v2::OutputChunkDescriptor MakeSyntheticOutputChunkDescriptor(uint32_t seed, uint32_t index)
{
    shielded::v2::OutputChunkDescriptor descriptor;
    descriptor.first_output_index = index;
    descriptor.output_count = 0;
    descriptor.ciphertext_bytes = 0;
    descriptor.scan_hint_commitment = DeterministicHash(seed * 131 + index * 2 + 1);
    descriptor.ciphertext_commitment = DeterministicHash(seed * 131 + index * 2 + 2);
    return descriptor;
}

shielded::v2::TransactionBundle MakeSyntheticEgressBundle(size_t output_count,
                                                          size_t chunk_count,
                                                          uint32_t seed,
                                                          const uint256& settlement_anchor)
{
    shielded::v2::TransactionBundle bundle;
    bundle.header.family_id = shielded::v2::TransactionFamily::V2_EGRESS_BATCH;
    bundle.header.proof_envelope.proof_kind = shielded::v2::ProofKind::IMPORTED_RECEIPT;
    bundle.header.proof_envelope.membership_proof_kind = shielded::v2::ProofComponentKind::NONE;
    bundle.header.proof_envelope.amount_proof_kind = shielded::v2::ProofComponentKind::NONE;
    bundle.header.proof_envelope.balance_proof_kind = shielded::v2::ProofComponentKind::NONE;
    bundle.header.proof_envelope.settlement_binding_kind = shielded::v2::SettlementBindingKind::BRIDGE_RECEIPT;
    bundle.header.proof_envelope.statement_digest = DeterministicHash(seed * 7 + 1);
    bundle.payload = shielded::v2::EgressBatchPayload{};
    auto& payload = std::get<shielded::v2::EgressBatchPayload>(bundle.payload);
    payload.settlement_anchor = settlement_anchor;
    payload.output_binding_digest = DeterministicHash(seed * 7 + 2);
    payload.settlement_binding_digest = DeterministicHash(seed * 7 + 3);
    payload.outputs.reserve(output_count);
    for (size_t i = 0; i < output_count; ++i) {
        auto output = MakeSyntheticOutputDescription(seed + static_cast<uint32_t>(i));
        output.note_class = shielded::v2::NoteClass::USER;
        output.encrypted_note.scan_domain = shielded::v2::ScanDomain::OPAQUE;
        output.value_commitment = shielded::v2::ComputeV2EgressOutputValueCommitment(
            payload.output_binding_digest,
            static_cast<uint32_t>(i),
            output.note_commitment);
        payload.outputs.push_back(std::move(output));
    }
    payload.egress_root = shielded::v2::ComputeOutputDescriptionRoot(
        Span<const shielded::v2::OutputDescription>{payload.outputs.data(), payload.outputs.size()});
    bundle.output_chunks.reserve(chunk_count);
    if (output_count == 0) {
        for (size_t i = 0; i < chunk_count; ++i) {
            bundle.output_chunks.push_back(MakeSyntheticOutputChunkDescriptor(seed, static_cast<uint32_t>(i)));
        }
    } else {
        size_t next_output_index{0};
        while (bundle.output_chunks.size() < chunk_count && next_output_index < payload.outputs.size()) {
            const size_t remaining_outputs = payload.outputs.size() - next_output_index;
            const size_t remaining_chunks = chunk_count - bundle.output_chunks.size();
            const size_t this_chunk_size = std::max<size_t>(1, (remaining_outputs + remaining_chunks - 1) / remaining_chunks);
            const auto descriptor = shielded::v2::BuildOutputChunkDescriptor(
                Span<const shielded::v2::OutputDescription>{payload.outputs.data() + next_output_index, this_chunk_size},
                static_cast<uint32_t>(next_output_index));
            assert(descriptor.has_value());
            bundle.output_chunks.push_back(*descriptor);
            next_output_index += this_chunk_size;
        }
        assert(next_output_index == payload.outputs.size());
    }
    bundle.header.output_chunk_root = bundle.output_chunks.empty()
        ? uint256{}
        : shielded::v2::ComputeOutputChunkRoot(
              Span<const shielded::v2::OutputChunkDescriptor>{bundle.output_chunks.data(), bundle.output_chunks.size()});
    bundle.header.output_chunk_count = static_cast<uint32_t>(bundle.output_chunks.size());
    bundle.header.payload_digest = shielded::v2::ComputeEgressBatchPayloadDigest(payload);
    return bundle;
}

shielded::v2::TransactionBundle MakeSyntheticIngressBundle(size_t nullifier_count,
                                                           uint32_t seed,
                                                           const uint256& spend_anchor,
                                                           const uint256& account_registry_anchor)
{
    shielded::v2::TransactionBundle bundle;
    bundle.header.family_id = shielded::v2::TransactionFamily::V2_INGRESS_BATCH;
    bundle.header.proof_envelope.proof_kind = shielded::v2::ProofKind::BATCH_SMILE;
    bundle.header.proof_envelope.membership_proof_kind = shielded::v2::ProofComponentKind::SMILE_MEMBERSHIP;
    bundle.header.proof_envelope.amount_proof_kind = shielded::v2::ProofComponentKind::SMILE_BALANCE;
    bundle.header.proof_envelope.balance_proof_kind = shielded::v2::ProofComponentKind::SMILE_BALANCE;
    bundle.header.proof_envelope.settlement_binding_kind = shielded::v2::SettlementBindingKind::NATIVE_BATCH;
    bundle.header.proof_envelope.statement_digest = DeterministicHash(seed * 11 + 1);
    bundle.payload = shielded::v2::IngressBatchPayload{};
    auto& payload = std::get<shielded::v2::IngressBatchPayload>(bundle.payload);
    payload.spend_anchor = spend_anchor;
    payload.settlement_binding_digest = DeterministicHash(seed * 11 + 5);
    payload.fee = 1;
    const auto spend_account = MakeSyntheticSmileAccount(seed * 19 + 1);
    const uint256 spend_note_commitment = smile2::ComputeCompactPublicAccountHash(spend_account);
    const auto registry_witness =
        test::shielded::MakeSingleLeafRegistryWitness(spend_note_commitment, spend_account);
    assert(registry_witness.has_value());
    payload.account_registry_anchor = account_registry_anchor;
    const size_t spend_count = nullifier_count > 1 ? nullifier_count - 1 : 1;
    payload.consumed_spends.reserve(spend_count);
    for (size_t i = 0; i < spend_count; ++i) {
        shielded::v2::ConsumedAccountLeafSpend spend;
        spend.nullifier = DeterministicHash(seed * 997 + static_cast<uint32_t>(i) + 1);
        spend.account_leaf_commitment = registry_witness->second.account_leaf_commitment;
        spend.account_registry_proof = registry_witness->second;
        payload.consumed_spends.push_back(spend);
    }
    shielded::v2::BatchLeaf leaf;
    leaf.family_id = shielded::v2::TransactionFamily::V2_INGRESS_BATCH;
    leaf.l2_id = DeterministicHash(seed * 11 + 11);
    leaf.destination_commitment = DeterministicHash(seed * 11 + 12);
    leaf.amount_commitment = DeterministicHash(seed * 11 + 13);
    leaf.fee_commitment = DeterministicHash(seed * 11 + 14);
    leaf.position = 0;
    leaf.nonce = DeterministicHash(seed * 11 + 15);
    leaf.settlement_domain = DeterministicHash(seed * 11 + 16);
    payload.ingress_leaves = {leaf};

    auto reserve_output = MakeSyntheticOutputDescription(seed * 19 + 2);
    reserve_output.note_class = shielded::v2::NoteClass::RESERVE;
    reserve_output.encrypted_note.scan_domain = shielded::v2::ScanDomain::OPAQUE;
    payload.reserve_outputs = {reserve_output};

    payload.ingress_root = shielded::v2::ComputeBatchLeafRoot(
        Span<const shielded::v2::BatchLeaf>{payload.ingress_leaves.data(), payload.ingress_leaves.size()});
    payload.l2_credit_root = shielded::v2::ComputeV2IngressL2CreditRoot(
        Span<const shielded::v2::BatchLeaf>{payload.ingress_leaves.data(), payload.ingress_leaves.size()});
    payload.aggregate_reserve_commitment = shielded::v2::ComputeV2IngressAggregateReserveCommitment(
        Span<const shielded::v2::OutputDescription>{payload.reserve_outputs.data(), payload.reserve_outputs.size()});
    payload.aggregate_fee_commitment = shielded::v2::ComputeV2IngressAggregateFeeCommitment(
        Span<const shielded::v2::BatchLeaf>{payload.ingress_leaves.data(), payload.ingress_leaves.size()});
    bundle.header.payload_digest = shielded::v2::ComputeIngressBatchPayloadDigest(payload);
    return bundle;
}

shielded::v2::TransactionBundle MakeSyntheticSendBundle(uint32_t seed,
                                                        const uint256& spend_anchor,
                                                        const uint256& account_registry_anchor)
{
    shielded::v2::TransactionBundle bundle;
    bundle.header.family_id = shielded::v2::TransactionFamily::V2_SEND;
    bundle.header.proof_envelope.proof_kind = shielded::v2::ProofKind::DIRECT_SMILE;
    bundle.header.proof_envelope.membership_proof_kind = shielded::v2::ProofComponentKind::SMILE_MEMBERSHIP;
    bundle.header.proof_envelope.amount_proof_kind = shielded::v2::ProofComponentKind::SMILE_BALANCE;
    bundle.header.proof_envelope.balance_proof_kind = shielded::v2::ProofComponentKind::SMILE_BALANCE;
    bundle.header.proof_envelope.settlement_binding_kind = shielded::v2::SettlementBindingKind::NONE;
    bundle.header.proof_envelope.statement_digest = DeterministicHash(seed * 23 + 1);
    bundle.payload = shielded::v2::SendPayload{};
    auto& payload = std::get<shielded::v2::SendPayload>(bundle.payload);
    payload.spend_anchor = spend_anchor;
    payload.fee = 1;
    payload.value_balance = payload.fee;

    const auto spend_account = MakeSyntheticSmileAccount(seed * 23 + 4);
    const uint256 spend_note_commitment = smile2::ComputeCompactPublicAccountHash(spend_account);
    const auto registry_witness =
        test::shielded::MakeSingleLeafRegistryWitness(spend_note_commitment, spend_account);
    assert(registry_witness.has_value());

    shielded::v2::SpendDescription spend;
    spend.nullifier = DeterministicHash(seed * 23 + 2);
    spend.merkle_anchor = spend_anchor;
    spend.account_leaf_commitment = registry_witness->second.account_leaf_commitment;
    spend.account_registry_proof = registry_witness->second;
    spend.note_commitment = spend_note_commitment;
    spend.value_commitment = DeterministicHash(seed * 23 + 4);
    payload.spends = {spend};
    payload.account_registry_anchor = account_registry_anchor;

    shielded::v2::OutputDescription output;
    output.note_class = shielded::v2::NoteClass::USER;
    output.smile_account = MakeSyntheticSmileAccount(seed * 23 + 5);
    output.note_commitment = smile2::ComputeCompactPublicAccountHash(*output.smile_account);
    output.value_commitment = smile2::ComputeSmileOutputCoinHash(output.smile_account->public_coin);
    output.encrypted_note.scan_domain = shielded::v2::ScanDomain::USER;
    output.encrypted_note.scan_hint.fill(static_cast<unsigned char>(seed));
    output.encrypted_note.ciphertext = {
        static_cast<unsigned char>(seed),
        static_cast<unsigned char>(seed + 1),
        static_cast<unsigned char>(seed + 2),
    };
    output.encrypted_note.ephemeral_key = shielded::v2::ComputeLegacyPayloadEphemeralKey(
        Span<const uint8_t>{output.encrypted_note.ciphertext.data(), output.encrypted_note.ciphertext.size()});
    payload.outputs = {output};

    bundle.proof_payload = {
        static_cast<uint8_t>(seed),
        static_cast<uint8_t>(seed + 1),
        static_cast<uint8_t>(seed + 2),
    };
    bundle.header.payload_digest = shielded::v2::ComputeSendPayloadDigest(payload);
    return bundle;
}

shielded::v2::TransactionBundle ExtractV2Bundle(const CMutableTransaction& tx)
{
    return *Assert(tx.shielded_bundle.v2_bundle);
}

CMutableTransaction MakeSyntheticShieldedMinerTx(const COutPoint& prevout,
                                                 CAmount input_value,
                                                 uint32_t seed,
                                                 CAmount fee,
                                                 const shielded::v2::TransactionBundle& bundle)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = prevout;
    tx.vin[0].scriptSig = CScript{} << OP_1;
    tx.vout.resize(1);
    tx.vout[0].nValue = input_value - fee;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;
    tx.shielded_bundle = CShieldedBundle{};
    tx.shielded_bundle.v2_bundle = bundle;
    return tx;
}

Txid AddSyntheticShieldedMinerTx(CTxMemPool& tx_mempool,
                                 const CTransactionRef& funding_tx,
                                 uint32_t seed,
                                 CAmount fee,
                                 const shielded::v2::TransactionBundle& bundle,
                                 uint64_t sequence)
{
    const COutPoint prevout{funding_tx->GetHash(), 0};
    const auto tx_ref = MakeTransactionRef(MakeSyntheticShieldedMinerTx(prevout, funding_tx->vout.at(0).nValue, seed, fee, bundle));
    const int64_t extra_weight = std::max<int64_t>(0, GetShieldedPolicyWeight(*tx_ref) - GetTransactionWeight(*tx_ref));
    const CTxMemPoolEntry entry{
        tx_ref,
        fee,
        TicksSinceEpoch<std::chrono::seconds>(Now<NodeSeconds>()),
        /*entry_height=*/1,
        sequence,
        COIN_AGE_CACHE_ZERO,
        /*spends_coinbase=*/funding_tx->IsCoinBase(),
        /*extra_weight=*/static_cast<int32_t>(extra_weight),
        /*sigops_cost=*/4,
        LockPoints{}};
    const Txid txid = tx_ref->GetHash();
    AddToMempool(tx_mempool, entry);
    return txid;
}

size_t FindBlockTxIndex(const CBlock& block, const Txid& txid)
{
    for (size_t i = 0; i < block.vtx.size(); ++i) {
        if (block.vtx[i]->GetHash() == txid) return i;
    }
    return block.vtx.size();
}

const CTxMemPoolEntry& GetSyntheticMinerEntry(const CTxMemPool& tx_mempool, const Txid& txid) EXCLUSIVE_LOCKS_REQUIRED(tx_mempool.cs)
{
    return *Assert(tx_mempool.GetEntry(txid));
}

BlockAssembler::Options MakeSyntheticBlockAssemblerOptions()
{
    BlockAssembler::Options options;
    options.coinbase_output_script = CScript{} << OP_2 << std::vector<unsigned char>(32, 0x42);
    options.test_block_validity = false;
    return options;
}

int32_t GetCurrentSyntheticValidationHeight(TestChain100Setup& setup)
{
    return WITH_LOCK(::cs_main, return Assert(setup.m_node.chainman)->ActiveChain().Height() + 1);
}

uint256 GetCurrentSyntheticSpendAnchor(TestChain100Setup& setup)
{
    uint256 spend_anchor;
    {
        LOCK(::cs_main);
        ChainstateManager& chainman{*Assert(setup.m_node.chainman)};
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        spend_anchor = chainman.GetShieldedMerkleTree().Root();
    }
    BOOST_REQUIRE(!spend_anchor.IsNull());
    return spend_anchor;
}

uint256 GetCurrentSyntheticAccountRegistryAnchor(TestChain100Setup& setup)
{
    uint256 account_registry_anchor;
    {
        LOCK(::cs_main);
        ChainstateManager& chainman{*Assert(setup.m_node.chainman)};
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        account_registry_anchor = chainman.GetShieldedAccountRegistryRoot();
    }
    BOOST_REQUIRE(!account_registry_anchor.IsNull());
    return account_registry_anchor;
}

uint256 ConfirmSyntheticSettlementAnchorDigest(TestChain100Setup& setup,
                                               const CScript& script_pub_key)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t validation_height = GetCurrentSyntheticValidationHeight(setup);
    const auto fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture(
        /*output_count=*/2,
        /*proof_receipt_count=*/1,
        /*required_receipts=*/1,
        &consensus,
        validation_height);
    setup.CreateAndProcessBlock({fixture.tx}, script_pub_key);

    BOOST_CHECK(WITH_LOCK(::cs_main,
                          return Assert(setup.m_node.chainman)->IsShieldedSettlementAnchorValid(
                              fixture.settlement_anchor_digest)));
    return fixture.settlement_anchor_digest;
}

struct ScopedShieldedRegistryAppendConsensus
{
    Consensus::Params& consensus;
    int32_t matrict_disable_height;
    uint64_t registry_append_limit;

    ~ScopedShieldedRegistryAppendConsensus()
    {
        consensus.nShieldedMatRiCTDisableHeight = matrict_disable_height;
        consensus.nMaxBlockShieldedAccountRegistryAppends = registry_append_limit;
    }
};

struct ScopedShieldedRegistryEntryConsensus
{
    Consensus::Params& consensus;
    int32_t matrict_disable_height;
    uint64_t registry_entry_limit;

    ~ScopedShieldedRegistryEntryConsensus()
    {
        consensus.nShieldedMatRiCTDisableHeight = matrict_disable_height;
        consensus.nMaxShieldedAccountRegistryEntries = registry_entry_limit;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(miner_tests, MinerTestingSetup)

static CFeeRate blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);

static std::unique_ptr<CBlockIndex> CreateBlockIndex(int nHeight, CBlockIndex* active_chain_tip) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    auto index{std::make_unique<CBlockIndex>()};
    index->nHeight = nHeight;
    index->pprev = active_chain_tip;
    return index;
}

// Test suite for ancestor feerate transaction selection.
// Implemented as an additional function, rather than a separate test case,
// to allow reusing the blockchain created in CreateNewBlock_validity.
void MinerTestingSetup::TestPackageSelection(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst)
{
    CTxMemPool& tx_mempool{MakeMempool()};
    auto mining{MakeMining()};
    BlockAssembler::Options options;
    options.coinbase_output_script = scriptPubKey;

    LOCK(tx_mempool.cs);
    // Test the ancestor feerate transaction selection.
    TestMemPoolEntryHelper entry;

    // Test that a medium fee transaction will be selected after a higher fee
    // rate package with a low fee rate parent.
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vout.resize(1);
    tx.vout[0].nValue = 5000000000LL - 1000;
    // This tx has a low fee: 1000 satoshis
    Txid hashParentTx = tx.GetHash(); // save this txid for later use
    const auto parent_tx{entry.Fee(1000).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx)};
    AddToMempool(tx_mempool, parent_tx);

    // This tx has a medium fee: 10000 satoshis
    tx.vin[0].prevout.hash = txFirst[1]->GetHash();
    tx.vout[0].nValue = 5000000000LL - 10000;
    Txid hashMediumFeeTx = tx.GetHash();
    const auto medium_fee_tx{entry.Fee(10000).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx)};
    AddToMempool(tx_mempool, medium_fee_tx);

    // This tx has a high fee, but depends on the first transaction
    tx.vin[0].prevout.hash = hashParentTx;
    tx.vout[0].nValue = 5000000000LL - 1000 - 50000; // 50k satoshi fee
    Txid hashHighFeeTx = tx.GetHash();
    const auto high_fee_tx{entry.Fee(50000).Time(Now<NodeSeconds>()).SpendsCoinbase(false).FromTx(tx)};
    AddToMempool(tx_mempool, high_fee_tx);

    std::unique_ptr<BlockTemplate> block_template = mining->createNewBlock(options);
    BOOST_REQUIRE(block_template);
    CBlock block{block_template->getBlock()};
    BOOST_REQUIRE_EQUAL(block.vtx.size(), 4U);
    BOOST_CHECK(block.vtx[1]->GetHash() == hashParentTx);
    BOOST_CHECK(block.vtx[2]->GetHash() == hashHighFeeTx);
    BOOST_CHECK(block.vtx[3]->GetHash() == hashMediumFeeTx);

    // Test the inclusion of package feerates in the block template and ensure they are sequential.
    const auto block_package_feerates = BlockAssembler{m_node.chainman->ActiveChainstate(), &tx_mempool, options, m_node}.CreateNewBlock()->m_package_feerates;
    BOOST_CHECK(block_package_feerates.size() == 2);

    // parent_tx and high_fee_tx are added to the block as a package.
    const auto combined_txs_fee = parent_tx.GetFee() + high_fee_tx.GetFee();
    const auto combined_txs_size = parent_tx.GetTxSize() + high_fee_tx.GetTxSize();
    FeeFrac package_feefrac{combined_txs_fee, combined_txs_size};
    // The package should be added first.
    BOOST_CHECK(block_package_feerates[0] == package_feefrac);

    // The medium_fee_tx should be added next.
    FeeFrac medium_tx_feefrac{medium_fee_tx.GetFee(), medium_fee_tx.GetTxSize()};
    BOOST_CHECK(block_package_feerates[1] == medium_tx_feefrac);

    // Test that a package below the block min tx fee doesn't get included
    tx.vin[0].prevout.hash = hashHighFeeTx;
    tx.vout[0].nValue = 5000000000LL - 1000 - 50000; // 0 fee
    Txid hashFreeTx = tx.GetHash();
    const auto free_tx_entry = entry.Fee(0).FromTx(tx);
    AddToMempool(tx_mempool, free_tx_entry);
    const size_t freeTxPolicySize = free_tx_entry.GetTxSize();

    // Calculate a fee on child transaction that will put the package just
    // below the block min tx fee based on the actual parent/child policy sizes.
    tx.vin[0].prevout.hash = hashFreeTx;
    const auto low_fee_probe_entry = entry.Fee(0).FromTx(tx);
    const size_t lowFeeTxPolicySize = low_fee_probe_entry.GetTxSize();
    const CAmount minPackageFee = blockMinFeeRate.GetFee(freeTxPolicySize + lowFeeTxPolicySize);
    CAmount feeToUse = minPackageFee - 1;

    tx.vout[0].nValue = 5000000000LL - 1000 - 50000 - feeToUse;
    Txid hashLowFeeTx = tx.GetHash();
    AddToMempool(tx_mempool, entry.Fee(feeToUse).FromTx(tx));
    block_template = mining->createNewBlock(options);
    BOOST_REQUIRE(block_template);
    block = block_template->getBlock();
    // Verify that the free tx and the low fee tx didn't get selected
    for (size_t i=0; i<block.vtx.size(); ++i) {
        BOOST_CHECK(block.vtx[i]->GetHash() != hashFreeTx);
        BOOST_CHECK(block.vtx[i]->GetHash() != hashLowFeeTx);
    }

    // Test that packages above the min relay fee do get included, even if one
    // of the transactions is below the min relay fee
    // Remove the low fee transaction and replace with an above-threshold fee transaction.
    tx_mempool.removeRecursive(CTransaction(tx), MemPoolRemovalReason::REPLACED);
    tx.vout[0].nValue = 5000000000LL - 1000 - 50000 - (minPackageFee + 1000);
    hashLowFeeTx = tx.GetHash();
    AddToMempool(tx_mempool, entry.Fee(minPackageFee + 1000).FromTx(tx));
    block_template = mining->createNewBlock(options);
    BOOST_REQUIRE(block_template);
    block = block_template->getBlock();
    BOOST_REQUIRE_EQUAL(block.vtx.size(), 6U);
    BOOST_CHECK(block.vtx[4]->GetHash() == hashFreeTx);
    BOOST_CHECK(block.vtx[5]->GetHash() == hashLowFeeTx);

    // Test that transaction selection properly updates ancestor fee
    // calculations as ancestor transactions get included in a block.
    // Add a 0-fee transaction that has 2 outputs.
    tx.vin[0].prevout.hash = txFirst[2]->GetHash();
    tx.vout.resize(2);
    tx.vout[0].nValue = 5000000000LL - 100000000;
    tx.vout[1].nValue = 100000000; // 1BTC output
    // Increase size to avoid rounding errors: when the feerate is extremely small (i.e. 1sat/kvB), evaluating the fee
    // at a smaller transaction size gives us a rounded value of 0.
    BulkTransaction(tx, 4000);
    Txid hashFreeTx2 = tx.GetHash();
    AddToMempool(tx_mempool, entry.Fee(0).SpendsCoinbase(true).FromTx(tx));

    // This tx can't be mined by itself
    tx.vin[0].prevout.hash = hashFreeTx2;
    tx.vout.resize(1);
    const size_t lowFeeTx2VSize = GetVirtualTransactionSize(CTransaction{tx});
    feeToUse = blockMinFeeRate.GetFee(lowFeeTx2VSize);
    tx.vout[0].nValue = 5000000000LL - 100000000 - feeToUse;
    Txid hashLowFeeTx2 = tx.GetHash();
    AddToMempool(tx_mempool, entry.Fee(feeToUse).SpendsCoinbase(false).FromTx(tx));
    block_template = mining->createNewBlock(options);
    BOOST_REQUIRE(block_template);
    block = block_template->getBlock();

    // Verify that this tx isn't selected.
    for (size_t i=0; i<block.vtx.size(); ++i) {
        BOOST_CHECK(block.vtx[i]->GetHash() != hashFreeTx2);
        BOOST_CHECK(block.vtx[i]->GetHash() != hashLowFeeTx2);
    }

    // This tx will be mineable, and should cause hashLowFeeTx2 to be selected
    // as well.
    tx.vin[0].prevout.n = 1;
    tx.vout[0].nValue = 100000000 - 10000; // 10k satoshi fee
    AddToMempool(tx_mempool, entry.Fee(10000).FromTx(tx));
    block_template = mining->createNewBlock(options);
    BOOST_REQUIRE(block_template);
    block = block_template->getBlock();
    BOOST_REQUIRE_EQUAL(block.vtx.size(), 9U);
    BOOST_CHECK(block.vtx[8]->GetHash() == hashLowFeeTx2);
}

void MinerTestingSetup::TestBasicMining(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst, int baseheight)
{
    Txid hash;
    CMutableTransaction tx;
    TestMemPoolEntryHelper entry;
    entry.nFee = 11;
    entry.nHeight = 11;

    const CAmount BLOCKSUBSIDY = 50 * COIN;
    const CAmount LOWFEE = CENT;
    const CAmount HIGHFEE = COIN;
    const CAmount HIGHERFEE = 4 * COIN;

    auto mining{MakeMining()};
    BOOST_REQUIRE(mining);

    BlockAssembler::Options options;
    options.coinbase_output_script = scriptPubKey;

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // Just to make sure we can still make simple blocks
        auto block_template{mining->createNewBlock(options)};
        BOOST_REQUIRE(block_template);
        CBlock block{block_template->getBlock()};

        // block sigops > limit: 1000 CHECKMULTISIG + 1
        tx.vin.resize(1);
        // NOTE: OP_NOP is used to force 20 SigOps for the CHECKMULTISIG
        tx.vin[0].scriptSig = CScript() << OP_0 << OP_0 << OP_0 << OP_NOP << OP_CHECKMULTISIG << OP_1;
        tx.vin[0].prevout.hash = txFirst[0]->GetHash();
        tx.vin[0].prevout.n = 0;
        tx.vout.resize(1);
        tx.vout[0].nValue = BLOCKSUBSIDY;
        for (unsigned int i = 0; i < 1001; ++i) {
            tx.vout[0].nValue -= LOWFEE;
            hash = tx.GetHash();
            bool spendsCoinbase = i == 0; // only first tx spends coinbase
            // If we don't set the # of sig ops in the CTxMemPoolEntry, template creation fails
            AddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(spendsCoinbase).FromTx(tx));
            tx.vin[0].prevout.hash = hash;
        }

        BOOST_REQUIRE(mining->createNewBlock(options));
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        tx.vin[0].prevout.hash = txFirst[0]->GetHash();
        tx.vout[0].nValue = BLOCKSUBSIDY;
        for (unsigned int i = 0; i < 1001; ++i) {
            tx.vout[0].nValue -= LOWFEE;
            hash = tx.GetHash();
            bool spendsCoinbase = i == 0; // only first tx spends coinbase
            // If we do set the # of sig ops in the CTxMemPoolEntry, template creation passes
            AddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(spendsCoinbase).SigOpsCost(80).FromTx(tx));
            tx.vin[0].prevout.hash = hash;
        }
        BOOST_REQUIRE(mining->createNewBlock(options));
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // block size > limit
        tx.vin[0].scriptSig = CScript();
        // 18 * (520char + DROP) + OP_1 = 9433 bytes
        std::vector<unsigned char> vchData(520);
        for (unsigned int i = 0; i < 18; ++i) {
            tx.vin[0].scriptSig << vchData << OP_DROP;
        }
        tx.vin[0].scriptSig << OP_1;
        tx.vin[0].prevout.hash = txFirst[0]->GetHash();
        tx.vout[0].nValue = BLOCKSUBSIDY;
        for (unsigned int i = 0; i < 128; ++i) {
            tx.vout[0].nValue -= LOWFEE;
            hash = tx.GetHash();
            bool spendsCoinbase = i == 0; // only first tx spends coinbase
            AddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(spendsCoinbase).FromTx(tx));
            tx.vin[0].prevout.hash = hash;
        }
        BOOST_REQUIRE(mining->createNewBlock(options));
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // orphan in tx_mempool, template creation fails
        hash = tx.GetHash();
        AddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).FromTx(tx));
        BOOST_REQUIRE(mining->createNewBlock(options));
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // child with higher feerate than parent
        tx.vin[0].scriptSig = CScript() << OP_1;
        tx.vin[0].prevout.hash = txFirst[1]->GetHash();
        tx.vout[0].nValue = BLOCKSUBSIDY - HIGHFEE;
        hash = tx.GetHash();
        AddToMempool(tx_mempool, entry.Fee(HIGHFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
        tx.vin[0].prevout.hash = hash;
        tx.vin.resize(2);
        tx.vin[1].scriptSig = CScript() << OP_1;
        tx.vin[1].prevout.hash = txFirst[0]->GetHash();
        tx.vin[1].prevout.n = 0;
        tx.vout[0].nValue = tx.vout[0].nValue + BLOCKSUBSIDY - HIGHERFEE; // First txn output + fresh coinbase - new txn fee
        hash = tx.GetHash();
        AddToMempool(tx_mempool, entry.Fee(HIGHERFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
        BOOST_REQUIRE(mining->createNewBlock(options));
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // coinbase in tx_mempool, template creation fails
        tx.vin.resize(1);
        tx.vin[0].prevout.SetNull();
        tx.vin[0].scriptSig = CScript() << OP_0 << OP_1;
        tx.vout[0].nValue = 0;
        hash = tx.GetHash();
        // give it a fee so it'll get mined
        AddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(false).FromTx(tx));
        BOOST_REQUIRE(mining->createNewBlock(options));
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // double spend txn pair in tx_mempool, template creation fails
        tx.vin[0].prevout.hash = txFirst[0]->GetHash();
        tx.vin[0].scriptSig = CScript() << OP_1;
        tx.vout[0].nValue = BLOCKSUBSIDY - HIGHFEE;
        tx.vout[0].scriptPubKey = CScript() << OP_1;
        hash = tx.GetHash();
        AddToMempool(tx_mempool, entry.Fee(HIGHFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
        const Txid first_double_spend = hash;
        tx.vout[0].scriptPubKey = CScript() << OP_2;
        hash = tx.GetHash();
        AddToMempool(tx_mempool, entry.Fee(HIGHFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
        const Txid second_double_spend = hash;
        (void)first_double_spend;
        (void)second_double_spend;
        BOOST_REQUIRE(mining->createNewBlock(options));
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // subsidy changing
        int nHeight = m_node.chainman->ActiveChain().Height();
        // Create an actual 209999-long block chain (without valid blocks).
        while (m_node.chainman->ActiveChain().Tip()->nHeight < 209999) {
            CBlockIndex* prev = m_node.chainman->ActiveChain().Tip();
            CBlockIndex* next = new CBlockIndex();
            next->phashBlock = new uint256(m_rng.rand256());
            m_node.chainman->ActiveChainstate().CoinsTip().SetBestBlock(next->GetBlockHash());
            next->pprev = prev;
            next->nHeight = prev->nHeight + 1;
            next->BuildSkip();
            m_node.chainman->ActiveChain().SetTip(*next);
        }
        BOOST_REQUIRE(mining->createNewBlock(options));
        // Extend to a 210000-long block chain.
        while (m_node.chainman->ActiveChain().Tip()->nHeight < 210000) {
            CBlockIndex* prev = m_node.chainman->ActiveChain().Tip();
            CBlockIndex* next = new CBlockIndex();
            next->phashBlock = new uint256(m_rng.rand256());
            m_node.chainman->ActiveChainstate().CoinsTip().SetBestBlock(next->GetBlockHash());
            next->pprev = prev;
            next->nHeight = prev->nHeight + 1;
            next->BuildSkip();
            m_node.chainman->ActiveChain().SetTip(*next);
        }
        BOOST_REQUIRE(mining->createNewBlock(options));

        // invalid p2sh txn in tx_mempool, template creation fails
        tx.vin[0].prevout.hash = txFirst[0]->GetHash();
        tx.vin[0].prevout.n = 0;
        tx.vin[0].scriptSig = CScript() << OP_1;
        tx.vout[0].nValue = BLOCKSUBSIDY - LOWFEE;
        CScript script = CScript() << OP_0;
        tx.vout[0].scriptPubKey = GetScriptForDestination(ScriptHash(script));
        hash = tx.GetHash();
        AddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
        tx.vin[0].prevout.hash = hash;
        tx.vin[0].scriptSig = CScript() << std::vector<unsigned char>(script.begin(), script.end());
        tx.vout[0].nValue -= LOWFEE;
        hash = tx.GetHash();
        AddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(false).FromTx(tx));
        const Txid invalid_p2sh_child = hash;
        (void)invalid_p2sh_child;
        BOOST_REQUIRE(mining->createNewBlock(options));

        // Delete the dummy blocks again.
        while (m_node.chainman->ActiveChain().Tip()->nHeight > nHeight) {
            CBlockIndex* del = m_node.chainman->ActiveChain().Tip();
            m_node.chainman->ActiveChain().SetTip(*Assert(del->pprev));
            m_node.chainman->ActiveChainstate().CoinsTip().SetBestBlock(del->pprev->GetBlockHash());
            delete del->phashBlock;
            delete del;
        }
    }

    CTxMemPool& tx_mempool{MakeMempool()};
    LOCK(tx_mempool.cs);

    // non-final txs in mempool
    SetMockTime(m_node.chainman->ActiveChain().Tip()->GetMedianTimePast() + 1);
    const int flags{LOCKTIME_VERIFY_SEQUENCE};
    // height map
    std::vector<int> prevheights;

    // relative height locked
    tx.version = 2;
    tx.vin.resize(1);
    prevheights.resize(1);
    tx.vin[0].prevout.hash = txFirst[0]->GetHash(); // only 1 transaction
    tx.vin[0].prevout.n = 0;
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].nSequence = m_node.chainman->ActiveChain().Tip()->nHeight + 1; // txFirst[0] is the 2nd block
    prevheights[0] = baseheight + 1;
    tx.vout.resize(1);
    tx.vout[0].nValue = BLOCKSUBSIDY-HIGHFEE;
    tx.vout[0].scriptPubKey = CScript() << OP_1;
    tx.nLockTime = 0;
    hash = tx.GetHash();
    AddToMempool(tx_mempool, entry.Fee(HIGHFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
    BOOST_CHECK(CheckFinalTxAtTip(*Assert(m_node.chainman->ActiveChain().Tip()), CTransaction{tx})); // Locktime passes
    BOOST_CHECK(!TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks fail

    {
        CBlockIndex* active_chain_tip = m_node.chainman->ActiveChain().Tip();
        BOOST_CHECK(SequenceLocks(CTransaction(tx), flags, prevheights, *CreateBlockIndex(active_chain_tip->nHeight + 2, active_chain_tip))); // Sequence locks pass on 2nd block
    }

    // relative time locked
    tx.vin[0].prevout.hash = txFirst[1]->GetHash();
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | (((m_node.chainman->ActiveChain().Tip()->GetMedianTimePast()+1-m_node.chainman->ActiveChain()[1]->GetMedianTimePast()) >> CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) + 1); // txFirst[1] is the 3rd block
    prevheights[0] = baseheight + 2;
    hash = tx.GetHash();
    AddToMempool(tx_mempool, entry.Time(Now<NodeSeconds>()).FromTx(tx));
    BOOST_CHECK(CheckFinalTxAtTip(*Assert(m_node.chainman->ActiveChain().Tip()), CTransaction{tx})); // Locktime passes
    BOOST_CHECK(!TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks fail

    const int SEQUENCE_LOCK_TIME = 512; // Sequence locks pass 512 seconds later
    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; ++i)
        m_node.chainman->ActiveChain().Tip()->GetAncestor(m_node.chainman->ActiveChain().Tip()->nHeight - i)->nTime += SEQUENCE_LOCK_TIME; // Trick the MedianTimePast
    {
        CBlockIndex* active_chain_tip = m_node.chainman->ActiveChain().Tip();
        BOOST_CHECK(SequenceLocks(CTransaction(tx), flags, prevheights, *CreateBlockIndex(active_chain_tip->nHeight + 1, active_chain_tip)));
    }

    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; ++i) {
        CBlockIndex* ancestor{Assert(m_node.chainman->ActiveChain().Tip()->GetAncestor(m_node.chainman->ActiveChain().Tip()->nHeight - i))};
        ancestor->nTime -= SEQUENCE_LOCK_TIME; // undo tricked MTP
    }

    // absolute height locked
    tx.vin[0].prevout.hash = txFirst[2]->GetHash();
    tx.vin[0].nSequence = CTxIn::MAX_SEQUENCE_NONFINAL;
    prevheights[0] = baseheight + 3;
    tx.nLockTime = m_node.chainman->ActiveChain().Tip()->nHeight + 1;
    hash = tx.GetHash();
    AddToMempool(tx_mempool, entry.Time(Now<NodeSeconds>()).FromTx(tx));
    BOOST_CHECK(!CheckFinalTxAtTip(*Assert(m_node.chainman->ActiveChain().Tip()), CTransaction{tx})); // Locktime fails
    BOOST_CHECK(TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks pass
    BOOST_CHECK(IsFinalTx(CTransaction(tx), m_node.chainman->ActiveChain().Tip()->nHeight + 2, m_node.chainman->ActiveChain().Tip()->GetMedianTimePast())); // Locktime passes on 2nd block

    // absolute time locked
    tx.vin[0].prevout.hash = txFirst[3]->GetHash();
    tx.nLockTime = m_node.chainman->ActiveChain().Tip()->GetMedianTimePast();
    prevheights.resize(1);
    prevheights[0] = baseheight + 4;
    hash = tx.GetHash();
    AddToMempool(tx_mempool, entry.Time(Now<NodeSeconds>()).FromTx(tx));
    BOOST_CHECK(!CheckFinalTxAtTip(*Assert(m_node.chainman->ActiveChain().Tip()), CTransaction{tx})); // Locktime fails
    BOOST_CHECK(TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks pass
    BOOST_CHECK(IsFinalTx(CTransaction(tx), m_node.chainman->ActiveChain().Tip()->nHeight + 2, m_node.chainman->ActiveChain().Tip()->GetMedianTimePast() + 1)); // Locktime passes 1 second later

    // mempool-dependent transactions (not added)
    tx.vin[0].prevout.hash = hash;
    prevheights[0] = m_node.chainman->ActiveChain().Tip()->nHeight + 1;
    tx.nLockTime = 0;
    tx.vin[0].nSequence = 0;
    BOOST_CHECK(CheckFinalTxAtTip(*Assert(m_node.chainman->ActiveChain().Tip()), CTransaction{tx})); // Locktime passes
    BOOST_CHECK(TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks pass
    tx.vin[0].nSequence = 1;
    BOOST_CHECK(!TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks fail
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG;
    BOOST_CHECK(TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks pass
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | 1;
    BOOST_CHECK(!TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks fail

    auto block_template = mining->createNewBlock(options);
    BOOST_REQUIRE(block_template);

    // None of the of the absolute height/time locked tx should have made
    // it into the template because we still check IsFinalTx in CreateNewBlock,
    // but relative locked txs will if inconsistently added to mempool.
    // For now these will still generate a valid template until BIP68 soft fork
    CBlock block{block_template->getBlock()};
    BOOST_CHECK_EQUAL(block.vtx.size(), 3U);
    // However if we advance height by 1 and time by SEQUENCE_LOCK_TIME, all of them should be mined
    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; ++i) {
        CBlockIndex* ancestor{Assert(m_node.chainman->ActiveChain().Tip()->GetAncestor(m_node.chainman->ActiveChain().Tip()->nHeight - i))};
        ancestor->nTime += SEQUENCE_LOCK_TIME; // Trick the MedianTimePast
    }
    m_node.chainman->ActiveChain().Tip()->nHeight++;
    SetMockTime(m_node.chainman->ActiveChain().Tip()->GetMedianTimePast() + 1);

    block_template = mining->createNewBlock(options);
    BOOST_REQUIRE(block_template);
    block = block_template->getBlock();
    BOOST_CHECK_EQUAL(block.vtx.size(), 5U);
}

void MinerTestingSetup::TestConsensusSerializedSizeLimit(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst)
{
    CTxMemPool& tx_mempool{MakeMempool()};
    auto mining{MakeMining()};
    BOOST_REQUIRE(mining);

    BlockAssembler::Options options;
    options.coinbase_output_script = scriptPubKey;
    options.nBlockMaxWeight = MAX_BLOCK_WEIGHT;
    options.nBlockMaxSize = MAX_BLOCK_SERIALIZED_SIZE;

    LOCK(tx_mempool.cs);

    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].scriptWitness.stack.emplace_back(MAX_BLOCK_SERIALIZED_SIZE + 1024, 0x42);
    tx.vout.resize(1);
    tx.vout[0].nValue = 50 * COIN - 1;
    tx.vout[0].scriptPubKey = CScript() << OP_1;

    const Txid oversized_txid = tx.GetHash();
    TestMemPoolEntryHelper entry;
    AddToMempool(tx_mempool, entry.Fee(1).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));

    std::unique_ptr<BlockTemplate> block_template = mining->createNewBlock(options);
    BOOST_REQUIRE(block_template);
    CBlock block{block_template->getBlock()};

    bool oversized_tx_included{false};
    for (const auto& block_tx : block.vtx) {
        if (block_tx->GetHash() == oversized_txid) {
            oversized_tx_included = true;
            break;
        }
    }
    BOOST_CHECK(!oversized_tx_included);
    BOOST_CHECK_LE(::GetSerializeSize(TX_WITH_WITNESS(block)), MAX_BLOCK_SERIALIZED_SIZE);
}

void MinerTestingSetup::TestPrioritisedMining(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst)
{
    auto mining{MakeMining()};
    BOOST_REQUIRE(mining);

    BlockAssembler::Options options;
    options.coinbase_output_script = scriptPubKey;

    CTxMemPool& tx_mempool{MakeMempool()};
    LOCK(tx_mempool.cs);

    TestMemPoolEntryHelper entry;

    // Test that a tx below min fee but prioritised is included
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vout.resize(1);
    tx.vout[0].nValue = 5000000000LL; // 0 fee
    uint256 hashFreePrioritisedTx = tx.GetHash();
    AddToMempool(tx_mempool, entry.Fee(0).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
    tx_mempool.PrioritiseTransaction(hashFreePrioritisedTx, 5 * COIN);

    tx.vin[0].prevout.hash = txFirst[1]->GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vout[0].nValue = 5000000000LL - 1000;
    // This tx has a low fee: 1000 satoshis
    Txid hashParentTx = tx.GetHash(); // save this txid for later use
    AddToMempool(tx_mempool, entry.Fee(1000).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));

    // This tx has a medium fee: 10000 satoshis
    tx.vin[0].prevout.hash = txFirst[2]->GetHash();
    tx.vout[0].nValue = 5000000000LL - 10000;
    Txid hashMediumFeeTx = tx.GetHash();
    AddToMempool(tx_mempool, entry.Fee(10000).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
    tx_mempool.PrioritiseTransaction(hashMediumFeeTx, -5 * COIN);

    // This tx also has a low fee, but is prioritised
    tx.vin[0].prevout.hash = hashParentTx;
    tx.vout[0].nValue = 5000000000LL - 1000 - 1000; // 1000 satoshi fee
    Txid hashPrioritsedChild = tx.GetHash();
    AddToMempool(tx_mempool, entry.Fee(1000).Time(Now<NodeSeconds>()).SpendsCoinbase(false).FromTx(tx));
    tx_mempool.PrioritiseTransaction(hashPrioritsedChild, 2 * COIN);

    // Test that transaction selection properly updates ancestor fee calculations as prioritised
    // parents get included in a block. Create a transaction with two prioritised ancestors, each
    // included by itself: FreeParent <- FreeChild <- FreeGrandchild.
    // When FreeParent is added, a modified entry will be created for FreeChild + FreeGrandchild
    // FreeParent's prioritisation should not be included in that entry.
    // When FreeChild is included, FreeChild's prioritisation should also not be included.
    tx.vin[0].prevout.hash = txFirst[3]->GetHash();
    tx.vout[0].nValue = 5000000000LL; // 0 fee
    Txid hashFreeParent = tx.GetHash();
    AddToMempool(tx_mempool, entry.Fee(0).SpendsCoinbase(true).FromTx(tx));
    tx_mempool.PrioritiseTransaction(hashFreeParent, 10 * COIN);

    tx.vin[0].prevout.hash = hashFreeParent;
    tx.vout[0].nValue = 5000000000LL; // 0 fee
    Txid hashFreeChild = tx.GetHash();
    AddToMempool(tx_mempool, entry.Fee(0).SpendsCoinbase(false).FromTx(tx));
    tx_mempool.PrioritiseTransaction(hashFreeChild, 1 * COIN);

    tx.vin[0].prevout.hash = hashFreeChild;
    tx.vout[0].nValue = 5000000000LL; // 0 fee
    Txid hashFreeGrandchild = tx.GetHash();
    AddToMempool(tx_mempool, entry.Fee(0).SpendsCoinbase(false).FromTx(tx));

    auto block_template = mining->createNewBlock(options);
    BOOST_REQUIRE(block_template);
    CBlock block{block_template->getBlock()};
    BOOST_REQUIRE_EQUAL(block.vtx.size(), 6U);
    BOOST_CHECK(block.vtx[1]->GetHash() == hashFreeParent);
    BOOST_CHECK(block.vtx[2]->GetHash() == hashFreePrioritisedTx);
    BOOST_CHECK(block.vtx[3]->GetHash() == hashParentTx);
    BOOST_CHECK(block.vtx[4]->GetHash() == hashPrioritsedChild);
    BOOST_CHECK(block.vtx[5]->GetHash() == hashFreeChild);
    for (size_t i=0; i<block.vtx.size(); ++i) {
        // The FreeParent and FreeChild's prioritisations should not impact the child.
        BOOST_CHECK(block.vtx[i]->GetHash() != hashFreeGrandchild);
        // De-prioritised transaction should not be included.
        BOOST_CHECK(block.vtx[i]->GetHash() != hashMediumFeeTx);
    }
}

void MinerTestingSetup::TestShieldedAnchorTemplateCleanup(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst)
{
    auto mining{MakeMining()};
    BOOST_REQUIRE(mining);

    BlockAssembler::Options options;
    options.coinbase_output_script = scriptPubKey;

    CTxMemPool& tx_mempool{MakeMempool()};
    TestMemPoolEntryHelper entry;
    Txid stale_txid;
    Txid stale_registry_txid;

    {
        LOCK2(::cs_main, tx_mempool.cs);
        ChainstateManager& chainman{*Assert(m_node.chainman)};
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());

        const uint256 stale_anchor = chainman.GetShieldedMerkleTree().Root();
        const uint256 stale_registry_anchor = chainman.GetShieldedAccountRegistryRoot();
        BOOST_REQUIRE(!stale_anchor.IsNull());
        BOOST_REQUIRE(!stale_registry_anchor.IsNull());

        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout.hash = txFirst[0]->GetHash();
        tx.vin[0].prevout.n = 0;
        tx.vin[0].scriptSig = CScript() << OP_1;
        tx.vout.resize(1);
        tx.vout[0].nValue = 5000000000LL - 1000;
        tx.shielded_bundle.proof = {0x01};

        CShieldedOutput out;
        out.note_commitment = GetRandHash();
        out.merkle_anchor = stale_anchor;
        tx.shielded_bundle.shielded_outputs.push_back(out);
        stale_txid = tx.GetHash();

        AddToMempool(tx_mempool, entry.Fee(1000).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
        BOOST_REQUIRE(tx_mempool.exists(GenTxid::Txid(stale_txid)));

        CMutableTransaction v2_tx;
        v2_tx.vin.resize(1);
        v2_tx.vin[0].prevout.hash = txFirst[1]->GetHash();
        v2_tx.vin[0].prevout.n = 0;
        v2_tx.vin[0].scriptSig = CScript() << OP_1;
        v2_tx.vout.resize(1);
        v2_tx.vout[0].nValue = 5000000000LL - 2000;
        v2_tx.shielded_bundle.v2_bundle =
            MakeSyntheticSendBundle(/*seed=*/90'000, stale_anchor, stale_registry_anchor);
        stale_registry_txid = v2_tx.GetHash();

        AddToMempool(tx_mempool,
                     entry.Fee(2000).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(v2_tx));
        BOOST_REQUIRE(tx_mempool.exists(GenTxid::Txid(stale_registry_txid)));

        for (int i = 0; i <= SHIELDED_ANCHOR_DEPTH; ++i) {
            chainman.RecordShieldedAnchorRoot(GetRandHash());
            chainman.RecordShieldedAccountRegistryRoot(GetRandHash());
        }
        BOOST_CHECK(HasInvalidShieldedAnchors(CTransaction{tx}, chainman));
        BOOST_CHECK(HasInvalidShieldedAnchors(CTransaction{v2_tx}, chainman));
    }

    auto block_template = mining->createNewBlock(options);
    BOOST_REQUIRE(block_template);
    CBlock block{block_template->getBlock()};

    {
        LOCK(tx_mempool.cs);
        BOOST_CHECK(!tx_mempool.exists(GenTxid::Txid(stale_txid)));
        BOOST_CHECK(!tx_mempool.exists(GenTxid::Txid(stale_registry_txid)));
    }
    for (const auto& block_tx : block.vtx) {
        BOOST_CHECK(block_tx->GetHash() != stale_txid);
        BOOST_CHECK(block_tx->GetHash() != stale_registry_txid);
    }
}

// NOTE: These tests rely on CreateNewBlock doing its own self-validation!
BOOST_AUTO_TEST_CASE(CreateNewBlock_validity)
{
    gArgs.ForceSetArg("-blockprioritysize", "0");

    auto mining{MakeMining()};
    BOOST_REQUIRE(mining);

    // Note that by default, these tests run with size accounting enabled.
    CScript scriptPubKey = CScript() << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"_hex << OP_CHECKSIG;
    BlockAssembler::Options options;
    options.coinbase_output_script = scriptPubKey;
    std::unique_ptr<BlockTemplate> block_template;

    // We can't make transactions until we have inputs
    // Therefore, load 110 blocks :)
    constexpr size_t kMatureInputsBlockCount{110};
    int baseheight = 0;
    std::vector<CTransactionRef> txFirst;
    for (size_t i = 0; i < kMatureInputsBlockCount; ++i) {
        const int current_height{mining->getTip()->height};

        // Simple block creation, nothing special yet:
        block_template = mining->createNewBlock(options);
        BOOST_REQUIRE(block_template);

        CBlock block{block_template->getBlock()};
        CMutableTransaction txCoinbase(*block.vtx[0]);
        {
            LOCK(cs_main);
            block.nVersion = VERSIONBITS_TOP_BITS;
            block.nTime = Assert(m_node.chainman)->ActiveChain().Tip()->GetMedianTimePast()+1;
            txCoinbase.version = 1;
            txCoinbase.vin[0].scriptSig = CScript{} << (current_height + 1) << static_cast<uint64_t>(i);
            txCoinbase.vout.resize(1); // Keep deterministic coinbase layout across strict KAWPOW solves.
            txCoinbase.vin[0].scriptWitness.SetNull();
            txCoinbase.vout[0].scriptPubKey = CScript();
            block.vtx[0] = MakeTransactionRef(txCoinbase);
            if (txFirst.size() == 0)
                baseheight = current_height;
            if (txFirst.size() < 4)
                txFirst.push_back(block.vtx[0]);
            block.hashMerkleRoot = BlockMerkleRoot(block);
            block.nNonce = 0;
            block.nNonce64 = 0;
            block.mix_hash.SetNull();
            const uint32_t block_height{static_cast<uint32_t>(current_height + 1)};
            BOOST_REQUIRE(MineHeaderForConsensus(block, block_height, Assert(m_node.chainman)->GetConsensus(), 10'000'000));
            PopulateFreivaldsPayload(block, Assert(m_node.chainman)->GetConsensus());
        }
        std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(block);
        // Alternate calls between Chainman's ProcessNewBlock and submitSolution
        // via the Mining interface. The former is used by net_processing as well
        // as the submitblock RPC.
        if (current_height % 2 == 0) {
            BOOST_REQUIRE(Assert(m_node.chainman)->ProcessNewBlock(shared_pblock, /*force_processing=*/true, /*min_pow_checked=*/true, nullptr));
        } else {
            BOOST_REQUIRE(block_template->submitSolution(block.nVersion, block.nTime, block.nNonce, MakeTransactionRef(txCoinbase), block.nNonce64, block.mix_hash));
        }
        {
            LOCK(cs_main);
            // The above calls don't guarantee the tip is actually updated, so
            // we explicitly check this.
            auto maybe_new_tip{Assert(m_node.chainman)->ActiveChain().Tip()};
            BOOST_REQUIRE_EQUAL(maybe_new_tip->GetBlockHash(), block.GetHash());
        }
        // This just adds coverage
        mining->waitTipChanged(block.hashPrevBlock);
    }

    LOCK(cs_main);

    TestBasicMining(scriptPubKey, txFirst, baseheight);
    TestConsensusSerializedSizeLimit(scriptPubKey, txFirst);

    m_node.chainman->ActiveChain().Tip()->nHeight--;
    SetMockTime(0);

    TestPackageSelection(scriptPubKey, txFirst);

    m_node.chainman->ActiveChain().Tip()->nHeight--;
    SetMockTime(0);

    TestPrioritisedMining(scriptPubKey, txFirst);
    TestShieldedAnchorTemplateCleanup(scriptPubKey, txFirst);
}

BOOST_AUTO_TEST_CASE(height_overflow_guards)
{
    auto mining{MakeMining()};
    BOOST_REQUIRE(mining);

    CBlockIndex* tip{nullptr};
    int original_height{0};
    {
        LOCK(cs_main);
        tip = Assert(m_node.chainman)->ActiveChain().Tip();
        BOOST_REQUIRE(tip != nullptr);
        original_height = tip->nHeight;
        tip->nHeight = std::numeric_limits<int>::max();

        CMutableTransaction tx_mut;
        tx_mut.nLockTime = std::numeric_limits<uint32_t>::max();
        const CTransaction tx{tx_mut};
        BOOST_CHECK(!CheckFinalTxAtTip(*tip, tx));
        BOOST_CHECK(!CalculateLockPointsAtTip(tip, m_node.chainman->ActiveChainstate().CoinsTip(), tx).has_value());
        BOOST_CHECK(!CheckSequenceLocksAtTip(tip, LockPoints{0, 0, nullptr}));

        CMutableTransaction coinbase_tx_mut;
        coinbase_tx_mut.version = 1;
        coinbase_tx_mut.vin.resize(1);
        coinbase_tx_mut.vout.resize(1);
        coinbase_tx_mut.vin[0].scriptSig = CScript{} << OP_1;
        coinbase_tx_mut.vout[0].nValue = 0;
        coinbase_tx_mut.vout[0].scriptPubKey = CScript{} << OP_TRUE;
        const MempoolAcceptResult tx_result{
            m_node.chainman->ProcessTransaction(MakeTransactionRef(coinbase_tx_mut), /*test_accept=*/true)};
        BOOST_CHECK(tx_result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    }

    BlockAssembler::Options options;
    options.coinbase_output_script = CScript{} << OP_2 << std::vector<unsigned char>(32, 0x01);
    BOOST_CHECK_THROW(mining->createNewBlock(options), std::runtime_error);
    CBlockIndex next_index{};
    BOOST_CHECK_THROW(NextEmptyBlockIndex(*tip, m_node.chainman->GetConsensus(), next_index), std::runtime_error);

    LOCK(cs_main);
    tip->nHeight = original_height;
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(miner_shielded_tests, miner_tests::ShieldedMinerTestingSetup)

BOOST_AUTO_TEST_CASE(block_assembler_fills_last_scan_slot_when_scan_capacity_is_scarce)
{
    BlockAssembler::Options options = MakeSyntheticBlockAssemblerOptions();
    const uint256 settlement_anchor = ConfirmSyntheticSettlementAnchorDigest(*this, options.coinbase_output_script);
    const uint256 spend_anchor = GetCurrentSyntheticSpendAnchor(*this);
    const uint256 account_registry_anchor = GetCurrentSyntheticAccountRegistryAnchor(*this);
    CTxMemPool& tx_mempool{MakeMempool()};
    size_t funding_index{0};
    auto next_funding_tx = [&]() -> const CTransactionRef& {
        BOOST_REQUIRE_LT(funding_index, m_coinbase_txns.size());
        return m_coinbase_txns.at(funding_index++);
    };

    uint64_t sequence{0};
    Txid scan_txid;
    Txid tree_txid;
    {
        LOCK(tx_mempool.cs);
        for (size_t i = 0; i < SCARCITY_TEST_FILLER_COUNT; ++i) {
            AddSyntheticShieldedMinerTx(tx_mempool,
                                        next_funding_tx(),
                                        10'000 + static_cast<uint32_t>(i),
                                        /*fee=*/1'000'000,
                                        MakeSyntheticEgressBundle(/*output_count=*/0,
                                                                  SCARCITY_TEST_OUTPUT_CHUNKS,
                                                                  10'000 + static_cast<uint32_t>(i),
                                                                  settlement_anchor),
                                        sequence++);
        }

        scan_txid = AddSyntheticShieldedMinerTx(tx_mempool,
                                                next_funding_tx(),
                                                20'000,
                                                /*fee=*/150'000,
                                                MakeSyntheticEgressBundle(/*output_count=*/0,
                                                                          SCARCITY_TEST_OUTPUT_CHUNKS,
                                                                          20'000,
                                                                          settlement_anchor),
                                                sequence++);
        tree_txid = AddSyntheticShieldedMinerTx(tx_mempool,
                                                next_funding_tx(),
                                                20'001,
                                                /*fee=*/100'000,
                                                MakeSyntheticIngressBundle(SCARCITY_TEST_RESOURCE_UNITS,
                                                                           20'001,
                                                                           spend_anchor,
                                                                           account_registry_anchor),
                                                sequence++);

        const auto& scan_entry = GetSyntheticMinerEntry(tx_mempool, scan_txid);
        const auto& tree_entry = GetSyntheticMinerEntry(tx_mempool, tree_txid);
        BOOST_CHECK(CompareTxMemPoolEntryByAncestorFee{}(scan_entry, tree_entry));
        BOOST_CHECK(!CompareTxMemPoolEntryByAncestorFee{}(tree_entry, scan_entry));
    }
    auto block_template = BlockAssembler{Assert(m_node.chainman)->ActiveChainstate(), &tx_mempool, options, m_node}.CreateNewBlock();
    BOOST_REQUIRE(block_template);

    const size_t scan_index = FindBlockTxIndex(block_template->block, scan_txid);
    const size_t tree_index = FindBlockTxIndex(block_template->block, tree_txid);
    BOOST_REQUIRE(scan_index != block_template->block.vtx.size());
    BOOST_CHECK_EQUAL(tree_index, block_template->block.vtx.size());
    BOOST_CHECK_EQUAL(block_template->nShieldedScanUnits, (SCARCITY_TEST_FILLER_COUNT + 1) * SCARCITY_TEST_OUTPUT_CHUNKS);
    BOOST_CHECK_EQUAL(block_template->nShieldedTreeUpdateUnits, 0U);
}

BOOST_AUTO_TEST_CASE(block_assembler_fills_last_tree_slot_when_tree_capacity_is_scarce)
{
    BlockAssembler::Options options = MakeSyntheticBlockAssemblerOptions();
    const uint256 settlement_anchor = ConfirmSyntheticSettlementAnchorDigest(*this, options.coinbase_output_script);
    const uint256 spend_anchor = GetCurrentSyntheticSpendAnchor(*this);
    const uint256 account_registry_anchor = GetCurrentSyntheticAccountRegistryAnchor(*this);
    CTxMemPool& tx_mempool{MakeMempool()};
    size_t funding_index{0};
    auto next_funding_tx = [&]() -> const CTransactionRef& {
        BOOST_REQUIRE_LT(funding_index, m_coinbase_txns.size());
        return m_coinbase_txns.at(funding_index++);
    };

    uint64_t sequence{0};
    Txid tree_txid;
    Txid scan_txid;
    {
        LOCK(tx_mempool.cs);
        for (size_t i = 0; i < SCARCITY_TEST_FILLER_COUNT; ++i) {
            AddSyntheticShieldedMinerTx(tx_mempool,
                                        next_funding_tx(),
                                        30'000 + static_cast<uint32_t>(i),
                                        /*fee=*/1'000'000,
                                        MakeSyntheticIngressBundle(SCARCITY_TEST_RESOURCE_UNITS,
                                                                   30'000 + static_cast<uint32_t>(i),
                                                                   spend_anchor,
                                                                   account_registry_anchor),
                                        sequence++);
        }

        tree_txid = AddSyntheticShieldedMinerTx(tx_mempool,
                                                next_funding_tx(),
                                                40'000,
                                                /*fee=*/150'000,
                                                MakeSyntheticIngressBundle(SCARCITY_TEST_RESOURCE_UNITS,
                                                                           40'000,
                                                                           spend_anchor,
                                                                           account_registry_anchor),
                                                sequence++);
        scan_txid = AddSyntheticShieldedMinerTx(tx_mempool,
                                                next_funding_tx(),
                                                40'001,
                                                /*fee=*/100'000,
                                                MakeSyntheticEgressBundle(/*output_count=*/0,
                                                                          SCARCITY_TEST_OUTPUT_CHUNKS,
                                                                          40'001,
                                                                          settlement_anchor),
                                                sequence++);

        const auto& tree_entry = GetSyntheticMinerEntry(tx_mempool, tree_txid);
        const auto& scan_entry = GetSyntheticMinerEntry(tx_mempool, scan_txid);
        BOOST_CHECK(CompareTxMemPoolEntryByAncestorFee{}(tree_entry, scan_entry));
        BOOST_CHECK(!CompareTxMemPoolEntryByAncestorFee{}(scan_entry, tree_entry));
    }
    auto block_template = BlockAssembler{Assert(m_node.chainman)->ActiveChainstate(), &tx_mempool, options, m_node}.CreateNewBlock();
    BOOST_REQUIRE(block_template);

    const size_t tree_index = FindBlockTxIndex(block_template->block, tree_txid);
    const size_t scan_index = FindBlockTxIndex(block_template->block, scan_txid);
    BOOST_REQUIRE(tree_index != block_template->block.vtx.size());
    BOOST_CHECK_EQUAL(scan_index, block_template->block.vtx.size());
    BOOST_CHECK_EQUAL(block_template->nShieldedScanUnits, 0U);
    BOOST_CHECK_EQUAL(block_template->nShieldedTreeUpdateUnits, (SCARCITY_TEST_FILLER_COUNT + 1) * SCARCITY_TEST_RESOURCE_UNITS);
}

BOOST_AUTO_TEST_CASE(mixed_family_mempool_trim_evicts_lowest_feerate_entry)
{
    const uint256 spend_anchor = GetCurrentSyntheticSpendAnchor(*this);
    const uint256 account_registry_anchor = GetCurrentSyntheticAccountRegistryAnchor(*this);
    const auto& consensus = Params().GetConsensus();
    const int32_t validation_height = GetCurrentSyntheticValidationHeight(*this);
    CTxMemPool& tx_mempool{MakeMempool()};
    size_t funding_index{0};
    auto next_funding_tx = [&]() -> const CTransactionRef& {
        BOOST_REQUIRE_LT(funding_index, m_coinbase_txns.size());
        return m_coinbase_txns.at(funding_index++);
    };

    const auto egress_fixture = test::shielded::BuildV2EgressReceiptFixture(
        /*output_count=*/2,
        &consensus,
        validation_height);
    const auto rebalance_fixture = test::shielded::BuildV2RebalanceFixture(
        /*reserve_output_count=*/1,
        /*settlement_window=*/144,
        &consensus,
        validation_height);
    auto settlement_fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture(
        /*output_count=*/2,
        /*proof_receipt_count=*/1,
        /*required_receipts=*/1,
        &consensus,
        validation_height);
    test::shielded::AttachSettlementAnchorReserveBinding(settlement_fixture.tx,
                                                         rebalance_fixture.reserve_deltas,
                                                         rebalance_fixture.manifest_id);

    uint64_t sequence{0};
    Txid send_txid;
    Txid ingress_txid;
    Txid egress_txid;
    Txid rebalance_txid;
    Txid settlement_txid;
    size_t low_entry_usage{0};
    size_t usage_before_trim{0};
    {
        LOCK(tx_mempool.cs);
        send_txid = AddSyntheticShieldedMinerTx(tx_mempool,
                                                next_funding_tx(),
                                                50'000,
                                                /*fee=*/20'000,
                                                MakeSyntheticSendBundle(50'000,
                                                                        spend_anchor,
                                                                        account_registry_anchor),
                                                sequence++);
        ingress_txid = AddSyntheticShieldedMinerTx(tx_mempool,
                                                   next_funding_tx(),
                                                   50'001,
                                                   /*fee=*/420'000,
                                                   MakeSyntheticIngressBundle(/*nullifier_count=*/16,
                                                                              50'001,
                                                                              spend_anchor,
                                                                              account_registry_anchor),
                                                   sequence++);
        egress_txid = AddSyntheticShieldedMinerTx(tx_mempool,
                                                  next_funding_tx(),
                                                  50'002,
                                                  /*fee=*/360'000,
                                                  ExtractV2Bundle(egress_fixture.tx),
                                                  sequence++);
        rebalance_txid = AddSyntheticShieldedMinerTx(tx_mempool,
                                                     next_funding_tx(),
                                                     50'003,
                                                     /*fee=*/300'000,
                                                     ExtractV2Bundle(rebalance_fixture.tx),
                                                     sequence++);
        settlement_txid = AddSyntheticShieldedMinerTx(tx_mempool,
                                                      next_funding_tx(),
                                                      50'004,
                                                      /*fee=*/240'000,
                                                      ExtractV2Bundle(settlement_fixture.tx),
                                                      sequence++);

        const auto& low_entry = GetSyntheticMinerEntry(tx_mempool, send_txid);
        low_entry_usage = low_entry.DynamicMemoryUsage();
        usage_before_trim = tx_mempool.DynamicMemoryUsage();
        BOOST_REQUIRE_GT(low_entry_usage, 0U);

        BOOST_CHECK(CompareTxMemPoolEntryByAncestorFee{}(GetSyntheticMinerEntry(tx_mempool, ingress_txid), low_entry));
        BOOST_CHECK(CompareTxMemPoolEntryByAncestorFee{}(GetSyntheticMinerEntry(tx_mempool, egress_txid), low_entry));
        BOOST_CHECK(CompareTxMemPoolEntryByAncestorFee{}(GetSyntheticMinerEntry(tx_mempool, rebalance_txid), low_entry));
        BOOST_CHECK(CompareTxMemPoolEntryByAncestorFee{}(GetSyntheticMinerEntry(tx_mempool, settlement_txid), low_entry));
    }

    const size_t trim_target = usage_before_trim - std::max<size_t>(1, low_entry_usage / 2);
    const auto trim_start = std::chrono::steady_clock::now();
    {
        LOCK(tx_mempool.cs);
        tx_mempool.TrimToSize(trim_target);
    }
    const auto trim_end = std::chrono::steady_clock::now();

    BOOST_CHECK(!tx_mempool.exists(GenTxid::Txid(send_txid)));
    BOOST_CHECK(tx_mempool.exists(GenTxid::Txid(ingress_txid)));
    BOOST_CHECK(tx_mempool.exists(GenTxid::Txid(egress_txid)));
    BOOST_CHECK(tx_mempool.exists(GenTxid::Txid(rebalance_txid)));
    BOOST_CHECK(tx_mempool.exists(GenTxid::Txid(settlement_txid)));

    BOOST_TEST_MESSAGE("mixed workload trim usage_before=" << usage_before_trim
                       << " low_entry_usage=" << low_entry_usage
                       << " target=" << trim_target
                       << " elapsed_ms=" << Ticks<MillisecondsDouble>(trim_end - trim_start));
}

BOOST_AUTO_TEST_CASE(block_assembler_orders_mixed_family_workload_by_ancestor_feerate)
{
    BlockAssembler::Options options = MakeSyntheticBlockAssemblerOptions();
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const auto& consensus = Params().GetConsensus();
    const int32_t validation_height = GetCurrentSyntheticValidationHeight(*this);

    const auto prerequisite_rebalance_fixture = test::shielded::BuildV2RebalanceFixture(
        /*reserve_output_count=*/1,
        /*settlement_window=*/144,
        &consensus,
        validation_height);
    const auto prerequisite_settlement_anchor_fixture =
        test::shielded::BuildV2SettlementAnchorReceiptFixture(
            /*output_count=*/2,
            /*proof_receipt_count=*/1,
            /*required_receipts=*/1,
            &consensus,
            validation_height);
    CreateAndProcessBlock({prerequisite_rebalance_fixture.tx, prerequisite_settlement_anchor_fixture.tx},
                          script_pub_key);

    const uint256 spend_anchor = GetCurrentSyntheticSpendAnchor(*this);
    const uint256 account_registry_anchor = GetCurrentSyntheticAccountRegistryAnchor(*this);
    CTxMemPool& tx_mempool{MakeMempool()};
    size_t funding_index{0};
    auto next_funding_tx = [&]() -> const CTransactionRef& {
        BOOST_REQUIRE_LT(funding_index, m_coinbase_txns.size());
        return m_coinbase_txns.at(funding_index++);
    };

    const auto egress_fixture = test::shielded::BuildV2EgressReceiptFixture(
        /*output_count=*/2,
        &consensus,
        validation_height);
    const auto rebalance_fixture = test::shielded::BuildV2RebalanceFixture(
        /*reserve_output_count=*/1,
        /*settlement_window=*/144,
        &consensus,
        validation_height);
    auto settlement_fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture(
        /*output_count=*/2,
        /*proof_receipt_count=*/1,
        /*required_receipts=*/1,
        &consensus,
        validation_height);
    test::shielded::AttachSettlementAnchorReserveBinding(settlement_fixture.tx,
                                                         prerequisite_rebalance_fixture.reserve_deltas,
                                                         prerequisite_rebalance_fixture.manifest_id);

    uint64_t sequence{0};
    std::vector<Txid> expected_order;
    std::vector<std::pair<Txid, std::string>> family_labels;
    std::map<Txid, ShieldedResourceUsage> expected_usage_by_txid;
    {
        LOCK(tx_mempool.cs);
        const Txid send_txid = AddSyntheticShieldedMinerTx(tx_mempool,
                                                           next_funding_tx(),
                                                           60'000,
                                                           /*fee=*/900'000,
                                                           MakeSyntheticSendBundle(60'000,
                                                                                   spend_anchor,
                                                                                   account_registry_anchor),
                                                           sequence++);
        const Txid ingress_txid = AddSyntheticShieldedMinerTx(tx_mempool,
                                                              next_funding_tx(),
                                                              60'001,
                                                              /*fee=*/700'000,
                                                              MakeSyntheticIngressBundle(/*nullifier_count=*/12,
                                                                                         60'001,
                                                                                         spend_anchor,
                                                                                         account_registry_anchor),
                                                              sequence++);
        const Txid egress_txid = AddSyntheticShieldedMinerTx(tx_mempool,
                                                             next_funding_tx(),
                                                             60'002,
                                                             /*fee=*/500'000,
                                                             ExtractV2Bundle(egress_fixture.tx),
                                                             sequence++);
        const Txid rebalance_txid = AddSyntheticShieldedMinerTx(tx_mempool,
                                                                next_funding_tx(),
                                                                60'003,
                                                                /*fee=*/320'000,
                                                                ExtractV2Bundle(rebalance_fixture.tx),
                                                                sequence++);
        const Txid settlement_txid = AddSyntheticShieldedMinerTx(tx_mempool,
                                                                 next_funding_tx(),
                                                                 60'004,
                                                                 /*fee=*/180'000,
                                                                 ExtractV2Bundle(settlement_fixture.tx),
                                                                 sequence++);

        family_labels = {
            {send_txid, "send"},
            {ingress_txid, "ingress"},
            {egress_txid, "egress"},
            {rebalance_txid, "rebalance"},
            {settlement_txid, "settlement"},
        };
        for (const auto& [txid, _label] : family_labels) {
            const auto& entry = GetSyntheticMinerEntry(tx_mempool, txid);
            expected_usage_by_txid.emplace(txid, GetShieldedResourceUsage(entry.GetTx().GetShieldedBundle()));
        }
        struct AncestorScoreSnapshot {
            Txid txid;
            CAmount modified_fee;
            int64_t tx_size;
            CAmount ancestor_fee;
            int64_t ancestor_size;
        };
        std::vector<AncestorScoreSnapshot> sorted_entries;
        sorted_entries.reserve(family_labels.size());
        for (const auto& [txid, _label] : family_labels) {
            const auto& entry = GetSyntheticMinerEntry(tx_mempool, txid);
            sorted_entries.push_back({txid,
                                      entry.GetModifiedFee(),
                                      entry.GetTxSize(),
                                      entry.GetModFeesWithAncestors(),
                                      entry.GetSizeWithAncestors()});
        }
        auto compare_snapshots = [](const AncestorScoreSnapshot& lhs, const AncestorScoreSnapshot& rhs) {
            double lhs_mod_fee;
            double lhs_size;
            double rhs_mod_fee;
            double rhs_size;

            const double lhs_self = static_cast<double>(lhs.modified_fee) * lhs.ancestor_size;
            const double lhs_ancestor = static_cast<double>(lhs.ancestor_fee) * lhs.tx_size;
            if (lhs_self > lhs_ancestor) {
                lhs_mod_fee = lhs.ancestor_fee;
                lhs_size = lhs.ancestor_size;
            } else {
                lhs_mod_fee = lhs.modified_fee;
                lhs_size = lhs.tx_size;
            }

            const double rhs_self = static_cast<double>(rhs.modified_fee) * rhs.ancestor_size;
            const double rhs_ancestor = static_cast<double>(rhs.ancestor_fee) * rhs.tx_size;
            if (rhs_self > rhs_ancestor) {
                rhs_mod_fee = rhs.ancestor_fee;
                rhs_size = rhs.ancestor_size;
            } else {
                rhs_mod_fee = rhs.modified_fee;
                rhs_size = rhs.tx_size;
            }

            const double lhs_cmp = lhs_mod_fee * rhs_size;
            const double rhs_cmp = lhs_size * rhs_mod_fee;
            if (lhs_cmp != rhs_cmp) return lhs_cmp > rhs_cmp;
            return lhs.txid < rhs.txid;
        };
        std::sort(sorted_entries.begin(), sorted_entries.end(), compare_snapshots);
        expected_order.reserve(sorted_entries.size());
        for (const auto& snapshot : sorted_entries) {
            expected_order.push_back(snapshot.txid);
        }
    }

    const auto build_start = std::chrono::steady_clock::now();
    auto block_template = BlockAssembler{Assert(m_node.chainman)->ActiveChainstate(), &tx_mempool, options, m_node}.CreateNewBlock();
    const auto build_end = std::chrono::steady_clock::now();
    BOOST_REQUIRE(block_template);

    std::vector<Txid> actual_order;
    actual_order.reserve(block_template->block.vtx.size() - 1);
    for (size_t i = 1; i < block_template->block.vtx.size(); ++i) {
        actual_order.push_back(block_template->block.vtx[i]->GetHash());
    }

    BOOST_REQUIRE_EQUAL(actual_order.size(), expected_order.size());
    BOOST_CHECK_EQUAL_COLLECTIONS(actual_order.begin(),
                                  actual_order.end(),
                                  expected_order.begin(),
                                  expected_order.end());
    BOOST_CHECK_GT(block_template->nShieldedVerifyUnits, 0U);
    BOOST_CHECK_GT(block_template->nShieldedScanUnits, 0U);
    BOOST_CHECK_GT(block_template->nShieldedTreeUpdateUnits, 0U);
    uint64_t expected_verify_units{0};
    uint64_t expected_scan_units{0};
    uint64_t expected_tree_units{0};
    for (const Txid& txid : actual_order) {
        const auto usage_it = expected_usage_by_txid.find(txid);
        BOOST_REQUIRE(usage_it != expected_usage_by_txid.end());
        expected_verify_units += usage_it->second.verify_units;
        expected_scan_units += usage_it->second.scan_units;
        expected_tree_units += usage_it->second.tree_update_units;
    }
    BOOST_CHECK_EQUAL(block_template->nShieldedVerifyUnits, expected_verify_units);
    BOOST_CHECK_EQUAL(block_template->nShieldedScanUnits, expected_scan_units);
    BOOST_CHECK_EQUAL(block_template->nShieldedTreeUpdateUnits, expected_tree_units);

    BOOST_TEST_MESSAGE("mixed workload block template included=" << actual_order.size()
                       << "/" << expected_order.size()
                        << " verify_units=" << block_template->nShieldedVerifyUnits
                       << " scan_units=" << block_template->nShieldedScanUnits
                       << " tree_units=" << block_template->nShieldedTreeUpdateUnits
                       << " elapsed_ms=" << Ticks<MillisecondsDouble>(build_end - build_start));
}

BOOST_AUTO_TEST_CASE(block_assembler_orders_same_block_rebalance_settlement_and_egress_dependencies)
{
    auto options = MakeSyntheticBlockAssemblerOptions();
    options.test_block_validity = true;
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const auto rebalance_fixture = test::shielded::BuildV2RebalanceFixture();
    const auto egress_fixture = test::shielded::BuildV2EgressReceiptFixture(/*output_count=*/2);
    auto settlement_fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture(egress_fixture);
    test::shielded::AttachSettlementAnchorReserveBinding(settlement_fixture.tx,
                                                         rebalance_fixture.reserve_deltas,
                                                         rebalance_fixture.manifest_id);

    BOOST_REQUIRE_EQUAL(
        settlement_fixture.settlement_anchor_digest,
        std::get<shielded::v2::EgressBatchPayload>(egress_fixture.tx.shielded_bundle.v2_bundle->payload)
            .settlement_anchor);

    CTxMemPool& tx_mempool{MakeMempool()};
    size_t funding_index{0};
    auto next_funding_tx = [&]() -> const CTransactionRef& {
        BOOST_REQUIRE_LT(funding_index, m_coinbase_txns.size());
        return m_coinbase_txns.at(funding_index++);
    };

    uint64_t sequence{0};
    Txid rebalance_txid;
    Txid settlement_txid;
    Txid egress_txid;
    {
        LOCK(tx_mempool.cs);
        egress_txid = AddSyntheticShieldedMinerTx(tx_mempool,
                                                  next_funding_tx(),
                                                  70'000,
                                                  /*fee=*/900'000,
                                                  ExtractV2Bundle(egress_fixture.tx),
                                                  sequence++);
        settlement_txid = AddSyntheticShieldedMinerTx(tx_mempool,
                                                      next_funding_tx(),
                                                      70'001,
                                                      /*fee=*/600'000,
                                                      ExtractV2Bundle(settlement_fixture.tx),
                                                      sequence++);
        rebalance_txid = AddSyntheticShieldedMinerTx(tx_mempool,
                                                     next_funding_tx(),
                                                     70'002,
                                                     /*fee=*/300'000,
                                                     ExtractV2Bundle(rebalance_fixture.tx),
                                                     sequence++);
    }

    auto block_template =
        BlockAssembler{Assert(m_node.chainman)->ActiveChainstate(), &tx_mempool, options, m_node}.CreateNewBlock();
    BOOST_REQUIRE(block_template);

    const size_t rebalance_index = FindBlockTxIndex(block_template->block, rebalance_txid);
    const size_t settlement_index = FindBlockTxIndex(block_template->block, settlement_txid);
    const size_t egress_index = FindBlockTxIndex(block_template->block, egress_txid);

    BOOST_REQUIRE(rebalance_index != block_template->block.vtx.size());
    BOOST_REQUIRE(settlement_index != block_template->block.vtx.size());
    BOOST_REQUIRE(egress_index != block_template->block.vtx.size());
    BOOST_CHECK_LT(rebalance_index, settlement_index);
    BOOST_CHECK_LT(settlement_index, egress_index);
}

BOOST_AUTO_TEST_CASE(block_assembler_skips_rebalance_that_exceeds_account_registry_append_limit)
{
    auto& consensus = const_cast<Consensus::Params&>(Assert(m_node.chainman)->GetConsensus());
    const int active_height = WITH_LOCK(::cs_main, return Assert(m_node.chainman)->ActiveChain().Height());
    const ScopedShieldedRegistryAppendConsensus restore{
        consensus,
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nMaxBlockShieldedAccountRegistryAppends};
    consensus.nShieldedMatRiCTDisableHeight = active_height + 1;
    consensus.nMaxBlockShieldedAccountRegistryAppends = 1;

    auto options = MakeSyntheticBlockAssemblerOptions();
    options.test_block_validity = true;

    const auto rebalance_fixture = test::shielded::BuildV2RebalanceFixture(
        /*reserve_output_count=*/2,
        /*settlement_window=*/144,
        &consensus,
        active_height + 1);
    BOOST_REQUIRE_EQUAL(rebalance_fixture.tx.GetShieldedBundle().GetShieldedOutputCount(), 2U);

    CTxMemPool& tx_mempool{MakeMempool()};
    {
        LOCK(tx_mempool.cs);
        AddSyntheticShieldedMinerTx(tx_mempool,
                                    m_coinbase_txns.at(0),
                                    90'000,
                                    /*fee=*/500'000,
                                    ExtractV2Bundle(rebalance_fixture.tx),
                                    /*sequence=*/0);
    }

    auto block_template =
        BlockAssembler{Assert(m_node.chainman)->ActiveChainstate(), &tx_mempool, options, m_node}.CreateNewBlock();
    BOOST_REQUIRE(block_template);

    BOOST_CHECK_EQUAL(block_template->block.vtx.size(), 1U);
    BOOST_CHECK_EQUAL(block_template->nShieldedTreeUpdateUnits, 0U);
}

BOOST_AUTO_TEST_CASE(block_assembler_skips_rebalance_that_exceeds_account_registry_total_entry_limit)
{
    auto& consensus = const_cast<Consensus::Params&>(Assert(m_node.chainman)->GetConsensus());
    const int active_height = WITH_LOCK(::cs_main, return Assert(m_node.chainman)->ActiveChain().Height());
    const ScopedShieldedRegistryEntryConsensus restore{
        consensus,
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nMaxShieldedAccountRegistryEntries};
    consensus.nShieldedMatRiCTDisableHeight = active_height + 1;
    consensus.nMaxShieldedAccountRegistryEntries = 1;

    auto options = MakeSyntheticBlockAssemblerOptions();
    options.test_block_validity = true;

    const auto rebalance_fixture = test::shielded::BuildV2RebalanceFixture(
        /*reserve_output_count=*/2,
        /*settlement_window=*/144,
        &consensus,
        active_height + 1);
    BOOST_REQUIRE_EQUAL(rebalance_fixture.tx.GetShieldedBundle().GetShieldedOutputCount(), 2U);

    CTxMemPool& tx_mempool{MakeMempool()};
    {
        LOCK(tx_mempool.cs);
        AddSyntheticShieldedMinerTx(tx_mempool,
                                    m_coinbase_txns.at(0),
                                    90'000,
                                    /*fee=*/500'000,
                                    ExtractV2Bundle(rebalance_fixture.tx),
                                    /*sequence=*/0);
    }

    auto block_template =
        BlockAssembler{Assert(m_node.chainman)->ActiveChainstate(), &tx_mempool, options, m_node}.CreateNewBlock();
    BOOST_REQUIRE(block_template);

    BOOST_CHECK_EQUAL(block_template->block.vtx.size(), 1U);
    BOOST_CHECK_EQUAL(block_template->nShieldedTreeUpdateUnits, 0U);
}

BOOST_AUTO_TEST_SUITE_END()
