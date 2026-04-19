// Copyright (c) 2017-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <crypto/chacha20poly1305.h>
#include <crypto/ml_kem.h>
#include <crypto/sha256.h>
#include <key_io.h>
#include <policy/packages.h>
#include <policy/policy.h>
#include <policy/ephemeral_policy.h>
#include <policy/truc_policy.h>
#include <pqkey.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <script/sign.h>
#include <shielded/account_registry.h>
#include <shielded/note_encryption.h>
#include <shielded/ringct/ring_selection.h>
#include <shielded/smile2/serialize.h>
#include <shielded/smile2/verify_dispatch.h>
#include <shielded/smile2/wallet_bridge.h>
#include <shielded/v2_ingress.h>
#include <shielded/v2_proof.h>
#include <shielded/v2_send.h>
#include <streams.h>
#include <test/util/shielded_account_registry_test_util.h>
#include <test/util/setup_common.h>
#include <test/util/shielded_v2_egress_fixture.h>
#include <test/util/transaction_utils.h>
#include <test/util/txmempool.h>
#include <txmempool.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <future>
#include <map>
#include <limits>
#include <mutex>
#include <numeric>
#include <stdexcept>
#include <thread>

BOOST_AUTO_TEST_SUITE(txvalidation_tests)

namespace {

namespace v2proof = shielded::v2::proof;

using shielded::BridgeBatchLeaf;
using shielded::BridgeBatchLeafKind;
using shielded::BridgeBatchStatement;
using shielded::BridgeProofDescriptor;
using shielded::BridgeDirection;
using shielded::v2::NoteClass;
using shielded::v2::ScanDomain;
using shielded::v2::TransactionFamily;
using shielded::v2::V2IngressBuildInput;
using shielded::v2::V2IngressBuildResult;
using shielded::v2::V2IngressLeafInput;
using shielded::v2::V2IngressStatementTemplate;
using shielded::v2::V2SendOutputInput;
using shielded::v2::V2SendSpendInput;

constexpr size_t V2_INGRESS_REAL_INDEX{4};
constexpr CAmount V2_INGRESS_RESERVE_VALUE{800'000};
constexpr size_t V2_DIRECT_SEND_REAL_INDEX{4};
constexpr CAmount V2_DIRECT_SEND_RING_NOTE_VALUE{180'000};
constexpr CAmount V2_DIRECT_SEND_SEED_FEE{15'000};
constexpr CAmount V2_DIRECT_SEND_FEE{70'000};
constexpr CAmount SHIELDED_FEE_CARRIER_FEE{40'000};

struct ScopedShieldedResourceLimits
{
    Consensus::Params& consensus;
    uint64_t scan_units;
    uint64_t tree_update_units;

    ~ScopedShieldedResourceLimits()
    {
        consensus.nMaxBlockShieldedScanUnits = scan_units;
        consensus.nMaxBlockShieldedTreeUpdateUnits = tree_update_units;
    }
};

struct ScopedShieldedRegistryAppendLimit
{
    Consensus::Params& consensus;
    uint64_t append_limit;

    ~ScopedShieldedRegistryAppendLimit()
    {
        consensus.nMaxBlockShieldedAccountRegistryAppends = append_limit;
    }
};

struct ScopedShieldedRegistryEntryLimit
{
    Consensus::Params& consensus;
    uint64_t entry_limit;

    ~ScopedShieldedRegistryEntryLimit()
    {
        consensus.nMaxShieldedAccountRegistryEntries = entry_limit;
    }
};

struct ScopedConsensusHeightOverride
{
    int32_t& target;
    int32_t original;

    ~ScopedConsensusHeightOverride()
    {
        target = original;
    }
};

struct ScopedConsensusU32Override
{
    uint32_t& target;
    uint32_t original;

    ~ScopedConsensusU32Override()
    {
        target = original;
    }
};

void ExpectBlockRejected(TestChain100Setup& setup,
                         const CBlock& block,
                         const std::string& expected_reject_reason)
{
    BlockValidationState state;
    bool valid{false};

    {
        LOCK(::cs_main);
        valid = TestBlockValidity(state,
                                  setup.m_node.chainman->GetParams(),
                                  setup.m_node.chainman->ActiveChainstate(),
                                  block,
                                  setup.m_node.chainman->ActiveChain().Tip(),
                                  /*fCheckPOW=*/false,
                                  /*fCheckMerkleRoot=*/false);
    }

    BOOST_CHECK(!valid);
    BOOST_CHECK(state.IsInvalid());
    BOOST_CHECK_EQUAL(state.GetRejectReason(), expected_reject_reason);
}

void ExpectBlockAccepted(TestChain100Setup& setup, const CBlock& block)
{
    BlockValidationState state;
    bool valid{false};

    {
        LOCK(::cs_main);
        valid = TestBlockValidity(state,
                                  setup.m_node.chainman->GetParams(),
                                  setup.m_node.chainman->ActiveChainstate(),
                                  block,
                                  setup.m_node.chainman->ActiveChain().Tip(),
                                  /*fCheckPOW=*/false,
                                  /*fCheckMerkleRoot=*/false);
    }

    BOOST_CHECK_MESSAGE(valid, state.GetRejectReason());
}

[[nodiscard]] ShieldedNote MakeIngressNote(CAmount value, unsigned char seed)
{
    ShieldedNote note;
    note.value = value;
    note.recipient_pk_hash = uint256{seed};
    note.rho = uint256{static_cast<unsigned char>(seed + 1)};
    note.rcm = uint256{static_cast<unsigned char>(seed + 2)};
    BOOST_REQUIRE(note.IsValid());
    return note;
}

[[nodiscard]] mlkem::KeyPair MakeIngressRecipient(unsigned char seed)
{
    std::array<uint8_t, mlkem::KEYGEN_SEEDBYTES> key_seed{};
    key_seed.fill(seed);
    return mlkem::KeyGenDerand(key_seed);
}

[[nodiscard]] shielded::EncryptedNote EncryptIngressNote(const ShieldedNote& note,
                                                         const mlkem::PublicKey& recipient_pk,
                                                         unsigned char kem_seed_byte,
                                                         unsigned char nonce_byte)
{
    std::array<uint8_t, mlkem::ENCAPS_SEEDBYTES> kem_seed{};
    kem_seed.fill(kem_seed_byte);
    std::array<uint8_t, 12> nonce{};
    nonce.fill(nonce_byte);
    return shielded::NoteEncryption::EncryptDeterministic(note, recipient_pk, kem_seed, nonce);
}

[[nodiscard]] shielded::v2::OutputDescription BuildIngressFundingOutput(const ShieldedNote& note,
                                                                        unsigned char recipient_seed)
{
    const auto recipient = MakeIngressRecipient(recipient_seed);
    const auto encrypted_note = EncryptIngressNote(note,
                                                   recipient.pk,
                                                   static_cast<unsigned char>(recipient_seed + 1),
                                                   static_cast<unsigned char>(recipient_seed + 2));
    auto payload = shielded::v2::EncodeLegacyEncryptedNotePayload(encrypted_note,
                                                                  recipient.pk,
                                                                  ScanDomain::BATCH);
    BOOST_REQUIRE(payload.has_value());

    const auto smile_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        note);
    BOOST_REQUIRE(smile_account.has_value());

    shielded::v2::OutputDescription output;
    output.note_class = NoteClass::USER;
    output.note_commitment = smile2::ComputeCompactPublicAccountHash(*smile_account);
    output.value_commitment = uint256{1};
    output.smile_account = *smile_account;
    output.encrypted_note = *payload;
    BOOST_REQUIRE(output.IsValid());
    return output;
}

[[nodiscard]] int32_t NextShieldedValidationHeight(TestChain100Setup& setup)
{
    return WITH_LOCK(cs_main, return Assert(setup.m_node.chainman)->ActiveChain().Height() + 1);
}

[[nodiscard]] test::shielded::V2SettlementAnchorReceiptFixture BuildSettlementAnchorFromEgressFixture(
    const test::shielded::V2EgressReceiptFixture& egress_fixture,
    const Consensus::Params* consensus = nullptr,
    int32_t validation_height = std::numeric_limits<int32_t>::max())
{
    test::shielded::V2SettlementAnchorReceiptFixture fixture;
    fixture.statement = egress_fixture.statement;
    fixture.descriptor = egress_fixture.descriptor;
    fixture.receipt = egress_fixture.receipt;
    fixture.attestors = egress_fixture.attestors;
    fixture.signed_receipts = egress_fixture.signed_receipts;
    fixture.signed_receipt_proofs = egress_fixture.signed_receipt_proofs;
    fixture.verification_bundle = egress_fixture.verification_bundle;
    fixture.witness = egress_fixture.witness;

    DataStream witness_stream;
    witness_stream << fixture.witness;
    const auto* witness_begin = reinterpret_cast<const unsigned char*>(witness_stream.data());
    std::vector<uint8_t> proof_payload(witness_begin, witness_begin + witness_stream.size());

    const auto abstract_context =
        shielded::v2::proof::DescribeImportedSettlementReceipt(fixture.receipt,
                                                               shielded::v2::proof::PayloadLocation::INLINE_WITNESS,
                                                               proof_payload,
                                                               fixture.descriptor);

    const auto settlement_anchor =
        shielded::BuildBridgeExternalAnchorFromProofReceipts(fixture.statement,
                                                             fixture.witness.proof_receipts);
    BOOST_REQUIRE(settlement_anchor.has_value());
    fixture.settlement_anchor_digest =
        shielded::v2::proof::ComputeSettlementExternalAnchorDigest(*settlement_anchor);

    shielded::v2::SettlementAnchorPayload payload;
    payload.proof_receipt_ids = test::shielded::CollectCanonicalProofReceiptIds(
        Span<const shielded::BridgeProofReceipt>{fixture.witness.proof_receipts.data(),
                                                fixture.witness.proof_receipts.size()});
    payload.batch_statement_digests = {shielded::ComputeBridgeBatchStatementHash(fixture.statement)};

    shielded::v2::TransactionBundle bundle;
    bundle.header.family_id = test::shielded::ResolveFixtureWireFamily(
        shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR,
        consensus,
        validation_height);
    bundle.header.proof_envelope = abstract_context.material.statement.envelope;
    test::shielded::ApplyFixtureWireEnvelopeKinds(
        shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR,
        bundle.header.proof_envelope,
        consensus,
        validation_height);
    bundle.payload = payload;

    auto proof_shard = abstract_context.material.proof_shards.front();
    proof_shard.settlement_domain = fixture.statement.domain_id;
    bundle.proof_shards = {proof_shard};
    bundle.proof_payload = proof_payload;
    bundle.header.payload_digest = shielded::v2::ComputeSettlementAnchorPayloadDigest(payload);
    bundle.header.proof_shard_root = shielded::v2::ComputeProofShardRoot(
        Span<const shielded::v2::ProofShardDescriptor>{bundle.proof_shards.data(), bundle.proof_shards.size()});
    bundle.header.proof_shard_count = bundle.proof_shards.size();
    BOOST_REQUIRE(bundle.IsValid());

    fixture.tx.shielded_bundle.v2_bundle = bundle;
    return fixture;
}

[[nodiscard]] test::shielded::V2SettlementAnchorReceiptFixture BuildSettlementAnchorHybridFromEgressFixture(
    const test::shielded::V2EgressReceiptFixture& egress_fixture,
    const Consensus::Params* consensus = nullptr,
    int32_t validation_height = std::numeric_limits<int32_t>::max())
{
    auto fixture = test::shielded::BuildV2SettlementAnchorHybridReceiptFixture(egress_fixture);
    auto* bundle = fixture.tx.shielded_bundle.v2_bundle ? &*fixture.tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(bundle != nullptr);
    bundle->header.family_id = test::shielded::ResolveFixtureWireFamily(
        shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR,
        consensus,
        validation_height);
    test::shielded::ApplyFixtureWireEnvelopeKinds(
        shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR,
        bundle->header.proof_envelope,
        consensus,
        validation_height);
    BOOST_REQUIRE(bundle->IsValid());
    return fixture;
}

[[nodiscard]] V2SendSpendInput MakeSpendInput(
    const ShieldedNote& note,
    const std::vector<uint64_t>& ring_positions,
    const std::vector<uint256>& ring_members,
    size_t real_index,
    const shielded::registry::AccountLeafHint& account_leaf_hint)
{
    V2SendSpendInput spend_input;
    spend_input.note = note;
    spend_input.note_commitment = ring_members.at(real_index);
    spend_input.account_leaf_hint = account_leaf_hint;
    spend_input.ring_positions = ring_positions;
    spend_input.ring_members = ring_members;
    spend_input.real_index = real_index;
    return spend_input;
}

[[nodiscard]] std::optional<std::vector<smile2::wallet::SmileRingMember>> BuildSmileRingMembersFromNotes(
    const std::vector<ShieldedNote>& ring_notes,
    const std::vector<uint256>& ring_members,
    const shielded::registry::AccountLeafHint& account_leaf_hint,
    const std::map<uint256, uint256>* known_account_leaf_commitments = nullptr)
{
    if (ring_notes.size() != ring_members.size()) {
        return std::nullopt;
    }

    std::vector<smile2::wallet::SmileRingMember> members;
    members.reserve(ring_members.size());
    for (size_t i = 0; i < ring_members.size(); ++i) {
        std::optional<uint256> leaf_commitment;
        if (known_account_leaf_commitments != nullptr) {
            const auto it = known_account_leaf_commitments->find(ring_members[i]);
            if (it != known_account_leaf_commitments->end()) {
                leaf_commitment = it->second;
            }
        }
        if (!leaf_commitment.has_value()) {
            const auto candidates = shielded::registry::CollectAccountLeafCommitmentCandidatesFromNote(
                ring_notes[i],
                ring_members[i],
                account_leaf_hint);
            if (candidates.size() != 1U) {
                return std::nullopt;
            }
            leaf_commitment = candidates.front();
        }
        auto member = smile2::wallet::BuildRingMemberFromNote(
            smile2::wallet::SMILE_GLOBAL_SEED,
            ring_notes[i],
            ring_members[i],
            *leaf_commitment);
        if (!member.has_value()) {
            return std::nullopt;
        }
        members.push_back(std::move(*member));
    }
    return members;
}

[[nodiscard]] bool AttachAccountRegistryWitnessesFromRegistry(
    std::vector<V2SendSpendInput>& spend_inputs,
    const shielded::registry::ShieldedAccountRegistryState& registry)
{
    if (spend_inputs.empty()) {
        return false;
    }
    const uint256 registry_root = registry.Root();
    if (registry_root.IsNull()) {
        return false;
    }

    for (auto& spend_input : spend_inputs) {
        const auto account_leaf_commitments =
            shielded::registry::CollectAccountLeafCommitmentCandidatesFromNote(
                spend_input.note,
                test::shielded::EffectiveNoteCommitment(spend_input),
                *spend_input.account_leaf_hint);
        if (account_leaf_commitments.empty()) {
            return false;
        }
        std::optional<shielded::registry::ShieldedAccountRegistrySpendWitness> witness;
        for (const auto& account_leaf_commitment : account_leaf_commitments) {
            witness = registry.BuildSpendWitnessByCommitment(account_leaf_commitment);
            if (witness.has_value()) break;
        }
        if (!witness.has_value()) return false;
        spend_input.account_registry_anchor = registry_root;
        spend_input.account_registry_proof = std::move(*witness);
    }
    return true;
}

void ReSignSpend(TestChain100Setup& setup,
                 CMutableTransaction& tx,
                 const CTransactionRef& funding_tx,
                 uint32_t prevout_index = 0,
                 bool is_coinbase = false)
{
    FillableSigningProvider keystore;
    BOOST_REQUIRE(keystore.AddKey(setup.coinbaseKey));

    std::map<COutPoint, Coin> input_coins;
    BOOST_REQUIRE_LT(prevout_index, funding_tx->vout.size());
    input_coins.emplace(COutPoint{funding_tx->GetHash(), prevout_index},
                        Coin{funding_tx->vout[prevout_index], /*nHeight=*/is_coinbase ? 0 : 1, is_coinbase});

    std::map<int, bilingual_str> input_errors;
    BOOST_REQUIRE(SignTransaction(tx, &keystore, input_coins, SIGHASH_ALL, input_errors));
}

void ReSignCoinbaseSpend(TestChain100Setup& setup,
                         CMutableTransaction& tx,
                         const CTransactionRef& funding_tx)
{
    ReSignSpend(setup, tx, funding_tx, /*prevout_index=*/0, /*is_coinbase=*/true);
}

void AttachCoinbaseFeeCarrier(TestChain100Setup& setup,
                              CMutableTransaction& tx,
                              const CTransactionRef& funding_tx,
                              CAmount fee = SHIELDED_FEE_CARRIER_FEE)
{
    BOOST_REQUIRE_GT(funding_tx->vout.size(), 0U);
    BOOST_REQUIRE_GT(funding_tx->vout[0].nValue, fee);

    const CScript change_script = GetScriptForDestination(WitnessV2P2MR(uint256::ONE));
    tx.vin = {CTxIn{COutPoint{funding_tx->GetHash(), 0}}};
    tx.vout = {CTxOut{funding_tx->vout[0].nValue - fee, change_script}};

    ReSignCoinbaseSpend(setup, tx, funding_tx);
}

[[nodiscard]] CMutableTransaction BuildLegacyShieldOnlyTx(TestChain100Setup& setup,
                                                          const CTransactionRef& funding_tx,
                                                          CAmount fee)
{
    BOOST_REQUIRE_GT(funding_tx->vout.size(), 0U);
    BOOST_REQUIRE_GT(funding_tx->vout[0].nValue, fee);

    CMutableTransaction tx;
    tx.vin = {CTxIn{COutPoint{funding_tx->GetHash(), 0}}};

    CShieldedOutput output;
    output.note_commitment = GetRandHash();
    output.merkle_anchor = WITH_LOCK(cs_main, return setup.m_node.chainman->GetShieldedMerkleTree().Root());
    output.encrypted_note.aead_ciphertext.assign(AEADChaCha20Poly1305::EXPANSION, 0x00);
    tx.shielded_bundle.shielded_outputs.push_back(output);
    tx.shielded_bundle.value_balance = -(funding_tx->vout[0].nValue - fee);

    ReSignCoinbaseSpend(setup, tx, funding_tx);
    return tx;
}

[[nodiscard]] V2SendOutputInput BuildDirectSendOutputInput(const ShieldedNote& note,
                                                           unsigned char recipient_seed)
{
    const auto recipient = MakeIngressRecipient(recipient_seed);
    const auto encrypted_note = EncryptIngressNote(note,
                                                   recipient.pk,
                                                   static_cast<unsigned char>(recipient_seed + 1),
                                                   static_cast<unsigned char>(recipient_seed + 2));
    auto payload = shielded::v2::EncodeLegacyEncryptedNotePayload(encrypted_note,
                                                                  recipient.pk,
                                                                  ScanDomain::USER);
    BOOST_REQUIRE(payload.has_value());

    V2SendOutputInput output_input;
    output_input.note_class = NoteClass::USER;
    output_input.note = note;
    output_input.encrypted_note = *payload;
    BOOST_REQUIRE(output_input.IsValid());
    return output_input;
}

void ReplaceV2SendWitness(CMutableTransaction& tx, const v2proof::V2SendWitness& witness);

void WriteU32LEForTest(std::vector<uint8_t>& out, uint32_t value)
{
    out.push_back(static_cast<uint8_t>(value));
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value >> 16));
    out.push_back(static_cast<uint8_t>(value >> 24));
}

class TestBitWriter
{
private:
    std::vector<uint8_t>& m_out;
    uint8_t m_current{0};
    int m_bits_used{0};

public:
    explicit TestBitWriter(std::vector<uint8_t>& out) : m_out(out) {}

    void WriteBit(bool bit)
    {
        if (bit) {
            m_current |= static_cast<uint8_t>(1u << m_bits_used);
        }
        ++m_bits_used;
        if (m_bits_used == 8) {
            m_out.push_back(m_current);
            m_current = 0;
            m_bits_used = 0;
        }
    }

    void Write(uint32_t value, uint8_t bits)
    {
        for (uint8_t bit = 0; bit < bits; ++bit) {
            WriteBit((value >> bit) & 1U);
        }
    }

    void Flush()
    {
        if (m_bits_used != 0) {
            m_out.push_back(m_current);
            m_current = 0;
            m_bits_used = 0;
        }
    }
};

int64_t CenterCoeffForTest(int64_t coeff)
{
    coeff = smile2::mod_q(coeff);
    return coeff > smile2::Q / 2 ? coeff - smile2::Q : coeff;
}

uint8_t ComputeBitsNeededForCenteredRangeForTest(int64_t max_abs)
{
    const uint64_t range = static_cast<uint64_t>(2 * max_abs + 1);
    uint8_t bits_needed = 1;
    while (bits_needed < 32 && (1ULL << bits_needed) < range) {
        ++bits_needed;
    }
    return bits_needed;
}

int64_t ComputeCenteredMaxAbsForTest(const smile2::SmilePolyVec& polys)
{
    int64_t max_abs = 0;
    for (const auto& poly : polys) {
        for (size_t i = 0; i < smile2::POLY_DEGREE; ++i) {
            const int64_t centered = CenterCoeffForTest(poly.coeffs[i]);
            const int64_t abs_centered = centered < 0 ? -centered : centered;
            max_abs = std::max(max_abs, abs_centered);
        }
    }
    return max_abs;
}

std::vector<uint8_t> SerializeNonCanonicalCenteredPolyVecFixedForTest(
    const smile2::SmilePolyVec& polys)
{
    std::vector<uint8_t> out;
    if (polys.empty()) {
        return out;
    }

    const int64_t canonical_max_abs = ComputeCenteredMaxAbsForTest(polys);
    const int64_t encoded_max_abs = canonical_max_abs + 1;
    WriteU32LEForTest(out, static_cast<uint32_t>(encoded_max_abs));

    const uint8_t bits_needed = ComputeBitsNeededForCenteredRangeForTest(encoded_max_abs);
    out.push_back(bits_needed);

    TestBitWriter bw(out);
    for (const auto& poly : polys) {
        for (size_t i = 0; i < smile2::POLY_DEGREE; ++i) {
            const int64_t centered = CenterCoeffForTest(poly.coeffs[i]);
            const uint32_t encoded = static_cast<uint32_t>(centered + encoded_max_abs);
            bw.Write(encoded, bits_needed);
        }
    }
    bw.Flush();
    return out;
}

std::vector<uint8_t> BuildNonCanonicalSmileProofBytes(const std::vector<uint8_t>& canonical_bytes,
                                                      size_t num_inputs,
                                                      size_t num_outputs)
{
    smile2::SmileCTProof proof;
    auto parse_err = smile2::ParseSmile2Proof(canonical_bytes, num_inputs, num_outputs, proof);
    BOOST_REQUIRE_MESSAGE(!parse_err.has_value(), parse_err.value_or("ok"));

    std::vector<uint8_t> canonical_wire_prefix;
    if (canonical_bytes.size() >= 5 &&
        canonical_bytes[0] == 0xFF &&
        canonical_bytes[1] == 0xFF &&
        canonical_bytes[2] == 0xFF &&
        canonical_bytes[3] == 0xFF) {
        canonical_wire_prefix.assign(canonical_bytes.begin(), canonical_bytes.begin() + 5);
    }

    std::vector<uint8_t> canonical_prefix;
    smile2::SerializeCenteredPolyVecFixed(proof.aux_commitment.t0, canonical_prefix);
    const size_t body_offset = canonical_wire_prefix.size();
    BOOST_REQUIRE(!canonical_prefix.empty());
    BOOST_REQUIRE_GE(canonical_bytes.size(), body_offset + canonical_prefix.size());

    const auto noncanonical_prefix =
        SerializeNonCanonicalCenteredPolyVecFixedForTest(proof.aux_commitment.t0);
    BOOST_REQUIRE(noncanonical_prefix != canonical_prefix);

    std::vector<uint8_t> mutated = canonical_wire_prefix;
    mutated.insert(mutated.end(), noncanonical_prefix.begin(), noncanonical_prefix.end());
    mutated.insert(mutated.end(),
                   canonical_bytes.begin() + static_cast<std::ptrdiff_t>(body_offset + canonical_prefix.size()),
                   canonical_bytes.end());

    smile2::SmileCTProof reparsed;
    parse_err = smile2::ParseSmile2Proof(mutated, num_inputs, num_outputs, reparsed);
    BOOST_REQUIRE_MESSAGE(!parse_err.has_value(), parse_err.value_or("ok"));
    BOOST_REQUIRE(
        smile2::SerializeCTProof(reparsed, smile2::SmileProofCodecPolicy::CANONICAL_NO_RICE) ==
        canonical_bytes);

    return mutated;
}

void MakeV2SendSmileProofNonCanonical(CMutableTransaction& tx)
{
    const auto* bundle = tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_REQUIRE(std::holds_alternative<shielded::v2::SendPayload>(bundle->payload));

    std::string reject_reason;
    auto witness = v2proof::ParseV2SendWitness(*bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(witness.has_value(), reject_reason);
    BOOST_REQUIRE(witness->use_smile);

    const auto& payload = std::get<shielded::v2::SendPayload>(bundle->payload);
    witness->smile_proof_bytes = BuildNonCanonicalSmileProofBytes(witness->smile_proof_bytes,
                                                                  payload.spends.size(),
                                                                  payload.outputs.size());
    ReplaceV2SendWitness(tx, *witness);
}

void ReplaceV2SendWitness(CMutableTransaction& tx, const v2proof::V2SendWitness& witness)
{
    auto* bundle = tx.shielded_bundle.v2_bundle ? &*tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(bundle != nullptr);

    DataStream witness_stream;
    witness_stream << witness;
    const auto* witness_begin = reinterpret_cast<const unsigned char*>(witness_stream.data());
    bundle->proof_payload.assign(witness_begin, witness_begin + witness_stream.size());
}

[[nodiscard]] BridgeBatchLeaf MakeIngressBridgeLeaf(unsigned char seed, CAmount amount)
{
    BridgeBatchLeaf leaf;
    leaf.kind = BridgeBatchLeafKind::SHIELD_CREDIT;
    leaf.wallet_id = uint256{seed};
    leaf.destination_id = uint256{static_cast<unsigned char>(seed + 1)};
    leaf.amount = amount;
    leaf.authorization_hash = uint256{static_cast<unsigned char>(seed + 2)};
    BOOST_REQUIRE(leaf.IsValid());
    return leaf;
}

[[nodiscard]] V2IngressLeafInput MakeIngressLeaf(unsigned char seed, CAmount amount, CAmount fee)
{
    V2IngressLeafInput leaf;
    leaf.bridge_leaf = MakeIngressBridgeLeaf(seed, amount);
    leaf.l2_id = uint256{static_cast<unsigned char>(seed + 3)};
    leaf.fee = fee;
    BOOST_REQUIRE(leaf.IsValid());
    return leaf;
}

[[nodiscard]] BridgeProofDescriptor MakeIngressProofDescriptor()
{
    const auto adapter = shielded::BuildCanonicalBridgeProofAdapter(
        shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    BOOST_REQUIRE(adapter.has_value());

    const auto descriptor = shielded::BuildBridgeProofDescriptorFromAdapter(*adapter, uint256{0xb2});
    BOOST_REQUIRE(descriptor.has_value());
    BOOST_REQUIRE(descriptor->IsValid());
    return *descriptor;
}

[[nodiscard]] shielded::v2::V2IngressSettlementWitness BuildIngressProofSettlementWitness(
    const BridgeBatchStatement& statement,
    unsigned char seed = 0xd1)
{
    const auto descriptor = MakeIngressProofDescriptor();
    std::vector<BridgeProofDescriptor> descriptors{descriptor};

    shielded::BridgeProofReceipt receipt;
    receipt.statement_hash = shielded::ComputeBridgeBatchStatementHash(statement);
    receipt.proof_system_id = descriptor.proof_system_id;
    receipt.verifier_key_hash = descriptor.verifier_key_hash;
    receipt.public_values_hash = uint256{seed};
    receipt.proof_commitment = uint256{static_cast<unsigned char>(seed + 1)};
    BOOST_REQUIRE(receipt.IsValid());

    auto descriptor_proof = shielded::BuildBridgeProofPolicyProof(descriptors, descriptor);
    BOOST_REQUIRE(descriptor_proof.has_value());

    shielded::v2::V2IngressSettlementWitness witness;
    witness.proof_receipts = {receipt};
    witness.proof_receipt_descriptor_proofs = {*descriptor_proof};
    BOOST_REQUIRE(witness.IsValid());
    return witness;
}

enum class IngressSettlementWitnessKind {
    PROOF_ONLY,
    SIGNED_ONLY,
    HYBRID,
};

struct IngressSettlementContext
{
    BridgeBatchStatement statement;
    shielded::v2::V2IngressSettlementWitness witness;
};

[[nodiscard]] shielded::BridgeKeySpec MakeIngressAttestor(unsigned char seed,
                                                          PQAlgorithm algo = PQAlgorithm::ML_DSA_44)
{
    std::array<unsigned char, 32> material{};
    material.fill(seed);

    CPQKey key;
    BOOST_REQUIRE(key.MakeDeterministicKey(algo, material));
    return {algo, key.GetPubKey()};
}

[[nodiscard]] shielded::BridgeBatchReceipt MakeIngressSignedReceipt(unsigned char seed,
                                                                    const BridgeBatchStatement& statement,
                                                                    PQAlgorithm algo = PQAlgorithm::ML_DSA_44)
{
    std::array<unsigned char, 32> material{};
    material.fill(seed);

    CPQKey key;
    BOOST_REQUIRE(key.MakeDeterministicKey(algo, material));

    shielded::BridgeBatchReceipt receipt;
    receipt.statement = statement;
    receipt.attestor = {algo, key.GetPubKey()};

    const uint256 receipt_hash = shielded::ComputeBridgeBatchReceiptHash(receipt);
    BOOST_REQUIRE(!receipt_hash.IsNull());
    BOOST_REQUIRE(key.Sign(receipt_hash, receipt.signature));
    BOOST_REQUIRE(receipt.IsValid());
    return receipt;
}

[[nodiscard]] IngressSettlementContext BuildIngressSettlementContext(
    const std::vector<V2IngressLeafInput>& ingress_leaves,
    IngressSettlementWitnessKind settlement_kind)
{
    struct AttestorSpec {
        unsigned char seed;
        PQAlgorithm algo;
    };

    const std::array<AttestorSpec, 2> attestor_specs{{
        {0xd1, PQAlgorithm::ML_DSA_44},
        {0xd2, PQAlgorithm::SLH_DSA_128S},
    }};

    std::vector<shielded::BridgeKeySpec> attestors;
    if (settlement_kind != IngressSettlementWitnessKind::PROOF_ONLY) {
        attestors.reserve(attestor_specs.size());
        for (const auto& spec : attestor_specs) {
            attestors.push_back(MakeIngressAttestor(spec.seed, spec.algo));
        }
    }

    std::vector<BridgeProofDescriptor> descriptors;
    if (settlement_kind != IngressSettlementWitnessKind::SIGNED_ONLY) {
        descriptors.push_back(MakeIngressProofDescriptor());
    }

    V2IngressStatementTemplate statement_template;
    statement_template.ids.bridge_id = uint256{0xc1};
    statement_template.ids.operation_id = uint256{0xc2};
    statement_template.domain_id = uint256{0xc3};
    statement_template.source_epoch = 11;
    statement_template.data_root = uint256{0xc4};

    if (!attestors.empty()) {
        const auto verifier_set = shielded::BuildBridgeVerifierSetCommitment(
            Span<const shielded::BridgeKeySpec>{attestors.data(), attestors.size()},
            /*required_signers=*/attestors.size());
        BOOST_REQUIRE(verifier_set.has_value());
        statement_template.verifier_set = *verifier_set;
    }

    if (!descriptors.empty()) {
        const auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(
            Span<const BridgeProofDescriptor>{descriptors.data(), descriptors.size()},
            /*required_receipts=*/1);
        BOOST_REQUIRE(proof_policy.has_value());
        statement_template.proof_policy = *proof_policy;
    }

    std::string reject_reason;
    auto statement = shielded::v2::BuildV2IngressStatement(
        statement_template,
        Span<const V2IngressLeafInput>{ingress_leaves.data(), ingress_leaves.size()},
        reject_reason);
    BOOST_REQUIRE_MESSAGE(statement.has_value(), reject_reason);
    BOOST_REQUIRE(statement->IsValid());

    shielded::v2::V2IngressSettlementWitness witness;
    if (!attestors.empty()) {
        witness.signed_receipts.reserve(attestors.size());
        witness.signed_receipt_proofs.reserve(attestors.size());
        for (const auto& spec : attestor_specs) {
            const auto receipt = MakeIngressSignedReceipt(spec.seed, *statement, spec.algo);
            auto proof = shielded::BuildBridgeVerifierSetProof(
                Span<const shielded::BridgeKeySpec>{attestors.data(), attestors.size()},
                receipt.attestor);
            BOOST_REQUIRE(proof.has_value());
            witness.signed_receipts.push_back(receipt);
            witness.signed_receipt_proofs.push_back(*proof);
        }
    }

    if (!descriptors.empty()) {
        const auto proof_witness = BuildIngressProofSettlementWitness(*statement);
        witness.proof_receipts = proof_witness.proof_receipts;
        witness.proof_receipt_descriptor_proofs = proof_witness.proof_receipt_descriptor_proofs;
    }

    BOOST_REQUIRE(witness.IsValid());
    return {*statement, witness};
}

[[nodiscard]] std::vector<uint64_t> BuildRingPositions()
{
    std::vector<uint64_t> positions;
    positions.reserve(shielded::lattice::RING_SIZE);
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        positions.push_back(i);
    }
    return positions;
}

[[nodiscard]] std::vector<uint256> ReadRingMembers(const shielded::ShieldedMerkleTree& tree,
                                                   Span<const uint64_t> positions)
{
    std::vector<uint256> members;
    members.reserve(positions.size());
    for (const uint64_t pos : positions) {
        const auto commitment = tree.CommitmentAt(pos);
        BOOST_REQUIRE(commitment.has_value());
        members.push_back(*commitment);
    }
    return members;
}

[[nodiscard]] std::vector<size_t> SelectIngressRealIndices(size_t spend_input_count)
{
    BOOST_REQUIRE_GT(spend_input_count, 0U);
    BOOST_REQUIRE_LE(spend_input_count, shielded::lattice::RING_SIZE);

    std::vector<size_t> indices;
    indices.reserve(spend_input_count);
    for (size_t input_idx = 0; input_idx < spend_input_count; ++input_idx) {
        const size_t index = (V2_INGRESS_REAL_INDEX + input_idx * 5) % shielded::lattice::RING_SIZE;
        BOOST_REQUIRE(std::find(indices.begin(), indices.end(), index) == indices.end());
        indices.push_back(index);
    }
    return indices;
}

[[nodiscard]] std::vector<CAmount> DistributeIngressInputValues(CAmount total, size_t count)
{
    BOOST_REQUIRE_GT(count, 0U);

    std::vector<CAmount> values;
    values.reserve(count);
    CAmount assigned{0};
    for (size_t idx = 0; idx < count; ++idx) {
        const size_t remaining = count - idx;
        const CAmount remaining_total = total - assigned;
        const CAmount value = remaining == 1
            ? remaining_total
            : remaining_total / static_cast<CAmount>(remaining);
        BOOST_REQUIRE_GT(value, 0);
        values.push_back(value);
        assigned += value;
    }
    BOOST_REQUIRE_EQUAL(assigned, total);
    return values;
}

[[nodiscard]] std::vector<V2IngressLeafInput> BuildCanonicalActivationIngressLeaves()
{
    std::vector<V2IngressLeafInput> ingress_leaves;
    ingress_leaves.push_back(MakeIngressLeaf(/*seed=*/0x81, /*amount=*/100'000, /*fee=*/35'000));
    ingress_leaves.push_back(MakeIngressLeaf(/*seed=*/0x91, /*amount=*/135'000, /*fee=*/35'000));
    return ingress_leaves;
}

[[nodiscard]] std::vector<V2IngressLeafInput> BuildNonCanonicalActivationIngressLeaves()
{
    std::vector<V2IngressLeafInput> ingress_leaves;
    ingress_leaves.push_back(MakeIngressLeaf(/*seed=*/0xa1, /*amount=*/100'000, /*fee=*/35'000));
    ingress_leaves.push_back(MakeIngressLeaf(/*seed=*/0xb1, /*amount=*/135'000, /*fee=*/35'001));
    return ingress_leaves;
}

[[nodiscard]] CAmount SumIngressLeafTransfers(Span<const V2IngressLeafInput> ingress_leaves)
{
    return std::accumulate(
        ingress_leaves.begin(),
        ingress_leaves.end(),
        CAmount{0},
        [](CAmount total, const V2IngressLeafInput& leaf) {
            return total + leaf.bridge_leaf.amount + leaf.fee;
        });
}

struct V2IngressChainFixture
{
    std::vector<unsigned char> spending_key;
    shielded::ShieldedMerkleTree tree_before;
    std::vector<ShieldedNote> input_notes;
    std::vector<uint256> input_nullifiers;
    std::vector<uint256> reserve_commitments;
    uint256 spend_anchor;
    uint256 account_registry_anchor;
    CAmount expected_state_value_balance{0};
    CAmount expected_tx_value_balance{0};
    V2IngressBuildResult built;
};

struct V2DirectSendChainFixture
{
    std::vector<unsigned char> spending_key;
    shielded::ShieldedMerkleTree tree_before;
    std::vector<ShieldedNote> ring_notes;
    uint256 spend_anchor;
    uint256 account_registry_anchor;
    Nullifier input_nullifier;
    uint256 output_commitment;
    shielded::v2::V2SendBuildResult built;
};

[[nodiscard]] V2DirectSendChainFixture BuildV2DirectSendChainFixture(
    TestChain100Setup& setup,
    const Consensus::Params* consensus = nullptr,
    int32_t validation_height = std::numeric_limits<int32_t>::max(),
    CAmount fee = V2_DIRECT_SEND_FEE,
    size_t seeded_note_count = shielded::ringct::GetMinimumPrivacyTreeSize(shielded::lattice::RING_SIZE),
    CAmount transparent_output_value = 0)
{
    V2DirectSendChainFixture fixture;
    fixture.spending_key.assign(32, 0x44);
    BOOST_REQUIRE_GE(seeded_note_count, shielded::lattice::RING_SIZE);
    Consensus::Params& mutable_consensus =
        const_cast<Consensus::Params&>(consensus != nullptr ? *consensus : Params().GetConsensus());
    const Consensus::Params* effective_consensus = &mutable_consensus;

    ChainstateManager& chainman = *Assert(setup.m_node.chainman);
    BOOST_REQUIRE(WITH_LOCK(cs_main, return chainman.EnsureShieldedStateInitialized()));

    const CTransactionRef funding_tx = setup.m_coinbase_txns[0];
    BOOST_REQUIRE_GT(funding_tx->vout.size(), 0U);

    std::vector<V2SendOutputInput> funding_outputs;
    funding_outputs.reserve(seeded_note_count);
    CAmount total_ring_value{0};
    for (size_t i = 0; i < seeded_note_count; ++i) {
        const CAmount note_value =
            V2_DIRECT_SEND_RING_NOTE_VALUE + static_cast<CAmount>(i) * 500;
        fixture.ring_notes.push_back(
            MakeIngressNote(note_value, static_cast<unsigned char>(0x20 + i * 4)));
        funding_outputs.push_back(
            BuildDirectSendOutputInput(fixture.ring_notes.back(),
                                       static_cast<unsigned char>(0x70 + i * 3)));
        total_ring_value += note_value;
    }
    BOOST_REQUIRE(MoneyRange(total_ring_value));
    BOOST_REQUIRE_GT(funding_tx->vout[0].nValue, total_ring_value + V2_DIRECT_SEND_SEED_FEE);

    CMutableTransaction seed_template;
    seed_template.version = CTransaction::CURRENT_VERSION;
    seed_template.nLockTime = 41;
    seed_template.vin = {CTxIn{COutPoint{funding_tx->GetHash(), 0}}};
    seed_template.vout = {CTxOut{funding_tx->vout[0].nValue - total_ring_value - V2_DIRECT_SEND_SEED_FEE,
                                 GetScriptForDestination(WitnessV2P2MR(uint256::ONE))}};

    std::string reject_reason;
    auto seeded = shielded::v2::BuildV2SendTransaction(seed_template,
                                                       uint256{},
                                                       {},
                                                       funding_outputs,
                                                       V2_DIRECT_SEND_SEED_FEE,
                                                       {},
                                                       reject_reason);
    BOOST_REQUIRE_MESSAGE(seeded.has_value(), reject_reason);
    ReSignCoinbaseSpend(setup, seeded->tx, funding_tx);

    const CScript block_script = GetScriptForDestination(PKHash(setup.coinbaseKey.GetPubKey()));
    int32_t original_disable_height{mutable_consensus.nShieldedMatRiCTDisableHeight};
    bool restore_disable_height{false};
    const int32_t seed_block_height = WITH_LOCK(cs_main, return chainman.ActiveChain().Height() + 1);
    if (mutable_consensus.IsShieldedMatRiCTDisabled(seed_block_height)) {
        mutable_consensus.nShieldedMatRiCTDisableHeight = seed_block_height + 1;
        restore_disable_height = true;
    }
    setup.CreateAndProcessBlock({seeded->tx}, block_script);
    if (restore_disable_height) {
        mutable_consensus.nShieldedMatRiCTDisableHeight = original_disable_height;
    }

    fixture.tree_before = WITH_LOCK(cs_main, return chainman.GetShieldedMerkleTree());
    fixture.spend_anchor = fixture.tree_before.Root();
    BOOST_REQUIRE_EQUAL(fixture.tree_before.Size(), seeded_note_count);
    BOOST_REQUIRE(!fixture.spend_anchor.IsNull());

    const auto account_registry = WITH_LOCK(cs_main, return chainman.GetShieldedAccountRegistry());
    BOOST_REQUIRE(!account_registry.Root().IsNull());

    const auto account_leaf_hint = shielded::registry::MakeDirectSendAccountLeafHint();
    const std::vector<uint64_t> ring_positions = BuildRingPositions();
    std::vector<ShieldedNote> selected_ring_notes;
    selected_ring_notes.reserve(ring_positions.size());
    for (const uint64_t position : ring_positions) {
        BOOST_REQUIRE_LT(position, fixture.ring_notes.size());
        selected_ring_notes.push_back(fixture.ring_notes[position]);
    }
    const std::vector<uint256> ring_members = ReadRingMembers(
        fixture.tree_before,
        Span<const uint64_t>{ring_positions.data(), ring_positions.size()});
    auto shared_smile_ring_members =
        BuildSmileRingMembersFromNotes(selected_ring_notes, ring_members, account_leaf_hint);
    BOOST_REQUIRE(shared_smile_ring_members.has_value());

    std::vector<V2SendSpendInput> spend_inputs;
    spend_inputs.push_back(MakeSpendInput(fixture.ring_notes[V2_DIRECT_SEND_REAL_INDEX],
                                          ring_positions,
                                          ring_members,
                                          V2_DIRECT_SEND_REAL_INDEX,
                                          account_leaf_hint));
    spend_inputs.front().smile_ring_members = *shared_smile_ring_members;
    BOOST_REQUIRE(AttachAccountRegistryWitnessesFromRegistry(spend_inputs, account_registry));

    BOOST_REQUIRE_GE(fixture.ring_notes[V2_DIRECT_SEND_REAL_INDEX].value, fee + transparent_output_value);
    const ShieldedNote output_note = MakeIngressNote(
        fixture.ring_notes[V2_DIRECT_SEND_REAL_INDEX].value - fee - transparent_output_value,
        /*seed=*/0xd1);
    const auto output_input = BuildDirectSendOutputInput(output_note, /*recipient_seed=*/0xe1);

    if (validation_height == std::numeric_limits<int32_t>::max()) {
        validation_height = WITH_LOCK(cs_main, return chainman.ActiveChain().Height() + 1);
    }
    std::optional<shielded::v2::V2SendBuildResult> built;
    for (uint8_t attempt = 0; attempt < 8; ++attempt) {
        std::array<unsigned char, 32> rng_entropy{};
        rng_entropy.fill(static_cast<unsigned char>(0xc4 + attempt));
        CMutableTransaction tx_template;
        if (transparent_output_value > 0) {
            tx_template.vout = {CTxOut{transparent_output_value,
                                       GetScriptForDestination(WitnessV2P2MR(uint256::ONE))}};
        }
        built = shielded::v2::BuildV2SendTransaction(
            tx_template,
            fixture.spend_anchor,
            spend_inputs,
            {output_input},
            fee,
            Span<const unsigned char>{fixture.spending_key.data(), fixture.spending_key.size()},
            reject_reason,
            Span<const unsigned char>{rng_entropy.data(), rng_entropy.size()},
            effective_consensus,
            validation_height);
        if (built.has_value() || reject_reason != "bad-shielded-v2-builder-proof") {
            break;
        }
    }
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);
    BOOST_REQUIRE(built->IsValid());

    const auto* bundle = built->tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_REQUIRE_EQUAL(bundle->header.family_id,
                        shielded::v2::GetWireTransactionFamilyForValidationHeight(
                            TransactionFamily::V2_SEND,
                            effective_consensus,
                            validation_height));
    BOOST_REQUIRE(shielded::v2::BundleHasSemanticFamily(*bundle, TransactionFamily::V2_SEND));
    const auto& payload = std::get<shielded::v2::SendPayload>(bundle->payload);
    BOOST_REQUIRE_EQUAL(payload.spends.size(), 1U);
    BOOST_REQUIRE_EQUAL(payload.outputs.size(), 1U);

    fixture.account_registry_anchor = payload.account_registry_anchor;
    fixture.input_nullifier = payload.spends.front().nullifier;
    fixture.output_commitment = payload.outputs.front().note_commitment;
    fixture.built = std::move(*built);
    return fixture;
}

[[nodiscard]] CMutableTransaction BuildTransparentShieldingV2SendTx(TestChain100Setup& setup,
                                                                    CAmount output_value = 49'000,
                                                                    CAmount fee = V2_DIRECT_SEND_FEE,
                                                                    const Consensus::Params* consensus = nullptr,
                                                                    int32_t validation_height = std::numeric_limits<int32_t>::max())
{
    const CTransactionRef funding_tx = setup.m_coinbase_txns[0];
    BOOST_REQUIRE_GT(funding_tx->vout.size(), 0U);
    static constexpr CAmount FUNDING_FEE{10'000};
    BOOST_REQUIRE_GT(funding_tx->vout[0].nValue, output_value + fee + FUNDING_FEE);

    const CScript spend_script = GetScriptForDestination(PKHash(setup.coinbaseKey.GetPubKey()));
    CMutableTransaction confirmed_funding;
    confirmed_funding.version = CTransaction::CURRENT_VERSION;
    confirmed_funding.nLockTime = 17;
    confirmed_funding.vin.emplace_back(COutPoint{funding_tx->GetHash(), 0});
    confirmed_funding.vout = {
        CTxOut{output_value + fee, spend_script},
        CTxOut{funding_tx->vout[0].nValue - output_value - fee - FUNDING_FEE, spend_script},
    };
    ReSignCoinbaseSpend(setup, confirmed_funding, funding_tx);
    setup.CreateAndProcessBlock({confirmed_funding}, spend_script);
    const CTransactionRef confirmed_funding_ref = MakeTransactionRef(confirmed_funding);

    const ShieldedNote output_note = MakeIngressNote(output_value, /*seed=*/0x73);
    const auto output_input = BuildDirectSendOutputInput(output_note, /*recipient_seed=*/0x83);

    CMutableTransaction tx_template;
    tx_template.version = CTransaction::CURRENT_VERSION;
    tx_template.nLockTime = 29;
    tx_template.vin.emplace_back(COutPoint{confirmed_funding_ref->GetHash(), 0});

    std::string reject_reason;
    auto built = shielded::v2::BuildV2SendTransaction(tx_template,
                                                      uint256{},
                                                      {},
                                                      {output_input},
                                                      fee,
                                                      {},
                                                      reject_reason,
                                                      {},
                                                      consensus,
                                                      validation_height);
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);
    BOOST_REQUIRE(built->IsValid());
    ReSignSpend(setup, built->tx, confirmed_funding_ref);
    return built->tx;
}

[[nodiscard]] CMutableTransaction BuildCoinbaseShieldingV2SendTx(TestChain100Setup& setup,
                                                                 CAmount output_value = 49'000,
                                                                 CAmount fee = V2_DIRECT_SEND_FEE,
                                                                 const Consensus::Params* consensus = nullptr,
                                                                 int32_t validation_height = std::numeric_limits<int32_t>::max())
{
    const CTransactionRef funding_tx = setup.m_coinbase_txns[0];
    BOOST_REQUIRE_GT(funding_tx->vout.size(), 0U);
    BOOST_REQUIRE_GT(funding_tx->vout[0].nValue, output_value + fee);

    const ShieldedNote output_note = MakeIngressNote(output_value, /*seed=*/0x91);
    const auto output_input = BuildDirectSendOutputInput(output_note, /*recipient_seed=*/0xa1);

    CMutableTransaction tx_template;
    tx_template.version = CTransaction::CURRENT_VERSION;
    tx_template.nLockTime = 31;
    tx_template.vin.emplace_back(COutPoint{funding_tx->GetHash(), 0});

    std::string reject_reason;
    auto built = shielded::v2::BuildV2SendTransaction(tx_template,
                                                      uint256{},
                                                      {},
                                                      {output_input},
                                                      fee,
                                                      {},
                                                      reject_reason,
                                                      {},
                                                      consensus,
                                                      validation_height);
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);
    BOOST_REQUIRE(built->IsValid());
    ReSignCoinbaseSpend(setup, built->tx, funding_tx);
    return built->tx;
}

[[nodiscard]] shielded::v2::LifecycleAddress MakeLifecycleAddressForTxValidation(
    CPQKey& signing_key,
    unsigned char seed)
{
    shielded::v2::LifecycleAddress address;
    address.version = 0x01;
    address.algo_byte = 0x00;
    const std::vector<unsigned char> pubkey = signing_key.GetPubKey();
    BOOST_REQUIRE_EQUAL(pubkey.size(), MLDSA44_PUBKEY_SIZE);
    CSHA256().Write(pubkey.data(), pubkey.size()).Finalize(address.pk_hash.begin());
    for (size_t i = 0; i < address.kem_public_key.size(); ++i) {
        address.kem_public_key[i] = static_cast<unsigned char>(seed + i);
    }
    address.has_kem_public_key = true;
    CSHA256()
        .Write(address.kem_public_key.data(), address.kem_public_key.size())
        .Finalize(address.kem_pk_hash.begin());
    BOOST_REQUIRE(address.IsValid());
    return address;
}

[[nodiscard]] shielded::v2::AddressLifecycleControl MakeLifecycleRecordForTxValidation(
    shielded::v2::AddressLifecycleControlKind kind,
    CPQKey& subject_key,
    const shielded::v2::LifecycleAddress& subject,
    const std::optional<shielded::v2::LifecycleAddress>& successor,
    const uint256& transparent_binding_digest)
{
    shielded::v2::AddressLifecycleControl control;
    control.kind = kind;
    control.output_index = 0;
    control.subject = subject;
    control.has_successor = successor.has_value();
    if (successor.has_value()) {
        control.successor = *successor;
    }
    control.subject_spending_pubkey = subject_key.GetPubKey();
    const uint256 sighash =
        shielded::v2::ComputeAddressLifecycleRecordSigHash(control, transparent_binding_digest);
    BOOST_REQUIRE(!sighash.IsNull());
    BOOST_REQUIRE(subject_key.Sign(sighash, control.signature));
    BOOST_REQUIRE(control.IsValid());
    BOOST_REQUIRE(shielded::v2::VerifyAddressLifecycleRecord(control, transparent_binding_digest));
    return control;
}

[[nodiscard]] CMutableTransaction BuildLifecycleControlTx(TestChain100Setup& setup,
                                                          CAmount change_value = 49'000,
                                                          CAmount fee = V2_DIRECT_SEND_FEE,
                                                          const Consensus::Params* consensus = nullptr,
                                                          int32_t validation_height =
                                                              std::numeric_limits<int32_t>::max(),
                                                          const std::vector<CTxOut>& extra_outputs = {},
                                                          CTransactionRef* confirmed_funding_out = nullptr)
{
    const CTransactionRef funding_tx = setup.m_coinbase_txns[0];
    BOOST_REQUIRE_GT(funding_tx->vout.size(), 0U);
    static constexpr CAmount FUNDING_FEE{10'000};
    const CAmount lifecycle_input_value = change_value + fee;
    BOOST_REQUIRE_GT(funding_tx->vout[0].nValue, lifecycle_input_value + FUNDING_FEE);

    const CScript spend_script = GetScriptForDestination(PKHash(setup.coinbaseKey.GetPubKey()));
    CMutableTransaction confirmed_funding;
    confirmed_funding.version = CTransaction::CURRENT_VERSION;
    confirmed_funding.nLockTime = 23;
    confirmed_funding.vin.emplace_back(COutPoint{funding_tx->GetHash(), 0});
    confirmed_funding.vout = {
        CTxOut{lifecycle_input_value, spend_script},
        CTxOut{funding_tx->vout[0].nValue - lifecycle_input_value - FUNDING_FEE, spend_script},
    };
    ReSignCoinbaseSpend(setup, confirmed_funding, funding_tx);
    setup.CreateAndProcessBlock({confirmed_funding}, spend_script);
    const CTransactionRef confirmed_funding_ref = MakeTransactionRef(confirmed_funding);
    if (confirmed_funding_out != nullptr) {
        *confirmed_funding_out = confirmed_funding_ref;
    }

    CMutableTransaction tx;
    tx.version = CTransaction::CURRENT_VERSION;
    tx.nLockTime = 31;
    tx.vin.emplace_back(COutPoint{confirmed_funding_ref->GetHash(), 0});
    tx.vout.emplace_back(change_value, GetScriptForDestination(WitnessV2P2MR(uint256{0x51})));
    tx.vout.insert(tx.vout.end(), extra_outputs.begin(), extra_outputs.end());

    CPQKey subject_key;
    CPQKey successor_key;
    subject_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    successor_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(subject_key.IsValid());
    BOOST_REQUIRE(successor_key.IsValid());

    const auto subject = MakeLifecycleAddressForTxValidation(subject_key, 0x21);
    const auto successor = MakeLifecycleAddressForTxValidation(successor_key, 0x41);
    const uint256 binding_digest =
        shielded::v2::ComputeV2LifecycleTransparentBindingDigest(CTransaction{tx});
    BOOST_REQUIRE(!binding_digest.IsNull());

    shielded::v2::LifecyclePayload payload;
    payload.transparent_binding_digest = binding_digest;
    payload.lifecycle_controls = {MakeLifecycleRecordForTxValidation(
        shielded::v2::AddressLifecycleControlKind::ROTATE,
        subject_key,
        subject,
        successor,
        binding_digest)};
    BOOST_REQUIRE(payload.IsValid());

    shielded::v2::TransactionBundle bundle;
    bundle.header.family_id = shielded::v2::GetWireTransactionFamilyForValidationHeight(
        shielded::v2::TransactionFamily::V2_LIFECYCLE,
        consensus,
        validation_height);
    bundle.header.proof_envelope.proof_kind = shielded::v2::ProofKind::NONE;
    bundle.header.proof_envelope.membership_proof_kind = shielded::v2::ProofComponentKind::NONE;
    bundle.header.proof_envelope.amount_proof_kind = shielded::v2::ProofComponentKind::NONE;
    bundle.header.proof_envelope.balance_proof_kind = shielded::v2::ProofComponentKind::NONE;
    bundle.header.proof_envelope.settlement_binding_kind =
        shielded::v2::GetWireSettlementBindingKindForValidationHeight(
            shielded::v2::TransactionFamily::V2_LIFECYCLE,
            shielded::v2::SettlementBindingKind::NONE,
            consensus,
            validation_height);
    bundle.header.proof_envelope.statement_digest = uint256{};
    bundle.payload = payload;
    bundle.header.payload_digest = shielded::v2::ComputeLifecyclePayloadDigest(payload);
    BOOST_REQUIRE(bundle.IsValid());
    tx.shielded_bundle.v2_bundle = bundle;
    ReSignSpend(setup, tx, confirmed_funding_ref);
    return tx;
}

[[nodiscard]] CMutableTransaction BuildLegacyLifecycleSendTx(TestChain100Setup& setup,
                                                             CAmount output_value = 49'000,
                                                             CAmount fee = V2_DIRECT_SEND_FEE,
                                                             const Consensus::Params* consensus = nullptr,
                                                             int32_t validation_height =
                                                                 std::numeric_limits<int32_t>::max());

[[nodiscard]] CMutableTransaction BuildPostforkGenericSendLifecycleControlTx(
    TestChain100Setup& setup,
    CAmount output_value = 49'000,
    CAmount fee = V2_DIRECT_SEND_FEE,
    const Consensus::Params* consensus = nullptr,
    int32_t validation_height = std::numeric_limits<int32_t>::max())
{
    auto tx = BuildLegacyLifecycleSendTx(setup,
                                         output_value,
                                         fee,
                                         consensus,
                                         validation_height - 1);
    auto& bundle = *tx.shielded_bundle.v2_bundle;
    bundle.header.family_id = shielded::v2::GetWireTransactionFamilyForValidationHeight(
        shielded::v2::TransactionFamily::V2_SEND,
        consensus,
        validation_height);
    bundle.header.proof_envelope.settlement_binding_kind =
        shielded::v2::GetWireSettlementBindingKindForValidationHeight(
            shielded::v2::TransactionFamily::V2_SEND,
            shielded::v2::SettlementBindingKind::NONE,
            consensus,
            validation_height);
    auto derived_output_chunks = shielded::v2::BuildDerivedGenericOutputChunks(bundle.payload);
    BOOST_REQUIRE(derived_output_chunks.has_value());
    bundle.output_chunks = std::move(*derived_output_chunks);
    bundle.header.output_chunk_root = bundle.output_chunks.empty()
        ? uint256::ZERO
        : shielded::v2::ComputeOutputChunkRoot(
              Span<const shielded::v2::OutputChunkDescriptor>{bundle.output_chunks.data(),
                                                              bundle.output_chunks.size()});
    bundle.header.output_chunk_count = bundle.output_chunks.size();
    BOOST_REQUIRE(bundle.IsValid());
    return tx;
}

[[nodiscard]] CMutableTransaction BuildLegacyLifecycleSendTx(TestChain100Setup& setup,
                                                             CAmount output_value,
                                                             CAmount fee,
                                                             const Consensus::Params* consensus,
                                                             int32_t validation_height)
{
    const CTransactionRef funding_tx = setup.m_coinbase_txns[0];
    BOOST_REQUIRE_GT(funding_tx->vout.size(), 0U);
    static constexpr CAmount FUNDING_FEE{10'000};
    BOOST_REQUIRE_GT(funding_tx->vout[0].nValue, output_value + fee + FUNDING_FEE);

    const CScript spend_script = GetScriptForDestination(PKHash(setup.coinbaseKey.GetPubKey()));
    CMutableTransaction confirmed_funding;
    confirmed_funding.version = CTransaction::CURRENT_VERSION;
    confirmed_funding.nLockTime = 27;
    confirmed_funding.vin.emplace_back(COutPoint{funding_tx->GetHash(), 0});
    confirmed_funding.vout = {
        CTxOut{output_value + fee, spend_script},
        CTxOut{funding_tx->vout[0].nValue - output_value - fee - FUNDING_FEE, spend_script},
    };
    ReSignCoinbaseSpend(setup, confirmed_funding, funding_tx);
    setup.CreateAndProcessBlock({confirmed_funding}, spend_script);
    const CTransactionRef confirmed_funding_ref = MakeTransactionRef(confirmed_funding);

    CPQKey subject_key;
    CPQKey successor_key;
    subject_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    successor_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(subject_key.IsValid());
    BOOST_REQUIRE(successor_key.IsValid());

    const ShieldedNote output_note = MakeIngressNote(output_value, /*seed=*/0x77);
    const auto smile_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        output_note);
    BOOST_REQUIRE(smile_account.has_value());
    const uint256 note_commitment = smile2::ComputeCompactPublicAccountHash(*smile_account);

    const auto recipient = MakeIngressRecipient(/*seed=*/0x87);
    const auto encrypted_note = EncryptIngressNote(output_note,
                                                   recipient.pk,
                                                   /*kem_seed_byte=*/0x97,
                                                   /*nonce_byte=*/0xA7);
    auto encrypted_payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        encrypted_note,
        recipient.pk,
        shielded::v2::ScanDomain::OPAQUE);
    BOOST_REQUIRE(encrypted_payload.has_value());

    shielded::v2::V2SendOutputInput output_input;
    output_input.note_class = shielded::v2::NoteClass::OPERATOR;
    output_input.note = output_note;
    output_input.encrypted_note = *encrypted_payload;
    output_input.lifecycle_control = [&] {
        shielded::v2::AddressLifecycleControl control;
        control.kind = shielded::v2::AddressLifecycleControlKind::ROTATE;
        control.output_index = 0;
        control.subject = MakeLifecycleAddressForTxValidation(subject_key, 0x25);
        control.has_successor = true;
        control.successor = MakeLifecycleAddressForTxValidation(successor_key, 0x45);
        control.subject_spending_pubkey = subject_key.GetPubKey();
        const uint256 sighash =
            shielded::v2::ComputeAddressLifecycleControlSigHash(control, note_commitment);
        BOOST_REQUIRE(!sighash.IsNull());
        BOOST_REQUIRE(subject_key.Sign(sighash, control.signature));
        BOOST_REQUIRE(control.IsValid());
        BOOST_REQUIRE(shielded::v2::VerifyAddressLifecycleControl(control, note_commitment));
        return control;
    }();

    CMutableTransaction tx_template;
    tx_template.version = CTransaction::CURRENT_VERSION;
    tx_template.nLockTime = 29;
    tx_template.vin.emplace_back(COutPoint{confirmed_funding_ref->GetHash(), 0});

    std::string reject_reason;
    auto built = shielded::v2::BuildV2SendTransaction(tx_template,
                                                      uint256{},
                                                      {},
                                                      {output_input},
                                                      fee,
                                                      {},
                                                      reject_reason,
                                                      {},
                                                      consensus,
                                                      validation_height);
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);
    ReSignSpend(setup, built->tx, confirmed_funding_ref);
    return built->tx;
}

bool RemoveShieldedSmilePublicAccountForTest(ChainstateManager& chainman,
                                             const uint256& commitment) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    auto& public_accounts =
        const_cast<std::map<uint256, smile2::CompactPublicAccount>&>(
            chainman.GetShieldedSmilePublicAccounts());
    const bool erased = public_accounts.erase(commitment) == 1;
    if (erased) {
        chainman.InvalidateShieldedAccountStateSnapshotCaches();
    }
    return erased;
}

bool RemoveShieldedAccountLeafCommitmentForTest(ChainstateManager& chainman,
                                                const uint256& commitment) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    auto& account_leaf_commitments =
        const_cast<std::map<uint256, uint256>&>(
            chainman.GetShieldedAccountLeafCommitments());
    const bool erased = account_leaf_commitments.erase(commitment) == 1;
    if (erased) {
        chainman.InvalidateShieldedAccountStateSnapshotCaches();
    }
    return erased;
}

void EnsureIngressAccountRegistryAnchorTracked(TestChain100Setup& setup,
                                               const V2IngressChainFixture& fixture)
{
    BOOST_REQUIRE(!fixture.account_registry_anchor.IsNull());
    WITH_LOCK(cs_main, {
        ChainstateManager& chainman = *Assert(setup.m_node.chainman);
        BOOST_REQUIRE(chainman.EnsureShieldedStateInitialized());
        if (!chainman.IsShieldedAccountRegistryRootValid(fixture.account_registry_anchor)) {
            chainman.RecordShieldedAccountRegistryRoot(fixture.account_registry_anchor);
        }
    });
}

void CheckIngressValueBalances(const V2IngressChainFixture& fixture)
{
    std::string reject_reason;
    const auto state_value_balance =
        TryGetShieldedStateValueBalance(fixture.built.tx.shielded_bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(state_value_balance.has_value(), reject_reason);
    BOOST_CHECK_EQUAL(*state_value_balance, fixture.expected_state_value_balance);
    BOOST_CHECK_EQUAL(GetShieldedTxValueBalance(fixture.built.tx.shielded_bundle),
                      fixture.expected_tx_value_balance);
}

[[nodiscard]] V2IngressChainFixture BuildV2IngressChainFixture(TestChain100Setup& setup,
                                                              std::vector<CAmount> input_values,
                                                              std::vector<CAmount> reserve_values,
                                                              std::vector<V2IngressLeafInput> ingress_leaves,
                                                              IngressSettlementWitnessKind settlement_kind =
                                                                  IngressSettlementWitnessKind::PROOF_ONLY,
                                                              size_t seeded_note_count =
                                                                  shielded::ringct::GetMinimumPrivacyTreeSize(
                                                                      shielded::lattice::RING_SIZE),
                                                              const Consensus::Params* consensus = nullptr,
                                                              int32_t validation_height =
                                                                  std::numeric_limits<int32_t>::max());

[[nodiscard]] V2IngressChainFixture BuildV2IngressChainFixture(TestChain100Setup& setup,
                                                              size_t spend_input_count = 1,
                                                              size_t reserve_output_count = 1,
                                                              size_t ingress_leaf_count = 2,
                                                              IngressSettlementWitnessKind settlement_kind =
                                                                  IngressSettlementWitnessKind::PROOF_ONLY,
                                                              size_t seeded_note_count =
                                                                  shielded::ringct::GetMinimumPrivacyTreeSize(
                                                                      shielded::lattice::RING_SIZE),
                                                              const Consensus::Params* consensus = nullptr,
                                                              int32_t validation_height =
                                                                  std::numeric_limits<int32_t>::max())
{
    BOOST_REQUIRE_GT(spend_input_count, 0U);
    BOOST_REQUIRE_GT(reserve_output_count, 0U);
    BOOST_REQUIRE_GT(ingress_leaf_count, 0U);
    BOOST_REQUIRE_LE(reserve_output_count, shielded::v2::MAX_BATCH_RESERVE_OUTPUTS);
    BOOST_REQUIRE_LE(ingress_leaf_count, shielded::v2::MAX_BATCH_LEAVES);

    std::vector<CAmount> reserve_values;
    reserve_values.reserve(reserve_output_count);
    for (size_t output_idx = 0; output_idx < reserve_output_count; ++output_idx) {
        reserve_values.push_back(V2_INGRESS_RESERVE_VALUE + static_cast<CAmount>(output_idx) * 120'000);
    }

    std::vector<V2IngressLeafInput> ingress_leaves;
    ingress_leaves.reserve(ingress_leaf_count);
    for (size_t leaf_idx = 0; leaf_idx < ingress_leaf_count; ++leaf_idx) {
        ingress_leaves.push_back(
            MakeIngressLeaf(static_cast<unsigned char>(0x81 + leaf_idx * 0x10),
                            /*amount=*/100'000 + static_cast<CAmount>(leaf_idx) * 35'000,
                            /*fee=*/1'000'000 + static_cast<CAmount>(leaf_idx) * 15'000));
    }

    const CAmount reserve_total = std::accumulate(reserve_values.begin(), reserve_values.end(), CAmount{0});
    const CAmount ingress_total = std::accumulate(
        ingress_leaves.begin(),
        ingress_leaves.end(),
        CAmount{0},
        [](CAmount total, const V2IngressLeafInput& leaf) {
            return total + leaf.bridge_leaf.amount + leaf.fee;
        });
    return BuildV2IngressChainFixture(setup,
                                      DistributeIngressInputValues(reserve_total + ingress_total, spend_input_count),
                                      std::move(reserve_values),
                                      std::move(ingress_leaves),
                                      settlement_kind,
                                      seeded_note_count,
                                      consensus,
                                      validation_height);
}

[[nodiscard]] V2IngressChainFixture BuildV2IngressChainFixture(TestChain100Setup& setup,
                                                              std::vector<CAmount> input_values,
                                                              std::vector<CAmount> reserve_values,
                                                              std::vector<V2IngressLeafInput> ingress_leaves,
                                                              IngressSettlementWitnessKind settlement_kind,
                                                              size_t seeded_note_count,
                                                              const Consensus::Params* consensus,
                                                              int32_t validation_height)
{
    V2IngressChainFixture fixture;
    fixture.spending_key.assign(32, 0x42);
    const Consensus::Params* effective_consensus = consensus != nullptr ? consensus : &Params().GetConsensus();
    const size_t spend_input_count = input_values.size();
    const size_t reserve_output_count = reserve_values.size();
    const size_t ingress_leaf_count = ingress_leaves.size();
    BOOST_REQUIRE_GE(seeded_note_count, shielded::lattice::RING_SIZE);
    BOOST_REQUIRE_GT(spend_input_count, 0U);
    BOOST_REQUIRE_GT(reserve_output_count, 0U);
    BOOST_REQUIRE_GT(ingress_leaf_count, 0U);
    BOOST_REQUIRE_LE(reserve_output_count, shielded::v2::MAX_BATCH_RESERVE_OUTPUTS);
    BOOST_REQUIRE_LE(ingress_leaf_count, shielded::v2::MAX_BATCH_LEAVES);
    BOOST_REQUIRE(std::all_of(input_values.begin(), input_values.end(), [](const CAmount value) {
        return value > 0 && MoneyRange(value);
    }));

    ChainstateManager& chainman = *Assert(setup.m_node.chainman);
    BOOST_REQUIRE(WITH_LOCK(cs_main, return chainman.EnsureShieldedStateInitialized()));
    Consensus::Params& mutable_consensus = const_cast<Consensus::Params&>(*effective_consensus);
    const int32_t seed_validation_height =
        WITH_LOCK(cs_main, return chainman.ActiveChain().Height() + 1);
    if (validation_height == std::numeric_limits<int32_t>::max()) {
        validation_height = seed_validation_height;
    }

    const CAmount reserve_total = std::accumulate(reserve_values.begin(), reserve_values.end(), CAmount{0});
    const CAmount ingress_total = std::accumulate(
        ingress_leaves.begin(),
        ingress_leaves.end(),
        CAmount{0},
        [](CAmount total, const V2IngressLeafInput& leaf) {
            return total + leaf.bridge_leaf.amount + leaf.fee;
        });
    BOOST_REQUIRE_EQUAL(std::accumulate(input_values.begin(), input_values.end(), CAmount{0}),
                        reserve_total + ingress_total);
    const auto real_indices = SelectIngressRealIndices(spend_input_count);

    const size_t output_count = seeded_note_count;
    std::vector<ShieldedNote> ring_notes;
    ring_notes.reserve(output_count);
    for (size_t i = 0; i < output_count; ++i) {
        const auto real_it = std::find(real_indices.begin(), real_indices.end(), i);
        const bool is_real_member = real_it != real_indices.end();
        const ShieldedNote note = is_real_member
            ? MakeIngressNote(input_values[std::distance(real_indices.begin(), real_it)],
                              static_cast<unsigned char>(0x21 + std::distance(real_indices.begin(), real_it) * 0x10))
            : MakeIngressNote(/*value=*/12'000 + static_cast<CAmount>(i),
                              static_cast<unsigned char>(0x30 + i * 3));
        ring_notes.push_back(note);
    }
    std::vector<shielded::v2::OutputDescription> funding_outputs;
    funding_outputs.reserve(ring_notes.size());
    for (size_t i = 0; i < ring_notes.size(); ++i) {
        funding_outputs.push_back(
            BuildIngressFundingOutput(ring_notes[i], static_cast<unsigned char>(0x60 + i * 5)));
    }
    const auto settlement_anchor_fixture = BuildSettlementAnchorFromEgressFixture(
        test::shielded::BuildV2EgressReceiptFixture(
            funding_outputs,
            {},
            std::accumulate(ring_notes.begin(),
                            ring_notes.end(),
                            CAmount{0},
                            [](CAmount total, const ShieldedNote& note) { return total + note.value; }),
            /*proof_receipt_count=*/1,
            /*required_receipts=*/1,
            effective_consensus,
            seed_validation_height),
        effective_consensus,
        seed_validation_height);
    const auto egress_fixture = test::shielded::BuildV2EgressReceiptFixture(
        std::move(funding_outputs),
        {},
        std::accumulate(ring_notes.begin(),
                        ring_notes.end(),
                        CAmount{0},
                        [](CAmount total, const ShieldedNote& note) { return total + note.value; }),
        /*proof_receipt_count=*/1,
        /*required_receipts=*/1,
        effective_consensus,
        seed_validation_height);

    const CScript block_script = GetScriptForDestination(PKHash(setup.coinbaseKey.GetPubKey()));
    const ScopedConsensusU32Override restore_anchor_maturity{
        mutable_consensus.nShieldedSettlementAnchorMaturity,
        mutable_consensus.nShieldedSettlementAnchorMaturity};
    mutable_consensus.nShieldedSettlementAnchorMaturity = 0;
    setup.CreateAndProcessBlock({settlement_anchor_fixture.tx}, block_script);
    setup.CreateAndProcessBlock({egress_fixture.tx}, block_script);

    fixture.tree_before = WITH_LOCK(cs_main, return chainman.GetShieldedMerkleTree());
    fixture.spend_anchor = fixture.tree_before.Root();
    BOOST_REQUIRE_EQUAL(fixture.tree_before.Size(), output_count);
    BOOST_REQUIRE(!fixture.spend_anchor.IsNull());
    const auto account_registry = WITH_LOCK(cs_main, return chainman.GetShieldedAccountRegistry());
    BOOST_REQUIRE(!account_registry.Root().IsNull());
    const auto& account_leaf_commitments =
        WITH_LOCK(cs_main, return chainman.GetShieldedAccountLeafCommitments());
    const auto& egress_payload = std::get<shielded::v2::EgressBatchPayload>(
        egress_fixture.tx.shielded_bundle.v2_bundle->payload);
    const auto egress_account_leaf_hint = shielded::registry::MakeEgressAccountLeafHint(
        egress_payload.settlement_binding_digest,
        egress_payload.output_binding_digest);
    BOOST_REQUIRE(egress_account_leaf_hint.has_value());

    const std::vector<uint64_t> ring_positions = BuildRingPositions();
    const std::vector<uint256> ring_members = ReadRingMembers(
        fixture.tree_before,
        Span<const uint64_t>{ring_positions.data(), ring_positions.size()});
    std::vector<ShieldedNote> selected_ring_notes;
    selected_ring_notes.reserve(ring_positions.size());
    for (const uint64_t position : ring_positions) {
        BOOST_REQUIRE_LT(position, ring_notes.size());
        selected_ring_notes.push_back(ring_notes[position]);
    }
    auto shared_smile_ring_members =
        BuildSmileRingMembersFromNotes(selected_ring_notes,
                                       ring_members,
                                       *egress_account_leaf_hint,
                                       &account_leaf_commitments);
    BOOST_REQUIRE(shared_smile_ring_members.has_value());

    V2IngressBuildInput input;
    const auto settlement = BuildIngressSettlementContext(ingress_leaves, settlement_kind);
    input.statement = settlement.statement;
    input.settlement_witness = settlement.witness;
    input.spend_inputs.reserve(spend_input_count);
    for (size_t input_idx = 0; input_idx < spend_input_count; ++input_idx) {
        fixture.input_notes.push_back(ring_notes[real_indices[input_idx]]);
        V2SendSpendInput spend_input = MakeSpendInput(fixture.input_notes[input_idx],
                                                      ring_positions,
                                                      ring_members,
                                                      real_indices[input_idx],
                                                      *egress_account_leaf_hint);
        spend_input.smile_ring_members = *shared_smile_ring_members;
        input.spend_inputs.push_back(std::move(spend_input));
    }
    BOOST_REQUIRE(AttachAccountRegistryWitnessesFromRegistry(input.spend_inputs, account_registry));

    input.reserve_outputs.reserve(reserve_output_count);
    for (size_t output_idx = 0; output_idx < reserve_output_count; ++output_idx) {
        const ShieldedNote reserve_note =
            MakeIngressNote(reserve_values[output_idx], static_cast<unsigned char>(0x41 + output_idx * 0x10));
        const auto reserve_recipient = MakeIngressRecipient(static_cast<unsigned char>(0x51 + output_idx * 0x10));
        const auto reserve_encrypted_note = EncryptIngressNote(
            reserve_note,
            reserve_recipient.pk,
            static_cast<unsigned char>(0x61 + output_idx * 0x10),
            static_cast<unsigned char>(0x71 + output_idx * 0x10));
        auto reserve_payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
            reserve_encrypted_note,
            reserve_recipient.pk,
            ScanDomain::RESERVE);
        BOOST_REQUIRE(reserve_payload.has_value());

        V2SendOutputInput reserve_output;
        reserve_output.note_class = NoteClass::RESERVE;
        reserve_output.note = reserve_note;
        reserve_output.encrypted_note = *reserve_payload;
        input.reserve_outputs.push_back(std::move(reserve_output));
        const auto reserve_account = smile2::wallet::BuildCompactPublicAccountFromNote(
            smile2::wallet::SMILE_GLOBAL_SEED,
            reserve_note);
        BOOST_REQUIRE(reserve_account.has_value());
        fixture.reserve_commitments.push_back(smile2::ComputeCompactPublicAccountHash(*reserve_account));
    }
    input.ingress_leaves = ingress_leaves;
    BOOST_REQUIRE(input.IsValid());

    std::string reject_reason;
    std::array<unsigned char, 32> rng_entropy{};
    rng_entropy.fill(0xA5);
    auto built = shielded::v2::BuildV2IngressBatchTransaction(
        CMutableTransaction{},
        fixture.spend_anchor,
        input,
        Span<const unsigned char>{fixture.spending_key.data(), fixture.spending_key.size()},
        reject_reason,
        Span<const unsigned char>{rng_entropy.data(), rng_entropy.size()},
        effective_consensus,
        validation_height);
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);
    BOOST_REQUIRE(built->IsValid());

    const auto& payload = std::get<shielded::v2::IngressBatchPayload>(
        built->tx.shielded_bundle.GetV2Bundle()->payload);
    fixture.account_registry_anchor = payload.account_registry_anchor;
    fixture.expected_state_value_balance = input.statement.total_amount + payload.fee;
    fixture.expected_tx_value_balance = payload.fee;
    fixture.input_nullifiers.clear();
    fixture.input_nullifiers.reserve(payload.consumed_spends.size());
    for (const auto& spend : payload.consumed_spends) {
        fixture.input_nullifiers.push_back(spend.nullifier);
    }
    BOOST_REQUIRE_EQUAL(fixture.input_nullifiers.size(), spend_input_count);
    BOOST_REQUIRE_EQUAL(fixture.reserve_commitments.size(), reserve_output_count);
    fixture.built = std::move(*built);
    return fixture;
}

} // namespace

std::optional<std::pair<std::string, CTransactionRef>> SingleTRUCChecks(const CTransactionRef& ptx, const CTxMemPool::setEntries& mempool_ancestors, const std::set<Txid>& direct_conflicts, int64_t vsize)
{
    std::string dummy;
    return SingleTRUCChecks(ptx, dummy, dummy, empty_ignore_rejects, mempool_ancestors, direct_conflicts, vsize);
}

std::optional<std::string> PackageTRUCChecks(const CTransactionRef& ptx, int64_t vsize, const Package& package, const CTxMemPool::setEntries& mempool_ancestors)
{
    std::string dummy;
    return PackageTRUCChecks(ptx, vsize, dummy, dummy, empty_ignore_rejects, package, mempool_ancestors);
}

/**
 * Ensure that the mempool won't accept coinbase transactions.
 */
BOOST_FIXTURE_TEST_CASE(tx_mempool_reject_coinbase, TestChain100Setup)
{
    CScript scriptPubKey = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CMutableTransaction coinbaseTx;

    coinbaseTx.version = 1;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vout.resize(1);
    coinbaseTx.vin[0].scriptSig = CScript() << OP_11 << OP_EQUAL;
    coinbaseTx.vout[0].nValue = 1 * CENT;
    coinbaseTx.vout[0].scriptPubKey = scriptPubKey;

    BOOST_CHECK(CTransaction(coinbaseTx).IsCoinBase());

    LOCK(cs_main);

    unsigned int initialPoolSize = m_node.mempool->size();
    const MempoolAcceptResult result = m_node.chainman->ProcessTransaction(MakeTransactionRef(coinbaseTx));

    BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);

    // Check that the transaction hasn't been added to mempool.
    BOOST_CHECK_EQUAL(m_node.mempool->size(), initialPoolSize);

    // Check that the validation state reflects the unsuccessful attempt.
    BOOST_CHECK(result.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "coinbase");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_accepts_v2_egress_after_settlement_anchor_and_evicts_it_after_reorg, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const ScopedConsensusU32Override restore_maturity{
        consensus.nShieldedSettlementAnchorMaturity,
        consensus.nShieldedSettlementAnchorMaturity};
    consensus.nShieldedSettlementAnchorMaturity = 0;
    const int32_t validation_height = NextShieldedValidationHeight(*this);
    const auto settlement_anchor_fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture(
        /*output_count=*/2,
        /*proof_receipt_count=*/1,
        /*required_receipts=*/1,
        &consensus,
        validation_height);
    const auto egress_fixture = test::shielded::BuildV2EgressReceiptFixture(
        /*output_count=*/2,
        &consensus,
        validation_height);
    const auto same_block_settlement_anchor_fixture =
        test::shielded::BuildV2SettlementAnchorReceiptFixture(
            /*output_count=*/3,
            /*proof_receipt_count=*/1,
            /*required_receipts=*/1,
            &consensus,
            validation_height);
    const auto same_block_egress_fixture = test::shielded::BuildV2EgressReceiptFixture(
        /*output_count=*/3,
        &consensus,
        validation_height);
    const auto egress_tx = MakeTransactionRef(egress_fixture.tx);
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));

    BOOST_REQUIRE_EQUAL(settlement_anchor_fixture.settlement_anchor_digest,
                        std::get<shielded::v2::EgressBatchPayload>(
                            egress_fixture.tx.shielded_bundle.v2_bundle->payload)
                            .settlement_anchor);

    const MempoolAcceptResult result =
        WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(egress_tx, /*test_accept=*/true));

    BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(result.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "bad-shielded-v2-egress-unanchored");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);

    CreateAndProcessBlock({settlement_anchor_fixture.tx}, script_pub_key);
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return m_node.chainman->IsShieldedSettlementAnchorValid(
                              settlement_anchor_fixture.settlement_anchor_digest)));
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs,
                          return !m_node.mempool->exists(GenTxid::Txid(egress_tx->GetHash()))));

    m_node.mempool->PrioritiseTransaction(egress_tx->GetHash(), COIN);
    const MempoolAcceptResult accepted_result =
        WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(egress_tx));

    BOOST_CHECK(accepted_result.m_result_type == MempoolAcceptResult::ResultType::VALID);
    BOOST_CHECK(accepted_result.m_state.IsValid());
    BOOST_CHECK(
        WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(GenTxid::Txid(egress_tx->GetHash()))));

    BlockValidationState invalidate_state;
    BOOST_REQUIRE(
        m_node.chainman->ActiveChainstate().InvalidateBlock(
            invalidate_state, WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip())));
    BOOST_CHECK(invalidate_state.IsValid());
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return !m_node.chainman->IsShieldedSettlementAnchorValid(
                              settlement_anchor_fixture.settlement_anchor_digest)));
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs,
                          return !m_node.mempool->exists(GenTxid::Txid(egress_tx->GetHash()))));

    const MempoolAcceptResult rejected_after_reorg =
        WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(egress_tx, /*test_accept=*/true));
    BOOST_CHECK(rejected_after_reorg.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(rejected_after_reorg.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(rejected_after_reorg.m_state.GetRejectReason(),
                      "bad-shielded-v2-egress-unanchored");

    const CBlock same_block = CreateAndProcessBlock({same_block_settlement_anchor_fixture.tx,
                                                     same_block_egress_fixture.tx},
                                                    script_pub_key);
    BOOST_CHECK_EQUAL(
        same_block.GetHash(),
        WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip()->GetBlockHash()));
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return !m_node.chainman->IsShieldedSettlementAnchorValid(
                              same_block_settlement_anchor_fixture.settlement_anchor_digest)));
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_rejects_v2_egress_when_imported_receipt_is_missing_from_witness_set, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const ScopedConsensusU32Override restore_maturity{
        consensus.nShieldedSettlementAnchorMaturity,
        consensus.nShieldedSettlementAnchorMaturity};
    consensus.nShieldedSettlementAnchorMaturity = 0;
    const int32_t validation_height = NextShieldedValidationHeight(*this);
    auto egress_fixture = test::shielded::BuildV2EgressReceiptFixture(
        /*output_count=*/2,
        /*proof_receipt_count=*/2,
        /*required_receipts=*/1,
        &consensus,
        validation_height);
    BOOST_REQUIRE_EQUAL(egress_fixture.witness.proof_receipts.size(), 2U);

    auto settlement_anchor_source = egress_fixture;
    settlement_anchor_source.receipt = settlement_anchor_source.witness.proof_receipts.back();
    settlement_anchor_source.witness.proof_receipts = {settlement_anchor_source.witness.proof_receipts.back()};
    BOOST_REQUIRE(settlement_anchor_source.witness.IsValid());
    const auto settlement_anchor_fixture = BuildSettlementAnchorFromEgressFixture(
        settlement_anchor_source,
        &consensus,
        validation_height);

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({settlement_anchor_fixture.tx}, script_pub_key);
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return m_node.chainman->IsShieldedSettlementAnchorValid(
                              settlement_anchor_fixture.settlement_anchor_digest)));

    auto attack_tx = egress_fixture.tx;
    auto& attack_bundle = *Assert(attack_tx.shielded_bundle.v2_bundle);
    auto& attack_payload = std::get<shielded::v2::EgressBatchPayload>(attack_bundle.payload);

    auto attack_witness = egress_fixture.witness;
    attack_witness.proof_receipts = {egress_fixture.witness.proof_receipts.back()};
    BOOST_REQUIRE(attack_witness.IsValid());

    const auto attack_anchor = shielded::BuildBridgeExternalAnchorFromProofReceipts(
        attack_witness.statement,
        Span<const shielded::BridgeProofReceipt>{attack_witness.proof_receipts.data(),
                                                 attack_witness.proof_receipts.size()});
    BOOST_REQUIRE(attack_anchor.has_value());
    attack_payload.settlement_anchor = shielded::v2::proof::ComputeSettlementExternalAnchorDigest(*attack_anchor);
    BOOST_REQUIRE(!attack_payload.settlement_anchor.IsNull());

    DataStream witness_stream;
    witness_stream << attack_witness;
    const auto* witness_begin = reinterpret_cast<const unsigned char*>(witness_stream.data());
    attack_bundle.proof_payload.assign(witness_begin, witness_begin + witness_stream.size());
    BOOST_REQUIRE_EQUAL(attack_bundle.proof_shards.size(), 1U);
    attack_bundle.proof_shards.front().proof_payload_size = attack_bundle.proof_payload.size();
    attack_bundle.header.proof_shard_root = shielded::v2::ComputeProofShardRoot(
        Span<const shielded::v2::ProofShardDescriptor>{attack_bundle.proof_shards.data(),
                                                       attack_bundle.proof_shards.size()});
    attack_bundle.header.payload_digest = shielded::v2::ComputeEgressBatchPayloadDigest(attack_payload);
    BOOST_REQUIRE(attack_bundle.IsValid());
    m_node.mempool->PrioritiseTransaction(attack_tx.GetHash(), COIN);

    const MempoolAcceptResult result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(attack_tx), /*test_accept=*/true));

    BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(result.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "bad-v2-settlement-missing-imported-receipt");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(block_rejects_v2_egress_when_shielded_scan_units_exceed_consensus_limit, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const ScopedShieldedResourceLimits restore{
        consensus,
        consensus.nMaxBlockShieldedScanUnits,
        consensus.nMaxBlockShieldedTreeUpdateUnits};
    const ScopedConsensusU32Override restore_maturity{
        consensus.nShieldedSettlementAnchorMaturity,
        consensus.nShieldedSettlementAnchorMaturity};
    consensus.nMaxBlockShieldedScanUnits = 2;
    consensus.nShieldedSettlementAnchorMaturity = 0;
    const int32_t validation_height = NextShieldedValidationHeight(*this);

    const auto egress_fixture =
        test::shielded::BuildV2EgressReceiptFixture(/*output_count=*/2, &consensus, validation_height);
    const auto usage = GetShieldedResourceUsage(egress_fixture.tx.GetShieldedBundle());
    BOOST_REQUIRE_EQUAL(usage.scan_units, 3U);
    BOOST_REQUIRE_EQUAL(usage.tree_update_units, 2U);
    const auto settlement_anchor_fixture =
        BuildSettlementAnchorFromEgressFixture(egress_fixture, &consensus, validation_height);
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const int active_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());

    const CBlock block = CreateBlock({settlement_anchor_fixture.tx, egress_fixture.tx},
                                     script_pub_key,
                                     m_node.chainman->ActiveChainstate());
    ExpectBlockRejected(*this, block, "bad-blk-shielded-scan");
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height()), active_height);
}

BOOST_FIXTURE_TEST_CASE(block_rejects_v2_egress_when_shielded_tree_updates_exceed_consensus_limit, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const ScopedShieldedResourceLimits restore{
        consensus,
        consensus.nMaxBlockShieldedScanUnits,
        consensus.nMaxBlockShieldedTreeUpdateUnits};
    const ScopedConsensusU32Override restore_maturity{
        consensus.nShieldedSettlementAnchorMaturity,
        consensus.nShieldedSettlementAnchorMaturity};
    consensus.nMaxBlockShieldedTreeUpdateUnits = 1;
    consensus.nShieldedSettlementAnchorMaturity = 0;
    const int32_t validation_height = NextShieldedValidationHeight(*this);

    const auto egress_fixture =
        test::shielded::BuildV2EgressReceiptFixture(/*output_count=*/2, &consensus, validation_height);
    const auto usage = GetShieldedResourceUsage(egress_fixture.tx.GetShieldedBundle());
    BOOST_REQUIRE_EQUAL(usage.scan_units, 3U);
    BOOST_REQUIRE_EQUAL(usage.tree_update_units, 2U);
    const auto settlement_anchor_fixture =
        BuildSettlementAnchorFromEgressFixture(egress_fixture, &consensus, validation_height);
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const int active_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());

    const CBlock block = CreateBlock({settlement_anchor_fixture.tx, egress_fixture.tx},
                                     script_pub_key,
                                     m_node.chainman->ActiveChainstate());
    ExpectBlockRejected(*this, block, "bad-blk-shielded-tree-updates");
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height()), active_height);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_activation_gates_shielded_account_registry_append_limit, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int active_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore_height{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    const ScopedShieldedRegistryAppendLimit restore_limit{
        consensus,
        consensus.nMaxBlockShieldedAccountRegistryAppends};
    consensus.nShieldedMatRiCTDisableHeight = active_height + 2;
    consensus.nMaxBlockShieldedAccountRegistryAppends = 1;

    auto rebalance_fixture = test::shielded::BuildV2RebalanceFixture(/*reserve_output_count=*/2);
    AttachCoinbaseFeeCarrier(*this, rebalance_fixture.tx, m_coinbase_txns[0]);
    BOOST_REQUIRE_EQUAL(rebalance_fixture.tx.GetShieldedBundle().GetShieldedOutputCount(), 2U);
    const auto rebalance_tx = MakeTransactionRef(rebalance_fixture.tx);

    const MempoolAcceptResult pre_activation_result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(rebalance_tx, /*test_accept=*/true));
    BOOST_CHECK(pre_activation_result.m_result_type == MempoolAcceptResult::ResultType::VALID);

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({}, script_pub_key);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height()), active_height + 1);

    const MempoolAcceptResult activation_result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(rebalance_tx, /*test_accept=*/true));
    BOOST_CHECK(activation_result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(activation_result.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(activation_result.m_state.GetRejectReason(),
                      "bad-shielded-account-registry-rate-limit");
    BOOST_CHECK(activation_result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(block_rejects_shielded_account_registry_append_limit_at_activation, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int active_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore_height{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    const ScopedShieldedRegistryAppendLimit restore_limit{
        consensus,
        consensus.nMaxBlockShieldedAccountRegistryAppends};
    consensus.nShieldedMatRiCTDisableHeight = active_height + 2;
    consensus.nMaxBlockShieldedAccountRegistryAppends = 1;

    const auto rebalance_fixture = test::shielded::BuildV2RebalanceFixture(/*reserve_output_count=*/2);
    BOOST_REQUIRE_EQUAL(rebalance_fixture.tx.GetShieldedBundle().GetShieldedOutputCount(), 2U);

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({}, script_pub_key);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height()), active_height + 1);

    const CBlock block = CreateBlock({rebalance_fixture.tx},
                                     script_pub_key,
                                     m_node.chainman->ActiveChainstate());
    ExpectBlockRejected(*this, block, "bad-blk-shielded-account-registry-rate-limit");
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height()), active_height + 1);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_activation_gates_shielded_account_registry_total_entry_limit, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int active_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore_height{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    const ScopedShieldedRegistryEntryLimit restore_limit{
        consensus,
        consensus.nMaxShieldedAccountRegistryEntries};
    consensus.nShieldedMatRiCTDisableHeight = active_height + 2;
    consensus.nMaxShieldedAccountRegistryEntries = 1;

    auto rebalance_fixture = test::shielded::BuildV2RebalanceFixture(/*reserve_output_count=*/2);
    AttachCoinbaseFeeCarrier(*this, rebalance_fixture.tx, m_coinbase_txns[0]);
    BOOST_REQUIRE_EQUAL(rebalance_fixture.tx.GetShieldedBundle().GetShieldedOutputCount(), 2U);
    const auto rebalance_tx = MakeTransactionRef(rebalance_fixture.tx);

    const MempoolAcceptResult pre_activation_result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(rebalance_tx, /*test_accept=*/true));
    BOOST_CHECK(pre_activation_result.m_result_type == MempoolAcceptResult::ResultType::VALID);

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({}, script_pub_key);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height()), active_height + 1);

    const MempoolAcceptResult activation_result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(rebalance_tx, /*test_accept=*/true));
    BOOST_CHECK(activation_result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(activation_result.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(activation_result.m_state.GetRejectReason(),
                      "bad-shielded-account-registry-size-limit");
    BOOST_CHECK(activation_result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(block_rejects_shielded_account_registry_total_entry_limit_at_activation, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int active_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore_height{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    const ScopedShieldedRegistryEntryLimit restore_limit{
        consensus,
        consensus.nMaxShieldedAccountRegistryEntries};
    consensus.nShieldedMatRiCTDisableHeight = active_height + 2;
    consensus.nMaxShieldedAccountRegistryEntries = 1;

    const auto rebalance_fixture = test::shielded::BuildV2RebalanceFixture(/*reserve_output_count=*/2);
    BOOST_REQUIRE_EQUAL(rebalance_fixture.tx.GetShieldedBundle().GetShieldedOutputCount(), 2U);

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({}, script_pub_key);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height()), active_height + 1);

    const CBlock block = CreateBlock({rebalance_fixture.tx},
                                     script_pub_key,
                                     m_node.chainman->ActiveChainstate());
    ExpectBlockRejected(*this, block, "bad-blk-shielded-account-registry-size-limit");
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height()), active_height + 1);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_accepts_hybrid_v2_egress_after_settlement_anchor_and_evicts_it_after_reorg, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const ScopedConsensusU32Override restore_maturity{
        consensus.nShieldedSettlementAnchorMaturity,
        consensus.nShieldedSettlementAnchorMaturity};
    consensus.nShieldedSettlementAnchorMaturity = 0;
    const int32_t validation_height = NextShieldedValidationHeight(*this);
    const auto egress_fixture = test::shielded::BuildV2EgressHybridReceiptFixture(
        /*output_count=*/2,
        /*proof_receipt_count=*/1,
        /*required_receipts=*/1,
        &consensus,
        validation_height);
    const auto settlement_anchor_fixture =
        BuildSettlementAnchorHybridFromEgressFixture(egress_fixture, &consensus, validation_height);
    const auto same_block_egress_fixture =
        test::shielded::BuildV2EgressHybridReceiptFixture(
            /*output_count=*/3,
            /*proof_receipt_count=*/1,
            /*required_receipts=*/1,
            &consensus,
            validation_height);
    const auto same_block_settlement_anchor_fixture =
        BuildSettlementAnchorHybridFromEgressFixture(
            same_block_egress_fixture,
            &consensus,
            validation_height);
    const auto egress_tx = MakeTransactionRef(egress_fixture.tx);
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));

    BOOST_REQUIRE_EQUAL(settlement_anchor_fixture.settlement_anchor_digest,
                        std::get<shielded::v2::EgressBatchPayload>(
                            egress_fixture.tx.shielded_bundle.v2_bundle->payload)
                            .settlement_anchor);

    const MempoolAcceptResult result =
        WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(egress_tx, /*test_accept=*/true));

    BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(result.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "bad-shielded-v2-egress-unanchored");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);

    CreateAndProcessBlock({settlement_anchor_fixture.tx}, script_pub_key);
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return m_node.chainman->IsShieldedSettlementAnchorValid(
                              settlement_anchor_fixture.settlement_anchor_digest)));
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs,
                          return !m_node.mempool->exists(GenTxid::Txid(egress_tx->GetHash()))));

    m_node.mempool->PrioritiseTransaction(egress_tx->GetHash(), COIN);
    const MempoolAcceptResult accepted_result =
        WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(egress_tx));

    BOOST_CHECK(accepted_result.m_result_type == MempoolAcceptResult::ResultType::VALID);
    BOOST_CHECK(accepted_result.m_state.IsValid());
    BOOST_CHECK(
        WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(GenTxid::Txid(egress_tx->GetHash()))));

    BlockValidationState invalidate_state;
    BOOST_REQUIRE(
        m_node.chainman->ActiveChainstate().InvalidateBlock(
            invalidate_state, WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip())));
    BOOST_CHECK(invalidate_state.IsValid());
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return !m_node.chainman->IsShieldedSettlementAnchorValid(
                              settlement_anchor_fixture.settlement_anchor_digest)));
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs,
                          return !m_node.mempool->exists(GenTxid::Txid(egress_tx->GetHash()))));

    const MempoolAcceptResult rejected_after_reorg =
        WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(egress_tx, /*test_accept=*/true));
    BOOST_CHECK(rejected_after_reorg.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(rejected_after_reorg.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(rejected_after_reorg.m_state.GetRejectReason(),
                      "bad-shielded-v2-egress-unanchored");

    const CBlock same_block = CreateAndProcessBlock({same_block_settlement_anchor_fixture.tx,
                                                     same_block_egress_fixture.tx},
                                                    script_pub_key);
    BOOST_CHECK_EQUAL(
        same_block.GetHash(),
        WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip()->GetBlockHash()));
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return !m_node.chainman->IsShieldedSettlementAnchorValid(
                              same_block_settlement_anchor_fixture.settlement_anchor_digest)));
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_accepts_multi_receipt_hybrid_v2_egress_after_settlement_anchor_and_evicts_it_after_reorg, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const ScopedConsensusU32Override restore_maturity{
        consensus.nShieldedSettlementAnchorMaturity,
        consensus.nShieldedSettlementAnchorMaturity};
    consensus.nShieldedSettlementAnchorMaturity = 0;
    const int32_t validation_height = NextShieldedValidationHeight(*this);
    const auto egress_fixture = test::shielded::BuildV2EgressHybridReceiptFixture(
        /*output_count=*/2,
        /*proof_receipt_count=*/2,
        /*required_receipts=*/2,
        &consensus,
        validation_height);
    const auto settlement_anchor_fixture =
        BuildSettlementAnchorHybridFromEgressFixture(egress_fixture, &consensus, validation_height);
    const auto same_block_egress_fixture = test::shielded::BuildV2EgressHybridReceiptFixture(
        /*output_count=*/3,
        /*proof_receipt_count=*/2,
        /*required_receipts=*/2,
        &consensus,
        validation_height);
    const auto same_block_settlement_anchor_fixture =
        BuildSettlementAnchorHybridFromEgressFixture(
            same_block_egress_fixture,
            &consensus,
            validation_height);
    const auto egress_tx = MakeTransactionRef(egress_fixture.tx);
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));

    BOOST_REQUIRE_EQUAL(settlement_anchor_fixture.settlement_anchor_digest,
                        std::get<shielded::v2::EgressBatchPayload>(
                            egress_fixture.tx.shielded_bundle.v2_bundle->payload)
                            .settlement_anchor);

    const MempoolAcceptResult result =
        WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(egress_tx, /*test_accept=*/true));

    BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(result.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "bad-shielded-v2-egress-unanchored");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);

    CreateAndProcessBlock({settlement_anchor_fixture.tx}, script_pub_key);
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return m_node.chainman->IsShieldedSettlementAnchorValid(
                              settlement_anchor_fixture.settlement_anchor_digest)));
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs,
                          return !m_node.mempool->exists(GenTxid::Txid(egress_tx->GetHash()))));

    m_node.mempool->PrioritiseTransaction(egress_tx->GetHash(), COIN);
    const MempoolAcceptResult accepted_result =
        WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(egress_tx));

    BOOST_CHECK(accepted_result.m_result_type == MempoolAcceptResult::ResultType::VALID);
    BOOST_CHECK(accepted_result.m_state.IsValid());
    BOOST_CHECK(
        WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(GenTxid::Txid(egress_tx->GetHash()))));

    BlockValidationState invalidate_state;
    BOOST_REQUIRE(
        m_node.chainman->ActiveChainstate().InvalidateBlock(
            invalidate_state, WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip())));
    BOOST_CHECK(invalidate_state.IsValid());
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return !m_node.chainman->IsShieldedSettlementAnchorValid(
                              settlement_anchor_fixture.settlement_anchor_digest)));
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs,
                          return !m_node.mempool->exists(GenTxid::Txid(egress_tx->GetHash()))));

    const MempoolAcceptResult rejected_after_reorg =
        WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(egress_tx, /*test_accept=*/true));
    BOOST_CHECK(rejected_after_reorg.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(rejected_after_reorg.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(rejected_after_reorg.m_state.GetRejectReason(),
                      "bad-shielded-v2-egress-unanchored");

    const CBlock same_block = CreateAndProcessBlock({same_block_settlement_anchor_fixture.tx,
                                                     same_block_egress_fixture.tx},
                                                    script_pub_key);
    BOOST_CHECK_EQUAL(
        same_block.GetHash(),
        WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip()->GetBlockHash()));
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return !m_node.chainman->IsShieldedSettlementAnchorValid(
                              same_block_settlement_anchor_fixture.settlement_anchor_digest)));
}

BOOST_FIXTURE_TEST_CASE(tx_connects_claim_backed_v2_settlement_anchor_and_rewinds_state_after_reorg, TestChain100Setup)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t validation_height = NextShieldedValidationHeight(*this);
    const auto fixture = test::shielded::BuildV2SettlementAnchorClaimFixture(
        /*output_count=*/2,
        &consensus,
        validation_height);
    const auto settlement_anchor_tx = MakeTransactionRef(fixture.tx);
    const auto settlement_anchor_txid = GenTxid::Txid(settlement_anchor_tx->GetHash());
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));

    const MempoolAcceptResult relay_result =
        WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(settlement_anchor_tx, /*test_accept=*/true));
    BOOST_CHECK(relay_result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(relay_result.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(relay_result.m_state.GetRejectReason(), "min relay fee not met");
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs,
                          return !m_node.mempool->exists(settlement_anchor_txid)));

    CreateAndProcessBlock({fixture.tx}, script_pub_key);
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return m_node.chainman->IsShieldedSettlementAnchorValid(
                              fixture.settlement_anchor_digest)));

    BlockValidationState invalidate_state;
    BOOST_REQUIRE(
        m_node.chainman->ActiveChainstate().InvalidateBlock(
            invalidate_state, WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip())));
    BOOST_CHECK(invalidate_state.IsValid());
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return !m_node.chainman->IsShieldedSettlementAnchorValid(
                              fixture.settlement_anchor_digest)));
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs,
                          return !m_node.mempool->exists(settlement_anchor_txid)));
}

BOOST_FIXTURE_TEST_CASE(tx_connects_adapter_backed_v2_settlement_anchor_and_rewinds_state_after_reorg, TestChain100Setup)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t validation_height = NextShieldedValidationHeight(*this);
    const auto fixture = test::shielded::BuildV2SettlementAnchorAdapterClaimFixture(
        /*output_count=*/2,
        &consensus,
        validation_height);
    const auto settlement_anchor_tx = MakeTransactionRef(fixture.tx);
    const auto settlement_anchor_txid = GenTxid::Txid(settlement_anchor_tx->GetHash());
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));

    const MempoolAcceptResult relay_result =
        WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(settlement_anchor_tx, /*test_accept=*/true));
    BOOST_CHECK(relay_result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(relay_result.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(relay_result.m_state.GetRejectReason(), "min relay fee not met");
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs,
                          return !m_node.mempool->exists(settlement_anchor_txid)));

    CreateAndProcessBlock({fixture.tx}, script_pub_key);
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return m_node.chainman->IsShieldedSettlementAnchorValid(
                              fixture.settlement_anchor_digest)));

    BlockValidationState invalidate_state;
    BOOST_REQUIRE(
        m_node.chainman->ActiveChainstate().InvalidateBlock(
            invalidate_state, WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip())));
    BOOST_CHECK(invalidate_state.IsValid());
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return !m_node.chainman->IsShieldedSettlementAnchorValid(
                              fixture.settlement_anchor_digest)));
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs,
                          return !m_node.mempool->exists(settlement_anchor_txid)));
}

BOOST_FIXTURE_TEST_CASE(tx_connects_receipt_adapter_backed_v2_settlement_anchor_and_rewinds_state_after_reorg, TestChain100Setup)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t validation_height = NextShieldedValidationHeight(*this);
    const auto fixture = test::shielded::BuildV2SettlementAnchorAdapterReceiptFixture(
        /*output_count=*/2,
        &consensus,
        validation_height);
    const auto settlement_anchor_tx = MakeTransactionRef(fixture.tx);
    const auto settlement_anchor_txid = GenTxid::Txid(settlement_anchor_tx->GetHash());
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));

    const MempoolAcceptResult relay_result =
        WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(settlement_anchor_tx, /*test_accept=*/true));
    BOOST_CHECK(relay_result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(relay_result.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(relay_result.m_state.GetRejectReason(), "min relay fee not met");
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs,
                          return !m_node.mempool->exists(settlement_anchor_txid)));

    CreateAndProcessBlock({fixture.tx}, script_pub_key);
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return m_node.chainman->IsShieldedSettlementAnchorValid(
                              fixture.settlement_anchor_digest)));

    BlockValidationState invalidate_state;
    BOOST_REQUIRE(
        m_node.chainman->ActiveChainstate().InvalidateBlock(
            invalidate_state, WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip())));
    BOOST_CHECK(invalidate_state.IsValid());
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return !m_node.chainman->IsShieldedSettlementAnchorValid(
                              fixture.settlement_anchor_digest)));
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs,
                          return !m_node.mempool->exists(settlement_anchor_txid)));
}

BOOST_FIXTURE_TEST_CASE(tx_connects_multi_receipt_v2_settlement_anchor_and_rewinds_state_after_reorg, TestChain100Setup)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t validation_height = NextShieldedValidationHeight(*this);
    const auto fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture(
        /*output_count=*/2,
        /*proof_receipt_count=*/2,
        /*required_receipts=*/2,
        &consensus,
        validation_height);
    const auto settlement_anchor_tx = MakeTransactionRef(fixture.tx);
    const auto settlement_anchor_txid = GenTxid::Txid(settlement_anchor_tx->GetHash());
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));

    const MempoolAcceptResult relay_result =
        WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(settlement_anchor_tx, /*test_accept=*/true));
    BOOST_CHECK(relay_result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(relay_result.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(relay_result.m_state.GetRejectReason(), "min relay fee not met");
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs,
                          return !m_node.mempool->exists(settlement_anchor_txid)));

    CreateAndProcessBlock({fixture.tx}, script_pub_key);
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return m_node.chainman->IsShieldedSettlementAnchorValid(
                              fixture.settlement_anchor_digest)));

    BlockValidationState invalidate_state;
    BOOST_REQUIRE(
        m_node.chainman->ActiveChainstate().InvalidateBlock(
            invalidate_state, WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip())));
    BOOST_CHECK(invalidate_state.IsValid());
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return !m_node.chainman->IsShieldedSettlementAnchorValid(
                              fixture.settlement_anchor_digest)));
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs,
                          return !m_node.mempool->exists(settlement_anchor_txid)));
}

BOOST_FIXTURE_TEST_CASE(tx_connects_reserve_bound_v2_settlement_anchor_and_rewinds_state_after_reorg, TestChain100Setup)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t validation_height = NextShieldedValidationHeight(*this);
    auto rebalance_fixture = test::shielded::BuildV2RebalanceFixture(
        /*reserve_output_count=*/1,
        /*settlement_window=*/144,
        &consensus,
        validation_height);
    AttachCoinbaseFeeCarrier(*this, rebalance_fixture.tx, m_coinbase_txns[0]);
    auto fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture(
        /*output_count=*/2,
        /*proof_receipt_count=*/1,
        /*required_receipts=*/1,
        &consensus,
        validation_height);
    test::shielded::AttachSettlementAnchorReserveBinding(
        fixture.tx,
        rebalance_fixture.reserve_deltas,
        rebalance_fixture.manifest_id);
    const auto settlement_anchor_tx = MakeTransactionRef(fixture.tx);
    const auto settlement_anchor_txid = GenTxid::Txid(settlement_anchor_tx->GetHash());
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));

    const MempoolAcceptResult relay_result =
        WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(settlement_anchor_tx, /*test_accept=*/true));
    BOOST_CHECK(relay_result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(relay_result.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(relay_result.m_state.GetRejectReason(), "bad-shielded-v2-settlement-unanchored-manifest");
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs,
                          return !m_node.mempool->exists(settlement_anchor_txid)));

    CreateAndProcessBlock({rebalance_fixture.tx, fixture.tx}, script_pub_key);
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return m_node.chainman->IsShieldedNettingManifestValid(
                              rebalance_fixture.manifest_id)));
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return m_node.chainman->IsShieldedSettlementAnchorValid(
                              fixture.settlement_anchor_digest)));

    BlockValidationState invalidate_state;
    BOOST_REQUIRE(
        m_node.chainman->ActiveChainstate().InvalidateBlock(
            invalidate_state, WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip())));
    BOOST_CHECK(invalidate_state.IsValid());
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return !m_node.chainman->IsShieldedNettingManifestValid(
                              rebalance_fixture.manifest_id)));
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return !m_node.chainman->IsShieldedSettlementAnchorValid(
                              fixture.settlement_anchor_digest)));
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs,
                          return !m_node.mempool->exists(settlement_anchor_txid)));
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_accepts_fee_bearing_v2_rebalance_and_rewinds_state_after_reorg, TestChain100Setup)
{
    auto fixture = test::shielded::BuildV2RebalanceFixture();
    AttachCoinbaseFeeCarrier(*this, fixture.tx, m_coinbase_txns[0]);

    const auto rebalance_tx = MakeTransactionRef(fixture.tx);
    const auto rebalance_txid = GenTxid::Txid(rebalance_tx->GetHash());
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));

    const MempoolAcceptResult accepted_result = WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(rebalance_tx));
    if (accepted_result.m_result_type != MempoolAcceptResult::ResultType::VALID ||
        !accepted_result.m_state.IsValid()) {
        BOOST_FAIL(strprintf("rebalance mempool accept failed result_type=%i reason=%s debug=%s",
                             static_cast<int>(accepted_result.m_result_type),
                             accepted_result.m_state.GetRejectReason(),
                             accepted_result.m_state.GetDebugMessage()));
    }
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(rebalance_txid)));

    CreateAndProcessBlock({fixture.tx}, script_pub_key);
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return !m_node.mempool->exists(rebalance_txid)));
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return m_node.chainman->IsShieldedNettingManifestValid(
                              fixture.manifest_id)));

    BlockValidationState invalidate_state;
    BOOST_REQUIRE(m_node.chainman->ActiveChainstate().InvalidateBlock(
        invalidate_state,
        WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip())));
    BOOST_CHECK(invalidate_state.IsValid());
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return !m_node.chainman->IsShieldedNettingManifestValid(
                              fixture.manifest_id)));

    if (!WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(rebalance_txid))) {
        const MempoolAcceptResult reaccepted_result = WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(rebalance_tx));
        if (reaccepted_result.m_result_type != MempoolAcceptResult::ResultType::VALID ||
            !reaccepted_result.m_state.IsValid()) {
            BOOST_FAIL(strprintf("rebalance mempool reaccept failed result_type=%i reason=%s debug=%s",
                                 static_cast<int>(reaccepted_result.m_result_type),
                                 reaccepted_result.m_state.GetRejectReason(),
                                 reaccepted_result.m_state.GetDebugMessage()));
        }
        BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(rebalance_txid)));
    }
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_accepts_fee_bearing_reserve_bound_v2_settlement_anchor_and_rewinds_state_after_reorg, TestChain100Setup)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t validation_height = NextShieldedValidationHeight(*this);
    auto rebalance_fixture = test::shielded::BuildV2RebalanceFixture(
        /*reserve_output_count=*/1,
        /*settlement_window=*/144,
        &consensus,
        validation_height);
    AttachCoinbaseFeeCarrier(*this, rebalance_fixture.tx, m_coinbase_txns[0]);

    auto fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture(
        /*output_count=*/2,
        /*proof_receipt_count=*/1,
        /*required_receipts=*/1,
        &consensus,
        validation_height);
    test::shielded::AttachSettlementAnchorReserveBinding(
        fixture.tx,
        rebalance_fixture.reserve_deltas,
        rebalance_fixture.manifest_id);
    AttachCoinbaseFeeCarrier(*this, fixture.tx, m_coinbase_txns[1]);

    const auto settlement_anchor_tx = MakeTransactionRef(fixture.tx);
    const auto settlement_anchor_txid = GenTxid::Txid(settlement_anchor_tx->GetHash());
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));

    CreateAndProcessBlock({rebalance_fixture.tx}, script_pub_key);
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return m_node.chainman->IsShieldedNettingManifestValid(
                              rebalance_fixture.manifest_id)));

    const MempoolAcceptResult accepted_result = WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(settlement_anchor_tx));
    if (accepted_result.m_result_type != MempoolAcceptResult::ResultType::VALID ||
        !accepted_result.m_state.IsValid()) {
        BOOST_FAIL(strprintf("settlement-anchor mempool accept failed result_type=%i reason=%s debug=%s",
                             static_cast<int>(accepted_result.m_result_type),
                             accepted_result.m_state.GetRejectReason(),
                             accepted_result.m_state.GetDebugMessage()));
    }
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(settlement_anchor_txid)));

    CreateAndProcessBlock({fixture.tx}, script_pub_key);
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return !m_node.mempool->exists(settlement_anchor_txid)));
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return m_node.chainman->IsShieldedSettlementAnchorValid(
                              fixture.settlement_anchor_digest)));

    BlockValidationState invalidate_state;
    BOOST_REQUIRE(m_node.chainman->ActiveChainstate().InvalidateBlock(
        invalidate_state,
        WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip())));
    BOOST_CHECK(invalidate_state.IsValid());
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return !m_node.chainman->IsShieldedSettlementAnchorValid(
                              fixture.settlement_anchor_digest)));
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return m_node.chainman->IsShieldedNettingManifestValid(
                              rebalance_fixture.manifest_id)));

    if (!WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(settlement_anchor_txid))) {
        const MempoolAcceptResult reaccepted_result = WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(settlement_anchor_tx));
        if (reaccepted_result.m_result_type != MempoolAcceptResult::ResultType::VALID ||
            !reaccepted_result.m_state.IsValid()) {
            BOOST_FAIL(strprintf("settlement-anchor mempool reaccept failed result_type=%i reason=%s debug=%s",
                                 static_cast<int>(reaccepted_result.m_result_type),
                                 reaccepted_result.m_state.GetRejectReason(),
                                 reaccepted_result.m_state.GetDebugMessage()));
        }
        BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(settlement_anchor_txid)));
    }
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_activation_gates_stale_v2_settlement_anchor_netting_manifest, TestChain100Setup)
{
    auto rebalance_fixture = test::shielded::BuildV2RebalanceFixture(/*reserve_output_count=*/1,
                                                                     /*settlement_window=*/1);
    AttachCoinbaseFeeCarrier(*this, rebalance_fixture.tx, m_coinbase_txns[0]);

    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 3;

    auto pre_activation_fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture(
        /*output_count=*/2,
        /*proof_receipt_count=*/1,
        /*required_receipts=*/1,
        &consensus,
        tip_height + 2);
    test::shielded::AttachSettlementAnchorReserveBinding(
        pre_activation_fixture.tx,
        rebalance_fixture.reserve_deltas,
        rebalance_fixture.manifest_id);
    AttachCoinbaseFeeCarrier(*this, pre_activation_fixture.tx, m_coinbase_txns[1]);

    auto post_activation_fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture(
        /*output_count=*/2,
        /*proof_receipt_count=*/1,
        /*required_receipts=*/1,
        &consensus,
        consensus.nShieldedMatRiCTDisableHeight);
    test::shielded::AttachSettlementAnchorReserveBinding(
        post_activation_fixture.tx,
        rebalance_fixture.reserve_deltas,
        rebalance_fixture.manifest_id);
    AttachCoinbaseFeeCarrier(*this, post_activation_fixture.tx, m_coinbase_txns[1]);

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({rebalance_fixture.tx}, script_pub_key);
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return m_node.chainman->IsShieldedNettingManifestValid(
                              rebalance_fixture.manifest_id)));

    const auto pre_activation = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(pre_activation_fixture.tx), /*test_accept=*/true));
    BOOST_CHECK(pre_activation.m_result_type == MempoolAcceptResult::ResultType::VALID);
    BOOST_CHECK(pre_activation.m_state.IsValid());

    CreateAndProcessBlock({}, script_pub_key);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height()),
                      tip_height + 2);

    const auto post_activation = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(post_activation_fixture.tx), /*test_accept=*/true));
    BOOST_CHECK(post_activation.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(post_activation.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(post_activation.m_state.GetRejectReason(),
                      "bad-shielded-v2-settlement-unanchored-manifest");
    BOOST_CHECK(post_activation.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(block_rejects_stale_v2_settlement_anchor_netting_manifest_at_activation, TestChain100Setup)
{
    auto rebalance_fixture = test::shielded::BuildV2RebalanceFixture(/*reserve_output_count=*/1,
                                                                     /*settlement_window=*/1);
    AttachCoinbaseFeeCarrier(*this, rebalance_fixture.tx, m_coinbase_txns[0]);

    auto fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture();
    test::shielded::AttachSettlementAnchorReserveBinding(
        fixture.tx,
        rebalance_fixture.reserve_deltas,
        rebalance_fixture.manifest_id);
    AttachCoinbaseFeeCarrier(*this, fixture.tx, m_coinbase_txns[1]);

    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t active_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = active_height + 2;

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({rebalance_fixture.tx}, script_pub_key);

    const CBlock block = CreateBlock({fixture.tx}, script_pub_key, m_node.chainman->ActiveChainstate());
    ExpectBlockRejected(*this, block, "bad-shielded-v2-settlement-unanchored-manifest");
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height()),
                      active_height + 1);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_rejects_duplicate_v2_rebalance_manifest_after_stale_activation, TestChain100Setup)
{
    auto original_fixture = test::shielded::BuildV2RebalanceFixture(/*reserve_output_count=*/1,
                                                                    /*settlement_window=*/1);
    auto duplicate_fixture = original_fixture;
    AttachCoinbaseFeeCarrier(*this, original_fixture.tx, m_coinbase_txns[0]);
    AttachCoinbaseFeeCarrier(*this, duplicate_fixture.tx, m_coinbase_txns[1]);

    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 3;

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({original_fixture.tx}, script_pub_key);
    CreateAndProcessBlock({}, script_pub_key);

    BOOST_CHECK(!WITH_LOCK(cs_main,
                           return m_node.chainman->IsShieldedNettingManifestValid(
                               original_fixture.manifest_id,
                               tip_height + 3)));

    const auto duplicate_result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(duplicate_fixture.tx), /*test_accept=*/true));
    BOOST_CHECK(duplicate_result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(duplicate_result.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(duplicate_result.m_state.GetRejectReason(),
                      "bad-shielded-v2-rebalance-manifest-duplicate");
    BOOST_CHECK(duplicate_result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_activation_gates_zero_fee_v2_rebalance, TestChain100Setup)
{
    auto fixture = test::shielded::BuildV2RebalanceFixture();
    AttachCoinbaseFeeCarrier(*this, fixture.tx, m_coinbase_txns[0], /*fee=*/0);
    const auto rebalance_tx = MakeTransactionRef(fixture.tx);
    m_node.mempool->PrioritiseTransaction(rebalance_tx->GetHash(), COIN);

    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 2;

    const auto pre_activation = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(rebalance_tx, /*test_accept=*/true));
    BOOST_CHECK(pre_activation.m_result_type == MempoolAcceptResult::ResultType::VALID);
    BOOST_CHECK(pre_activation.m_state.IsValid());

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({}, script_pub_key);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height()),
                      tip_height + 1);

    const auto post_activation = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(rebalance_tx, /*test_accept=*/true));
    BOOST_CHECK(post_activation.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(post_activation.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(post_activation.m_state.GetRejectReason(),
                      "bad-shielded-v2-rebalance-zero-fee");
    BOOST_CHECK(post_activation.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_activation_gates_noncanonical_fee_v2_rebalance, TestChain100Setup)
{
    auto fixture = test::shielded::BuildV2RebalanceFixture();
    AttachCoinbaseFeeCarrier(*this,
                             fixture.tx,
                             m_coinbase_txns[0],
                             shielded::SHIELDED_PRIVACY_FEE_QUANTUM + 1);
    const auto rebalance_tx = MakeTransactionRef(fixture.tx);
    m_node.mempool->PrioritiseTransaction(rebalance_tx->GetHash(), COIN);

    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 2;

    const auto pre_activation = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(rebalance_tx, /*test_accept=*/true));
    BOOST_CHECK(pre_activation.m_result_type == MempoolAcceptResult::ResultType::VALID);
    BOOST_CHECK(pre_activation.m_state.IsValid());

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({}, script_pub_key);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height()),
                      tip_height + 1);

    const auto post_activation = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(rebalance_tx, /*test_accept=*/true));
    BOOST_CHECK(post_activation.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(post_activation.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(post_activation.m_state.GetRejectReason(),
                      "bad-shielded-v2-rebalance-fee-bucket");
    BOOST_CHECK(post_activation.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_activation_gates_legacy_matrict_rebalance_envelope, TestChain100Setup)
{
    auto fixture = test::shielded::BuildV2RebalanceFixture();
    auto& proof_envelope = fixture.tx.shielded_bundle.v2_bundle->header.proof_envelope;
    proof_envelope.proof_kind = shielded::v2::ProofKind::BATCH_MATRICT;
    proof_envelope.membership_proof_kind = shielded::v2::ProofComponentKind::MATRICT;
    proof_envelope.amount_proof_kind = shielded::v2::ProofComponentKind::RANGE;
    proof_envelope.balance_proof_kind = shielded::v2::ProofComponentKind::BALANCE;
    BOOST_REQUIRE(fixture.tx.shielded_bundle.v2_bundle->IsValid());
    AttachCoinbaseFeeCarrier(*this, fixture.tx, m_coinbase_txns[0]);

    const auto rebalance_tx = MakeTransactionRef(fixture.tx);
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 2;

    const auto pre_activation = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(rebalance_tx, /*test_accept=*/true));
    BOOST_CHECK(pre_activation.m_result_type == MempoolAcceptResult::ResultType::VALID);
    BOOST_CHECK(pre_activation.m_state.IsValid());

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({}, script_pub_key);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height()),
                      tip_height + 1);

    const auto post_activation = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(rebalance_tx, /*test_accept=*/true));
    BOOST_CHECK(post_activation.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(post_activation.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(post_activation.m_state.GetRejectReason(), "bad-shielded-matrict-disabled");
    BOOST_CHECK(post_activation.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(block_rejects_zero_fee_v2_rebalance_at_activation, TestChain100Setup)
{
    auto fixture = test::shielded::BuildV2RebalanceFixture();
    AttachCoinbaseFeeCarrier(*this, fixture.tx, m_coinbase_txns[0], /*fee=*/0);

    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t active_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    const ScopedConsensusU32Override restore_maturity{
        consensus.nShieldedSettlementAnchorMaturity,
        consensus.nShieldedSettlementAnchorMaturity};
    consensus.nShieldedMatRiCTDisableHeight = active_height + 1;
    consensus.nShieldedSettlementAnchorMaturity = 0;

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const CBlock block = CreateBlock({fixture.tx}, script_pub_key, m_node.chainman->ActiveChainstate());
    ExpectBlockRejected(*this, block, "bad-shielded-v2-rebalance-zero-fee");
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height()), active_height);
}

BOOST_FIXTURE_TEST_CASE(block_rejects_noncanonical_fee_v2_rebalance_at_activation, TestChain100Setup)
{
    auto fixture = test::shielded::BuildV2RebalanceFixture();
    AttachCoinbaseFeeCarrier(*this,
                             fixture.tx,
                             m_coinbase_txns[0],
                             shielded::SHIELDED_PRIVACY_FEE_QUANTUM + 1);

    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t active_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    const ScopedConsensusU32Override restore_maturity{
        consensus.nShieldedSettlementAnchorMaturity,
        consensus.nShieldedSettlementAnchorMaturity};
    consensus.nShieldedMatRiCTDisableHeight = active_height + 1;
    consensus.nShieldedSettlementAnchorMaturity = 0;

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const CBlock block = CreateBlock({fixture.tx}, script_pub_key, m_node.chainman->ActiveChainstate());
    ExpectBlockRejected(*this, block, "bad-shielded-v2-rebalance-fee-bucket");
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height()), active_height);
}

BOOST_FIXTURE_TEST_CASE(block_rejects_legacy_matrict_rebalance_envelope_at_activation, TestChain100Setup)
{
    auto fixture = test::shielded::BuildV2RebalanceFixture();
    auto& proof_envelope = fixture.tx.shielded_bundle.v2_bundle->header.proof_envelope;
    proof_envelope.proof_kind = shielded::v2::ProofKind::BATCH_MATRICT;
    proof_envelope.membership_proof_kind = shielded::v2::ProofComponentKind::MATRICT;
    proof_envelope.amount_proof_kind = shielded::v2::ProofComponentKind::RANGE;
    proof_envelope.balance_proof_kind = shielded::v2::ProofComponentKind::BALANCE;
    BOOST_REQUIRE(fixture.tx.shielded_bundle.v2_bundle->IsValid());
    AttachCoinbaseFeeCarrier(*this, fixture.tx, m_coinbase_txns[0]);

    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t active_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = active_height + 1;

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const CBlock block = CreateBlock({fixture.tx}, script_pub_key, m_node.chainman->ActiveChainstate());
    ExpectBlockRejected(*this, block, "bad-shielded-matrict-disabled");
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height()), active_height);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_activation_gates_immature_v2_egress_settlement_anchor, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore_height{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    const ScopedConsensusU32Override restore_maturity{
        consensus.nShieldedSettlementAnchorMaturity,
        consensus.nShieldedSettlementAnchorMaturity};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 2;
    consensus.nShieldedSettlementAnchorMaturity = 2;

    const auto settlement_anchor_fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture(
        /*output_count=*/2,
        /*proof_receipt_count=*/1,
        /*required_receipts=*/1,
        &consensus,
        tip_height + 1);
    const auto egress_fixture = test::shielded::BuildV2EgressReceiptFixture(
        /*output_count=*/2,
        &consensus,
        consensus.nShieldedMatRiCTDisableHeight);
    BOOST_REQUIRE_EQUAL(settlement_anchor_fixture.settlement_anchor_digest,
                        std::get<shielded::v2::EgressBatchPayload>(
                            egress_fixture.tx.shielded_bundle.v2_bundle->payload)
                            .settlement_anchor);

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({settlement_anchor_fixture.tx}, script_pub_key);
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return m_node.chainman->IsShieldedSettlementAnchorValid(
                              settlement_anchor_fixture.settlement_anchor_digest)));

    const auto egress_tx = MakeTransactionRef(egress_fixture.tx);
    m_node.mempool->PrioritiseTransaction(egress_tx->GetHash(), COIN);
    const auto immature_result =
        WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(egress_tx, /*test_accept=*/true));
    BOOST_CHECK(immature_result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(immature_result.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(immature_result.m_state.GetRejectReason(),
                      "bad-shielded-v2-egress-immature-anchor");

    CreateAndProcessBlock({}, script_pub_key);
    const auto matured_result =
        WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(egress_tx, /*test_accept=*/true));
    BOOST_CHECK(matured_result.m_result_type == MempoolAcceptResult::ResultType::VALID);
    BOOST_CHECK(matured_result.m_state.IsValid());
}

BOOST_FIXTURE_TEST_CASE(block_rejects_v2_egress_when_settlement_anchor_is_immature_after_activation, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore_height{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    const ScopedConsensusU32Override restore_maturity{
        consensus.nShieldedSettlementAnchorMaturity,
        consensus.nShieldedSettlementAnchorMaturity};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 2;
    consensus.nShieldedSettlementAnchorMaturity = 2;

    const auto settlement_anchor_fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture(
        /*output_count=*/2,
        /*proof_receipt_count=*/1,
        /*required_receipts=*/1,
        &consensus,
        tip_height + 1);
    const auto egress_fixture = test::shielded::BuildV2EgressReceiptFixture(
        /*output_count=*/2,
        &consensus,
        consensus.nShieldedMatRiCTDisableHeight);
    BOOST_REQUIRE_EQUAL(settlement_anchor_fixture.settlement_anchor_digest,
                        std::get<shielded::v2::EgressBatchPayload>(
                            egress_fixture.tx.shielded_bundle.v2_bundle->payload)
                            .settlement_anchor);

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({settlement_anchor_fixture.tx}, script_pub_key);
    const CBlock immature_block =
        CreateBlock({egress_fixture.tx}, script_pub_key, m_node.chainman->ActiveChainstate());
    ExpectBlockRejected(*this, immature_block, "bad-shielded-v2-egress-immature-anchor");
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height()), tip_height + 1);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_rejects_reused_v2_egress_settlement_anchor_after_single_use_activation, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t active_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight =
        active_height + static_cast<int32_t>(consensus.nShieldedSettlementAnchorMaturity) + 1;

    const auto settlement_anchor_fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture(
        /*output_count=*/2,
        /*proof_receipt_count=*/1,
        /*required_receipts=*/1,
        &consensus,
        active_height + 1);
    const auto egress_fixture = test::shielded::BuildV2EgressReceiptFixture(
        /*output_count=*/2,
        &consensus,
        consensus.nShieldedMatRiCTDisableHeight);
    BOOST_REQUIRE_EQUAL(settlement_anchor_fixture.settlement_anchor_digest,
                        std::get<shielded::v2::EgressBatchPayload>(
                            egress_fixture.tx.shielded_bundle.v2_bundle->payload)
                            .settlement_anchor);

    CMutableTransaction reused_egress = egress_fixture.tx;
    reused_egress.nLockTime += 1;
    const auto egress_tx = MakeTransactionRef(egress_fixture.tx);
    const auto reused_egress_tx = MakeTransactionRef(reused_egress);
    BOOST_REQUIRE(egress_tx->GetHash() != reused_egress_tx->GetHash());

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({settlement_anchor_fixture.tx}, script_pub_key);
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return m_node.chainman->IsShieldedSettlementAnchorValid(
                              settlement_anchor_fixture.settlement_anchor_digest)));
    for (uint32_t i = 1; i < consensus.nShieldedSettlementAnchorMaturity; ++i) {
        CreateAndProcessBlock({}, script_pub_key);
    }

    m_node.mempool->PrioritiseTransaction(egress_tx->GetHash(), COIN);
    const auto first_accept = WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(egress_tx));
    BOOST_CHECK(first_accept.m_result_type == MempoolAcceptResult::ResultType::VALID);
    BOOST_CHECK(first_accept.m_state.IsValid());

    m_node.mempool->PrioritiseTransaction(reused_egress_tx->GetHash(), COIN);
    const auto second_accept =
        WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(reused_egress_tx, /*test_accept=*/true));
    BOOST_CHECK(second_accept.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(second_accept.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(second_accept.m_state.GetRejectReason(),
                      "bad-shielded-v2-egress-anchor-mempool-conflict");
    BOOST_CHECK(second_accept.m_state.GetResult() == TxValidationResult::TX_MEMPOOL_POLICY);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_accepts_v2_ingress_and_rewinds_state_after_reorg, TestChain100Setup)
{
    const auto fixture = BuildV2IngressChainFixture(*this);
    const auto ingress_tx = MakeTransactionRef(fixture.built.tx);
    const auto ingress_txid = GenTxid::Txid(ingress_tx->GetHash());
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const auto* bundle = fixture.built.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_REQUIRE(shielded::v2::BundleHasSemanticFamily(*bundle,
                                                        TransactionFamily::V2_INGRESS_BATCH));
    const auto& payload = std::get<shielded::v2::IngressBatchPayload>(bundle->payload);
    BOOST_REQUIRE_EQUAL(payload.consumed_spends.size(), 1U);
    BOOST_CHECK_EQUAL(payload.consumed_spends.front().nullifier, fixture.input_nullifiers.front());
    CheckIngressValueBalances(fixture);
    const int64_t policy_weight = GetShieldedPolicyWeight(*ingress_tx);
    BOOST_CHECK_GT(policy_weight, 0);
    BOOST_CHECK_LE(policy_weight, MAX_STANDARD_INGRESS_SHIELDED_POLICY_WEIGHT);

    EnsureIngressAccountRegistryAnchorTracked(*this, fixture);
    const MempoolAcceptResult accepted_result = WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(ingress_tx));
    if (accepted_result.m_result_type != MempoolAcceptResult::ResultType::VALID ||
        !accepted_result.m_state.IsValid()) {
        BOOST_FAIL(strprintf("ingress mempool accept failed result_type=%i reason=%s debug=%s policy_weight=%lld",
                             static_cast<int>(accepted_result.m_result_type),
                             accepted_result.m_state.GetRejectReason(),
                             accepted_result.m_state.GetDebugMessage(),
                             static_cast<long long>(policy_weight)));
    }
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(ingress_txid)));

    const uint64_t nullifier_count_before_block =
        WITH_LOCK(cs_main, return m_node.chainman->GetShieldedNullifierCount());
    CreateAndProcessBlock({fixture.built.tx}, script_pub_key);

    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return !m_node.mempool->exists(ingress_txid)));
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->GetShieldedNullifierCount()),
                      nullifier_count_before_block + 1);
    BOOST_CHECK(WITH_LOCK(cs_main, return m_node.chainman->IsShieldedNullifierSpent(fixture.input_nullifiers.front())));
    BOOST_CHECK_EQUAL(
        WITH_LOCK(cs_main, return m_node.chainman->GetShieldedMerkleTree().Size()),
        fixture.tree_before.Size() + 1);
    BOOST_CHECK(WITH_LOCK(cs_main, {
        const auto commitment = m_node.chainman->GetShieldedMerkleTree().CommitmentAt(fixture.tree_before.Size());
        return commitment.has_value() && *commitment == fixture.reserve_commitments.front();
    }));

    BlockValidationState invalidate_state;
    BOOST_REQUIRE(m_node.chainman->ActiveChainstate().InvalidateBlock(
        invalidate_state,
        WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip())));
    BOOST_CHECK(invalidate_state.IsValid());

    BOOST_CHECK(WITH_LOCK(cs_main, return !m_node.chainman->IsShieldedNullifierSpent(fixture.input_nullifiers.front())));
    BOOST_CHECK_EQUAL(
        WITH_LOCK(cs_main, return m_node.chainman->GetShieldedMerkleTree().Size()),
        fixture.tree_before.Size());
    BOOST_CHECK_EQUAL(
        WITH_LOCK(cs_main, return m_node.chainman->GetShieldedMerkleTree().Root()),
        fixture.spend_anchor);
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return !m_node.chainman->GetShieldedMerkleTree().CommitmentAt(
                                      fixture.tree_before.Size())
                                      .has_value()));

    if (!WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(ingress_txid))) {
        EnsureIngressAccountRegistryAnchorTracked(*this, fixture);
        const MempoolAcceptResult reaccepted_result = WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(ingress_tx));
        if (reaccepted_result.m_result_type != MempoolAcceptResult::ResultType::VALID ||
            !reaccepted_result.m_state.IsValid()) {
            BOOST_FAIL(strprintf("ingress mempool reaccept failed result_type=%i reason=%s debug=%s policy_weight=%lld",
                                 static_cast<int>(reaccepted_result.m_result_type),
                                 reaccepted_result.m_state.GetRejectReason(),
                                 reaccepted_result.m_state.GetDebugMessage(),
                                 static_cast<long long>(policy_weight)));
        }
        BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(ingress_txid)));
    }
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_accepts_signed_v2_ingress_and_rewinds_state_after_reorg, TestChain100Setup)
{
    const auto fixture = BuildV2IngressChainFixture(*this,
                                                    /*spend_input_count=*/1,
                                                    /*reserve_output_count=*/1,
                                                    /*ingress_leaf_count=*/2,
                                                    IngressSettlementWitnessKind::SIGNED_ONLY);
    const auto ingress_tx = MakeTransactionRef(fixture.built.tx);
    const auto ingress_txid = GenTxid::Txid(ingress_tx->GetHash());
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const auto* bundle = fixture.built.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_REQUIRE(shielded::v2::BundleHasSemanticFamily(*bundle,
                                                        TransactionFamily::V2_INGRESS_BATCH));
    const auto& payload = std::get<shielded::v2::IngressBatchPayload>(bundle->payload);
    BOOST_REQUIRE_EQUAL(payload.consumed_spends.size(), 1U);
    BOOST_REQUIRE_EQUAL(fixture.input_nullifiers.size(), 1U);
    BOOST_CHECK_EQUAL(payload.consumed_spends.front().nullifier, fixture.input_nullifiers.front());
    CheckIngressValueBalances(fixture);
    BOOST_REQUIRE(fixture.built.witness.header.statement.verifier_set.IsValid());
    BOOST_CHECK(!fixture.built.witness.header.statement.proof_policy.IsValid());

    const int64_t policy_weight = GetShieldedPolicyWeight(*ingress_tx);
    BOOST_CHECK_GT(policy_weight, 0);
    BOOST_CHECK_LE(policy_weight, MAX_STANDARD_INGRESS_SHIELDED_POLICY_WEIGHT);

    EnsureIngressAccountRegistryAnchorTracked(*this, fixture);
    const MempoolAcceptResult accepted_result = WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(ingress_tx));
    if (accepted_result.m_result_type != MempoolAcceptResult::ResultType::VALID ||
        !accepted_result.m_state.IsValid()) {
        BOOST_FAIL(strprintf("signed ingress mempool accept failed result_type=%i reason=%s debug=%s policy_weight=%lld",
                             static_cast<int>(accepted_result.m_result_type),
                             accepted_result.m_state.GetRejectReason(),
                             accepted_result.m_state.GetDebugMessage(),
                             static_cast<long long>(policy_weight)));
    }
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(ingress_txid)));

    const uint64_t nullifier_count_before_block =
        WITH_LOCK(cs_main, return m_node.chainman->GetShieldedNullifierCount());
    CreateAndProcessBlock({fixture.built.tx}, script_pub_key);

    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return !m_node.mempool->exists(ingress_txid)));
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->GetShieldedNullifierCount()),
                      nullifier_count_before_block + 1);
    BOOST_CHECK(WITH_LOCK(cs_main, return m_node.chainman->IsShieldedNullifierSpent(fixture.input_nullifiers.front())));
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->GetShieldedMerkleTree().Size()),
                      fixture.tree_before.Size() + 1);
    BOOST_CHECK(WITH_LOCK(cs_main, {
        const auto commitment = m_node.chainman->GetShieldedMerkleTree().CommitmentAt(fixture.tree_before.Size());
        return commitment.has_value() && *commitment == fixture.reserve_commitments.front();
    }));

    BlockValidationState invalidate_state;
    BOOST_REQUIRE(m_node.chainman->ActiveChainstate().InvalidateBlock(
        invalidate_state,
        WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip())));
    BOOST_CHECK(invalidate_state.IsValid());

    BOOST_CHECK(WITH_LOCK(cs_main, return !m_node.chainman->IsShieldedNullifierSpent(fixture.input_nullifiers.front())));
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->GetShieldedMerkleTree().Size()),
                      fixture.tree_before.Size());
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->GetShieldedMerkleTree().Root()),
                      fixture.spend_anchor);
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return !m_node.chainman->GetShieldedMerkleTree().CommitmentAt(
                                      fixture.tree_before.Size())
                                      .has_value()));

    if (!WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(ingress_txid))) {
        EnsureIngressAccountRegistryAnchorTracked(*this, fixture);
        const MempoolAcceptResult reaccepted_result = WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(ingress_tx));
        if (reaccepted_result.m_result_type != MempoolAcceptResult::ResultType::VALID ||
            !reaccepted_result.m_state.IsValid()) {
            BOOST_FAIL(strprintf("signed ingress mempool reaccept failed result_type=%i reason=%s debug=%s policy_weight=%lld",
                                 static_cast<int>(reaccepted_result.m_result_type),
                                 reaccepted_result.m_state.GetRejectReason(),
                                 reaccepted_result.m_state.GetDebugMessage(),
                                 static_cast<long long>(policy_weight)));
        }
        BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(ingress_txid)));
    }
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_accepts_scaled_v2_ingress_and_rewinds_state_after_reorg, TestChain100Setup)
{
    const auto fixture = BuildV2IngressChainFixture(*this,
                                                    /*spend_input_count=*/2,
                                                    /*reserve_output_count=*/2,
                                                    /*ingress_leaf_count=*/3);
    const auto ingress_tx = MakeTransactionRef(fixture.built.tx);
    const auto ingress_txid = GenTxid::Txid(ingress_tx->GetHash());
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const auto* bundle = fixture.built.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_REQUIRE(shielded::v2::BundleHasSemanticFamily(*bundle,
                                                        TransactionFamily::V2_INGRESS_BATCH));
    const auto& payload = std::get<shielded::v2::IngressBatchPayload>(bundle->payload);
    BOOST_REQUIRE_EQUAL(payload.consumed_spends.size(), 2U);
    BOOST_REQUIRE_EQUAL(payload.reserve_outputs.size(), 2U);
    BOOST_REQUIRE_EQUAL(payload.ingress_leaves.size(), 3U);
    BOOST_REQUIRE_EQUAL(fixture.input_nullifiers.size(), 2U);
    BOOST_REQUIRE_EQUAL(fixture.reserve_commitments.size(), 2U);
    BOOST_CHECK(std::equal(payload.consumed_spends.begin(),
                           payload.consumed_spends.end(),
                           fixture.input_nullifiers.begin(),
                           [](const auto& spend, const auto& nullifier) {
                               return spend.nullifier == nullifier;
                           }));
    CheckIngressValueBalances(fixture);
    const size_t serialized_size = ::GetSerializeSize(TX_WITH_WITNESS(*ingress_tx));
    BOOST_CHECK_GT(serialized_size, 60'000U);
    BOOST_CHECK_LE(serialized_size, m_node.chainman->GetConsensus().nMaxShieldedTxSize);

    const int64_t policy_weight = GetShieldedPolicyWeight(*ingress_tx);
    BOOST_CHECK_GT(policy_weight, 0);
    BOOST_CHECK_LE(policy_weight, MAX_STANDARD_INGRESS_SHIELDED_POLICY_WEIGHT);

    EnsureIngressAccountRegistryAnchorTracked(*this, fixture);
    const MempoolAcceptResult accepted_result = WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(ingress_tx));
    if (accepted_result.m_result_type != MempoolAcceptResult::ResultType::VALID ||
        !accepted_result.m_state.IsValid()) {
        BOOST_FAIL(strprintf("scaled ingress mempool accept failed result_type=%i reason=%s debug=%s policy_weight=%lld",
                             static_cast<int>(accepted_result.m_result_type),
                             accepted_result.m_state.GetRejectReason(),
                             accepted_result.m_state.GetDebugMessage(),
                             static_cast<long long>(policy_weight)));
    }
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(ingress_txid)));

    const uint64_t nullifier_count_before_block =
        WITH_LOCK(cs_main, return m_node.chainman->GetShieldedNullifierCount());
    CreateAndProcessBlock({fixture.built.tx}, script_pub_key);

    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return !m_node.mempool->exists(ingress_txid)));
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->GetShieldedNullifierCount()),
                      nullifier_count_before_block + fixture.input_nullifiers.size());
    for (const auto& nullifier : fixture.input_nullifiers) {
        BOOST_CHECK(WITH_LOCK(cs_main, return m_node.chainman->IsShieldedNullifierSpent(nullifier)));
    }
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->GetShieldedMerkleTree().Size()),
                      fixture.tree_before.Size() + fixture.reserve_commitments.size());
    for (size_t output_idx = 0; output_idx < fixture.reserve_commitments.size(); ++output_idx) {
        BOOST_CHECK(WITH_LOCK(cs_main, {
            const auto commitment = m_node.chainman->GetShieldedMerkleTree().CommitmentAt(
                fixture.tree_before.Size() + output_idx);
            return commitment.has_value() && *commitment == fixture.reserve_commitments[output_idx];
        }));
    }

    BlockValidationState invalidate_state;
    BOOST_REQUIRE(m_node.chainman->ActiveChainstate().InvalidateBlock(
        invalidate_state,
        WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip())));
    BOOST_CHECK(invalidate_state.IsValid());

    for (const auto& nullifier : fixture.input_nullifiers) {
        BOOST_CHECK(WITH_LOCK(cs_main, return !m_node.chainman->IsShieldedNullifierSpent(nullifier)));
    }
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->GetShieldedMerkleTree().Size()),
                      fixture.tree_before.Size());
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->GetShieldedMerkleTree().Root()),
                      fixture.spend_anchor);
    for (size_t output_idx = 0; output_idx < fixture.reserve_commitments.size(); ++output_idx) {
        BOOST_CHECK(WITH_LOCK(cs_main, {
            return !m_node.chainman->GetShieldedMerkleTree().CommitmentAt(
                        fixture.tree_before.Size() + output_idx)
                        .has_value();
        }));
    }

    if (!WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(ingress_txid))) {
        EnsureIngressAccountRegistryAnchorTracked(*this, fixture);
        const MempoolAcceptResult reaccepted_result = WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(ingress_tx));
        if (reaccepted_result.m_result_type != MempoolAcceptResult::ResultType::VALID ||
            !reaccepted_result.m_state.IsValid()) {
            BOOST_FAIL(strprintf("scaled ingress mempool reaccept failed result_type=%i reason=%s debug=%s policy_weight=%lld",
                                 static_cast<int>(reaccepted_result.m_result_type),
                                 reaccepted_result.m_state.GetRejectReason(),
                                 reaccepted_result.m_state.GetDebugMessage(),
                                 static_cast<long long>(policy_weight)));
        }
        BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(ingress_txid)));
    }
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_accepts_hybrid_v2_ingress_and_rewinds_state_after_reorg, TestChain100Setup)
{
    const auto fixture = BuildV2IngressChainFixture(*this,
                                                    /*spend_input_count=*/2,
                                                    /*reserve_output_count=*/2,
                                                    /*ingress_leaf_count=*/3,
                                                    IngressSettlementWitnessKind::HYBRID);
    const auto ingress_tx = MakeTransactionRef(fixture.built.tx);
    const auto ingress_txid = GenTxid::Txid(ingress_tx->GetHash());
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const auto* bundle = fixture.built.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_REQUIRE(shielded::v2::BundleHasSemanticFamily(*bundle,
                                                        TransactionFamily::V2_INGRESS_BATCH));
    const auto& payload = std::get<shielded::v2::IngressBatchPayload>(bundle->payload);
    BOOST_REQUIRE_EQUAL(payload.consumed_spends.size(), 2U);
    BOOST_REQUIRE_EQUAL(payload.reserve_outputs.size(), 2U);
    BOOST_REQUIRE_EQUAL(payload.ingress_leaves.size(), 3U);
    BOOST_REQUIRE_EQUAL(fixture.input_nullifiers.size(), 2U);
    BOOST_REQUIRE_EQUAL(fixture.reserve_commitments.size(), 2U);
    BOOST_CHECK(std::equal(payload.consumed_spends.begin(),
                           payload.consumed_spends.end(),
                           fixture.input_nullifiers.begin(),
                           [](const auto& spend, const auto& nullifier) {
                               return spend.nullifier == nullifier;
                           }));
    CheckIngressValueBalances(fixture);
    BOOST_REQUIRE(fixture.built.witness.header.statement.verifier_set.IsValid());
    BOOST_REQUIRE(fixture.built.witness.header.statement.proof_policy.IsValid());

    const size_t serialized_size = ::GetSerializeSize(TX_WITH_WITNESS(*ingress_tx));
    BOOST_CHECK_GT(serialized_size, 70'000U);
    BOOST_CHECK_LE(serialized_size, m_node.chainman->GetConsensus().nMaxShieldedTxSize);

    const int64_t policy_weight = GetShieldedPolicyWeight(*ingress_tx);
    BOOST_CHECK_GT(policy_weight, 0);
    BOOST_CHECK_LE(policy_weight, MAX_STANDARD_INGRESS_SHIELDED_POLICY_WEIGHT);

    EnsureIngressAccountRegistryAnchorTracked(*this, fixture);
    const MempoolAcceptResult accepted_result = WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(ingress_tx));
    if (accepted_result.m_result_type != MempoolAcceptResult::ResultType::VALID ||
        !accepted_result.m_state.IsValid()) {
        BOOST_FAIL(strprintf("hybrid ingress mempool accept failed result_type=%i reason=%s debug=%s policy_weight=%lld",
                             static_cast<int>(accepted_result.m_result_type),
                             accepted_result.m_state.GetRejectReason(),
                             accepted_result.m_state.GetDebugMessage(),
                             static_cast<long long>(policy_weight)));
    }
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(ingress_txid)));

    const uint64_t nullifier_count_before_block =
        WITH_LOCK(cs_main, return m_node.chainman->GetShieldedNullifierCount());
    CreateAndProcessBlock({fixture.built.tx}, script_pub_key);

    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return !m_node.mempool->exists(ingress_txid)));
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->GetShieldedNullifierCount()),
                      nullifier_count_before_block + fixture.input_nullifiers.size());
    for (const auto& nullifier : fixture.input_nullifiers) {
        BOOST_CHECK(WITH_LOCK(cs_main, return m_node.chainman->IsShieldedNullifierSpent(nullifier)));
    }
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->GetShieldedMerkleTree().Size()),
                      fixture.tree_before.Size() + fixture.reserve_commitments.size());
    for (size_t output_idx = 0; output_idx < fixture.reserve_commitments.size(); ++output_idx) {
        BOOST_CHECK(WITH_LOCK(cs_main, {
            const auto commitment = m_node.chainman->GetShieldedMerkleTree().CommitmentAt(
                fixture.tree_before.Size() + output_idx);
            return commitment.has_value() && *commitment == fixture.reserve_commitments[output_idx];
        }));
    }

    BlockValidationState invalidate_state;
    BOOST_REQUIRE(m_node.chainman->ActiveChainstate().InvalidateBlock(
        invalidate_state,
        WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip())));
    BOOST_CHECK(invalidate_state.IsValid());

    for (const auto& nullifier : fixture.input_nullifiers) {
        BOOST_CHECK(WITH_LOCK(cs_main, return !m_node.chainman->IsShieldedNullifierSpent(nullifier)));
    }
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->GetShieldedMerkleTree().Size()),
                      fixture.tree_before.Size());
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->GetShieldedMerkleTree().Root()),
                      fixture.spend_anchor);
    for (size_t output_idx = 0; output_idx < fixture.reserve_commitments.size(); ++output_idx) {
        BOOST_CHECK(WITH_LOCK(cs_main, {
            return !m_node.chainman->GetShieldedMerkleTree().CommitmentAt(
                        fixture.tree_before.Size() + output_idx)
                        .has_value();
        }));
    }

    if (!WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(ingress_txid))) {
        EnsureIngressAccountRegistryAnchorTracked(*this, fixture);
        const MempoolAcceptResult reaccepted_result = WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(ingress_tx));
        if (reaccepted_result.m_result_type != MempoolAcceptResult::ResultType::VALID ||
            !reaccepted_result.m_state.IsValid()) {
            BOOST_FAIL(strprintf("hybrid ingress mempool reaccept failed result_type=%i reason=%s debug=%s policy_weight=%lld",
                                 static_cast<int>(reaccepted_result.m_result_type),
                                 reaccepted_result.m_state.GetRejectReason(),
                                 reaccepted_result.m_state.GetDebugMessage(),
                                 static_cast<long long>(policy_weight)));
        }
        BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(ingress_txid)));
    }
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_accepts_multishard_v2_ingress_and_rewinds_state_after_reorg, TestChain100Setup)
{
    std::vector<V2IngressLeafInput> ingress_leaves;
    ingress_leaves.reserve(8);
    constexpr CAmount kIngressLeafFee{700'000};
    for (size_t leaf_idx = 0; leaf_idx < 8; ++leaf_idx) {
        ingress_leaves.push_back(
            MakeIngressLeaf(static_cast<unsigned char>(0xb1 + leaf_idx * 0x10),
                            /*amount=*/80'000,
                            /*fee=*/kIngressLeafFee));
    }

    const std::vector<CAmount> reserve_values{400'000, 400'000};
    const CAmount ingress_total = std::accumulate(
        ingress_leaves.begin(),
        ingress_leaves.end(),
        CAmount{0},
        [](CAmount total, const V2IngressLeafInput& leaf) {
            return total + leaf.bridge_leaf.amount + leaf.fee;
        });
    const auto fixture = BuildV2IngressChainFixture(*this,
                                                    /*input_values=*/DistributeIngressInputValues(
                                                        std::accumulate(reserve_values.begin(), reserve_values.end(), CAmount{0}) +
                                                            ingress_total,
                                                        /*count=*/2),
                                                    reserve_values,
                                                    std::move(ingress_leaves));
    const auto ingress_tx = MakeTransactionRef(fixture.built.tx);
    const auto ingress_txid = GenTxid::Txid(ingress_tx->GetHash());
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const auto* bundle = fixture.built.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_REQUIRE(shielded::v2::BundleHasSemanticFamily(*bundle,
                                                        TransactionFamily::V2_INGRESS_BATCH));
    const auto& payload = std::get<shielded::v2::IngressBatchPayload>(bundle->payload);
    BOOST_REQUIRE_EQUAL(payload.consumed_spends.size(), 2U);
    BOOST_REQUIRE_EQUAL(payload.reserve_outputs.size(), 2U);
    BOOST_REQUIRE_EQUAL(payload.ingress_leaves.size(), 8U);
    BOOST_REQUIRE_EQUAL(bundle->proof_shards.size(), 2U);
    BOOST_REQUIRE_EQUAL(bundle->proof_shards[0].first_leaf_index, 0U);
    BOOST_REQUIRE_GT(bundle->proof_shards[0].leaf_count, 0U);
    BOOST_REQUIRE_GT(bundle->proof_shards[1].leaf_count, 0U);
    BOOST_REQUIRE_EQUAL(bundle->proof_shards[1].first_leaf_index,
                        bundle->proof_shards[0].first_leaf_index + bundle->proof_shards[0].leaf_count);
    BOOST_REQUIRE_EQUAL(bundle->proof_shards[0].leaf_count + bundle->proof_shards[1].leaf_count,
                        payload.ingress_leaves.size());
    BOOST_REQUIRE_EQUAL(fixture.input_nullifiers.size(), 2U);
    BOOST_REQUIRE_EQUAL(fixture.reserve_commitments.size(), 2U);
    BOOST_CHECK(std::equal(payload.consumed_spends.begin(),
                           payload.consumed_spends.end(),
                           fixture.input_nullifiers.begin(),
                           [](const auto& spend, const auto& nullifier) {
                               return spend.nullifier == nullifier;
                           }));
    CheckIngressValueBalances(fixture);

    const size_t serialized_size = ::GetSerializeSize(TX_WITH_WITNESS(*ingress_tx));
    const int64_t policy_weight = GetShieldedPolicyWeight(*ingress_tx);
    BOOST_CHECK_GT(serialized_size, 80'000U);
    BOOST_CHECK_LE(serialized_size, m_node.chainman->GetConsensus().nMaxShieldedTxSize);
    BOOST_CHECK_GT(policy_weight, 0);
    BOOST_CHECK_LE(policy_weight, MAX_STANDARD_INGRESS_SHIELDED_POLICY_WEIGHT);

    EnsureIngressAccountRegistryAnchorTracked(*this, fixture);
    const MempoolAcceptResult accepted_result = WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(ingress_tx));
    if (accepted_result.m_result_type != MempoolAcceptResult::ResultType::VALID ||
        !accepted_result.m_state.IsValid()) {
        BOOST_FAIL(strprintf("multishard ingress mempool accept failed result_type=%i reason=%s debug=%s serialized_size=%u policy_weight=%lld",
                             static_cast<int>(accepted_result.m_result_type),
                             accepted_result.m_state.GetRejectReason(),
                             accepted_result.m_state.GetDebugMessage(),
                             static_cast<unsigned int>(serialized_size),
                             static_cast<long long>(policy_weight)));
    }
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(ingress_txid)));

    const uint64_t nullifier_count_before_block =
        WITH_LOCK(cs_main, return m_node.chainman->GetShieldedNullifierCount());
    CreateAndProcessBlock({fixture.built.tx}, script_pub_key);

    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return !m_node.mempool->exists(ingress_txid)));
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->GetShieldedNullifierCount()),
                      nullifier_count_before_block + fixture.input_nullifiers.size());
    for (const auto& nullifier : fixture.input_nullifiers) {
        BOOST_CHECK(WITH_LOCK(cs_main, return m_node.chainman->IsShieldedNullifierSpent(nullifier)));
    }
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->GetShieldedMerkleTree().Size()),
                      fixture.tree_before.Size() + fixture.reserve_commitments.size());
    for (size_t output_idx = 0; output_idx < fixture.reserve_commitments.size(); ++output_idx) {
        BOOST_CHECK(WITH_LOCK(cs_main, {
            const auto commitment = m_node.chainman->GetShieldedMerkleTree().CommitmentAt(
                fixture.tree_before.Size() + output_idx);
            return commitment.has_value() && *commitment == fixture.reserve_commitments[output_idx];
        }));
    }

    BlockValidationState invalidate_state;
    BOOST_REQUIRE(m_node.chainman->ActiveChainstate().InvalidateBlock(
        invalidate_state,
        WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip())));
    BOOST_CHECK(invalidate_state.IsValid());

    for (const auto& nullifier : fixture.input_nullifiers) {
        BOOST_CHECK(WITH_LOCK(cs_main, return !m_node.chainman->IsShieldedNullifierSpent(nullifier)));
    }
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->GetShieldedMerkleTree().Size()),
                      fixture.tree_before.Size());
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->GetShieldedMerkleTree().Root()),
                      fixture.spend_anchor);
    BOOST_CHECK(WITH_LOCK(cs_main,
                          return !m_node.chainman->GetShieldedMerkleTree().CommitmentAt(
                                      fixture.tree_before.Size())
                                      .has_value()));

    if (!WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(ingress_txid))) {
        EnsureIngressAccountRegistryAnchorTracked(*this, fixture);
        const MempoolAcceptResult reaccepted_result = WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(ingress_tx));
        if (reaccepted_result.m_result_type != MempoolAcceptResult::ResultType::VALID ||
            !reaccepted_result.m_state.IsValid()) {
            BOOST_FAIL(strprintf("multishard ingress mempool reaccept failed result_type=%i reason=%s debug=%s serialized_size=%u policy_weight=%lld",
                                 static_cast<int>(reaccepted_result.m_result_type),
                                 reaccepted_result.m_state.GetRejectReason(),
                                 reaccepted_result.m_state.GetDebugMessage(),
                                 static_cast<unsigned int>(serialized_size),
                                 static_cast<long long>(policy_weight)));
        }
        BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(ingress_txid)));
    }
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_accepts_v2_send_after_direct_send_seed_and_rewinds_state_after_reorg, TestChain100Setup)
{
    const auto fixture = BuildV2DirectSendChainFixture(*this);
    const auto send_tx = MakeTransactionRef(fixture.built.tx);
    const auto send_txid = GenTxid::Txid(send_tx->GetHash());
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const auto* bundle = fixture.built.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_REQUIRE(shielded::v2::BundleHasSemanticFamily(*bundle, TransactionFamily::V2_SEND));
    const auto& payload = std::get<shielded::v2::SendPayload>(bundle->payload);
    BOOST_REQUIRE_EQUAL(payload.spends.size(), 1U);
    BOOST_REQUIRE_EQUAL(payload.outputs.size(), 1U);
    BOOST_CHECK_EQUAL(payload.account_registry_anchor, fixture.account_registry_anchor);
    BOOST_CHECK_EQUAL(payload.spends.front().nullifier, fixture.input_nullifier);
    BOOST_CHECK_EQUAL(payload.outputs.front().note_commitment, fixture.output_commitment);

    const int64_t policy_weight = GetShieldedPolicyWeight(*send_tx);
    BOOST_CHECK_GT(policy_weight, 0);
    BOOST_CHECK_LE(policy_weight, MAX_STANDARD_SHIELDED_POLICY_WEIGHT);

    const MempoolAcceptResult accepted_result =
        WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(send_tx));
    if (accepted_result.m_result_type != MempoolAcceptResult::ResultType::VALID ||
        !accepted_result.m_state.IsValid()) {
        BOOST_FAIL(strprintf("v2 send mempool accept failed result_type=%i reason=%s debug=%s policy_weight=%lld",
                             static_cast<int>(accepted_result.m_result_type),
                             accepted_result.m_state.GetRejectReason(),
                             accepted_result.m_state.GetDebugMessage(),
                             static_cast<long long>(policy_weight)));
    }
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(send_txid)));

    const uint64_t nullifier_count_before_block =
        WITH_LOCK(cs_main, return m_node.chainman->GetShieldedNullifierCount());
    CreateAndProcessBlock({fixture.built.tx}, script_pub_key);

    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return !m_node.mempool->exists(send_txid)));
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->GetShieldedNullifierCount()),
                      nullifier_count_before_block + 1);
    BOOST_CHECK(WITH_LOCK(cs_main, return m_node.chainman->IsShieldedNullifierSpent(fixture.input_nullifier)));
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->GetShieldedMerkleTree().Size()),
                      fixture.tree_before.Size() + 1);
    BOOST_CHECK(WITH_LOCK(cs_main, {
        const auto commitment = m_node.chainman->GetShieldedMerkleTree().CommitmentAt(
            fixture.tree_before.Size());
        return commitment.has_value() && *commitment == fixture.output_commitment;
    }));

    BlockValidationState invalidate_state;
    BOOST_REQUIRE(m_node.chainman->ActiveChainstate().InvalidateBlock(
        invalidate_state,
        WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip())));
    BOOST_CHECK(invalidate_state.IsValid());

    BOOST_CHECK(WITH_LOCK(cs_main, return !m_node.chainman->IsShieldedNullifierSpent(fixture.input_nullifier)));
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->GetShieldedMerkleTree().Size()),
                      fixture.tree_before.Size());
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->GetShieldedMerkleTree().Root()),
                      fixture.spend_anchor);
    BOOST_CHECK(WITH_LOCK(cs_main, {
        return !m_node.chainman->GetShieldedMerkleTree().CommitmentAt(fixture.tree_before.Size())
                    .has_value();
    }));

    if (!WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(send_txid))) {
        const MempoolAcceptResult reaccepted_result =
            WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(send_tx));
        if (reaccepted_result.m_result_type != MempoolAcceptResult::ResultType::VALID ||
            !reaccepted_result.m_state.IsValid()) {
            BOOST_FAIL(strprintf("v2 send mempool reaccept failed result_type=%i reason=%s debug=%s policy_weight=%lld",
                                 static_cast<int>(reaccepted_result.m_result_type),
                                 reaccepted_result.m_state.GetRejectReason(),
                                 reaccepted_result.m_state.GetDebugMessage(),
                                 static_cast<long long>(policy_weight)));
        }
        BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(send_txid)));
    }
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_rejects_v2_send_duplicate_ring_positions, TestChain100Setup)
{
    const auto fixture = BuildV2DirectSendChainFixture(*this);
    auto mutated_tx = fixture.built.tx;
    const auto* bundle = mutated_tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);

    std::string reject_reason;
    auto witness = v2proof::ParseV2SendWitness(*bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(witness.has_value(), reject_reason);
    BOOST_REQUIRE_EQUAL(witness->spends.size(), 1U);
    BOOST_REQUIRE_GE(witness->spends.front().ring_positions.size(), 2U);
    witness->spends.front().ring_positions[1] = witness->spends.front().ring_positions[0];
    ReplaceV2SendWitness(mutated_tx, *witness);

    const MempoolAcceptResult result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(mutated_tx), /*test_accept=*/true));

    BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(result.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(),
                      "bad-shielded-ring-member-insufficient-diversity");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_rejects_v2_send_out_of_range_ring_member_position, TestChain100Setup)
{
    const auto fixture = BuildV2DirectSendChainFixture(*this);
    auto mutated_tx = fixture.built.tx;
    const auto* bundle = mutated_tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);

    std::string reject_reason;
    auto witness = v2proof::ParseV2SendWitness(*bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(witness.has_value(), reject_reason);
    BOOST_REQUIRE_EQUAL(witness->spends.size(), 1U);
    BOOST_REQUIRE(!witness->spends.front().ring_positions.empty());
    witness->spends.front().ring_positions.back() = fixture.tree_before.Size();
    ReplaceV2SendWitness(mutated_tx, *witness);

    const MempoolAcceptResult result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(mutated_tx), /*test_accept=*/true));

    BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(result.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "bad-shielded-ring-member-position");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_rejects_v2_send_subminimum_ring_witness_with_ring_position_reason, TestChain100Setup)
{
    const auto fixture = BuildV2DirectSendChainFixture(*this);
    auto mutated_tx = fixture.built.tx;
    const auto* bundle = mutated_tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);

    std::string reject_reason;
    auto witness = v2proof::ParseV2SendWitness(*bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(witness.has_value(), reject_reason);
    BOOST_REQUIRE_EQUAL(witness->spends.size(), 1U);
    BOOST_REQUIRE(!witness->spends.front().ring_positions.empty());
    witness->spends.front().ring_positions = {witness->spends.front().ring_positions.front()};
    ReplaceV2SendWitness(mutated_tx, *witness);

    const MempoolAcceptResult result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(mutated_tx), /*test_accept=*/true));

    BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(result.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "bad-shielded-ring-positions");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_auto_recovers_v2_send_missing_smile_public_account_snapshot_entry, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 2;

    const auto fixture = BuildV2DirectSendChainFixture(*this, &consensus);
    const auto missing_commitment =
        WITH_LOCK(cs_main, return m_node.chainman->GetShieldedMerkleTree().CommitmentAt(0));
    BOOST_REQUIRE(missing_commitment.has_value());
    BOOST_REQUIRE(WITH_LOCK(cs_main,
                            return RemoveShieldedSmilePublicAccountForTest(*m_node.chainman,
                                                                           *missing_commitment)));
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main,
                                return m_node.chainman->GetShieldedSmilePublicAccounts().count(
                                    *missing_commitment)),
                      0U);

    const MempoolAcceptResult result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(fixture.built.tx), /*test_accept=*/true));

    BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::VALID);
    BOOST_CHECK(result.m_state.IsValid());
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main,
                                return m_node.chainman->GetShieldedAutoRepairAttemptCountForTest(
                                    ShieldedAutoRepairKind::STATE_REBUILD)),
                      1U);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main,
                                return m_node.chainman->GetShieldedSmilePublicAccounts().count(
                                    *missing_commitment)),
                      1U);

    const MempoolAcceptResult retried_result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(fixture.built.tx), /*test_accept=*/true));
    BOOST_CHECK(retried_result.m_result_type == MempoolAcceptResult::ResultType::VALID);
    BOOST_CHECK(retried_result.m_state.IsValid());
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main,
                                return m_node.chainman->GetShieldedAutoRepairAttemptCountForTest(
                                    ShieldedAutoRepairKind::STATE_REBUILD)),
                      1U);
}

BOOST_FIXTURE_TEST_CASE(block_auto_recovers_v2_send_missing_account_leaf_snapshot_entry, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 2;

    const auto fixture = BuildV2DirectSendChainFixture(*this, &consensus);
    const auto missing_commitment =
        WITH_LOCK(cs_main, return m_node.chainman->GetShieldedMerkleTree().CommitmentAt(0));
    BOOST_REQUIRE(missing_commitment.has_value());
    BOOST_REQUIRE(WITH_LOCK(cs_main,
                            return RemoveShieldedAccountLeafCommitmentForTest(*m_node.chainman,
                                                                              *missing_commitment)));
    BOOST_REQUIRE(WITH_LOCK(cs_main, return m_node.chainman->m_script_check_queue_enabled));
    BOOST_REQUIRE(WITH_LOCK(cs_main, return m_node.chainman->GetShieldedProofCheckQueue().HasThreads()));
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main,
                                return m_node.chainman->GetShieldedAccountLeafCommitments().count(
                                    *missing_commitment)),
                      0U);

    const int active_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const CBlock accepted_block = CreateAndProcessBlock({fixture.built.tx}, script_pub_key);
    const uint256 accepted_hash = accepted_block.GetHash();
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height()),
                      active_height + 1);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveTip()->GetBlockHash()),
                      accepted_hash);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main,
                                return m_node.chainman->GetShieldedAutoRepairAttemptCountForTest(
                                    ShieldedAutoRepairKind::STATE_REBUILD)),
                      1U);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main,
                                return m_node.chainman->GetShieldedAccountLeafCommitments().count(
                                    *missing_commitment)),
                      1U);
    CBlockIndex* accepted_index =
        WITH_LOCK(cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(accepted_hash));
    BOOST_REQUIRE(accepted_index != nullptr);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return accepted_index->nStatus & BLOCK_FAILED_MASK), 0U);
    BOOST_CHECK_EQUAL(
        WITH_LOCK(cs_main, return m_node.chainman->m_failed_blocks.count(accepted_index)), 0U);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_auto_recovery_serializes_concurrent_inbound_v2_send_requests,
                        TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 2;

    const auto fixture = BuildV2DirectSendChainFixture(*this, &consensus);
    const auto missing_commitment =
        WITH_LOCK(cs_main, return m_node.chainman->GetShieldedMerkleTree().CommitmentAt(0));
    BOOST_REQUIRE(missing_commitment.has_value());
    BOOST_REQUIRE(WITH_LOCK(cs_main,
                            return RemoveShieldedSmilePublicAccountForTest(*m_node.chainman,
                                                                           *missing_commitment)));

    std::mutex hook_mutex;
    std::condition_variable hook_cv;
    bool hook_entered{false};
    bool release_hook{false};

    WITH_LOCK(cs_main,
              m_node.chainman->SetShieldedAutoRepairHookForTest(
                  [&](ShieldedAutoRepairKind kind) {
                      if (kind != ShieldedAutoRepairKind::STATE_REBUILD) return;
                      std::unique_lock<std::mutex> lock{hook_mutex};
                      hook_entered = true;
                      hook_cv.notify_all();
                      hook_cv.wait(lock, [&] { return release_hook; });
                  }));

    std::promise<MempoolAcceptResult> first_promise;
    auto first_future = first_promise.get_future();
    std::thread first_thread([&] {
        first_promise.set_value(WITH_LOCK(
            cs_main,
            return m_node.chainman->ProcessTransaction(MakeTransactionRef(fixture.built.tx),
                                                       /*test_accept=*/true)));
    });

    {
        std::unique_lock<std::mutex> lock{hook_mutex};
        BOOST_REQUIRE(hook_cv.wait_for(lock, std::chrono::seconds{5}, [&] { return hook_entered; }));
    }

    std::promise<MempoolAcceptResult> second_promise;
    auto second_future = second_promise.get_future();
    std::thread second_thread([&] {
        second_promise.set_value(WITH_LOCK(
            cs_main,
            return m_node.chainman->ProcessTransaction(MakeTransactionRef(fixture.built.tx),
                                                       /*test_accept=*/true)));
    });

    BOOST_CHECK(second_future.wait_for(std::chrono::milliseconds{100}) == std::future_status::timeout);

    {
        std::lock_guard<std::mutex> lock{hook_mutex};
        release_hook = true;
    }
    hook_cv.notify_all();

    first_thread.join();
    second_thread.join();
    WITH_LOCK(cs_main, m_node.chainman->SetShieldedAutoRepairHookForTest({}));

    const MempoolAcceptResult first_result = first_future.get();
    const MempoolAcceptResult second_result = second_future.get();
    BOOST_CHECK(first_result.m_result_type == MempoolAcceptResult::ResultType::VALID);
    BOOST_CHECK(first_result.m_state.IsValid());
    BOOST_CHECK(second_result.m_result_type == MempoolAcceptResult::ResultType::VALID);
    BOOST_CHECK(second_result.m_state.IsValid());
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main,
                                return m_node.chainman->GetShieldedAutoRepairAttemptCountForTest(
                                    ShieldedAutoRepairKind::STATE_REBUILD)),
                      1U);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main,
                                return m_node.chainman->GetShieldedSmilePublicAccounts().count(
                                    *missing_commitment)),
                      1U);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_activation_gates_noncanonical_smile_v2_send, TestChain100Setup)
{
    const auto fixture = BuildV2DirectSendChainFixture(*this);
    auto mutated_tx = fixture.built.tx;
    MakeV2SendSmileProofNonCanonical(mutated_tx);

    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedSmileRiceCodecDisableHeight,
        consensus.nShieldedSmileRiceCodecDisableHeight};
    consensus.nShieldedSmileRiceCodecDisableHeight = tip_height + 2;

    const auto pre_activation = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(mutated_tx), /*test_accept=*/true));
    BOOST_CHECK(pre_activation.m_result_type == MempoolAcceptResult::ResultType::VALID);
    BOOST_CHECK(pre_activation.m_state.IsValid());

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({}, script_pub_key);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height()),
                      tip_height + 1);

    const auto post_activation = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(mutated_tx), /*test_accept=*/true));
    BOOST_CHECK(post_activation.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(post_activation.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(post_activation.m_state.GetRejectReason(),
                      "bad-shielded-spend-auth-proof-noncanonical-codec");
    BOOST_CHECK(post_activation.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_rejects_noncanonical_smile_v2_send_at_codec_disable_height, TestChain100Setup)
{
    const auto fixture = BuildV2DirectSendChainFixture(*this);
    auto mutated_tx = fixture.built.tx;
    MakeV2SendSmileProofNonCanonical(mutated_tx);

    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedSmileRiceCodecDisableHeight,
        consensus.nShieldedSmileRiceCodecDisableHeight};
    consensus.nShieldedSmileRiceCodecDisableHeight = tip_height + 1;

    const auto result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(mutated_tx), /*test_accept=*/true));

    BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(result.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(),
                      "bad-shielded-spend-auth-proof-noncanonical-codec");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(block_rejects_noncanonical_smile_v2_send_at_codec_disable_height, TestChain100Setup)
{
    const auto fixture = BuildV2DirectSendChainFixture(*this);
    auto mutated_tx = fixture.built.tx;
    MakeV2SendSmileProofNonCanonical(mutated_tx);

    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t active_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedSmileRiceCodecDisableHeight,
        consensus.nShieldedSmileRiceCodecDisableHeight};
    consensus.nShieldedSmileRiceCodecDisableHeight = active_height + 1;

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const CBlock block = CreateBlock({mutated_tx}, script_pub_key, m_node.chainman->ActiveChainstate());
    ExpectBlockRejected(*this, block, "bad-shielded-spend-auth-proof-noncanonical-codec");
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height()), active_height);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_activation_gates_legacy_smile_anonset_binding, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 3;
    const auto fixture = BuildV2DirectSendChainFixture(*this, &consensus);

    const auto pre_activation = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(fixture.built.tx), /*test_accept=*/true));
    BOOST_CHECK(pre_activation.m_result_type == MempoolAcceptResult::ResultType::VALID);
    BOOST_CHECK(pre_activation.m_state.IsValid());

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({}, script_pub_key);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height()),
                      tip_height + 2);

    const auto post_activation = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(fixture.built.tx), /*test_accept=*/true));
    BOOST_CHECK(post_activation.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(post_activation.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(post_activation.m_state.GetRejectReason(), "bad-shielded-v2-family-wire");
    BOOST_CHECK(post_activation.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_accepts_context_bound_smile_v2_send_at_activation, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 1;

    const auto fixture = BuildV2DirectSendChainFixture(*this, &consensus);
    BOOST_REQUIRE(fixture.built.tx.shielded_bundle.v2_bundle);
    BOOST_CHECK_EQUAL(fixture.built.tx.shielded_bundle.v2_bundle->header.proof_envelope.proof_kind,
                      shielded::v2::ProofKind::GENERIC_OPAQUE);
    BOOST_CHECK_EQUAL(fixture.built.tx.shielded_bundle.v2_bundle->header.proof_envelope.settlement_binding_kind,
                      shielded::v2::SettlementBindingKind::GENERIC_POSTFORK);
    m_node.mempool->PrioritiseTransaction(fixture.built.tx.GetHash(), COIN);
    const auto result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(fixture.built.tx), /*test_accept=*/true));

    BOOST_CHECK_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID,
                        result.m_state.GetRejectReason());
    BOOST_CHECK_MESSAGE(result.m_state.IsValid(), result.m_state.GetRejectReason());
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_accepts_postfork_v2_lifecycle_control, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 1;

    auto lifecycle_tx = BuildLifecycleControlTx(*this,
                                                /*change_value=*/49'000,
                                                /*fee=*/V2_DIRECT_SEND_FEE,
                                                &consensus,
                                                consensus.nShieldedMatRiCTDisableHeight);
    BOOST_REQUIRE(lifecycle_tx.shielded_bundle.v2_bundle);
    const auto& bundle = *lifecycle_tx.shielded_bundle.v2_bundle;
    BOOST_CHECK(shielded::v2::BundleHasSemanticFamily(bundle, TransactionFamily::V2_LIFECYCLE));

    std::string reject_reason;
    const auto state_value_balance =
        TryGetShieldedStateValueBalance(lifecycle_tx.shielded_bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(state_value_balance.has_value(), reject_reason);
    BOOST_CHECK_EQUAL(*state_value_balance, 0);
    BOOST_CHECK_EQUAL(GetShieldedTxValueBalance(lifecycle_tx.shielded_bundle), 0);

    const auto result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(lifecycle_tx), /*test_accept=*/false));

    BOOST_CHECK_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID,
                        result.m_state.GetRejectReason());
    BOOST_CHECK_MESSAGE(result.m_state.IsValid(), result.m_state.GetRejectReason());

    const auto txid = lifecycle_tx.GetHash();
    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(GenTxid::Txid(txid))));

    const uint64_t tree_size_before =
        WITH_LOCK(cs_main, return m_node.chainman->GetShieldedMerkleTree().Size());
    const uint64_t nullifier_count_before =
        WITH_LOCK(cs_main, return m_node.chainman->GetShieldedNullifierCount());
    const CAmount pool_before =
        WITH_LOCK(cs_main, return m_node.chainman->GetShieldedPoolBalance());

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({lifecycle_tx}, script_pub_key);

    BOOST_CHECK(WITH_LOCK(m_node.mempool->cs, return !m_node.mempool->exists(GenTxid::Txid(txid))));
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->GetShieldedMerkleTree().Size()),
                      tree_size_before);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->GetShieldedNullifierCount()),
                      nullifier_count_before);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->GetShieldedPoolBalance()),
                      pool_before);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_accepts_postfork_v2_lifecycle_control_with_multiple_transparent_outputs,
                        TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 1;

    const auto extra_script = GetScriptForDestination(WitnessV2P2MR(uint256{0x52}));
    auto lifecycle_tx = BuildLifecycleControlTx(*this,
                                                /*change_value=*/39'000,
                                                /*fee=*/V2_DIRECT_SEND_FEE,
                                                &consensus,
                                                consensus.nShieldedMatRiCTDisableHeight,
                                                {CTxOut{10'000, extra_script}});
    BOOST_REQUIRE(lifecycle_tx.shielded_bundle.v2_bundle);

    std::string reject_reason;
    const auto state_value_balance =
        TryGetShieldedStateValueBalance(lifecycle_tx.shielded_bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(state_value_balance.has_value(), reject_reason);
    BOOST_CHECK_EQUAL(*state_value_balance, 0);
    BOOST_CHECK_EQUAL(GetShieldedTxValueBalance(lifecycle_tx.shielded_bundle), 0);

    const auto result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(lifecycle_tx), /*test_accept=*/false));

    BOOST_CHECK_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID,
                        result.m_state.GetRejectReason());
    BOOST_CHECK_MESSAGE(result.m_state.IsValid(), result.m_state.GetRejectReason());
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_rejects_postfork_proofless_transparent_shielding_v2_send, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 1;
    auto shielding_tx = BuildTransparentShieldingV2SendTx(*this,
                                                          /*output_value=*/49'000,
                                                          /*fee=*/V2_DIRECT_SEND_FEE,
                                                          &consensus,
                                                          consensus.nShieldedMatRiCTDisableHeight);

    const auto result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(shielding_tx), /*test_accept=*/true));

    BOOST_CHECK_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::INVALID,
                        result.m_state.GetRejectReason());
    BOOST_CHECK_MESSAGE(result.m_state.IsInvalid(), result.m_state.GetRejectReason());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "bad-shielded-v2-send-public-flow-disabled");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_accepts_postfork_coinbase_shielding_v2_send, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 1;

    const auto shielding_tx = BuildCoinbaseShieldingV2SendTx(*this,
                                                             /*output_value=*/49'000,
                                                             /*fee=*/V2_DIRECT_SEND_FEE,
                                                             &consensus,
                                                             consensus.nShieldedMatRiCTDisableHeight);

    const auto result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(shielding_tx), /*test_accept=*/true));

    BOOST_CHECK_EQUAL(result.m_result_type, MempoolAcceptResult::ResultType::VALID);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_rejects_postfork_v2_lifecycle_tampered_binding, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 1;

    auto lifecycle_tx = BuildLifecycleControlTx(*this,
                                                /*change_value=*/49'000,
                                                /*fee=*/V2_DIRECT_SEND_FEE,
                                                &consensus,
                                                consensus.nShieldedMatRiCTDisableHeight);
    auto& bundle = *lifecycle_tx.shielded_bundle.v2_bundle;
    auto& payload = std::get<shielded::v2::LifecyclePayload>(bundle.payload);
    payload.transparent_binding_digest = uint256{0x99};
    bundle.header.payload_digest = shielded::v2::ComputeLifecyclePayloadDigest(payload);

    const auto result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(lifecycle_tx), /*test_accept=*/true));

    BOOST_CHECK_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::INVALID,
                        result.m_state.GetRejectReason());
    BOOST_CHECK_MESSAGE(result.m_state.IsInvalid(), result.m_state.GetRejectReason());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "bad-shielded-bundle");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_rejects_postfork_v2_lifecycle_tampered_output_value, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 1;

    CTransactionRef confirmed_funding_ref;
    auto lifecycle_tx = BuildLifecycleControlTx(*this,
                                                /*change_value=*/49'000,
                                                /*fee=*/V2_DIRECT_SEND_FEE,
                                                &consensus,
                                                consensus.nShieldedMatRiCTDisableHeight,
                                                {},
                                                &confirmed_funding_ref);
    BOOST_REQUIRE_EQUAL(lifecycle_tx.vout.size(), 1U);
    ++lifecycle_tx.vout[0].nValue;
    BOOST_REQUIRE(confirmed_funding_ref);
    ReSignSpend(*this, lifecycle_tx, confirmed_funding_ref);

    const auto result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(lifecycle_tx), /*test_accept=*/true));

    BOOST_CHECK_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::INVALID,
                        result.m_state.GetRejectReason());
    BOOST_CHECK_MESSAGE(result.m_state.IsInvalid(), result.m_state.GetRejectReason());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "bad-shielded-v2-lifecycle-binding");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_rejects_postfork_legacy_v2_send_lifecycle_control, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 1;

    auto legacy_lifecycle_tx = BuildPostforkGenericSendLifecycleControlTx(
        *this,
        /*output_value=*/49'000,
        /*fee=*/V2_DIRECT_SEND_FEE,
        &consensus,
        consensus.nShieldedMatRiCTDisableHeight);

    const auto result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(legacy_lifecycle_tx),
                                                   /*test_accept=*/true));

    BOOST_CHECK_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::INVALID,
                        result.m_state.GetRejectReason());
    BOOST_CHECK_MESSAGE(result.m_state.IsInvalid(), result.m_state.GetRejectReason());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "bad-shielded-v2-send-lifecycle-control");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_rejects_postfork_mixed_direct_v2_send, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 1;
    auto fixture = BuildV2DirectSendChainFixture(*this,
                                                 &consensus,
                                                 consensus.nShieldedMatRiCTDisableHeight,
                                                 V2_DIRECT_SEND_FEE);
    fixture.built.tx.vout.emplace_back(25'000, GetScriptForDestination(WitnessV2P2MR(uint256::ONE)));
    m_node.mempool->PrioritiseTransaction(fixture.built.tx.GetHash(), COIN);

    const auto result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(fixture.built.tx), /*test_accept=*/true));

    BOOST_CHECK_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::INVALID,
                        result.m_state.GetRejectReason());
    BOOST_CHECK_MESSAGE(result.m_state.IsInvalid(), result.m_state.GetRejectReason());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "bad-shielded-proof");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(
    tx_mempool_rejects_postfork_mixed_direct_v2_send_after_single_auto_rebuild_retry,
    TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 1;
    auto fixture = BuildV2DirectSendChainFixture(*this,
                                                 &consensus,
                                                 consensus.nShieldedMatRiCTDisableHeight,
                                                 V2_DIRECT_SEND_FEE);
    fixture.built.tx.vout.emplace_back(25'000, GetScriptForDestination(WitnessV2P2MR(uint256::ONE)));
    m_node.mempool->PrioritiseTransaction(fixture.built.tx.GetHash(), COIN);

    const auto result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(fixture.built.tx), /*test_accept=*/true));

    BOOST_CHECK_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::INVALID,
                        result.m_state.GetRejectReason());
    BOOST_CHECK_MESSAGE(result.m_state.IsInvalid(), result.m_state.GetRejectReason());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "bad-shielded-proof");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main,
                                return m_node.chainman->GetShieldedAutoRepairAttemptCountForTest(
                                    ShieldedAutoRepairKind::STATE_REBUILD)),
                      1U);

    const auto retried_result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(fixture.built.tx), /*test_accept=*/true));

    BOOST_CHECK_MESSAGE(retried_result.m_result_type == MempoolAcceptResult::ResultType::INVALID,
                        retried_result.m_state.GetRejectReason());
    BOOST_CHECK_MESSAGE(retried_result.m_state.IsInvalid(), retried_result.m_state.GetRejectReason());
    BOOST_CHECK_EQUAL(retried_result.m_state.GetRejectReason(), "bad-shielded-proof");
    BOOST_CHECK(retried_result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main,
                                return m_node.chainman->GetShieldedAutoRepairAttemptCountForTest(
                                    ShieldedAutoRepairKind::STATE_REBUILD)),
                      1U);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_rejects_postfork_legacy_compact_direct_send_encoding, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 1;

    auto fixture = BuildV2DirectSendChainFixture(*this,
                                                 &consensus,
                                                 consensus.nShieldedMatRiCTDisableHeight);
    auto& bundle = *fixture.built.tx.shielded_bundle.v2_bundle;
    auto& payload = std::get<shielded::v2::SendPayload>(bundle.payload);
    payload.output_encoding = shielded::v2::SendOutputEncoding::SMILE_COMPACT;
    bundle.header.payload_digest = shielded::v2::ComputeSendPayloadDigest(payload);
    m_node.mempool->PrioritiseTransaction(fixture.built.tx.GetHash(), COIN);

    const auto result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(fixture.built.tx), /*test_accept=*/true));

    BOOST_CHECK_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::INVALID,
                        result.m_state.GetRejectReason());
    BOOST_CHECK_MESSAGE(result.m_state.IsInvalid(), result.m_state.GetRejectReason());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "bad-shielded-v2-send-encoding");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_accepts_v2_ingress_with_canonical_fee_bucket_after_activation, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 3;

    const auto ingress_leaves = BuildCanonicalActivationIngressLeaves();
    const auto fixture = BuildV2IngressChainFixture(
        *this,
        DistributeIngressInputValues(V2_INGRESS_RESERVE_VALUE + SumIngressLeafTransfers(ingress_leaves), /*count=*/1),
        std::vector<CAmount>{V2_INGRESS_RESERVE_VALUE},
        ingress_leaves,
        IngressSettlementWitnessKind::SIGNED_ONLY,
        shielded::ringct::GetMinimumPrivacyTreeSize(shielded::lattice::RING_SIZE),
        &consensus,
        consensus.nShieldedMatRiCTDisableHeight);
    EnsureIngressAccountRegistryAnchorTracked(*this, fixture);
    const auto result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(fixture.built.tx), /*test_accept=*/true));

    BOOST_CHECK_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID,
                        result.m_state.GetRejectReason());
    BOOST_CHECK_MESSAGE(result.m_state.IsValid(), result.m_state.GetRejectReason());
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_rejects_noncanonical_v2_send_fee_bucket_after_activation, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 1;

    const auto fixture = BuildV2DirectSendChainFixture(
        *this,
        &consensus,
        std::numeric_limits<int32_t>::max(),
        shielded::SHIELDED_PRIVACY_FEE_QUANTUM + 1);
    const auto result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(fixture.built.tx), /*test_accept=*/true));

    BOOST_CHECK_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::INVALID,
                        result.m_state.GetRejectReason());
    BOOST_CHECK_MESSAGE(result.m_state.IsInvalid(), result.m_state.GetRejectReason());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "bad-shielded-v2-send-fee-bucket");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_rejects_v2_ingress_noncanonical_fee_bucket_after_activation, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 3;

    const auto ingress_leaves = BuildNonCanonicalActivationIngressLeaves();
    const auto fixture = BuildV2IngressChainFixture(
        *this,
        DistributeIngressInputValues(V2_INGRESS_RESERVE_VALUE + SumIngressLeafTransfers(ingress_leaves), /*count=*/1),
        std::vector<CAmount>{V2_INGRESS_RESERVE_VALUE},
        ingress_leaves,
        IngressSettlementWitnessKind::SIGNED_ONLY,
        shielded::ringct::GetMinimumPrivacyTreeSize(shielded::lattice::RING_SIZE),
        &consensus,
        consensus.nShieldedMatRiCTDisableHeight);
    EnsureIngressAccountRegistryAnchorTracked(*this, fixture);
    const auto result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(fixture.built.tx), /*test_accept=*/true));

    BOOST_CHECK_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::INVALID,
                        result.m_state.GetRejectReason());
    BOOST_CHECK_MESSAGE(result.m_state.IsInvalid(), result.m_state.GetRejectReason());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "bad-shielded-v2-ingress-fee-bucket");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_rejects_legacy_shield_noncanonical_fee_bucket_after_activation, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 1;

    const auto tx = BuildLegacyShieldOnlyTx(*this, m_coinbase_txns[0], shielded::SHIELDED_PRIVACY_FEE_QUANTUM + 1);
    const auto result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(tx), /*test_accept=*/true));

    BOOST_CHECK_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::INVALID,
                        result.m_state.GetRejectReason());
    BOOST_CHECK_MESSAGE(result.m_state.IsInvalid(), result.m_state.GetRejectReason());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "bad-shielded-legacy-fee-bucket");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_rejects_v2_send_small_anonymity_pool_after_activation, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 1;

    const auto fixture = BuildV2DirectSendChainFixture(
        *this,
        &consensus,
        std::numeric_limits<int32_t>::max(),
        V2_DIRECT_SEND_FEE,
        shielded::lattice::RING_SIZE);
    const auto result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(fixture.built.tx), /*test_accept=*/true));

    BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(result.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "bad-shielded-anonymity-pool-size");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_rejects_v2_ingress_small_anonymity_pool_after_activation, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 3;

    const auto ingress_leaves = BuildCanonicalActivationIngressLeaves();
    const auto fixture = BuildV2IngressChainFixture(
        *this,
        DistributeIngressInputValues(V2_INGRESS_RESERVE_VALUE + SumIngressLeafTransfers(ingress_leaves), /*count=*/1),
        std::vector<CAmount>{V2_INGRESS_RESERVE_VALUE},
        ingress_leaves,
        IngressSettlementWitnessKind::SIGNED_ONLY,
        shielded::lattice::RING_SIZE,
        &consensus,
        consensus.nShieldedMatRiCTDisableHeight);
    EnsureIngressAccountRegistryAnchorTracked(*this, fixture);
    const auto result = WITH_LOCK(
        cs_main,
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(fixture.built.tx), /*test_accept=*/true));

    BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(result.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "bad-shielded-anonymity-pool-size");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(block_rejects_noncanonical_v2_send_fee_bucket_after_activation, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 1;

    const auto fixture = BuildV2DirectSendChainFixture(
        *this,
        &consensus,
        std::numeric_limits<int32_t>::max(),
        shielded::SHIELDED_PRIVACY_FEE_QUANTUM + 1);

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const CBlock block = CreateBlock({fixture.built.tx}, script_pub_key, m_node.chainman->ActiveChainstate());
    ExpectBlockRejected(*this, block, "bad-shielded-v2-send-fee-bucket");
}

BOOST_FIXTURE_TEST_CASE(block_rejects_postfork_proofless_transparent_shielding_v2_send, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 1;
    auto shielding_tx = BuildTransparentShieldingV2SendTx(*this,
                                                          /*output_value=*/49'000,
                                                          /*fee=*/V2_DIRECT_SEND_FEE,
                                                          &consensus,
                                                          consensus.nShieldedMatRiCTDisableHeight);

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const CBlock block = CreateBlock({shielding_tx}, script_pub_key, m_node.chainman->ActiveChainstate());
    ExpectBlockRejected(*this, block, "bad-shielded-v2-send-public-flow-disabled");
}

BOOST_FIXTURE_TEST_CASE(block_accepts_postfork_coinbase_shielding_v2_send, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 1;

    const auto shielding_tx = BuildCoinbaseShieldingV2SendTx(*this,
                                                             /*output_value=*/49'000,
                                                             /*fee=*/V2_DIRECT_SEND_FEE,
                                                             &consensus,
                                                             consensus.nShieldedMatRiCTDisableHeight);

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const CBlock block = CreateBlock({shielding_tx}, script_pub_key, m_node.chainman->ActiveChainstate());
    ExpectBlockAccepted(*this, block);
}

BOOST_FIXTURE_TEST_CASE(block_rejects_postfork_v2_lifecycle_tampered_binding, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 1;

    auto lifecycle_tx = BuildLifecycleControlTx(*this,
                                                /*change_value=*/49'000,
                                                /*fee=*/V2_DIRECT_SEND_FEE,
                                                &consensus,
                                                consensus.nShieldedMatRiCTDisableHeight);
    auto& bundle = *lifecycle_tx.shielded_bundle.v2_bundle;
    auto& payload = std::get<shielded::v2::LifecyclePayload>(bundle.payload);
    payload.transparent_binding_digest = uint256{0x99};
    bundle.header.payload_digest = shielded::v2::ComputeLifecyclePayloadDigest(payload);

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const CBlock block = CreateBlock({lifecycle_tx}, script_pub_key, m_node.chainman->ActiveChainstate());
    ExpectBlockRejected(*this, block, "bad-shielded-bundle");
}

BOOST_FIXTURE_TEST_CASE(block_rejects_postfork_v2_lifecycle_tampered_output_value, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 1;

    CTransactionRef confirmed_funding_ref;
    auto lifecycle_tx = BuildLifecycleControlTx(*this,
                                                /*change_value=*/49'000,
                                                /*fee=*/V2_DIRECT_SEND_FEE,
                                                &consensus,
                                                consensus.nShieldedMatRiCTDisableHeight,
                                                {},
                                                &confirmed_funding_ref);
    BOOST_REQUIRE_EQUAL(lifecycle_tx.vout.size(), 1U);
    ++lifecycle_tx.vout[0].nValue;
    BOOST_REQUIRE(confirmed_funding_ref);
    ReSignSpend(*this, lifecycle_tx, confirmed_funding_ref);

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const CBlock block = CreateBlock({lifecycle_tx}, script_pub_key, m_node.chainman->ActiveChainstate());
    ExpectBlockRejected(*this, block, "bad-shielded-v2-lifecycle-binding");
}

BOOST_FIXTURE_TEST_CASE(block_rejects_postfork_mixed_direct_v2_send, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 1;
    auto fixture = BuildV2DirectSendChainFixture(*this,
                                                 &consensus,
                                                 consensus.nShieldedMatRiCTDisableHeight,
                                                 V2_DIRECT_SEND_FEE);
    fixture.built.tx.vout.emplace_back(25'000, GetScriptForDestination(WitnessV2P2MR(uint256::ONE)));

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const CBlock block = CreateBlock({fixture.built.tx}, script_pub_key, m_node.chainman->ActiveChainstate());
    ExpectBlockRejected(*this, block, "bad-shielded-proof");
}

BOOST_FIXTURE_TEST_CASE(block_rejects_postfork_legacy_v2_send_lifecycle_control, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 1;

    auto legacy_lifecycle_tx = BuildPostforkGenericSendLifecycleControlTx(
        *this,
        /*output_value=*/49'000,
        /*fee=*/V2_DIRECT_SEND_FEE,
        &consensus,
        consensus.nShieldedMatRiCTDisableHeight);

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const CBlock block =
        CreateBlock({legacy_lifecycle_tx}, script_pub_key, m_node.chainman->ActiveChainstate());
    ExpectBlockRejected(*this, block, "bad-shielded-v2-send-lifecycle-control");
}

BOOST_FIXTURE_TEST_CASE(block_rejects_postfork_legacy_compact_direct_send_encoding, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 1;

    auto fixture = BuildV2DirectSendChainFixture(*this,
                                                 &consensus,
                                                 consensus.nShieldedMatRiCTDisableHeight);
    auto& bundle = *fixture.built.tx.shielded_bundle.v2_bundle;
    auto& payload = std::get<shielded::v2::SendPayload>(bundle.payload);
    payload.output_encoding = shielded::v2::SendOutputEncoding::SMILE_COMPACT;
    bundle.header.payload_digest = shielded::v2::ComputeSendPayloadDigest(payload);

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const CBlock block = CreateBlock({fixture.built.tx}, script_pub_key, m_node.chainman->ActiveChainstate());
    ExpectBlockRejected(*this, block, "bad-shielded-v2-send-encoding");
}

BOOST_FIXTURE_TEST_CASE(block_rejects_v2_ingress_noncanonical_fee_bucket_after_activation, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 3;

    const auto ingress_leaves = BuildNonCanonicalActivationIngressLeaves();
    const auto fixture = BuildV2IngressChainFixture(
        *this,
        DistributeIngressInputValues(V2_INGRESS_RESERVE_VALUE + SumIngressLeafTransfers(ingress_leaves), /*count=*/1),
        std::vector<CAmount>{V2_INGRESS_RESERVE_VALUE},
        ingress_leaves,
        IngressSettlementWitnessKind::SIGNED_ONLY,
        shielded::ringct::GetMinimumPrivacyTreeSize(shielded::lattice::RING_SIZE),
        &consensus,
        consensus.nShieldedMatRiCTDisableHeight);
    EnsureIngressAccountRegistryAnchorTracked(*this, fixture);

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const CBlock block = CreateBlock({fixture.built.tx}, script_pub_key, m_node.chainman->ActiveChainstate());
    ExpectBlockRejected(*this, block, "bad-shielded-v2-ingress-fee-bucket");
}

BOOST_FIXTURE_TEST_CASE(block_rejects_legacy_shield_noncanonical_fee_bucket_after_activation, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 1;

    const auto tx = BuildLegacyShieldOnlyTx(*this, m_coinbase_txns[0], shielded::SHIELDED_PRIVACY_FEE_QUANTUM + 1);
    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const CBlock block = CreateBlock({tx}, script_pub_key, m_node.chainman->ActiveChainstate());
    ExpectBlockRejected(*this, block, "bad-shielded-legacy-fee-bucket");
}

BOOST_FIXTURE_TEST_CASE(block_rejects_v2_send_small_anonymity_pool_after_activation, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 1;

    const auto fixture = BuildV2DirectSendChainFixture(
        *this,
        &consensus,
        std::numeric_limits<int32_t>::max(),
        V2_DIRECT_SEND_FEE,
        shielded::lattice::RING_SIZE);

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const CBlock block = CreateBlock({fixture.built.tx}, script_pub_key, m_node.chainman->ActiveChainstate());
    ExpectBlockRejected(*this, block, "bad-shielded-anonymity-pool-size");
}

BOOST_FIXTURE_TEST_CASE(block_rejects_v2_ingress_small_anonymity_pool_after_activation, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t tip_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = tip_height + 3;

    const auto ingress_leaves = BuildCanonicalActivationIngressLeaves();
    const auto fixture = BuildV2IngressChainFixture(
        *this,
        DistributeIngressInputValues(V2_INGRESS_RESERVE_VALUE + SumIngressLeafTransfers(ingress_leaves), /*count=*/1),
        std::vector<CAmount>{V2_INGRESS_RESERVE_VALUE},
        ingress_leaves,
        IngressSettlementWitnessKind::SIGNED_ONLY,
        shielded::lattice::RING_SIZE,
        &consensus,
        consensus.nShieldedMatRiCTDisableHeight);
    EnsureIngressAccountRegistryAnchorTracked(*this, fixture);

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const CBlock block = CreateBlock({fixture.built.tx}, script_pub_key, m_node.chainman->ActiveChainstate());
    ExpectBlockRejected(*this, block, "bad-shielded-anonymity-pool-size");
}

BOOST_FIXTURE_TEST_CASE(block_rejects_legacy_smile_v2_send_at_anonset_binding_height, TestChain100Setup)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int32_t active_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const ScopedConsensusHeightOverride restore{
        consensus.nShieldedMatRiCTDisableHeight,
        consensus.nShieldedMatRiCTDisableHeight};
    consensus.nShieldedMatRiCTDisableHeight = active_height + 3;
    const auto fixture = BuildV2DirectSendChainFixture(*this, &consensus);

    const auto script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({}, script_pub_key);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height()), active_height + 2);
    const CBlock block = CreateBlock({fixture.built.tx}, script_pub_key, m_node.chainman->ActiveChainstate());
    ExpectBlockRejected(*this, block, "bad-shielded-v2-family-wire");
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height()), active_height + 2);
}

// Generate a number of random, nonexistent outpoints.
static inline std::vector<COutPoint> random_outpoints(size_t num_outpoints) {
    std::vector<COutPoint> outpoints;
    for (size_t i{0}; i < num_outpoints; ++i) {
        outpoints.emplace_back(Txid::FromUint256(GetRandHash()), 0);
    }
    return outpoints;
}

// Creates a placeholder tx (not valid) with 25 outputs. Specify the version and the inputs.
static inline CTransactionRef make_tx(const std::vector<COutPoint>& inputs, int32_t version)
{
    CMutableTransaction mtx = CMutableTransaction{};
    mtx.version = version;
    mtx.vin.resize(inputs.size());
    mtx.vout.resize(25);
    for (size_t i{0}; i < inputs.size(); ++i) {
        mtx.vin[i].prevout = inputs[i];
    }
    for (auto i{0}; i < 25; ++i) {
        mtx.vout[i].scriptPubKey = CScript() << OP_TRUE;
        mtx.vout[i].nValue = 10000;
    }
    return MakeTransactionRef(mtx);
}

static constexpr auto NUM_EPHEMERAL_TX_OUTPUTS = 3;
static constexpr auto EPHEMERAL_DUST_INDEX = NUM_EPHEMERAL_TX_OUTPUTS - 1;

// Same as make_tx but adds 2 normal outputs and 0-value dust to end of vout
static inline CTransactionRef make_ephemeral_tx(const std::vector<COutPoint>& inputs, int32_t version)
{
    CMutableTransaction mtx = CMutableTransaction{};
    mtx.version = version;
    mtx.vin.resize(inputs.size());
    for (size_t i{0}; i < inputs.size(); ++i) {
        mtx.vin[i].prevout = inputs[i];
    }
    mtx.vout.resize(NUM_EPHEMERAL_TX_OUTPUTS);
    for (auto i{0}; i < NUM_EPHEMERAL_TX_OUTPUTS; ++i) {
        mtx.vout[i].scriptPubKey = CScript() << OP_TRUE;
        mtx.vout[i].nValue = (i == EPHEMERAL_DUST_INDEX) ? 0 : 10000;
    }
    return MakeTransactionRef(mtx);
}

BOOST_FIXTURE_TEST_CASE(ephemeral_tests, RegTestingSetup)
{
    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(cs_main, pool.cs);
    TestMemPoolEntryHelper entry;
    CTxMemPool::setEntries empty_ancestors;

    TxValidationState child_state;
    Wtxid child_wtxid;

    // Arbitrary non-0 feerate for these tests
    CFeeRate dustrelay(DUST_RELAY_TX_FEE);

    // Basic transaction with dust
    auto grandparent_tx_1 = make_ephemeral_tx(random_outpoints(1), /*version=*/2);
    const auto dust_txid = grandparent_tx_1->GetHash();

    // Child transaction spending dust
    auto dust_spend = make_tx({COutPoint{dust_txid, EPHEMERAL_DUST_INDEX}}, /*version=*/2);

    // We first start with nothing "in the mempool", using package checks

    // Trivial single transaction with no dust
    BOOST_CHECK(CheckEphemeralSpends({dust_spend}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    // Now with dust, ok because the tx has no dusty parents
    BOOST_CHECK(CheckEphemeralSpends({grandparent_tx_1}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    // Dust checks pass
    BOOST_CHECK(CheckEphemeralSpends({grandparent_tx_1, dust_spend}, CFeeRate(0), pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());
    BOOST_CHECK(CheckEphemeralSpends({grandparent_tx_1, dust_spend}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    auto dust_non_spend = make_tx({COutPoint{dust_txid, EPHEMERAL_DUST_INDEX - 1}}, /*version=*/2);

    // Child spending non-dust only from parent should be disallowed even if dust otherwise spent
    const auto dust_non_spend_wtxid{dust_non_spend->GetWitnessHash()};
    BOOST_CHECK(!CheckEphemeralSpends({grandparent_tx_1, dust_non_spend, dust_spend}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(!child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, dust_non_spend_wtxid);
    child_state = TxValidationState();
    child_wtxid = Wtxid();

    BOOST_CHECK(!CheckEphemeralSpends({grandparent_tx_1, dust_spend, dust_non_spend}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(!child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, dust_non_spend_wtxid);
    child_state = TxValidationState();
    child_wtxid = Wtxid();

    BOOST_CHECK(!CheckEphemeralSpends({grandparent_tx_1, dust_non_spend}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(!child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, dust_non_spend_wtxid);
    child_state = TxValidationState();
    child_wtxid = Wtxid();

    auto grandparent_tx_2 = make_ephemeral_tx(random_outpoints(1), /*version=*/2);
    const auto dust_txid_2 = grandparent_tx_2->GetHash();

    // Spend dust from one but not another is ok, as long as second grandparent has no child
    BOOST_CHECK(CheckEphemeralSpends({grandparent_tx_1, grandparent_tx_2, dust_spend}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    auto dust_non_spend_both_parents = make_tx({COutPoint{dust_txid, EPHEMERAL_DUST_INDEX}, COutPoint{dust_txid_2, EPHEMERAL_DUST_INDEX - 1}}, /*version=*/2);
    // But if we spend from the parent, it must spend dust
    BOOST_CHECK(!CheckEphemeralSpends({grandparent_tx_1, grandparent_tx_2, dust_non_spend_both_parents}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(!child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, dust_non_spend_both_parents->GetWitnessHash());
    child_state = TxValidationState();
    child_wtxid = Wtxid();

    auto dust_spend_both_parents = make_tx({COutPoint{dust_txid, EPHEMERAL_DUST_INDEX}, COutPoint{dust_txid_2, EPHEMERAL_DUST_INDEX}}, /*version=*/2);
    BOOST_CHECK(CheckEphemeralSpends({grandparent_tx_1, grandparent_tx_2, dust_spend_both_parents}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    // Spending other outputs is also correct, as long as the dusty one is spent
    const std::vector<COutPoint> all_outpoints{COutPoint(dust_txid, 0), COutPoint(dust_txid, 1), COutPoint(dust_txid, 2),
        COutPoint(dust_txid_2, 0), COutPoint(dust_txid_2, 1), COutPoint(dust_txid_2, 2)};
    auto dust_spend_all_outpoints = make_tx(all_outpoints, /*version=*/2);
    BOOST_CHECK(CheckEphemeralSpends({grandparent_tx_1, grandparent_tx_2, dust_spend_all_outpoints}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    // 2 grandparents with dust <- 1 dust-spending parent with dust <- child with no dust
    auto parent_with_dust = make_ephemeral_tx({COutPoint{dust_txid, EPHEMERAL_DUST_INDEX}, COutPoint{dust_txid_2, EPHEMERAL_DUST_INDEX}}, /*version=*/2);
    // Ok for parent to have dust
    BOOST_CHECK(CheckEphemeralSpends({grandparent_tx_1, grandparent_tx_2, parent_with_dust}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());
    auto child_no_dust = make_tx({COutPoint{parent_with_dust->GetHash(), EPHEMERAL_DUST_INDEX}}, /*version=*/2);
    BOOST_CHECK(CheckEphemeralSpends({grandparent_tx_1, grandparent_tx_2, parent_with_dust, child_no_dust}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    // 2 grandparents with dust <- 1 dust-spending parent with dust <- child with dust
    auto child_with_dust = make_ephemeral_tx({COutPoint{parent_with_dust->GetHash(), EPHEMERAL_DUST_INDEX}}, /*version=*/2);
    BOOST_CHECK(CheckEphemeralSpends({grandparent_tx_1, grandparent_tx_2, parent_with_dust, child_with_dust}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    // Tests with parents in mempool

    // Nothing in mempool, this should pass for any transaction
    BOOST_CHECK(CheckEphemeralSpends({grandparent_tx_1}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    // Add first grandparent to mempool and fetch entry
    AddToMempool(pool, entry.FromTx(grandparent_tx_1));

    // Ignores ancestors that aren't direct parents
    BOOST_CHECK(CheckEphemeralSpends({child_no_dust}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    // Valid spend of dust with grandparent in mempool
    BOOST_CHECK(CheckEphemeralSpends({parent_with_dust}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    // Second grandparent in same package
    BOOST_CHECK(CheckEphemeralSpends({parent_with_dust, grandparent_tx_2}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    // Order in package doesn't matter
    BOOST_CHECK(CheckEphemeralSpends({grandparent_tx_2, parent_with_dust}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    // Add second grandparent to mempool
    AddToMempool(pool, entry.FromTx(grandparent_tx_2));

    // Only spends single dust out of two direct parents
    BOOST_CHECK(!CheckEphemeralSpends({dust_non_spend_both_parents}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(!child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, dust_non_spend_both_parents->GetWitnessHash());
    child_state = TxValidationState();
    child_wtxid = Wtxid();

    // Spends both parents' dust
    BOOST_CHECK(CheckEphemeralSpends({parent_with_dust}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    // Now add dusty parent to mempool
    AddToMempool(pool, entry.FromTx(parent_with_dust));

    // Passes dust checks even with non-parent ancestors
    BOOST_CHECK(CheckEphemeralSpends({child_no_dust}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());
}

BOOST_FIXTURE_TEST_CASE(version3_tests, RegTestingSetup)
{
    // Test TRUC policy helper functions
    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(cs_main, pool.cs);
    TestMemPoolEntryHelper entry;
    std::set<Txid> empty_conflicts_set;
    CTxMemPool::setEntries empty_ancestors;

    auto mempool_tx_v3 = make_tx(random_outpoints(1), /*version=*/3);
    AddToMempool(pool, entry.FromTx(mempool_tx_v3));
    auto mempool_tx_v2 = make_tx(random_outpoints(1), /*version=*/2);
    AddToMempool(pool, entry.FromTx(mempool_tx_v2));
    // Default values.
    CTxMemPool::Limits m_limits{};

    // Cannot spend from an unconfirmed TRUC transaction unless this tx is also TRUC.
    {
        // mempool_tx_v3
        //      ^
        // tx_v2_from_v3
        auto tx_v2_from_v3 = make_tx({COutPoint{mempool_tx_v3->GetHash(), 0}}, /*version=*/2);
        auto ancestors_v2_from_v3{pool.CalculateMemPoolAncestors(entry.FromTx(tx_v2_from_v3), m_limits)};
        const auto expected_error_str{strprintf("non-version=3 tx %s (wtxid=%s) cannot spend from version=3 tx %s (wtxid=%s)",
            tx_v2_from_v3->GetHash().ToString(), tx_v2_from_v3->GetWitnessHash().ToString(),
            mempool_tx_v3->GetHash().ToString(), mempool_tx_v3->GetWitnessHash().ToString())};
        auto result_v2_from_v3{SingleTRUCChecks(tx_v2_from_v3, *ancestors_v2_from_v3, empty_conflicts_set, GetVirtualTransactionSize(*tx_v2_from_v3))};
        BOOST_CHECK_EQUAL(result_v2_from_v3->first, expected_error_str);
        BOOST_CHECK_EQUAL(result_v2_from_v3->second, nullptr);

        Package package_v3_v2{mempool_tx_v3, tx_v2_from_v3};
        BOOST_CHECK_EQUAL(*PackageTRUCChecks(tx_v2_from_v3, GetVirtualTransactionSize(*tx_v2_from_v3), package_v3_v2, empty_ancestors), expected_error_str);
        CTxMemPool::setEntries entries_mempool_v3{pool.GetIter(mempool_tx_v3->GetHash().ToUint256()).value()};
        BOOST_CHECK_EQUAL(*PackageTRUCChecks(tx_v2_from_v3, GetVirtualTransactionSize(*tx_v2_from_v3), {tx_v2_from_v3}, entries_mempool_v3), expected_error_str);

        // mempool_tx_v3  mempool_tx_v2
        //            ^    ^
        //    tx_v2_from_v2_and_v3
        auto tx_v2_from_v2_and_v3 = make_tx({COutPoint{mempool_tx_v3->GetHash(), 0}, COutPoint{mempool_tx_v2->GetHash(), 0}}, /*version=*/2);
        auto ancestors_v2_from_both{pool.CalculateMemPoolAncestors(entry.FromTx(tx_v2_from_v2_and_v3), m_limits)};
        const auto expected_error_str_2{strprintf("non-version=3 tx %s (wtxid=%s) cannot spend from version=3 tx %s (wtxid=%s)",
            tx_v2_from_v2_and_v3->GetHash().ToString(), tx_v2_from_v2_and_v3->GetWitnessHash().ToString(),
            mempool_tx_v3->GetHash().ToString(), mempool_tx_v3->GetWitnessHash().ToString())};
        auto result_v2_from_both{SingleTRUCChecks(tx_v2_from_v2_and_v3, *ancestors_v2_from_both, empty_conflicts_set, GetVirtualTransactionSize(*tx_v2_from_v2_and_v3))};
        BOOST_CHECK_EQUAL(result_v2_from_both->first, expected_error_str_2);
        BOOST_CHECK_EQUAL(result_v2_from_both->second, nullptr);

        Package package_v3_v2_v2{mempool_tx_v3, mempool_tx_v2, tx_v2_from_v2_and_v3};
        BOOST_CHECK_EQUAL(*PackageTRUCChecks(tx_v2_from_v2_and_v3, GetVirtualTransactionSize(*tx_v2_from_v2_and_v3), package_v3_v2_v2, empty_ancestors), expected_error_str_2);
    }

    // TRUC cannot spend from an unconfirmed non-TRUC transaction.
    {
        // mempool_tx_v2
        //      ^
        // tx_v3_from_v2
        auto tx_v3_from_v2 = make_tx({COutPoint{mempool_tx_v2->GetHash(), 0}}, /*version=*/3);
        auto ancestors_v3_from_v2{pool.CalculateMemPoolAncestors(entry.FromTx(tx_v3_from_v2), m_limits)};
        const auto expected_error_str{strprintf("version=3 tx %s (wtxid=%s) cannot spend from non-version=3 tx %s (wtxid=%s)",
            tx_v3_from_v2->GetHash().ToString(), tx_v3_from_v2->GetWitnessHash().ToString(),
            mempool_tx_v2->GetHash().ToString(), mempool_tx_v2->GetWitnessHash().ToString())};
        auto result_v3_from_v2{SingleTRUCChecks(tx_v3_from_v2, *ancestors_v3_from_v2,  empty_conflicts_set, GetVirtualTransactionSize(*tx_v3_from_v2))};
        BOOST_CHECK_EQUAL(result_v3_from_v2->first, expected_error_str);
        BOOST_CHECK_EQUAL(result_v3_from_v2->second, nullptr);

        Package package_v2_v3{mempool_tx_v2, tx_v3_from_v2};
        BOOST_CHECK_EQUAL(*PackageTRUCChecks(tx_v3_from_v2, GetVirtualTransactionSize(*tx_v3_from_v2), package_v2_v3, empty_ancestors), expected_error_str);
        CTxMemPool::setEntries entries_mempool_v2{pool.GetIter(mempool_tx_v2->GetHash().ToUint256()).value()};
        BOOST_CHECK_EQUAL(*PackageTRUCChecks(tx_v3_from_v2, GetVirtualTransactionSize(*tx_v3_from_v2), {tx_v3_from_v2}, entries_mempool_v2), expected_error_str);

        // mempool_tx_v3  mempool_tx_v2
        //            ^    ^
        //    tx_v3_from_v2_and_v3
        auto tx_v3_from_v2_and_v3 = make_tx({COutPoint{mempool_tx_v3->GetHash(), 0}, COutPoint{mempool_tx_v2->GetHash(), 0}}, /*version=*/3);
        auto ancestors_v3_from_both{pool.CalculateMemPoolAncestors(entry.FromTx(tx_v3_from_v2_and_v3), m_limits)};
        const auto expected_error_str_2{strprintf("version=3 tx %s (wtxid=%s) cannot spend from non-version=3 tx %s (wtxid=%s)",
            tx_v3_from_v2_and_v3->GetHash().ToString(), tx_v3_from_v2_and_v3->GetWitnessHash().ToString(),
            mempool_tx_v2->GetHash().ToString(), mempool_tx_v2->GetWitnessHash().ToString())};
        auto result_v3_from_both{SingleTRUCChecks(tx_v3_from_v2_and_v3, *ancestors_v3_from_both, empty_conflicts_set, GetVirtualTransactionSize(*tx_v3_from_v2_and_v3))};
        BOOST_CHECK_EQUAL(result_v3_from_both->first, expected_error_str_2);
        BOOST_CHECK_EQUAL(result_v3_from_both->second, nullptr);

        // tx_v3_from_v2_and_v3 also violates TRUC_ANCESTOR_LIMIT.
        const auto expected_error_str_3{strprintf("tx %s (wtxid=%s) would have too many ancestors",
            tx_v3_from_v2_and_v3->GetHash().ToString(), tx_v3_from_v2_and_v3->GetWitnessHash().ToString())};
        Package package_v3_v2_v3{mempool_tx_v3, mempool_tx_v2, tx_v3_from_v2_and_v3};
        BOOST_CHECK_EQUAL(*PackageTRUCChecks(tx_v3_from_v2_and_v3, GetVirtualTransactionSize(*tx_v3_from_v2_and_v3), package_v3_v2_v3, empty_ancestors), expected_error_str_3);
    }
    // V3 from V3 is ok, and non-V3 from non-V3 is ok.
    {
        // mempool_tx_v3
        //      ^
        // tx_v3_from_v3
        auto tx_v3_from_v3 = make_tx({COutPoint{mempool_tx_v3->GetHash(), 0}}, /*version=*/3);
        auto ancestors_v3{pool.CalculateMemPoolAncestors(entry.FromTx(tx_v3_from_v3), m_limits)};
        BOOST_CHECK(SingleTRUCChecks(tx_v3_from_v3, *ancestors_v3, empty_conflicts_set, GetVirtualTransactionSize(*tx_v3_from_v3))
                    == std::nullopt);

        Package package_v3_v3{mempool_tx_v3, tx_v3_from_v3};
        BOOST_CHECK(PackageTRUCChecks(tx_v3_from_v3, GetVirtualTransactionSize(*tx_v3_from_v3), package_v3_v3, empty_ancestors) == std::nullopt);

        // mempool_tx_v2
        //      ^
        // tx_v2_from_v2
        auto tx_v2_from_v2 = make_tx({COutPoint{mempool_tx_v2->GetHash(), 0}}, /*version=*/2);
        auto ancestors_v2{pool.CalculateMemPoolAncestors(entry.FromTx(tx_v2_from_v2), m_limits)};
        BOOST_CHECK(SingleTRUCChecks(tx_v2_from_v2, *ancestors_v2, empty_conflicts_set, GetVirtualTransactionSize(*tx_v2_from_v2))
                    == std::nullopt);

        Package package_v2_v2{mempool_tx_v2, tx_v2_from_v2};
        BOOST_CHECK(PackageTRUCChecks(tx_v2_from_v2, GetVirtualTransactionSize(*tx_v2_from_v2), package_v2_v2, empty_ancestors) == std::nullopt);
    }

    // Tx spending TRUC cannot have too many mempool ancestors
    // Configuration where the tx has multiple direct parents.
    {
        Package package_multi_parents;
        std::vector<COutPoint> mempool_outpoints;
        mempool_outpoints.emplace_back(mempool_tx_v3->GetHash(), 0);
        package_multi_parents.emplace_back(mempool_tx_v3);
        for (size_t i{0}; i < 2; ++i) {
            auto mempool_tx = make_tx(random_outpoints(i + 1), /*version=*/3);
            AddToMempool(pool, entry.FromTx(mempool_tx));
            mempool_outpoints.emplace_back(mempool_tx->GetHash(), 0);
            package_multi_parents.emplace_back(mempool_tx);
        }
        auto tx_v3_multi_parent = make_tx(mempool_outpoints, /*version=*/3);
        package_multi_parents.emplace_back(tx_v3_multi_parent);
        auto ancestors{pool.CalculateMemPoolAncestors(entry.FromTx(tx_v3_multi_parent), m_limits)};
        BOOST_CHECK_EQUAL(ancestors->size(), 3);
        const auto expected_error_str{strprintf("tx %s (wtxid=%s) would have too many ancestors",
            tx_v3_multi_parent->GetHash().ToString(), tx_v3_multi_parent->GetWitnessHash().ToString())};
        auto result{SingleTRUCChecks(tx_v3_multi_parent, *ancestors, empty_conflicts_set, GetVirtualTransactionSize(*tx_v3_multi_parent))};
        BOOST_CHECK_EQUAL(result->first, expected_error_str);
        BOOST_CHECK_EQUAL(result->second, nullptr);

        BOOST_CHECK_EQUAL(*PackageTRUCChecks(tx_v3_multi_parent, GetVirtualTransactionSize(*tx_v3_multi_parent), package_multi_parents, empty_ancestors),
                          expected_error_str);
    }

    // Configuration where the tx is in a multi-generation chain.
    {
        Package package_multi_gen;
        CTransactionRef middle_tx;
        auto last_outpoint{random_outpoints(1)[0]};
        for (size_t i{0}; i < 2; ++i) {
            auto mempool_tx = make_tx({last_outpoint}, /*version=*/3);
            AddToMempool(pool, entry.FromTx(mempool_tx));
            last_outpoint = COutPoint{mempool_tx->GetHash(), 0};
            package_multi_gen.emplace_back(mempool_tx);
            if (i == 1) middle_tx = mempool_tx;
        }
        auto tx_v3_multi_gen = make_tx({last_outpoint}, /*version=*/3);
        package_multi_gen.emplace_back(tx_v3_multi_gen);
        auto ancestors{pool.CalculateMemPoolAncestors(entry.FromTx(tx_v3_multi_gen), m_limits)};
        const auto expected_error_str{strprintf("tx %s (wtxid=%s) would have too many ancestors",
            tx_v3_multi_gen->GetHash().ToString(), tx_v3_multi_gen->GetWitnessHash().ToString())};
        auto result{SingleTRUCChecks(tx_v3_multi_gen, *ancestors, empty_conflicts_set, GetVirtualTransactionSize(*tx_v3_multi_gen))};
        BOOST_CHECK_EQUAL(result->first, expected_error_str);
        BOOST_CHECK_EQUAL(result->second, nullptr);

        // Middle tx is what triggers a failure for the grandchild:
        BOOST_CHECK_EQUAL(*PackageTRUCChecks(middle_tx, GetVirtualTransactionSize(*middle_tx), package_multi_gen, empty_ancestors), expected_error_str);
        BOOST_CHECK(PackageTRUCChecks(tx_v3_multi_gen, GetVirtualTransactionSize(*tx_v3_multi_gen), package_multi_gen, empty_ancestors) == std::nullopt);
    }

    // Tx spending TRUC cannot be too large in virtual size.
    auto many_inputs{random_outpoints(100)};
    many_inputs.emplace_back(mempool_tx_v3->GetHash(), 0);
    {
        auto tx_v3_child_big = make_tx(many_inputs, /*version=*/3);
        const auto vsize{GetVirtualTransactionSize(*tx_v3_child_big)};
        auto ancestors{pool.CalculateMemPoolAncestors(entry.FromTx(tx_v3_child_big), m_limits)};
        const auto expected_error_str{strprintf("version=3 child tx %s (wtxid=%s) is too big: %u > %u virtual bytes",
            tx_v3_child_big->GetHash().ToString(), tx_v3_child_big->GetWitnessHash().ToString(), vsize, TRUC_CHILD_MAX_VSIZE)};
        auto result{SingleTRUCChecks(tx_v3_child_big, *ancestors, empty_conflicts_set, GetVirtualTransactionSize(*tx_v3_child_big))};
        BOOST_CHECK_EQUAL(result->first, expected_error_str);
        BOOST_CHECK_EQUAL(result->second, nullptr);

        Package package_child_big{mempool_tx_v3, tx_v3_child_big};
        BOOST_CHECK_EQUAL(*PackageTRUCChecks(tx_v3_child_big, GetVirtualTransactionSize(*tx_v3_child_big), package_child_big, empty_ancestors),
                          expected_error_str);
    }

    // Tx spending TRUC cannot have too many sigops.
    // Keep the raw tx below the child vsize limit while making the sigop-adjusted
    // virtual size exceed it.
    auto multisig_outpoints{random_outpoints(5)};
    multisig_outpoints.emplace_back(mempool_tx_v3->GetHash(), 0);
    CScript script_multisig;
    script_multisig << OP_CHECKMULTISIG << OP_CHECKMULTISIG;
    {
        CMutableTransaction mtx_many_sigops = CMutableTransaction{};
        mtx_many_sigops.version = TRUC_VERSION;
        for (const auto& outpoint : multisig_outpoints) {
            mtx_many_sigops.vin.emplace_back(outpoint);
            mtx_many_sigops.vin.back().scriptWitness.stack.emplace_back(script_multisig.begin(), script_multisig.end());
        }
        mtx_many_sigops.vout.resize(1);
        mtx_many_sigops.vout.back().scriptPubKey = CScript() << OP_TRUE;
        mtx_many_sigops.vout.back().nValue = 10000;
        auto tx_many_sigops{MakeTransactionRef(mtx_many_sigops)};

        auto ancestors{pool.CalculateMemPoolAncestors(entry.FromTx(tx_many_sigops), m_limits)};
        // legacy uses fAccurate = false, and the maximum number of multisig keys is used
        // for each CHECKMULTISIG occurrence.
        const int64_t total_sigops{static_cast<int64_t>(tx_many_sigops->vin.size()) * static_cast<int64_t>(script_multisig.GetSigOpCount(/*fAccurate=*/false))};
        BOOST_CHECK_EQUAL(total_sigops, tx_many_sigops->vin.size() * 2 * MAX_PUBKEYS_PER_MULTISIG);
        const int64_t bip141_vsize{GetVirtualTransactionSize(*tx_many_sigops)};
        // Weight limit is not reached...
        BOOST_CHECK_LT(bip141_vsize, TRUC_CHILD_MAX_VSIZE);
        BOOST_CHECK(SingleTRUCChecks(tx_many_sigops, *ancestors, empty_conflicts_set, bip141_vsize) == std::nullopt);
        // ...but sigop limit is.
        const auto expected_error_str{strprintf("version=3 child tx %s (wtxid=%s) is too big: %u > %u virtual bytes",
            tx_many_sigops->GetHash().ToString(), tx_many_sigops->GetWitnessHash().ToString(),
            total_sigops * DEFAULT_BYTES_PER_SIGOP / WITNESS_SCALE_FACTOR, TRUC_CHILD_MAX_VSIZE)};
        auto result{SingleTRUCChecks(tx_many_sigops, *ancestors, empty_conflicts_set,
                                        GetVirtualTransactionSize(*tx_many_sigops, /*nSigOpCost=*/total_sigops, /*bytes_per_sigop=*/ DEFAULT_BYTES_PER_SIGOP))};
        BOOST_CHECK_EQUAL(result->first, expected_error_str);
        BOOST_CHECK_EQUAL(result->second, nullptr);

        Package package_child_sigops{mempool_tx_v3, tx_many_sigops};
        BOOST_CHECK_EQUAL(*PackageTRUCChecks(tx_many_sigops, total_sigops * DEFAULT_BYTES_PER_SIGOP / WITNESS_SCALE_FACTOR, package_child_sigops, empty_ancestors),
                          expected_error_str);
    }

    // Parent + child with TRUC in the mempool. Child is allowed as long as it is under TRUC_CHILD_MAX_VSIZE.
    auto tx_mempool_v3_child = make_tx({COutPoint{mempool_tx_v3->GetHash(), 0}}, /*version=*/3);
    {
        BOOST_CHECK(GetTransactionWeight(*tx_mempool_v3_child) <= TRUC_CHILD_MAX_VSIZE * WITNESS_SCALE_FACTOR);
        auto ancestors{pool.CalculateMemPoolAncestors(entry.FromTx(tx_mempool_v3_child), m_limits)};
        BOOST_CHECK(SingleTRUCChecks(tx_mempool_v3_child, *ancestors, empty_conflicts_set, GetVirtualTransactionSize(*tx_mempool_v3_child)) == std::nullopt);
        AddToMempool(pool, entry.FromTx(tx_mempool_v3_child));

        Package package_v3_1p1c{mempool_tx_v3, tx_mempool_v3_child};
        BOOST_CHECK(PackageTRUCChecks(tx_mempool_v3_child, GetVirtualTransactionSize(*tx_mempool_v3_child), package_v3_1p1c, empty_ancestors) == std::nullopt);
    }

    // A TRUC transaction cannot have more than 1 descendant. Sibling is returned when exactly 1 exists.
    {
        auto tx_v3_child2 = make_tx({COutPoint{mempool_tx_v3->GetHash(), 1}}, /*version=*/3);

        // Configuration where parent already has 1 other child in mempool
        auto ancestors_1sibling{pool.CalculateMemPoolAncestors(entry.FromTx(tx_v3_child2), m_limits)};
        const auto expected_error_str{strprintf("tx %s (wtxid=%s) would exceed descendant count limit",
            mempool_tx_v3->GetHash().ToString(), mempool_tx_v3->GetWitnessHash().ToString())};
        auto result_with_sibling_eviction{SingleTRUCChecks(tx_v3_child2, *ancestors_1sibling, empty_conflicts_set, GetVirtualTransactionSize(*tx_v3_child2))};
        BOOST_CHECK_EQUAL(result_with_sibling_eviction->first, expected_error_str);
        // The other mempool child is returned to allow for sibling eviction.
        BOOST_CHECK_EQUAL(result_with_sibling_eviction->second, tx_mempool_v3_child);

        // If directly replacing the child, make sure there is no double-counting.
        BOOST_CHECK(SingleTRUCChecks(tx_v3_child2, *ancestors_1sibling, {tx_mempool_v3_child->GetHash()}, GetVirtualTransactionSize(*tx_v3_child2))
                    == std::nullopt);

        Package package_v3_1p2c{mempool_tx_v3, tx_mempool_v3_child, tx_v3_child2};
        BOOST_CHECK_EQUAL(*PackageTRUCChecks(tx_v3_child2, GetVirtualTransactionSize(*tx_v3_child2), package_v3_1p2c, empty_ancestors),
                          expected_error_str);

        // Configuration where parent already has 2 other children in mempool (no sibling eviction allowed). This may happen as the result of a reorg.
        AddToMempool(pool, entry.FromTx(tx_v3_child2));
        auto tx_v3_child3 = make_tx({COutPoint{mempool_tx_v3->GetHash(), 24}}, /*version=*/3);
        auto entry_mempool_parent = pool.GetIter(mempool_tx_v3->GetHash().ToUint256()).value();
        BOOST_CHECK_EQUAL(entry_mempool_parent->GetCountWithDescendants(), 3);
        auto ancestors_2siblings{pool.CalculateMemPoolAncestors(entry.FromTx(tx_v3_child3), m_limits)};

        auto result_2children{SingleTRUCChecks(tx_v3_child3, *ancestors_2siblings, empty_conflicts_set, GetVirtualTransactionSize(*tx_v3_child3))};
        BOOST_CHECK_EQUAL(result_2children->first, expected_error_str);
        // The other mempool child is not returned because sibling eviction is not allowed.
        BOOST_CHECK_EQUAL(result_2children->second, nullptr);
    }

    // Sibling eviction: parent already has 1 other child, which also has its own child (no sibling eviction allowed). This may happen as the result of a reorg.
    {
        auto tx_mempool_grandparent = make_tx(random_outpoints(1), /*version=*/3);
        auto tx_mempool_sibling = make_tx({COutPoint{tx_mempool_grandparent->GetHash(), 0}}, /*version=*/3);
        auto tx_mempool_nibling = make_tx({COutPoint{tx_mempool_sibling->GetHash(), 0}}, /*version=*/3);
        auto tx_to_submit = make_tx({COutPoint{tx_mempool_grandparent->GetHash(), 1}}, /*version=*/3);

        AddToMempool(pool, entry.FromTx(tx_mempool_grandparent));
        AddToMempool(pool, entry.FromTx(tx_mempool_sibling));
        AddToMempool(pool, entry.FromTx(tx_mempool_nibling));

        auto ancestors_3gen{pool.CalculateMemPoolAncestors(entry.FromTx(tx_to_submit), m_limits)};
        const auto expected_error_str{strprintf("tx %s (wtxid=%s) would exceed descendant count limit",
            tx_mempool_grandparent->GetHash().ToString(), tx_mempool_grandparent->GetWitnessHash().ToString())};
        auto result_3gen{SingleTRUCChecks(tx_to_submit, *ancestors_3gen, empty_conflicts_set, GetVirtualTransactionSize(*tx_to_submit))};
        BOOST_CHECK_EQUAL(result_3gen->first, expected_error_str);
        // The other mempool child is not returned because sibling eviction is not allowed.
        BOOST_CHECK_EQUAL(result_3gen->second, nullptr);
    }

    // Configuration where tx has multiple generations of descendants is not tested because that is
    // equivalent to the tx with multiple generations of ancestors.
}

BOOST_AUTO_TEST_SUITE_END()
