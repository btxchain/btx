// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <crypto/ml_kem.h>
#include <hash.h>
#include <pqkey.h>
#include <random.h>
#include <crypto/chacha20poly1305.h>
#include <shielded/lattice/params.h>
#include <shielded/ringct/ring_selection.h>
#include <shielded/ringct/matrict.h>
#include <shielded/note_encryption.h>
#include <shielded/smile2/verify_dispatch.h>
#include <shielded/smile2/wallet_bridge.h>
#include <shielded/spend_auth.h>
#include <shielded/validation.h>
#include <shielded/v2_bundle.h>
#include <shielded/v2_proof.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <test/shielded_spend_path_recovery_fixture_builder.h>
#include <test/util/shielded_account_registry_test_util.h>
#include <test/util/setup_common.h>
#include <test/util/shielded_v2_egress_fixture.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <limits>
#include <string>
#include <vector>

namespace {

using namespace shielded::ringct;
namespace v2proof = shielded::v2::proof;

[[nodiscard]] ShieldedNote MakeNote(CAmount value, unsigned char seed)
{
    ShieldedNote note;
    note.value = value;
    note.recipient_pk_hash = uint256{seed};
    note.rho = uint256{static_cast<unsigned char>(seed + 1)};
    note.rcm = uint256{static_cast<unsigned char>(seed + 2)};
    BOOST_REQUIRE(note.IsValid());
    return note;
}

[[nodiscard]] mlkem::KeyPair BuildRecipientKeyPair(unsigned char seed)
{
    std::array<uint8_t, mlkem::KEYGEN_SEEDBYTES> key_seed{};
    key_seed.fill(seed);
    return mlkem::KeyGenDerand(key_seed);
}

[[nodiscard]] shielded::EncryptedNote BuildEncryptedNote(const ShieldedNote& note,
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

[[nodiscard]] shielded::v2::LifecycleAddress MakeLifecycleAddress(CPQKey& signing_key,
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

[[nodiscard]] shielded::v2::AddressLifecycleControl MakeLifecycleRecord(
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

[[nodiscard]] CMutableTransaction BuildLifecycleControlTx(
    const Consensus::Params* consensus = nullptr,
    int32_t validation_height = std::numeric_limits<int32_t>::max(),
    const std::vector<CTxOut>& extra_outputs = {})
{
    CMutableTransaction tx;
    tx.version = CTransaction::CURRENT_VERSION;
    tx.nLockTime = 41;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{0x91}) , 0},
                        CScript{},
                        0xfffffffd);
    tx.vout.emplace_back(25'000, CScript{} << OP_TRUE);
    tx.vout.insert(tx.vout.end(), extra_outputs.begin(), extra_outputs.end());

    CPQKey subject_key;
    CPQKey successor_key;
    subject_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    successor_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(subject_key.IsValid());
    BOOST_REQUIRE(successor_key.IsValid());

    const auto subject = MakeLifecycleAddress(subject_key, 0x21);
    const auto successor = MakeLifecycleAddress(successor_key, 0x41);
    const uint256 binding_digest =
        shielded::v2::ComputeV2LifecycleTransparentBindingDigest(CTransaction{tx});
    BOOST_REQUIRE(!binding_digest.IsNull());

    shielded::v2::LifecyclePayload payload;
    payload.transparent_binding_digest = binding_digest;
    payload.lifecycle_controls = {MakeLifecycleRecord(
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
    return tx;
}

[[nodiscard]] CMutableTransaction BuildLegacyLifecycleSendTx(const Consensus::Params& consensus,
                                                             int32_t validation_height)
{
    CPQKey subject_key;
    CPQKey successor_key;
    subject_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    successor_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(subject_key.IsValid());
    BOOST_REQUIRE(successor_key.IsValid());

    const ShieldedNote output_note = MakeNote(/*value=*/10'000, /*seed=*/0x73);
    const auto smile_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        output_note);
    BOOST_REQUIRE(smile_account.has_value());
    const uint256 note_commitment = smile2::ComputeCompactPublicAccountHash(*smile_account);

    const auto recipient = BuildRecipientKeyPair(/*seed=*/0x83);
    const auto encrypted_note = BuildEncryptedNote(output_note,
                                                   recipient.pk,
                                                   /*kem_seed_byte=*/0x93,
                                                   /*nonce_byte=*/0xA3);
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
        const auto subject = MakeLifecycleAddress(subject_key, 0x25);
        const auto successor = MakeLifecycleAddress(successor_key, 0x45);
        shielded::v2::AddressLifecycleControl control;
        control.kind = shielded::v2::AddressLifecycleControlKind::ROTATE;
        control.output_index = 0;
        control.subject = subject;
        control.has_successor = true;
        control.successor = successor;
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
    tx_template.nLockTime = 43;
    tx_template.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{0x92}), 0},
                                 CScript{},
                                 0xffffffff);

    std::string reject_reason;
    auto built = shielded::v2::BuildV2SendTransaction(tx_template,
                                                      uint256::ZERO,
                                                      {},
                                                      {output_input},
                                                      /*fee=*/10'000,
                                                      {},
                                                      reject_reason,
                                                      {},
                                                      &consensus,
                                                      validation_height);
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);
    return built->tx;
}

[[nodiscard]] CMutableTransaction BuildPostforkGenericSendLifecycleControlTx(
    const Consensus::Params& consensus,
    int32_t validation_height)
{
    auto tx = BuildLegacyLifecycleSendTx(consensus, validation_height - 1);
    auto& bundle = *tx.shielded_bundle.v2_bundle;
    bundle.header.family_id = shielded::v2::GetWireTransactionFamilyForValidationHeight(
        shielded::v2::TransactionFamily::V2_SEND,
        &consensus,
        validation_height);
    bundle.header.proof_envelope.settlement_binding_kind =
        shielded::v2::GetWireSettlementBindingKindForValidationHeight(
            shielded::v2::TransactionFamily::V2_SEND,
            shielded::v2::SettlementBindingKind::NONE,
            &consensus,
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

uint256 ComputeLegacySpendAuthV2SigHashForTest(const CTransaction& tx,
                                               size_t input_index,
                                               const Consensus::Params& consensus,
                                               int32_t validation_height)
{
    if (!tx.HasShieldedBundle()) return uint256{};
    const auto& bundle = tx.GetShieldedBundle();
    if (input_index >= bundle.shielded_inputs.size()) return uint256{};

    const uint256 stripped_hash =
        shielded::ringct::ComputeMatRiCTBindingHash(tx, consensus, validation_height);

    HashWriter hw;
    hw << std::string{"BTX_Shielded_SpendAuth_V2"};
    hw << consensus.hashGenesisBlock;
    hw << static_cast<uint32_t>(consensus.nShieldedMatRiCTDisableHeight);
    hw << stripped_hash;
    hw << static_cast<uint32_t>(input_index);
    hw << bundle.shielded_inputs[input_index].nullifier;
    return hw.GetSHA256();
}

std::vector<std::vector<uint256>> BuildRingMembers(const CShieldedBundle& bundle)
{
    std::vector<std::vector<uint256>> ring_members;
    ring_members.reserve(bundle.shielded_inputs.size());
    for (const auto& spend : bundle.shielded_inputs) {
        std::vector<uint256> ring;
        ring.reserve(spend.ring_positions.size());
        for (const uint64_t pos : spend.ring_positions) {
            HashWriter hw;
            hw << std::string{"BTX_Shielded_RingMember_V1"};
            hw << pos;
            ring.push_back(hw.GetSHA256());
        }
        ring_members.push_back(std::move(ring));
    }
    return ring_members;
}

shielded::ShieldedMerkleTree BuildLegacyRingTree()
{
    shielded::ShieldedMerkleTree tree;
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        HashWriter hw;
        hw << std::string{"BTX_Shielded_RingMember_V1"};
        hw << static_cast<uint64_t>(i);
        tree.Append(hw.GetSHA256());
    }
    return tree;
}

CShieldedProofCheck MakeLegacyProofCheck(const CTransaction& tx,
                                         const shielded::ShieldedMerkleTree& tree)
{
    const auto& consensus = Params().GetConsensus();
    return CShieldedProofCheck(tx,
                               consensus,
                               consensus.nShieldedMatRiCTDisableHeight - 1,
                               std::make_shared<shielded::ShieldedMerkleTree>(tree));
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

void RefreshSingleDescriptorSettlementAnchorFixture(test::shielded::V2SettlementAnchorReceiptFixture& fixture)
{
    const std::vector<shielded::BridgeProofDescriptor> descriptors{fixture.descriptor};
    const auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(descriptors, /*required_receipts=*/1);
    BOOST_REQUIRE(proof_policy.has_value());
    fixture.statement.proof_policy = *proof_policy;

    fixture.witness.statement = fixture.statement;
    if (fixture.witness.proof_receipts.size() == 1) {
        fixture.receipt.statement_hash = shielded::ComputeBridgeBatchStatementHash(fixture.statement);
        fixture.witness.proof_receipts.front() = fixture.receipt;
    }
    fixture.witness.imported_adapters = fixture.imported_adapters;
    if (fixture.witness.descriptor_proof.has_value()) {
        fixture.witness.descriptor_proof =
            shielded::BuildBridgeProofPolicyProof(descriptors, fixture.descriptor);
        BOOST_REQUIRE(fixture.witness.descriptor_proof.has_value());
    }
    BOOST_REQUIRE(fixture.witness.IsValid());

    DataStream witness_stream;
    witness_stream << fixture.witness;
    const auto* witness_begin = reinterpret_cast<const unsigned char*>(witness_stream.data());
    std::vector<uint8_t> proof_payload(witness_begin, witness_begin + witness_stream.size());

    const auto abstract_context =
        v2proof::DescribeImportedSettlementReceipt(fixture.receipt,
                                                   v2proof::PayloadLocation::INLINE_WITNESS,
                                                   proof_payload,
                                                   fixture.descriptor,
                                                   fixture.verification_bundle);

    const auto settlement_anchor =
        shielded::BuildBridgeExternalAnchorFromProofReceipts(fixture.statement,
                                                             fixture.witness.proof_receipts);
    BOOST_REQUIRE(settlement_anchor.has_value());
    fixture.settlement_anchor_digest =
        v2proof::ComputeSettlementExternalAnchorDigest(*settlement_anchor);

    shielded::v2::SettlementAnchorPayload payload;
    payload.proof_receipt_ids = test::shielded::CollectCanonicalProofReceiptIds(
        Span<const shielded::BridgeProofReceipt>{fixture.witness.proof_receipts.data(),
                                                fixture.witness.proof_receipts.size()});
    if (!fixture.imported_adapters.empty()) {
        payload.imported_adapter_ids.reserve(fixture.imported_adapters.size());
        for (const auto& adapter : fixture.imported_adapters) {
            payload.imported_adapter_ids.push_back(shielded::ComputeBridgeProofAdapterId(adapter));
        }
        std::sort(payload.imported_adapter_ids.begin(), payload.imported_adapter_ids.end());
    }
    payload.batch_statement_digests = {shielded::ComputeBridgeBatchStatementHash(fixture.statement)};

    shielded::v2::TransactionBundle bundle;
    bundle.header.family_id = shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR;
    bundle.header.proof_envelope = abstract_context.material.statement.envelope;
    bundle.payload = payload;

    auto proof_shard = abstract_context.material.proof_shards.front();
    proof_shard.settlement_domain = fixture.statement.domain_id;
    bundle.proof_shards = {proof_shard};
    bundle.proof_payload = proof_payload;
    bundle.header.payload_digest = shielded::v2::ComputeSettlementAnchorPayloadDigest(payload);
    bundle.header.proof_shard_root = shielded::v2::ComputeProofShardRoot(
        Span<const shielded::v2::ProofShardDescriptor>{bundle.proof_shards.data(),
                                                       bundle.proof_shards.size()});
    bundle.header.proof_shard_count = bundle.proof_shards.size();
    BOOST_REQUIRE(bundle.IsValid());

    fixture.tx.shielded_bundle.v2_bundle = bundle;
}

CShieldedBundle BuildProofBundle(CAmount value_balance = 0, const uint256& tx_binding_hash = uint256{})
{
    CShieldedBundle bundle;
    const std::vector<unsigned char> spending_key(32, 0x42);
    bundle.value_balance = value_balance;

    CShieldedInput spend;
    spend.ring_positions.reserve(shielded::lattice::RING_SIZE);
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        spend.ring_positions.push_back(i);
    }

    ShieldedNote in_note;
    in_note.value = 5000;
    in_note.recipient_pk_hash = GetRandHash();
    in_note.rho = GetRandHash();
    in_note.rcm = GetRandHash();

    ShieldedNote out_note;
    out_note.value = 5000 - value_balance;
    out_note.recipient_pk_hash = GetRandHash();
    out_note.rho = GetRandHash();
    out_note.rcm = GetRandHash();

    CShieldedOutput out;
    out.note_commitment = out_note.GetCommitment();
    out.merkle_anchor = GetRandHash();
    out.encrypted_note.aead_ciphertext.assign(AEADChaCha20Poly1305::EXPANSION, 0x00);
    bundle.shielded_outputs.push_back(out);
    bundle.shielded_inputs.push_back(spend);

    std::vector<ShieldedNote> input_notes{in_note};
    std::vector<ShieldedNote> output_notes{out_note};

    const auto ring_members = BuildRingMembers(bundle);
    BOOST_REQUIRE(ring_members.size() == 1);
    BOOST_REQUIRE(ring_members[0].size() == shielded::lattice::RING_SIZE);
    BOOST_REQUIRE(DeriveInputNullifierForNote(bundle.shielded_inputs[0].nullifier,
                                              spending_key,
                                              in_note,
                                              ring_members[0][0]));
    std::vector<Nullifier> input_nullifiers;
    input_nullifiers.reserve(bundle.shielded_inputs.size());
    for (const auto& in : bundle.shielded_inputs) {
        input_nullifiers.push_back(in.nullifier);
    }
    std::vector<size_t> real_indices{0};

    uint256 effective_binding_hash = tx_binding_hash;
    if (effective_binding_hash.IsNull()) {
        CMutableTransaction binding_tx;
        binding_tx.shielded_bundle = bundle;
        effective_binding_hash = shielded::ringct::ComputeMatRiCTBindingHash(binding_tx);
    }

    MatRiCTProof proof;
    const bool created = CreateMatRiCTProof(proof,
                                            input_notes,
                                            output_notes,
                                            input_nullifiers,
                                            ring_members,
                                            real_indices,
                                            spending_key,
                                            value_balance,
                                            effective_binding_hash);
    BOOST_REQUIRE(created);

    DataStream ds;
    ds << proof;
    const auto* begin = reinterpret_cast<const unsigned char*>(ds.data());
    bundle.proof.assign(begin, begin + ds.size());
    return bundle;
}

struct V2SendFixture {
    CMutableTransaction tx;
    shielded::ShieldedMerkleTree tree;
    std::map<uint256, smile2::CompactPublicAccount> public_accounts;
    std::map<uint256, uint256> account_leaf_commitments;
    const Consensus::Params* consensus{nullptr};
    int32_t validation_height{std::numeric_limits<int32_t>::max()};
};

uint256 ComputeFixtureStatementDigest(const V2SendFixture& fixture)
{
    if (fixture.consensus != nullptr) {
        return v2proof::ComputeV2SendStatementDigest(CTransaction{fixture.tx},
                                                     *fixture.consensus,
                                                     fixture.validation_height);
    }
    return v2proof::ComputeV2SendStatementDigest(CTransaction{fixture.tx});
}

v2proof::ProofStatement DescribeFixtureStatement(const V2SendFixture& fixture)
{
    if (fixture.consensus != nullptr) {
        return v2proof::DescribeV2SendStatement(CTransaction{fixture.tx},
                                                *fixture.consensus,
                                                fixture.validation_height);
    }
    return v2proof::DescribeV2SendStatement(CTransaction{fixture.tx});
}

bool FixtureUsesBoundSmileAnonsetContext(const V2SendFixture& fixture)
{
    return fixture.consensus != nullptr &&
           fixture.consensus->IsShieldedMatRiCTDisabled(fixture.validation_height);
}

void RefreshFixtureEnvelopeDigests(V2SendFixture& fixture)
{
    auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;
    bundle.header.proof_envelope.extension_digest =
        v2proof::ComputeV2SendExtensionDigest(CTransaction{fixture.tx});
    bundle.header.proof_envelope.statement_digest = ComputeFixtureStatementDigest(fixture);
}

void RefreshFixtureWireOutputChunks(shielded::v2::TransactionBundle& bundle)
{
    bundle.output_chunks.clear();
    bundle.header.output_chunk_count = 0;
    bundle.header.output_chunk_root = uint256::ZERO;

    if (!shielded::v2::UseDerivedGenericOutputChunkWire(bundle.header, bundle.payload)) {
        return;
    }

    auto output_chunks = shielded::v2::BuildDerivedGenericOutputChunks(bundle.payload);
    BOOST_REQUIRE(output_chunks.has_value());
    bundle.output_chunks = std::move(*output_chunks);
    bundle.header.output_chunk_count = bundle.output_chunks.size();
    bundle.header.output_chunk_root = bundle.output_chunks.empty()
        ? uint256::ZERO
        : shielded::v2::ComputeOutputChunkRoot(
              Span<const shielded::v2::OutputChunkDescriptor>{bundle.output_chunks.data(),
                                                              bundle.output_chunks.size()});
}

void ReplaceFixtureWitness(V2SendFixture& fixture, const v2proof::V2SendWitness& witness)
{
    auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;
    DataStream witness_stream;
    witness_stream << witness;
    const auto* witness_begin = reinterpret_cast<const unsigned char*>(witness_stream.data());
    bundle.proof_payload.assign(witness_begin, witness_begin + witness_stream.size());
}

void AssertV2SendFixtureVerifies(const V2SendFixture& fixture,
                                 bool reject_rice_codec = false)
{
    const CTransaction tx{fixture.tx};
    BOOST_REQUIRE(tx.HasShieldedBundle());
    const auto* v2_bundle = tx.GetShieldedBundle().GetV2Bundle();
    BOOST_REQUIRE(v2_bundle != nullptr);
    BOOST_REQUIRE_EQUAL(v2_bundle->header.family_id,
                        shielded::v2::GetWireTransactionFamilyForValidationHeight(
                            shielded::v2::TransactionFamily::V2_SEND,
                            fixture.consensus,
                            fixture.validation_height));
    BOOST_REQUIRE(shielded::v2::BundleHasSemanticFamily(*v2_bundle,
                                                        shielded::v2::TransactionFamily::V2_SEND));

    const uint256 expected_extension_digest = v2proof::ComputeV2SendExtensionDigest(tx);
    BOOST_REQUIRE_EQUAL(v2_bundle->header.proof_envelope.extension_digest, expected_extension_digest);
    BOOST_REQUIRE_EQUAL(v2_bundle->header.proof_envelope.statement_digest,
                        ComputeFixtureStatementDigest(fixture));

    std::string reject_reason;
    const auto statement =
        fixture.consensus != nullptr
            ? v2proof::DescribeV2SendStatement(tx,
                                               *fixture.consensus,
                                               fixture.validation_height,
                                               expected_extension_digest)
            : v2proof::DescribeV2SendStatement(tx, expected_extension_digest);
    const auto context = v2proof::ParseV2SendProof(*v2_bundle, statement, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);

    const auto& payload = std::get<shielded::v2::SendPayload>(v2_bundle->payload);
    BOOST_REQUIRE(context->IsValid(payload.spends.size(), payload.outputs.size()));

    const auto ring_members = v2proof::BuildV2SendSmileRingMembers(*v2_bundle,
                                                                   *context,
                                                                   fixture.tree,
                                                                   fixture.public_accounts,
                                                                   fixture.account_leaf_commitments,
                                                                   reject_reason);
    BOOST_REQUIRE_MESSAGE(ring_members.has_value(), reject_reason);
    BOOST_REQUIRE(v2proof::VerifyV2SendProof(*v2_bundle,
                                             *context,
                                             *ring_members,
                                             reject_rice_codec,
                                             FixtureUsesBoundSmileAnonsetContext(fixture)));
}

V2SendFixture BuildV2SendFixture(CAmount fee = 0,
                                 smile2::SmileProofCodecPolicy codec_policy =
                                     smile2::SmileProofCodecPolicy::CANONICAL_NO_RICE,
                                 const Consensus::Params* consensus = nullptr,
                                 int32_t validation_height = std::numeric_limits<int32_t>::max())
{
    using namespace shielded::v2;

    V2SendFixture fixture;
    fixture.consensus = consensus != nullptr ? consensus : &Params().GetConsensus();
    fixture.validation_height = validation_height;
    const size_t real_index = 3;
    const size_t tree_member_count = fixture.consensus->IsShieldedMatRiCTDisabled(fixture.validation_height)
        ? shielded::ringct::GetMinimumPrivacyTreeSize(shielded::lattice::RING_SIZE)
        : shielded::lattice::RING_SIZE;
    const std::vector<uint64_t> ring_positions = [] {
        std::vector<uint64_t> positions;
        positions.reserve(shielded::lattice::RING_SIZE);
        for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
            positions.push_back(i);
        }
        return positions;
    }();

    ShieldedNote in_note;
    in_note.value = 5000;
    in_note.recipient_pk_hash = uint256{0x61};
    in_note.rho = uint256{0x62};
    in_note.rcm = uint256{0x63};

    ShieldedNote out_note;
    out_note.value = 5000 - fee;
    out_note.recipient_pk_hash = uint256{0x64};
    out_note.rho = uint256{0x65};
    out_note.rcm = uint256{0x66};

    std::vector<smile2::wallet::SmileRingMember> ring_members;
    ring_members.reserve(shielded::lattice::RING_SIZE);
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        ShieldedNote ring_note;
        if (i == real_index) {
            ring_note = in_note;
        } else {
            ring_note.value = 4000 + static_cast<CAmount>(i);
            ring_note.recipient_pk_hash = uint256{static_cast<unsigned char>(0x80 + i)};
            ring_note.rho = uint256{static_cast<unsigned char>(0x90 + i)};
            ring_note.rcm = uint256{static_cast<unsigned char>(0xa0 + i)};
        }

        auto account = smile2::wallet::BuildCompactPublicAccountFromNote(
            smile2::wallet::SMILE_GLOBAL_SEED,
            ring_note);
        BOOST_REQUIRE(account.has_value());
        const uint256 ring_commitment = smile2::ComputeCompactPublicAccountHash(*account);
        const auto account_leaf_commitment = shielded::registry::ComputeAccountLeafCommitmentFromNote(
            ring_note,
            ring_commitment,
            shielded::registry::MakeDirectSendAccountLeafHint());
        BOOST_REQUIRE(account_leaf_commitment.has_value());

        fixture.tree.Append(ring_commitment);
        fixture.public_accounts.emplace(ring_commitment, *account);
        fixture.account_leaf_commitments.emplace(ring_commitment, *account_leaf_commitment);

        std::optional<smile2::wallet::SmileRingMember> member;
        if (i == real_index) {
            member = smile2::wallet::BuildRingMemberFromNote(smile2::wallet::SMILE_GLOBAL_SEED,
                                                             ring_note,
                                                             ring_commitment,
                                                             *account_leaf_commitment);
        } else {
            member = smile2::wallet::BuildRingMemberFromCompactPublicAccount(
                smile2::wallet::SMILE_GLOBAL_SEED,
                ring_commitment,
                *account,
                *account_leaf_commitment);
        }
        BOOST_REQUIRE(member.has_value());
        ring_members.push_back(std::move(*member));
    }

    smile2::wallet::SmileInputMaterial smile_input;
    smile_input.note = in_note;
    smile_input.note_commitment = ring_members[real_index].note_commitment;
    smile_input.account_leaf_commitment = ring_members[real_index].account_leaf_commitment;
    smile_input.ring_index = real_index;

    const std::vector<uint8_t> entropy(32, 0x37);
    std::vector<uint256> serial_hashes;
    auto smile_result = smile2::wallet::CreateSmileProof(
        smile2::wallet::SMILE_GLOBAL_SEED,
        {smile_input},
        {out_note},
        Span<const smile2::wallet::SmileRingMember>{ring_members.data(), ring_members.size()},
        Span<const uint8_t>(entropy),
        serial_hashes,
        fee,
        codec_policy,
        FixtureUsesBoundSmileAnonsetContext(fixture));
    BOOST_REQUIRE(smile_result.has_value());
    BOOST_REQUIRE_EQUAL(serial_hashes.size(), 1U);

    for (size_t i = shielded::lattice::RING_SIZE; i < tree_member_count; ++i) {
        ShieldedNote filler_note;
        filler_note.value = 4500 + static_cast<CAmount>(i);
        filler_note.recipient_pk_hash = uint256{static_cast<unsigned char>(0xb0 + (i & 0x3f))};
        filler_note.rho = uint256{static_cast<unsigned char>(0xc0 + (i & 0x3f))};
        filler_note.rcm = uint256{static_cast<unsigned char>(0xd0 + (i & 0x3f))};

        auto filler_account = smile2::wallet::BuildCompactPublicAccountFromNote(
            smile2::wallet::SMILE_GLOBAL_SEED,
            filler_note);
        BOOST_REQUIRE(filler_account.has_value());
        const uint256 filler_commitment = smile2::ComputeCompactPublicAccountHash(*filler_account);
        const auto filler_leaf_commitment = shielded::registry::ComputeAccountLeafCommitmentFromNote(
            filler_note,
            filler_commitment,
            shielded::registry::MakeDirectSendAccountLeafHint());
        BOOST_REQUIRE(filler_leaf_commitment.has_value());

        fixture.tree.Append(filler_commitment);
        fixture.public_accounts.emplace(filler_commitment, *filler_account);
        fixture.account_leaf_commitments.emplace(filler_commitment, *filler_leaf_commitment);
    }

    SpendDescription spend;
    spend.nullifier = serial_hashes[0];
    spend.merkle_anchor = fixture.tree.Root();
    spend.account_leaf_commitment = ring_members[real_index].account_leaf_commitment;
    const auto account_registry_witness = test::shielded::MakeSingleLeafRegistryWitness(
        ring_members[real_index].note_commitment,
        fixture.public_accounts.at(ring_members[real_index].note_commitment));
    BOOST_REQUIRE(account_registry_witness.has_value());
    spend.account_registry_proof = account_registry_witness->second;
    spend.value_commitment = smile2::ComputeSmileDirectInputBindingHash(
        Span<const smile2::wallet::SmileRingMember>{ring_members.data(), ring_members.size()},
        fixture.tree.Root(),
        0,
        spend.nullifier);

    OutputDescription output;
    output.note_class = NoteClass::USER;
    output.smile_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        out_note);
    BOOST_REQUIRE(output.smile_account.has_value());
    output.note_commitment = smile2::ComputeCompactPublicAccountHash(*output.smile_account);
    output.value_commitment = smile2::ComputeSmileOutputCoinHash(output.smile_account->public_coin);
    output.encrypted_note.scan_domain = ScanDomain::OPAQUE;
    output.encrypted_note.scan_hint.fill(0x31);
    output.encrypted_note.ciphertext = {0x51, 0x52, 0x53};
    output.encrypted_note.ephemeral_key = shielded::v2::ComputeLegacyPayloadEphemeralKey(
        Span<const uint8_t>{output.encrypted_note.ciphertext.data(), output.encrypted_note.ciphertext.size()});

    SendPayload payload;
    payload.spend_anchor = fixture.tree.Root();
    payload.account_registry_anchor = account_registry_witness->first;
    payload.output_encoding =
        fixture.consensus->IsShieldedMatRiCTDisabled(fixture.validation_height)
            ? SendOutputEncoding::SMILE_COMPACT_POSTFORK
            : SendOutputEncoding::SMILE_COMPACT;
    payload.output_note_class = NoteClass::USER;
    payload.output_scan_domain = ScanDomain::OPAQUE;
    payload.spends = {spend};
    payload.outputs = {output};
    payload.fee = fee;
    payload.value_balance = payload.fee;

    TransactionBundle tx_bundle;
    tx_bundle.header.family_id = GetWireTransactionFamilyForValidationHeight(
        TransactionFamily::V2_SEND,
        fixture.consensus,
        fixture.validation_height);
    tx_bundle.header.proof_envelope.proof_kind = GetWireProofKindForValidationHeight(
        TransactionFamily::V2_SEND,
        ProofKind::DIRECT_SMILE,
        fixture.consensus,
        fixture.validation_height);
    tx_bundle.header.proof_envelope.membership_proof_kind =
        GetWireProofComponentKindForValidationHeight(ProofComponentKind::SMILE_MEMBERSHIP,
                                                     fixture.consensus,
                                                     fixture.validation_height);
    tx_bundle.header.proof_envelope.amount_proof_kind =
        GetWireProofComponentKindForValidationHeight(ProofComponentKind::SMILE_BALANCE,
                                                     fixture.consensus,
                                                     fixture.validation_height);
    tx_bundle.header.proof_envelope.balance_proof_kind =
        GetWireProofComponentKindForValidationHeight(ProofComponentKind::SMILE_BALANCE,
                                                     fixture.consensus,
                                                     fixture.validation_height);
    tx_bundle.header.proof_envelope.settlement_binding_kind =
        GetWireSettlementBindingKindForValidationHeight(TransactionFamily::V2_SEND,
                                                        SettlementBindingKind::NONE,
                                                        fixture.consensus,
                                                        fixture.validation_height);
    tx_bundle.payload = payload;
    tx_bundle.header.payload_digest = ComputeSendPayloadDigest(payload);
    RefreshFixtureWireOutputChunks(tx_bundle);
    fixture.tx.shielded_bundle.v2_bundle = tx_bundle;

    tx_bundle.header.proof_envelope.statement_digest = ComputeFixtureStatementDigest(fixture);

    shielded::v2::proof::V2SendWitness witness;
    shielded::v2::proof::V2SendSpendWitness spend_witness;
    spend_witness.real_index = 0;
    spend_witness.ring_positions = ring_positions;
    witness.spends = {spend_witness};
    witness.use_smile = true;
    witness.smile_proof_bytes = smile_result->proof_bytes;
    witness.smile_output_coins = smile_result->output_coins;

    DataStream witness_stream;
    witness_stream << witness;
    const auto* witness_begin = reinterpret_cast<const unsigned char*>(witness_stream.data());
    tx_bundle.proof_payload.assign(witness_begin, witness_begin + witness_stream.size());
    tx_bundle.payload = payload;
    tx_bundle.header.payload_digest = ComputeSendPayloadDigest(payload);
    RefreshFixtureWireOutputChunks(tx_bundle);
    fixture.tx.shielded_bundle.v2_bundle = tx_bundle;
    RefreshFixtureEnvelopeDigests(fixture);
    return fixture;
}

[[nodiscard]] CMutableTransaction BuildProoflessTransparentShieldingTx(
    CAmount output_value = 49'000,
    CAmount fee = 70'000,
    const Consensus::Params* consensus = nullptr,
    int32_t validation_height = std::numeric_limits<int32_t>::max())
{
    const ShieldedNote output_note = MakeNote(output_value, /*seed=*/0x73);
    const mlkem::KeyPair recipient = BuildRecipientKeyPair(/*seed=*/0x83);
    const shielded::EncryptedNote encrypted_note =
        BuildEncryptedNote(output_note, recipient.pk, /*kem_seed_byte=*/0x93, /*nonce_byte=*/0xa3);
    auto encrypted_payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        encrypted_note,
        recipient.pk,
        shielded::v2::ScanDomain::USER);
    BOOST_REQUIRE(encrypted_payload.has_value());

    shielded::v2::V2SendOutputInput output_input;
    output_input.note_class = shielded::v2::NoteClass::USER;
    output_input.note = output_note;
    output_input.encrypted_note = *encrypted_payload;
    BOOST_REQUIRE(output_input.IsValid());

    CMutableTransaction tx_template;
    tx_template.version = CTransaction::CURRENT_VERSION;
    tx_template.nLockTime = 29;
    tx_template.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{0x91}), 0});

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
    return built->tx;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(shielded_validation_checks_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(describe_shielded_v2_context_reports_expected_family_names)
{
    CShieldedBundle legacy_bundle;
    BOOST_CHECK_EQUAL(DescribeShieldedV2Context(legacy_bundle), "legacy-bundle");

    auto send_tx = BuildLegacyLifecycleSendTx(Params().GetConsensus(),
                                              Params().GetConsensus().nShieldedMatRiCTDisableHeight - 1);
    BOOST_REQUIRE(send_tx.HasShieldedBundle());
    BOOST_CHECK_EQUAL(DescribeShieldedV2Context(send_tx.GetShieldedBundle()), "v2-family-send");

    auto lifecycle_tx = BuildLifecycleControlTx();
    BOOST_REQUIRE(lifecycle_tx.HasShieldedBundle());
    BOOST_CHECK_EQUAL(DescribeShieldedV2Context(lifecycle_tx.GetShieldedBundle()),
                      "v2-family-lifecycle");

    auto generic_tx = BuildPostforkGenericSendLifecycleControlTx(
        Params().GetConsensus(),
        Params().GetConsensus().nShieldedMatRiCTDisableHeight);
    BOOST_REQUIRE(generic_tx.HasShieldedBundle());
    BOOST_CHECK_EQUAL(DescribeShieldedV2Context(generic_tx.GetShieldedBundle()), "v2-family-send");

    BOOST_CHECK_EQUAL(ShieldedV2FamilyName(shielded::v2::TransactionFamily::V2_INGRESS_BATCH),
                      "ingress-batch");
    BOOST_CHECK_EQUAL(ShieldedV2FamilyName(shielded::v2::TransactionFamily::V2_GENERIC),
                      "generic");
    BOOST_CHECK_EQUAL(ShieldedV2FamilyName(shielded::v2::V2_SPEND_PATH_RECOVERY),
                      "spend-path-recovery");
}

BOOST_AUTO_TEST_CASE(proof_check_accepts_valid_bundle)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildProofBundle();
    const CTransaction tx{mtx};

    shielded::ShieldedMerkleTree tree;
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        HashWriter hw;
        hw << std::string{"BTX_Shielded_RingMember_V1"};
        hw << static_cast<uint64_t>(i);
        tree.Append(hw.GetSHA256());
    }

    CShieldedProofCheck check = MakeLegacyProofCheck(tx, tree);
    const auto res = check();
    BOOST_CHECK(!res.has_value());
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_tampered_proof)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildProofBundle();
    mtx.shielded_bundle.proof.back() ^= 0x01;
    const CTransaction tx{mtx};

    shielded::ShieldedMerkleTree tree;
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        HashWriter hw;
        hw << std::string{"BTX_Shielded_RingMember_V1"};
        hw << static_cast<uint64_t>(i);
        tree.Append(hw.GetSHA256());
    }

    CShieldedProofCheck check = MakeLegacyProofCheck(tx, tree);
    const auto res = check();
    BOOST_CHECK(res.has_value());
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_malformed_proof_shape_encoding)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildProofBundle();

    DataStream proof_ds{mtx.shielded_bundle.proof};
    MatRiCTProof proof;
    proof_ds >> proof;
    // Force output-note commitment count mismatch relative to output commitments.
    proof.output_note_commitments.clear();

    DataStream tampered;
    tampered << proof;
    const auto* begin = reinterpret_cast<const unsigned char*>(tampered.data());
    mtx.shielded_bundle.proof.assign(begin, begin + tampered.size());
    const CTransaction tx{mtx};

    shielded::ShieldedMerkleTree tree;
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        HashWriter hw;
        hw << std::string{"BTX_Shielded_RingMember_V1"};
        hw << static_cast<uint64_t>(i);
        tree.Append(hw.GetSHA256());
    }

    CShieldedProofCheck check = MakeLegacyProofCheck(tx, tree);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-proof-encoding");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_value_balance_mismatch)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildProofBundle(/*value_balance=*/1000);
    mtx.shielded_bundle.value_balance = 1001;
    const CTransaction tx{mtx};

    shielded::ShieldedMerkleTree tree;
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        HashWriter hw;
        hw << std::string{"BTX_Shielded_RingMember_V1"};
        hw << static_cast<uint64_t>(i);
        tree.Append(hw.GetSHA256());
    }

    CShieldedProofCheck check = MakeLegacyProofCheck(tx, tree);
    const auto res = check();
    BOOST_CHECK(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-proof");
}

BOOST_AUTO_TEST_CASE(proof_check_accepts_valid_v2_send_bundle)
{
    auto fixture = BuildV2SendFixture();
    AssertV2SendFixtureVerifies(fixture);
    AssertV2SendFixtureVerifies(fixture, /*reject_rice_codec=*/true);
    const CTransaction tx{fixture.tx};
    BOOST_REQUIRE(tx.HasShieldedBundle());
    BOOST_REQUIRE(tx.GetShieldedBundle().GetV2Bundle() != nullptr);
    BOOST_CHECK(tx.GetShieldedBundle().GetV2Bundle()->IsValid());
    BOOST_CHECK(tx.GetShieldedBundle().CheckStructure());

    CShieldedProofCheck check(tx,
                              std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                              std::make_shared<const std::map<uint256, smile2::CompactPublicAccount>>(
                                  fixture.public_accounts),
                              std::make_shared<const std::map<uint256, uint256>>(
                                  fixture.account_leaf_commitments));
    const auto res = check();
    BOOST_CHECK_MESSAGE(!res.has_value(), res.value_or("ok"));
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_prefork_generic_v2_send_wire_family)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t prefork_height = consensus.nShieldedMatRiCTDisableHeight - 1;
    BOOST_REQUIRE(prefork_height >= 0);

    auto fixture = BuildV2SendFixture(/*fee=*/0,
                                      smile2::SmileProofCodecPolicy::CANONICAL_NO_RICE,
                                      &consensus,
                                      prefork_height);
    auto* bundle = fixture.tx.shielded_bundle.v2_bundle ? &*fixture.tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(bundle != nullptr);
    bundle->header.family_id = shielded::v2::TransactionFamily::V2_GENERIC;
    RefreshFixtureWireOutputChunks(*bundle);

    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(tx,
                              consensus,
                              prefork_height,
                              std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                              std::make_shared<const std::map<uint256, smile2::CompactPublicAccount>>(
                                  fixture.public_accounts),
                              std::make_shared<const std::map<uint256, uint256>>(
                                  fixture.account_leaf_commitments));
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-family-wire");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_postfork_legacy_v2_send_wire_family)
{
    auto fixture = BuildV2SendFixture();
    auto* bundle = fixture.tx.shielded_bundle.v2_bundle ? &*fixture.tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(bundle != nullptr);
    bundle->header.family_id = shielded::v2::TransactionFamily::V2_SEND;
    RefreshFixtureWireOutputChunks(*bundle);

    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(tx,
                              *fixture.consensus,
                              fixture.validation_height,
                              std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                              std::make_shared<const std::map<uint256, smile2::CompactPublicAccount>>(
                                  fixture.public_accounts),
                              std::make_shared<const std::map<uint256, uint256>>(
                                  fixture.account_leaf_commitments));
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-family-wire");
}

struct SpendPathRecoveryFixture {
    CMutableTransaction tx;
    shielded::ShieldedMerkleTree tree;
    const Consensus::Params* consensus{nullptr};
    int32_t validation_height{0};
    uint256 input_note_commitment;
    uint256 input_account_leaf_commitment;
};

SpendPathRecoveryFixture BuildSpendPathRecoveryFixture(
    const Consensus::Params* consensus = nullptr,
    int32_t validation_height = std::numeric_limits<int32_t>::max())
{
    SpendPathRecoveryFixture fixture;
    fixture.consensus = consensus != nullptr ? consensus : &Params().GetConsensus();
    if (validation_height == std::numeric_limits<int32_t>::max()) {
        validation_height = fixture.consensus->nShieldedMatRiCTDisableHeight;
    }
    fixture.validation_height = validation_height;

    btx::test::shielded::SpendPathRecoveryFixtureBuildInput input;
    input.validation_height = validation_height;
    input.matrict_disable_height = fixture.consensus->nShieldedMatRiCTDisableHeight;
    input.legacy_shield_fee = 1'000;
    input.recovery_fee = shielded::SHIELDED_PRIVACY_FEE_QUANTUM;
    input.legacy_funding_inputs.resize(3);
    for (size_t i = 0; i < input.legacy_funding_inputs.size(); ++i) {
        input.legacy_funding_inputs[i].funding_outpoint =
            COutPoint{Txid::FromUint256(uint256{static_cast<unsigned char>(0x30 + i)}), 0};
        input.legacy_funding_inputs[i].funding_value = 60'000 + static_cast<CAmount>(i) * 1'000;
    }

    std::string reject_reason;
    const auto built = btx::test::shielded::BuildSpendPathRecoveryFixture(input, reject_reason);
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);

    fixture.tx = built->recovery_tx;
    fixture.input_note_commitment = built->recovery_input_note_commitment;
    for (const auto& commitment : built->legacy_note_commitments) {
        fixture.tree.Append(commitment);
    }
    const auto& payload =
        std::get<shielded::v2::SpendPathRecoveryPayload>(fixture.tx.shielded_bundle.v2_bundle->payload);
    BOOST_REQUIRE_EQUAL(payload.spends.size(), 1U);
    fixture.input_account_leaf_commitment = payload.spends.front().account_leaf_commitment;
    return fixture;
}

void RefreshSpendPathRecoveryFixturePayload(SpendPathRecoveryFixture& fixture)
{
    auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;
    const auto& payload = std::get<shielded::v2::SpendPathRecoveryPayload>(bundle.payload);
    bundle.header.payload_digest = shielded::v2::ComputeSpendPathRecoveryPayloadDigest(payload);
    RefreshFixtureWireOutputChunks(bundle);
    bundle.header.proof_envelope.statement_digest =
        shielded::v2::proof::ComputeSpendPathRecoveryStatementDigest(CTransaction{fixture.tx});
    BOOST_REQUIRE(bundle.IsValid());
}

BOOST_AUTO_TEST_CASE(postfork_spend_path_recovery_bundle_is_serializable)
{
    auto fixture = BuildSpendPathRecoveryFixture();
    auto* bundle = fixture.tx.shielded_bundle.v2_bundle ? &*fixture.tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(bundle != nullptr);

    DataStream ss{};
    BOOST_CHECK_NO_THROW(ss << *bundle);

    shielded::v2::TransactionBundle decoded;
    BOOST_CHECK_NO_THROW(ss >> decoded);
    BOOST_REQUIRE(decoded.IsValid());
    BOOST_CHECK(shielded::v2::BundleHasSemanticFamily(decoded, shielded::v2::V2_SPEND_PATH_RECOVERY));
    BOOST_CHECK(std::holds_alternative<shielded::v2::SpendPathRecoveryPayload>(decoded.payload));
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_postfork_spend_path_recovery_when_feature_is_disabled)
{
    auto fixture = BuildSpendPathRecoveryFixture();

    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(
        tx,
        *fixture.consensus,
        fixture.validation_height,
        std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
        nullptr,
        std::make_shared<const std::map<uint256, uint256>>());
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-matrict-disabled");
}

BOOST_AUTO_TEST_CASE(proof_check_accepts_postfork_spend_path_recovery_when_activated)
{
    auto consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    BOOST_REQUIRE(activation_height >= 0);
    consensus.nShieldedSpendPathRecoveryActivationHeight = activation_height;

    auto fixture = BuildSpendPathRecoveryFixture(&consensus, activation_height);
    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(
        tx,
        consensus,
        activation_height,
        std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
        nullptr,
        std::make_shared<const std::map<uint256, uint256>>());
    const auto res = check();
    BOOST_CHECK_MESSAGE(!res.has_value(), res.value_or("unexpected spend-path recovery failure"));
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_prefork_validation_of_postfork_recovery_wire)
{
    auto consensus = Params().GetConsensus();
    const int32_t postfork_height = consensus.nShieldedMatRiCTDisableHeight;
    const int32_t prefork_height = postfork_height - 1;
    BOOST_REQUIRE(prefork_height > 0);
    consensus.nShieldedSpendPathRecoveryActivationHeight = prefork_height;

    auto fixture = BuildSpendPathRecoveryFixture(&consensus, postfork_height);
    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(
        tx,
        consensus,
        prefork_height,
        std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
        nullptr,
        std::make_shared<const std::map<uint256, uint256>>());
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-family-wire");
}

BOOST_AUTO_TEST_CASE(proof_check_postfork_spend_path_recovery_enforces_activation_boundary)
{
    auto consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight + 1;
    consensus.nShieldedSpendPathRecoveryActivationHeight = activation_height;

    auto fixture = BuildSpendPathRecoveryFixture(&consensus, activation_height);
    const auto tree = std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree);
    const auto empty_leaves = std::make_shared<const std::map<uint256, uint256>>();
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck pre_activation_check(
        tx,
        consensus,
        activation_height - 1,
        tree,
        nullptr,
        empty_leaves);
    const auto pre_activation_result = pre_activation_check();
    BOOST_REQUIRE(pre_activation_result.has_value());
    BOOST_CHECK_EQUAL(*pre_activation_result, "bad-shielded-matrict-disabled");

    CShieldedProofCheck at_activation_check(
        tx,
        consensus,
        activation_height,
        tree,
        nullptr,
        empty_leaves);
    const auto at_activation_result = at_activation_check();
    BOOST_CHECK_MESSAGE(!at_activation_result.has_value(),
                        at_activation_result.value_or("unexpected postfork activation-boundary failure"));
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_postfork_activated_spend_path_recovery_for_non_stranded_note)
{
    auto consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    consensus.nShieldedSpendPathRecoveryActivationHeight = activation_height;

    auto fixture = BuildSpendPathRecoveryFixture(&consensus, activation_height);
    std::map<uint256, uint256> account_leaf_commitments{
        {fixture.input_note_commitment, fixture.input_account_leaf_commitment},
    };

    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(
        tx,
        consensus,
        activation_height,
        std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
        nullptr,
        std::make_shared<const std::map<uint256, uint256>>(account_leaf_commitments));
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-spend-path-recovery-not-stranded");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_postfork_activated_spend_path_recovery_with_tampered_nullifier)
{
    auto consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    BOOST_REQUIRE(activation_height >= 0);
    consensus.nShieldedSpendPathRecoveryActivationHeight = activation_height;

    auto fixture = BuildSpendPathRecoveryFixture(&consensus, activation_height);
    auto* bundle = fixture.tx.shielded_bundle.v2_bundle ? &*fixture.tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(bundle != nullptr);
    auto& payload = std::get<shielded::v2::SpendPathRecoveryPayload>(bundle->payload);
    payload.spends[0].nullifier = uint256{0x54};
    RefreshSpendPathRecoveryFixturePayload(fixture);

    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(
        tx,
        consensus,
        activation_height,
        std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
        nullptr,
        std::make_shared<const std::map<uint256, uint256>>());
    const auto res = check();
    BOOST_REQUIRE_MESSAGE(res.has_value(), "expected reject for tampered postfork spend-path recovery nullifier");
    BOOST_CHECK_EQUAL(*res, "bad-shielded-proof");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_prefork_generic_v2_send_proof_wire)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t prefork_height = consensus.nShieldedMatRiCTDisableHeight - 1;
    BOOST_REQUIRE(prefork_height >= 0);

    auto fixture = BuildV2SendFixture(/*fee=*/0,
                                      smile2::SmileProofCodecPolicy::CANONICAL_NO_RICE,
                                      &consensus,
                                      prefork_height);
    auto* bundle = fixture.tx.shielded_bundle.v2_bundle ? &*fixture.tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(bundle != nullptr);
    bundle->header.proof_envelope.proof_kind = shielded::v2::ProofKind::GENERIC_OPAQUE;

    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(tx,
                              consensus,
                              prefork_height,
                              std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                              std::make_shared<const std::map<uint256, smile2::CompactPublicAccount>>(
                                  fixture.public_accounts),
                              std::make_shared<const std::map<uint256, uint256>>(
                                  fixture.account_leaf_commitments));
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-proof-wire");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_postfork_legacy_v2_send_proof_wire)
{
    auto fixture = BuildV2SendFixture();
    auto* bundle = fixture.tx.shielded_bundle.v2_bundle ? &*fixture.tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(bundle != nullptr);
    bundle->header.proof_envelope.proof_kind = shielded::v2::ProofKind::DIRECT_SMILE;

    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(tx,
                              *fixture.consensus,
                              fixture.validation_height,
                              std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                              std::make_shared<const std::map<uint256, smile2::CompactPublicAccount>>(
                                  fixture.public_accounts),
                              std::make_shared<const std::map<uint256, uint256>>(
                                  fixture.account_leaf_commitments));
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-proof-wire");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_prefork_generic_v2_send_binding_wire)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t prefork_height = consensus.nShieldedMatRiCTDisableHeight - 1;
    BOOST_REQUIRE(prefork_height >= 0);

    auto fixture = BuildV2SendFixture(/*fee=*/0,
                                      smile2::SmileProofCodecPolicy::CANONICAL_NO_RICE,
                                      &consensus,
                                      prefork_height);
    auto* bundle = fixture.tx.shielded_bundle.v2_bundle ? &*fixture.tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(bundle != nullptr);
    bundle->header.proof_envelope.settlement_binding_kind = shielded::v2::SettlementBindingKind::GENERIC_POSTFORK;

    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(tx,
                              consensus,
                              prefork_height,
                              std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                              std::make_shared<const std::map<uint256, smile2::CompactPublicAccount>>(
                                  fixture.public_accounts),
                              std::make_shared<const std::map<uint256, uint256>>(
                                  fixture.account_leaf_commitments));
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-binding-wire");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_postfork_legacy_v2_send_binding_wire)
{
    auto fixture = BuildV2SendFixture();
    auto* bundle = fixture.tx.shielded_bundle.v2_bundle ? &*fixture.tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(bundle != nullptr);
    bundle->header.proof_envelope.settlement_binding_kind = shielded::v2::SettlementBindingKind::NONE;

    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(tx,
                              *fixture.consensus,
                              fixture.validation_height,
                              std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                              std::make_shared<const std::map<uint256, smile2::CompactPublicAccount>>(
                                  fixture.public_accounts),
                              std::make_shared<const std::map<uint256, uint256>>(
                                  fixture.account_leaf_commitments));
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-binding-wire");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_v2_send_duplicate_ring_positions)
{
    auto fixture = BuildV2SendFixture();
    auto* bundle = fixture.tx.shielded_bundle.v2_bundle ? &*fixture.tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(bundle != nullptr);

    std::string reject_reason;
    auto witness = v2proof::ParseV2SendWitness(*bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(witness.has_value(), reject_reason);
    BOOST_REQUIRE_EQUAL(witness->spends.size(), 1U);
    BOOST_REQUIRE_GE(witness->spends[0].ring_positions.size(), 2U);
    witness->spends[0].ring_positions[1] = witness->spends[0].ring_positions[0];
    ReplaceFixtureWitness(fixture, *witness);

    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(tx,
                              std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                              std::make_shared<const std::map<uint256, smile2::CompactPublicAccount>>(
                                  fixture.public_accounts),
                              std::make_shared<const std::map<uint256, uint256>>(
                                  fixture.account_leaf_commitments));
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    // Contextual validation rejects this earlier with the more specific
    // ring-diversity code; the standalone proof-check path treats the mutated
    // witness as an invalid proof context.
    BOOST_CHECK_EQUAL(*res, "bad-shielded-proof");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_v2_send_subminimum_ring_size)
{
    auto fixture = BuildV2SendFixture();
    auto* bundle = fixture.tx.shielded_bundle.v2_bundle ? &*fixture.tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(bundle != nullptr);

    std::string reject_reason;
    auto witness = v2proof::ParseV2SendWitness(*bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(witness.has_value(), reject_reason);
    BOOST_REQUIRE_EQUAL(witness->spends.size(), 1U);
    witness->spends[0].ring_positions.resize(1);
    ReplaceFixtureWitness(fixture, *witness);

    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(tx,
                              std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                              std::make_shared<const std::map<uint256, smile2::CompactPublicAccount>>(
                                  fixture.public_accounts),
                              std::make_shared<const std::map<uint256, uint256>>(
                                  fixture.account_leaf_commitments));
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-ring-positions");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_v2_send_without_smile_account_snapshots)
{
    auto fixture = BuildV2SendFixture();
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx, std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree));
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-smile2-ring-member-account");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_v2_send_missing_public_account_snapshot_entry)
{
    auto fixture = BuildV2SendFixture();
    const auto missing_commitment = fixture.tree.CommitmentAt(0);
    BOOST_REQUIRE(missing_commitment.has_value());
    BOOST_REQUIRE_EQUAL(fixture.public_accounts.erase(*missing_commitment), 1U);

    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(tx,
                              std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                              std::make_shared<const std::map<uint256, smile2::CompactPublicAccount>>(
                                  fixture.public_accounts),
                              std::make_shared<const std::map<uint256, uint256>>(
                                  fixture.account_leaf_commitments));
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-smile2-ring-member-public-account");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_v2_send_missing_account_leaf_snapshot_entry)
{
    auto fixture = BuildV2SendFixture();
    const auto missing_commitment = fixture.tree.CommitmentAt(0);
    BOOST_REQUIRE(missing_commitment.has_value());
    BOOST_REQUIRE_EQUAL(fixture.account_leaf_commitments.erase(*missing_commitment), 1U);

    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(tx,
                              std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                              std::make_shared<const std::map<uint256, smile2::CompactPublicAccount>>(
                                  fixture.public_accounts),
                              std::make_shared<const std::map<uint256, uint256>>(
                                  fixture.account_leaf_commitments));
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-smile2-ring-member-account-leaf");
}

BOOST_AUTO_TEST_CASE(proof_check_v2_send_enforces_extension_digest_only_after_activation_height)
{
    auto consensus = Params().GetConsensus();
    consensus.nShieldedMatRiCTDisableHeight = consensus.nShieldedTxBindingActivationHeight + 1;
    auto fixture = BuildV2SendFixture(/*fee=*/0,
                                      smile2::SmileProofCodecPolicy::CANONICAL_NO_RICE,
                                      &consensus,
                                      consensus.nShieldedTxBindingActivationHeight);
    AssertV2SendFixtureVerifies(fixture);

    fixture.tx.shielded_bundle.v2_bundle->header.proof_envelope.extension_digest = uint256{0x6b};
    fixture.tx.shielded_bundle.v2_bundle->header.proof_envelope.statement_digest =
        ComputeFixtureStatementDigest(fixture);

    const CTransaction tx{fixture.tx};
    const auto tree = std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree);
    const auto public_accounts =
        std::make_shared<const std::map<uint256, smile2::CompactPublicAccount>>(fixture.public_accounts);
    const auto account_leaf_commitments =
        std::make_shared<const std::map<uint256, uint256>>(fixture.account_leaf_commitments);

    CShieldedProofCheck pre_activation_check(tx,
                                             consensus,
                                             consensus.nShieldedTxBindingActivationHeight - 1,
                                             tree,
                                             public_accounts,
                                             account_leaf_commitments);
    const auto pre_activation_result = pre_activation_check();
    BOOST_CHECK_MESSAGE(!pre_activation_result.has_value(), pre_activation_result.value_or("ok"));

    CShieldedProofCheck post_activation_check(tx,
                                              consensus,
                                              consensus.nShieldedTxBindingActivationHeight,
                                              tree,
                                              public_accounts,
                                              account_leaf_commitments);
    const auto post_activation_result = post_activation_check();
    BOOST_REQUIRE(post_activation_result.has_value());
    BOOST_CHECK_EQUAL(*post_activation_result, "bad-shielded-proof");
}

BOOST_AUTO_TEST_CASE(proof_check_v2_send_rejects_rice_codec_only_after_activation_height)
{
    auto consensus = Params().GetConsensus();
    consensus.nShieldedMatRiCTDisableHeight = consensus.nShieldedSmileRiceCodecDisableHeight + 1;
    auto fixture = BuildV2SendFixture(/*fee=*/0,
                                      smile2::SmileProofCodecPolicy::SMALLEST,
                                      &consensus,
                                      consensus.nShieldedSmileRiceCodecDisableHeight);

    auto* bundle = fixture.tx.shielded_bundle.v2_bundle ? &*fixture.tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(bundle != nullptr);

    std::string reject_reason;
    const auto statement = DescribeFixtureStatement(fixture);
    const auto context = v2proof::ParseV2SendProof(*bundle, statement, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);
    BOOST_REQUIRE(context->witness.use_smile);

    const auto& payload = std::get<shielded::v2::SendPayload>(bundle->payload);
    smile2::SmileCTProof parsed_proof;
    auto pre_activation_parse = smile2::ParseSmile2Proof(context->witness.smile_proof_bytes,
                                                         payload.spends.size(),
                                                         payload.outputs.size(),
                                                         parsed_proof);
    BOOST_REQUIRE_MESSAGE(!pre_activation_parse.has_value(), pre_activation_parse.value_or("ok"));
    auto post_activation_parse = smile2::ParseSmile2Proof(context->witness.smile_proof_bytes,
                                                          payload.spends.size(),
                                                          payload.outputs.size(),
                                                          parsed_proof,
                                                          /*reject_rice_codec=*/true);
    BOOST_REQUIRE(post_activation_parse.has_value());
    BOOST_CHECK_EQUAL(*post_activation_parse, "bad-smile2-proof-rice-codec");

    const CTransaction tx{fixture.tx};
    const auto tree = std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree);
    const auto public_accounts =
        std::make_shared<const std::map<uint256, smile2::CompactPublicAccount>>(fixture.public_accounts);
    const auto account_leaf_commitments =
        std::make_shared<const std::map<uint256, uint256>>(fixture.account_leaf_commitments);

    CShieldedProofCheck pre_activation_check(tx,
                                             consensus,
                                             consensus.nShieldedSmileRiceCodecDisableHeight - 1,
                                             tree,
                                             public_accounts,
                                             account_leaf_commitments);
    const auto pre_activation_result = pre_activation_check();
    BOOST_CHECK_MESSAGE(!pre_activation_result.has_value(), pre_activation_result.value_or("ok"));

    CShieldedProofCheck post_activation_check(tx,
                                              consensus,
                                              consensus.nShieldedSmileRiceCodecDisableHeight,
                                              tree,
                                              public_accounts,
                                              account_leaf_commitments);
    const auto post_activation_result = post_activation_check();
    BOOST_REQUIRE(post_activation_result.has_value());
    BOOST_CHECK_EQUAL(*post_activation_result, "bad-smile2-proof-rice-codec");
}

BOOST_AUTO_TEST_CASE(proof_check_v2_send_requires_hardened_smile_wire_version_at_activation_height)
{
    const auto& consensus = Params().GetConsensus();
    auto fixture = BuildV2SendFixture(/*fee=*/0,
                                      smile2::SmileProofCodecPolicy::CANONICAL_NO_RICE,
                                      &consensus,
                                      consensus.nShieldedMatRiCTDisableHeight);

    auto* bundle = fixture.tx.shielded_bundle.v2_bundle ? &*fixture.tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(bundle != nullptr);

    std::string reject_reason;
    const auto statement = DescribeFixtureStatement(fixture);
    const auto context = v2proof::ParseV2SendProof(*bundle, statement, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);
    BOOST_REQUIRE(context->witness.use_smile);
    BOOST_REQUIRE_GE(context->witness.smile_proof_bytes.size(), 5U);
    BOOST_CHECK_EQUAL(context->witness.smile_proof_bytes[0], 0xFF);
    BOOST_CHECK_EQUAL(context->witness.smile_proof_bytes[1], 0xFF);
    BOOST_CHECK_EQUAL(context->witness.smile_proof_bytes[2], 0xFF);
    BOOST_CHECK_EQUAL(context->witness.smile_proof_bytes[3], 0xFF);
    BOOST_CHECK_EQUAL(context->witness.smile_proof_bytes[4], smile2::SmileCTProof::WIRE_VERSION_M4_HARDENED);

    smile2::SmileCTProof parsed_proof;
    auto parse_err = smile2::ParseSmile2Proof(context->witness.smile_proof_bytes,
                                              context->witness.spends.size(),
                                              std::get<shielded::v2::SendPayload>(bundle->payload).outputs.size(),
                                              parsed_proof);
    BOOST_REQUIRE_MESSAGE(!parse_err.has_value(), parse_err.value_or("ok"));
    BOOST_CHECK_EQUAL(parsed_proof.wire_version, smile2::SmileCTProof::WIRE_VERSION_M4_HARDENED);

    const CTransaction accepted_tx{fixture.tx};
    const auto tree = std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree);
    const auto public_accounts =
        std::make_shared<const std::map<uint256, smile2::CompactPublicAccount>>(fixture.public_accounts);
    const auto account_leaf_commitments =
        std::make_shared<const std::map<uint256, uint256>>(fixture.account_leaf_commitments);

    CShieldedProofCheck accepted_check(accepted_tx,
                                       consensus,
                                       consensus.nShieldedMatRiCTDisableHeight,
                                       tree,
                                       public_accounts,
                                       account_leaf_commitments);
    const auto accepted_result = accepted_check();
    BOOST_CHECK_MESSAGE(!accepted_result.has_value(), accepted_result.value_or("ok"));

    CMutableTransaction legacy_tx{fixture.tx};
    auto legacy_witness = v2proof::ParseV2SendWitness(*bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(legacy_witness.has_value(), reject_reason);
    BOOST_REQUIRE(legacy_witness->use_smile);
    legacy_witness->smile_proof_bytes.erase(legacy_witness->smile_proof_bytes.begin(),
                                            legacy_witness->smile_proof_bytes.begin() + 5);
    ReplaceV2SendWitness(legacy_tx, *legacy_witness);

    const CTransaction rejected_tx{legacy_tx};
    CShieldedProofCheck rejected_check(rejected_tx,
                                       consensus,
                                       consensus.nShieldedMatRiCTDisableHeight,
                                       tree,
                                       public_accounts,
                                       account_leaf_commitments);
    const auto rejected_result = rejected_check();
    BOOST_REQUIRE(rejected_result.has_value());
    BOOST_CHECK_EQUAL(*rejected_result, "bad-shielded-proof");
}

BOOST_AUTO_TEST_CASE(proof_check_default_constructor_rejects_rice_codec_after_activation)
{
    auto fixture = BuildV2SendFixture(/*fee=*/0, smile2::SmileProofCodecPolicy::SMALLEST);
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx,
                              std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                              std::make_shared<const std::map<uint256, smile2::CompactPublicAccount>>(
                                  fixture.public_accounts),
                              std::make_shared<const std::map<uint256, uint256>>(
                                  fixture.account_leaf_commitments));
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-smile2-proof-rice-codec");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_legacy_matrict_after_disable_height)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildProofBundle();
    const CTransaction tx{mtx};
    const auto tree = std::make_shared<shielded::ShieldedMerkleTree>(BuildLegacyRingTree());
    const auto& consensus = Params().GetConsensus();

    CShieldedProofCheck pre_disable(tx,
                                    consensus,
                                    consensus.nShieldedMatRiCTDisableHeight - 1,
                                    tree);
    const auto pre_disable_result = pre_disable();
    BOOST_CHECK_MESSAGE(!pre_disable_result.has_value(), pre_disable_result.value_or("ok"));

    CShieldedProofCheck post_disable(tx,
                                     consensus,
                                     consensus.nShieldedMatRiCTDisableHeight,
                                     tree);
    const auto post_disable_result = post_disable();
    BOOST_REQUIRE(post_disable_result.has_value());
    BOOST_CHECK_EQUAL(*post_disable_result, "bad-shielded-matrict-disabled");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_v2_send_matrict_after_disable_height)
{
    auto fixture = BuildV2SendFixture();
    auto& proof_envelope = fixture.tx.shielded_bundle.v2_bundle->header.proof_envelope;
    proof_envelope.proof_kind = shielded::v2::ProofKind::DIRECT_MATRICT;
    proof_envelope.membership_proof_kind = shielded::v2::ProofComponentKind::MATRICT;
    proof_envelope.amount_proof_kind = shielded::v2::ProofComponentKind::RANGE;
    proof_envelope.balance_proof_kind = shielded::v2::ProofComponentKind::BALANCE;
    proof_envelope.statement_digest = ComputeFixtureStatementDigest(fixture);

    const CTransaction tx{fixture.tx};
    const auto& consensus = Params().GetConsensus();
    CShieldedProofCheck check(tx,
                              consensus,
                              consensus.nShieldedMatRiCTDisableHeight,
                              std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                              std::make_shared<const std::map<uint256, smile2::CompactPublicAccount>>(
                                  fixture.public_accounts),
                              std::make_shared<const std::map<uint256, uint256>>(
                                  fixture.account_leaf_commitments));
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-matrict-disabled");
}

BOOST_AUTO_TEST_CASE(proof_check_v2_send_switches_statement_digest_at_disable_height)
{
    const auto& consensus = Params().GetConsensus();
    auto legacy_fixture = BuildV2SendFixture(/*fee=*/0,
                                             smile2::SmileProofCodecPolicy::CANONICAL_NO_RICE,
                                             &consensus,
                                             consensus.nShieldedMatRiCTDisableHeight - 1);
    auto& legacy_bundle = *legacy_fixture.tx.shielded_bundle.v2_bundle;
    legacy_bundle.header.proof_envelope.statement_digest =
        v2proof::ComputeV2SendStatementDigest(CTransaction{legacy_fixture.tx});

    const auto legacy_tree =
        std::make_shared<shielded::ShieldedMerkleTree>(legacy_fixture.tree);
    const auto legacy_public_accounts =
        std::make_shared<const std::map<uint256, smile2::CompactPublicAccount>>(
            legacy_fixture.public_accounts);
    const auto legacy_account_leaf_commitments =
        std::make_shared<const std::map<uint256, uint256>>(
            legacy_fixture.account_leaf_commitments);

    CShieldedProofCheck pre_disable(CTransaction{legacy_fixture.tx},
                                    consensus,
                                    consensus.nShieldedMatRiCTDisableHeight - 1,
                                    legacy_tree,
                                    legacy_public_accounts,
                                    legacy_account_leaf_commitments);
    const auto pre_disable_result = pre_disable();
    BOOST_CHECK_MESSAGE(!pre_disable_result.has_value(), pre_disable_result.value_or("ok"));

    CShieldedProofCheck wrong_post_disable(CTransaction{legacy_fixture.tx},
                                           consensus,
                                           consensus.nShieldedMatRiCTDisableHeight,
                                           legacy_tree,
                                           legacy_public_accounts,
                                           legacy_account_leaf_commitments);
    const auto wrong_post_disable_result = wrong_post_disable();
    BOOST_REQUIRE(wrong_post_disable_result.has_value());
    BOOST_CHECK_EQUAL(*wrong_post_disable_result, "bad-shielded-v2-family-wire");

    auto bound_fixture = BuildV2SendFixture(/*fee=*/0,
                                            smile2::SmileProofCodecPolicy::CANONICAL_NO_RICE,
                                            &consensus,
                                            consensus.nShieldedMatRiCTDisableHeight);
    auto& bound_bundle = *bound_fixture.tx.shielded_bundle.v2_bundle;
    bound_bundle.header.proof_envelope.statement_digest = v2proof::ComputeV2SendStatementDigest(
        CTransaction{bound_fixture.tx},
        consensus,
        consensus.nShieldedMatRiCTDisableHeight);

    const auto bound_tree =
        std::make_shared<shielded::ShieldedMerkleTree>(bound_fixture.tree);
    const auto bound_public_accounts =
        std::make_shared<const std::map<uint256, smile2::CompactPublicAccount>>(
            bound_fixture.public_accounts);
    const auto bound_account_leaf_commitments =
        std::make_shared<const std::map<uint256, uint256>>(
            bound_fixture.account_leaf_commitments);

    CShieldedProofCheck correct_post_disable(CTransaction{bound_fixture.tx},
                                             consensus,
                                             consensus.nShieldedMatRiCTDisableHeight,
                                             bound_tree,
                                             bound_public_accounts,
                                             bound_account_leaf_commitments);
    const auto correct_post_disable_result = correct_post_disable();
    BOOST_CHECK_MESSAGE(!correct_post_disable_result.has_value(), correct_post_disable_result.value_or("ok"));
}

BOOST_AUTO_TEST_CASE(proof_check_accepts_v2_send_nonzero_fee)
{
    auto fixture = BuildV2SendFixture(/*fee=*/shielded::SHIELDED_PRIVACY_FEE_QUANTUM);
    AssertV2SendFixtureVerifies(fixture);
    AssertV2SendFixtureVerifies(fixture, /*reject_rice_codec=*/true);
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx,
                              std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                              std::make_shared<const std::map<uint256, smile2::CompactPublicAccount>>(
                                  fixture.public_accounts),
                              std::make_shared<const std::map<uint256, uint256>>(
                                  fixture.account_leaf_commitments));
    const auto res = check();
    BOOST_CHECK_MESSAGE(!res.has_value(), res.value_or("ok"));
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_v2_send_with_tampered_transparent_output)
{
    auto fixture = BuildV2SendFixture(/*fee=*/shielded::SHIELDED_PRIVACY_FEE_QUANTUM);
    fixture.tx.vout.emplace_back(1, CScript{} << OP_TRUE);
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx,
                              std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                              std::make_shared<const std::map<uint256, smile2::CompactPublicAccount>>(
                                  fixture.public_accounts),
                              std::make_shared<const std::map<uint256, uint256>>(
                                  fixture.account_leaf_commitments));
    const auto res = check();
    BOOST_REQUIRE_MESSAGE(res.has_value(), "expected reject for tampered transparent output");
    BOOST_CHECK_EQUAL(*res, "bad-shielded-proof");
}

BOOST_AUTO_TEST_CASE(proof_check_defers_postfork_proofless_transparent_shielding_to_contextual_validation)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    const CTransaction tx{BuildProoflessTransparentShieldingTx(/*output_value=*/49'000,
                                                              /*fee=*/70'000,
                                                              &consensus,
                                                              activation_height)};

    CShieldedProofCheck check(tx,
                              consensus,
                              activation_height,
                              {},
                              {},
                              {});
    const auto res = check();
    BOOST_CHECK_MESSAGE(!res.has_value(), res.value_or("ok"));
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_postfork_mixed_shielded_to_transparent_v2_send)
{
    auto fixture = BuildV2SendFixture(/*fee=*/shielded::SHIELDED_PRIVACY_FEE_QUANTUM);
    fixture.tx.vout.emplace_back(1, CScript{} << OP_TRUE);
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx,
                              consensus,
                              activation_height,
                              std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                              std::make_shared<const std::map<uint256, smile2::CompactPublicAccount>>(
                                  fixture.public_accounts),
                              std::make_shared<const std::map<uint256, uint256>>(
                                  fixture.account_leaf_commitments));
    const auto res = check();
    BOOST_REQUIRE_MESSAGE(res.has_value(), "expected reject for post-fork mixed direct send");
    BOOST_CHECK_EQUAL(*res, "bad-shielded-proof");
}

BOOST_AUTO_TEST_CASE(proof_check_accepts_postfork_v2_lifecycle_bundle)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    const CTransaction tx{BuildLifecycleControlTx(&consensus, activation_height)};

    CShieldedProofCheck check(tx,
                              consensus,
                              activation_height,
                              {},
                              {},
                              {});
    const auto res = check();
    BOOST_CHECK_MESSAGE(!res.has_value(), res.value_or("unexpected post-fork lifecycle failure"));
}

BOOST_AUTO_TEST_CASE(proof_check_accepts_postfork_v2_lifecycle_bundle_with_multiple_transparent_outputs)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    CTxOut extra_output;
    extra_output.nValue = 7'000;
    extra_output.scriptPubKey = CScript{} << OP_1;
    const CTransaction tx{BuildLifecycleControlTx(&consensus, activation_height, {extra_output})};

    CShieldedProofCheck check(tx,
                              consensus,
                              activation_height,
                              {},
                              {},
                              {});
    const auto res = check();
    BOOST_CHECK_MESSAGE(!res.has_value(), res.value_or("unexpected lifecycle transparent-skeleton failure"));
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_prefork_v2_lifecycle_bundle)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t prefork_height = consensus.nShieldedMatRiCTDisableHeight - 1;
    const CTransaction tx{BuildLifecycleControlTx(&consensus, prefork_height)};

    CShieldedProofCheck check(tx,
                              consensus,
                              prefork_height,
                              {},
                              {},
                              {});
    const auto res = check();
    BOOST_REQUIRE_MESSAGE(res.has_value(), "expected reject for prefork lifecycle bundle");
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-lifecycle-disabled");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_postfork_v2_lifecycle_with_tampered_binding_digest)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    auto tx = BuildLifecycleControlTx(&consensus, activation_height);
    tx.vout.emplace_back(1, CScript{} << OP_TRUE);

    CShieldedProofCheck check(CTransaction{tx},
                              consensus,
                              activation_height,
                              {},
                              {},
                              {});
    const auto res = check();
    BOOST_REQUIRE_MESSAGE(res.has_value(), "expected reject for tampered lifecycle binding");
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-lifecycle-binding");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_postfork_v2_lifecycle_with_tampered_output_value)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    auto tx = BuildLifecycleControlTx(&consensus, activation_height);
    BOOST_REQUIRE_EQUAL(tx.vout.size(), 1U);
    ++tx.vout[0].nValue;

    CShieldedProofCheck check(CTransaction{tx},
                              consensus,
                              activation_height,
                              {},
                              {},
                              {});
    const auto res = check();
    BOOST_REQUIRE_MESSAGE(res.has_value(), "expected reject for lifecycle output-value tamper");
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-lifecycle-binding");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_postfork_legacy_v2_send_lifecycle_controls)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    const CTransaction tx{BuildPostforkGenericSendLifecycleControlTx(consensus, activation_height)};

    CShieldedProofCheck check(tx,
                              consensus,
                              activation_height,
                              {},
                              {},
                              {});
    const auto res = check();
    BOOST_REQUIRE_MESSAGE(res.has_value(), "expected reject for legacy send lifecycle controls");
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-send-lifecycle-control");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_prefork_postfork_direct_send_encoding)
{
    const auto& consensus = Params().GetConsensus();
    auto fixture = BuildV2SendFixture(/*fee=*/1,
                                      smile2::SmileProofCodecPolicy::CANONICAL_NO_RICE,
                                      &consensus,
                                      consensus.nShieldedMatRiCTDisableHeight - 1);
    auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;
    auto& payload = std::get<shielded::v2::SendPayload>(bundle.payload);
    payload.output_encoding = shielded::v2::SendOutputEncoding::SMILE_COMPACT_POSTFORK;
    bundle.header.payload_digest = shielded::v2::ComputeSendPayloadDigest(payload);
    RefreshFixtureEnvelopeDigests(fixture);

    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(tx,
                              consensus,
                              consensus.nShieldedMatRiCTDisableHeight - 1,
                              std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                              std::make_shared<const std::map<uint256, smile2::CompactPublicAccount>>(
                                  fixture.public_accounts),
                              std::make_shared<const std::map<uint256, uint256>>(
                                  fixture.account_leaf_commitments));
    const auto res = check();
    BOOST_REQUIRE_MESSAGE(res.has_value(), "expected reject for prefork postfork direct-send encoding");
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-send-encoding");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_postfork_legacy_compact_direct_send_encoding)
{
    const auto& consensus = Params().GetConsensus();
    auto fixture = BuildV2SendFixture(/*fee=*/shielded::SHIELDED_PRIVACY_FEE_QUANTUM,
                                      smile2::SmileProofCodecPolicy::CANONICAL_NO_RICE,
                                      &consensus,
                                      consensus.nShieldedMatRiCTDisableHeight);
    auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;
    auto& payload = std::get<shielded::v2::SendPayload>(bundle.payload);
    payload.output_encoding = shielded::v2::SendOutputEncoding::SMILE_COMPACT;
    bundle.header.payload_digest = shielded::v2::ComputeSendPayloadDigest(payload);
    RefreshFixtureEnvelopeDigests(fixture);

    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(tx,
                              consensus,
                              consensus.nShieldedMatRiCTDisableHeight,
                              std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                              std::make_shared<const std::map<uint256, smile2::CompactPublicAccount>>(
                                  fixture.public_accounts),
                              std::make_shared<const std::map<uint256, uint256>>(
                                  fixture.account_leaf_commitments));
    const auto res = check();
    BOOST_REQUIRE_MESSAGE(res.has_value(), "expected reject for post-fork legacy compact direct-send encoding");
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-send-encoding");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_v2_send_with_wrong_anchor)
{
    auto fixture = BuildV2SendFixture();
    auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;
    auto& payload = std::get<shielded::v2::SendPayload>(bundle.payload);
    payload.spend_anchor = uint256{0xab};
    payload.spends[0].merkle_anchor = payload.spend_anchor;
    bundle.header.payload_digest = shielded::v2::ComputeSendPayloadDigest(payload);
    RefreshFixtureEnvelopeDigests(fixture);

    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(tx,
                              std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                              std::make_shared<const std::map<uint256, smile2::CompactPublicAccount>>(
                                  fixture.public_accounts),
                              std::make_shared<const std::map<uint256, uint256>>(
                                  fixture.account_leaf_commitments));
    const auto res = check();
    BOOST_REQUIRE_MESSAGE(res.has_value(), "expected reject for wrong v2_send anchor");
    BOOST_CHECK_EQUAL(*res, "bad-shielded-proof");
}

BOOST_AUTO_TEST_CASE(proof_check_accepts_valid_v2_egress_receipt_bundle)
{
    const auto fixture = test::shielded::BuildV2EgressReceiptFixture();
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx, nullptr);
    const auto res = check();
    BOOST_CHECK(!res.has_value());
}

BOOST_AUTO_TEST_CASE(proof_check_accepts_postfork_generic_v2_egress_wire_family)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    const auto fixture = test::shielded::BuildV2EgressReceiptFixture(/*output_count=*/2,
                                                                     &consensus,
                                                                     activation_height);
    const auto* bundle = fixture.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_CHECK_EQUAL(bundle->header.family_id, shielded::v2::TransactionFamily::V2_GENERIC);
    BOOST_CHECK_EQUAL(bundle->header.proof_envelope.proof_kind, shielded::v2::ProofKind::GENERIC_OPAQUE);

    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(tx, consensus, activation_height, nullptr);
    const auto res = check();
    BOOST_CHECK_MESSAGE(!res.has_value(), res.value_or("unexpected postfork egress wire-family failure"));
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_postfork_legacy_v2_egress_wire_family)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    auto fixture = test::shielded::BuildV2EgressReceiptFixture(/*output_count=*/2,
                                                               &consensus,
                                                               activation_height);
    auto* bundle = fixture.tx.shielded_bundle.v2_bundle ? &*fixture.tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(bundle != nullptr);
    bundle->header.family_id = shielded::v2::TransactionFamily::V2_EGRESS_BATCH;

    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(tx, consensus, activation_height, nullptr);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-family-wire");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_postfork_legacy_v2_egress_proof_wire)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    auto fixture = test::shielded::BuildV2EgressReceiptFixture(/*output_count=*/2,
                                                               &consensus,
                                                               activation_height);
    auto* bundle = fixture.tx.shielded_bundle.v2_bundle ? &*fixture.tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(bundle != nullptr);
    bundle->header.proof_envelope.proof_kind = shielded::v2::ProofKind::IMPORTED_RECEIPT;

    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(tx, consensus, activation_height, nullptr);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-proof-wire");
}

BOOST_AUTO_TEST_CASE(proof_check_accepts_valid_v2_egress_hybrid_bundle)
{
    const auto fixture = test::shielded::BuildV2EgressHybridReceiptFixture();
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx, nullptr);
    const auto res = check();
    BOOST_CHECK(!res.has_value());
}

BOOST_AUTO_TEST_CASE(proof_check_accepts_valid_multi_receipt_v2_egress_bundle)
{
    const auto fixture = test::shielded::BuildV2EgressReceiptFixture(
        /*output_count=*/2,
        /*proof_receipt_count=*/2,
        /*required_receipts=*/2);
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx, nullptr);
    const auto res = check();
    BOOST_CHECK(!res.has_value());
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_v2_egress_binding_mismatch)
{
    auto fixture = test::shielded::BuildV2EgressReceiptFixture();
    auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;
    auto& payload = std::get<shielded::v2::EgressBatchPayload>(bundle.payload);
    payload.settlement_binding_digest = uint256{0xaa};
    bundle.header.payload_digest = shielded::v2::ComputeEgressBatchPayloadDigest(payload);
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx, nullptr);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-egress-binding");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_v2_egress_anchor_mismatch)
{
    auto fixture = test::shielded::BuildV2EgressReceiptFixture();
    auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;
    auto& payload = std::get<shielded::v2::EgressBatchPayload>(bundle.payload);
    payload.settlement_anchor = uint256{0xab};
    bundle.header.payload_digest = shielded::v2::ComputeEgressBatchPayloadDigest(payload);
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx, nullptr);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-egress-anchor");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_v2_egress_transparent_unwrap)
{
    auto fixture = test::shielded::BuildV2EgressReceiptFixture();
    auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;
    auto& payload = std::get<shielded::v2::EgressBatchPayload>(bundle.payload);
    payload.allow_transparent_unwrap = true;
    bundle.header.payload_digest = shielded::v2::ComputeEgressBatchPayloadDigest(payload);
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx, nullptr);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-egress-transparent-unwrap");
}

BOOST_AUTO_TEST_CASE(proof_check_accepts_valid_v2_settlement_anchor_bundle)
{
    const auto fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture();
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx, nullptr);
    const auto res = check();
    BOOST_CHECK(!res.has_value());
}

BOOST_AUTO_TEST_CASE(proof_check_accepts_postfork_generic_v2_settlement_anchor_wire_family)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    const auto fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture(/*output_count=*/2,
                                                                                /*proof_receipt_count=*/1,
                                                                                /*required_receipts=*/1,
                                                                                &consensus,
                                                                                activation_height);
    const auto* bundle = fixture.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_CHECK_EQUAL(bundle->header.family_id, shielded::v2::TransactionFamily::V2_GENERIC);
    BOOST_CHECK_EQUAL(bundle->header.proof_envelope.proof_kind, shielded::v2::ProofKind::GENERIC_OPAQUE);

    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(tx, consensus, activation_height, nullptr);
    const auto res = check();
    BOOST_CHECK_MESSAGE(!res.has_value(), res.value_or("unexpected postfork settlement-anchor wire-family failure"));
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_postfork_legacy_v2_settlement_anchor_wire_family)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    auto fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture(/*output_count=*/2,
                                                                         /*proof_receipt_count=*/1,
                                                                         /*required_receipts=*/1,
                                                                         &consensus,
                                                                         activation_height);
    auto* bundle = fixture.tx.shielded_bundle.v2_bundle ? &*fixture.tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(bundle != nullptr);
    bundle->header.family_id = shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR;

    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(tx, consensus, activation_height, nullptr);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-family-wire");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_postfork_legacy_v2_settlement_anchor_proof_wire)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    auto fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture(/*output_count=*/2,
                                                                         /*proof_receipt_count=*/1,
                                                                         /*required_receipts=*/1,
                                                                         &consensus,
                                                                         activation_height);
    auto* bundle = fixture.tx.shielded_bundle.v2_bundle ? &*fixture.tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(bundle != nullptr);
    bundle->header.proof_envelope.proof_kind = shielded::v2::ProofKind::IMPORTED_RECEIPT;

    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(tx, consensus, activation_height, nullptr);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-proof-wire");
}

BOOST_AUTO_TEST_CASE(proof_check_accepts_valid_v2_rebalance_bundle)
{
    const auto fixture = test::shielded::BuildV2RebalanceFixture();
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx, nullptr);
    const auto res = check();
    BOOST_CHECK(!res.has_value());
}

BOOST_AUTO_TEST_CASE(proof_check_accepts_postfork_generic_v2_rebalance_wire_family)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    const auto fixture = test::shielded::BuildV2RebalanceFixture(/*reserve_output_count=*/1,
                                                                 /*settlement_window=*/144,
                                                                 &consensus,
                                                                 activation_height);
    const auto* bundle = fixture.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_CHECK_EQUAL(bundle->header.family_id, shielded::v2::TransactionFamily::V2_GENERIC);
    BOOST_CHECK_EQUAL(bundle->header.proof_envelope.proof_kind, shielded::v2::ProofKind::GENERIC_OPAQUE);

    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(tx, consensus, activation_height, nullptr);
    const auto res = check();
    BOOST_CHECK_MESSAGE(!res.has_value(), res.value_or("unexpected postfork rebalance wire-family failure"));
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_postfork_legacy_v2_rebalance_wire_family)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    auto fixture = test::shielded::BuildV2RebalanceFixture(/*reserve_output_count=*/1,
                                                           /*settlement_window=*/144,
                                                           &consensus,
                                                           activation_height);
    auto* bundle = fixture.tx.shielded_bundle.v2_bundle ? &*fixture.tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(bundle != nullptr);
    bundle->header.family_id = shielded::v2::TransactionFamily::V2_REBALANCE;

    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(tx, consensus, activation_height, nullptr);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-family-wire");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_postfork_legacy_v2_rebalance_proof_wire)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    auto fixture = test::shielded::BuildV2RebalanceFixture(/*reserve_output_count=*/1,
                                                           /*settlement_window=*/144,
                                                           &consensus,
                                                           activation_height);
    auto* bundle = fixture.tx.shielded_bundle.v2_bundle ? &*fixture.tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(bundle != nullptr);
    bundle->header.proof_envelope.proof_kind = shielded::v2::ProofKind::BATCH_SMILE;

    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(tx, consensus, activation_height, nullptr);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-proof-wire");
}

BOOST_AUTO_TEST_CASE(proof_check_accepts_fee_bearing_v2_settlement_anchor_bundle)
{
    auto fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture();
    fixture.tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{0xa1}), 0}, CScript{});
    fixture.tx.vout.emplace_back(10'000, CScript{} << OP_TRUE);
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx, nullptr);
    const auto res = check();
    BOOST_CHECK(!res.has_value());
}

BOOST_AUTO_TEST_CASE(proof_check_accepts_valid_receipt_adapter_backed_v2_settlement_anchor_bundle)
{
    const auto fixture = test::shielded::BuildV2SettlementAnchorAdapterReceiptFixture();
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx, nullptr);
    const auto res = check();
    BOOST_CHECK(!res.has_value());
}

BOOST_AUTO_TEST_CASE(proof_check_accepts_valid_hybrid_v2_settlement_anchor_bundle)
{
    const auto fixture = test::shielded::BuildV2SettlementAnchorHybridReceiptFixture();
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx, nullptr);
    const auto res = check();
    BOOST_CHECK(!res.has_value());
}

BOOST_AUTO_TEST_CASE(proof_check_accepts_valid_multi_receipt_hybrid_v2_settlement_anchor_bundle)
{
    const auto fixture = test::shielded::BuildV2SettlementAnchorHybridReceiptFixture(
        /*output_count=*/2,
        /*proof_receipt_count=*/2,
        /*required_receipts=*/2);
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx, nullptr);
    const auto res = check();
    BOOST_CHECK(!res.has_value());
}

BOOST_AUTO_TEST_CASE(proof_check_accepts_valid_multi_receipt_v2_settlement_anchor_bundle)
{
    const auto fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture(
        /*output_count=*/2,
        /*proof_receipt_count=*/2,
        /*required_receipts=*/2);
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx, nullptr);
    const auto res = check();
    BOOST_CHECK(!res.has_value());
}

BOOST_AUTO_TEST_CASE(proof_check_accepts_reserve_bound_receipt_v2_settlement_anchor_bundle)
{
    auto fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture();
    test::shielded::AttachSettlementAnchorReserveBinding(fixture.tx);
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx, nullptr);
    const auto res = check();
    BOOST_CHECK(!res.has_value());
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_noncanonical_bridge_proof_system_after_disable_height)
{
    auto fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture();
    fixture.descriptor.proof_system_id = uint256{0xf7};
    fixture.receipt.statement_hash = shielded::ComputeBridgeBatchStatementHash(fixture.statement);
    fixture.receipt.proof_system_id = fixture.descriptor.proof_system_id;
    fixture.witness.proof_receipts = {fixture.receipt};
    RefreshSingleDescriptorSettlementAnchorFixture(fixture);

    const CTransaction tx{fixture.tx};
    const auto& consensus = Params().GetConsensus();

    CShieldedProofCheck pre_disable(tx,
                                    consensus,
                                    consensus.nShieldedMatRiCTDisableHeight - 1,
                                    nullptr);
    const auto pre_disable_result = pre_disable();
    BOOST_CHECK_MESSAGE(!pre_disable_result.has_value(), pre_disable_result.value_or("ok"));

    CShieldedProofCheck post_disable(tx,
                                     consensus,
                                     consensus.nShieldedMatRiCTDisableHeight,
                                     nullptr);
    const auto post_disable_result = post_disable();
    BOOST_REQUIRE(post_disable_result.has_value());
    BOOST_CHECK_EQUAL(*post_disable_result, "bad-shielded-v2-family-wire");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_v2_settlement_anchor_binding_mismatch)
{
    auto fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture();
    auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;
    auto& payload = std::get<shielded::v2::SettlementAnchorPayload>(bundle.payload);
    payload.proof_receipt_ids = {uint256{0xac}};
    bundle.header.payload_digest = shielded::v2::ComputeSettlementAnchorPayloadDigest(payload);
    BOOST_REQUIRE(bundle.IsValid());
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx, nullptr);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-settlement-anchor-binding");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_multi_receipt_v2_settlement_anchor_binding_mismatch)
{
    auto fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture(
        /*output_count=*/2,
        /*proof_receipt_count=*/2,
        /*required_receipts=*/2);
    auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;
    auto& payload = std::get<shielded::v2::SettlementAnchorPayload>(bundle.payload);
    BOOST_REQUIRE_EQUAL(payload.proof_receipt_ids.size(), 2U);
    payload.proof_receipt_ids.pop_back();
    bundle.header.payload_digest = shielded::v2::ComputeSettlementAnchorPayloadDigest(payload);
    BOOST_REQUIRE(bundle.IsValid());
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx, nullptr);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-settlement-anchor-binding");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_receipt_adapter_backed_v2_settlement_anchor_binding_mismatch)
{
    auto fixture = test::shielded::BuildV2SettlementAnchorAdapterReceiptFixture();
    auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;
    auto& payload = std::get<shielded::v2::SettlementAnchorPayload>(bundle.payload);
    payload.imported_adapter_ids = {uint256{0xae}};
    bundle.header.payload_digest = shielded::v2::ComputeSettlementAnchorPayloadDigest(payload);
    BOOST_REQUIRE(bundle.IsValid());
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx, nullptr);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-settlement-anchor-binding");
}

BOOST_AUTO_TEST_CASE(proof_check_accepts_valid_claim_backed_v2_settlement_anchor_bundle)
{
    const auto fixture = test::shielded::BuildV2SettlementAnchorClaimFixture();
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx, nullptr);
    const auto res = check();
    BOOST_CHECK(!res.has_value());
}

BOOST_AUTO_TEST_CASE(proof_check_accepts_valid_adapter_backed_v2_settlement_anchor_bundle)
{
    const auto fixture = test::shielded::BuildV2SettlementAnchorAdapterClaimFixture();
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx, nullptr);
    const auto res = check();
    BOOST_CHECK(!res.has_value());
}

BOOST_AUTO_TEST_CASE(proof_check_accepts_reserve_bound_claim_backed_v2_settlement_anchor_bundle)
{
    auto fixture = test::shielded::BuildV2SettlementAnchorClaimFixture();
    test::shielded::AttachSettlementAnchorReserveBinding(fixture.tx);
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx, nullptr);
    const auto res = check();
    BOOST_CHECK(!res.has_value());
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_claim_backed_v2_settlement_anchor_binding_mismatch)
{
    auto fixture = test::shielded::BuildV2SettlementAnchorClaimFixture();
    auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;
    auto& payload = std::get<shielded::v2::SettlementAnchorPayload>(bundle.payload);
    payload.imported_claim_ids = {uint256{0xad}};
    bundle.header.payload_digest = shielded::v2::ComputeSettlementAnchorPayloadDigest(payload);
    BOOST_REQUIRE(bundle.IsValid());
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx, nullptr);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-settlement-anchor-binding");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_adapter_backed_v2_settlement_anchor_binding_mismatch)
{
    auto fixture = test::shielded::BuildV2SettlementAnchorAdapterClaimFixture();
    auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;
    auto& payload = std::get<shielded::v2::SettlementAnchorPayload>(bundle.payload);
    payload.imported_adapter_ids = {uint256{0xae}};
    bundle.header.payload_digest = shielded::v2::ComputeSettlementAnchorPayloadDigest(payload);
    BOOST_REQUIRE(bundle.IsValid());
    const CTransaction tx{fixture.tx};

    CShieldedProofCheck check(tx, nullptr);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-settlement-anchor-binding");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_out_of_range_ring_position)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildProofBundle();
    mtx.shielded_bundle.shielded_inputs[0].ring_positions[0] = shielded::lattice::RING_SIZE + 100;
    const CTransaction tx{mtx};

    shielded::ShieldedMerkleTree tree;
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        HashWriter hw;
        hw << std::string{"BTX_Shielded_RingMember_V1"};
        hw << static_cast<uint64_t>(i);
        tree.Append(hw.GetSHA256());
    }

    CShieldedProofCheck check = MakeLegacyProofCheck(tx, tree);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-ring-member-position");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_invalid_ring_position_before_proof_parse)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildProofBundle();
    mtx.shielded_bundle.shielded_inputs[0].ring_positions[0] = shielded::lattice::RING_SIZE + 100;
    mtx.shielded_bundle.proof = {0x01}; // malformed proof bytes should not mask bad ring positions
    const CTransaction tx{mtx};

    shielded::ShieldedMerkleTree tree;
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        HashWriter hw;
        hw << std::string{"BTX_Shielded_RingMember_V1"};
        hw << static_cast<uint64_t>(i);
        tree.Append(hw.GetSHA256());
    }

    CShieldedProofCheck check = MakeLegacyProofCheck(tx, tree);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-ring-member-position");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_duplicate_ring_positions)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildProofBundle();
    mtx.shielded_bundle.shielded_inputs[0].ring_positions[1] =
        mtx.shielded_bundle.shielded_inputs[0].ring_positions[0];
    const CTransaction tx{mtx};

    shielded::ShieldedMerkleTree tree;
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        HashWriter hw;
        hw << std::string{"BTX_Shielded_RingMember_V1"};
        hw << static_cast<uint64_t>(i);
        tree.Append(hw.GetSHA256());
    }

    CShieldedProofCheck check = MakeLegacyProofCheck(tx, tree);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-ring-member-insufficient-diversity");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_low_diversity_small_tree)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildProofBundle();

    // Tree has 4 commitments, so we require at least 4 unique ring positions.
    for (size_t i = 0; i < mtx.shielded_bundle.shielded_inputs[0].ring_positions.size(); ++i) {
        mtx.shielded_bundle.shielded_inputs[0].ring_positions[i] = static_cast<uint64_t>(i % 3);
    }
    const CTransaction tx{mtx};

    shielded::ShieldedMerkleTree tree;
    for (size_t i = 0; i < 4; ++i) {
        HashWriter hw;
        hw << std::string{"BTX_Shielded_RingMember_V1"};
        hw << static_cast<uint64_t>(i);
        tree.Append(hw.GetSHA256());
    }

    CShieldedProofCheck check = MakeLegacyProofCheck(tx, tree);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-ring-member-insufficient-diversity");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_tx_context_mutation)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildProofBundle();
    mtx.shielded_bundle = BuildProofBundle(/*value_balance=*/0, shielded::ringct::ComputeMatRiCTBindingHash(CTransaction{mtx}));
    mtx.nLockTime ^= 1;
    const CTransaction tx{mtx};

    shielded::ShieldedMerkleTree tree;
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        HashWriter hw;
        hw << std::string{"BTX_Shielded_RingMember_V1"};
        hw << static_cast<uint64_t>(i);
        tree.Append(hw.GetSHA256());
    }

    CShieldedProofCheck check = MakeLegacyProofCheck(tx, tree);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-proof");
}

BOOST_AUTO_TEST_CASE(spend_auth_check_accepts_valid_bound_nullifier)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildProofBundle();
    mtx.shielded_bundle = BuildProofBundle(/*value_balance=*/0, shielded::ringct::ComputeMatRiCTBindingHash(CTransaction{mtx}));
    const CTransaction tx{mtx};

    CShieldedSpendAuthCheck check(tx, /*spend_index=*/0);
    const auto res = check();
    BOOST_CHECK(!res.has_value());
}

BOOST_AUTO_TEST_CASE(spend_auth_check_rejects_nullifier_mismatch)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildProofBundle();
    mtx.shielded_bundle = BuildProofBundle(/*value_balance=*/0, shielded::ringct::ComputeMatRiCTBindingHash(CTransaction{mtx}));
    mtx.shielded_bundle.shielded_inputs[0].nullifier = GetRandHash();
    const CTransaction tx{mtx};
    CShieldedSpendAuthCheck check(tx, /*spend_index=*/0);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-spend-auth-nullifier-mismatch");
}

BOOST_AUTO_TEST_CASE(spend_auth_check_accepts_valid_v2_send_bound_nullifier)
{
    auto fixture = BuildV2SendFixture();
    const CTransaction tx{fixture.tx};

    CShieldedSpendAuthCheck check(tx, /*spend_index=*/0);
    const auto res = check();
    BOOST_CHECK(!res.has_value());
}

BOOST_AUTO_TEST_CASE(spend_auth_check_rejects_v2_send_nullifier_mismatch)
{
    auto fixture = BuildV2SendFixture();
    auto& payload = std::get<shielded::v2::SendPayload>(fixture.tx.shielded_bundle.v2_bundle->payload);
    payload.spends[0].nullifier = GetRandHash();
    fixture.tx.shielded_bundle.v2_bundle->header.payload_digest =
        shielded::v2::ComputeSendPayloadDigest(payload);

    const CTransaction tx{fixture.tx};
    CShieldedSpendAuthCheck check(tx, /*spend_index=*/0);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-spend-auth-nullifier-mismatch");
}

BOOST_AUTO_TEST_CASE(spend_auth_check_rejects_missing_proof)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildProofBundle();
    mtx.shielded_bundle.proof.clear();
    const CTransaction tx{mtx};

    CShieldedSpendAuthCheck check(tx, /*spend_index=*/0);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-spend-auth-proof-missing");
}

BOOST_AUTO_TEST_CASE(spend_auth_check_rejects_oversized_proof)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildProofBundle();
    mtx.shielded_bundle.proof.resize(MAX_SHIELDED_PROOF_BYTES + 1, 0x55);
    BOOST_CHECK_THROW((void)CTransaction{mtx}, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(spend_auth_check_rejects_invalid_proof_encoding)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildProofBundle();
    mtx.shielded_bundle.proof = {0x01};
    const CTransaction tx{mtx};

    CShieldedSpendAuthCheck check(tx, /*spend_index=*/0);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-spend-auth-proof-encoding");
}

BOOST_AUTO_TEST_CASE(spend_auth_check_rejects_oversized_proof_vector_count)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildProofBundle();

    DataStream proof_ds{mtx.shielded_bundle.proof};
    MatRiCTProof proof;
    proof_ds >> proof;

    DataStream tampered;
    tampered << proof.ring_signature;
    tampered << proof.balance_proof;
    WriteCompactSize(tampered, static_cast<uint64_t>(MAX_MATRICT_OUTPUTS + 1));

    const auto* begin = reinterpret_cast<const unsigned char*>(tampered.data());
    mtx.shielded_bundle.proof.assign(begin, begin + tampered.size());

    const CTransaction tx{mtx};
    CShieldedSpendAuthCheck check(tx, /*spend_index=*/0);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-spend-auth-proof-encoding");
}

BOOST_AUTO_TEST_CASE(spend_auth_check_rejects_missing_pubkey)
{
    CShieldedInput spend;
    spend.nullifier.SetNull();
    CMutableTransaction mtx;
    mtx.shielded_bundle.shielded_inputs.push_back(spend);
    mtx.shielded_bundle.proof = {0x01};
    CShieldedOutput out;
    out.note_commitment = GetRandHash();
    out.merkle_anchor = GetRandHash();
    mtx.shielded_bundle.shielded_outputs.push_back(out);
    const CTransaction tx{mtx};
    CShieldedSpendAuthCheck check(tx, /*spend_index=*/0);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-spend-auth-nullifier");
}

BOOST_AUTO_TEST_CASE(spend_auth_check_rejects_present_pubkey_and_algo)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle.proof = {0x01};
    CShieldedOutput out;
    out.note_commitment = GetRandHash();
    out.merkle_anchor = GetRandHash();
    mtx.shielded_bundle.shielded_outputs.push_back(out);
    const CTransaction tx{mtx};
    CShieldedSpendAuthCheck check(tx, /*spend_index=*/0);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-spend-auth-index");
}

// ---------------------------------------------------------------------------
// P0-6 explicit test: 15 of 16 identical ring positions must be rejected.
// The anonymity set is reduced to 2 in this scenario.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(proof_check_rejects_15_of_16_identical_positions)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildProofBundle();

    // Set 15 of 16 positions to the same value (position 0), leave one different.
    auto& positions = mtx.shielded_bundle.shielded_inputs[0].ring_positions;
    for (size_t i = 0; i < positions.size() - 1; ++i) {
        positions[i] = 0;
    }
    positions.back() = 1; // Only 2 unique positions out of 16 required
    const CTransaction tx{mtx};

    shielded::ShieldedMerkleTree tree;
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        HashWriter hw;
        hw << std::string{"BTX_Shielded_RingMember_V1"};
        hw << static_cast<uint64_t>(i);
        tree.Append(hw.GetSHA256());
    }

    CShieldedProofCheck check = MakeLegacyProofCheck(tx, tree);
    const auto res = check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-ring-member-insufficient-diversity");
}

// ---------------------------------------------------------------------------
// P1-15: ComputeShieldedSpendAuthSigHash direct test.
// Verify the spend auth hash is deterministic, bound to spend index and
// nullifier, and that proof bytes are excluded from the binding hash.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(spend_auth_sig_hash_deterministic_and_proof_excluded)
{
    CMutableTransaction mtx;
    CShieldedInput input;
    input.nullifier = GetRandHash();
    input.ring_positions.resize(shielded::lattice::RING_SIZE);
    for (size_t i = 0; i < input.ring_positions.size(); ++i) {
        input.ring_positions[i] = i;
    }
    mtx.shielded_bundle.shielded_inputs.push_back(input);

    CShieldedOutput output;
    output.note_commitment = GetRandHash();
    output.merkle_anchor = GetRandHash();
    mtx.shielded_bundle.shielded_outputs.push_back(output);
    mtx.shielded_bundle.value_balance = 1000;
    mtx.version = 2;

    // Compute spend auth hash with empty proof
    const uint256 hash_no_proof = shielded::ComputeShieldedSpendAuthSigHash(CTransaction{mtx}, 0);
    BOOST_CHECK(!hash_no_proof.IsNull());

    // Add proof bytes — hash must NOT change (proof is stripped)
    mtx.shielded_bundle.proof = {0x01, 0x02, 0x03, 0xFF};
    const uint256 hash_with_proof = shielded::ComputeShieldedSpendAuthSigHash(CTransaction{mtx}, 0);
    BOOST_CHECK_EQUAL(hash_no_proof, hash_with_proof);

    // Different spend index must produce different hash
    CShieldedInput input2;
    input2.nullifier = GetRandHash();
    input2.ring_positions = input.ring_positions;
    mtx.shielded_bundle.shielded_inputs.push_back(input2);
    const uint256 hash_idx0 = shielded::ComputeShieldedSpendAuthSigHash(CTransaction{mtx}, 0);
    const uint256 hash_idx1 = shielded::ComputeShieldedSpendAuthSigHash(CTransaction{mtx}, 1);
    BOOST_CHECK(hash_idx0 != hash_idx1);

    // Determinism: same tx produces same hash
    const uint256 hash_again = shielded::ComputeShieldedSpendAuthSigHash(CTransaction{mtx}, 0);
    BOOST_CHECK_EQUAL(hash_idx0, hash_again);

    // Out-of-bounds index returns null
    const uint256 hash_oob = shielded::ComputeShieldedSpendAuthSigHash(CTransaction{mtx}, 999);
    BOOST_CHECK(hash_oob.IsNull());
}

BOOST_AUTO_TEST_CASE(spend_auth_sig_hash_binds_chain_context_after_disable_height)
{
    CMutableTransaction mtx;
    CShieldedInput input;
    input.nullifier = GetRandHash();
    input.ring_positions.resize(shielded::lattice::RING_SIZE);
    for (size_t i = 0; i < input.ring_positions.size(); ++i) {
        input.ring_positions[i] = i;
    }
    mtx.shielded_bundle.shielded_inputs.push_back(input);

    CShieldedOutput output;
    output.note_commitment = GetRandHash();
    output.merkle_anchor = GetRandHash();
    mtx.shielded_bundle.shielded_outputs.push_back(output);
    mtx.shielded_bundle.value_balance = 500;

    const CTransaction tx{mtx};
    const auto& main_consensus = Params().GetConsensus();
    const auto alt_params = CreateChainParams(*m_node.args, ChainType::SHIELDEDV2DEV);
    BOOST_REQUIRE(alt_params != nullptr);

    const uint256 legacy_hash = shielded::ComputeShieldedSpendAuthSigHash(tx, 0);
    const uint256 pre_disable_hash = shielded::ComputeShieldedSpendAuthSigHash(
        tx,
        0,
        main_consensus,
        main_consensus.nShieldedMatRiCTDisableHeight - 1);
    const uint256 pre_disable_legacy_v2_hash = ComputeLegacySpendAuthV2SigHashForTest(
        tx,
        0,
        main_consensus,
        main_consensus.nShieldedMatRiCTDisableHeight - 1);
    const uint256 post_disable_hash = shielded::ComputeShieldedSpendAuthSigHash(
        tx,
        0,
        main_consensus,
        main_consensus.nShieldedMatRiCTDisableHeight);
    const uint256 post_disable_legacy_v2_hash = ComputeLegacySpendAuthV2SigHashForTest(
        tx,
        0,
        main_consensus,
        main_consensus.nShieldedMatRiCTDisableHeight);
    const uint256 alt_chain_hash = shielded::ComputeShieldedSpendAuthSigHash(
        tx,
        0,
        alt_params->GetConsensus(),
        alt_params->GetConsensus().nShieldedMatRiCTDisableHeight);

    BOOST_CHECK(pre_disable_hash != legacy_hash);
    BOOST_CHECK_EQUAL(pre_disable_hash, pre_disable_legacy_v2_hash);
    BOOST_CHECK(post_disable_hash != legacy_hash);
    BOOST_CHECK(post_disable_hash != pre_disable_hash);
    BOOST_CHECK(post_disable_hash != post_disable_legacy_v2_hash);
    BOOST_CHECK(post_disable_hash != alt_chain_hash);
}

BOOST_AUTO_TEST_SUITE_END()
