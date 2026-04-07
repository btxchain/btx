// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainparams.h>
#include <consensus/amount.h>
#include <crypto/sha256.h>
#include <crypto/ml_kem.h>
#include <hash.h>
#include <pqkey.h>
#include <primitives/transaction.h>
#include <shielded/account_registry.h>
#include <shielded/bundle.h>
#include <shielded/v2_bundle.h>
#include <shielded/v2_ingress.h>
#include <shielded/v2_send.h>
#include <streams.h>
#include <test/util/shielded_account_registry_test_util.h>
#include <test/util/setup_common.h>
#include <test/util/smile2_placeholder_utils.h>
#include <test/util/shielded_v2_egress_fixture.h>
#include <test/util/shielded_smile_test_util.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <stdexcept>
#include <vector>

namespace {

using namespace shielded::v2;

smile2::CompactPublicAccount MakeSmileAccount(unsigned char seed)
{
    return test::shielded::MakeDeterministicCompactPublicAccount(seed);
}

EncryptedNotePayload MakeEncryptedNotePayload(ScanDomain domain, unsigned char seed)
{
    EncryptedNotePayload payload;
    payload.scan_domain = domain;
    for (size_t i = 0; i < payload.scan_hint.size(); ++i) {
        payload.scan_hint[i] = seed + static_cast<unsigned char>(i);
    }
    payload.ciphertext = {seed, static_cast<uint8_t>(seed + 1), static_cast<uint8_t>(seed + 2)};
    payload.ephemeral_key = ComputeLegacyPayloadEphemeralKey(
        Span<const uint8_t>{payload.ciphertext.data(), payload.ciphertext.size()});
    return payload;
}

LifecycleAddress MakeLifecycleAddress(CPQKey& signing_key, unsigned char seed)
{
    LifecycleAddress address;
    address.version = 0x01;
    address.algo_byte = 0x00;
    const std::vector<unsigned char> pubkey = signing_key.GetPubKey();
    BOOST_REQUIRE_EQUAL(pubkey.size(), MLDSA44_PUBKEY_SIZE);
    CSHA256().Write(pubkey.data(), pubkey.size()).Finalize(address.pk_hash.begin());
    for (size_t i = 0; i < address.kem_public_key.size(); ++i) {
        address.kem_public_key[i] = static_cast<unsigned char>(seed + i);
    }
    address.has_kem_public_key = true;
    CSHA256().Write(address.kem_public_key.data(), address.kem_public_key.size()).Finalize(address.kem_pk_hash.begin());
    BOOST_REQUIRE(address.IsValid());
    return address;
}

AddressLifecycleControl MakeLifecycleControl(AddressLifecycleControlKind kind,
                                             CPQKey& subject_key,
                                             const LifecycleAddress& subject,
                                             const std::optional<LifecycleAddress>& successor,
                                             const uint256& note_commitment)
{
    AddressLifecycleControl control;
    control.kind = kind;
    control.output_index = 0;
    control.subject = subject;
    control.has_successor = successor.has_value();
    if (successor.has_value()) {
        control.successor = *successor;
    }
    control.subject_spending_pubkey = subject_key.GetPubKey();
    const uint256 sighash = ComputeAddressLifecycleControlSigHash(control, note_commitment);
    BOOST_REQUIRE(!sighash.IsNull());
    BOOST_REQUIRE(subject_key.Sign(sighash, control.signature));
    BOOST_REQUIRE(control.IsValid());
    BOOST_REQUIRE(VerifyAddressLifecycleControl(control, note_commitment));
    return control;
}

CTransaction MakeLifecycleBindingTx(unsigned char seed)
{
    CMutableTransaction tx;
    tx.version = CTransaction::CURRENT_VERSION;
    tx.nLockTime = static_cast<unsigned int>(100 + seed);
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{seed}), 0},
                        CScript{},
                        0xfffffffe);
    tx.vout.emplace_back(1'000 + seed, CScript{});
    return CTransaction{tx};
}

AddressLifecycleControl MakeLifecycleRecord(AddressLifecycleControlKind kind,
                                            CPQKey& subject_key,
                                            const LifecycleAddress& subject,
                                            const std::optional<LifecycleAddress>& successor,
                                            const uint256& transparent_binding_digest)
{
    AddressLifecycleControl control;
    control.kind = kind;
    control.output_index = 0;
    control.subject = subject;
    control.has_successor = successor.has_value();
    if (successor.has_value()) {
        control.successor = *successor;
    }
    control.subject_spending_pubkey = subject_key.GetPubKey();
    const uint256 sighash = ComputeAddressLifecycleRecordSigHash(control, transparent_binding_digest);
    BOOST_REQUIRE(!sighash.IsNull());
    BOOST_REQUIRE(subject_key.Sign(sighash, control.signature));
    BOOST_REQUIRE(control.IsValid());
    BOOST_REQUIRE(VerifyAddressLifecycleRecord(control, transparent_binding_digest));
    return control;
}

SpendDescription MakeSpend(unsigned char seed)
{
    SpendDescription spend;
    const auto account = MakeSmileAccount(static_cast<unsigned char>(seed + 9));
    spend.nullifier = uint256{seed};
    spend.merkle_anchor = uint256{static_cast<unsigned char>(seed + 1)};
    spend.note_commitment = smile2::ComputeCompactPublicAccountHash(account);
    const auto account_leaf = shielded::registry::BuildShieldedAccountLeaf(
        account,
        spend.note_commitment,
        shielded::registry::AccountDomain::DIRECT_SEND);
    BOOST_REQUIRE(account_leaf.has_value());
    spend.account_leaf_commitment = shielded::registry::ComputeShieldedAccountLeafCommitment(*account_leaf);
    spend.value_commitment = uint256{static_cast<unsigned char>(seed + 4)};
    const auto witness = test::shielded::MakeSingleLeafRegistryWitness(*account_leaf);
    BOOST_REQUIRE(witness.has_value());
    spend.account_registry_proof = witness->second;
    return spend;
}

ConsumedAccountLeafSpend MakeConsumedSpend(unsigned char seed)
{
    ConsumedAccountLeafSpend spend;
    const auto account = MakeSmileAccount(static_cast<unsigned char>(seed + 19));
    const uint256 note_commitment = smile2::ComputeCompactPublicAccountHash(account);
    const auto account_leaf = shielded::registry::BuildShieldedAccountLeaf(
        account,
        note_commitment,
        shielded::registry::AccountDomain::DIRECT_SEND);
    BOOST_REQUIRE(account_leaf.has_value());
    spend.nullifier = uint256{seed};
    spend.account_leaf_commitment = shielded::registry::ComputeShieldedAccountLeafCommitment(*account_leaf);
    const auto witness = test::shielded::MakeSingleLeafRegistryWitness(*account_leaf);
    BOOST_REQUIRE(witness.has_value());
    spend.account_registry_proof = witness->second;
    return spend;
}

OutputDescription MakeOutput(NoteClass note_class, ScanDomain domain, unsigned char seed)
{
    (void)domain;
    OutputDescription output;
    output.note_class = note_class;
    output.smile_account = MakeSmileAccount(seed);
    output.note_commitment = smile2::ComputeCompactPublicAccountHash(*output.smile_account);
    output.value_commitment = note_class == NoteClass::USER
        ? smile2::ComputeSmileOutputCoinHash(output.smile_account->public_coin)
        : uint256{static_cast<unsigned char>(seed + 1)};
    output.encrypted_note = MakeEncryptedNotePayload(ScanDomain::OPAQUE, static_cast<unsigned char>(seed + 2));
    return output;
}

struct LegacyPreLifecycleSendPayloadWire
{
    SendPayload payload;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        BOOST_REQUIRE_EQUAL(payload.version, WIRE_VERSION);
        ::Serialize(s, payload.spend_anchor);
        ::Serialize(s, payload.account_registry_anchor);
        shielded::v2::detail::SerializeEnum(s, static_cast<uint8_t>(payload.output_encoding));
        if (payload.output_encoding == SendOutputEncoding::SMILE_COMPACT) {
            shielded::v2::detail::SerializeEnum(s, static_cast<uint8_t>(payload.output_note_class));
            shielded::v2::detail::SerializeEnum(s, static_cast<uint8_t>(payload.output_scan_domain));
        }
        shielded::v2::detail::SerializeBoundedCompactSize(
            s,
            payload.spends.size(),
            MAX_DIRECT_SPENDS,
            "LegacyPreLifecycleSendPayloadWire::Serialize oversized spends");
        for (const SpendDescription& spend : payload.spends) {
            ::Serialize(s, spend.nullifier);
            ::Serialize(s, spend.account_leaf_commitment);
            ::Serialize(s, spend.account_registry_proof);
            if (payload.output_encoding != SendOutputEncoding::SMILE_COMPACT) {
                ::Serialize(s, spend.value_commitment);
            }
        }
        shielded::v2::detail::SerializeBoundedCompactSize(
            s,
            payload.outputs.size(),
            MAX_DIRECT_OUTPUTS,
            "LegacyPreLifecycleSendPayloadWire::Serialize oversized outputs");
        for (const OutputDescription& output : payload.outputs) {
            if (payload.output_encoding == SendOutputEncoding::SMILE_COMPACT) {
                output.SerializeDirectSend(s, payload.output_note_class, payload.output_scan_domain);
            } else {
                ::Serialize(s, output);
            }
        }
        ::Serialize(s, payload.value_balance);
        ::Serialize(s, payload.fee);
    }
};

ShieldedNote MakeDirectSendNote(CAmount value, unsigned char seed)
{
    ShieldedNote note;
    note.value = value;
    note.recipient_pk_hash = uint256{seed};
    note.rho = uint256{static_cast<unsigned char>(seed + 1)};
    note.rcm = uint256{static_cast<unsigned char>(seed + 2)};
    return note;
}

shielded::ShieldedMerkleTree BuildDirectSendTree(const uint256& real_member,
                                                 size_t real_index,
                                                 size_t ring_size = shielded::lattice::RING_SIZE)
{
    shielded::ShieldedMerkleTree tree;
    for (size_t i = 0; i < ring_size; ++i) {
        if (i == real_index) {
            tree.Append(real_member);
            continue;
        }
        HashWriter hw;
        hw << std::string{"BTX_ShieldedV2_Bundle_Test_RingMember_V1"} << static_cast<uint64_t>(i);
        tree.Append(hw.GetSHA256());
    }
    return tree;
}

std::vector<uint64_t> BuildDirectSendRingPositions(size_t ring_size = shielded::lattice::RING_SIZE)
{
    std::vector<uint64_t> positions;
    positions.reserve(ring_size);
    for (size_t i = 0; i < ring_size; ++i) {
        positions.push_back(i);
    }
    return positions;
}

std::vector<uint256> BuildDirectSendRingMembers(const shielded::ShieldedMerkleTree& tree,
                                                const std::vector<uint64_t>& positions)
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

std::vector<smile2::wallet::SmileRingMember> BuildDirectSendSmileRingMembers(
    const std::vector<uint256>& ring_commitments,
    const ShieldedNote& real_note,
    const uint256& real_commitment,
    size_t real_index)
{
    std::vector<smile2::wallet::SmileRingMember> members;
    members.reserve(ring_commitments.size());
    for (const uint256& commitment : ring_commitments) {
        members.push_back(
            smile2::wallet::BuildPlaceholderRingMember(smile2::wallet::SMILE_GLOBAL_SEED, commitment));
    }

    auto real_member = smile2::wallet::BuildRingMemberFromNote(smile2::wallet::SMILE_GLOBAL_SEED,
                                                               real_note,
                                                               real_commitment);
    BOOST_REQUIRE(real_member.has_value());
    members[real_index] = *real_member;
    return members;
}

V2SendSpendInput MakeDirectSendSpendInput(const ShieldedNote& note,
                                          const std::vector<uint64_t>& ring_positions,
                                          const std::vector<uint256>& ring_members,
                                          size_t real_index)
{
    V2SendSpendInput spend_input;
    spend_input.note = note;
    spend_input.note_commitment = note.GetCommitment();
    spend_input.account_leaf_hint = shielded::registry::MakeDirectSendAccountLeafHint();
    spend_input.ring_positions = ring_positions;
    spend_input.ring_members = ring_members;
    spend_input.smile_ring_members =
        BuildDirectSendSmileRingMembers(ring_members, note, spend_input.note_commitment, real_index);
    spend_input.real_index = real_index;
    BOOST_REQUIRE(test::shielded::AttachAccountRegistryWitness(spend_input));
    return spend_input;
}

mlkem::KeyPair BuildRecipientKeyPair(unsigned char seed)
{
    std::array<uint8_t, mlkem::KEYGEN_SEEDBYTES> key_seed{};
    key_seed.fill(seed);
    return mlkem::KeyGenDerand(key_seed);
}

shielded::EncryptedNote BuildEncryptedNote(const ShieldedNote& note,
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

void CanonicalizeIngressReserveOutputs(std::vector<OutputDescription>& outputs,
                                       const uint256& settlement_binding_digest)
{
    for (size_t output_index = 0; output_index < outputs.size(); ++output_index) {
        outputs[output_index].value_commitment = ComputeV2IngressPlaceholderReserveValueCommitment(
            settlement_binding_digest,
            static_cast<uint32_t>(output_index),
            outputs[output_index].note_commitment);
    }
}

void CanonicalizeIngressPayload(IngressBatchPayload& payload)
{
    payload.ingress_root = ComputeBatchLeafRoot(
        Span<const BatchLeaf>{payload.ingress_leaves.data(), payload.ingress_leaves.size()});
    payload.l2_credit_root = ComputeV2IngressL2CreditRoot(
        Span<const BatchLeaf>{payload.ingress_leaves.data(), payload.ingress_leaves.size()});
    CanonicalizeIngressReserveOutputs(payload.reserve_outputs, payload.settlement_binding_digest);
    payload.aggregate_reserve_commitment = ComputeV2IngressAggregateReserveCommitment(
        Span<const OutputDescription>{payload.reserve_outputs.data(), payload.reserve_outputs.size()});
    payload.aggregate_fee_commitment = ComputeV2IngressAggregateFeeCommitment(
        Span<const BatchLeaf>{payload.ingress_leaves.data(), payload.ingress_leaves.size()});
}

void CanonicalizeEgressOutputs(std::vector<OutputDescription>& outputs,
                               const uint256& output_binding_digest)
{
    for (size_t output_index = 0; output_index < outputs.size(); ++output_index) {
        outputs[output_index].value_commitment = ComputeV2EgressOutputValueCommitment(
            output_binding_digest,
            static_cast<uint32_t>(output_index),
            outputs[output_index].note_commitment);
    }
}

void CanonicalizeRebalanceOutputs(std::vector<OutputDescription>& outputs)
{
    for (size_t output_index = 0; output_index < outputs.size(); ++output_index) {
        outputs[output_index].value_commitment = ComputeV2RebalanceOutputValueCommitment(
            static_cast<uint32_t>(output_index),
            outputs[output_index].note_commitment);
    }
}

void CanonicalizeRebalancePayload(RebalancePayload& payload)
{
    CanonicalizeRebalanceOutputs(payload.reserve_outputs);
    payload.settlement_binding_digest = ComputeNettingManifestId(payload.netting_manifest);
    payload.batch_statement_digest = ComputeV2RebalanceStatementDigest(
        payload.settlement_binding_digest,
        Span<const ReserveDelta>{payload.reserve_deltas.data(), payload.reserve_deltas.size()},
        Span<const OutputDescription>{payload.reserve_outputs.data(), payload.reserve_outputs.size()});
}

ReserveDelta MakeReserveDelta(unsigned char seed, CAmount delta)
{
    ReserveDelta reserve_delta;
    reserve_delta.l2_id = uint256{seed};
    reserve_delta.reserve_delta = delta;
    return reserve_delta;
}

BatchLeaf MakeBatchLeaf(uint32_t position, unsigned char seed)
{
    BatchLeaf leaf;
    leaf.family_id = TransactionFamily::V2_INGRESS_BATCH;
    leaf.l2_id = uint256{seed};
    leaf.destination_commitment = uint256{static_cast<unsigned char>(seed + 1)};
    leaf.amount_commitment = uint256{static_cast<unsigned char>(seed + 2)};
    leaf.fee_commitment = uint256{static_cast<unsigned char>(seed + 3)};
    leaf.position = position;
    leaf.nonce = uint256{static_cast<unsigned char>(seed + 4)};
    leaf.settlement_domain = uint256{static_cast<unsigned char>(seed + 5)};
    return leaf;
}

ProofShardDescriptor MakeProofShard(uint32_t first_leaf_index,
                                    uint32_t leaf_count,
                                    uint32_t payload_offset,
                                    uint32_t payload_size,
                                    unsigned char seed,
                                    const uint256& statement_digest)
{
    ProofShardDescriptor descriptor;
    descriptor.settlement_domain = uint256{seed};
    descriptor.first_leaf_index = first_leaf_index;
    descriptor.leaf_count = leaf_count;
    descriptor.leaf_subroot = uint256{static_cast<unsigned char>(seed + 1)};
    descriptor.nullifier_commitment = uint256{static_cast<unsigned char>(seed + 2)};
    descriptor.value_commitment = uint256{static_cast<unsigned char>(seed + 3)};
    descriptor.statement_digest = statement_digest;
    descriptor.proof_metadata = {seed, static_cast<uint8_t>(seed + 1)};
    descriptor.proof_payload_offset = payload_offset;
    descriptor.proof_payload_size = payload_size;
    return descriptor;
}

OutputChunkDescriptor MakeOutputChunk(const std::vector<OutputDescription>& outputs,
                                      uint32_t first_output_index,
                                      uint32_t output_count)
{
    const auto* begin = outputs.data() + first_output_index;
    auto descriptor = BuildOutputChunkDescriptor({begin, output_count}, first_output_index);
    if (!descriptor.has_value()) {
        throw std::runtime_error("failed to build valid test output chunk");
    }
    return *descriptor;
}

GenericOpaqueOutputRecord MakeGenericOutputRecordForTest(const OutputDescription& output)
{
    GenericOpaqueOutputRecord record;
    record.note_class = output.note_class;
    record.scan_domain = output.encrypted_note.scan_domain;
    record.note_commitment = output.note_commitment;
    record.value_commitment = output.value_commitment;
    record.has_smile_account = output.smile_account.has_value();
    if (record.has_smile_account) {
        record.smile_account = *output.smile_account;
    }
    record.has_smile_public_key =
        !record.has_smile_account && output.smile_public_key.has_value();
    if (record.has_smile_public_key) {
        record.smile_public_key = *output.smile_public_key;
    }
    record.encrypted_note = output.encrypted_note;
    return record;
}

void ApplyDerivedGenericOutputChunks(TransactionBundle& bundle)
{
    auto output_chunks = BuildDerivedGenericOutputChunks(bundle.payload);
    BOOST_REQUIRE(output_chunks.has_value());
    bundle.output_chunks = std::move(*output_chunks);
    bundle.header.output_chunk_root = bundle.output_chunks.empty()
        ? uint256::ZERO
        : ComputeOutputChunkRoot({bundle.output_chunks.data(), bundle.output_chunks.size()});
    bundle.header.output_chunk_count = bundle.output_chunks.size();
}

struct ParsedWireBundleMetadata
{
    TransactionHeader header;
    std::vector<uint8_t> payload_bytes;
    std::vector<ProofShardDescriptor> proof_shards;
    uint64_t output_chunk_count{0};
    std::vector<uint8_t> proof_payload;
};

ParsedWireBundleMetadata ParseWireBundleMetadata(const TransactionBundle& bundle)
{
    DataStream ss{};
    ss << bundle;

    ParsedWireBundleMetadata parsed;
    uint8_t bundle_version{0};
    ss >> bundle_version;
    BOOST_REQUIRE_EQUAL(bundle_version, WIRE_VERSION);
    ss >> parsed.header;
    ss >> parsed.payload_bytes;

    const uint64_t proof_shard_count = ReadCompactSize(ss);
    parsed.proof_shards.assign(proof_shard_count, {});
    for (auto& descriptor : parsed.proof_shards) {
        ss >> descriptor;
    }

    parsed.output_chunk_count = ReadCompactSize(ss);
    if (!UseDerivedGenericOutputChunkWire(parsed.header, bundle.payload)) {
        std::vector<OutputChunkDescriptor> ignored_chunks(parsed.output_chunk_count);
        for (auto& descriptor : ignored_chunks) {
            ss >> descriptor;
        }
    }

    ss >> parsed.proof_payload;
    return parsed;
}

GenericOpaquePayloadEnvelope ParseRawOpaquePayloadEnvelope(const TransactionBundle& bundle)
{
    const auto parsed = ParseWireBundleMetadata(bundle);
    auto envelope = DeserializeOpaquePayloadEnvelopeWire(parsed.payload_bytes, /*strip_padding=*/false);
    BOOST_REQUIRE(envelope.has_value());
    return *envelope;
}

void ExpectCanonicalOpaqueSectionSurface(const GenericOpaquePayloadEnvelope& envelope)
{
    BOOST_CHECK(!envelope.spend_anchor.IsNull());
    BOOST_CHECK(!envelope.account_registry_anchor.IsNull());
    BOOST_CHECK(!envelope.settlement_anchor.IsNull());
    BOOST_CHECK(!envelope.ingress_root.IsNull());
    BOOST_CHECK(!envelope.l2_credit_root.IsNull());
    BOOST_CHECK(!envelope.aggregate_reserve_commitment.IsNull());
    BOOST_CHECK(!envelope.aggregate_fee_commitment.IsNull());
    BOOST_CHECK(!envelope.output_binding_digest.IsNull());
    BOOST_CHECK(!envelope.egress_root.IsNull());
    BOOST_CHECK(!envelope.settlement_binding_digest.IsNull());
    BOOST_CHECK(!envelope.batch_statement_digest.IsNull());
    BOOST_CHECK(!envelope.anchored_netting_manifest_id.IsNull());
    BOOST_CHECK(!envelope.spends.empty());
    BOOST_CHECK(!envelope.outputs.empty());
    BOOST_CHECK(!envelope.lifecycle_controls.empty());
    BOOST_CHECK(!envelope.ingress_leaves.empty());
    BOOST_CHECK(!envelope.reserve_deltas.empty());
    BOOST_CHECK(!envelope.imported_claim_ids.empty());
    BOOST_CHECK(!envelope.imported_adapter_ids.empty());
    BOOST_CHECK(!envelope.proof_receipt_ids.empty());
    BOOST_CHECK(!envelope.batch_statement_digests.empty());
    BOOST_CHECK(envelope.spends.front().IsValid());
    BOOST_CHECK(envelope.outputs.front().IsValid());
    BOOST_CHECK(envelope.lifecycle_controls.front().IsValid());
    BOOST_CHECK(envelope.ingress_leaves.front().IsValid());
    BOOST_CHECK(envelope.reserve_deltas.front().IsValid());
    BOOST_CHECK(envelope.has_netting_manifest);
    BOOST_CHECK(envelope.netting_manifest.IsValid());
}

template <typename F>
void ExpectMissingSmileAccountSerialize(F&& fn)
{
    BOOST_CHECK_EXCEPTION(static_cast<void>(fn()),
                          std::ios_base::failure,
                          [](const std::ios_base::failure& ex) {
                              const std::string what{ex.what()};
                              return what.find("OutputDescription::Serialize missing smile_account") != std::string::npos ||
                                     what.find("OutputDescription::SerializeWithSharedMetadata missing smile_account") != std::string::npos ||
                                     what.find("OutputDescription::SerializeDirectSend missing smile_account") != std::string::npos ||
                                     what.find("OutputDescription::SerializeIngressReserve missing smile_account") != std::string::npos ||
                                     what.find("OutputDescription::SerializeEgressOutput missing smile_account") != std::string::npos ||
                                     what.find("OutputDescription::SerializeRebalanceReserve missing smile_account") != std::string::npos;
                          });
}

ProofEnvelope MakeProofEnvelope(ProofKind kind,
                                SettlementBindingKind binding_kind,
                                const uint256& statement_digest = uint256{0x55})
{
    ProofEnvelope envelope;
    envelope.proof_kind = kind;
    switch (kind) {
    case ProofKind::DIRECT_MATRICT:
    case ProofKind::BATCH_MATRICT:
        envelope.membership_proof_kind = ProofComponentKind::MATRICT;
        envelope.amount_proof_kind = ProofComponentKind::RANGE;
        envelope.balance_proof_kind = ProofComponentKind::BALANCE;
        break;
    case ProofKind::IMPORTED_RECEIPT:
    case ProofKind::IMPORTED_CLAIM:
    case ProofKind::GENERIC_BRIDGE:
    case ProofKind::NONE:
        envelope.membership_proof_kind = ProofComponentKind::NONE;
        envelope.amount_proof_kind = ProofComponentKind::NONE;
        envelope.balance_proof_kind = ProofComponentKind::NONE;
        break;
    case ProofKind::DIRECT_SMILE:
    case ProofKind::BATCH_SMILE:
    case ProofKind::GENERIC_SMILE:
        envelope.membership_proof_kind = ProofComponentKind::MATRICT;
        envelope.amount_proof_kind = ProofComponentKind::RANGE;
        envelope.balance_proof_kind = ProofComponentKind::BALANCE;
        break;
    case ProofKind::GENERIC_OPAQUE:
        envelope.membership_proof_kind = ProofComponentKind::GENERIC_OPAQUE;
        envelope.amount_proof_kind = ProofComponentKind::GENERIC_OPAQUE;
        envelope.balance_proof_kind = ProofComponentKind::GENERIC_OPAQUE;
        break;
    }
    envelope.settlement_binding_kind = binding_kind;
    envelope.statement_digest = kind == ProofKind::NONE ? uint256::ZERO : statement_digest;
    return envelope;
}

NettingManifest MakeNettingManifest(const std::vector<ReserveDelta>& deltas)
{
    NettingManifest manifest;
    manifest.settlement_window = 144;
    manifest.binding_kind = SettlementBindingKind::NETTING_MANIFEST;
    manifest.gross_flow_commitment = uint256{0x44};
    manifest.authorization_digest = uint256{0x45};
    manifest.aggregate_net_delta = 0;
    for (const ReserveDelta& delta : deltas) {
        manifest.domains.push_back({delta.l2_id, delta.reserve_delta});
    }
    return manifest;
}

TransactionHeader MakeBaseHeader(TransactionFamily family,
                                 ProofKind kind,
                                 SettlementBindingKind binding_kind,
                                 const uint256& statement_digest = uint256{0x55})
{
    TransactionHeader header;
    header.family_id = family;
    header.proof_envelope = MakeProofEnvelope(kind, binding_kind, statement_digest);
    return header;
}

BOOST_FIXTURE_TEST_SUITE(shielded_v2_bundle_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(send_bundle_roundtrip_and_bundle_id_commits_to_proof_payload)
{
    SendPayload payload;
    payload.spend_anchor = uint256{0x01};
    payload.account_registry_anchor = uint256{0x02};
    payload.spends = {MakeSpend(0x10), MakeSpend(0x20)};
    payload.outputs = {MakeOutput(NoteClass::USER, ScanDomain::USER, 0x30),
                       MakeOutput(NoteClass::USER, ScanDomain::USER, 0x40)};
    payload.fee = 2 * COIN;
    payload.value_balance = payload.fee;

    TransactionBundle bundle;
    bundle.header = MakeBaseHeader(TransactionFamily::V2_SEND, ProofKind::DIRECT_MATRICT, SettlementBindingKind::NONE);
    bundle.payload = payload;
    bundle.proof_payload = {0x01, 0x02, 0x03, 0x04};
    bundle.header.payload_digest = ComputeSendPayloadDigest(payload);

    BOOST_REQUIRE(bundle.IsValid());

    DataStream ss{};
    ss << bundle;

    TransactionBundle decoded;
    ss >> decoded;
    BOOST_REQUIRE(decoded.IsValid());
    BOOST_CHECK(ComputeTransactionBundleId(decoded) == ComputeTransactionBundleId(bundle));

    TransactionBundle different_proof = bundle;
    different_proof.proof_payload.push_back(0x99);
    BOOST_CHECK(ComputeTransactionBundleId(different_proof) != ComputeTransactionBundleId(bundle));
}

BOOST_AUTO_TEST_CASE(postfork_generic_send_bundle_roundtrip_uses_opaque_payload_encoding)
{
    SendPayload payload;
    payload.outputs = {MakeOutput(NoteClass::USER, ScanDomain::USER, 0x30),
                       MakeOutput(NoteClass::USER, ScanDomain::USER, 0x40)};
    payload.fee = 2 * COIN;
    payload.value_balance = -payload.fee;

    TransactionBundle legacy_bundle;
    legacy_bundle.header = MakeBaseHeader(TransactionFamily::V2_SEND,
                                          ProofKind::NONE,
                                          SettlementBindingKind::NONE);
    legacy_bundle.payload = payload;
    legacy_bundle.header.payload_digest = ComputeSendPayloadDigest(payload);
    BOOST_REQUIRE(legacy_bundle.IsValid());

    TransactionBundle generic_bundle = legacy_bundle;
    generic_bundle.header.family_id = TransactionFamily::V2_GENERIC;
    generic_bundle.header.proof_envelope.settlement_binding_kind =
        SettlementBindingKind::GENERIC_POSTFORK;
    ApplyDerivedGenericOutputChunks(generic_bundle);
    BOOST_REQUIRE(generic_bundle.IsValid());

    DataStream legacy_stream{};
    legacy_stream << legacy_bundle;
    DataStream generic_stream{};
    generic_stream << generic_bundle;

    const bool identical_serialization =
        legacy_stream.size() == generic_stream.size() &&
        std::equal(legacy_stream.begin(), legacy_stream.end(), generic_stream.begin());
    BOOST_CHECK(!identical_serialization);

    const auto opaque_bytes = SerializePayloadBytes(payload, TransactionFamily::V2_SEND);
    BOOST_REQUIRE(!opaque_bytes.empty());
    BOOST_CHECK_EQUAL(opaque_bytes.size() % OPAQUE_FAMILY_PAYLOAD_PAD_QUANTUM, 0U);

    TransactionBundle decoded;
    generic_stream >> decoded;
    BOOST_REQUIRE(decoded.IsValid());
    BOOST_CHECK_EQUAL(decoded.header.family_id, TransactionFamily::V2_GENERIC);
    BOOST_CHECK(BundleHasSemanticFamily(decoded, TransactionFamily::V2_SEND));
    BOOST_CHECK(std::holds_alternative<SendPayload>(decoded.payload));
    BOOST_CHECK(ComputeTransactionBundleId(decoded) == ComputeTransactionBundleId(generic_bundle));
}

BOOST_AUTO_TEST_CASE(postfork_generic_output_record_omits_redundant_smile_public_key_when_account_present)
{
    const ShieldedNote input_note = MakeDirectSendNote(/*value=*/5000, /*seed=*/0x54);
    const ShieldedNote output_note = MakeDirectSendNote(/*value=*/4900, /*seed=*/0x55);
    const size_t real_index = 3;
    const auto tree = BuildDirectSendTree(input_note.GetCommitment(), real_index);
    const auto ring_positions = BuildDirectSendRingPositions();
    const auto ring_members = BuildDirectSendRingMembers(tree, ring_positions);
    const auto spend_input = MakeDirectSendSpendInput(input_note, ring_positions, ring_members, real_index);

    const mlkem::KeyPair recipient = BuildRecipientKeyPair(/*seed=*/0x65);
    const auto encrypted_note = BuildEncryptedNote(output_note, recipient.pk, /*kem_seed_byte=*/0x75, /*nonce_byte=*/0x85);
    auto encrypted_payload = EncodeLegacyEncryptedNotePayload(encrypted_note,
                                                              recipient.pk,
                                                              ScanDomain::USER);
    BOOST_REQUIRE(encrypted_payload.has_value());

    V2SendOutputInput output_input;
    output_input.note_class = NoteClass::USER;
    output_input.note = output_note;
    output_input.encrypted_note = *encrypted_payload;
    BOOST_REQUIRE(output_input.IsValid());

    std::array<unsigned char, 32> rng_entropy{};
    rng_entropy.fill(0x96);
    std::string reject_reason;
    auto built = BuildV2SendTransaction(CMutableTransaction{},
                                        tree.Root(),
                                        {spend_input},
                                        {output_input},
                                        /*fee=*/100,
                                        std::vector<unsigned char>(32, 0x33),
                                        reject_reason,
                                        Span<const unsigned char>{rng_entropy.data(), rng_entropy.size()},
                                        &Params().GetConsensus(),
                                        Params().GetConsensus().nShieldedMatRiCTDisableHeight);
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);
    const auto* bundle = built->tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_REQUIRE(bundle->IsValid());
    BOOST_CHECK_EQUAL(bundle->header.family_id, TransactionFamily::V2_GENERIC);

    const auto raw_envelope = ParseRawOpaquePayloadEnvelope(*bundle);
    BOOST_REQUIRE_GE(raw_envelope.outputs.size(), 1U);
    BOOST_CHECK(!raw_envelope.outputs.front().has_smile_account);
    BOOST_CHECK(raw_envelope.outputs.front().has_smile_public_key);

    DataStream stream{};
    stream << *bundle;
    TransactionBundle decoded;
    stream >> decoded;
    BOOST_REQUIRE(decoded.IsValid());
    BOOST_REQUIRE(std::holds_alternative<SendPayload>(decoded.payload));

    const auto& decoded_payload = std::get<SendPayload>(decoded.payload);
    BOOST_REQUIRE_EQUAL(decoded_payload.outputs.size(), 1U);
    BOOST_REQUIRE(decoded_payload.outputs.front().smile_account.has_value());
    BOOST_REQUIRE(decoded_payload.outputs.front().smile_public_key.has_value());
    const auto expected_key =
        smile2::ExtractCompactPublicKeyData(*decoded_payload.outputs.front().smile_account);
    BOOST_REQUIRE_EQUAL(decoded_payload.outputs.front().smile_public_key->public_key.size(),
                        expected_key.public_key.size());
    BOOST_CHECK(std::equal(decoded_payload.outputs.front().smile_public_key->public_key.begin(),
                           decoded_payload.outputs.front().smile_public_key->public_key.end(),
                           expected_key.public_key.begin()));
}

BOOST_AUTO_TEST_CASE(legacy_send_payload_without_lifecycle_controls_remains_deserializable)
{
    SendPayload legacy_payload;
    legacy_payload.output_encoding = SendOutputEncoding::LEGACY;
    legacy_payload.outputs = {MakeOutput(NoteClass::USER, ScanDomain::USER, 0x39)};
    legacy_payload.fee = 123;
    // Use a low byte of 0x00 so the legacy value_balance can be misread as a
    // zero lifecycle-control count unless the parser validates the full tail.
    legacy_payload.value_balance = -256;
    BOOST_REQUIRE(legacy_payload.IsValid());

    std::vector<unsigned char> legacy_bytes;
    VectorWriter legacy_writer(legacy_bytes, 0, LegacyPreLifecycleSendPayloadWire{legacy_payload});

    DataStream legacy_stream{Span<const unsigned char>{legacy_bytes.data(), legacy_bytes.size()}};
    SendPayload legacy_decoded;
    legacy_decoded.Unserialize(legacy_stream);

    BOOST_CHECK(legacy_stream.empty());
    BOOST_CHECK(legacy_decoded.IsValid());
    BOOST_CHECK_EQUAL(legacy_decoded.output_encoding, legacy_payload.output_encoding);
    BOOST_REQUIRE_EQUAL(legacy_decoded.outputs.size(), legacy_payload.outputs.size());
    BOOST_CHECK_EQUAL(legacy_decoded.outputs.front().note_commitment,
                      legacy_payload.outputs.front().note_commitment);
    BOOST_CHECK_EQUAL(legacy_decoded.outputs.front().value_commitment,
                      legacy_payload.outputs.front().value_commitment);
    BOOST_CHECK_EQUAL(legacy_decoded.value_balance, legacy_payload.value_balance);
    BOOST_CHECK_EQUAL(legacy_decoded.fee, legacy_payload.fee);
    BOOST_CHECK(legacy_decoded.lifecycle_controls.empty());
    BOOST_CHECK(legacy_decoded.legacy_omit_lifecycle_controls_count);
    std::vector<unsigned char> legacy_roundtrip_bytes;
    VectorWriter legacy_roundtrip_writer(legacy_roundtrip_bytes, 0, legacy_decoded);
    BOOST_CHECK(legacy_roundtrip_bytes == legacy_bytes);

    SpanReader legacy_span_reader{Span<const unsigned char>{legacy_bytes.data(), legacy_bytes.size()}};
    SendPayload legacy_span_decoded;
    legacy_span_decoded.Unserialize(legacy_span_reader);

    BOOST_CHECK(legacy_span_reader.empty());
    BOOST_CHECK(legacy_span_decoded.IsValid());
    BOOST_CHECK_EQUAL(legacy_span_decoded.output_encoding, legacy_payload.output_encoding);
    BOOST_REQUIRE_EQUAL(legacy_span_decoded.outputs.size(), legacy_payload.outputs.size());
    BOOST_CHECK_EQUAL(legacy_span_decoded.outputs.front().note_commitment,
                      legacy_payload.outputs.front().note_commitment);
    BOOST_CHECK_EQUAL(legacy_span_decoded.outputs.front().value_commitment,
                      legacy_payload.outputs.front().value_commitment);
    BOOST_CHECK_EQUAL(legacy_span_decoded.value_balance, legacy_payload.value_balance);
    BOOST_CHECK_EQUAL(legacy_span_decoded.fee, legacy_payload.fee);
    BOOST_CHECK(legacy_span_decoded.lifecycle_controls.empty());
    BOOST_CHECK(legacy_span_decoded.legacy_omit_lifecycle_controls_count);
    std::vector<unsigned char> legacy_span_roundtrip_bytes;
    VectorWriter legacy_span_roundtrip_writer(legacy_span_roundtrip_bytes, 0, legacy_span_decoded);
    BOOST_CHECK(legacy_span_roundtrip_bytes == legacy_bytes);

    auto legacy_params_stream = ParamsStream{
        SpanReader{Span<const unsigned char>{legacy_bytes.data(), legacy_bytes.size()}},
        TX_WITH_WITNESS};
    SendPayload legacy_params_decoded;
    legacy_params_decoded.Unserialize(legacy_params_stream);

    BOOST_CHECK(legacy_params_stream.empty());
    BOOST_CHECK(legacy_params_decoded.IsValid());
    BOOST_CHECK_EQUAL(legacy_params_decoded.output_encoding, legacy_payload.output_encoding);
    BOOST_REQUIRE_EQUAL(legacy_params_decoded.outputs.size(), legacy_payload.outputs.size());
    BOOST_CHECK_EQUAL(legacy_params_decoded.outputs.front().note_commitment,
                      legacy_payload.outputs.front().note_commitment);
    BOOST_CHECK_EQUAL(legacy_params_decoded.outputs.front().value_commitment,
                      legacy_payload.outputs.front().value_commitment);
    BOOST_CHECK_EQUAL(legacy_params_decoded.value_balance, legacy_payload.value_balance);
    BOOST_CHECK_EQUAL(legacy_params_decoded.fee, legacy_payload.fee);
    BOOST_CHECK(legacy_params_decoded.lifecycle_controls.empty());
    BOOST_CHECK(legacy_params_decoded.legacy_omit_lifecycle_controls_count);
    std::vector<unsigned char> legacy_params_roundtrip_bytes;
    VectorWriter legacy_params_roundtrip_writer(legacy_params_roundtrip_bytes, 0, legacy_params_decoded);
    BOOST_CHECK(legacy_params_roundtrip_bytes == legacy_bytes);
}

BOOST_AUTO_TEST_CASE(postfork_generic_send_bundle_bucket_pads_opaque_payload_counts)
{
    SendPayload payload;
    payload.outputs = {MakeOutput(NoteClass::USER, ScanDomain::USER, 0x3a)};
    payload.fee = 0;
    payload.value_balance = -1;

    TransactionBundle generic_bundle;
    generic_bundle.header = MakeBaseHeader(TransactionFamily::V2_GENERIC,
                                           ProofKind::NONE,
                                           SettlementBindingKind::NONE);
    generic_bundle.payload = payload;
    generic_bundle.header.payload_digest = ComputeSendPayloadDigest(payload);
    ApplyDerivedGenericOutputChunks(generic_bundle);
    BOOST_REQUIRE(generic_bundle.IsValid());

    const auto opaque_bytes = SerializePayloadBytes(payload, TransactionFamily::V2_SEND);
    BOOST_REQUIRE(!opaque_bytes.empty());

    const auto raw_envelope = ParseRawOpaquePayloadEnvelope(generic_bundle);
    ExpectCanonicalOpaqueSectionSurface(raw_envelope);
    BOOST_CHECK_EQUAL(raw_envelope.spends.size(), 1U);
    BOOST_CHECK_EQUAL(raw_envelope.outputs.size(), 2U);
    BOOST_CHECK(raw_envelope.outputs.front().IsValid());
    BOOST_CHECK(raw_envelope.outputs.back().IsValid());
    BOOST_CHECK_EQUAL(raw_envelope.lifecycle_controls.size(), 1U);
    BOOST_CHECK_EQUAL(raw_envelope.ingress_leaves.size(), 1U);
    BOOST_CHECK_EQUAL(raw_envelope.reserve_deltas.size(), 1U);
    BOOST_CHECK_EQUAL(raw_envelope.imported_claim_ids.size(), 1U);
    BOOST_CHECK(raw_envelope.has_netting_manifest);

    const auto semantic_payload = DeserializeOpaquePayload(opaque_bytes, generic_bundle.header);
    BOOST_REQUIRE(std::holds_alternative<SendPayload>(semantic_payload));
    const auto& decoded = std::get<SendPayload>(semantic_payload);
    BOOST_CHECK(decoded.spends.empty());
    BOOST_CHECK_EQUAL(decoded.outputs.size(), 1U);
    BOOST_CHECK(decoded.lifecycle_controls.empty());
}

BOOST_AUTO_TEST_CASE(postfork_generic_payload_surface_unifies_unused_sections_across_families)
{
    SendPayload send_payload;
    send_payload.outputs = {MakeOutput(NoteClass::USER, ScanDomain::USER, 0x3c)};
    send_payload.fee = 0;
    send_payload.value_balance = -1;

    TransactionBundle send_bundle;
    send_bundle.header = MakeBaseHeader(TransactionFamily::V2_GENERIC,
                                        ProofKind::NONE,
                                        SettlementBindingKind::NONE);
    send_bundle.payload = send_payload;
    send_bundle.header.payload_digest = ComputeSendPayloadDigest(send_payload);
    ApplyDerivedGenericOutputChunks(send_bundle);
    BOOST_REQUIRE(send_bundle.IsValid());

    const auto send_envelope = ParseRawOpaquePayloadEnvelope(send_bundle);
    ExpectCanonicalOpaqueSectionSurface(send_envelope);

    const auto settlement_fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture();
    const auto* settlement_bundle = settlement_fixture.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(settlement_bundle != nullptr);
    BOOST_REQUIRE_EQUAL(settlement_bundle->header.family_id, TransactionFamily::V2_GENERIC);
    const auto settlement_envelope = ParseRawOpaquePayloadEnvelope(*settlement_bundle);
    ExpectCanonicalOpaqueSectionSurface(settlement_envelope);

    BOOST_CHECK_EQUAL(send_envelope.has_netting_manifest, settlement_envelope.has_netting_manifest);
    BOOST_CHECK(!send_envelope.spend_anchor.IsNull() && !settlement_envelope.spend_anchor.IsNull());
    BOOST_CHECK(!send_envelope.settlement_anchor.IsNull() && !settlement_envelope.settlement_anchor.IsNull());
    BOOST_CHECK(!send_envelope.ingress_root.IsNull() && !settlement_envelope.ingress_root.IsNull());
    BOOST_CHECK(!send_envelope.output_binding_digest.IsNull() &&
                !settlement_envelope.output_binding_digest.IsNull());
}

BOOST_AUTO_TEST_CASE(postfork_generic_send_bundle_bucket_pads_wire_metadata_counts)
{
    SendPayload payload;
    payload.outputs = {MakeOutput(NoteClass::USER, ScanDomain::USER, 0x3b)};
    payload.fee = 0;
    payload.value_balance = -1;

    TransactionBundle generic_bundle;
    generic_bundle.header = MakeBaseHeader(TransactionFamily::V2_GENERIC,
                                           ProofKind::NONE,
                                           SettlementBindingKind::NONE);
    generic_bundle.payload = payload;
    generic_bundle.header.payload_digest = ComputeSendPayloadDigest(payload);
    ApplyDerivedGenericOutputChunks(generic_bundle);
    BOOST_REQUIRE(generic_bundle.IsValid());

    const auto wire = ParseWireBundleMetadata(generic_bundle);
    BOOST_CHECK_EQUAL(wire.header.proof_shard_count, 1U);
    BOOST_CHECK_EQUAL(wire.proof_shards.size(), 1U);
    BOOST_CHECK_EQUAL(wire.header.output_chunk_count, 2U);
    BOOST_CHECK_EQUAL(wire.output_chunk_count, 2U);
    BOOST_CHECK(!wire.header.proof_shard_root.IsNull());
    BOOST_CHECK(!wire.header.output_chunk_root.IsNull());

    DataStream ss{};
    ss << generic_bundle;
    TransactionBundle decoded;
    ss >> decoded;
    BOOST_REQUIRE(decoded.IsValid());
    BOOST_CHECK(decoded.proof_shards.empty());
    BOOST_CHECK_EQUAL(decoded.header.proof_shard_count, 0U);
    BOOST_REQUIRE_EQUAL(decoded.output_chunks.size(), 1U);
    BOOST_CHECK_EQUAL(decoded.header.output_chunk_count, 1U);
    BOOST_CHECK(ComputeTransactionBundleId(decoded) == ComputeTransactionBundleId(generic_bundle));
}

BOOST_AUTO_TEST_CASE(postfork_generic_send_bundle_rejects_noncanonical_unpadded_opaque_payload)
{
    SendPayload payload;
    payload.outputs = {MakeOutput(NoteClass::USER, ScanDomain::USER, 0x14)};
    payload.fee = 0;
    payload.value_balance = -1;

    TransactionBundle generic_bundle;
    generic_bundle.header = MakeBaseHeader(TransactionFamily::V2_GENERIC,
                                           ProofKind::NONE,
                                           SettlementBindingKind::NONE);
    generic_bundle.payload = payload;
    generic_bundle.header.payload_digest = ComputeSendPayloadDigest(payload);
    ApplyDerivedGenericOutputChunks(generic_bundle);
    BOOST_REQUIRE(generic_bundle.IsValid());

    DataStream raw_payload_stream{};
    SerializePayload(raw_payload_stream, payload, TransactionFamily::V2_SEND);
    const auto* begin = reinterpret_cast<const uint8_t*>(raw_payload_stream.data());
    const std::vector<uint8_t> raw_payload_bytes{begin, begin + raw_payload_stream.size()};

    BOOST_REQUIRE_LT(raw_payload_bytes.size(), SerializePayloadBytes(payload, TransactionFamily::V2_SEND).size());
    BOOST_CHECK_THROW(
        [&] {
            (void)DeserializeOpaquePayload(raw_payload_bytes, generic_bundle.header);
        }(),
        std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(postfork_generic_send_bundle_rejects_padded_legacy_family_payload_bytes)
{
    SendPayload payload;
    payload.outputs = {MakeOutput(NoteClass::USER, ScanDomain::USER, 0x21),
                       MakeOutput(NoteClass::USER, ScanDomain::USER, 0x22)};
    payload.fee = COIN;
    payload.value_balance = -payload.fee;

    TransactionBundle generic_bundle;
    generic_bundle.header = MakeBaseHeader(TransactionFamily::V2_GENERIC,
                                           ProofKind::NONE,
                                           SettlementBindingKind::NONE);
    generic_bundle.payload = payload;
    generic_bundle.header.payload_digest = ComputeSendPayloadDigest(payload);
    ApplyDerivedGenericOutputChunks(generic_bundle);
    BOOST_REQUIRE(generic_bundle.IsValid());

    DataStream raw_payload_stream{};
    SerializePayload(raw_payload_stream, payload, TransactionFamily::V2_SEND);
    const auto* begin = reinterpret_cast<const uint8_t*>(raw_payload_stream.data());
    std::vector<uint8_t> padded_legacy_payload{begin, begin + raw_payload_stream.size()};
    const size_t quantum = static_cast<size_t>(OPAQUE_FAMILY_PAYLOAD_PAD_QUANTUM);
    const size_t padded_size = ((padded_legacy_payload.size() + quantum - 1) / quantum) * quantum;
    padded_legacy_payload.resize(padded_size, 0);

    const auto generic_payload_bytes = SerializePayloadBytes(payload, TransactionFamily::V2_SEND);
    BOOST_REQUIRE(!generic_payload_bytes.empty());
    BOOST_CHECK(padded_legacy_payload != generic_payload_bytes);
    BOOST_CHECK_THROW(
        [&] {
            (void)DeserializeOpaquePayload(padded_legacy_payload, generic_bundle.header);
        }(),
        std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(postfork_generic_send_bundle_rejects_noncanonical_exact_count_opaque_envelope)
{
    SendPayload payload;
    payload.outputs = {MakeOutput(NoteClass::USER, ScanDomain::USER, 0x24)};
    payload.fee = 0;
    payload.value_balance = -1;

    GenericOpaquePayloadEnvelope envelope;
    envelope.output_encoding = payload.output_encoding;
    envelope.output_note_class = payload.output_note_class;
    envelope.output_scan_domain = payload.output_scan_domain;
    envelope.value_balance = payload.value_balance;
    envelope.fee = payload.fee;
    envelope.outputs = {MakeGenericOutputRecordForTest(payload.outputs.front())};

    DataStream envelope_stream{};
    envelope_stream << envelope;
    const auto* begin = reinterpret_cast<const uint8_t*>(envelope_stream.data());
    std::vector<uint8_t> opaque_bytes{begin, begin + envelope_stream.size()};
    const size_t quantum = static_cast<size_t>(OPAQUE_FAMILY_PAYLOAD_PAD_QUANTUM);
    opaque_bytes.resize(((opaque_bytes.size() + quantum - 1) / quantum) * quantum, 0);

    TransactionHeader header = MakeBaseHeader(TransactionFamily::V2_GENERIC,
                                              ProofKind::NONE,
                                              SettlementBindingKind::NONE);
    header.payload_digest = ComputeSendPayloadDigest(payload);

    BOOST_CHECK_THROW(
        [&] {
            (void)DeserializeOpaquePayload(opaque_bytes, header);
        }(),
        std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(address_lifecycle_control_signature_binds_note_commitment_and_successor)
{
    CPQKey subject_key;
    CPQKey successor_key;
    CPQKey alternate_successor_key;
    subject_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    successor_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    alternate_successor_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(subject_key.IsValid());
    BOOST_REQUIRE(successor_key.IsValid());
    BOOST_REQUIRE(alternate_successor_key.IsValid());

    const auto subject = MakeLifecycleAddress(subject_key, 0x20);
    const auto successor = MakeLifecycleAddress(successor_key, 0x40);
    const auto alternate_successor = MakeLifecycleAddress(alternate_successor_key, 0x60);
    const auto output = MakeOutput(NoteClass::OPERATOR, ScanDomain::OPAQUE, 0x55);
    const auto control = MakeLifecycleControl(AddressLifecycleControlKind::ROTATE,
                                              subject_key,
                                              subject,
                                              successor,
                                              output.note_commitment);

    BOOST_CHECK(VerifyAddressLifecycleControl(control, output.note_commitment));
    BOOST_CHECK(!VerifyAddressLifecycleControl(control, uint256{0x91}));

    auto tampered = control;
    tampered.successor = alternate_successor;
    BOOST_CHECK(!VerifyAddressLifecycleControl(tampered, output.note_commitment));
}

BOOST_AUTO_TEST_CASE(address_lifecycle_record_signature_binds_transparent_binding_digest_and_successor)
{
    CPQKey subject_key;
    CPQKey successor_key;
    CPQKey alternate_successor_key;
    subject_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    successor_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    alternate_successor_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(subject_key.IsValid());
    BOOST_REQUIRE(successor_key.IsValid());
    BOOST_REQUIRE(alternate_successor_key.IsValid());

    const auto subject = MakeLifecycleAddress(subject_key, 0x20);
    const auto successor = MakeLifecycleAddress(successor_key, 0x40);
    const auto alternate_successor = MakeLifecycleAddress(alternate_successor_key, 0x60);
    const CTransaction binding_tx = MakeLifecycleBindingTx(0x55);
    const uint256 binding_digest = ComputeV2LifecycleTransparentBindingDigest(binding_tx);
    BOOST_REQUIRE(!binding_digest.IsNull());

    const auto control = MakeLifecycleRecord(AddressLifecycleControlKind::ROTATE,
                                             subject_key,
                                             subject,
                                             successor,
                                             binding_digest);

    BOOST_CHECK(VerifyAddressLifecycleRecord(control, binding_digest));
    BOOST_CHECK(!VerifyAddressLifecycleRecord(control, uint256{0x91}));

    auto tampered = control;
    tampered.successor = alternate_successor;
    BOOST_CHECK(!VerifyAddressLifecycleRecord(tampered, binding_digest));
}

BOOST_AUTO_TEST_CASE(send_payload_rejects_tampered_or_misencoded_address_lifecycle_control)
{
    CPQKey subject_key;
    CPQKey successor_key;
    subject_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    successor_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(subject_key.IsValid());
    BOOST_REQUIRE(successor_key.IsValid());

    SendPayload payload;
    payload.output_encoding = SendOutputEncoding::LEGACY;
    payload.output_note_class = NoteClass::OPERATOR;
    payload.output_scan_domain = ScanDomain::OPAQUE;
    payload.outputs = {MakeOutput(NoteClass::OPERATOR, ScanDomain::OPAQUE, 0x31)};
    payload.value_balance = -10000;
    payload.fee = 10000;

    const auto subject = MakeLifecycleAddress(subject_key, 0x10);
    const auto successor = MakeLifecycleAddress(successor_key, 0x30);
    payload.lifecycle_controls = {MakeLifecycleControl(AddressLifecycleControlKind::ROTATE,
                                                       subject_key,
                                                       subject,
                                                       successor,
                                                       payload.outputs[0].note_commitment)};
    BOOST_REQUIRE(payload.IsValid());

    auto tampered_signature = payload;
    tampered_signature.lifecycle_controls.front().signature.front() ^= 0x01;
    BOOST_CHECK(!tampered_signature.IsValid());

    auto compact_encoding = payload;
    compact_encoding.output_encoding = SendOutputEncoding::SMILE_COMPACT_POSTFORK;
    BOOST_CHECK(!compact_encoding.IsValid());
}

BOOST_AUTO_TEST_CASE(lifecycle_payload_rejects_tampered_transparent_binding_digest)
{
    CPQKey subject_key;
    CPQKey successor_key;
    subject_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    successor_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(subject_key.IsValid());
    BOOST_REQUIRE(successor_key.IsValid());

    const auto subject = MakeLifecycleAddress(subject_key, 0x10);
    const auto successor = MakeLifecycleAddress(successor_key, 0x30);
    const CTransaction binding_tx = MakeLifecycleBindingTx(0x56);
    const uint256 binding_digest = ComputeV2LifecycleTransparentBindingDigest(binding_tx);
    BOOST_REQUIRE(!binding_digest.IsNull());

    LifecyclePayload payload;
    payload.transparent_binding_digest = binding_digest;
    payload.lifecycle_controls = {MakeLifecycleRecord(AddressLifecycleControlKind::ROTATE,
                                                      subject_key,
                                                      subject,
                                                      successor,
                                                      binding_digest)};
    BOOST_REQUIRE(payload.IsValid());

    auto tampered = payload;
    tampered.transparent_binding_digest = uint256{0x91};
    BOOST_CHECK(!tampered.IsValid());
}

BOOST_AUTO_TEST_CASE(postfork_generic_lifecycle_bundle_roundtrip_preserves_transparent_binding_and_controls)
{
    CPQKey subject_key;
    CPQKey successor_key;
    subject_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    successor_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(subject_key.IsValid());
    BOOST_REQUIRE(successor_key.IsValid());

    const auto subject = MakeLifecycleAddress(subject_key, 0x10);
    const auto successor = MakeLifecycleAddress(successor_key, 0x30);
    const CTransaction binding_tx = MakeLifecycleBindingTx(0x57);
    const uint256 binding_digest = ComputeV2LifecycleTransparentBindingDigest(binding_tx);
    BOOST_REQUIRE(!binding_digest.IsNull());

    LifecyclePayload payload;
    payload.transparent_binding_digest = binding_digest;
    payload.lifecycle_controls = {MakeLifecycleRecord(AddressLifecycleControlKind::ROTATE,
                                                      subject_key,
                                                      subject,
                                                      successor,
                                                      binding_digest)};
    BOOST_REQUIRE(payload.IsValid());

    TransactionBundle bundle;
    bundle.header = MakeBaseHeader(TransactionFamily::V2_GENERIC,
                                   ProofKind::NONE,
                                   SettlementBindingKind::GENERIC_POSTFORK);
    bundle.payload = payload;
    bundle.header.payload_digest = ComputeLifecyclePayloadDigest(payload);
    ApplyDerivedGenericOutputChunks(bundle);
    BOOST_REQUIRE(bundle.IsValid());
    BOOST_CHECK(bundle.output_chunks.empty());
    BOOST_CHECK_EQUAL(bundle.header.output_chunk_count, 0U);

    const auto raw_envelope = ParseRawOpaquePayloadEnvelope(bundle);
    BOOST_CHECK_EQUAL(raw_envelope.transparent_binding_digest, payload.transparent_binding_digest);
    BOOST_CHECK_EQUAL(raw_envelope.lifecycle_controls.size(), 1U);
    BOOST_CHECK(raw_envelope.lifecycle_controls.front().IsValid());
    BOOST_CHECK(raw_envelope.outputs.size() >= 1U);

    DataStream ss{};
    ss << bundle;

    TransactionBundle decoded;
    ss >> decoded;
    BOOST_REQUIRE(decoded.IsValid());
    BOOST_CHECK_EQUAL(decoded.header.family_id, TransactionFamily::V2_GENERIC);
    BOOST_CHECK(BundleHasSemanticFamily(decoded, TransactionFamily::V2_LIFECYCLE));
    BOOST_REQUIRE(std::holds_alternative<LifecyclePayload>(decoded.payload));
    const auto& decoded_payload = std::get<LifecyclePayload>(decoded.payload);
    BOOST_CHECK_EQUAL(decoded_payload.transparent_binding_digest, payload.transparent_binding_digest);
    BOOST_CHECK_EQUAL(decoded_payload.lifecycle_controls.size(), 1U);
    BOOST_CHECK(decoded_payload.lifecycle_controls.front().IsValid());
    BOOST_CHECK(VerifyAddressLifecycleRecord(decoded_payload.lifecycle_controls.front(),
                                             decoded_payload.transparent_binding_digest));
}

BOOST_AUTO_TEST_CASE(ingress_bundle_requires_canonical_shard_coverage)
{
    IngressBatchPayload payload;
    payload.spend_anchor = uint256{0x11};
    payload.account_registry_anchor = uint256{0x12};
    payload.consumed_spends = {MakeConsumedSpend(0x21), MakeConsumedSpend(0x23)};
    payload.ingress_leaves = {MakeBatchLeaf(0, 0x31), MakeBatchLeaf(1, 0x32)};
    payload.reserve_outputs = {MakeOutput(NoteClass::RESERVE, ScanDomain::RESERVE, 0x34)};
    payload.reserve_output_encoding = ReserveOutputEncoding::INGRESS_PLACEHOLDER_DERIVED;
    payload.settlement_binding_digest = uint256{0x37};
    CanonicalizeIngressPayload(payload);

    TransactionBundle bundle;
    bundle.header = MakeBaseHeader(TransactionFamily::V2_INGRESS_BATCH, ProofKind::BATCH_MATRICT, SettlementBindingKind::NATIVE_BATCH);
    bundle.payload = payload;
    bundle.proof_shards = {
        MakeProofShard(0, 1, 0, 4, 0x40, bundle.header.proof_envelope.statement_digest),
        MakeProofShard(1, 1, 4, 4, 0x41, bundle.header.proof_envelope.statement_digest),
    };
    bundle.proof_payload = {0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23};
    bundle.header.payload_digest = ComputeIngressBatchPayloadDigest(payload);
    bundle.header.proof_shard_root = ComputeProofShardRoot(Span<const ProofShardDescriptor>{bundle.proof_shards.data(), bundle.proof_shards.size()});
    bundle.header.proof_shard_count = bundle.proof_shards.size();

    BOOST_REQUIRE(bundle.IsValid());

    DataStream ss{};
    ss << bundle;
    TransactionBundle decoded;
    ss >> decoded;
    BOOST_CHECK(decoded.IsValid());

    TransactionBundle overlapping = bundle;
    std::get<IngressBatchPayload>(overlapping.payload).ingress_root = payload.ingress_root;
    overlapping.proof_shards[1].first_leaf_index = 0;
    overlapping.header.proof_shard_root = ComputeProofShardRoot(Span<const ProofShardDescriptor>{overlapping.proof_shards.data(), overlapping.proof_shards.size()});
    BOOST_CHECK(!overlapping.IsValid());

    TransactionBundle mismatched_statement = bundle;
    mismatched_statement.proof_shards[0].statement_digest = uint256{0xee};
    mismatched_statement.header.proof_shard_root =
        ComputeProofShardRoot(Span<const ProofShardDescriptor>{mismatched_statement.proof_shards.data(),
                                                               mismatched_statement.proof_shards.size()});
    BOOST_CHECK(!mismatched_statement.IsValid());
}

BOOST_AUTO_TEST_CASE(egress_bundle_roundtrip_requires_output_chunk_cover)
{
    EgressBatchPayload payload;
    payload.settlement_anchor = uint256{0x50};
    payload.outputs = {
        MakeOutput(NoteClass::USER, ScanDomain::BATCH, 0x51),
        MakeOutput(NoteClass::USER, ScanDomain::BATCH, 0x61),
        MakeOutput(NoteClass::USER, ScanDomain::BATCH, 0x71),
    };
    payload.output_binding_digest = uint256{0x53};
    CanonicalizeEgressOutputs(payload.outputs, payload.output_binding_digest);
    payload.egress_root = ComputeOutputDescriptionRoot(Span<const OutputDescription>{payload.outputs.data(), payload.outputs.size()});
    payload.allow_transparent_unwrap = false;
    payload.settlement_binding_digest = uint256{0x52};

    TransactionBundle bundle;
    bundle.header = MakeBaseHeader(TransactionFamily::V2_EGRESS_BATCH, ProofKind::IMPORTED_RECEIPT, SettlementBindingKind::BRIDGE_RECEIPT);
    bundle.payload = payload;
    bundle.proof_shards = {
        MakeProofShard(0, 1, 0, 2, 0x79, bundle.header.proof_envelope.statement_digest),
    };
    bundle.output_chunks = {
        MakeOutputChunk(payload.outputs, 0, 2),
        MakeOutputChunk(payload.outputs, 2, 1),
    };
    bundle.proof_payload = {0xaa, 0xbb};
    bundle.header.payload_digest = ComputeEgressBatchPayloadDigest(payload);
    bundle.header.proof_shard_root = ComputeProofShardRoot(Span<const ProofShardDescriptor>{bundle.proof_shards.data(), bundle.proof_shards.size()});
    bundle.header.proof_shard_count = bundle.proof_shards.size();
    bundle.header.output_chunk_root = ComputeOutputChunkRoot(Span<const OutputChunkDescriptor>{bundle.output_chunks.data(), bundle.output_chunks.size()});
    bundle.header.output_chunk_count = bundle.output_chunks.size();

    BOOST_REQUIRE(bundle.IsValid());

    DataStream ss{};
    ss << bundle;
    TransactionBundle decoded;
    ss >> decoded;
    BOOST_CHECK(decoded.IsValid());

    TransactionBundle bad_root = bundle;
    std::get<EgressBatchPayload>(bad_root.payload).egress_root = uint256{0x99};
    BOOST_CHECK(!bad_root.IsValid());

    TransactionBundle bad_envelope = bundle;
    bad_envelope.header.proof_envelope.membership_proof_kind = ProofComponentKind::MATRICT;
    BOOST_CHECK(!bad_envelope.IsValid());
}

BOOST_AUTO_TEST_CASE(postfork_generic_imported_receipt_roundtrip_resolves_egress_payload)
{
    const auto& consensus = Params().GetConsensus();
    const auto fixture = test::shielded::BuildV2EgressReceiptFixture(
        /*output_count=*/2,
        &consensus,
        consensus.nShieldedMatRiCTDisableHeight);
    const auto* bundle = fixture.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_REQUIRE_EQUAL(bundle->header.family_id, TransactionFamily::V2_GENERIC);
    BOOST_REQUIRE(bundle->IsValid());

    DataStream ss{};
    ss << *bundle;

    TransactionBundle decoded;
    ss >> decoded;
    BOOST_REQUIRE(std::holds_alternative<EgressBatchPayload>(decoded.payload));
    BOOST_CHECK(std::get<EgressBatchPayload>(decoded.payload).IsValid());
    BOOST_CHECK(WireFamilyMatchesPayload(decoded.header.family_id, decoded.payload));
    BOOST_CHECK(BundleHasSemanticFamily(decoded, TransactionFamily::V2_EGRESS_BATCH));
    BOOST_CHECK(TransactionBundleOutputChunksAreCanonical(decoded));
    BOOST_REQUIRE_EQUAL(decoded.proof_shards.size(), 1U);
    BOOST_CHECK_EQUAL(decoded.proof_shards.front().first_leaf_index, 0U);
    BOOST_CHECK_EQUAL(decoded.proof_shards.front().leaf_count, 1U);
    BOOST_CHECK_EQUAL(decoded.proof_shards.front().proof_payload_offset, 0U);
    BOOST_CHECK_EQUAL(static_cast<size_t>(decoded.proof_shards.front().proof_payload_size),
                      decoded.proof_payload.size());
    BOOST_CHECK(ProofShardCoverageIsCanonical(Span<const ProofShardDescriptor>{decoded.proof_shards.data(),
                                                                              decoded.proof_shards.size()},
                                             /*leaf_count=*/1,
                                             decoded.proof_payload.size()));
    BOOST_CHECK(ComputePayloadDigest(decoded.payload) == decoded.header.payload_digest);
    BOOST_REQUIRE(decoded.IsValid());
    BOOST_CHECK_EQUAL(decoded.header.family_id, TransactionFamily::V2_GENERIC);
    BOOST_CHECK(BundleHasSemanticFamily(decoded, TransactionFamily::V2_EGRESS_BATCH));
    BOOST_CHECK(std::holds_alternative<EgressBatchPayload>(decoded.payload));
    BOOST_CHECK(decoded.proof_payload == bundle->proof_payload);
    BOOST_REQUIRE_EQUAL(bundle->output_chunks.size(), 1U);
    BOOST_REQUIRE_EQUAL(decoded.output_chunks.size(), 1U);
    BOOST_CHECK_EQUAL(decoded.output_chunks.front().output_count,
                      std::get<EgressBatchPayload>(decoded.payload).outputs.size());
}

BOOST_AUTO_TEST_CASE(postfork_generic_imported_receipt_bucket_pads_wire_shard_and_chunk_counts)
{
    const auto& consensus = Params().GetConsensus();
    const auto fixture = test::shielded::BuildV2EgressReceiptFixture(
        /*output_count=*/2,
        &consensus,
        consensus.nShieldedMatRiCTDisableHeight);
    const auto* bundle = fixture.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_REQUIRE_EQUAL(bundle->proof_shards.size(), 1U);
    BOOST_REQUIRE_EQUAL(bundle->output_chunks.size(), 1U);

    const auto wire = ParseWireBundleMetadata(*bundle);
    BOOST_CHECK_EQUAL(wire.header.proof_shard_count, 2U);
    BOOST_CHECK_EQUAL(wire.proof_shards.size(), 2U);
    BOOST_CHECK_EQUAL(wire.header.output_chunk_count, 2U);
    BOOST_CHECK_EQUAL(wire.output_chunk_count, 2U);

    DataStream ss{};
    ss << *bundle;
    TransactionBundle decoded;
    ss >> decoded;
    BOOST_REQUIRE(decoded.IsValid());
    BOOST_REQUIRE_EQUAL(decoded.proof_shards.size(), 1U);
    BOOST_REQUIRE_EQUAL(decoded.output_chunks.size(), 1U);
    BOOST_CHECK_EQUAL(decoded.header.proof_shard_count, 1U);
    BOOST_CHECK_EQUAL(decoded.header.output_chunk_count, 1U);
}

BOOST_AUTO_TEST_CASE(egress_bundle_rejects_unsupported_imported_claim_surface)
{
    const auto fixture = test::shielded::BuildV2EgressReceiptFixture();
    auto bundle = *Assert(fixture.tx.shielded_bundle.v2_bundle);
    bundle.header.proof_envelope.proof_kind = ProofKind::IMPORTED_CLAIM;
    BOOST_CHECK(!bundle.IsValid());
}

BOOST_AUTO_TEST_CASE(v2_output_families_require_smile_accounts)
{
    SendPayload send_payload;
    send_payload.spend_anchor = uint256{0x11};
    send_payload.account_registry_anchor = uint256{0x12};
    send_payload.spends = {MakeSpend(0x12)};
    send_payload.outputs = {MakeOutput(NoteClass::USER, ScanDomain::USER, 0x13)};
    send_payload.outputs[0].smile_account.reset();
    send_payload.fee = 1;
    send_payload.value_balance = send_payload.fee;
    BOOST_CHECK(!send_payload.outputs[0].IsValid());
    ExpectMissingSmileAccountSerialize([&] { return ComputeSendPayloadDigest(send_payload); });

    IngressBatchPayload ingress_payload;
    ingress_payload.spend_anchor = uint256{0x21};
    ingress_payload.account_registry_anchor = uint256{0x22};
    ingress_payload.consumed_spends = {MakeConsumedSpend(0x22)};
    ingress_payload.ingress_leaves = {MakeBatchLeaf(0, 0x23)};
    ingress_payload.reserve_outputs = {MakeOutput(NoteClass::RESERVE, ScanDomain::RESERVE, 0x25)};
    ingress_payload.reserve_output_encoding = ReserveOutputEncoding::INGRESS_PLACEHOLDER_DERIVED;
    ingress_payload.settlement_binding_digest = uint256{0x28};
    CanonicalizeIngressPayload(ingress_payload);
    ingress_payload.reserve_outputs[0].smile_account.reset();
    BOOST_CHECK(!ingress_payload.reserve_outputs[0].IsValid());
    ExpectMissingSmileAccountSerialize([&] { return ComputeIngressBatchPayloadDigest(ingress_payload); });

    EgressBatchPayload egress_payload;
    egress_payload.settlement_anchor = uint256{0x31};
    egress_payload.outputs = {MakeOutput(NoteClass::USER, ScanDomain::BATCH, 0x32)};
    egress_payload.output_binding_digest = uint256{0x34};
    CanonicalizeEgressOutputs(egress_payload.outputs, egress_payload.output_binding_digest);
    egress_payload.egress_root = ComputeOutputDescriptionRoot(
        Span<const OutputDescription>{egress_payload.outputs.data(), egress_payload.outputs.size()});
    egress_payload.outputs[0].smile_account.reset();
    egress_payload.settlement_binding_digest = uint256{0x33};
    BOOST_CHECK(!egress_payload.outputs[0].IsValid());
    ExpectMissingSmileAccountSerialize(
        [&] { return ComputeOutputDescriptionRoot({egress_payload.outputs.data(), egress_payload.outputs.size()}); });
    ExpectMissingSmileAccountSerialize([&] { return ComputeEgressBatchPayloadDigest(egress_payload); });

    RebalancePayload rebalance_payload;
    rebalance_payload.reserve_deltas = {
        MakeReserveDelta(0x41, 2 * COIN),
        MakeReserveDelta(0x42, -2 * COIN),
    };
    rebalance_payload.reserve_outputs = {MakeOutput(NoteClass::RESERVE, ScanDomain::RESERVE, 0x43)};
    rebalance_payload.has_netting_manifest = true;
    rebalance_payload.netting_manifest = MakeNettingManifest(rebalance_payload.reserve_deltas);
    CanonicalizeRebalancePayload(rebalance_payload);
    rebalance_payload.reserve_outputs[0].smile_account.reset();
    BOOST_CHECK(!rebalance_payload.reserve_outputs[0].IsValid());
    ExpectMissingSmileAccountSerialize([&] { return ComputeRebalancePayloadDigest(rebalance_payload); });
}

BOOST_AUTO_TEST_CASE(output_chunk_builder_requires_uniform_scan_domain)
{
    std::vector<OutputDescription> outputs{
        MakeOutput(NoteClass::USER, ScanDomain::BATCH, 0xa0),
        MakeOutput(NoteClass::USER, ScanDomain::USER, 0xa1),
    };
    outputs[1].encrypted_note.scan_domain = ScanDomain::USER;

    BOOST_CHECK(!BuildOutputChunkDescriptor({outputs.data(), outputs.size()}, 0).has_value());
}

BOOST_AUTO_TEST_CASE(egress_bundle_rejects_chunk_commitment_mismatch)
{
    EgressBatchPayload payload;
    payload.settlement_anchor = uint256{0xb0};
    payload.outputs = {
        MakeOutput(NoteClass::USER, ScanDomain::BATCH, 0xb1),
        MakeOutput(NoteClass::USER, ScanDomain::BATCH, 0xb2),
        MakeOutput(NoteClass::USER, ScanDomain::BATCH, 0xb3),
    };
    payload.output_binding_digest = uint256{0xb6};
    CanonicalizeEgressOutputs(payload.outputs, payload.output_binding_digest);
    payload.egress_root = ComputeOutputDescriptionRoot({payload.outputs.data(), payload.outputs.size()});
    payload.allow_transparent_unwrap = false;
    payload.settlement_binding_digest = uint256{0xb4};

    TransactionBundle bundle;
    bundle.header = MakeBaseHeader(TransactionFamily::V2_EGRESS_BATCH, ProofKind::IMPORTED_RECEIPT, SettlementBindingKind::BRIDGE_RECEIPT);
    bundle.payload = payload;
    bundle.proof_shards = {
        MakeProofShard(0, 1, 0, 2, 0xb5, bundle.header.proof_envelope.statement_digest),
    };
    bundle.output_chunks = {
        MakeOutputChunk(payload.outputs, 0, 2),
        MakeOutputChunk(payload.outputs, 2, 1),
    };
    bundle.proof_payload = {0xc0, 0xc1};
    bundle.header.payload_digest = ComputeEgressBatchPayloadDigest(payload);
    bundle.header.proof_shard_root = ComputeProofShardRoot({bundle.proof_shards.data(), bundle.proof_shards.size()});
    bundle.header.proof_shard_count = bundle.proof_shards.size();
    bundle.header.output_chunk_root = ComputeOutputChunkRoot({bundle.output_chunks.data(), bundle.output_chunks.size()});
    bundle.header.output_chunk_count = bundle.output_chunks.size();

    BOOST_REQUIRE(bundle.IsValid());

    TransactionBundle bad_hint_commitment = bundle;
    bad_hint_commitment.output_chunks[0].scan_hint_commitment = uint256{0xc2};
    bad_hint_commitment.header.output_chunk_root =
        ComputeOutputChunkRoot({bad_hint_commitment.output_chunks.data(), bad_hint_commitment.output_chunks.size()});
    BOOST_CHECK(!bad_hint_commitment.IsValid());

    TransactionBundle bad_bytes = bundle;
    ++bad_bytes.output_chunks[1].ciphertext_bytes;
    bad_bytes.header.output_chunk_root =
        ComputeOutputChunkRoot({bad_bytes.output_chunks.data(), bad_bytes.output_chunks.size()});
    BOOST_CHECK(!bad_bytes.IsValid());

    TransactionBundle bad_domain = bundle;
    auto& bad_domain_payload = std::get<EgressBatchPayload>(bad_domain.payload);
    bad_domain_payload.outputs[1].encrypted_note.scan_domain = ScanDomain::USER;
    BOOST_CHECK(!bad_domain_payload.IsValid());
    BOOST_CHECK(!bad_domain.IsValid());
}

BOOST_AUTO_TEST_CASE(transaction_bundle_output_chunks_are_canonical_only_when_header_and_payload_match)
{
    EgressBatchPayload payload;
    payload.settlement_anchor = uint256{0xc8};
    payload.outputs = {
        MakeOutput(NoteClass::USER, ScanDomain::BATCH, 0xc9),
        MakeOutput(NoteClass::USER, ScanDomain::BATCH, 0xca),
        MakeOutput(NoteClass::USER, ScanDomain::BATCH, 0xcb),
    };
    payload.output_binding_digest = uint256{0xcd};
    CanonicalizeEgressOutputs(payload.outputs, payload.output_binding_digest);
    payload.egress_root = ComputeOutputDescriptionRoot({payload.outputs.data(), payload.outputs.size()});
    payload.settlement_binding_digest = uint256{0xcc};

    TransactionBundle bundle;
    bundle.header = MakeBaseHeader(TransactionFamily::V2_EGRESS_BATCH, ProofKind::IMPORTED_RECEIPT, SettlementBindingKind::BRIDGE_RECEIPT);
    bundle.payload = payload;
    bundle.proof_shards = {
        MakeProofShard(0, 1, 0, 2, 0xcd, bundle.header.proof_envelope.statement_digest),
    };
    bundle.output_chunks = {
        MakeOutputChunk(payload.outputs, 0, 2),
        MakeOutputChunk(payload.outputs, 2, 1),
    };
    bundle.proof_payload = {0xce, 0xcf};
    bundle.header.payload_digest = ComputeEgressBatchPayloadDigest(payload);
    bundle.header.proof_shard_root = ComputeProofShardRoot({bundle.proof_shards.data(), bundle.proof_shards.size()});
    bundle.header.proof_shard_count = bundle.proof_shards.size();
    bundle.header.output_chunk_root = ComputeOutputChunkRoot({bundle.output_chunks.data(), bundle.output_chunks.size()});
    bundle.header.output_chunk_count = bundle.output_chunks.size();

    BOOST_REQUIRE(bundle.IsValid());
    BOOST_CHECK(TransactionBundleOutputChunksAreCanonical(bundle));

    TransactionBundle bad_root = bundle;
    bad_root.output_chunks[0].scan_hint_commitment = uint256{0xd0};
    BOOST_CHECK(!TransactionBundleOutputChunksAreCanonical(bad_root));

    TransactionBundle bad_count = bundle;
    --bad_count.header.output_chunk_count;
    BOOST_CHECK(!TransactionBundleOutputChunksAreCanonical(bad_count));

    RebalancePayload rebalance_payload;
    rebalance_payload.reserve_deltas = {
        MakeReserveDelta(0xd1, 2 * COIN),
        MakeReserveDelta(0xd2, -2 * COIN),
    };
    rebalance_payload.reserve_outputs = {MakeOutput(NoteClass::RESERVE, ScanDomain::RESERVE, 0xd3)};
    rebalance_payload.has_netting_manifest = true;
    rebalance_payload.netting_manifest = MakeNettingManifest(rebalance_payload.reserve_deltas);
    CanonicalizeRebalancePayload(rebalance_payload);

    TransactionBundle rebalance_bundle;
    rebalance_bundle.header = MakeBaseHeader(TransactionFamily::V2_REBALANCE, ProofKind::BATCH_MATRICT, SettlementBindingKind::NETTING_MANIFEST);
    rebalance_bundle.header.proof_envelope.statement_digest = rebalance_payload.batch_statement_digest;
    rebalance_bundle.payload = rebalance_payload;
    rebalance_bundle.proof_shards = {
        MakeProofShard(0, 2, 0, 2, 0xd6, rebalance_payload.batch_statement_digest),
    };
    rebalance_bundle.proof_payload = {0xd7, 0xd8};
    rebalance_bundle.header.payload_digest = ComputeRebalancePayloadDigest(rebalance_payload);
    rebalance_bundle.header.proof_shard_root = ComputeProofShardRoot({rebalance_bundle.proof_shards.data(), rebalance_bundle.proof_shards.size()});
    rebalance_bundle.header.proof_shard_count = rebalance_bundle.proof_shards.size();
    rebalance_bundle.header.netting_manifest_version = rebalance_payload.netting_manifest.version;

    BOOST_REQUIRE(rebalance_bundle.IsValid());
    BOOST_CHECK(TransactionBundleOutputChunksAreCanonical(rebalance_bundle));

    rebalance_bundle.output_chunks = {MakeOutputChunk(rebalance_payload.reserve_outputs, 0, 1)};
    rebalance_bundle.header.output_chunk_root = ComputeOutputChunkRoot({rebalance_bundle.output_chunks.data(), rebalance_bundle.output_chunks.size()});
    rebalance_bundle.header.output_chunk_count = rebalance_bundle.output_chunks.size();
    BOOST_REQUIRE(rebalance_bundle.IsValid());
    BOOST_CHECK(TransactionBundleOutputChunksAreCanonical(rebalance_bundle));
}

BOOST_AUTO_TEST_CASE(rebalance_bundle_requires_manifest_header_consistency)
{
    RebalancePayload payload;
    payload.reserve_deltas = {
        MakeReserveDelta(0x90, 5 * COIN),
        MakeReserveDelta(0x91, -2 * COIN),
        MakeReserveDelta(0x92, -3 * COIN),
    };
    payload.reserve_outputs = {MakeOutput(NoteClass::RESERVE, ScanDomain::RESERVE, 0x93)};
    payload.has_netting_manifest = true;
    payload.netting_manifest = MakeNettingManifest(payload.reserve_deltas);
    CanonicalizeRebalancePayload(payload);

    TransactionBundle bundle;
    bundle.header = MakeBaseHeader(TransactionFamily::V2_REBALANCE, ProofKind::BATCH_MATRICT, SettlementBindingKind::NETTING_MANIFEST);
    bundle.header.proof_envelope.statement_digest = payload.batch_statement_digest;
    bundle.payload = payload;
    bundle.proof_shards = {
        MakeProofShard(0, 2, 0, 2, 0xa0, payload.batch_statement_digest),
        MakeProofShard(2, 1, 2, 2, 0xa1, payload.batch_statement_digest),
    };
    bundle.proof_payload = {0xde, 0xad, 0xbe, 0xef};
    bundle.header.payload_digest = ComputeRebalancePayloadDigest(payload);
    bundle.header.proof_shard_root = ComputeProofShardRoot(Span<const ProofShardDescriptor>{bundle.proof_shards.data(), bundle.proof_shards.size()});
    bundle.header.proof_shard_count = bundle.proof_shards.size();
    bundle.header.netting_manifest_version = payload.netting_manifest.version;

    BOOST_REQUIRE(bundle.IsValid());

    TransactionBundle mismatched_header = bundle;
    mismatched_header.header.netting_manifest_version = 0;
    BOOST_CHECK(!mismatched_header.IsValid());

    TransactionBundle mismatched_statement = bundle;
    std::get<RebalancePayload>(mismatched_statement.payload).batch_statement_digest = uint256{0x96};
    BOOST_CHECK(!mismatched_statement.IsValid());
}

BOOST_AUTO_TEST_CASE(settlement_anchor_bundle_roundtrip)
{
    SettlementAnchorPayload payload;
    payload.imported_claim_ids = {uint256{0xa0}, uint256{0xa1}};
    payload.imported_adapter_ids = {uint256{0xb0}};
    payload.proof_receipt_ids = {uint256{0xc0}, uint256{0xc1}};
    payload.batch_statement_digests = {uint256{0xd0}};
    payload.reserve_deltas = {
        MakeReserveDelta(0xd1, 4 * COIN),
        MakeReserveDelta(0xd2, -4 * COIN),
    };
    payload.anchored_netting_manifest_id = uint256{0xd3};

    TransactionBundle bundle;
    bundle.header = MakeBaseHeader(TransactionFamily::V2_SETTLEMENT_ANCHOR, ProofKind::IMPORTED_CLAIM, SettlementBindingKind::BRIDGE_CLAIM);
    payload.batch_statement_digests = {bundle.header.proof_envelope.statement_digest};
    bundle.payload = payload;
    bundle.proof_shards = {
        MakeProofShard(0, 1, 0, 3, 0xd4, bundle.header.proof_envelope.statement_digest),
    };
    bundle.proof_payload = {0xfa, 0xfb, 0xfc};
    bundle.header.payload_digest = ComputeSettlementAnchorPayloadDigest(payload);
    bundle.header.proof_shard_root = ComputeProofShardRoot(Span<const ProofShardDescriptor>{bundle.proof_shards.data(), bundle.proof_shards.size()});
    bundle.header.proof_shard_count = bundle.proof_shards.size();

    BOOST_REQUIRE(bundle.IsValid());

    DataStream ss{};
    ss << bundle;
    TransactionBundle decoded;
    ss >> decoded;
    BOOST_CHECK(decoded.IsValid());
    BOOST_CHECK(ComputeTransactionBundleId(decoded) == ComputeTransactionBundleId(bundle));

    TransactionBundle missing_digest = bundle;
    std::get<SettlementAnchorPayload>(missing_digest.payload).batch_statement_digests = {uint256{0xd0}};
    missing_digest.header.payload_digest =
        ComputeSettlementAnchorPayloadDigest(std::get<SettlementAnchorPayload>(missing_digest.payload));
    BOOST_CHECK(!missing_digest.IsValid());
}

BOOST_AUTO_TEST_CASE(postfork_generic_imported_receipt_roundtrip_resolves_settlement_anchor_payload)
{
    const auto& consensus = Params().GetConsensus();
    const auto fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture(
        /*output_count=*/2,
        /*proof_receipt_count=*/1,
        /*required_receipts=*/1,
        &consensus,
        consensus.nShieldedMatRiCTDisableHeight);
    const auto* bundle = fixture.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_REQUIRE_EQUAL(bundle->header.family_id, TransactionFamily::V2_GENERIC);
    BOOST_REQUIRE(bundle->IsValid());

    DataStream ss{};
    ss << *bundle;

    TransactionBundle decoded;
    ss >> decoded;
    BOOST_REQUIRE(decoded.IsValid());
    BOOST_CHECK_EQUAL(decoded.header.family_id, TransactionFamily::V2_GENERIC);
    BOOST_CHECK(BundleHasSemanticFamily(decoded, TransactionFamily::V2_SETTLEMENT_ANCHOR));
    BOOST_CHECK(std::holds_alternative<SettlementAnchorPayload>(decoded.payload));
    BOOST_CHECK(decoded.proof_payload == bundle->proof_payload);
}

BOOST_AUTO_TEST_CASE(settlement_anchor_bundle_requires_canonical_reserve_deltas)
{
    SettlementAnchorPayload payload;
    payload.imported_claim_ids = {uint256{0xa0}};
    payload.batch_statement_digests = {uint256{0xa1}};
    payload.reserve_deltas = {
        MakeReserveDelta(0xd1, 4 * COIN),
        MakeReserveDelta(0xd0, -4 * COIN),
    };
    payload.anchored_netting_manifest_id = uint256{0xd3};

    TransactionBundle bundle;
    bundle.header = MakeBaseHeader(TransactionFamily::V2_SETTLEMENT_ANCHOR, ProofKind::IMPORTED_CLAIM, SettlementBindingKind::BRIDGE_CLAIM);
    payload.batch_statement_digests = {bundle.header.proof_envelope.statement_digest};
    bundle.payload = payload;
    bundle.proof_shards = {
        MakeProofShard(0, 1, 0, 3, 0xd4, bundle.header.proof_envelope.statement_digest),
    };
    bundle.proof_payload = {0xfa, 0xfb, 0xfc};
    bundle.header.payload_digest = ComputeSettlementAnchorPayloadDigest(payload);
    bundle.header.proof_shard_root = ComputeProofShardRoot(Span<const ProofShardDescriptor>{bundle.proof_shards.data(), bundle.proof_shards.size()});
    bundle.header.proof_shard_count = bundle.proof_shards.size();

    BOOST_CHECK(!bundle.IsValid());

    auto& settlement_payload = std::get<SettlementAnchorPayload>(bundle.payload);
    settlement_payload.reserve_deltas = {
        MakeReserveDelta(0xd0, 4 * COIN),
        MakeReserveDelta(0xd1, 4 * COIN),
    };
    bundle.header.payload_digest = ComputeSettlementAnchorPayloadDigest(settlement_payload);
    BOOST_CHECK(!bundle.IsValid());
}

BOOST_AUTO_TEST_CASE(settlement_anchor_bundle_rejects_anchored_manifest_without_reserve_deltas)
{
    SettlementAnchorPayload payload;
    payload.imported_claim_ids = {uint256{0xa0}};
    payload.batch_statement_digests = {uint256{0xa1}};
    payload.anchored_netting_manifest_id = uint256{0xd3};

    TransactionBundle bundle;
    bundle.header = MakeBaseHeader(TransactionFamily::V2_SETTLEMENT_ANCHOR, ProofKind::IMPORTED_CLAIM, SettlementBindingKind::BRIDGE_CLAIM);
    payload.batch_statement_digests = {bundle.header.proof_envelope.statement_digest};
    bundle.payload = payload;
    bundle.proof_shards = {
        MakeProofShard(0, 1, 0, 3, 0xd4, bundle.header.proof_envelope.statement_digest),
    };
    bundle.proof_payload = {0xfa, 0xfb, 0xfc};
    bundle.header.payload_digest = ComputeSettlementAnchorPayloadDigest(payload);
    bundle.header.proof_shard_root = ComputeProofShardRoot(Span<const ProofShardDescriptor>{bundle.proof_shards.data(), bundle.proof_shards.size()});
    bundle.header.proof_shard_count = bundle.proof_shards.size();

    BOOST_CHECK(!bundle.IsValid());
}

BOOST_AUTO_TEST_CASE(bundle_state_accessors_cover_v2_families)
{
    CShieldedBundle send_bundle;
    {
        SendPayload payload;
        payload.spend_anchor = uint256{0xe0};
        payload.account_registry_anchor = uint256{0xe1};
        payload.spends = {MakeSpend(0xe1)};
        payload.outputs = {MakeOutput(NoteClass::USER, ScanDomain::USER, 0xe4)};
        payload.fee = 7;
        payload.value_balance = payload.fee;
        send_bundle.v2_bundle.emplace();
        send_bundle.v2_bundle->header =
            MakeBaseHeader(TransactionFamily::V2_SEND, ProofKind::DIRECT_MATRICT, SettlementBindingKind::NONE);
        send_bundle.v2_bundle->payload = payload;
    }
    const auto send_nullifiers = CollectShieldedNullifiers(send_bundle);
    const auto send_commitments = CollectShieldedOutputCommitments(send_bundle);
    const auto send_anchors = CollectShieldedAnchors(send_bundle);
    BOOST_REQUIRE_EQUAL(send_nullifiers.size(), 1U);
    BOOST_REQUIRE_EQUAL(send_commitments.size(), 1U);
    BOOST_REQUIRE_EQUAL(send_anchors.size(), 2U);
    BOOST_CHECK(send_nullifiers[0] == std::get<SendPayload>(send_bundle.v2_bundle->payload).spends[0].nullifier);
    BOOST_CHECK(send_commitments[0] == std::get<SendPayload>(send_bundle.v2_bundle->payload).outputs[0].note_commitment);
    BOOST_CHECK(send_anchors[0] == std::get<SendPayload>(send_bundle.v2_bundle->payload).spend_anchor);
    BOOST_CHECK(send_anchors[1] == std::get<SendPayload>(send_bundle.v2_bundle->payload).spends[0].merkle_anchor);
    BOOST_CHECK(CollectShieldedSettlementAnchorRefs(send_bundle).empty());
    BOOST_CHECK_EQUAL(GetShieldedStateValueBalance(send_bundle), 7);
    BOOST_CHECK_EQUAL(GetShieldedVerifyCost(send_bundle), 115U);
    const auto send_usage = GetShieldedResourceUsage(send_bundle);
    BOOST_CHECK_EQUAL(send_usage.verify_units, 115U);
    BOOST_CHECK_EQUAL(send_usage.scan_units, 1U);
    BOOST_CHECK_EQUAL(send_usage.tree_update_units, 2U);

    CShieldedBundle deposit_bundle;
    {
        SendPayload payload;
        payload.outputs = {MakeOutput(NoteClass::USER, ScanDomain::USER, 0xe8)};
        payload.fee = 5;
        payload.value_balance = -25;
        deposit_bundle.v2_bundle.emplace();
        deposit_bundle.v2_bundle->header =
            MakeBaseHeader(TransactionFamily::V2_SEND, ProofKind::NONE, SettlementBindingKind::NONE);
        deposit_bundle.v2_bundle->payload = payload;
    }
    BOOST_CHECK(CollectShieldedNullifiers(deposit_bundle).empty());
    const auto deposit_commitments = CollectShieldedOutputCommitments(deposit_bundle);
    BOOST_REQUIRE_EQUAL(deposit_commitments.size(), 1U);
    BOOST_CHECK(deposit_commitments[0] == std::get<SendPayload>(deposit_bundle.v2_bundle->payload).outputs[0].note_commitment);
    BOOST_CHECK(CollectShieldedAnchors(deposit_bundle).empty());
    BOOST_CHECK(CollectShieldedSettlementAnchorRefs(deposit_bundle).empty());
    BOOST_CHECK_EQUAL(GetShieldedStateValueBalance(deposit_bundle), -25);
    BOOST_CHECK_EQUAL(GetShieldedVerifyCost(deposit_bundle), 15U);
    const auto deposit_usage = GetShieldedResourceUsage(deposit_bundle);
    BOOST_CHECK_EQUAL(deposit_usage.verify_units, 15U);
    BOOST_CHECK_EQUAL(deposit_usage.scan_units, 1U);
    BOOST_CHECK_EQUAL(deposit_usage.tree_update_units, 1U);

    CShieldedBundle ingress_bundle;
    {
        IngressBatchPayload payload;
        payload.spend_anchor = uint256{0xf0};
        payload.account_registry_anchor = uint256{0xf1};
        payload.consumed_spends = {MakeConsumedSpend(0xf1), MakeConsumedSpend(0xf3)};
        payload.reserve_outputs = {
            MakeOutput(NoteClass::RESERVE, ScanDomain::RESERVE, 0xf3),
            MakeOutput(NoteClass::RESERVE, ScanDomain::RESERVE, 0xf4),
        };
        payload.reserve_output_encoding = ReserveOutputEncoding::INGRESS_PLACEHOLDER_DERIVED;
        payload.settlement_binding_digest = uint256{0x01};
        CanonicalizeIngressReserveOutputs(payload.reserve_outputs, payload.settlement_binding_digest);
        ingress_bundle.v2_bundle.emplace();
        ingress_bundle.v2_bundle->header = MakeBaseHeader(
            TransactionFamily::V2_INGRESS_BATCH, ProofKind::BATCH_MATRICT, SettlementBindingKind::NATIVE_BATCH);
        ingress_bundle.v2_bundle->payload = payload;
    }
    const auto ingress_nullifiers = CollectShieldedNullifiers(ingress_bundle);
    const auto ingress_commitments = CollectShieldedOutputCommitments(ingress_bundle);
    const auto ingress_anchors = CollectShieldedAnchors(ingress_bundle);
    BOOST_REQUIRE_EQUAL(ingress_nullifiers.size(), 2U);
    BOOST_REQUIRE_EQUAL(ingress_commitments.size(), 2U);
    BOOST_REQUIRE_EQUAL(ingress_anchors.size(), 1U);
    BOOST_CHECK(ingress_nullifiers[0] == uint256{0xf1});
    BOOST_CHECK(ingress_nullifiers[1] == uint256{0xf3});
    BOOST_CHECK(ingress_commitments[0] == std::get<IngressBatchPayload>(ingress_bundle.v2_bundle->payload).reserve_outputs[0].note_commitment);
    BOOST_CHECK(ingress_commitments[1] == std::get<IngressBatchPayload>(ingress_bundle.v2_bundle->payload).reserve_outputs[1].note_commitment);
    BOOST_CHECK(ingress_anchors[0] == uint256{0xf0});
    BOOST_CHECK(CollectShieldedSettlementAnchorRefs(ingress_bundle).empty());
    BOOST_CHECK_EQUAL(GetShieldedVerifyCost(ingress_bundle), 100U);
    const auto ingress_usage = GetShieldedResourceUsage(ingress_bundle);
    BOOST_CHECK_EQUAL(ingress_usage.verify_units, 100U);
    BOOST_CHECK_EQUAL(ingress_usage.scan_units, 0U);
    BOOST_CHECK_EQUAL(ingress_usage.tree_update_units, 4U);

    CShieldedBundle rebalance_bundle;
    {
        RebalancePayload payload;
        payload.reserve_deltas = {
            MakeReserveDelta(0x90, 5 * COIN),
            MakeReserveDelta(0x91, -5 * COIN),
        };
        payload.reserve_outputs = {MakeOutput(NoteClass::RESERVE, ScanDomain::RESERVE, 0x92)};
        CanonicalizeRebalanceOutputs(payload.reserve_outputs);
        rebalance_bundle.v2_bundle.emplace();
        rebalance_bundle.v2_bundle->header = MakeBaseHeader(
            TransactionFamily::V2_REBALANCE, ProofKind::BATCH_MATRICT, SettlementBindingKind::NETTING_MANIFEST);
        rebalance_bundle.v2_bundle->payload = payload;
    }
    BOOST_CHECK(CollectShieldedNullifiers(rebalance_bundle).empty());
    const auto rebalance_commitments = CollectShieldedOutputCommitments(rebalance_bundle);
    BOOST_REQUIRE_EQUAL(rebalance_commitments.size(), 1U);
    BOOST_CHECK(rebalance_commitments[0] == std::get<RebalancePayload>(rebalance_bundle.v2_bundle->payload).reserve_outputs[0].note_commitment);
    BOOST_CHECK(CollectShieldedAnchors(rebalance_bundle).empty());
    BOOST_CHECK(CollectShieldedSettlementAnchorRefs(rebalance_bundle).empty());
    BOOST_CHECK_EQUAL(GetShieldedVerifyCost(rebalance_bundle), 100U);
    const auto rebalance_usage = GetShieldedResourceUsage(rebalance_bundle);
    BOOST_CHECK_EQUAL(rebalance_usage.verify_units, 100U);
    BOOST_CHECK_EQUAL(rebalance_usage.scan_units, 0U);
    BOOST_CHECK_EQUAL(rebalance_usage.tree_update_units, 1U);

    CShieldedBundle egress_bundle;
    {
        EgressBatchPayload payload;
        payload.settlement_anchor = uint256{0xa5};
        payload.outputs = {MakeOutput(NoteClass::USER, ScanDomain::BATCH, 0xa6)};
        payload.output_binding_digest = uint256{0xa8};
        CanonicalizeEgressOutputs(payload.outputs, payload.output_binding_digest);
        payload.egress_root = ComputeOutputDescriptionRoot(Span<const OutputDescription>{payload.outputs.data(), payload.outputs.size()});
        payload.settlement_binding_digest = uint256{0xa7};
        egress_bundle.v2_bundle.emplace();
        egress_bundle.v2_bundle->header = MakeBaseHeader(
            TransactionFamily::V2_EGRESS_BATCH, ProofKind::IMPORTED_RECEIPT, SettlementBindingKind::BRIDGE_RECEIPT);
        egress_bundle.v2_bundle->payload = payload;
        egress_bundle.v2_bundle->output_chunks = {MakeOutputChunk(payload.outputs, 0, 1)};
    }
    const auto settlement_anchor_refs = CollectShieldedSettlementAnchorRefs(egress_bundle);
    BOOST_REQUIRE_EQUAL(settlement_anchor_refs.size(), 1U);
    BOOST_CHECK(settlement_anchor_refs[0] == uint256{0xa5});
    BOOST_CHECK_EQUAL(GetShieldedVerifyCost(egress_bundle), 100U);
    const auto egress_usage = GetShieldedResourceUsage(egress_bundle);
    BOOST_CHECK_EQUAL(egress_usage.verify_units, 100U);
    BOOST_CHECK_EQUAL(egress_usage.scan_units, 2U);
    BOOST_CHECK_EQUAL(egress_usage.tree_update_units, 1U);

    CShieldedBundle settlement_anchor_bundle;
    settlement_anchor_bundle.v2_bundle.emplace();
    settlement_anchor_bundle.v2_bundle->header = MakeBaseHeader(
        TransactionFamily::V2_SETTLEMENT_ANCHOR, ProofKind::IMPORTED_CLAIM, SettlementBindingKind::BRIDGE_CLAIM);
    settlement_anchor_bundle.v2_bundle->payload = SettlementAnchorPayload{};
    BOOST_CHECK(CollectShieldedNullifiers(settlement_anchor_bundle).empty());
    BOOST_CHECK(CollectShieldedOutputCommitments(settlement_anchor_bundle).empty());
    BOOST_CHECK(CollectShieldedAnchors(settlement_anchor_bundle).empty());
    BOOST_CHECK(CollectShieldedSettlementAnchorRefs(settlement_anchor_bundle).empty());
    BOOST_CHECK_EQUAL(GetShieldedVerifyCost(settlement_anchor_bundle), 100U);
    const auto settlement_usage = GetShieldedResourceUsage(settlement_anchor_bundle);
    BOOST_CHECK_EQUAL(settlement_usage.verify_units, 100U);
    BOOST_CHECK_EQUAL(settlement_usage.scan_units, 0U);
    BOOST_CHECK_EQUAL(settlement_usage.tree_update_units, 0U);
}

BOOST_AUTO_TEST_CASE(value_balance_helpers_distinguish_pool_and_tx_accounting)
{
    std::string reject_reason;

    const auto egress_fixture = test::shielded::BuildV2EgressReceiptFixture(/*output_count=*/3);
    const auto egress_state_value =
        TryGetShieldedStateValueBalance(egress_fixture.tx.shielded_bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(egress_state_value.has_value(), reject_reason);
    BOOST_CHECK_EQUAL(*egress_state_value, -egress_fixture.statement.total_amount);
    BOOST_CHECK_EQUAL(GetShieldedTxValueBalance(egress_fixture.tx.shielded_bundle), 0);

    const auto rebalance_fixture = test::shielded::BuildV2RebalanceFixture();
    reject_reason.clear();
    const auto rebalance_state_value =
        TryGetShieldedStateValueBalance(rebalance_fixture.tx.shielded_bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(rebalance_state_value.has_value(), reject_reason);
    BOOST_CHECK_EQUAL(*rebalance_state_value, -(7 * COIN));
    BOOST_CHECK_EQUAL(GetShieldedTxValueBalance(rebalance_fixture.tx.shielded_bundle), 0);

    const auto settlement_fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture();
    reject_reason.clear();
    const auto settlement_state_value =
        TryGetShieldedStateValueBalance(settlement_fixture.tx.shielded_bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(settlement_state_value.has_value(), reject_reason);
    BOOST_CHECK_EQUAL(*settlement_state_value, 0);
    BOOST_CHECK_EQUAL(GetShieldedTxValueBalance(settlement_fixture.tx.shielded_bundle), 0);
}

BOOST_AUTO_TEST_CASE(batch_settlement_verify_cost_scales_with_proof_shards)
{
    const auto single_shard_fixture = test::shielded::BuildV2EgressReceiptFixture(/*output_count=*/2);
    V2RebalanceBuildInput input;
    input.reserve_deltas = {
        MakeReserveDelta(0xe0, 7 * COIN),
        MakeReserveDelta(0xe1, -4 * COIN),
        MakeReserveDelta(0xe2, -3 * COIN),
    };
    input.reserve_outputs = {
        MakeOutput(NoteClass::RESERVE, ScanDomain::RESERVE, 0xe3),
        MakeOutput(NoteClass::RESERVE, ScanDomain::RESERVE, 0xe4),
    };
    input.netting_manifest = MakeNettingManifest(input.reserve_deltas);

    std::string reject_reason;
    const auto multi_shard_bundle = BuildDeterministicV2RebalanceBundle(input, reject_reason);
    BOOST_REQUIRE_MESSAGE(multi_shard_bundle.has_value(), reject_reason);
    CShieldedBundle rebalance_bundle;
    rebalance_bundle.v2_bundle = multi_shard_bundle->bundle;

    BOOST_REQUIRE_EQUAL(single_shard_fixture.tx.shielded_bundle.v2_bundle->proof_shards.size(), 1U);
    BOOST_REQUIRE_EQUAL(multi_shard_bundle->bundle.proof_shards.size(), 3U);
    BOOST_CHECK_EQUAL(GetShieldedVerifyCost(single_shard_fixture.tx.shielded_bundle), 100U);
    BOOST_CHECK_EQUAL(GetShieldedVerifyCost(rebalance_bundle), 300U);
}

BOOST_AUTO_TEST_CASE(bundle_serialize_rejects_family_payload_mismatch)
{
    TransactionBundle bundle;
    bundle.header = MakeBaseHeader(TransactionFamily::V2_SEND, ProofKind::DIRECT_MATRICT, SettlementBindingKind::NONE);

    IngressBatchPayload wrong_payload;
    wrong_payload.spend_anchor = uint256{0xf1};
    wrong_payload.account_registry_anchor = uint256{0xf2};
    wrong_payload.consumed_spends = {MakeConsumedSpend(0xf2)};
    wrong_payload.ingress_leaves = {MakeBatchLeaf(0, 0xf3)};
    wrong_payload.reserve_outputs = {MakeOutput(NoteClass::RESERVE, ScanDomain::RESERVE, 0xf5)};
    wrong_payload.reserve_output_encoding = ReserveOutputEncoding::INGRESS_PLACEHOLDER_DERIVED;
    wrong_payload.settlement_binding_digest = uint256{0xf8};
    CanonicalizeIngressPayload(wrong_payload);
    bundle.payload = wrong_payload;
    bundle.header.payload_digest = ComputeIngressBatchPayloadDigest(wrong_payload);

    DataStream ss{};
    BOOST_CHECK_EXCEPTION(ss << bundle,
                          std::ios_base::failure,
                          HasReason("TransactionBundle::Serialize family/payload mismatch"));
}

BOOST_AUTO_TEST_CASE(deterministic_rebalance_builder_produces_valid_canonical_bundle)
{
    std::vector<ReserveDelta> reserve_deltas{
        MakeReserveDelta(0xe0, 7 * COIN),
        MakeReserveDelta(0xe1, -4 * COIN),
        MakeReserveDelta(0xe2, -3 * COIN),
    };
    std::vector<OutputDescription> reserve_outputs{
        MakeOutput(NoteClass::RESERVE, ScanDomain::RESERVE, 0xe3),
        MakeOutput(NoteClass::RESERVE, ScanDomain::RESERVE, 0xe4),
    };

    V2RebalanceBuildInput input;
    input.reserve_deltas = reserve_deltas;
    input.reserve_outputs = reserve_outputs;
    input.netting_manifest = MakeNettingManifest(reserve_deltas);

    std::string reject_reason;
    auto built = BuildDeterministicV2RebalanceBundle(input, reject_reason);
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);
    BOOST_REQUIRE(built->bundle.IsValid());
    BOOST_REQUIRE(BundleHasSemanticFamily(built->bundle, TransactionFamily::V2_REBALANCE));
    BOOST_CHECK_EQUAL(built->bundle.header.proof_envelope.proof_kind, ProofKind::BATCH_SMILE);
    BOOST_CHECK_EQUAL(built->bundle.header.proof_envelope.membership_proof_kind,
                      ProofComponentKind::SMILE_MEMBERSHIP);
    BOOST_CHECK_EQUAL(built->bundle.header.proof_envelope.amount_proof_kind,
                      ProofComponentKind::SMILE_BALANCE);
    BOOST_CHECK_EQUAL(built->bundle.header.proof_envelope.balance_proof_kind,
                      ProofComponentKind::SMILE_BALANCE);
    BOOST_REQUIRE_EQUAL(built->bundle.proof_shards.size(), reserve_deltas.size());
    BOOST_REQUIRE_EQUAL(built->bundle.output_chunks.size(), 1U);

    const auto& payload = std::get<RebalancePayload>(built->bundle.payload);
    BOOST_CHECK_EQUAL(payload.settlement_binding_digest, built->netting_manifest_id);
    BOOST_CHECK_EQUAL(payload.batch_statement_digest, built->bundle.header.proof_envelope.statement_digest);
    BOOST_CHECK(TransactionBundleOutputChunksAreCanonical(built->bundle));

    auto rebuilt = BuildDeterministicV2RebalanceBundle(input, reject_reason);
    BOOST_REQUIRE_MESSAGE(rebuilt.has_value(), reject_reason);
    BOOST_CHECK(ComputeTransactionBundleId(rebuilt->bundle) == ComputeTransactionBundleId(built->bundle));
}

BOOST_AUTO_TEST_CASE(postfork_rebalance_builder_uses_generic_wire_family)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    BOOST_REQUIRE(activation_height > 0);

    V2RebalanceBuildInput input;
    input.reserve_deltas = {
        MakeReserveDelta(0xf0, 7 * COIN),
        MakeReserveDelta(0xf1, -7 * COIN),
    };
    input.reserve_outputs = {
        MakeOutput(NoteClass::RESERVE, ScanDomain::RESERVE, 0xf2),
    };
    input.netting_manifest = MakeNettingManifest(input.reserve_deltas);

    std::string reject_reason;
    auto built = BuildDeterministicV2RebalanceBundle(input,
                                                     reject_reason,
                                                     &consensus,
                                                     activation_height);
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);
    BOOST_CHECK_EQUAL(built->bundle.header.family_id, TransactionFamily::V2_GENERIC);
    BOOST_CHECK_EQUAL(built->bundle.header.proof_envelope.proof_kind, ProofKind::GENERIC_OPAQUE);
    BOOST_CHECK(BundleHasSemanticFamily(built->bundle, TransactionFamily::V2_REBALANCE));
    BOOST_REQUIRE_EQUAL(built->bundle.output_chunks.size(), 1U);
    BOOST_CHECK_EQUAL(built->bundle.output_chunks.front().output_count, input.reserve_outputs.size());

    DataStream stream{};
    stream << built->bundle;

    TransactionBundle decoded;
    stream >> decoded;
    BOOST_REQUIRE(decoded.IsValid());
    BOOST_CHECK(BundleHasSemanticFamily(decoded, TransactionFamily::V2_REBALANCE));
    BOOST_REQUIRE_EQUAL(decoded.output_chunks.size(), 1U);
    BOOST_CHECK_EQUAL(decoded.output_chunks.front().output_count,
                      std::get<RebalancePayload>(decoded.payload).reserve_outputs.size());
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace
