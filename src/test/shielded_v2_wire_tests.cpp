// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainparams.h>
#include <consensus/amount.h>
#include <shielded/smile2/verify_dispatch.h>
#include <shielded/v2_ingress.h>
#include <shielded/v2_proof.h>
#include <shielded/v2_types.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <vector>

namespace {

using namespace shielded::v2;

Note MakeNote(NoteClass note_class = NoteClass::USER)
{
    Note note;
    note.note_class = note_class;
    note.value = 42 * COIN;
    note.owner_commitment = uint256{0x11};
    note.rho = uint256{0x12};
    note.rseed = uint256{0x13};
    note.source_binding = note_class == NoteClass::USER ? uint256::ZERO : uint256{0x14};
    note.memo = {0x01, 0x02, 0x03, 0x04};
    return note;
}

EncryptedNotePayload MakeEncryptedNotePayload()
{
    EncryptedNotePayload payload;
    payload.scan_domain = ScanDomain::USER;
    payload.scan_hint = {0x10, 0x11, 0x12, 0x13};
    payload.ciphertext = {0xaa, 0xbb, 0xcc, 0xdd};
    payload.ephemeral_key = ComputeLegacyPayloadEphemeralKey(
        Span<const uint8_t>{payload.ciphertext.data(), payload.ciphertext.size()});
    return payload;
}

ProofEnvelope MakeProofEnvelope(ProofKind kind = ProofKind::BATCH_MATRICT)
{
    ProofEnvelope envelope;
    envelope.proof_kind = kind;
    envelope.membership_proof_kind = kind == ProofKind::NONE ? ProofComponentKind::NONE : ProofComponentKind::MATRICT;
    envelope.amount_proof_kind = kind == ProofKind::NONE ? ProofComponentKind::NONE : ProofComponentKind::RANGE;
    envelope.balance_proof_kind = kind == ProofKind::NONE ? ProofComponentKind::NONE : ProofComponentKind::BALANCE;
    envelope.settlement_binding_kind = kind == ProofKind::NONE ? SettlementBindingKind::NONE : SettlementBindingKind::NATIVE_BATCH;
    envelope.statement_digest = kind == ProofKind::NONE ? uint256::ZERO : uint256{0x33};
    return envelope;
}

BatchLeaf MakeBatchLeaf(TransactionFamily family = TransactionFamily::V2_INGRESS_BATCH, unsigned char seed = 0x40)
{
    BatchLeaf leaf;
    leaf.family_id = family;
    leaf.l2_id = uint256{seed};
    leaf.destination_commitment = uint256{static_cast<unsigned char>(seed + 1)};
    leaf.amount_commitment = uint256{static_cast<unsigned char>(seed + 2)};
    leaf.fee_commitment = uint256{static_cast<unsigned char>(seed + 3)};
    leaf.position = seed;
    leaf.nonce = uint256{static_cast<unsigned char>(seed + 4)};
    leaf.settlement_domain = uint256{static_cast<unsigned char>(seed + 5)};
    return leaf;
}

ProofShardDescriptor MakeProofShard(unsigned char seed = 0x50)
{
    ProofShardDescriptor shard;
    shard.settlement_domain = uint256{seed};
    shard.first_leaf_index = seed;
    shard.leaf_count = 4;
    shard.leaf_subroot = uint256{static_cast<unsigned char>(seed + 1)};
    shard.nullifier_commitment = uint256{static_cast<unsigned char>(seed + 2)};
    shard.value_commitment = uint256{static_cast<unsigned char>(seed + 3)};
    shard.statement_digest = uint256{static_cast<unsigned char>(seed + 4)};
    shard.proof_metadata = {static_cast<uint8_t>(seed), static_cast<uint8_t>(seed + 1)};
    shard.proof_payload_offset = seed * 10U;
    shard.proof_payload_size = 512;
    return shard;
}

OutputChunkDescriptor MakeOutputChunk(unsigned char seed = 0x60)
{
    OutputChunkDescriptor chunk;
    chunk.scan_domain = ScanDomain::BATCH;
    chunk.first_output_index = seed;
    chunk.output_count = 8;
    chunk.ciphertext_bytes = 2048;
    chunk.scan_hint_commitment = uint256{static_cast<unsigned char>(seed + 1)};
    chunk.ciphertext_commitment = uint256{static_cast<unsigned char>(seed + 2)};
    return chunk;
}

NettingManifest MakeNettingManifest()
{
    NettingManifest manifest;
    manifest.settlement_window = 144;
    manifest.domains = {
        {uint256{0x70}, 15 * COIN},
        {uint256{0x71}, -5 * COIN},
        {uint256{0x72}, -10 * COIN},
    };
    manifest.aggregate_net_delta = 0;
    manifest.gross_flow_commitment = uint256{0x73};
    manifest.binding_kind = SettlementBindingKind::BRIDGE_RECEIPT;
    manifest.authorization_digest = uint256{0x74};
    return manifest;
}

TransactionHeader MakeTransactionHeader(TransactionFamily family = TransactionFamily::V2_REBALANCE)
{
    std::vector<ProofShardDescriptor> shards{MakeProofShard(0x80), MakeProofShard(0x81)};
    std::vector<OutputChunkDescriptor> chunks{MakeOutputChunk(0x90), MakeOutputChunk(0x91)};

    TransactionHeader header;
    header.family_id = family;
    header.proof_envelope = MakeProofEnvelope(ProofKind::IMPORTED_RECEIPT);
    header.payload_digest = uint256{0x82};
    header.proof_shard_root = ComputeProofShardRoot(Span<const ProofShardDescriptor>{shards.data(), shards.size()});
    header.proof_shard_count = shards.size();
    header.output_chunk_root = ComputeOutputChunkRoot(Span<const OutputChunkDescriptor>{chunks.data(), chunks.size()});
    header.output_chunk_count = chunks.size();
    header.netting_manifest_version = family == TransactionFamily::V2_REBALANCE ? WIRE_VERSION : 0;
    return header;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(shielded_v2_wire_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(family_id_inventory_is_stable)
{
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(TransactionFamily::V2_SEND), 1);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(TransactionFamily::V2_INGRESS_BATCH), 2);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(TransactionFamily::V2_EGRESS_BATCH), 3);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(TransactionFamily::V2_REBALANCE), 4);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(TransactionFamily::V2_SETTLEMENT_ANCHOR), 5);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(TransactionFamily::V2_GENERIC), 6);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(TransactionFamily::V2_LIFECYCLE), 7);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(V2_SPEND_PATH_RECOVERY), 8);

    BOOST_CHECK_EQUAL(GetTransactionFamilyName(TransactionFamily::V2_EGRESS_BATCH), "v2_egress_batch");
    BOOST_CHECK_EQUAL(GetTransactionFamilyName(TransactionFamily::V2_GENERIC), "shielded_v2");
    BOOST_CHECK_EQUAL(GetTransactionFamilyName(V2_SPEND_PATH_RECOVERY), "v2_spend_path_recovery");
    BOOST_CHECK(IsValidTransactionFamily(V2_SPEND_PATH_RECOVERY));
}

BOOST_AUTO_TEST_CASE(proof_kind_inventory_is_stable)
{
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(ProofKind::DIRECT_SMILE), 5);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(ProofKind::BATCH_SMILE), 6);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(ProofKind::GENERIC_SMILE), 7);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(ProofKind::GENERIC_BRIDGE), 8);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(ProofKind::GENERIC_OPAQUE), 9);

    BOOST_CHECK_EQUAL(GetProofKindName(ProofKind::GENERIC_SMILE), "generic_smile");
    BOOST_CHECK_EQUAL(GetProofKindName(ProofKind::GENERIC_BRIDGE), "generic_bridge");
    BOOST_CHECK_EQUAL(GetProofKindName(ProofKind::GENERIC_OPAQUE), "generic_opaque");
}

BOOST_AUTO_TEST_CASE(generic_wire_family_activates_at_disable_height)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    BOOST_REQUIRE(activation_height > 0);

    BOOST_CHECK(!UseGenericV2WireFamily(&consensus, activation_height - 1));
    BOOST_CHECK(UseGenericV2WireFamily(&consensus, activation_height));

    BOOST_CHECK_EQUAL(
        GetWireTransactionFamilyForValidationHeight(TransactionFamily::V2_SEND,
                                                    &consensus,
                                                    activation_height - 1),
        TransactionFamily::V2_SEND);
    BOOST_CHECK_EQUAL(
        GetWireTransactionFamilyForValidationHeight(TransactionFamily::V2_SEND,
                                                    &consensus,
                                                    activation_height),
        TransactionFamily::V2_GENERIC);
    BOOST_CHECK_EQUAL(
        GetWireTransactionFamilyForValidationHeight(TransactionFamily::V2_INGRESS_BATCH,
                                                    &consensus,
                                                    activation_height),
        TransactionFamily::V2_GENERIC);
    BOOST_CHECK_EQUAL(
        GetWireTransactionFamilyForValidationHeight(TransactionFamily::V2_EGRESS_BATCH,
                                                    &consensus,
                                                    activation_height),
        TransactionFamily::V2_GENERIC);
    BOOST_CHECK_EQUAL(
        GetWireTransactionFamilyForValidationHeight(TransactionFamily::V2_REBALANCE,
                                                    &consensus,
                                                    activation_height),
        TransactionFamily::V2_GENERIC);
    BOOST_CHECK_EQUAL(
        GetWireTransactionFamilyForValidationHeight(TransactionFamily::V2_SETTLEMENT_ANCHOR,
                                                    &consensus,
                                                    activation_height),
        TransactionFamily::V2_GENERIC);
    BOOST_CHECK_EQUAL(
        GetWireTransactionFamilyForValidationHeight(V2_SPEND_PATH_RECOVERY,
                                                    &consensus,
                                                    activation_height - 1),
        V2_SPEND_PATH_RECOVERY);
    BOOST_CHECK_EQUAL(
        GetWireTransactionFamilyForValidationHeight(V2_SPEND_PATH_RECOVERY,
                                                    &consensus,
                                                    activation_height),
        TransactionFamily::V2_GENERIC);
}

BOOST_AUTO_TEST_CASE(generic_proof_envelope_activates_at_disable_height)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    BOOST_REQUIRE(activation_height > 0);

    BOOST_CHECK(!UseGenericV2ProofEnvelope(&consensus, activation_height - 1));
    BOOST_CHECK(UseGenericV2ProofEnvelope(&consensus, activation_height));

    BOOST_CHECK_EQUAL(GetWireProofKindForValidationHeight(TransactionFamily::V2_SEND,
                                                          ProofKind::DIRECT_SMILE,
                                                          &consensus,
                                                          activation_height - 1),
                      ProofKind::DIRECT_SMILE);
    BOOST_CHECK_EQUAL(GetWireProofKindForValidationHeight(TransactionFamily::V2_SEND,
                                                          ProofKind::DIRECT_SMILE,
                                                          &consensus,
                                                          activation_height),
                      ProofKind::GENERIC_OPAQUE);
    BOOST_CHECK_EQUAL(GetWireProofKindForValidationHeight(TransactionFamily::V2_INGRESS_BATCH,
                                                          ProofKind::BATCH_SMILE,
                                                          &consensus,
                                                          activation_height),
                      ProofKind::GENERIC_OPAQUE);
    BOOST_CHECK_EQUAL(GetWireProofKindForValidationHeight(TransactionFamily::V2_REBALANCE,
                                                          ProofKind::BATCH_SMILE,
                                                          &consensus,
                                                          activation_height),
                      ProofKind::GENERIC_OPAQUE);
    BOOST_CHECK_EQUAL(GetWireProofKindForValidationHeight(TransactionFamily::V2_EGRESS_BATCH,
                                                          ProofKind::IMPORTED_RECEIPT,
                                                          &consensus,
                                                          activation_height),
                      ProofKind::GENERIC_OPAQUE);
    BOOST_CHECK_EQUAL(GetWireProofKindForValidationHeight(TransactionFamily::V2_SETTLEMENT_ANCHOR,
                                                          ProofKind::IMPORTED_CLAIM,
                                                          &consensus,
                                                          activation_height),
                      ProofKind::GENERIC_OPAQUE);
}

BOOST_AUTO_TEST_CASE(generic_settlement_binding_activates_at_disable_height)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    BOOST_REQUIRE(activation_height > 0);

    BOOST_CHECK(!UseGenericV2SettlementBinding(&consensus, activation_height - 1));
    BOOST_CHECK(UseGenericV2SettlementBinding(&consensus, activation_height));

    BOOST_CHECK_EQUAL(
        GetWireSettlementBindingKindForValidationHeight(TransactionFamily::V2_SEND,
                                                        SettlementBindingKind::NONE,
                                                        &consensus,
                                                        activation_height - 1),
        SettlementBindingKind::NONE);
    BOOST_CHECK_EQUAL(
        GetWireSettlementBindingKindForValidationHeight(TransactionFamily::V2_SEND,
                                                        SettlementBindingKind::NONE,
                                                        &consensus,
                                                        activation_height),
        SettlementBindingKind::GENERIC_POSTFORK);
    BOOST_CHECK_EQUAL(
        GetWireSettlementBindingKindForValidationHeight(TransactionFamily::V2_INGRESS_BATCH,
                                                        SettlementBindingKind::NATIVE_BATCH,
                                                        &consensus,
                                                        activation_height),
        SettlementBindingKind::GENERIC_POSTFORK);
    BOOST_CHECK_EQUAL(
        GetWireSettlementBindingKindForValidationHeight(TransactionFamily::V2_REBALANCE,
                                                        SettlementBindingKind::NETTING_MANIFEST,
                                                        &consensus,
                                                        activation_height),
        SettlementBindingKind::GENERIC_POSTFORK);
    BOOST_CHECK_EQUAL(
        GetWireSettlementBindingKindForValidationHeight(TransactionFamily::V2_EGRESS_BATCH,
                                                        SettlementBindingKind::BRIDGE_RECEIPT,
                                                        &consensus,
                                                        activation_height),
        SettlementBindingKind::GENERIC_POSTFORK);
    BOOST_CHECK_EQUAL(
        GetWireSettlementBindingKindForValidationHeight(TransactionFamily::V2_SETTLEMENT_ANCHOR,
                                                        SettlementBindingKind::BRIDGE_CLAIM,
                                                        &consensus,
                                                        activation_height),
        SettlementBindingKind::GENERIC_POSTFORK);
}

BOOST_AUTO_TEST_CASE(note_and_encrypted_payload_roundtrip_with_domain_separation)
{
    const Note user_note = MakeNote(NoteClass::USER);
    const Note reserve_note = MakeNote(NoteClass::RESERVE);
    const auto user_commitment = ComputeNoteCommitment(user_note);
    const auto reserve_commitment = ComputeNoteCommitment(reserve_note);
    BOOST_CHECK(user_note.IsValid());
    BOOST_CHECK(reserve_note.IsValid());
    BOOST_CHECK(user_commitment != reserve_commitment);

    const std::array<uint8_t, 32> spend_key_a{0x01};
    const std::array<uint8_t, 32> spend_key_b{0x02};
    BOOST_CHECK(ComputeNullifier(user_note, spend_key_a) != ComputeNullifier(user_note, spend_key_b));

    DataStream note_stream{};
    note_stream << user_note;
    Note decoded_note;
    note_stream >> decoded_note;
    BOOST_CHECK(decoded_note.IsValid());
    BOOST_CHECK(decoded_note.memo == user_note.memo);
    BOOST_CHECK(ComputeNoteCommitment(decoded_note) == user_commitment);

    const EncryptedNotePayload payload = MakeEncryptedNotePayload();
    BOOST_CHECK(payload.IsValid());
    DataStream payload_stream{};
    payload_stream << payload;
    EncryptedNotePayload decoded_payload;
    payload_stream >> decoded_payload;
    BOOST_CHECK(decoded_payload.IsValid());
    BOOST_CHECK(decoded_payload.ciphertext == payload.ciphertext);
    BOOST_CHECK(decoded_payload.scan_hint == payload.scan_hint);
}

BOOST_AUTO_TEST_CASE(encrypted_payload_rejects_oversized_ciphertext)
{
    EncryptedNotePayload payload = MakeEncryptedNotePayload();
    payload.ciphertext.resize(MAX_NOTE_CIPHERTEXT_BYTES + 1, 0x55);

    DataStream ss{};
    BOOST_CHECK_EXCEPTION(ss << payload,
                          std::ios_base::failure,
                          HasReason("EncryptedNotePayload::Serialize oversized ciphertext"));

    DataStream malformed{};
    malformed << static_cast<uint8_t>(ScanDomain::USER)
              << payload.scan_hint;
    const uint64_t oversize = MAX_NOTE_CIPHERTEXT_BYTES + 1;
    ::Serialize(malformed, COMPACTSIZE(oversize));

    EncryptedNotePayload decoded;
    BOOST_CHECK_EXCEPTION(malformed >> decoded,
                          std::ios_base::failure,
                          HasReason("EncryptedNotePayload::Unserialize oversized ciphertext"));
}

BOOST_AUTO_TEST_CASE(encrypted_payload_ignores_cached_ephemeral_key_for_validity)
{
    EncryptedNotePayload payload = MakeEncryptedNotePayload();
    payload.ephemeral_key.SetNull();
    BOOST_CHECK(payload.IsValid());

    DataStream ss{};
    ss << payload;
    EncryptedNotePayload decoded;
    ss >> decoded;
    BOOST_CHECK(decoded.IsValid());
    BOOST_CHECK(decoded.ephemeral_key == ComputeLegacyPayloadEphemeralKey(
                                           Span<const uint8_t>{decoded.ciphertext.data(), decoded.ciphertext.size()}));
}

BOOST_AUTO_TEST_CASE(v2_send_spend_witness_serialization_redacts_real_index)
{
    proof::V2SendSpendWitness witness;
    witness.real_index = 7;
    witness.ring_positions = {3, 4, 5, 6};

    DataStream ss{};
    ss << witness;

    proof::V2SendSpendWitness decoded;
    ss >> decoded;

    BOOST_CHECK_EQUAL(decoded.real_index, 0U);
    BOOST_CHECK(decoded.ring_positions == witness.ring_positions);
}

BOOST_AUTO_TEST_CASE(v2_ingress_spend_witness_serialization_redacts_real_index)
{
    V2IngressSpendWitness witness;
    witness.real_index = 9;
    witness.note_commitment = uint256{0x44};
    witness.ring_positions = {8, 9, 10};

    DataStream ss{};
    ss << witness;

    V2IngressSpendWitness decoded;
    ss >> decoded;

    BOOST_CHECK_EQUAL(decoded.real_index, 0U);
    BOOST_CHECK_EQUAL(decoded.note_commitment, witness.note_commitment);
    BOOST_CHECK(decoded.ring_positions == witness.ring_positions);
}

BOOST_AUTO_TEST_CASE(v2_send_witness_rejects_oversized_smile_proof_bytes)
{
    proof::V2SendWitness witness;
    witness.use_smile = true;
    witness.smile_proof_bytes.resize(smile2::MAX_SMILE2_PROOF_BYTES + 1, 0x5a);

    DataStream encoded{};
    BOOST_CHECK_EXCEPTION(encoded << witness,
                          std::ios_base::failure,
                          HasReason("V2SendWitness::Serialize oversized smile_proof_bytes"));

    DataStream malformed{};
    const uint64_t spend_count = 0;
    const uint64_t oversize = smile2::MAX_SMILE2_PROOF_BYTES + 1;
    ::Serialize(malformed, WIRE_VERSION);
    ::Serialize(malformed, COMPACTSIZE(spend_count));
    ::Serialize(malformed, proof::V2SendWitness::PROOF_TAG_SMILE);
    ::Serialize(malformed, COMPACTSIZE(oversize));

    proof::V2SendWitness decoded;
    BOOST_CHECK_EXCEPTION(malformed >> decoded,
                          std::ios_base::failure,
                          HasReason("V2SendWitness::Unserialize oversized smile_proof_bytes"));
}

BOOST_AUTO_TEST_CASE(batch_leaf_hash_commits_family_and_settlement_domain)
{
    const BatchLeaf ingress_leaf = MakeBatchLeaf(TransactionFamily::V2_INGRESS_BATCH, 0x41);
    BatchLeaf egress_leaf = ingress_leaf;
    egress_leaf.family_id = TransactionFamily::V2_EGRESS_BATCH;
    BatchLeaf generic_leaf = ingress_leaf;
    generic_leaf.family_id = TransactionFamily::V2_GENERIC;

    BatchLeaf rebased_leaf = ingress_leaf;
    rebased_leaf.settlement_domain = uint256{0x99};

    BOOST_CHECK(ingress_leaf.IsValid());
    BOOST_CHECK(egress_leaf.IsValid());
    BOOST_CHECK(generic_leaf.IsValid());
    BOOST_CHECK(ComputeBatchLeafHash(ingress_leaf) != ComputeBatchLeafHash(egress_leaf));
    BOOST_CHECK(ComputeBatchLeafHash(ingress_leaf) != ComputeBatchLeafHash(generic_leaf));
    BOOST_CHECK(ComputeBatchLeafHash(ingress_leaf) != ComputeBatchLeafHash(rebased_leaf));

    BatchLeaf invalid_leaf = ingress_leaf;
    invalid_leaf.family_id = TransactionFamily::V2_SEND;
    BOOST_CHECK(!invalid_leaf.IsValid());
}

BOOST_AUTO_TEST_CASE(proof_shard_and_output_chunk_roots_are_ordered)
{
    const ProofShardDescriptor shard_a = MakeProofShard(0xa0);
    const ProofShardDescriptor shard_b = MakeProofShard(0xa1);
    const std::vector<ProofShardDescriptor> ordered_shards{shard_a, shard_b};
    const std::vector<ProofShardDescriptor> reversed_shards{shard_b, shard_a};

    BOOST_CHECK(shard_a.IsValid());
    BOOST_CHECK(shard_b.IsValid());
    BOOST_CHECK(ComputeProofShardRoot(Span<const ProofShardDescriptor>{ordered_shards.data(), ordered_shards.size()}) !=
                ComputeProofShardRoot(Span<const ProofShardDescriptor>{reversed_shards.data(), reversed_shards.size()}));

    const OutputChunkDescriptor chunk_a = MakeOutputChunk(0xb0);
    const OutputChunkDescriptor chunk_b = MakeOutputChunk(0xb1);
    const std::vector<OutputChunkDescriptor> chunks{chunk_a, chunk_b};
    BOOST_CHECK(chunk_a.IsValid());
    BOOST_CHECK(chunk_b.IsValid());
    BOOST_CHECK(!ComputeOutputChunkRoot(Span<const OutputChunkDescriptor>{chunks.data(), chunks.size()}).IsNull());

    ProofShardDescriptor invalid_shard = shard_a;
    invalid_shard.proof_metadata.clear();
    BOOST_CHECK(!invalid_shard.IsValid());
}

BOOST_AUTO_TEST_CASE(netting_manifest_roundtrip_and_zero_sum_rules)
{
    const NettingManifest manifest = MakeNettingManifest();
    BOOST_CHECK(manifest.IsValid());
    const uint256 manifest_id = ComputeNettingManifestId(manifest);
    BOOST_CHECK(!manifest_id.IsNull());

    DataStream ss{};
    ss << manifest;
    NettingManifest decoded;
    ss >> decoded;
    BOOST_CHECK(decoded.IsValid());
    BOOST_CHECK(decoded.domains.size() == manifest.domains.size());
    BOOST_CHECK(ComputeNettingManifestId(decoded) == manifest_id);

    NettingManifest bad_sum = manifest;
    bad_sum.aggregate_net_delta = 1;
    BOOST_CHECK(!bad_sum.IsValid());

    NettingManifest unsorted = manifest;
    std::swap(unsorted.domains[0], unsorted.domains[1]);
    BOOST_CHECK(!unsorted.IsValid());
}

BOOST_AUTO_TEST_CASE(proof_envelope_roundtrip_accepts_extension_digest)
{
    ProofEnvelope envelope = MakeProofEnvelope(ProofKind::BATCH_SMILE);
    envelope.membership_proof_kind = ProofComponentKind::SMILE_MEMBERSHIP;
    envelope.amount_proof_kind = ProofComponentKind::SMILE_BALANCE;
    envelope.balance_proof_kind = ProofComponentKind::SMILE_BALANCE;
    envelope.extension_digest = uint256{0xaa};
    BOOST_CHECK(envelope.IsValid());

    DataStream ss{};
    ss << envelope;
    ProofEnvelope decoded;
    ss >> decoded;
    BOOST_CHECK(decoded.IsValid());
    BOOST_CHECK(decoded.extension_digest == envelope.extension_digest);
}

BOOST_AUTO_TEST_CASE(transaction_header_roundtrip_and_invalid_family_rejected)
{
    const TransactionHeader header = MakeTransactionHeader();
    BOOST_CHECK(header.IsValid());
    const uint256 header_id = ComputeTransactionHeaderId(header);
    BOOST_CHECK(!header_id.IsNull());

    DataStream ss{};
    ss << header;
    TransactionHeader decoded;
    ss >> decoded;
    BOOST_CHECK(decoded.IsValid());
    BOOST_CHECK(ComputeTransactionHeaderId(decoded) == header_id);

    TransactionHeader extension_mutated = header;
    extension_mutated.proof_envelope.extension_digest = uint256{0xab};
    BOOST_CHECK(extension_mutated.IsValid());
    BOOST_CHECK(ComputeTransactionHeaderId(extension_mutated) != header_id);

    DataStream malformed{};
    malformed << uint8_t{WIRE_VERSION}
              << uint8_t{99}
              << MakeProofEnvelope(ProofKind::NONE)
              << uint256{0x01}
              << uint256::ZERO
              << uint32_t{0}
              << uint256::ZERO
              << uint32_t{0}
              << uint8_t{0};

    TransactionHeader invalid;
    BOOST_CHECK_EXCEPTION(malformed >> invalid,
                          std::ios_base::failure,
                          HasReason("TransactionHeader::Unserialize invalid family_id"));

    TransactionHeader wrong_manifest_family = MakeTransactionHeader(TransactionFamily::V2_SEND);
    wrong_manifest_family.netting_manifest_version = WIRE_VERSION;
    BOOST_CHECK(!wrong_manifest_family.IsValid());
}

BOOST_AUTO_TEST_SUITE_END()
