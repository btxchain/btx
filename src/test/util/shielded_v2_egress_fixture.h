// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_TEST_UTIL_SHIELDED_V2_EGRESS_FIXTURE_H
#define BTX_TEST_UTIL_SHIELDED_V2_EGRESS_FIXTURE_H

#include <chainparams.h>
#include <consensus/amount.h>
#include <hash.h>
#include <key.h>
#include <shielded/bridge.h>
#include <shielded/v2_egress.h>
#include <shielded/v2_bundle.h>
#include <shielded/v2_proof.h>
#include <streams.h>
#include <test/util/shielded_smile_test_util.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef OPAQUE
#undef OPAQUE
#endif

namespace test::shielded {

inline std::string DescribeInvalidBundleForFixture(const ::shielded::v2::TransactionBundle& bundle)
{
    std::ostringstream reason;
    const auto semantic_family = ::shielded::v2::GetBundleSemanticFamily(bundle);
    const bool proof_shard_count_match = bundle.proof_shards.size() == bundle.header.proof_shard_count;
    const bool output_chunk_count_match = bundle.output_chunks.size() == bundle.header.output_chunk_count;
    const bool proof_root_match =
        bundle.header.proof_shard_root ==
        (bundle.proof_shards.empty() ? uint256::ZERO : ::shielded::v2::ComputeProofShardRoot({bundle.proof_shards.data(), bundle.proof_shards.size()}));
    bool statement_digest_present = false;
    bool shard_statement_match = false;
    bool shard_shape_match = false;
    if (!bundle.proof_shards.empty()) {
        statement_digest_present = std::find(std::get<::shielded::v2::SettlementAnchorPayload>(bundle.payload).batch_statement_digests.begin(),
                                             std::get<::shielded::v2::SettlementAnchorPayload>(bundle.payload).batch_statement_digests.end(),
                                             bundle.header.proof_envelope.statement_digest) !=
                                   std::get<::shielded::v2::SettlementAnchorPayload>(bundle.payload).batch_statement_digests.end();
        shard_statement_match =
            std::all_of(bundle.proof_shards.begin(), bundle.proof_shards.end(), [&](const ::shielded::v2::ProofShardDescriptor& descriptor) {
                return descriptor.statement_digest == bundle.header.proof_envelope.statement_digest;
            });
        const auto& shard = bundle.proof_shards.front();
        shard_shape_match = bundle.proof_shards.size() == 1 &&
                            shard.first_leaf_index == 0 &&
                            shard.leaf_count == 1 &&
                            shard.proof_payload_offset == 0 &&
                            shard.proof_payload_size == bundle.proof_payload.size();
    }
    ::shielded::v2::proof::ProofStatement statement;
    statement.domain = semantic_family == ::shielded::v2::TransactionFamily::V2_SEND
        ? ::shielded::v2::proof::VerificationDomain::DIRECT_SPEND
        : ::shielded::v2::proof::VerificationDomain::BATCH_SETTLEMENT;
    statement.envelope = bundle.header.proof_envelope;
    reason << "version=" << static_cast<unsigned int>(bundle.version)
           << " family=" << static_cast<unsigned int>(bundle.header.family_id)
           << " semantic=" << static_cast<unsigned int>(semantic_family)
           << " proof_kind=" << static_cast<unsigned int>(bundle.header.proof_envelope.proof_kind)
           << " membership_kind=" << static_cast<unsigned int>(bundle.header.proof_envelope.membership_proof_kind)
           << " amount_kind=" << static_cast<unsigned int>(bundle.header.proof_envelope.amount_proof_kind)
           << " balance_kind=" << static_cast<unsigned int>(bundle.header.proof_envelope.balance_proof_kind)
           << " binding_kind=" << static_cast<unsigned int>(bundle.header.proof_envelope.settlement_binding_kind)
           << " header_valid=" << bundle.header.IsValid()
           << " family_payload_match=" << ::shielded::v2::WireFamilyMatchesPayload(bundle.header.family_id, bundle.payload)
           << " envelope_valid=" << bundle.header.proof_envelope.IsValid()
           << " statement_valid=" << statement.IsValid()
           << " proof_shard_count_match=" << proof_shard_count_match
           << " output_chunk_count_match=" << output_chunk_count_match
           << " proof_root_match=" << proof_root_match
            << " proof_shards=" << bundle.proof_shards.size()
            << " output_chunks=" << bundle.output_chunks.size()
            << " proof_payload=" << bundle.proof_payload.size()
           << " payload_digest_match="
           << (::shielded::v2::ComputePayloadDigest(bundle.payload) == bundle.header.payload_digest)
           << " statement_digest_present=" << statement_digest_present
           << " shard_statement_match=" << shard_statement_match
           << " shard_shape_match=" << shard_shape_match
           << " netting_manifest_version=" << static_cast<unsigned int>(bundle.header.netting_manifest_version);
    return reason.str();
}

struct V2EgressReceiptFixture
{
    CMutableTransaction tx;
    ::shielded::BridgeBatchStatement statement;
    ::shielded::BridgeProofDescriptor descriptor;
    ::shielded::BridgeProofReceipt receipt;
    std::vector<::shielded::BridgeKeySpec> attestors;
    std::vector<::shielded::BridgeBatchReceipt> signed_receipts;
    std::vector<::shielded::BridgeVerifierSetProof> signed_receipt_proofs;
    std::optional<::shielded::BridgeVerificationBundle> verification_bundle;
    ::shielded::v2::proof::SettlementWitness witness;
};

struct V2SettlementAnchorReceiptFixture
{
    CMutableTransaction tx;
    ::shielded::BridgeBatchStatement statement;
    ::shielded::BridgeProofDescriptor descriptor;
    ::shielded::BridgeProofReceipt receipt;
    std::vector<::shielded::BridgeProofAdapter> imported_adapters;
    std::vector<::shielded::BridgeKeySpec> attestors;
    std::vector<::shielded::BridgeBatchReceipt> signed_receipts;
    std::vector<::shielded::BridgeVerifierSetProof> signed_receipt_proofs;
    std::optional<::shielded::BridgeVerificationBundle> verification_bundle;
    ::shielded::v2::proof::SettlementWitness witness;
    uint256 settlement_anchor_digest;
};

struct V2SettlementAnchorClaimFixture
{
    CMutableTransaction tx;
    ::shielded::BridgeBatchStatement statement;
    ::shielded::BridgeProofClaim claim;
    std::vector<::shielded::BridgeProofAdapter> imported_adapters;
    ::shielded::v2::proof::SettlementWitness witness;
    uint256 settlement_anchor_digest;
};

struct V2RebalanceFixture
{
    CMutableTransaction tx;
    std::vector<::shielded::v2::ReserveDelta> reserve_deltas;
    std::vector<::shielded::v2::OutputDescription> reserve_outputs;
    ::shielded::v2::NettingManifest manifest;
    uint256 manifest_id;
};

inline ::shielded::v2::TransactionFamily ResolveFixtureWireFamily(
    ::shielded::v2::TransactionFamily semantic_family,
    const Consensus::Params* consensus = nullptr,
    int32_t validation_height = std::numeric_limits<int32_t>::max())
{
    const Consensus::Params* effective_consensus = consensus != nullptr ? consensus : &Params().GetConsensus();
    return ::shielded::v2::GetWireTransactionFamilyForValidationHeight(
        semantic_family,
        effective_consensus,
        validation_height);
}

inline ::shielded::v2::ProofKind ResolveFixtureProofKind(
    ::shielded::v2::TransactionFamily semantic_family,
    ::shielded::v2::ProofKind semantic_proof_kind,
    const Consensus::Params* consensus = nullptr,
    int32_t validation_height = std::numeric_limits<int32_t>::max())
{
    const Consensus::Params* effective_consensus = consensus != nullptr ? consensus : &Params().GetConsensus();
    return ::shielded::v2::GetWireProofKindForValidationHeight(
        semantic_family,
        semantic_proof_kind,
        effective_consensus,
        validation_height);
}

inline void ApplyFixtureWireEnvelopeKinds(
    ::shielded::v2::TransactionFamily semantic_family,
    ::shielded::v2::ProofEnvelope& envelope,
    const Consensus::Params* consensus = nullptr,
    int32_t validation_height = std::numeric_limits<int32_t>::max())
{
    const Consensus::Params* effective_consensus = consensus != nullptr ? consensus : &Params().GetConsensus();
    envelope.proof_kind = ::shielded::v2::GetWireProofKindForValidationHeight(
        semantic_family,
        envelope.proof_kind,
        effective_consensus,
        validation_height);
    envelope.membership_proof_kind = ::shielded::v2::GetWireProofComponentKindForValidationHeight(
        envelope.membership_proof_kind,
        effective_consensus,
        validation_height);
    envelope.amount_proof_kind = ::shielded::v2::GetWireProofComponentKindForValidationHeight(
        envelope.amount_proof_kind,
        effective_consensus,
        validation_height);
    envelope.balance_proof_kind = ::shielded::v2::GetWireProofComponentKindForValidationHeight(
        envelope.balance_proof_kind,
        effective_consensus,
        validation_height);
    envelope.settlement_binding_kind = ::shielded::v2::GetWireSettlementBindingKindForValidationHeight(
        semantic_family,
        envelope.settlement_binding_kind,
        effective_consensus,
        validation_height);
}

inline ::shielded::v2::OutputDescription MakeV2EgressOutput(unsigned char seed)
{
    ::shielded::v2::OutputDescription output;
    output.note_class = ::shielded::v2::NoteClass::USER;
    output.smile_account = test::shielded::MakeDeterministicCompactPublicAccount(seed);
    output.note_commitment = ::smile2::ComputeCompactPublicAccountHash(*output.smile_account);
    output.value_commitment = uint256{static_cast<unsigned char>(seed + 1)};
    output.encrypted_note.scan_domain = ::shielded::v2::ScanDomain::OPAQUE;
    output.encrypted_note.scan_hint.fill(static_cast<unsigned char>(seed + 2));
    output.encrypted_note.ciphertext = {
        static_cast<unsigned char>(seed + 4),
        static_cast<unsigned char>(seed + 5),
        static_cast<unsigned char>(seed + 6),
    };
    output.encrypted_note.ephemeral_key = ::shielded::v2::ComputeLegacyPayloadEphemeralKey(
        Span<const uint8_t>{output.encrypted_note.ciphertext.data(), output.encrypted_note.ciphertext.size()});
    return output;
}

inline ::shielded::v2::OutputDescription MakeV2ReserveOutput(unsigned char seed)
{
    ::shielded::v2::OutputDescription output = MakeV2EgressOutput(seed);
    output.note_class = ::shielded::v2::NoteClass::RESERVE;
    output.encrypted_note.scan_domain = ::shielded::v2::ScanDomain::OPAQUE;
    return output;
}

inline void CanonicalizeV2EgressOutputs(std::vector<::shielded::v2::OutputDescription>& outputs,
                                        ::shielded::BridgeBatchStatement& statement)
{
    const uint256 output_binding_digest = ::shielded::v2::ComputeV2EgressOutputBindingDigest(statement);
    if (output_binding_digest.IsNull()) {
        throw std::runtime_error("invalid v2 egress output binding digest fixture");
    }
    for (size_t output_index = 0; output_index < outputs.size(); ++output_index) {
        outputs[output_index].value_commitment = ::shielded::v2::ComputeV2EgressOutputValueCommitment(
            output_binding_digest,
            static_cast<uint32_t>(output_index),
            outputs[output_index].note_commitment);
    }
    statement.batch_root = ::shielded::v2::ComputeOutputDescriptionRoot(
        Span<const ::shielded::v2::OutputDescription>{outputs.data(), outputs.size()});
}

inline void CanonicalizeV2RebalanceOutputs(std::vector<::shielded::v2::OutputDescription>& outputs)
{
    for (size_t output_index = 0; output_index < outputs.size(); ++output_index) {
        outputs[output_index].value_commitment = ::shielded::v2::ComputeV2RebalanceOutputValueCommitment(
            static_cast<uint32_t>(output_index),
            outputs[output_index].note_commitment);
    }
}

inline ::shielded::v2::ReserveDelta MakeV2ReserveDelta(unsigned char seed, CAmount delta)
{
    ::shielded::v2::ReserveDelta reserve_delta;
    reserve_delta.l2_id = uint256{seed};
    reserve_delta.reserve_delta = delta;
    if (!reserve_delta.IsValid()) {
        throw std::runtime_error("invalid v2 rebalance reserve delta fixture");
    }
    return reserve_delta;
}

inline ::shielded::v2::NettingManifest MakeV2NettingManifest(
    const std::vector<::shielded::v2::ReserveDelta>& reserve_deltas,
    uint32_t settlement_window = 144)
{
    ::shielded::v2::NettingManifest manifest;
    manifest.settlement_window = settlement_window;
    manifest.binding_kind = ::shielded::v2::SettlementBindingKind::NETTING_MANIFEST;
    manifest.gross_flow_commitment = uint256{0xe1};
    manifest.authorization_digest = uint256{0xe2};
    manifest.aggregate_net_delta = 0;
    manifest.domains.reserve(reserve_deltas.size());
    for (const auto& reserve_delta : reserve_deltas) {
        manifest.domains.push_back({reserve_delta.l2_id, reserve_delta.reserve_delta});
    }
    if (!manifest.IsValid()) {
        throw std::runtime_error("invalid v2 rebalance netting manifest fixture");
    }
    return manifest;
}

inline ::shielded::v2::ProofShardDescriptor MakeV2ProofShard(unsigned char seed,
                                                             const uint256& statement_digest)
{
    ::shielded::v2::ProofShardDescriptor descriptor;
    descriptor.settlement_domain = uint256{seed};
    descriptor.first_leaf_index = 0;
    descriptor.leaf_count = 2;
    descriptor.leaf_subroot = uint256{static_cast<unsigned char>(seed + 1)};
    descriptor.nullifier_commitment = uint256{static_cast<unsigned char>(seed + 2)};
    descriptor.value_commitment = uint256{static_cast<unsigned char>(seed + 3)};
    descriptor.statement_digest = statement_digest;
    descriptor.proof_metadata = {seed, static_cast<unsigned char>(seed + 1)};
    descriptor.proof_payload_offset = 0;
    descriptor.proof_payload_size = 2;
    return descriptor;
}

inline ::shielded::BridgeProofDescriptor MakeV2EgressDescriptor(unsigned char seed)
{
    const auto adapter = ::shielded::BuildCanonicalBridgeProofAdapter(
        ::shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    if (!adapter.has_value()) {
        throw std::runtime_error("missing canonical v2 egress descriptor profile");
    }
    const auto descriptor = ::shielded::BuildBridgeProofDescriptorFromAdapter(
        *adapter,
        uint256{static_cast<unsigned char>(seed + 1)});
    if (!descriptor.has_value()) {
        throw std::runtime_error("invalid v2 egress descriptor fixture");
    }
    return *descriptor;
}

inline ::shielded::BridgeProofAdapter MakeV2ProofAdapter(unsigned char seed,
                                                         ::shielded::BridgeProofClaimKind claim_kind)
{
    const auto adapter = ::shielded::BuildCanonicalBridgeProofAdapter(
        claim_kind,
        static_cast<size_t>(seed));
    if (!adapter.has_value()) {
        throw std::runtime_error("invalid v2 settlement proof adapter fixture");
    }
    return *adapter;
}

inline ::shielded::BridgeProofReceipt MakeV2ProofReceipt(const ::shielded::BridgeBatchStatement& statement,
                                                         const ::shielded::BridgeProofDescriptor& descriptor,
                                                         unsigned char seed)
{
    ::shielded::BridgeProofReceipt receipt;
    receipt.statement_hash = ::shielded::ComputeBridgeBatchStatementHash(statement);
    receipt.proof_system_id = descriptor.proof_system_id;
    receipt.verifier_key_hash = descriptor.verifier_key_hash;
    receipt.public_values_hash = uint256{static_cast<unsigned char>(seed + 1)};
    receipt.proof_commitment = uint256{static_cast<unsigned char>(seed + 2)};
    if (!receipt.IsValid()) {
        throw std::runtime_error("invalid v2 egress proof receipt fixture");
    }
    return receipt;
}

inline std::vector<uint256> CollectCanonicalProofReceiptIds(
    Span<const ::shielded::BridgeProofReceipt> receipts)
{
    std::vector<uint256> receipt_ids;
    receipt_ids.reserve(receipts.size());
    for (const auto& receipt : receipts) {
        const uint256 receipt_id = ::shielded::ComputeBridgeProofReceiptHash(receipt);
        if (receipt_id.IsNull()) {
            throw std::runtime_error("invalid v2 settlement-anchor receipt id fixture");
        }
        receipt_ids.push_back(receipt_id);
    }
    std::sort(receipt_ids.begin(), receipt_ids.end());
    if (std::adjacent_find(receipt_ids.begin(), receipt_ids.end()) != receipt_ids.end()) {
        throw std::runtime_error("duplicate v2 settlement-anchor receipt id fixture");
    }
    return receipt_ids;
}

inline std::vector<::shielded::v2::ReserveDelta> MakeSettlementAnchorReserveDeltas()
{
    ::shielded::v2::ReserveDelta positive;
    positive.l2_id = uint256{0xf0};
    positive.reserve_delta = 7 * COIN;

    ::shielded::v2::ReserveDelta negative;
    negative.l2_id = uint256{0xf1};
    negative.reserve_delta = -7 * COIN;

    if (!positive.IsValid() || !negative.IsValid()) {
        throw std::runtime_error("invalid v2 settlement-anchor reserve delta fixture");
    }

    return {positive, negative};
}

inline void AttachSettlementAnchorReserveBinding(
    CMutableTransaction& tx,
    const std::vector<::shielded::v2::ReserveDelta>& reserve_deltas = MakeSettlementAnchorReserveDeltas(),
    const uint256& anchored_netting_manifest_id = uint256{0xf2})
{
    if (!tx.shielded_bundle.v2_bundle.has_value()) {
        throw std::runtime_error("missing v2 settlement-anchor bundle fixture");
    }

    auto& bundle = *tx.shielded_bundle.v2_bundle;
    auto& payload = std::get<::shielded::v2::SettlementAnchorPayload>(bundle.payload);
    payload.reserve_deltas = reserve_deltas;
    payload.anchored_netting_manifest_id = anchored_netting_manifest_id;
    bundle.header.payload_digest = ::shielded::v2::ComputeSettlementAnchorPayloadDigest(payload);

    if (!bundle.IsValid()) {
        throw std::runtime_error("invalid v2 settlement-anchor reserve binding fixture");
    }
}

inline void RefreshV2RebalanceFixture(
    V2RebalanceFixture& fixture,
    const Consensus::Params* consensus = nullptr,
    int32_t validation_height = std::numeric_limits<int32_t>::max())
{
    const Consensus::Params* effective_consensus = consensus != nullptr ? consensus : &Params().GetConsensus();
    fixture.manifest_id = ::shielded::v2::ComputeNettingManifestId(fixture.manifest);
    if (fixture.manifest_id.IsNull()) {
        throw std::runtime_error("invalid refreshed v2 rebalance manifest id fixture");
    }

    ::shielded::v2::V2RebalanceBuildInput input;
    input.reserve_deltas = fixture.reserve_deltas;
    input.reserve_outputs = fixture.reserve_outputs;
    input.netting_manifest = fixture.manifest;

    std::string reject_reason;
    auto built = ::shielded::v2::BuildDeterministicV2RebalanceBundle(input,
                                                                     reject_reason,
                                                                     effective_consensus,
                                                                     validation_height);
    if (!built.has_value()) {
        throw std::runtime_error("invalid refreshed v2 rebalance fixture: " + reject_reason);
    }
    if (built->netting_manifest_id != fixture.manifest_id) {
        throw std::runtime_error("mismatched refreshed v2 rebalance manifest id fixture");
    }

    fixture.tx.shielded_bundle.v2_bundle = std::move(built->bundle);
}

inline V2RebalanceFixture BuildV2RebalanceFixture(
    size_t reserve_output_count = 1,
    uint32_t settlement_window = 144,
    const Consensus::Params* consensus = nullptr,
    int32_t validation_height = std::numeric_limits<int32_t>::max())
{
    if (reserve_output_count == 0) {
        throw std::runtime_error("v2 rebalance fixture requires reserve outputs");
    }

    V2RebalanceFixture fixture;
    fixture.reserve_deltas = {
        MakeV2ReserveDelta(0xe3, 7 * COIN),
        MakeV2ReserveDelta(0xe4, -7 * COIN),
    };
    fixture.reserve_outputs.reserve(reserve_output_count);
    for (size_t i = 0; i < reserve_output_count; ++i) {
        fixture.reserve_outputs.push_back(
            MakeV2ReserveOutput(static_cast<unsigned char>(0xe5 + i * 4)));
    }
    CanonicalizeV2RebalanceOutputs(fixture.reserve_outputs);
    fixture.manifest = MakeV2NettingManifest(fixture.reserve_deltas, settlement_window);
    RefreshV2RebalanceFixture(fixture, consensus, validation_height);
    return fixture;
}

inline std::vector<::shielded::BridgeKeySpec> MakeV2EgressAttestors(unsigned char seed_base, size_t count)
{
    std::vector<::shielded::BridgeKeySpec> attestors;
    attestors.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        std::array<unsigned char, 32> material{};
        material.fill(static_cast<unsigned char>(seed_base + i));

        CPQKey key;
        if (!key.MakeDeterministicKey(PQAlgorithm::ML_DSA_44, material)) {
            throw std::runtime_error("failed to build v2 egress attestor fixture");
        }
        attestors.push_back({PQAlgorithm::ML_DSA_44, key.GetPubKey()});
    }
    return attestors;
}

inline ::shielded::BridgeBatchReceipt MakeV2SignedBatchReceipt(unsigned char seed,
                                                               const ::shielded::BridgeBatchStatement& statement)
{
    std::array<unsigned char, 32> material{};
    material.fill(seed);

    CPQKey key;
    if (!key.MakeDeterministicKey(PQAlgorithm::ML_DSA_44, material)) {
        throw std::runtime_error("failed to build v2 signed batch receipt fixture");
    }

    ::shielded::BridgeBatchReceipt receipt;
    receipt.statement = statement;
    receipt.attestor = {PQAlgorithm::ML_DSA_44, key.GetPubKey()};

    const uint256 receipt_hash = ::shielded::ComputeBridgeBatchReceiptHash(receipt);
    if (receipt_hash.IsNull() || !key.Sign(receipt_hash, receipt.signature) || !receipt.IsValid()) {
        throw std::runtime_error("invalid v2 signed batch receipt fixture");
    }
    return receipt;
}

inline V2EgressReceiptFixture BuildV2EgressReceiptFixture(std::vector<::shielded::v2::OutputDescription> outputs,
                                                          std::vector<uint32_t> output_chunk_sizes = {},
                                                          std::optional<CAmount> total_amount = std::nullopt,
                                                          size_t proof_receipt_count = 1,
                                                          size_t required_receipts = 1,
                                                          const Consensus::Params* consensus = nullptr,
                                                          int32_t validation_height = std::numeric_limits<int32_t>::max())
{
    const Consensus::Params* effective_consensus = consensus != nullptr ? consensus : &Params().GetConsensus();
    if (outputs.empty()) {
        throw std::runtime_error("v2 egress fixture requires outputs");
    }
    if (proof_receipt_count == 0 || required_receipts == 0 || proof_receipt_count < required_receipts) {
        throw std::runtime_error("v2 egress fixture requires satisfiable proof receipt threshold");
    }

    V2EgressReceiptFixture fixture;

    fixture.descriptor = MakeV2EgressDescriptor(0x91);
    const std::vector<::shielded::BridgeProofDescriptor> descriptors{fixture.descriptor};

    const auto proof_policy =
        ::shielded::BuildBridgeProofPolicyCommitment(descriptors, required_receipts);
    if (!proof_policy.has_value()) {
        throw std::runtime_error("failed to build v2 egress proof policy");
    }

    fixture.statement.version = 3;
    fixture.statement.direction = ::shielded::BridgeDirection::BRIDGE_OUT;
    fixture.statement.ids.bridge_id = uint256{0x81};
    fixture.statement.ids.operation_id = uint256{0x82};
    fixture.statement.entry_count = static_cast<uint32_t>(outputs.size());
    fixture.statement.total_amount = total_amount.value_or(static_cast<CAmount>(outputs.size()) * COIN);
    fixture.statement.domain_id = uint256{0x83};
    fixture.statement.source_epoch = 12;
    fixture.statement.data_root = uint256{0x84};
    fixture.statement.proof_policy = *proof_policy;
    CanonicalizeV2EgressOutputs(outputs, fixture.statement);
    if (!fixture.statement.IsValid()) {
        throw std::runtime_error("invalid v2 egress batch statement fixture");
    }

    std::vector<::shielded::BridgeProofReceipt> proof_receipts;
    proof_receipts.reserve(proof_receipt_count);
    for (size_t i = 0; i < proof_receipt_count; ++i) {
        proof_receipts.push_back(
            MakeV2ProofReceipt(fixture.statement,
                               fixture.descriptor,
                               static_cast<unsigned char>(0x84 + (i * 4))));
    }
    fixture.receipt = proof_receipts.front();

    fixture.witness.statement = fixture.statement;
    fixture.witness.proof_receipts = proof_receipts;
    fixture.witness.descriptor_proof =
        ::shielded::BuildBridgeProofPolicyProof(descriptors, fixture.descriptor);
    if (!fixture.witness.descriptor_proof.has_value() || !fixture.witness.IsValid()) {
        throw std::runtime_error("invalid v2 egress witness fixture");
    }

    ::shielded::v2::V2EgressBuildInput input;
    input.statement = fixture.statement;
    input.proof_descriptors = descriptors;
    input.imported_descriptor = fixture.descriptor;
    input.proof_receipts = proof_receipts;
    input.imported_receipt = fixture.receipt;
    input.outputs = std::move(outputs);
    input.output_chunk_sizes = std::move(output_chunk_sizes);

    std::string reject_reason;
    auto built = ::shielded::v2::BuildV2EgressBatchTransaction(CMutableTransaction{},
                                                               input,
                                                               reject_reason,
                                                               effective_consensus,
                                                               validation_height);
    if (!built.has_value()) {
        throw std::runtime_error(reject_reason.empty() ? "failed to build v2 egress transaction bundle fixture"
                                                       : reject_reason);
    }

    fixture.tx = built->tx;
    fixture.witness = built->witness;
    return fixture;
}

inline V2EgressReceiptFixture BuildV2EgressReceiptFixture(
    size_t output_count = 2,
    const Consensus::Params* consensus = nullptr,
    int32_t validation_height = std::numeric_limits<int32_t>::max())
{
    if (output_count == 0) {
        throw std::runtime_error("v2 egress fixture requires outputs");
    }

    std::vector<::shielded::v2::OutputDescription> outputs;
    outputs.reserve(output_count);
    for (size_t i = 0; i < output_count; ++i) {
        outputs.push_back(MakeV2EgressOutput(static_cast<unsigned char>(0x40 + i * 8)));
    }
    return BuildV2EgressReceiptFixture(std::move(outputs),
                                       {},
                                       std::nullopt,
                                       /*proof_receipt_count=*/1,
                                       /*required_receipts=*/1,
                                       consensus,
                                       validation_height);
}

inline V2EgressReceiptFixture BuildV2EgressReceiptFixture(size_t output_count,
                                                          size_t proof_receipt_count,
                                                          size_t required_receipts,
                                                          const Consensus::Params* consensus = nullptr,
                                                          int32_t validation_height = std::numeric_limits<int32_t>::max())
{
    if (output_count == 0) {
        throw std::runtime_error("v2 egress fixture requires outputs");
    }

    std::vector<::shielded::v2::OutputDescription> outputs;
    outputs.reserve(output_count);
    for (size_t i = 0; i < output_count; ++i) {
        outputs.push_back(MakeV2EgressOutput(static_cast<unsigned char>(0x40 + i * 8)));
    }
    return BuildV2EgressReceiptFixture(std::move(outputs),
                                       {},
                                       std::nullopt,
                                       proof_receipt_count,
                                       required_receipts,
                                       consensus,
                                       validation_height);
}

inline V2EgressReceiptFixture BuildV2EgressHybridReceiptFixture(size_t output_count = 2,
                                                                size_t proof_receipt_count = 1,
                                                                size_t required_receipts = 1,
                                                                const Consensus::Params* consensus = nullptr,
                                                                int32_t validation_height = std::numeric_limits<int32_t>::max())
{
    const Consensus::Params* effective_consensus = consensus != nullptr ? consensus : &Params().GetConsensus();
    if (output_count == 0) {
        throw std::runtime_error("v2 egress hybrid fixture requires outputs");
    }
    if (proof_receipt_count == 0 || required_receipts == 0 || proof_receipt_count < required_receipts) {
        throw std::runtime_error("v2 egress hybrid fixture requires satisfiable proof receipt threshold");
    }

    std::vector<::shielded::v2::OutputDescription> outputs;
    outputs.reserve(output_count);
    for (size_t i = 0; i < output_count; ++i) {
        outputs.push_back(MakeV2EgressOutput(static_cast<unsigned char>(0x70 + i * 8)));
    }

    V2EgressReceiptFixture fixture;

    fixture.descriptor = MakeV2EgressDescriptor(0xa1);
    const std::vector<::shielded::BridgeProofDescriptor> descriptors{fixture.descriptor};

    fixture.attestors = MakeV2EgressAttestors(0xb0, 3);
    const auto verifier_set =
        ::shielded::BuildBridgeVerifierSetCommitment(
            Span<const ::shielded::BridgeKeySpec>{fixture.attestors.data(), fixture.attestors.size()},
            /*required_signers=*/2);
    if (!verifier_set.has_value()) {
        throw std::runtime_error("failed to build v2 egress hybrid verifier set");
    }

    const auto proof_policy =
        ::shielded::BuildBridgeProofPolicyCommitment(descriptors, required_receipts);
    if (!proof_policy.has_value()) {
        throw std::runtime_error("failed to build v2 egress hybrid proof policy");
    }

    fixture.statement.version = 4;
    fixture.statement.direction = ::shielded::BridgeDirection::BRIDGE_OUT;
    fixture.statement.ids.bridge_id = uint256{0xa2};
    fixture.statement.ids.operation_id = uint256{0xa3};
    fixture.statement.entry_count = static_cast<uint32_t>(outputs.size());
    fixture.statement.total_amount = static_cast<CAmount>(outputs.size()) * COIN;
    fixture.statement.domain_id = uint256{0xa4};
    fixture.statement.source_epoch = 13;
    fixture.statement.data_root = uint256{0xa5};
    fixture.statement.verifier_set = *verifier_set;
    fixture.statement.proof_policy = *proof_policy;
    CanonicalizeV2EgressOutputs(outputs, fixture.statement);
    if (!fixture.statement.IsValid()) {
        throw std::runtime_error("invalid v2 egress hybrid batch statement fixture");
    }

    std::vector<::shielded::BridgeProofReceipt> proof_receipts;
    proof_receipts.reserve(proof_receipt_count);
    for (size_t i = 0; i < proof_receipt_count; ++i) {
        proof_receipts.push_back(
            MakeV2ProofReceipt(fixture.statement,
                               fixture.descriptor,
                               static_cast<unsigned char>(0xa6 + (i * 4))));
    }
    fixture.receipt = proof_receipts.front();

    fixture.signed_receipts = {
        MakeV2SignedBatchReceipt(0xb0, fixture.statement),
        MakeV2SignedBatchReceipt(0xb1, fixture.statement),
    };
    auto proof_a = ::shielded::BuildBridgeVerifierSetProof(
        Span<const ::shielded::BridgeKeySpec>{fixture.attestors.data(), fixture.attestors.size()},
        fixture.attestors[0]);
    auto proof_b = ::shielded::BuildBridgeVerifierSetProof(
        Span<const ::shielded::BridgeKeySpec>{fixture.attestors.data(), fixture.attestors.size()},
        fixture.attestors[1]);
    if (!proof_a.has_value() || !proof_b.has_value()) {
        throw std::runtime_error("failed to build v2 egress hybrid verifier proofs");
    }
    fixture.signed_receipt_proofs = {*proof_a, *proof_b};
    fixture.verification_bundle = ::shielded::BuildBridgeVerificationBundle(
        Span<const ::shielded::BridgeBatchReceipt>{fixture.signed_receipts.data(), fixture.signed_receipts.size()},
        Span<const ::shielded::BridgeProofReceipt>{proof_receipts.data(), proof_receipts.size()});
    if (!fixture.verification_bundle.has_value()) {
        throw std::runtime_error("failed to build v2 egress hybrid verification bundle");
    }

    ::shielded::v2::V2EgressBuildInput input;
    input.statement = fixture.statement;
    input.proof_descriptors = descriptors;
    input.imported_descriptor = fixture.descriptor;
    input.signed_receipts = fixture.signed_receipts;
    input.signed_receipt_proofs = fixture.signed_receipt_proofs;
    input.proof_receipts = proof_receipts;
    input.imported_receipt = fixture.receipt;
    input.outputs = std::move(outputs);

    std::string reject_reason;
    auto built = ::shielded::v2::BuildV2EgressBatchTransaction(CMutableTransaction{},
                                                               input,
                                                               reject_reason,
                                                               effective_consensus,
                                                               validation_height);
    if (!built.has_value()) {
        throw std::runtime_error(reject_reason.empty() ? "failed to build v2 hybrid egress transaction bundle fixture"
                                                       : reject_reason);
    }

    fixture.tx = built->tx;
    fixture.witness = built->witness;
    return fixture;
}

inline V2SettlementAnchorReceiptFixture BuildV2SettlementAnchorReceiptFixture(
    const V2EgressReceiptFixture& egress_fixture);

inline V2SettlementAnchorReceiptFixture BuildV2SettlementAnchorReceiptFixture(size_t output_count = 2,
                                                                              size_t proof_receipt_count = 1,
                                                                              size_t required_receipts = 1,
                                                                              const Consensus::Params* consensus = nullptr,
                                                                              int32_t validation_height = std::numeric_limits<int32_t>::max())
{
    const auto egress_fixture =
        BuildV2EgressReceiptFixture(output_count,
                                    proof_receipt_count,
                                    required_receipts,
                                    consensus,
                                    validation_height);

    auto fixture = BuildV2SettlementAnchorReceiptFixture(egress_fixture);
    auto* bundle = fixture.tx.shielded_bundle.v2_bundle ? &*fixture.tx.shielded_bundle.v2_bundle : nullptr;
    if (bundle != nullptr) {
        bundle->header.family_id = ResolveFixtureWireFamily(::shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR,
                                                            consensus,
                                                            validation_height);
        ApplyFixtureWireEnvelopeKinds(::shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR,
                                      bundle->header.proof_envelope,
                                      consensus,
                                      validation_height);
        if (!bundle->IsValid()) {
            throw std::runtime_error("invalid v2 settlement-anchor receipt fixture wire family: " +
                                     DescribeInvalidBundleForFixture(*bundle));
        }
    }
    return fixture;
}

inline V2SettlementAnchorReceiptFixture BuildV2SettlementAnchorReceiptFixture(
    const V2EgressReceiptFixture& egress_fixture)
{

    V2SettlementAnchorReceiptFixture fixture;
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
    const auto* witness_begin =
        reinterpret_cast<const unsigned char*>(witness_stream.data());
    std::vector<uint8_t> proof_payload(witness_begin, witness_begin + witness_stream.size());

    const auto abstract_context =
        ::shielded::v2::proof::DescribeImportedSettlementReceipt(fixture.receipt,
                                                                 ::shielded::v2::proof::PayloadLocation::INLINE_WITNESS,
                                                                 proof_payload,
                                                                 fixture.descriptor);

    auto settlement_anchor =
        ::shielded::BuildBridgeExternalAnchorFromProofReceipts(fixture.statement,
                                                               fixture.witness.proof_receipts);
    if (!settlement_anchor.has_value()) {
        throw std::runtime_error("failed to build v2 settlement-anchor fixture");
    }
    fixture.settlement_anchor_digest =
        ::shielded::v2::proof::ComputeSettlementExternalAnchorDigest(*settlement_anchor);

    ::shielded::v2::SettlementAnchorPayload payload;
    payload.proof_receipt_ids = CollectCanonicalProofReceiptIds(
        Span<const ::shielded::BridgeProofReceipt>{fixture.witness.proof_receipts.data(),
                                                   fixture.witness.proof_receipts.size()});
    payload.batch_statement_digests = {::shielded::ComputeBridgeBatchStatementHash(fixture.statement)};

    const auto* egress_bundle = egress_fixture.tx.shielded_bundle.GetV2Bundle();
    ::shielded::v2::TransactionBundle bundle;
    bundle.header.family_id =
        (egress_bundle != nullptr && ::shielded::v2::IsGenericTransactionFamily(egress_bundle->header.family_id))
        ? ::shielded::v2::TransactionFamily::V2_GENERIC
        : ::shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR;
    bundle.header.proof_envelope = abstract_context.material.statement.envelope;
    bundle.payload = payload;

    auto proof_shard = abstract_context.material.proof_shards.front();
    proof_shard.settlement_domain = fixture.statement.domain_id;
    bundle.proof_shards = {proof_shard};
    bundle.proof_payload = proof_payload;

    bundle.header.payload_digest = ::shielded::v2::ComputeSettlementAnchorPayloadDigest(payload);
    bundle.header.proof_shard_root =
        ::shielded::v2::ComputeProofShardRoot(
            Span<const ::shielded::v2::ProofShardDescriptor>{bundle.proof_shards.data(), bundle.proof_shards.size()});
    bundle.header.proof_shard_count = bundle.proof_shards.size();

    if (!bundle.IsValid()) {
        throw std::runtime_error("invalid v2 settlement-anchor transaction bundle fixture");
    }

    fixture.tx.shielded_bundle.v2_bundle = bundle;
    return fixture;
}

inline V2SettlementAnchorReceiptFixture BuildV2SettlementAnchorHybridReceiptFixture(
    const V2EgressReceiptFixture& egress_fixture)
{
    V2SettlementAnchorReceiptFixture fixture;
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
    const auto* witness_begin =
        reinterpret_cast<const unsigned char*>(witness_stream.data());
    std::vector<uint8_t> proof_payload(witness_begin, witness_begin + witness_stream.size());

    const auto abstract_context =
        ::shielded::v2::proof::DescribeImportedSettlementReceipt(fixture.receipt,
                                                                 ::shielded::v2::proof::PayloadLocation::INLINE_WITNESS,
                                                                 proof_payload,
                                                                 fixture.descriptor,
                                                                 fixture.verification_bundle);

    auto settlement_anchor = ::shielded::BuildBridgeExternalAnchorFromHybridWitness(
        fixture.statement,
        Span<const ::shielded::BridgeBatchReceipt>{fixture.signed_receipts.data(), fixture.signed_receipts.size()},
        Span<const ::shielded::BridgeProofReceipt>{fixture.witness.proof_receipts.data(),
                                                   fixture.witness.proof_receipts.size()});
    if (!settlement_anchor.has_value()) {
        throw std::runtime_error("failed to build v2 hybrid settlement-anchor fixture");
    }
    fixture.settlement_anchor_digest =
        ::shielded::v2::proof::ComputeSettlementExternalAnchorDigest(*settlement_anchor);

    ::shielded::v2::SettlementAnchorPayload payload;
    payload.proof_receipt_ids = CollectCanonicalProofReceiptIds(
        Span<const ::shielded::BridgeProofReceipt>{fixture.witness.proof_receipts.data(),
                                                   fixture.witness.proof_receipts.size()});
    payload.batch_statement_digests = {::shielded::ComputeBridgeBatchStatementHash(fixture.statement)};

    const auto* egress_bundle = egress_fixture.tx.shielded_bundle.GetV2Bundle();
    ::shielded::v2::TransactionBundle bundle;
    bundle.header.family_id =
        (egress_bundle != nullptr && ::shielded::v2::IsGenericTransactionFamily(egress_bundle->header.family_id))
        ? ::shielded::v2::TransactionFamily::V2_GENERIC
        : ::shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR;
    bundle.header.proof_envelope = abstract_context.material.statement.envelope;
    bundle.payload = payload;

    auto proof_shard = abstract_context.material.proof_shards.front();
    proof_shard.settlement_domain = fixture.statement.domain_id;
    bundle.proof_shards = {proof_shard};
    bundle.proof_payload = proof_payload;

    bundle.header.payload_digest = ::shielded::v2::ComputeSettlementAnchorPayloadDigest(payload);
    bundle.header.proof_shard_root =
        ::shielded::v2::ComputeProofShardRoot(
            Span<const ::shielded::v2::ProofShardDescriptor>{bundle.proof_shards.data(), bundle.proof_shards.size()});
    bundle.header.proof_shard_count = bundle.proof_shards.size();

    if (!bundle.IsValid()) {
        throw std::runtime_error("invalid v2 hybrid settlement-anchor transaction bundle fixture");
    }

    fixture.tx.shielded_bundle.v2_bundle = bundle;
    return fixture;
}

inline V2SettlementAnchorReceiptFixture BuildV2SettlementAnchorHybridReceiptFixture(size_t output_count = 2,
                                                                                    size_t proof_receipt_count = 1,
                                                                                    size_t required_receipts = 1,
                                                                                    const Consensus::Params* consensus = nullptr,
                                                                                    int32_t validation_height = std::numeric_limits<int32_t>::max())
{
    const auto egress_fixture = BuildV2EgressHybridReceiptFixture(output_count,
                                                                  proof_receipt_count,
                                                                  required_receipts,
                                                                  consensus,
                                                                  validation_height);
    auto fixture = BuildV2SettlementAnchorHybridReceiptFixture(egress_fixture);
    auto* bundle = fixture.tx.shielded_bundle.v2_bundle ? &*fixture.tx.shielded_bundle.v2_bundle : nullptr;
    if (bundle != nullptr) {
        bundle->header.family_id = ResolveFixtureWireFamily(::shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR,
                                                            consensus,
                                                            validation_height);
        ApplyFixtureWireEnvelopeKinds(::shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR,
                                      bundle->header.proof_envelope,
                                      consensus,
                                      validation_height);
        if (!bundle->IsValid()) {
            throw std::runtime_error("invalid v2 hybrid settlement-anchor fixture wire family");
        }
    }
    return fixture;
}

inline V2SettlementAnchorReceiptFixture BuildV2SettlementAnchorAdapterReceiptFixture(
    size_t output_count = 2,
    const Consensus::Params* consensus = nullptr,
    int32_t validation_height = std::numeric_limits<int32_t>::max())
{
    if (output_count == 0) {
        throw std::runtime_error("v2 settlement-anchor adapter receipt fixture requires outputs");
    }

    std::vector<::shielded::v2::OutputDescription> outputs;
    outputs.reserve(output_count);
    for (size_t i = 0; i < output_count; ++i) {
        outputs.push_back(MakeV2EgressOutput(static_cast<unsigned char>(0xd0 + i * 8)));
    }

    V2SettlementAnchorReceiptFixture fixture;
    fixture.imported_adapters = {
        MakeV2ProofAdapter(0xe0, ::shielded::BridgeProofClaimKind::SETTLEMENT_METADATA),
    };

    const auto descriptor =
        ::shielded::BuildBridgeProofDescriptorFromAdapter(fixture.imported_adapters.front(), uint256{0xe1});
    if (!descriptor.has_value()) {
        throw std::runtime_error("failed to build v2 settlement-anchor adapter descriptor fixture");
    }
    fixture.descriptor = *descriptor;
    const std::vector<::shielded::BridgeProofDescriptor> descriptors{fixture.descriptor};

    const auto proof_policy =
        ::shielded::BuildBridgeProofPolicyCommitment(descriptors, /*required_receipts=*/1);
    if (!proof_policy.has_value()) {
        throw std::runtime_error("failed to build v2 settlement-anchor adapter proof policy");
    }

    fixture.statement.version = 3;
    fixture.statement.direction = ::shielded::BridgeDirection::BRIDGE_OUT;
    fixture.statement.ids.bridge_id = uint256{0xe2};
    fixture.statement.ids.operation_id = uint256{0xe3};
    fixture.statement.entry_count = static_cast<uint32_t>(outputs.size());
    fixture.statement.total_amount = static_cast<CAmount>(outputs.size()) * COIN;
    fixture.statement.domain_id = uint256{0xe4};
    fixture.statement.source_epoch = 14;
    fixture.statement.data_root = uint256{0xe5};
    fixture.statement.proof_policy = *proof_policy;
    CanonicalizeV2EgressOutputs(outputs, fixture.statement);
    if (!fixture.statement.IsValid()) {
        throw std::runtime_error("invalid v2 settlement-anchor adapter statement fixture");
    }

    const auto receipt = ::shielded::BuildBridgeProofReceiptFromAdapter(fixture.statement,
                                                                        fixture.imported_adapters.front(),
                                                                        fixture.descriptor.verifier_key_hash,
                                                                        uint256{0xe6});
    if (!receipt.has_value()) {
        throw std::runtime_error("failed to build v2 settlement-anchor adapter receipt fixture");
    }
    fixture.receipt = *receipt;

    fixture.witness.statement = fixture.statement;
    fixture.witness.proof_receipts = {fixture.receipt};
    fixture.witness.imported_adapters = fixture.imported_adapters;
    fixture.witness.descriptor_proof =
        ::shielded::BuildBridgeProofPolicyProof(descriptors, fixture.descriptor);
    if (!fixture.witness.descriptor_proof.has_value() || !fixture.witness.IsValid()) {
        throw std::runtime_error("invalid v2 settlement-anchor adapter witness fixture");
    }

    DataStream witness_stream;
    witness_stream << fixture.witness;
    const auto* witness_begin =
        reinterpret_cast<const unsigned char*>(witness_stream.data());
    std::vector<uint8_t> proof_payload(witness_begin, witness_begin + witness_stream.size());

    const auto abstract_context =
        ::shielded::v2::proof::DescribeImportedSettlementReceipt(fixture.receipt,
                                                                 ::shielded::v2::proof::PayloadLocation::INLINE_WITNESS,
                                                                 proof_payload,
                                                                 fixture.descriptor);

    const auto settlement_anchor =
        ::shielded::BuildBridgeExternalAnchorFromProofReceipts(
            fixture.statement,
            Span<const ::shielded::BridgeProofReceipt>{fixture.witness.proof_receipts.data(),
                                                       fixture.witness.proof_receipts.size()});
    if (!settlement_anchor.has_value()) {
        throw std::runtime_error("failed to build v2 settlement-anchor adapter anchor fixture");
    }
    fixture.settlement_anchor_digest =
        ::shielded::v2::proof::ComputeSettlementExternalAnchorDigest(*settlement_anchor);

    std::vector<uint256> adapter_ids;
    adapter_ids.reserve(fixture.imported_adapters.size());
    for (const auto& adapter : fixture.imported_adapters) {
        adapter_ids.push_back(::shielded::ComputeBridgeProofAdapterId(adapter));
    }
    std::sort(adapter_ids.begin(), adapter_ids.end());

    ::shielded::v2::SettlementAnchorPayload payload;
    payload.proof_receipt_ids = CollectCanonicalProofReceiptIds(
        Span<const ::shielded::BridgeProofReceipt>{fixture.witness.proof_receipts.data(),
                                                   fixture.witness.proof_receipts.size()});
    payload.imported_adapter_ids = std::move(adapter_ids);
    payload.batch_statement_digests = {::shielded::ComputeBridgeBatchStatementHash(fixture.statement)};

    ::shielded::v2::TransactionBundle bundle;
    bundle.header.family_id = ResolveFixtureWireFamily(::shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR,
                                                       consensus,
                                                       validation_height);
    bundle.header.proof_envelope = abstract_context.material.statement.envelope;
    ApplyFixtureWireEnvelopeKinds(::shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR,
                                  bundle.header.proof_envelope,
                                  consensus,
                                  validation_height);
    bundle.payload = payload;

    auto proof_shard = abstract_context.material.proof_shards.front();
    proof_shard.settlement_domain = fixture.statement.domain_id;
    bundle.proof_shards = {proof_shard};
    bundle.proof_payload = proof_payload;

    bundle.header.payload_digest = ::shielded::v2::ComputeSettlementAnchorPayloadDigest(payload);
    bundle.header.proof_shard_root =
        ::shielded::v2::ComputeProofShardRoot(
            Span<const ::shielded::v2::ProofShardDescriptor>{bundle.proof_shards.data(), bundle.proof_shards.size()});
    bundle.header.proof_shard_count = bundle.proof_shards.size();

    if (!bundle.IsValid()) {
        throw std::runtime_error("invalid v2 settlement-anchor adapter receipt bundle fixture");
    }

    fixture.tx.shielded_bundle.v2_bundle = bundle;
    return fixture;
}

inline V2SettlementAnchorClaimFixture BuildV2SettlementAnchorClaimFixture(
    size_t output_count = 2,
    const Consensus::Params* consensus = nullptr,
    int32_t validation_height = std::numeric_limits<int32_t>::max())
{
    const auto egress_fixture = BuildV2EgressReceiptFixture(output_count, consensus, validation_height);

    V2SettlementAnchorClaimFixture fixture;
    fixture.statement = egress_fixture.statement;
    const auto claim = ::shielded::BuildBridgeProofClaimFromStatement(
        fixture.statement,
        ::shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    if (!claim.has_value()) {
        throw std::runtime_error("failed to build v2 settlement-anchor claim fixture");
    }
    fixture.claim = *claim;
    fixture.witness.statement = fixture.statement;
    if (!fixture.witness.IsValid()) {
        throw std::runtime_error("invalid v2 settlement-anchor claim witness fixture");
    }

    DataStream witness_stream;
    witness_stream << fixture.witness;
    const auto* witness_begin =
        reinterpret_cast<const unsigned char*>(witness_stream.data());
    std::vector<uint8_t> proof_payload(witness_begin, witness_begin + witness_stream.size());

    const auto abstract_context =
        ::shielded::v2::proof::DescribeImportedSettlementClaim(
            fixture.claim,
            ::shielded::v2::proof::PayloadLocation::INLINE_WITNESS,
            proof_payload);

    const auto settlement_anchor =
        ::shielded::BuildBridgeExternalAnchorFromClaim(fixture.statement, fixture.claim);
    if (!settlement_anchor.has_value()) {
        throw std::runtime_error("failed to build v2 settlement-anchor claim anchor fixture");
    }
    fixture.settlement_anchor_digest =
        ::shielded::v2::proof::ComputeSettlementExternalAnchorDigest(*settlement_anchor);

    ::shielded::v2::SettlementAnchorPayload payload;
    payload.imported_claim_ids = {::shielded::ComputeBridgeProofClaimHash(fixture.claim)};
    payload.batch_statement_digests = {::shielded::ComputeBridgeBatchStatementHash(fixture.statement)};

    ::shielded::v2::TransactionBundle bundle;
    bundle.header.family_id = ResolveFixtureWireFamily(::shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR,
                                                       consensus,
                                                       validation_height);
    bundle.header.proof_envelope = abstract_context.material.statement.envelope;
    ApplyFixtureWireEnvelopeKinds(::shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR,
                                  bundle.header.proof_envelope,
                                  consensus,
                                  validation_height);
    bundle.payload = payload;
    bundle.proof_shards = abstract_context.material.proof_shards;
    bundle.proof_payload = proof_payload;
    bundle.header.payload_digest = ::shielded::v2::ComputeSettlementAnchorPayloadDigest(payload);
    bundle.header.proof_shard_root =
        ::shielded::v2::ComputeProofShardRoot(
            Span<const ::shielded::v2::ProofShardDescriptor>{bundle.proof_shards.data(), bundle.proof_shards.size()});
    bundle.header.proof_shard_count = bundle.proof_shards.size();

    if (!bundle.IsValid()) {
        throw std::runtime_error("invalid v2 settlement-anchor claim transaction bundle fixture");
    }

    fixture.tx.shielded_bundle.v2_bundle = bundle;
    return fixture;
}

inline V2SettlementAnchorClaimFixture BuildV2SettlementAnchorAdapterClaimFixture(
    size_t output_count = 2,
    const Consensus::Params* consensus = nullptr,
    int32_t validation_height = std::numeric_limits<int32_t>::max())
{
    auto fixture = BuildV2SettlementAnchorClaimFixture(output_count, consensus, validation_height);
    fixture.imported_adapters = {
        MakeV2ProofAdapter(0xc0, ::shielded::BridgeProofClaimKind::SETTLEMENT_METADATA),
        MakeV2ProofAdapter(0xc4, ::shielded::BridgeProofClaimKind::SETTLEMENT_METADATA),
    };
    fixture.witness.imported_adapters = fixture.imported_adapters;
    if (!fixture.witness.IsValid()) {
        throw std::runtime_error("invalid v2 settlement-anchor adapter witness fixture");
    }

    DataStream witness_stream;
    witness_stream << fixture.witness;
    const auto* witness_begin =
        reinterpret_cast<const unsigned char*>(witness_stream.data());
    std::vector<uint8_t> proof_payload(witness_begin, witness_begin + witness_stream.size());

    const auto abstract_context =
        ::shielded::v2::proof::DescribeImportedSettlementClaim(
            fixture.claim,
            ::shielded::v2::proof::PayloadLocation::INLINE_WITNESS,
            proof_payload);

    std::vector<uint256> adapter_ids;
    adapter_ids.reserve(fixture.imported_adapters.size());
    for (const auto& adapter : fixture.imported_adapters) {
        adapter_ids.push_back(::shielded::ComputeBridgeProofAdapterId(adapter));
    }
    std::sort(adapter_ids.begin(), adapter_ids.end());

    auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;
    auto& payload = std::get<::shielded::v2::SettlementAnchorPayload>(bundle.payload);
    payload.imported_adapter_ids = std::move(adapter_ids);
    bundle.proof_payload = proof_payload;
    bundle.header.proof_envelope = abstract_context.material.statement.envelope;
    ApplyFixtureWireEnvelopeKinds(::shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR,
                                  bundle.header.proof_envelope,
                                  consensus,
                                  validation_height);
    bundle.proof_shards = abstract_context.material.proof_shards;
    bundle.header.payload_digest = ::shielded::v2::ComputeSettlementAnchorPayloadDigest(payload);
    bundle.header.proof_shard_root =
        ::shielded::v2::ComputeProofShardRoot(
            Span<const ::shielded::v2::ProofShardDescriptor>{bundle.proof_shards.data(), bundle.proof_shards.size()});
    bundle.header.proof_shard_count = bundle.proof_shards.size();
    if (!bundle.IsValid()) {
        throw std::runtime_error("invalid v2 settlement-anchor adapter transaction bundle fixture");
    }
    return fixture;
}

} // namespace test::shielded

#endif // BTX_TEST_UTIL_SHIELDED_V2_EGRESS_FIXTURE_H
