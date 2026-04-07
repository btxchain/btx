// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_v2_egress_runtime_report.h>

#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <chainparams.h>
#include <crypto/ml_kem.h>
#include <hash.h>
#include <kernel/mempool_options.h>
#include <policy/policy.h>
#include <shielded/note_encryption.h>
#include <shielded/validation.h>
#include <shielded/v2_egress.h>
#include <shielded/v2_send.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace btx::test::shieldedv2egress {
namespace {

using shielded::BridgeBatchStatement;
using shielded::BridgeProofDescriptor;
using shielded::BridgeProofPolicyCommitment;
using shielded::BridgeProofReceipt;
using shielded::v2::EgressBatchPayload;
using shielded::v2::OutputDescription;
using shielded::v2::V2EgressBuildInput;
using shielded::v2::V2EgressBuildResult;
using shielded::v2::V2EgressRecipient;
using shielded::v2::V2EgressStatementTemplate;

struct ScenarioFixture
{
    RuntimeScenarioConfig config;
    mlkem::KeyPair owned_recipient;
    BridgeProofDescriptor imported_descriptor;
    std::vector<BridgeProofDescriptor> proof_descriptors;
    V2EgressStatementTemplate statement_template;
    std::vector<V2EgressRecipient> recipients;
    std::vector<uint32_t> output_chunk_sizes;
    std::vector<uint32_t> expected_chunk_owned_counts;
    std::vector<CAmount> expected_chunk_owned_amounts;
    CMutableTransaction tx_template;
    size_t owned_output_count{0};
    size_t owned_chunk_count{0};
    CAmount owned_amount{0};
};

struct BuildArtifacts
{
    BridgeBatchStatement statement;
    std::vector<OutputDescription> outputs;
    BridgeProofReceipt imported_receipt;
    V2EgressBuildResult build_result;
};

struct OutputView
{
    uint256 commitment;
    CAmount amount{0};
    bool is_ours{false};
};

struct DiscoveryResult
{
    std::vector<OutputView> outputs;
    size_t hint_match_count{0};
    size_t decrypt_attempt_count{0};
    size_t successful_decrypt_count{0};
    size_t false_positive_hint_count{0};
    CAmount owned_amount{0};
};

struct OutputChunkView
{
    uint32_t owned_output_count{0};
    CAmount owned_amount{0};
};

struct SampleMeasurement
{
    uint64_t build_statement_ns{0};
    uint64_t derive_outputs_ns{0};
    uint64_t build_bundle_ns{0};
    uint64_t proof_check_ns{0};
    uint64_t output_discovery_ns{0};
    uint64_t chunk_summary_ns{0};
    uint64_t full_pipeline_ns{0};
    uint64_t hint_match_count{0};
    uint64_t decrypt_attempt_count{0};
    uint64_t successful_decrypt_count{0};
    uint64_t false_positive_hint_count{0};
    uint64_t skipped_decrypt_attempt_count{0};
    uint64_t owned_output_count{0};
    uint64_t owned_chunk_count{0};
    int64_t owned_amount{0};
};

struct ScenarioMetrics
{
    uint64_t serialized_size_bytes{0};
    uint64_t tx_weight{0};
    int64_t shielded_policy_weight{0};
    uint64_t proof_payload_bytes{0};
    uint64_t output_chunk_count{0};
    uint64_t total_ciphertext_bytes{0};
    ShieldedResourceUsage usage{};
    bool is_standard_tx{false};
    std::string standard_reason;
    bool within_standard_tx_weight{false};
    int64_t standard_tx_weight_headroom{0};
    uint64_t max_transactions_by_standard_tx_weight{0};
    bool within_standard_shielded_policy_weight{false};
    int64_t standard_shielded_policy_weight_headroom{0};
    uint64_t max_transactions_by_standard_shielded_policy_weight{0};
    uint64_t max_transactions_by_serialized_size{0};
    uint64_t max_transactions_by_weight{0};
    uint64_t max_transactions_by_verify{0};
    uint64_t max_transactions_by_scan{0};
    uint64_t max_transactions_by_tree_updates{0};
    uint64_t max_transactions_per_block{0};
    uint64_t max_output_notes_per_block{0};
    uint64_t max_output_chunks_per_block{0};
    uint64_t max_ciphertext_bytes_per_block{0};
    std::string block_binding_limit;
};

template <size_t N>
std::array<uint8_t, N> DeriveSeed(std::string_view tag, uint32_t scenario_id, uint32_t index)
{
    std::array<uint8_t, N> seed{};
    size_t offset{0};
    uint32_t counter{0};
    while (offset < seed.size()) {
        HashWriter hw;
        hw << std::string{tag} << scenario_id << index << counter;
        const uint256 digest = hw.GetSHA256();
        const size_t copy_len = std::min(seed.size() - offset, static_cast<size_t>(uint256::size()));
        std::copy_n(digest.begin(), copy_len, seed.begin() + offset);
        offset += copy_len;
        ++counter;
    }
    return seed;
}

uint256 DeterministicUint256(std::string_view tag, uint32_t scenario_id, uint32_t index)
{
    HashWriter hw;
    hw << std::string{tag} << scenario_id << index;
    return hw.GetSHA256();
}

uint32_t ScenarioId(const RuntimeScenarioConfig& config)
{
    return (static_cast<uint32_t>(config.output_count) << 16) ^
           static_cast<uint32_t>(config.outputs_per_chunk);
}

mlkem::KeyPair BuildKeyPair(std::string_view tag, uint32_t scenario_id, uint32_t index)
{
    return mlkem::KeyGenDerand(DeriveSeed<mlkem::KEYGEN_SEEDBYTES>(tag, scenario_id, index));
}

BridgeProofDescriptor BuildImportedDescriptor(uint32_t scenario_id)
{
    const uint256 verifier_key_hash =
        DeterministicUint256("BTX_ShieldedV2_EgressRuntime_VerifierKey", scenario_id, 0);
    const auto adapter = shielded::BuildCanonicalBridgeProofAdapter(
        shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    if (!adapter.has_value()) {
        throw std::runtime_error("failed to build canonical egress runtime adapter");
    }
    const auto descriptor = shielded::BuildBridgeProofDescriptorFromAdapter(*adapter, verifier_key_hash);
    if (!descriptor.has_value() || !descriptor->IsValid()) {
        throw std::runtime_error("constructed invalid egress runtime descriptor");
    }
    return *descriptor;
}

BridgeProofPolicyCommitment BuildProofPolicy(const BridgeProofDescriptor& descriptor)
{
    const std::vector<BridgeProofDescriptor> descriptors{descriptor};
    auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(
        Span<const BridgeProofDescriptor>{descriptors.data(), descriptors.size()},
        /*required_receipts=*/1);
    if (!proof_policy.has_value()) {
        throw std::runtime_error("failed to build egress runtime proof policy");
    }
    return *proof_policy;
}

std::vector<uint32_t> BuildOutputChunkSizes(size_t output_count, size_t outputs_per_chunk)
{
    if (outputs_per_chunk == 0) {
        throw std::runtime_error("outputs_per_chunk must be non-zero");
    }

    std::vector<uint32_t> chunk_sizes;
    size_t remaining = output_count;
    while (remaining > 0) {
        const size_t chunk_size = std::min(outputs_per_chunk, remaining);
        chunk_sizes.push_back(static_cast<uint32_t>(chunk_size));
        remaining -= chunk_size;
    }
    if (chunk_sizes.size() > shielded::v2::MAX_OUTPUT_CHUNKS) {
        throw std::runtime_error("output chunk count exceeds MAX_OUTPUT_CHUNKS");
    }
    return chunk_sizes;
}

bool IsOwnedRecipientIndex(size_t index, size_t output_count)
{
    const size_t owned_stride = std::max<size_t>(64, output_count / 8);
    return (index % owned_stride) == 0;
}

BridgeProofReceipt BuildImportedReceipt(const BridgeBatchStatement& statement,
                                        const BridgeProofDescriptor& descriptor,
                                        uint32_t scenario_id)
{
    BridgeProofReceipt receipt;
    receipt.statement_hash = shielded::ComputeBridgeBatchStatementHash(statement);
    receipt.proof_system_id = descriptor.proof_system_id;
    receipt.verifier_key_hash = descriptor.verifier_key_hash;
    receipt.public_values_hash =
        DeterministicUint256("BTX_ShieldedV2_EgressRuntime_PublicValues", scenario_id, 0);
    receipt.proof_commitment =
        DeterministicUint256("BTX_ShieldedV2_EgressRuntime_ProofCommitment", scenario_id, 0);
    if (!receipt.IsValid()) {
        throw std::runtime_error("constructed invalid egress runtime receipt");
    }
    return receipt;
}

ScenarioFixture BuildScenarioFixture(const RuntimeScenarioConfig& config)
{
    if (config.output_count == 0 || config.output_count > shielded::v2::MAX_EGRESS_OUTPUTS) {
        throw std::runtime_error("output_count must be within MAX_EGRESS_OUTPUTS");
    }
    if (config.outputs_per_chunk == 0) {
        throw std::runtime_error("outputs_per_chunk must be non-zero");
    }

    const auto& consensus = Params().GetConsensus();
    const int32_t validation_height = consensus.nShieldedMatRiCTDisableHeight;
    const bool use_generic_wire = shielded::v2::UseGenericV2WireFamily(&consensus, validation_height);
    const uint32_t scenario_id = ScenarioId(config);
    ScenarioFixture fixture;
    fixture.config = config;
    fixture.owned_recipient = BuildKeyPair("BTX_ShieldedV2_EgressRuntime_OwnedRecipient", scenario_id, 0);
    fixture.imported_descriptor = BuildImportedDescriptor(scenario_id);
    fixture.proof_descriptors = {fixture.imported_descriptor};
    if (use_generic_wire) {
        fixture.expected_chunk_owned_counts.assign(1, 0);
        fixture.expected_chunk_owned_amounts.assign(1, 0);
    } else {
        fixture.output_chunk_sizes = BuildOutputChunkSizes(config.output_count, config.outputs_per_chunk);
        fixture.expected_chunk_owned_counts.assign(fixture.output_chunk_sizes.size(), 0);
        fixture.expected_chunk_owned_amounts.assign(fixture.output_chunk_sizes.size(), 0);
    }

    fixture.statement_template.ids.bridge_id =
        DeterministicUint256("BTX_ShieldedV2_EgressRuntime_BridgeId", scenario_id, 0);
    fixture.statement_template.ids.operation_id =
        DeterministicUint256("BTX_ShieldedV2_EgressRuntime_OperationId", scenario_id, 0);
    fixture.statement_template.domain_id =
        DeterministicUint256("BTX_ShieldedV2_EgressRuntime_DomainId", scenario_id, 0);
    fixture.statement_template.source_epoch = 17;
    fixture.statement_template.data_root =
        DeterministicUint256("BTX_ShieldedV2_EgressRuntime_DataRoot", scenario_id, 0);
    fixture.statement_template.proof_policy = BuildProofPolicy(fixture.imported_descriptor);

    fixture.recipients.reserve(config.output_count);
    for (size_t i = 0; i < config.output_count; ++i) {
        const bool owned = IsOwnedRecipientIndex(i, config.output_count);
        const mlkem::KeyPair recipient = owned
            ? fixture.owned_recipient
            : BuildKeyPair("BTX_ShieldedV2_EgressRuntime_ForeignRecipient",
                           scenario_id,
                           static_cast<uint32_t>(i));

        V2EgressRecipient egress_recipient;
        egress_recipient.recipient_pk_hash =
            DeterministicUint256("BTX_ShieldedV2_EgressRuntime_RecipientPkHash",
                                 scenario_id,
                                 static_cast<uint32_t>(i));
        egress_recipient.recipient_kem_pk = recipient.pk;
        egress_recipient.amount = 2 * COIN + static_cast<CAmount>(i) * 1000;
        if (!egress_recipient.IsValid()) {
            throw std::runtime_error("constructed invalid egress runtime recipient");
        }

        fixture.recipients.push_back(std::move(egress_recipient));
        if (owned) {
            const size_t chunk_index = use_generic_wire ? 0 : i / config.outputs_per_chunk;
            ++fixture.expected_chunk_owned_counts[chunk_index];
            fixture.expected_chunk_owned_amounts[chunk_index] += fixture.recipients.back().amount;
            ++fixture.owned_output_count;
            fixture.owned_amount += fixture.recipients.back().amount;
        }
    }
    fixture.owned_chunk_count = std::count_if(
        fixture.expected_chunk_owned_counts.begin(),
        fixture.expected_chunk_owned_counts.end(),
        [](uint32_t count) { return count > 0; });

    fixture.tx_template.version = CTransaction::CURRENT_VERSION;
    fixture.tx_template.nLockTime =
        31 + static_cast<uint32_t>(config.output_count + fixture.output_chunk_sizes.size());
    return fixture;
}

uint64_t MeasureNanoseconds(const std::function<void()>& fn)
{
    const auto start = std::chrono::steady_clock::now();
    fn();
    const auto end = std::chrono::steady_clock::now();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
}

uint64_t Average(const std::vector<uint64_t>& values)
{
    if (values.empty()) return 0;
    const uint64_t total = std::accumulate(values.begin(), values.end(), uint64_t{0});
    return total / values.size();
}

uint64_t Median(std::vector<uint64_t> values)
{
    if (values.empty()) return 0;
    std::sort(values.begin(), values.end());
    const size_t mid = values.size() / 2;
    if ((values.size() % 2) == 1) {
        return values[mid];
    }
    return (values[mid - 1] + values[mid]) / 2;
}

UniValue BuildSummary(const std::vector<uint64_t>& values)
{
    UniValue summary(UniValue::VOBJ);
    summary.pushKV("count", static_cast<uint64_t>(values.size()));
    summary.pushKV("min_ns", values.empty() ? 0 : *std::min_element(values.begin(), values.end()));
    summary.pushKV("median_ns", Median(values));
    summary.pushKV("average_ns", Average(values));
    summary.pushKV("max_ns", values.empty() ? 0 : *std::max_element(values.begin(), values.end()));
    return summary;
}

BuildArtifacts BuildTransaction(const ScenarioFixture& fixture, std::string& reject_reason)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t validation_height = consensus.nShieldedMatRiCTDisableHeight;
    const uint32_t scenario_id = ScenarioId(fixture.config);
    BuildArtifacts artifacts;

    auto statement = shielded::v2::BuildV2EgressStatement(
        fixture.statement_template,
        Span<const V2EgressRecipient>{fixture.recipients.data(), fixture.recipients.size()},
        reject_reason);
    if (!statement.has_value()) {
        throw std::runtime_error("egress runtime statement build failed: " + reject_reason);
    }
    artifacts.statement = std::move(*statement);

    auto outputs = shielded::v2::BuildDeterministicEgressOutputs(
        artifacts.statement,
        Span<const V2EgressRecipient>{fixture.recipients.data(), fixture.recipients.size()},
        reject_reason);
    if (!outputs.has_value()) {
        throw std::runtime_error("egress runtime output derivation failed: " + reject_reason);
    }
    artifacts.outputs = std::move(*outputs);
    artifacts.imported_receipt =
        BuildImportedReceipt(artifacts.statement, fixture.imported_descriptor, scenario_id);

    V2EgressBuildInput input;
    input.statement = artifacts.statement;
    input.proof_descriptors = fixture.proof_descriptors;
    input.imported_descriptor = fixture.imported_descriptor;
    input.proof_receipts = {artifacts.imported_receipt};
    input.imported_receipt = artifacts.imported_receipt;
    input.outputs = artifacts.outputs;
    input.output_chunk_sizes = fixture.output_chunk_sizes;

    auto built = shielded::v2::BuildV2EgressBatchTransaction(
        fixture.tx_template,
        input,
        reject_reason,
        &consensus,
        validation_height);
    if (!built.has_value()) {
        throw std::runtime_error("egress runtime bundle build failed: " + reject_reason);
    }
    artifacts.build_result = std::move(*built);
    return artifacts;
}

void VerifyBuiltTransaction(const CTransaction& tx)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t validation_height = consensus.nShieldedMatRiCTDisableHeight;
    CShieldedProofCheck proof_check{tx, consensus, validation_height, {}};
    const auto reject_reason = proof_check();
    if (reject_reason.has_value()) {
        throw std::runtime_error("egress proof check failed: " + *reject_reason);
    }
}

DiscoveryResult DiscoverOwnedOutputs(const CTransaction& tx, const mlkem::KeyPair& owned_recipient)
{
    const auto* bundle = tx.shielded_bundle.GetV2Bundle();
    if (bundle == nullptr || !std::holds_alternative<EgressBatchPayload>(bundle->payload)) {
        throw std::runtime_error("missing egress payload during discovery");
    }

    const auto& payload = std::get<EgressBatchPayload>(bundle->payload);
    DiscoveryResult result;
    result.outputs.reserve(payload.outputs.size());
    for (const auto& output : payload.outputs) {
        OutputView view;
        view.commitment = output.note_commitment;

        const auto decoded = shielded::v2::DecodeLegacyEncryptedNotePayload(output.encrypted_note);
        if (!decoded.has_value()) {
            throw std::runtime_error("failed to decode egress output during discovery");
        }
        if (shielded::v2::LegacyEncryptedNotePayloadMatchesRecipient(output.encrypted_note,
                                                                     *decoded,
                                                                     owned_recipient.pk)) {
            ++result.hint_match_count;
        }

        ++result.decrypt_attempt_count;
        auto note = shielded::NoteEncryption::TryDecrypt(
            *decoded,
            owned_recipient.pk,
            owned_recipient.sk,
            /*constant_time_scan=*/true);
        if (note.has_value()) {
            auto smile_account = smile2::wallet::BuildCompactPublicAccountFromNote(
                smile2::wallet::SMILE_GLOBAL_SEED,
                *note);
            if (!smile_account.has_value()) {
                throw std::runtime_error("egress discovery failed to derive smile account");
            }
            if (smile2::ComputeCompactPublicAccountHash(*smile_account) != output.note_commitment) {
                throw std::runtime_error("egress discovery produced unexpected note commitment");
            }
            view.amount = note->value;
            view.is_ours = true;
            ++result.successful_decrypt_count;
            result.owned_amount += note->value;
        }

        result.outputs.push_back(std::move(view));
    }
    result.false_positive_hint_count = result.hint_match_count;
    return result;
}

std::vector<OutputChunkView> BuildChunkViews(const CTransaction& tx, Span<const OutputView> output_views)
{
    const auto* bundle = tx.shielded_bundle.GetV2Bundle();
    if (bundle == nullptr) {
        throw std::runtime_error("missing v2 bundle during chunk summarization");
    }

    std::vector<OutputChunkView> chunk_views;
    chunk_views.reserve(bundle->output_chunks.size());
    for (const auto& chunk : bundle->output_chunks) {
        const size_t first = chunk.first_output_index;
        const size_t count = chunk.output_count;
        if (first > output_views.size() || count > output_views.size() - first) {
            throw std::runtime_error("egress chunk bounds exceeded output views");
        }

        OutputChunkView chunk_view;
        for (size_t i = first; i < first + count; ++i) {
            const auto& output = output_views[i];
            if (!output.is_ours) continue;
            ++chunk_view.owned_output_count;
            chunk_view.owned_amount += output.amount;
        }
        chunk_views.push_back(std::move(chunk_view));
    }
    return chunk_views;
}

SampleMeasurement RunMeasurement(const ScenarioFixture& fixture)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t validation_height = consensus.nShieldedMatRiCTDisableHeight;
    SampleMeasurement measurement;

    std::optional<BridgeBatchStatement> statement;
    std::string reject_reason;
    measurement.build_statement_ns = MeasureNanoseconds([&] {
        statement = shielded::v2::BuildV2EgressStatement(
            fixture.statement_template,
            Span<const V2EgressRecipient>{fixture.recipients.data(), fixture.recipients.size()},
            reject_reason);
        if (!statement.has_value()) {
            throw std::runtime_error("egress runtime statement build failed: " + reject_reason);
        }
    });

    std::optional<std::vector<OutputDescription>> outputs;
    measurement.derive_outputs_ns = MeasureNanoseconds([&] {
        outputs = shielded::v2::BuildDeterministicEgressOutputs(
            *statement,
            Span<const V2EgressRecipient>{fixture.recipients.data(), fixture.recipients.size()},
            reject_reason);
        if (!outputs.has_value()) {
            throw std::runtime_error("egress runtime output derivation failed: " + reject_reason);
        }
    });

    const BridgeProofReceipt imported_receipt =
        BuildImportedReceipt(*statement, fixture.imported_descriptor, ScenarioId(fixture.config));
    V2EgressBuildInput input;
    input.statement = *statement;
    input.proof_descriptors = fixture.proof_descriptors;
    input.imported_descriptor = fixture.imported_descriptor;
    input.proof_receipts = {imported_receipt};
    input.imported_receipt = imported_receipt;
    input.outputs = *outputs;
    input.output_chunk_sizes = fixture.output_chunk_sizes;

    std::optional<V2EgressBuildResult> build_result;
    measurement.build_bundle_ns = MeasureNanoseconds([&] {
        build_result = shielded::v2::BuildV2EgressBatchTransaction(
            fixture.tx_template,
            input,
            reject_reason,
            &consensus,
            validation_height);
        if (!build_result.has_value()) {
            throw std::runtime_error("egress runtime bundle build failed: " + reject_reason);
        }
    });

    const CTransaction tx{build_result->tx};
    measurement.proof_check_ns = MeasureNanoseconds([&] {
        VerifyBuiltTransaction(tx);
    });

    DiscoveryResult discovery;
    measurement.output_discovery_ns = MeasureNanoseconds([&] {
        discovery = DiscoverOwnedOutputs(tx, fixture.owned_recipient);
    });

    std::vector<OutputChunkView> chunk_views;
    measurement.chunk_summary_ns = MeasureNanoseconds([&] {
        chunk_views = BuildChunkViews(tx, {discovery.outputs.data(), discovery.outputs.size()});
    });

    if (discovery.successful_decrypt_count != fixture.owned_output_count) {
        throw std::runtime_error("egress discovery missed owned outputs");
    }
    if (discovery.owned_amount != fixture.owned_amount) {
        throw std::runtime_error("egress discovery drifted owned amount");
    }
    if (chunk_views.size() != fixture.expected_chunk_owned_counts.size()) {
        throw std::runtime_error("egress chunk summary count drifted");
    }

    uint64_t owned_chunk_count{0};
    for (size_t i = 0; i < chunk_views.size(); ++i) {
        if (chunk_views[i].owned_output_count != fixture.expected_chunk_owned_counts[i] ||
            chunk_views[i].owned_amount != fixture.expected_chunk_owned_amounts[i]) {
            throw std::runtime_error("egress chunk summary drifted");
        }
        if (chunk_views[i].owned_output_count > 0) {
            ++owned_chunk_count;
        }
    }

    measurement.full_pipeline_ns = measurement.build_statement_ns +
                                   measurement.derive_outputs_ns +
                                   measurement.build_bundle_ns +
                                   measurement.proof_check_ns +
                                   measurement.output_discovery_ns +
                                   measurement.chunk_summary_ns;
    measurement.hint_match_count = discovery.hint_match_count;
    measurement.decrypt_attempt_count = discovery.decrypt_attempt_count;
    measurement.successful_decrypt_count = discovery.successful_decrypt_count;
    measurement.false_positive_hint_count = discovery.false_positive_hint_count;
    measurement.skipped_decrypt_attempt_count = discovery.outputs.size() - discovery.decrypt_attempt_count;
    measurement.owned_output_count = discovery.successful_decrypt_count;
    measurement.owned_chunk_count = owned_chunk_count;
    measurement.owned_amount = discovery.owned_amount;
    return measurement;
}

ScenarioMetrics MeasureScenarioMetrics(const CTransaction& tx, const RuntimeScenarioConfig& config)
{
    const auto* bundle = tx.shielded_bundle.GetV2Bundle();
    if (bundle == nullptr) {
        throw std::runtime_error("missing egress bundle");
    }

    const auto& payload = std::get<EgressBatchPayload>(bundle->payload);

    ScenarioMetrics metrics;
    metrics.serialized_size_bytes = tx.GetTotalSize();
    metrics.tx_weight = GetTransactionWeight(tx);
    metrics.shielded_policy_weight = GetShieldedPolicyWeight(tx);
    metrics.proof_payload_bytes = bundle->proof_payload.size();
    metrics.output_chunk_count = bundle->output_chunks.size();
    metrics.total_ciphertext_bytes = 0;
    for (const auto& output : payload.outputs) {
        metrics.total_ciphertext_bytes += output.encrypted_note.ciphertext.size();
    }
    metrics.usage = GetShieldedResourceUsage(tx.GetShieldedBundle());

    kernel::MemPoolOptions opts;
    metrics.is_standard_tx = IsStandardTx(tx, opts, metrics.standard_reason);
    metrics.within_standard_tx_weight = metrics.tx_weight <= MAX_STANDARD_TX_WEIGHT;
    metrics.standard_tx_weight_headroom = metrics.within_standard_tx_weight
        ? static_cast<int64_t>(MAX_STANDARD_TX_WEIGHT) - static_cast<int64_t>(metrics.tx_weight)
        : 0;
    metrics.max_transactions_by_standard_tx_weight =
        metrics.tx_weight > 0 ? MAX_STANDARD_TX_WEIGHT / metrics.tx_weight : 0;
    metrics.within_standard_shielded_policy_weight =
        metrics.shielded_policy_weight <= MAX_STANDARD_SHIELDED_POLICY_WEIGHT;
    metrics.standard_shielded_policy_weight_headroom = metrics.within_standard_shielded_policy_weight
        ? static_cast<int64_t>(MAX_STANDARD_SHIELDED_POLICY_WEIGHT) - metrics.shielded_policy_weight
        : 0;
    metrics.max_transactions_by_standard_shielded_policy_weight =
        metrics.shielded_policy_weight > 0
            ? static_cast<uint64_t>(MAX_STANDARD_SHIELDED_POLICY_WEIGHT) /
                  static_cast<uint64_t>(metrics.shielded_policy_weight)
            : 0;

    metrics.max_transactions_by_serialized_size =
        metrics.serialized_size_bytes > 0 ? MAX_BLOCK_SERIALIZED_SIZE / metrics.serialized_size_bytes : 0;
    metrics.max_transactions_by_weight =
        metrics.tx_weight > 0 ? MAX_BLOCK_WEIGHT / metrics.tx_weight : 0;
    metrics.max_transactions_by_verify =
        metrics.usage.verify_units > 0
            ? ::Consensus::DEFAULT_MAX_BLOCK_SHIELDED_VERIFY_COST / metrics.usage.verify_units
            : 0;
    metrics.max_transactions_by_scan =
        metrics.usage.scan_units > 0
            ? ::Consensus::DEFAULT_MAX_BLOCK_SHIELDED_SCAN_UNITS / metrics.usage.scan_units
            : 0;
    metrics.max_transactions_by_tree_updates =
        metrics.usage.tree_update_units > 0
            ? ::Consensus::DEFAULT_MAX_BLOCK_SHIELDED_TREE_UPDATE_UNITS / metrics.usage.tree_update_units
            : 0;

    std::vector<std::pair<std::string, uint64_t>> limits{
        {"serialized_size", metrics.max_transactions_by_serialized_size},
        {"weight", metrics.max_transactions_by_weight},
    };
    if (metrics.usage.verify_units > 0) {
        limits.emplace_back("shielded_verify_units", metrics.max_transactions_by_verify);
    }
    if (metrics.usage.scan_units > 0) {
        limits.emplace_back("shielded_scan_units", metrics.max_transactions_by_scan);
    }
    if (metrics.usage.tree_update_units > 0) {
        limits.emplace_back("shielded_tree_update_units", metrics.max_transactions_by_tree_updates);
    }
    const auto best = std::min_element(limits.begin(),
                                       limits.end(),
                                       [](const auto& lhs, const auto& rhs) {
                                           return lhs.second < rhs.second;
                                       });
    metrics.block_binding_limit = best->first;
    metrics.max_transactions_per_block = best->second;
    metrics.max_output_notes_per_block = metrics.max_transactions_per_block * config.output_count;
    metrics.max_output_chunks_per_block = metrics.max_transactions_per_block * metrics.output_chunk_count;
    metrics.max_ciphertext_bytes_per_block = metrics.max_transactions_per_block * metrics.total_ciphertext_bytes;
    return metrics;
}

UniValue BuildRuntimeConfigJson(const RuntimeReportConfig& config)
{
    UniValue runtime_config(UniValue::VOBJ);
    runtime_config.pushKV("warmup_iterations", static_cast<uint64_t>(config.warmup_iterations));
    runtime_config.pushKV("measured_iterations", static_cast<uint64_t>(config.measured_iterations));
    runtime_config.pushKV("duration_unit", "nanoseconds");
    runtime_config.pushKV("clock", "steady_clock");

    UniValue requested(UniValue::VARR);
    for (const auto& scenario : config.scenarios) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("output_count", static_cast<uint64_t>(scenario.output_count));
        entry.pushKV("outputs_per_chunk", static_cast<uint64_t>(scenario.outputs_per_chunk));
        requested.push_back(std::move(entry));
    }
    runtime_config.pushKV("requested_scenarios", std::move(requested));
    return runtime_config;
}

UniValue BuildLimitsJson()
{
    UniValue limits(UniValue::VOBJ);
    limits.pushKV("max_egress_outputs", static_cast<uint64_t>(shielded::v2::MAX_EGRESS_OUTPUTS));
    limits.pushKV("max_output_chunks", static_cast<uint64_t>(shielded::v2::MAX_OUTPUT_CHUNKS));
    limits.pushKV("max_block_serialized_size", static_cast<uint64_t>(MAX_BLOCK_SERIALIZED_SIZE));
    limits.pushKV("max_block_weight", static_cast<uint64_t>(MAX_BLOCK_WEIGHT));
    limits.pushKV("max_block_shielded_verify_units",
                  static_cast<uint64_t>(::Consensus::DEFAULT_MAX_BLOCK_SHIELDED_VERIFY_COST));
    limits.pushKV("max_block_shielded_scan_units",
                  static_cast<uint64_t>(::Consensus::DEFAULT_MAX_BLOCK_SHIELDED_SCAN_UNITS));
    limits.pushKV("max_block_shielded_tree_update_units",
                  static_cast<uint64_t>(::Consensus::DEFAULT_MAX_BLOCK_SHIELDED_TREE_UPDATE_UNITS));
    limits.pushKV("max_standard_tx_weight", static_cast<uint64_t>(MAX_STANDARD_TX_WEIGHT));
    limits.pushKV("max_standard_shielded_policy_weight",
                  static_cast<uint64_t>(MAX_STANDARD_SHIELDED_POLICY_WEIGHT));
    return limits;
}

} // namespace

UniValue BuildRuntimeReport(const RuntimeReportConfig& config)
{
    if (config.measured_iterations == 0) {
        throw std::runtime_error("measured_iterations must be non-zero");
    }
    if (config.scenarios.empty()) {
        throw std::runtime_error("scenarios must be non-empty");
    }

    UniValue scenarios(UniValue::VARR);
    for (const auto& scenario_config : config.scenarios) {
        const ScenarioFixture fixture = BuildScenarioFixture(scenario_config);

        for (size_t i = 0; i < config.warmup_iterations; ++i) {
            const SampleMeasurement warmup = RunMeasurement(fixture);
            if (warmup.successful_decrypt_count != fixture.owned_output_count) {
                throw std::runtime_error("egress runtime warmup drifted");
            }
        }

        std::vector<uint64_t> build_statement_times_ns;
        std::vector<uint64_t> derive_output_times_ns;
        std::vector<uint64_t> build_bundle_times_ns;
        std::vector<uint64_t> proof_check_times_ns;
        std::vector<uint64_t> output_discovery_times_ns;
        std::vector<uint64_t> chunk_summary_times_ns;
        std::vector<uint64_t> full_pipeline_times_ns;
        build_statement_times_ns.reserve(config.measured_iterations);
        derive_output_times_ns.reserve(config.measured_iterations);
        build_bundle_times_ns.reserve(config.measured_iterations);
        proof_check_times_ns.reserve(config.measured_iterations);
        output_discovery_times_ns.reserve(config.measured_iterations);
        chunk_summary_times_ns.reserve(config.measured_iterations);
        full_pipeline_times_ns.reserve(config.measured_iterations);

        UniValue measurements(UniValue::VARR);
        std::optional<ScenarioMetrics> metrics;
        {
            std::string reject_reason;
            const BuildArtifacts metric_artifacts = BuildTransaction(fixture, reject_reason);
            const CTransaction tx{metric_artifacts.build_result.tx};
            metrics = MeasureScenarioMetrics(tx, scenario_config);
        }

        for (size_t i = 0; i < config.measured_iterations; ++i) {
            const SampleMeasurement measurement = RunMeasurement(fixture);
            build_statement_times_ns.push_back(measurement.build_statement_ns);
            derive_output_times_ns.push_back(measurement.derive_outputs_ns);
            build_bundle_times_ns.push_back(measurement.build_bundle_ns);
            proof_check_times_ns.push_back(measurement.proof_check_ns);
            output_discovery_times_ns.push_back(measurement.output_discovery_ns);
            chunk_summary_times_ns.push_back(measurement.chunk_summary_ns);
            full_pipeline_times_ns.push_back(measurement.full_pipeline_ns);

            UniValue measurement_json(UniValue::VOBJ);
            measurement_json.pushKV("sample_index", static_cast<uint64_t>(i));
            measurement_json.pushKV("build_statement_ns", measurement.build_statement_ns);
            measurement_json.pushKV("derive_outputs_ns", measurement.derive_outputs_ns);
            measurement_json.pushKV("build_bundle_ns", measurement.build_bundle_ns);
            measurement_json.pushKV("proof_check_ns", measurement.proof_check_ns);
            measurement_json.pushKV("output_discovery_ns", measurement.output_discovery_ns);
            measurement_json.pushKV("chunk_summary_ns", measurement.chunk_summary_ns);
            measurement_json.pushKV("full_pipeline_ns", measurement.full_pipeline_ns);
            measurement_json.pushKV("hint_match_count", measurement.hint_match_count);
            measurement_json.pushKV("decrypt_attempt_count", measurement.decrypt_attempt_count);
            measurement_json.pushKV("successful_decrypt_count", measurement.successful_decrypt_count);
            measurement_json.pushKV("false_positive_hint_count", measurement.false_positive_hint_count);
            measurement_json.pushKV("skipped_decrypt_attempt_count", measurement.skipped_decrypt_attempt_count);
            measurement_json.pushKV("owned_output_count", measurement.owned_output_count);
            measurement_json.pushKV("owned_chunk_count", measurement.owned_chunk_count);
            measurement_json.pushKV("owned_amount_sats", measurement.owned_amount);
            measurements.push_back(std::move(measurement_json));
        }

        if (!metrics.has_value()) {
            throw std::runtime_error("no egress measurements were recorded");
        }

        UniValue scenario(UniValue::VOBJ);
        scenario.pushKV("output_count", static_cast<uint64_t>(scenario_config.output_count));
        scenario.pushKV("outputs_per_chunk", static_cast<uint64_t>(scenario_config.outputs_per_chunk));
        scenario.pushKV("output_chunk_count", metrics->output_chunk_count);
        scenario.pushKV("owned_output_count", static_cast<uint64_t>(fixture.owned_output_count));
        scenario.pushKV("owned_chunk_count", static_cast<uint64_t>(fixture.owned_chunk_count));
        scenario.pushKV("owned_amount_sats", static_cast<int64_t>(fixture.owned_amount));

        UniValue tx_shape(UniValue::VOBJ);
        tx_shape.pushKV("serialized_size_bytes", metrics->serialized_size_bytes);
        tx_shape.pushKV("tx_weight", metrics->tx_weight);
        tx_shape.pushKV("shielded_policy_weight", metrics->shielded_policy_weight);
        tx_shape.pushKV("proof_payload_bytes", metrics->proof_payload_bytes);
        tx_shape.pushKV("total_ciphertext_bytes", metrics->total_ciphertext_bytes);
        scenario.pushKV("tx_shape", std::move(tx_shape));

        UniValue usage(UniValue::VOBJ);
        usage.pushKV("verify_units", metrics->usage.verify_units);
        usage.pushKV("scan_units", metrics->usage.scan_units);
        usage.pushKV("tree_update_units", metrics->usage.tree_update_units);
        scenario.pushKV("resource_usage", std::move(usage));

        UniValue relay_policy(UniValue::VOBJ);
        relay_policy.pushKV("is_standard_tx", metrics->is_standard_tx);
        relay_policy.pushKV("standard_reason", metrics->standard_reason);
        relay_policy.pushKV("within_standard_tx_weight", metrics->within_standard_tx_weight);
        relay_policy.pushKV("standard_tx_weight_headroom", metrics->standard_tx_weight_headroom);
        relay_policy.pushKV("max_transactions_by_standard_tx_weight",
                            metrics->max_transactions_by_standard_tx_weight);
        relay_policy.pushKV("within_standard_shielded_policy_weight",
                            metrics->within_standard_shielded_policy_weight);
        relay_policy.pushKV("standard_shielded_policy_weight_headroom",
                            metrics->standard_shielded_policy_weight_headroom);
        relay_policy.pushKV("max_transactions_by_standard_shielded_policy_weight",
                            metrics->max_transactions_by_standard_shielded_policy_weight);
        scenario.pushKV("relay_policy", std::move(relay_policy));

        UniValue block_capacity(UniValue::VOBJ);
        block_capacity.pushKV("binding_limit", metrics->block_binding_limit);
        block_capacity.pushKV("max_transactions_by_serialized_size",
                              metrics->max_transactions_by_serialized_size);
        block_capacity.pushKV("max_transactions_by_weight", metrics->max_transactions_by_weight);
        block_capacity.pushKV("max_transactions_by_shielded_verify_units",
                              metrics->max_transactions_by_verify);
        block_capacity.pushKV("max_transactions_by_shielded_scan_units",
                              metrics->max_transactions_by_scan);
        block_capacity.pushKV("max_transactions_by_shielded_tree_update_units",
                              metrics->max_transactions_by_tree_updates);
        block_capacity.pushKV("max_transactions_per_block", metrics->max_transactions_per_block);
        block_capacity.pushKV("max_output_notes_per_block", metrics->max_output_notes_per_block);
        block_capacity.pushKV("max_output_chunks_per_block", metrics->max_output_chunks_per_block);
        block_capacity.pushKV("max_ciphertext_bytes_per_block", metrics->max_ciphertext_bytes_per_block);
        scenario.pushKV("block_capacity", std::move(block_capacity));

        scenario.pushKV("build_statement_summary", BuildSummary(build_statement_times_ns));
        scenario.pushKV("derive_outputs_summary", BuildSummary(derive_output_times_ns));
        scenario.pushKV("build_bundle_summary", BuildSummary(build_bundle_times_ns));
        scenario.pushKV("proof_check_summary", BuildSummary(proof_check_times_ns));
        scenario.pushKV("output_discovery_summary", BuildSummary(output_discovery_times_ns));
        scenario.pushKV("chunk_summary", BuildSummary(chunk_summary_times_ns));
        scenario.pushKV("full_pipeline_summary", BuildSummary(full_pipeline_times_ns));
        scenario.pushKV("measurements", std::move(measurements));
        scenarios.push_back(std::move(scenario));
    }

    UniValue report(UniValue::VOBJ);
    report.pushKV("format_version", 1);
    report.pushKV("report_kind", "v2_egress_validation_runtime");
    report.pushKV("runtime_config", BuildRuntimeConfigJson(config));
    report.pushKV("limits", BuildLimitsJson());
    report.pushKV("scenarios", std::move(scenarios));
    return report;
}

} // namespace btx::test::shieldedv2egress
