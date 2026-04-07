// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_v2_netting_capacity_report.h>

#include <consensus/consensus.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <crypto/ml_kem.h>
#include <hash.h>
#include <kernel/mempool_options.h>
#include <policy/policy.h>
#include <shielded/note.h>
#include <shielded/note_encryption.h>
#include <shielded/smile2/verify_dispatch.h>
#include <shielded/smile2/wallet_bridge.h>
#include <shielded/validation.h>
#include <shielded/v2_bundle.h>
#include <shielded/v2_send.h>
#include <test/util/shielded_v2_egress_fixture.h>

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

namespace btx::test::shieldedv2netting {
namespace {

using shielded::v2::NettingManifest;
using shielded::v2::OutputDescription;
using shielded::v2::ReserveDelta;
using shielded::v2::V2RebalanceBuildInput;
using ::ShieldedNote;
using ::test::shielded::AttachSettlementAnchorReserveBinding;
using ::test::shielded::BuildV2SettlementAnchorReceiptFixture;

struct WindowSimulation
{
    uint32_t window_index{0};
    CAmount gross_boundary_sat{0};
    CAmount net_boundary_sat{0};
    uint64_t achieved_netting_bps{0};
    uint64_t effective_capacity_multiplier_milli{0};
    size_t manifest_domain_count{0};
    size_t reserve_output_count{0};
    CAmount max_abs_domain_delta_sat{0};
    std::vector<ReserveDelta> reserve_deltas;
};

struct RepresentativeArtifacts
{
    CMutableTransaction rebalance_tx;
    CMutableTransaction settlement_anchor_tx;
    uint64_t rebalance_build_ns{0};
    uint64_t rebalance_validation_ns{0};
    uint64_t settlement_anchor_build_ns{0};
    uint64_t settlement_anchor_validation_ns{0};
};

struct TransactionMetrics
{
    uint64_t serialized_size_bytes{0};
    uint64_t tx_weight{0};
    int64_t shielded_policy_weight{0};
    uint64_t proof_payload_bytes{0};
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
    return (static_cast<uint32_t>(config.domain_count) << 16) ^
           static_cast<uint32_t>(config.pairwise_cancellation_bps);
}

uint64_t MeasureNanoseconds(const std::function<void()>& fn)
{
    const auto start = std::chrono::steady_clock::now();
    fn();
    const auto end = std::chrono::steady_clock::now();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
}

uint64_t AverageUint64(const std::vector<uint64_t>& values)
{
    if (values.empty()) return 0;
    const uint64_t total = std::accumulate(values.begin(), values.end(), uint64_t{0});
    return total / values.size();
}

int64_t AverageInt64(const std::vector<int64_t>& values)
{
    if (values.empty()) return 0;
    const int64_t total = std::accumulate(values.begin(), values.end(), int64_t{0});
    return total / static_cast<int64_t>(values.size());
}

uint64_t MedianUint64(std::vector<uint64_t> values)
{
    if (values.empty()) return 0;
    std::sort(values.begin(), values.end());
    const size_t mid = values.size() / 2;
    if ((values.size() % 2) == 1) {
        return values[mid];
    }
    return (values[mid - 1] + values[mid]) / 2;
}

int64_t MedianInt64(std::vector<int64_t> values)
{
    if (values.empty()) return 0;
    std::sort(values.begin(), values.end());
    const size_t mid = values.size() / 2;
    if ((values.size() % 2) == 1) {
        return values[mid];
    }
    return (values[mid - 1] + values[mid]) / 2;
}

UniValue BuildUint64Summary(const std::vector<uint64_t>& values)
{
    UniValue summary(UniValue::VOBJ);
    summary.pushKV("count", static_cast<uint64_t>(values.size()));
    summary.pushKV("min", values.empty() ? 0 : *std::min_element(values.begin(), values.end()));
    summary.pushKV("median", MedianUint64(values));
    summary.pushKV("average", AverageUint64(values));
    summary.pushKV("max", values.empty() ? 0 : *std::max_element(values.begin(), values.end()));
    return summary;
}

UniValue BuildInt64Summary(const std::vector<int64_t>& values)
{
    UniValue summary(UniValue::VOBJ);
    summary.pushKV("count", static_cast<uint64_t>(values.size()));
    summary.pushKV("min", values.empty() ? 0 : *std::min_element(values.begin(), values.end()));
    summary.pushKV("median", MedianInt64(values));
    summary.pushKV("average", AverageInt64(values));
    summary.pushKV("max", values.empty() ? 0 : *std::max_element(values.begin(), values.end()));
    return summary;
}

mlkem::KeyPair BuildKeyPair(uint32_t scenario_id, uint32_t index)
{
    return mlkem::KeyGenDerand(
        DeriveSeed<mlkem::KEYGEN_SEEDBYTES>("BTX_ShieldedV2_NettingCapacity_Recipient", scenario_id, index));
}

ShieldedNote BuildReserveNote(uint32_t scenario_id, uint32_t window_index, uint32_t output_index, CAmount amount)
{
    ShieldedNote note;
    note.value = amount;
    const uint32_t seed_index = (window_index * 256U) + output_index;
    note.recipient_pk_hash =
        DeterministicUint256("BTX_ShieldedV2_NettingCapacity_RecipientPkHash", scenario_id, seed_index);
    note.rho = DeterministicUint256("BTX_ShieldedV2_NettingCapacity_Rho", scenario_id, seed_index);
    note.rcm = DeterministicUint256("BTX_ShieldedV2_NettingCapacity_Rcm", scenario_id, seed_index);
    if (!note.IsValid()) {
        throw std::runtime_error("constructed invalid reserve note");
    }
    return note;
}

shielded::EncryptedNote EncryptReserveNote(const ShieldedNote& note,
                                           const mlkem::PublicKey& recipient_pk,
                                           uint32_t scenario_id,
                                           uint32_t seed_index)
{
    return shielded::NoteEncryption::EncryptDeterministic(
        note,
        recipient_pk,
        DeriveSeed<mlkem::ENCAPS_SEEDBYTES>("BTX_ShieldedV2_NettingCapacity_KEM", scenario_id, seed_index),
        DeriveSeed<12>("BTX_ShieldedV2_NettingCapacity_Nonce", scenario_id, seed_index));
}

std::vector<OutputDescription> BuildReserveOutputs(uint32_t scenario_id,
                                                   uint32_t window_index,
                                                   Span<const ReserveDelta> reserve_deltas)
{
    std::vector<OutputDescription> outputs;
    outputs.reserve(reserve_deltas.size());
    uint32_t output_index{0};
    for (const auto& reserve_delta : reserve_deltas) {
        if (reserve_delta.reserve_delta <= 0) continue;

        const uint32_t seed_index = window_index * 256U + output_index;
        const ShieldedNote note =
            BuildReserveNote(scenario_id, window_index, output_index, reserve_delta.reserve_delta);
        const mlkem::KeyPair recipient = BuildKeyPair(scenario_id, seed_index);
        const shielded::EncryptedNote encrypted_note =
            EncryptReserveNote(note, recipient.pk, scenario_id, seed_index);
        auto payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
            encrypted_note,
            recipient.pk,
            shielded::v2::ScanDomain::RESERVE);
        if (!payload.has_value()) {
            throw std::runtime_error("failed to encode reserve output payload");
        }

        OutputDescription output;
        output.note_class = shielded::v2::NoteClass::RESERVE;
        auto smile_account = smile2::wallet::BuildCompactPublicAccountFromNote(
            smile2::wallet::SMILE_GLOBAL_SEED,
            note);
        if (!smile_account.has_value()) {
            throw std::runtime_error("failed to derive reserve SMILE public account");
        }
        output.note_commitment = smile2::ComputeCompactPublicAccountHash(*smile_account);
        output.value_commitment = smile2::ComputeSmileOutputCoinHash(smile_account->public_coin);
        output.smile_account = std::move(*smile_account);
        output.encrypted_note = std::move(*payload);
        if (!output.IsValid()) {
            throw std::runtime_error("constructed invalid reserve output");
        }

        outputs.push_back(std::move(output));
        ++output_index;
    }
    return outputs;
}

NettingManifest BuildNettingManifest(uint32_t scenario_id,
                                     uint32_t window_index,
                                     uint32_t settlement_window,
                                     CAmount gross_boundary_sat,
                                     Span<const ReserveDelta> reserve_deltas)
{
    NettingManifest manifest;
    manifest.settlement_window = settlement_window;
    manifest.binding_kind = shielded::v2::SettlementBindingKind::NETTING_MANIFEST;

    HashWriter gross_hw;
    gross_hw << std::string{"BTX_ShieldedV2_NettingCapacity_GrossFlow"}
             << scenario_id
             << window_index
             << gross_boundary_sat;
    HashWriter auth_hw;
    auth_hw << std::string{"BTX_ShieldedV2_NettingCapacity_Authorization"}
            << scenario_id
            << window_index
            << gross_boundary_sat;
    for (const auto& reserve_delta : reserve_deltas) {
        gross_hw << reserve_delta;
        auth_hw << reserve_delta;
    }
    manifest.gross_flow_commitment = gross_hw.GetSHA256();
    manifest.authorization_digest = auth_hw.GetSHA256();
    manifest.aggregate_net_delta = 0;
    manifest.domains.reserve(reserve_deltas.size());
    for (const auto& reserve_delta : reserve_deltas) {
        manifest.domains.push_back({reserve_delta.l2_id, reserve_delta.reserve_delta});
    }
    if (!manifest.IsValid()) {
        throw std::runtime_error("constructed invalid netting manifest");
    }
    return manifest;
}

CAmount PairGrossFlowForWindow(const RuntimeReportConfig& config,
                               uint32_t window_index,
                               uint32_t pair_index)
{
    const CAmount scale = 100 + static_cast<CAmount>((window_index + pair_index) % 5);
    return (config.pair_gross_flow_sat * scale) / 100;
}

WindowSimulation SimulateWindow(const RuntimeReportConfig& config,
                                const RuntimeScenarioConfig& scenario,
                                uint32_t window_index)
{
    std::vector<CAmount> domain_net_deltas(scenario.domain_count, 0);
    CAmount gross_boundary_sat{0};
    uint32_t pair_index{0};
    for (size_t left = 0; left < scenario.domain_count; ++left) {
        for (size_t right = left + 1; right < scenario.domain_count; ++right) {
            const CAmount pair_gross_sat = PairGrossFlowForWindow(config, window_index, pair_index);
            const CAmount canceled_sat =
                (pair_gross_sat * static_cast<CAmount>(scenario.pairwise_cancellation_bps)) / 10000;
            const CAmount residual_sat = pair_gross_sat - canceled_sat;
            const uint32_t left_rank = (static_cast<uint32_t>(left) + window_index) %
                static_cast<uint32_t>(scenario.domain_count);
            const uint32_t right_rank = (static_cast<uint32_t>(right) + window_index) %
                static_cast<uint32_t>(scenario.domain_count);
            if (left_rank < right_rank) {
                domain_net_deltas[left] -= residual_sat;
                domain_net_deltas[right] += residual_sat;
            } else {
                domain_net_deltas[left] += residual_sat;
                domain_net_deltas[right] -= residual_sat;
            }
            gross_boundary_sat += pair_gross_sat;
            ++pair_index;
        }
    }

    WindowSimulation simulation;
    simulation.window_index = window_index;
    simulation.gross_boundary_sat = gross_boundary_sat;
    for (size_t domain = 0; domain < domain_net_deltas.size(); ++domain) {
        const CAmount net_delta = domain_net_deltas[domain];
        if (net_delta == 0) continue;

        ReserveDelta reserve_delta;
        reserve_delta.l2_id = uint256{static_cast<unsigned char>(domain + 1)};
        reserve_delta.reserve_delta = net_delta;
        if (!reserve_delta.IsValid()) {
            throw std::runtime_error("constructed invalid reserve delta");
        }
        simulation.reserve_deltas.push_back(std::move(reserve_delta));
        simulation.max_abs_domain_delta_sat =
            std::max(simulation.max_abs_domain_delta_sat, std::abs(net_delta));
        if (net_delta > 0) {
            simulation.net_boundary_sat += net_delta;
            ++simulation.reserve_output_count;
        }
    }

    if (!shielded::v2::ReserveDeltaSetIsCanonical(
            Span<const ReserveDelta>{simulation.reserve_deltas.data(), simulation.reserve_deltas.size()})) {
        throw std::runtime_error("simulated reserve deltas are not canonical");
    }
    simulation.manifest_domain_count = simulation.reserve_deltas.size();
    if (simulation.gross_boundary_sat <= 0 || simulation.net_boundary_sat <= 0) {
        throw std::runtime_error("simulated cross-L2 window produced no net settlement");
    }
    simulation.achieved_netting_bps = static_cast<uint64_t>(
        ((simulation.gross_boundary_sat - simulation.net_boundary_sat) * 10000) /
        simulation.gross_boundary_sat);
    simulation.effective_capacity_multiplier_milli = static_cast<uint64_t>(
        (simulation.gross_boundary_sat * 1000) / simulation.net_boundary_sat);
    return simulation;
}

RepresentativeArtifacts BuildRepresentativeArtifacts(const RuntimeReportConfig& config,
                                                     const RuntimeScenarioConfig& scenario,
                                                     const WindowSimulation& simulation)
{
    const uint32_t scenario_id = ScenarioId(scenario);
    const NettingManifest manifest = BuildNettingManifest(scenario_id,
                                                          simulation.window_index,
                                                          config.settlement_window,
                                                          simulation.gross_boundary_sat,
                                                          Span<const ReserveDelta>{
                                                              simulation.reserve_deltas.data(),
                                                              simulation.reserve_deltas.size()});
    const uint256 manifest_id = shielded::v2::ComputeNettingManifestId(manifest);
    if (manifest_id.IsNull()) {
        throw std::runtime_error("failed to compute representative manifest id");
    }

    RepresentativeArtifacts artifacts;

    artifacts.rebalance_build_ns = MeasureNanoseconds([&] {
        const auto outputs = BuildReserveOutputs(scenario_id,
                                                 simulation.window_index,
                                                 Span<const ReserveDelta>{
                                                     simulation.reserve_deltas.data(),
                                                     simulation.reserve_deltas.size()});
        V2RebalanceBuildInput input;
        input.reserve_deltas = simulation.reserve_deltas;
        input.reserve_outputs = outputs;
        input.netting_manifest = manifest;

        std::string reject_reason;
        auto built = shielded::v2::BuildDeterministicV2RebalanceBundle(input, reject_reason);
        if (!built.has_value()) {
            throw std::runtime_error("representative rebalance build failed: " + reject_reason);
        }

        artifacts.rebalance_tx = CMutableTransaction{};
        artifacts.rebalance_tx.version = CTransaction::CURRENT_VERSION;
        artifacts.rebalance_tx.nLockTime = 500 + simulation.window_index;
        artifacts.rebalance_tx.shielded_bundle.v2_bundle = std::move(built->bundle);
    });

    artifacts.rebalance_validation_ns = MeasureNanoseconds([&] {
        const CTransaction tx{artifacts.rebalance_tx};
        std::string reject_reason;
        auto manifests = ExtractCreatedShieldedNettingManifests(tx, reject_reason);
        if (!manifests.has_value() || manifests->empty()) {
            throw std::runtime_error("representative rebalance validation failed: " + reject_reason);
        }
    });

    artifacts.settlement_anchor_build_ns = MeasureNanoseconds([&] {
        auto fixture = BuildV2SettlementAnchorReceiptFixture();
        AttachSettlementAnchorReserveBinding(fixture.tx, simulation.reserve_deltas, manifest_id);
        artifacts.settlement_anchor_tx = std::move(fixture.tx);
    });

    artifacts.settlement_anchor_validation_ns = MeasureNanoseconds([&] {
        const CTransaction tx{artifacts.settlement_anchor_tx};
        std::string reject_reason;
        auto anchors = ExtractCreatedShieldedSettlementAnchors(tx, reject_reason);
        if (!anchors.has_value() || anchors->empty()) {
            throw std::runtime_error("representative settlement-anchor validation failed: " + reject_reason);
        }
    });

    return artifacts;
}

TransactionMetrics MeasureTransactionMetrics(const CTransaction& tx)
{
    const auto* bundle = tx.shielded_bundle.GetV2Bundle();
    if (bundle == nullptr) {
        throw std::runtime_error("missing shielded_v2 bundle");
    }

    TransactionMetrics metrics;
    metrics.serialized_size_bytes = tx.GetTotalSize();
    metrics.tx_weight = GetTransactionWeight(tx);
    metrics.shielded_policy_weight = GetShieldedPolicyWeight(tx);
    metrics.proof_payload_bytes = bundle->proof_payload.size();
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
    return metrics;
}

UniValue BuildRuntimeConfigJson(const RuntimeReportConfig& config)
{
    UniValue runtime_config(UniValue::VOBJ);
    runtime_config.pushKV("warmup_iterations", static_cast<uint64_t>(config.warmup_iterations));
    runtime_config.pushKV("measured_iterations", static_cast<uint64_t>(config.measured_iterations));
    runtime_config.pushKV("pair_gross_flow_sat", static_cast<int64_t>(config.pair_gross_flow_sat));
    runtime_config.pushKV("settlement_window", config.settlement_window);

    UniValue requested(UniValue::VARR);
    for (const auto& scenario : config.scenarios) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("domain_count", static_cast<uint64_t>(scenario.domain_count));
        entry.pushKV("pairwise_cancellation_bps", scenario.pairwise_cancellation_bps);
        requested.push_back(std::move(entry));
    }
    runtime_config.pushKV("requested_scenarios", std::move(requested));
    return runtime_config;
}

UniValue BuildLimitsJson()
{
    UniValue limits(UniValue::VOBJ);
    limits.pushKV("max_rebalance_domains", static_cast<uint64_t>(shielded::v2::MAX_REBALANCE_DOMAINS));
    limits.pushKV("max_batch_reserve_outputs", static_cast<uint64_t>(shielded::v2::MAX_BATCH_RESERVE_OUTPUTS));
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

UniValue BuildTransactionMetricsJson(const TransactionMetrics& metrics)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("serialized_size_bytes", metrics.serialized_size_bytes);
    out.pushKV("tx_weight", metrics.tx_weight);
    out.pushKV("shielded_policy_weight", metrics.shielded_policy_weight);
    out.pushKV("proof_payload_bytes", metrics.proof_payload_bytes);

    UniValue usage(UniValue::VOBJ);
    usage.pushKV("verify_units", static_cast<uint64_t>(metrics.usage.verify_units));
    usage.pushKV("scan_units", static_cast<uint64_t>(metrics.usage.scan_units));
    usage.pushKV("tree_update_units", static_cast<uint64_t>(metrics.usage.tree_update_units));
    out.pushKV("shielded_resource_usage", std::move(usage));

    UniValue policy(UniValue::VOBJ);
    policy.pushKV("is_standard_tx", metrics.is_standard_tx);
    policy.pushKV("standard_reason", metrics.standard_reason);
    policy.pushKV("within_standard_tx_weight", metrics.within_standard_tx_weight);
    policy.pushKV("standard_tx_weight_headroom",
                  metrics.within_standard_tx_weight ? metrics.standard_tx_weight_headroom : 0);
    policy.pushKV("max_transactions_by_standard_tx_weight",
                  metrics.max_transactions_by_standard_tx_weight);
    policy.pushKV("within_standard_shielded_policy_weight",
                  metrics.within_standard_shielded_policy_weight);
    policy.pushKV("standard_shielded_policy_weight_headroom",
                  metrics.within_standard_shielded_policy_weight
                      ? metrics.standard_shielded_policy_weight_headroom
                      : 0);
    policy.pushKV("max_transactions_by_standard_shielded_policy_weight",
                  metrics.max_transactions_by_standard_shielded_policy_weight);
    out.pushKV("policy", std::move(policy));

    UniValue block_capacity(UniValue::VOBJ);
    block_capacity.pushKV("binding_limit", metrics.block_binding_limit);
    block_capacity.pushKV("max_transactions_by_serialized_size", metrics.max_transactions_by_serialized_size);
    block_capacity.pushKV("max_transactions_by_weight", metrics.max_transactions_by_weight);
    block_capacity.pushKV("max_transactions_by_shielded_verify_units", metrics.max_transactions_by_verify);
    block_capacity.pushKV("max_transactions_by_shielded_scan_units", metrics.max_transactions_by_scan);
    block_capacity.pushKV("max_transactions_by_shielded_tree_update_units",
                          metrics.max_transactions_by_tree_updates);
    block_capacity.pushKV("max_transactions_per_block", metrics.max_transactions_per_block);
    out.pushKV("block_capacity", std::move(block_capacity));
    return out;
}

std::string FormatScenarioLabel(const RuntimeScenarioConfig& scenario)
{
    return strprintf("%ux%u",
                     static_cast<unsigned int>(scenario.domain_count),
                     static_cast<unsigned int>(scenario.pairwise_cancellation_bps / 100));
}

} // namespace

UniValue BuildRuntimeReport(const RuntimeReportConfig& config)
{
    if (config.measured_iterations == 0) {
        throw std::runtime_error("measured_iterations must be greater than zero");
    }
    if (config.pair_gross_flow_sat <= 0 || !MoneyRange(config.pair_gross_flow_sat)) {
        throw std::runtime_error("pair_gross_flow_sat must be a valid positive amount");
    }
    if (config.settlement_window == 0) {
        throw std::runtime_error("settlement_window must be positive");
    }
    if (config.scenarios.empty()) {
        throw std::runtime_error("at least one scenario is required");
    }

    UniValue report(UniValue::VOBJ);
    report.pushKV("runtime_config", BuildRuntimeConfigJson(config));
    report.pushKV("limits", BuildLimitsJson());

    UniValue scenarios_json(UniValue::VARR);
    for (const auto& scenario : config.scenarios) {
        if (scenario.domain_count < 2 || scenario.domain_count > shielded::v2::MAX_REBALANCE_DOMAINS) {
            throw std::runtime_error("domain_count must be within [2, MAX_REBALANCE_DOMAINS]");
        }
        if (scenario.pairwise_cancellation_bps > 9900) {
            throw std::runtime_error("pairwise_cancellation_bps must not exceed 9900");
        }

        std::vector<uint64_t> gross_boundary_samples;
        std::vector<uint64_t> net_boundary_samples;
        std::vector<uint64_t> achieved_netting_samples;
        std::vector<uint64_t> capacity_multiplier_samples;
        std::vector<uint64_t> manifest_domain_samples;
        std::vector<uint64_t> reserve_output_samples;
        std::vector<int64_t> max_abs_delta_samples;
        gross_boundary_samples.reserve(config.measured_iterations);
        net_boundary_samples.reserve(config.measured_iterations);
        achieved_netting_samples.reserve(config.measured_iterations);
        capacity_multiplier_samples.reserve(config.measured_iterations);
        manifest_domain_samples.reserve(config.measured_iterations);
        reserve_output_samples.reserve(config.measured_iterations);
        max_abs_delta_samples.reserve(config.measured_iterations);

        std::optional<WindowSimulation> representative_window;
        const size_t total_iterations = config.warmup_iterations + config.measured_iterations;
        for (size_t iteration = 0; iteration < total_iterations; ++iteration) {
            const auto simulation = SimulateWindow(config,
                                                   scenario,
                                                   static_cast<uint32_t>(iteration));
            if (iteration < config.warmup_iterations) {
                continue;
            }

            gross_boundary_samples.push_back(static_cast<uint64_t>(simulation.gross_boundary_sat));
            net_boundary_samples.push_back(static_cast<uint64_t>(simulation.net_boundary_sat));
            achieved_netting_samples.push_back(simulation.achieved_netting_bps);
            capacity_multiplier_samples.push_back(simulation.effective_capacity_multiplier_milli);
            manifest_domain_samples.push_back(static_cast<uint64_t>(simulation.manifest_domain_count));
            reserve_output_samples.push_back(static_cast<uint64_t>(simulation.reserve_output_count));
            max_abs_delta_samples.push_back(simulation.max_abs_domain_delta_sat);

            if (!representative_window.has_value() ||
                std::tie(simulation.manifest_domain_count,
                         simulation.reserve_output_count,
                         simulation.net_boundary_sat,
                         simulation.gross_boundary_sat,
                         simulation.window_index) >
                    std::tie(representative_window->manifest_domain_count,
                             representative_window->reserve_output_count,
                             representative_window->net_boundary_sat,
                             representative_window->gross_boundary_sat,
                             representative_window->window_index)) {
                representative_window = simulation;
            }
        }
        if (!representative_window.has_value()) {
            throw std::runtime_error("missing representative netting window");
        }

        const RepresentativeArtifacts artifacts =
            BuildRepresentativeArtifacts(config, scenario, *representative_window);
        const TransactionMetrics rebalance_metrics =
            MeasureTransactionMetrics(CTransaction{artifacts.rebalance_tx});
        const TransactionMetrics settlement_metrics =
            MeasureTransactionMetrics(CTransaction{artifacts.settlement_anchor_tx});

        UniValue scenario_json(UniValue::VOBJ);
        scenario_json.pushKV("label", FormatScenarioLabel(scenario));
        scenario_json.pushKV("domain_count", static_cast<uint64_t>(scenario.domain_count));
        scenario_json.pushKV("pairwise_cancellation_bps", scenario.pairwise_cancellation_bps);
        scenario_json.pushKV("gross_boundary_sat_summary", BuildUint64Summary(gross_boundary_samples));
        scenario_json.pushKV("net_boundary_sat_summary", BuildUint64Summary(net_boundary_samples));
        scenario_json.pushKV("achieved_netting_bps_summary", BuildUint64Summary(achieved_netting_samples));
        scenario_json.pushKV("effective_capacity_multiplier_milli_summary",
                             BuildUint64Summary(capacity_multiplier_samples));
        scenario_json.pushKV("manifest_domain_count_summary", BuildUint64Summary(manifest_domain_samples));
        scenario_json.pushKV("reserve_output_count_summary", BuildUint64Summary(reserve_output_samples));
        scenario_json.pushKV("max_abs_domain_delta_sat_summary", BuildInt64Summary(max_abs_delta_samples));

        UniValue peak_window(UniValue::VOBJ);
        peak_window.pushKV("window_index", representative_window->window_index);
        peak_window.pushKV("gross_boundary_sat",
                           static_cast<int64_t>(representative_window->gross_boundary_sat));
        peak_window.pushKV("net_boundary_sat",
                           static_cast<int64_t>(representative_window->net_boundary_sat));
        peak_window.pushKV("achieved_netting_bps", representative_window->achieved_netting_bps);
        peak_window.pushKV("effective_capacity_multiplier_milli",
                           representative_window->effective_capacity_multiplier_milli);
        peak_window.pushKV("manifest_domain_count",
                           static_cast<uint64_t>(representative_window->manifest_domain_count));
        peak_window.pushKV("reserve_output_count",
                           static_cast<uint64_t>(representative_window->reserve_output_count));
        peak_window.pushKV("max_abs_domain_delta_sat",
                           representative_window->max_abs_domain_delta_sat);
        peak_window.pushKV("representative_rebalance_build_ns", artifacts.rebalance_build_ns);
        peak_window.pushKV("representative_rebalance_validation_ns",
                           artifacts.rebalance_validation_ns);
        peak_window.pushKV("representative_settlement_anchor_build_ns",
                           artifacts.settlement_anchor_build_ns);
        peak_window.pushKV("representative_settlement_anchor_validation_ns",
                           artifacts.settlement_anchor_validation_ns);
        peak_window.pushKV("representative_rebalance_tx",
                           BuildTransactionMetricsJson(rebalance_metrics));
        peak_window.pushKV("representative_settlement_anchor_tx",
                           BuildTransactionMetricsJson(settlement_metrics));
        scenario_json.pushKV("peak_window", std::move(peak_window));

        scenarios_json.push_back(std::move(scenario_json));
    }

    report.pushKV("scenarios", std::move(scenarios_json));
    return report;
}

} // namespace btx::test::shieldedv2netting
