// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_chunk_runtime_report.h>

#include <consensus/amount.h>
#include <crypto/ml_kem.h>
#include <hash.h>
#include <shielded/note.h>
#include <shielded/note_encryption.h>
#include <shielded/smile2/wallet_bridge.h>
#include <shielded/v2_bundle.h>
#include <shielded/v2_send.h>
#include <util/overflow.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <numeric>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace btx::test::shieldedv2chunk {
namespace {

using namespace shielded::v2;

struct OutputView
{
    uint256 commitment;
    CAmount amount{0};
    bool is_ours{false};
};

struct OutputChunkView
{
    std::string scan_domain{"unknown"};
    uint32_t first_output_index{0};
    uint32_t output_count{0};
    uint32_t ciphertext_bytes{0};
    uint256 scan_hint_commitment;
    uint256 ciphertext_commitment;
    uint32_t owned_output_count{0};
    CAmount owned_amount{0};
};

struct Fixture
{
    mlkem::KeyPair owned_recipient;
    TransactionBundle bundle;
    size_t owned_output_count{0};
    size_t owned_chunk_count{0};
    CAmount owned_amount{0};
    uint64_t total_ciphertext_bytes{0};
    std::vector<uint32_t> expected_chunk_owned_counts;
    std::vector<CAmount> expected_chunk_owned_amounts;
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

struct Measurement
{
    uint64_t canonicality_check_ns{0};
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

template <size_t N>
std::array<uint8_t, N> DeriveSeed(std::string_view tag, uint32_t index)
{
    std::array<uint8_t, N> seed{};
    size_t offset{0};
    uint32_t counter{0};
    while (offset < seed.size()) {
        HashWriter hw;
        hw << std::string{tag} << index << counter;
        const uint256 digest = hw.GetSHA256();
        const size_t copy_len = std::min(seed.size() - offset, static_cast<size_t>(uint256::size()));
        std::copy_n(digest.begin(), copy_len, seed.begin() + offset);
        offset += copy_len;
        ++counter;
    }
    return seed;
}

uint256 DeriveUint256(std::string_view tag, uint32_t index)
{
    HashWriter hw;
    hw << std::string{tag} << index;
    return hw.GetSHA256();
}

mlkem::KeyPair BuildKeyPair(std::string_view tag, uint32_t index)
{
    return mlkem::KeyGenDerand(DeriveSeed<mlkem::KEYGEN_SEEDBYTES>(tag, index));
}

ShieldedNote BuildNote(uint32_t index, bool owned)
{
    ShieldedNote note;
    note.value = 2 * COIN + static_cast<CAmount>(index) * 1000;
    note.recipient_pk_hash = owned ? DeriveUint256("BTX_ShieldedV2_ChunkRuntime_OwnedPkHash", 0)
                                   : DeriveUint256("BTX_ShieldedV2_ChunkRuntime_ForeignPkHash", index);
    note.rho = DeriveUint256("BTX_ShieldedV2_ChunkRuntime_Rho", index);
    note.rcm = DeriveUint256("BTX_ShieldedV2_ChunkRuntime_Rcm", index);
    if (!note.IsValid()) {
        throw std::runtime_error("chunk runtime note fixture is invalid");
    }
    return note;
}

shielded::BoundEncryptedNoteResult EncryptNote(const ShieldedNote& note,
                                               const mlkem::PublicKey& recipient_pk,
                                               uint32_t index)
{
    return shielded::NoteEncryption::EncryptBoundNoteDeterministic(
        note,
        recipient_pk,
        DeriveSeed<mlkem::ENCAPS_SEEDBYTES>("BTX_ShieldedV2_ChunkRuntime_KEM", index),
        DeriveSeed<12>("BTX_ShieldedV2_ChunkRuntime_Nonce", index));
}

bool IsOwnedOutputIndex(size_t index, size_t output_count)
{
    const size_t owned_stride = std::max<size_t>(64, output_count / 8);
    return (index % owned_stride) == 0;
}

OutputDescription BuildOutput(const Fixture& fixture, size_t index, bool owned)
{
    const ShieldedNote note_template = BuildNote(static_cast<uint32_t>(index), owned);
    const mlkem::PublicKey recipient_pk = owned
        ? fixture.owned_recipient.pk
        : BuildKeyPair("BTX_ShieldedV2_ChunkRuntime_ForeignRecipient", static_cast<uint32_t>(index)).pk;
    const auto bound_note = EncryptNote(note_template, recipient_pk, static_cast<uint32_t>(index));
    const auto payload =
        EncodeLegacyEncryptedNotePayload(bound_note.encrypted_note, recipient_pk, ScanDomain::OPAQUE);
    if (!payload.has_value()) {
        throw std::runtime_error("failed to encode chunk runtime payload");
    }

    OutputDescription output;
    output.note_class = NoteClass::USER;
    auto smile_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        bound_note.note);
    if (!smile_account.has_value()) {
        throw std::runtime_error("failed to build chunk runtime smile account");
    }
    output.note_commitment = smile2::ComputeCompactPublicAccountHash(*smile_account);
    output.value_commitment = DeriveUint256("BTX_ShieldedV2_ChunkRuntime_ValueCommitment", static_cast<uint32_t>(index));
    output.smile_account = std::move(*smile_account);
    output.encrypted_note = *payload;
    if (!output.IsValid()) {
        throw std::runtime_error("invalid chunk runtime output fixture");
    }
    return output;
}

ProofShardDescriptor BuildProofShard(const uint256& statement_digest)
{
    ProofShardDescriptor descriptor;
    descriptor.settlement_domain = DeriveUint256("BTX_ShieldedV2_ChunkRuntime_SettlementDomain", 0);
    descriptor.first_leaf_index = 0;
    descriptor.leaf_count = 1;
    descriptor.leaf_subroot = DeriveUint256("BTX_ShieldedV2_ChunkRuntime_LeafSubroot", 0);
    descriptor.nullifier_commitment = DeriveUint256("BTX_ShieldedV2_ChunkRuntime_NullifierCommitment", 0);
    descriptor.value_commitment = DeriveUint256("BTX_ShieldedV2_ChunkRuntime_ProofValueCommitment", 0);
    descriptor.statement_digest = statement_digest;
    descriptor.proof_metadata = {0xaa, 0xbb};
    descriptor.proof_payload_offset = 0;
    descriptor.proof_payload_size = 2;
    if (!descriptor.IsValid()) {
        throw std::runtime_error("invalid chunk runtime proof shard");
    }
    return descriptor;
}

Fixture BuildFixture(const RuntimeReportConfig& config)
{
    if (config.output_count == 0) {
        throw std::runtime_error("output_count must be non-zero");
    }
    if (config.outputs_per_chunk == 0) {
        throw std::runtime_error("outputs_per_chunk must be non-zero");
    }
    if (config.output_count > MAX_EGRESS_OUTPUTS) {
        throw std::runtime_error("output_count exceeds MAX_EGRESS_OUTPUTS");
    }

    const size_t chunk_count = (config.output_count + config.outputs_per_chunk - 1) / config.outputs_per_chunk;
    if (chunk_count > MAX_OUTPUT_CHUNKS) {
        throw std::runtime_error("chunk_count exceeds MAX_OUTPUT_CHUNKS");
    }

    Fixture fixture;
    fixture.owned_recipient = BuildKeyPair("BTX_ShieldedV2_ChunkRuntime_OwnedRecipient", 0);

    EgressBatchPayload payload;
    payload.settlement_anchor = DeriveUint256("BTX_ShieldedV2_ChunkRuntime_SettlementAnchor", 0);
    payload.allow_transparent_unwrap = false;
    payload.settlement_binding_digest = DeriveUint256("BTX_ShieldedV2_ChunkRuntime_SettlementBinding", 0);
    payload.output_binding_digest = DeriveUint256("BTX_ShieldedV2_ChunkRuntime_OutputBinding", 0);
    payload.outputs.reserve(config.output_count);

    fixture.expected_chunk_owned_counts.assign(chunk_count, 0);
    fixture.expected_chunk_owned_amounts.assign(chunk_count, 0);

    for (size_t i = 0; i < config.output_count; ++i) {
        const bool owned = IsOwnedOutputIndex(i, config.output_count);
        OutputDescription output = BuildOutput(fixture, i, owned);
        const auto decoded = DecodeLegacyEncryptedNotePayload(output.encrypted_note);
        if (!decoded.has_value()) {
            throw std::runtime_error("failed to decode chunk runtime output payload");
        }
        fixture.total_ciphertext_bytes += output.encrypted_note.ciphertext.size();
        if (owned) {
            const ShieldedNote note = BuildNote(static_cast<uint32_t>(i), /*owned=*/true);
            ++fixture.owned_output_count;
            fixture.owned_amount += note.value;
            const size_t chunk_index = i / config.outputs_per_chunk;
            ++fixture.expected_chunk_owned_counts[chunk_index];
            fixture.expected_chunk_owned_amounts[chunk_index] += note.value;
        }
        payload.outputs.push_back(std::move(output));
    }
    fixture.owned_chunk_count = std::count_if(
        fixture.expected_chunk_owned_counts.begin(),
        fixture.expected_chunk_owned_counts.end(),
        [](uint32_t count) { return count > 0; });

    for (size_t i = 0; i < payload.outputs.size(); ++i) {
        payload.outputs[i].value_commitment = ComputeV2EgressOutputValueCommitment(
            payload.output_binding_digest,
            static_cast<uint32_t>(i),
            payload.outputs[i].note_commitment);
    }
    payload.egress_root = ComputeOutputDescriptionRoot({payload.outputs.data(), payload.outputs.size()});

    fixture.bundle.header.family_id = TransactionFamily::V2_EGRESS_BATCH;
    fixture.bundle.header.proof_envelope.proof_kind = ProofKind::IMPORTED_RECEIPT;
    fixture.bundle.header.proof_envelope.membership_proof_kind = ProofComponentKind::NONE;
    fixture.bundle.header.proof_envelope.amount_proof_kind = ProofComponentKind::NONE;
    fixture.bundle.header.proof_envelope.balance_proof_kind = ProofComponentKind::NONE;
    fixture.bundle.header.proof_envelope.settlement_binding_kind = SettlementBindingKind::BRIDGE_RECEIPT;
    fixture.bundle.header.proof_envelope.statement_digest =
        DeriveUint256("BTX_ShieldedV2_ChunkRuntime_StatementDigest", 0);
    fixture.bundle.payload = payload;
    fixture.bundle.proof_shards = {BuildProofShard(fixture.bundle.header.proof_envelope.statement_digest)};
    fixture.bundle.proof_payload = {0xde, 0xad};

    for (size_t first = 0; first < payload.outputs.size(); first += config.outputs_per_chunk) {
        const size_t count = std::min(config.outputs_per_chunk, payload.outputs.size() - first);
        const auto descriptor = BuildOutputChunkDescriptor({payload.outputs.data() + first, count}, first);
        if (!descriptor.has_value()) {
            throw std::runtime_error("failed to build output chunk descriptor");
        }
        fixture.bundle.output_chunks.push_back(*descriptor);
    }

    fixture.bundle.header.payload_digest = ComputeEgressBatchPayloadDigest(payload);
    fixture.bundle.header.proof_shard_root =
        ComputeProofShardRoot({fixture.bundle.proof_shards.data(), fixture.bundle.proof_shards.size()});
    fixture.bundle.header.proof_shard_count = fixture.bundle.proof_shards.size();
    fixture.bundle.header.output_chunk_root =
        ComputeOutputChunkRoot({fixture.bundle.output_chunks.data(), fixture.bundle.output_chunks.size()});
    fixture.bundle.header.output_chunk_count = fixture.bundle.output_chunks.size();
    if (!fixture.bundle.IsValid()) {
        throw std::runtime_error("invalid chunk runtime bundle fixture");
    }
    return fixture;
}

template <typename Fn>
uint64_t MeasureNanoseconds(Fn&& fn)
{
    const auto start = std::chrono::steady_clock::now();
    fn();
    const auto end = std::chrono::steady_clock::now();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
}

DiscoveryResult DiscoverOwnedOutputs(const Fixture& fixture)
{
    DiscoveryResult result;
    const auto& payload = std::get<EgressBatchPayload>(fixture.bundle.payload);
    result.outputs.reserve(payload.outputs.size());

    for (const auto& output : payload.outputs) {
        OutputView view;
        view.commitment = output.note_commitment;

        const auto decoded = DecodeLegacyEncryptedNotePayload(output.encrypted_note);
        if (!decoded.has_value()) {
            throw std::runtime_error("failed to decode output during chunk runtime scan");
        }
        if (LegacyEncryptedNotePayloadMatchesRecipient(output.encrypted_note, *decoded, fixture.owned_recipient.pk)) {
            ++result.hint_match_count;
        }

        ++result.decrypt_attempt_count;
        auto note = shielded::NoteEncryption::TryDecrypt(
            *decoded,
            fixture.owned_recipient.pk,
            fixture.owned_recipient.sk,
            /*constant_time_scan=*/true);
        if (note.has_value()) {
            auto smile_account = smile2::wallet::BuildCompactPublicAccountFromNote(
                smile2::wallet::SMILE_GLOBAL_SEED,
                *note);
            if (!smile_account.has_value()) {
                throw std::runtime_error("chunk runtime scan failed to derive smile account");
            }
            if (smile2::ComputeCompactPublicAccountHash(*smile_account) != output.note_commitment) {
                throw std::runtime_error("chunk runtime scan produced unexpected note commitment");
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

std::vector<OutputChunkView> BuildChunkViews(Span<const OutputChunkDescriptor> output_chunks,
                                             Span<const OutputView> output_views)
{
    std::vector<OutputChunkView> chunk_views;
    chunk_views.reserve(output_chunks.size());

    for (const auto& chunk : output_chunks) {
        const size_t first = chunk.first_output_index;
        const size_t count = chunk.output_count;
        if (first > output_views.size() || count > output_views.size() - first) {
            throw std::runtime_error("output chunk bounds exceeded output views");
        }

        OutputChunkView chunk_view;
        chunk_view.scan_domain = GetScanDomainName(chunk.scan_domain);
        chunk_view.first_output_index = chunk.first_output_index;
        chunk_view.output_count = chunk.output_count;
        chunk_view.ciphertext_bytes = chunk.ciphertext_bytes;
        chunk_view.scan_hint_commitment = chunk.scan_hint_commitment;
        chunk_view.ciphertext_commitment = chunk.ciphertext_commitment;
        for (size_t i = first; i < first + count; ++i) {
            const auto& output = output_views[i];
            if (!output.is_ours) continue;
            ++chunk_view.owned_output_count;
            const auto next_amount = CheckedAdd(chunk_view.owned_amount, output.amount);
            if (!next_amount || !MoneyRange(*next_amount)) {
                throw std::runtime_error("output chunk owned amount overflowed");
            }
            chunk_view.owned_amount = *next_amount;
        }
        chunk_views.push_back(std::move(chunk_view));
    }

    return chunk_views;
}

Measurement RunMeasurement(const Fixture& fixture)
{
    Measurement measurement;

    measurement.canonicality_check_ns = MeasureNanoseconds([&] {
        if (!TransactionBundleOutputChunksAreCanonical(fixture.bundle)) {
            throw std::runtime_error("fixture bundle lost canonical output chunks");
        }
    });

    DiscoveryResult discovery;
    measurement.output_discovery_ns = MeasureNanoseconds([&] {
        discovery = DiscoverOwnedOutputs(fixture);
    });

    std::vector<OutputChunkView> chunk_views;
    measurement.chunk_summary_ns = MeasureNanoseconds([&] {
        chunk_views = BuildChunkViews(
            {fixture.bundle.output_chunks.data(), fixture.bundle.output_chunks.size()},
            {discovery.outputs.data(), discovery.outputs.size()});
    });

    measurement.full_pipeline_ns = MeasureNanoseconds([&] {
        if (!TransactionBundleOutputChunksAreCanonical(fixture.bundle)) {
            throw std::runtime_error("fixture bundle lost canonical output chunks in full pipeline");
        }
        const DiscoveryResult full_discovery = DiscoverOwnedOutputs(fixture);
        const auto full_chunk_views = BuildChunkViews(
            {fixture.bundle.output_chunks.data(), fixture.bundle.output_chunks.size()},
            {full_discovery.outputs.data(), full_discovery.outputs.size()});
        if (full_discovery.successful_decrypt_count != fixture.owned_output_count ||
            full_discovery.owned_amount != fixture.owned_amount ||
            full_chunk_views.size() != fixture.expected_chunk_owned_counts.size()) {
            throw std::runtime_error("chunk runtime full pipeline drifted");
        }
    });

    if (discovery.successful_decrypt_count != fixture.owned_output_count) {
        throw std::runtime_error("chunk runtime scan missed owned outputs");
    }
    if (discovery.owned_amount != fixture.owned_amount) {
        throw std::runtime_error("chunk runtime scan drifted owned amount");
    }
    if (chunk_views.size() != fixture.expected_chunk_owned_counts.size()) {
        throw std::runtime_error("chunk runtime chunk view count drifted");
    }

    uint64_t owned_chunk_count{0};
    for (size_t i = 0; i < chunk_views.size(); ++i) {
        if (chunk_views[i].owned_output_count != fixture.expected_chunk_owned_counts[i] ||
            chunk_views[i].owned_amount != fixture.expected_chunk_owned_amounts[i]) {
            throw std::runtime_error("chunk runtime chunk summary drifted");
        }
        if (chunk_views[i].owned_output_count > 0) {
            ++owned_chunk_count;
        }
    }

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
    if ((values.size() % 2) == 1) return values[mid];
    return (values[mid - 1] + values[mid]) / 2;
}

UniValue BuildSummary(const std::vector<uint64_t>& values)
{
    UniValue summary(UniValue::VOBJ);
    summary.pushKV("count", static_cast<uint64_t>(values.size()));
    summary.pushKV("min", values.empty() ? 0 : *std::min_element(values.begin(), values.end()));
    summary.pushKV("median", Median(values));
    summary.pushKV("average", Average(values));
    summary.pushKV("max", values.empty() ? 0 : *std::max_element(values.begin(), values.end()));
    return summary;
}

UniValue BuildFixtureJson(const Fixture& fixture, const RuntimeReportConfig& config)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("output_count", static_cast<uint64_t>(config.output_count));
    out.pushKV("output_chunk_count", static_cast<uint64_t>(fixture.bundle.output_chunks.size()));
    out.pushKV("outputs_per_chunk", static_cast<uint64_t>(config.outputs_per_chunk));
    out.pushKV("scan_domain", "opaque");
    out.pushKV("scan_hint_version", static_cast<uint64_t>(SCAN_HINT_VERSION));
    out.pushKV("owned_output_count", static_cast<uint64_t>(fixture.owned_output_count));
    out.pushKV("owned_chunk_count", static_cast<uint64_t>(fixture.owned_chunk_count));
    out.pushKV("owned_amount_sats", fixture.owned_amount);
    out.pushKV("total_ciphertext_bytes", fixture.total_ciphertext_bytes);
    return out;
}

UniValue BuildMeasurementJson(const Measurement& measurement, const Fixture& fixture, size_t sample_index)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("sample_index", static_cast<uint64_t>(sample_index));
    out.pushKV("output_count",
               static_cast<uint64_t>(std::get<EgressBatchPayload>(fixture.bundle.payload).outputs.size()));
    out.pushKV("output_chunk_count", static_cast<uint64_t>(fixture.bundle.output_chunks.size()));
    out.pushKV("canonicality_check_ns", measurement.canonicality_check_ns);
    out.pushKV("output_discovery_ns", measurement.output_discovery_ns);
    out.pushKV("chunk_summary_ns", measurement.chunk_summary_ns);
    out.pushKV("full_pipeline_ns", measurement.full_pipeline_ns);
    out.pushKV("hint_match_count", measurement.hint_match_count);
    out.pushKV("decrypt_attempt_count", measurement.decrypt_attempt_count);
    out.pushKV("successful_decrypt_count", measurement.successful_decrypt_count);
    out.pushKV("false_positive_hint_count", measurement.false_positive_hint_count);
    out.pushKV("skipped_decrypt_attempt_count", measurement.skipped_decrypt_attempt_count);
    out.pushKV("owned_output_count", measurement.owned_output_count);
    out.pushKV("owned_chunk_count", measurement.owned_chunk_count);
    out.pushKV("owned_amount_sats", measurement.owned_amount);
    out.pushKV("chunk_summary_overhead_ratio",
               measurement.output_discovery_ns == 0
                   ? 0.0
                   : static_cast<double>(measurement.chunk_summary_ns) /
                         static_cast<double>(measurement.output_discovery_ns));
    return out;
}

} // namespace

UniValue BuildRuntimeReport(const RuntimeReportConfig& config)
{
    if (config.measured_iterations == 0) {
        throw std::runtime_error("measured_iterations must be non-zero");
    }

    const Fixture fixture = BuildFixture(config);
    for (size_t i = 0; i < config.warmup_iterations; ++i) {
        const Measurement warmup = RunMeasurement(fixture);
        if (warmup.successful_decrypt_count != fixture.owned_output_count) {
            throw std::runtime_error("chunk runtime warmup drifted");
        }
    }

    std::vector<uint64_t> canonicality_check_ns;
    std::vector<uint64_t> output_discovery_ns;
    std::vector<uint64_t> chunk_summary_ns;
    std::vector<uint64_t> full_pipeline_ns;
    std::vector<uint64_t> skipped_decrypt_attempts;
    std::vector<uint64_t> false_positive_hints;
    canonicality_check_ns.reserve(config.measured_iterations);
    output_discovery_ns.reserve(config.measured_iterations);
    chunk_summary_ns.reserve(config.measured_iterations);
    full_pipeline_ns.reserve(config.measured_iterations);
    skipped_decrypt_attempts.reserve(config.measured_iterations);
    false_positive_hints.reserve(config.measured_iterations);

    UniValue measurements(UniValue::VARR);
    for (size_t i = 0; i < config.measured_iterations; ++i) {
        const Measurement measurement = RunMeasurement(fixture);
        canonicality_check_ns.push_back(measurement.canonicality_check_ns);
        output_discovery_ns.push_back(measurement.output_discovery_ns);
        chunk_summary_ns.push_back(measurement.chunk_summary_ns);
        full_pipeline_ns.push_back(measurement.full_pipeline_ns);
        skipped_decrypt_attempts.push_back(measurement.skipped_decrypt_attempt_count);
        false_positive_hints.push_back(measurement.false_positive_hint_count);
        measurements.push_back(BuildMeasurementJson(measurement, fixture, i));
    }

    UniValue runtime_config(UniValue::VOBJ);
    runtime_config.pushKV("warmup_iterations", static_cast<uint64_t>(config.warmup_iterations));
    runtime_config.pushKV("measured_iterations", static_cast<uint64_t>(config.measured_iterations));
    runtime_config.pushKV("output_count", static_cast<uint64_t>(config.output_count));
    runtime_config.pushKV("outputs_per_chunk", static_cast<uint64_t>(config.outputs_per_chunk));
    runtime_config.pushKV("duration_unit", "nanoseconds");
    runtime_config.pushKV("clock", "steady_clock");

    UniValue out(UniValue::VOBJ);
    out.pushKV("format_version", 1);
    out.pushKV("report_kind", "shielded_v2_chunk_discovery_runtime");
    out.pushKV("fixture", BuildFixtureJson(fixture, config));
    out.pushKV("runtime_config", std::move(runtime_config));
    out.pushKV("canonicality_check_ns_summary", BuildSummary(canonicality_check_ns));
    out.pushKV("output_discovery_ns_summary", BuildSummary(output_discovery_ns));
    out.pushKV("chunk_summary_ns_summary", BuildSummary(chunk_summary_ns));
    out.pushKV("full_pipeline_ns_summary", BuildSummary(full_pipeline_ns));
    out.pushKV("skipped_decrypt_attempt_summary", BuildSummary(skipped_decrypt_attempts));
    out.pushKV("false_positive_hint_summary", BuildSummary(false_positive_hints));
    out.pushKV("measurements", std::move(measurements));
    return out;
}

} // namespace btx::test::shieldedv2chunk
