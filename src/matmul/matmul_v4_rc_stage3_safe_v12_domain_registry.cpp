// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_safe_v12_domain_registry.h>

#include <algorithm>
#include <cmath>
#include <limits>

namespace matmul::v4::rc::stage3_safe_v12_domain_registry {
namespace {

// Distinct leading words make entry and registry-root frames prefix-free even
// though both intentionally use the ProgramTableCommitment capacity class.
constexpr uint32_t kEntryFrameTagV12 = UINT32_C(0x53414531);
constexpr uint32_t kRootFrameTagV12 = UINT32_C(0x53415231);

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:safe_v12_domain_registry:" + detail;
    }
    return false;
}

bool CanonicalDigest(const alg_hash::Digest& digest)
{
    return std::all_of(
        digest.begin(), digest.end(),
        [](gf::Fp value) { return value < gf::kP; });
}

void AppendU32(std::vector<gf::Fp>& out, uint32_t value)
{
    out.push_back(gf::FromU64(value));
}

void AppendU64Injective(std::vector<gf::Fp>& out, uint64_t value)
{
    AppendU32(out, static_cast<uint32_t>(value));
    AppendU32(out, static_cast<uint32_t>(value >> 32));
}

void AppendBytes(
    std::vector<gf::Fp>& out, const std::vector<uint8_t>& bytes)
{
    AppendU32(out, static_cast<uint32_t>(bytes.size()));
    for (uint8_t byte : bytes) {
        out.push_back(gf::FromU64(byte));
    }
}

void AppendString(
    std::vector<gf::Fp>& out, const std::string& text)
{
    AppendU32(out, static_cast<uint32_t>(text.size()));
    for (unsigned char byte : text) {
        out.push_back(gf::FromU64(byte));
    }
}

void AppendShape(
    std::vector<gf::Fp>& out, const fsair::ShapeV12& shape)
{
    AppendU32(out, shape.child_w);
    AppendU32(out, shape.child_n_rows);
    AppendU32(out, shape.child_quotient_len);
    AppendU32(out, shape.n_coeffs);
    AppendU32(out, shape.n_lde);
    AppendU32(out, shape.n_folds);
}

void AppendCall(
    std::vector<gf::Fp>& out, const fsair::CallSpecV12& call)
{
    AppendU32(out, static_cast<uint32_t>(call.channel));
    AppendU32(out, static_cast<uint32_t>(call.role));
    AppendU32(out, static_cast<uint32_t>(call.typed_role));
    AppendU32(out, static_cast<uint32_t>(call.io_kind));
    AppendU32(out, static_cast<uint32_t>(call.payload_source));
    AppendU32(out, call.ordinal);
    AppendU32(out, call.items);
    AppendU32(out, call.payload_lanes);
    AppendU32(out, call.elements);
    AppendString(out, call.label);
}

bool CommitEntry(
    const DomainRegistryEntryV12& entry,
    alg_hash::Digest& digest,
    std::string* why)
{
    std::vector<gf::Fp> lanes;
    lanes.reserve(
        32 + entry.application_domain.size() +
        entry.typed_domain.size() +
        entry.canonical_io_words.size() * 2 +
        entry.calls.size() * 16);
    AppendU32(lanes, kEntryFrameTagV12);
    AppendU32(lanes, kDomainRegistryVersionV12);
    AppendU32(lanes, static_cast<uint32_t>(entry.channel));
    AppendU32(lanes, entry.lane);
    AppendU32(lanes, static_cast<uint32_t>(entry.capacity_role));
    AppendBytes(lanes, entry.application_domain);
    AppendBytes(lanes, entry.typed_domain);
    AppendU32(
        lanes,
        static_cast<uint32_t>(
            entry.canonical_io_words.size()));
    for (uint32_t word : entry.canonical_io_words) {
        AppendU32(lanes, word);
    }
    AppendU32(lanes, static_cast<uint32_t>(entry.calls.size()));
    for (const auto& call : entry.calls) {
        AppendCall(lanes, call);
    }
    for (gf::Fp tag_lane : entry.tag) {
        if (tag_lane >= gf::kP) {
            return Fail(why, "noncanonical_tag");
        }
        AppendU64Injective(lanes, tag_lane);
    }
    if (!aht::SpongeHashFpV12(
            aht::RoleV12::ProgramTableCommitment,
            lanes, digest, why) ||
        !CanonicalDigest(digest)) {
        return Fail(why, "entry_commitment");
    }
    return true;
}

bool FillEntry(
    const fsair::ChannelManifestV12& channel,
    DomainRegistryEntryV12& entry,
    std::string* why)
{
    if (!channel.valid ||
        !safe::ValidateIoPatternV12(
            channel.safe_manifest.canonical_pattern, why)) {
        return false;
    }
    entry.channel = channel.channel;
    entry.lane = channel.lane;
    entry.capacity_role = channel.capacity_role;
    entry.application_domain = channel.application_domain;
    entry.typed_domain = channel.typed_domain;
    entry.canonical_io_words =
        channel.safe_manifest.canonical_io_words;
    entry.calls = channel.calls;
    entry.tag = channel.safe_manifest.tag;
    return CommitEntry(entry, entry.entry_commitment, why);
}

uint32_t CountViolations(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns)
{
    if (columns.size() != cs.n_columns) {
        return std::numeric_limits<uint32_t>::max();
    }
    uint32_t violations = 0;
    std::vector<gf::Fp3> current(cs.n_columns);
    std::vector<gf::Fp3> next(cs.n_columns);
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        const uint32_t next_row = (row + 1) % cs.n_rows;
        for (uint32_t column = 0; column < cs.n_columns; ++column) {
            if (columns[column].size() != cs.n_rows) {
                return std::numeric_limits<uint32_t>::max();
            }
            current[column] = columns[column][row];
            next[column] = columns[column][next_row];
        }
        for (const auto& constraint : cs.constraints) {
            if (!gf::IsZero(constraint.eval(current, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

bool SameColumns(
    const std::vector<std::vector<gf::Fp3>>& left,
    const std::vector<std::vector<gf::Fp3>>& right)
{
    if (left.size() != right.size()) return false;
    for (size_t column = 0; column < left.size(); ++column) {
        if (left[column].size() != right[column].size()) return false;
        for (size_t row = 0; row < left[column].size(); ++row) {
            if (!gf::Eq(left[column][row], right[column][row])) {
                return false;
            }
        }
    }
    return true;
}

} // namespace

bool BuildTranscriptDomainRegistryV12(
    const fsair::ManifestV12& manifest,
    TranscriptDomainRegistryV12& out,
    std::string* why)
{
    out = {};
    if (!fsair::ValidateManifestV12(manifest, why)) {
        return false;
    }
    fsair::ManifestV12 rebuilt;
    if (!fsair::BuildManifestV12(
            manifest.shape, rebuilt, why) ||
        !fsair::ValidateManifestV12(rebuilt, why)) {
        return false;
    }
    out.shape = rebuilt.shape;
    if (!FillEntry(
            rebuilt.air_quotient, out.entries[0], why) ||
        !FillEntry(
            rebuilt.fri_lane[0], out.entries[1], why) ||
        !FillEntry(
            rebuilt.fri_lane[1], out.entries[2], why) ||
        !FillEntry(
            rebuilt.query_lane[0], out.entries[3], why) ||
        !FillEntry(
            rebuilt.query_lane[1], out.entries[4], why)) {
        out = {};
        return false;
    }
    out.manifest_rebuilt_from_shape = true;
    out.exact_five_channel_inventory =
        out.entries[0].channel ==
            fsair::ChannelV12::AirQuotient &&
        out.entries[1].channel == fsair::ChannelV12::FriLane0 &&
        out.entries[2].channel == fsair::ChannelV12::FriLane1 &&
        out.entries[3].channel == fsair::ChannelV12::QueryLane0 &&
        out.entries[4].channel == fsair::ChannelV12::QueryLane1 &&
        out.entries[0].lane == 0 &&
        out.entries[1].lane == 0 &&
        out.entries[2].lane == 1 &&
        out.entries[3].lane == 0 &&
        out.entries[4].lane == 1;
    out.io_patterns_fixed = true;
    out.all_tags_fill_capacity = true;
    for (const auto& entry : out.entries) {
        out.exact_call_count +=
            static_cast<uint32_t>(entry.calls.size());
        out.io_patterns_fixed &=
            !entry.canonical_io_words.empty() &&
            !entry.calls.empty();
        out.all_tags_fill_capacity &=
            entry.tag.size() == kGoldilocksTagLanesV12 &&
            std::all_of(
                entry.tag.begin(), entry.tag.end(),
                [](gf::Fp value) { return value < gf::kP; });
    }
    out.pairwise_domains_distinct = true;
    out.pairwise_tags_distinct = true;
    for (size_t left = 0; left < out.entries.size(); ++left) {
        for (size_t right = left + 1;
             right < out.entries.size(); ++right) {
            out.pairwise_domains_distinct &=
                out.entries[left].typed_domain !=
                out.entries[right].typed_domain;
            out.pairwise_tags_distinct &=
                out.entries[left].tag !=
                out.entries[right].tag;
        }
    }

    std::vector<gf::Fp> root_lanes;
    AppendU32(root_lanes, kRootFrameTagV12);
    AppendU32(root_lanes, kDomainRegistryVersionV12);
    AppendShape(root_lanes, out.shape);
    AppendU32(root_lanes, kTranscriptChannelsV12);
    for (const auto& entry : out.entries) {
        for (gf::Fp lane : entry.entry_commitment) {
            AppendU64Injective(root_lanes, lane);
        }
    }
    out.root_field_native =
        aht::SpongeHashFpV12(
            aht::RoleV12::ProgramTableCommitment,
            root_lanes, out.root, why) &&
        CanonicalDigest(out.root);
    out.valid =
        out.manifest_rebuilt_from_shape &&
        out.exact_five_channel_inventory &&
        out.io_patterns_fixed &&
        out.pairwise_domains_distinct &&
        out.pairwise_tags_distinct &&
        out.all_tags_fill_capacity &&
        out.root_field_native &&
        out.exact_call_count != 0;
    out.note = out.valid
        ? "stage3:safe_v12_domain_registry:"
          "shape_rebuilt_exact_io_domain_tag_root"
        : "stage3:safe_v12_domain_registry:invalid";
    if (!out.valid) return Fail(why, "incomplete_registry");
    return true;
}

bool ValidateTranscriptDomainRegistryV12(
    const fsair::ManifestV12& manifest,
    const TranscriptDomainRegistryV12& registry,
    std::string* why)
{
    TranscriptDomainRegistryV12 expected;
    if (!BuildTranscriptDomainRegistryV12(
            manifest, expected, why)) {
        return false;
    }
    if (!registry.valid || registry != expected) {
        return Fail(why, "registry_substitution");
    }
    return true;
}

SafeCrossOracleAuditV12 AssessSafeCrossOracleParametersV12(
    const TranscriptDomainRegistryV12& registry)
{
    SafeCrossOracleAuditV12 out;
    out.field_element_bits = 64;
    out.arithmetic_capacity_elements = safe::kSafeCapacityV12;
    out.tag_elements = kGoldilocksTagLanesV12;
    out.registry_oracles = kTranscriptChannelsV12;
    out.ideal_permutation_capacity_bits =
        0.5 *
        static_cast<double>(safe::kSafeCapacityV12) *
        std::log2(static_cast<double>(gf::kP));
    out.fixed_io_patterns =
        registry.valid && registry.io_patterns_fixed;
    out.pairwise_domain_separators =
        registry.valid &&
        registry.pairwise_domains_distinct &&
        registry.pairwise_tags_distinct;
    out.full_capacity_tags =
        registry.valid &&
        registry.all_tags_fill_capacity &&
        out.tag_elements ==
            out.arithmetic_capacity_elements;
    out.safe_cross_oracle_parameter_target_met =
        out.fixed_io_patterns &&
        out.pairwise_domain_separators &&
        out.full_capacity_tags &&
        out.ideal_permutation_capacity_bits >=
            static_cast<double>(
                kSafeV1SecurityTargetBitsV12);
    out.concrete_poseidon2_permutation_assumption_registered =
        false;
    out.registry_root_recursively_consumed = false;
    out.conditional_cross_oracle_reduction_complete =
        out.safe_cross_oracle_parameter_target_met &&
        out.concrete_poseidon2_permutation_assumption_registered &&
        out.registry_root_recursively_consumed;
    out.note =
        "stage3:safe_v12_domain_registry:"
        "SAFE_2023_520_cross_oracle_parameters_met;"
        "concrete_poseidon_assumption_and_recursive_root_open";
    return out;
}

bool BuildDomainRegistryRootPinAirV12(
    const TranscriptDomainRegistryV12& registry,
    const alg_hash::Digest& proof_root,
    DomainRegistryRootPinAirV12& out,
    std::string* why)
{
    out = {};
    if (!registry.valid ||
        !CanonicalDigest(registry.root) ||
        !CanonicalDigest(proof_root)) {
        return Fail(why, "root_pin_input");
    }
    constexpr uint32_t kRows = 2;
    constexpr uint32_t kRootLanes = alg_hash::kAlgHashDigestLen;
    out.cs.n_rows = kRows;
    out.cs.n_columns = 2 * kRootLanes;
    out.columns.assign(
        out.cs.n_columns,
        std::vector<gf::Fp3>(kRows, gf::Fp3::Zero()));
    out.expected_root = registry.root;
    out.proof_root = proof_root;
    out.cs.preprocessed_pin_ood = true;
    for (uint32_t lane = 0; lane < kRootLanes; ++lane) {
        const uint32_t expected_column = lane;
        const uint32_t proof_column = kRootLanes + lane;
        std::fill(
            out.columns[expected_column].begin(),
            out.columns[expected_column].end(),
            gf::Fp3::FromFp(registry.root[lane]));
        std::fill(
            out.columns[proof_column].begin(),
            out.columns[proof_column].end(),
            gf::Fp3::FromFp(proof_root[lane]));
        out.cs.preprocessed.emplace_back(
            expected_column,
            out.columns[expected_column]);
        aq::AirConstraint<gf::Fp3> equality;
        equality.name =
            "stage3.safe_v12.domain_registry_root_pin";
        equality.kind = aq::AirKind::kEverywhere;
        equality.alg_degree = 1;
        equality.eval = [expected_column, proof_column](
                            const std::vector<gf::Fp3>& current,
                            const std::vector<gf::Fp3>&) {
            return gf::Sub(
                current[proof_column],
                current[expected_column]);
        };
        out.cs.constraints.push_back(std::move(equality));
    }
    out.verifier_owned_preprocessed_columns = kRootLanes;
    out.proof_owned_preprocessed_columns = 0;
    out.equality_constraints =
        static_cast<uint32_t>(out.cs.constraints.size());
    out.violations = CountViolations(out.cs, out.columns);
    out.valid =
        out.equality_constraints == kRootLanes &&
        out.verifier_owned_preprocessed_columns == kRootLanes &&
        out.proof_owned_preprocessed_columns == 0 &&
        out.violations == 0;
    out.recursively_consumed = false;
    out.note = out.valid
        ? "stage3:safe_v12_domain_registry:"
          "root_pin_air_valid;recursive_consumption_open"
        : "stage3:safe_v12_domain_registry:root_pin_violation";
    if (!out.valid) return Fail(why, "root_pin_violation");
    return true;
}

bool ValidateDomainRegistryRootPinAirV12(
    const TranscriptDomainRegistryV12& registry,
    const alg_hash::Digest& proof_root,
    const DomainRegistryRootPinAirV12& air,
    std::string* why)
{
    DomainRegistryRootPinAirV12 expected;
    if (!BuildDomainRegistryRootPinAirV12(
            registry, proof_root, expected, why)) {
        return false;
    }
    if (!air.valid ||
        air.recursively_consumed ||
        air.expected_root != expected.expected_root ||
        air.proof_root != expected.proof_root ||
        air.verifier_owned_preprocessed_columns !=
            expected.verifier_owned_preprocessed_columns ||
        air.proof_owned_preprocessed_columns != 0 ||
        air.equality_constraints != expected.equality_constraints ||
        air.violations != 0 ||
        air.cs.n_rows != expected.cs.n_rows ||
        air.cs.n_columns != expected.cs.n_columns ||
        air.cs.preprocessed.size() !=
            expected.cs.preprocessed.size() ||
        !SameColumns(air.columns, expected.columns)) {
        return Fail(why, "root_pin_substitution");
    }
    return true;
}

} // namespace matmul::v4::rc::stage3_safe_v12_domain_registry
