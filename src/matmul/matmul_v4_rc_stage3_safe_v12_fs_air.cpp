// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_safe_v12_fs_air.h>

#include <algorithm>
#include <limits>

namespace matmul::v4::rc::stage3_safe_v12_fs_air {
namespace detail {

inline bool Fail(std::string* why, const std::string& text)
{
    if (why != nullptr) *why = "stage3:safe_v12_fs_air:" + text;
    return false;
}

inline bool IsPowerOfTwo(uint32_t value)
{
    return value != 0 && (value & (value - 1)) == 0;
}

inline uint32_t Log2Exact(uint32_t value)
{
    uint32_t out = 0;
    while (value > 1) {
        value >>= 1;
        ++out;
    }
    return out;
}

inline void AppendBE32(std::vector<uint8_t>& out, uint32_t value)
{
    out.push_back(static_cast<uint8_t>(value >> 24));
    out.push_back(static_cast<uint8_t>(value >> 16));
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}

inline bool CanonicalDigest(const ah::Digest& digest)
{
    return std::all_of(
        digest.begin(), digest.end(),
        [](gf::Fp lane) { return lane < gf::kP; });
}

inline void AppendDigest(
    std::vector<gf::Fp>& out, const ah::Digest& digest)
{
    out.insert(out.end(), digest.begin(), digest.end());
}

inline gf::Fp3 Fp3At(
    const std::vector<gf::Fp>& lanes, size_t offset)
{
    return {lanes[offset], lanes[offset + 1], lanes[offset + 2]};
}

inline void AppendFp3(
    std::vector<gf::Fp>& out, const gf::Fp3& value)
{
    out.push_back(value.c0);
    out.push_back(value.c1);
    out.push_back(value.c2);
}

inline bool SameSnapshot(
    const safe::SafeStateSnapshotV12& left,
    const safe::SafeStateSnapshotV12& right)
{
    return left.state == right.state &&
        left.lifecycle == right.lifecycle &&
        left.segment_index == right.segment_index &&
        left.segment_used == right.segment_used &&
        left.absorb_pos == right.absorb_pos &&
        left.squeeze_pos == right.squeeze_pos &&
        left.permutation_calls == right.permutation_calls;
}

inline bool SameChannelManifest(
    const ChannelManifestV12& left,
    const ChannelManifestV12& right)
{
    const auto& a = left.safe_manifest;
    const auto& b = right.safe_manifest;
    bool exact_calls_equal =
        a.exact_calls.size() == b.exact_calls.size();
    for (size_t i = 0;
         exact_calls_equal && i < a.exact_calls.size(); ++i) {
        exact_calls_equal =
            a.exact_calls[i].kind == b.exact_calls[i].kind &&
            a.exact_calls[i].elements ==
                b.exact_calls[i].elements &&
            a.exact_calls[i].label == b.exact_calls[i].label;
    }
    return exact_calls_equal &&
        left.channel == right.channel &&
        left.lane == right.lane &&
        left.capacity_role == right.capacity_role &&
        left.application_domain == right.application_domain &&
        left.typed_domain == right.typed_domain &&
        left.calls == right.calls &&
        left.valid == right.valid &&
        a.protocol_version == b.protocol_version &&
        a.encoding_version == b.encoding_version &&
        a.domain == b.domain &&
        a.canonical_pattern.segments ==
            b.canonical_pattern.segments &&
        a.canonical_pattern.exact_calls ==
            b.canonical_pattern.exact_calls &&
        a.canonical_io_words == b.canonical_io_words &&
        a.canonical_io_bytes == b.canonical_io_bytes &&
        a.tag == b.tag &&
        a.absorb_elements == b.absorb_elements &&
        a.squeeze_elements == b.squeeze_elements &&
        a.online_poseidon_calls == b.online_poseidon_calls;
}

inline std::vector<uint8_t> ApplicationDomain(
    ChannelV12 channel, uint32_t lane, const ShapeV12& shape)
{
    static constexpr char kPrefix[] =
        "BTX_STAGE3_PR95_SAFE_FS_V12";
    std::vector<uint8_t> out(
        reinterpret_cast<const uint8_t*>(kPrefix),
        reinterpret_cast<const uint8_t*>(kPrefix) +
            sizeof(kPrefix) - 1);
    AppendBE32(out, kProtocolVersionV12);
    AppendBE32(out, static_cast<uint32_t>(channel));
    AppendBE32(out, lane);
    AppendBE32(out, kQueriesPerLaneV12);
    AppendBE32(out, kQueryCandidatesPerLaneV12);
    AppendBE32(out, kOodCandidatesPerPointV12);
    AppendBE32(out, shape.child_w);
    AppendBE32(out, shape.child_n_rows);
    AppendBE32(out, shape.child_quotient_len);
    AppendBE32(out, shape.n_coeffs);
    AppendBE32(out, shape.n_lde);
    AppendBE32(out, shape.n_folds);
    return out;
}

inline std::string Label(
    ChannelV12 channel, CallRoleV12 role, uint32_t ordinal)
{
    return "stage3.safe_v12_fs_air." +
        std::to_string(static_cast<uint32_t>(channel)) + "." +
        std::to_string(static_cast<uint32_t>(role)) + "." +
        std::to_string(ordinal);
}

inline bool AddCall(
    ChannelManifestV12& channel,
    safe::TranscriptPatternManifestBuilderV12& builder,
    CallRoleV12 role, aht::RoleV12 typed_role,
    safe::IoKindV12 io_kind, PayloadSourceV12 source,
    uint32_t ordinal, uint32_t items, uint32_t payload_lanes,
    uint32_t elements, std::string* why)
{
    if (!IsFiatShamirRoleV12(typed_role)) {
        return Fail(why, "non-FS role in transcript call");
    }
    if (elements == 0) return Fail(why, "zero-width call");
    CallSpecV12 call;
    call.channel = channel.channel;
    call.role = role;
    call.typed_role = typed_role;
    call.io_kind = io_kind;
    call.payload_source = source;
    call.ordinal = ordinal;
    call.items = items;
    call.payload_lanes = payload_lanes;
    call.elements = elements;
    call.label = Label(channel.channel, role, ordinal);
    const bool ok =
        io_kind == safe::IoKindV12::Absorb
        ? builder.Absorb(call.label, elements, why)
        : builder.Squeeze(call.label, elements, why);
    if (!ok) return false;
    channel.calls.push_back(std::move(call));
    return true;
}

inline bool AddAbsorb(
    ChannelManifestV12& channel,
    safe::TranscriptPatternManifestBuilderV12& builder,
    CallRoleV12 role, aht::RoleV12 typed_role,
    PayloadSourceV12 source, uint32_t ordinal, uint32_t items,
    uint32_t payload_lanes, std::string* why)
{
    if (payload_lanes >
        std::numeric_limits<uint32_t>::max() -
            kEventHeaderLanesV12) {
        return Fail(why, "absorb width overflow");
    }
    return AddCall(
        channel, builder, role, typed_role,
        safe::IoKindV12::Absorb, source, ordinal, items,
        payload_lanes, payload_lanes + kEventHeaderLanesV12,
        why);
}

inline bool AddSqueeze(
    ChannelManifestV12& channel,
    safe::TranscriptPatternManifestBuilderV12& builder,
    CallRoleV12 role, aht::RoleV12 typed_role,
    uint32_t ordinal, uint32_t items, uint32_t elements,
    std::string* why)
{
    return AddCall(
        channel, builder, role, typed_role,
        safe::IoKindV12::Squeeze, PayloadSourceV12::None,
        ordinal, items, 0, elements, why);
}

inline bool BuildAirChannel(
    const ShapeV12& shape, ChannelManifestV12& out,
    std::string* why)
{
    out = {};
    out.channel = ChannelV12::AirQuotient;
    out.capacity_role = aht::RoleV12::TranscriptAirLambda;
    out.application_domain =
        ApplicationDomain(out.channel, 0, shape);
    if (!safe::TypedDomainV12(
            out.capacity_role, out.application_domain,
            out.typed_domain, why)) {
        return false;
    }
    safe::TranscriptPatternManifestBuilderV12 builder;
    if (!AddAbsorb(
            out, builder, CallRoleV12::AbsorbAirStatement,
            aht::RoleV12::TranscriptAirLambda,
            PayloadSourceV12::AirStatement, 0, 1, 11, why) ||
        !AddAbsorb(
            out, builder, CallRoleV12::BindAirLambda,
            aht::RoleV12::TranscriptAirLambda,
            PayloadSourceV12::DrawDescriptor, 0, 1, 2, why) ||
        !AddSqueeze(
            out, builder, CallRoleV12::SqueezeAirLambda,
            aht::RoleV12::TranscriptAirLambda, 0, 1, 3, why) ||
        !builder.Build(out.typed_domain, out.safe_manifest, why)) {
        out = {};
        return false;
    }
    out.valid = true;
    return true;
}

inline bool BuildFriChannel(
    const ShapeV12& shape, uint32_t lane,
    ChannelManifestV12& out, std::string* why)
{
    out = {};
    out.channel =
        lane == 0 ? ChannelV12::FriLane0 : ChannelV12::FriLane1;
    out.lane = lane;
    out.capacity_role = aht::RoleV12::TranscriptFriSeed;
    out.application_domain =
        ApplicationDomain(out.channel, lane, shape);
    if (!safe::TypedDomainV12(
            out.capacity_role, out.application_domain,
            out.typed_domain, why)) {
        return false;
    }

    const uint64_t columns =
        static_cast<uint64_t>(shape.child_w) + 1;
    const uint64_t coefficient_lanes = 3 * columns;
    if (coefficient_lanes >
        safe::kSafeMaxIoElementsPerPhase -
            kEventHeaderLanesV12) {
        return Fail(why, "batch coefficient vector too wide");
    }

    safe::TranscriptPatternManifestBuilderV12 builder;
    if (!AddAbsorb(
            out, builder, CallRoleV12::AbsorbFriPreamble,
            aht::RoleV12::TranscriptFriSeed,
            PayloadSourceV12::FriPreamble, 0,
            static_cast<uint32_t>(columns), 18, why) ||
        !AddAbsorb(
            out, builder, CallRoleV12::BindBatchCoefficientVector,
            aht::RoleV12::TranscriptBatchSeed,
            PayloadSourceV12::DrawDescriptor, 0,
            static_cast<uint32_t>(columns), 2, why) ||
        !AddSqueeze(
            out, builder, CallRoleV12::SqueezeBatchCoefficientVector,
            aht::RoleV12::TranscriptBatchCoefficient, 0,
            static_cast<uint32_t>(columns),
            static_cast<uint32_t>(coefficient_lanes), why) ||
        !AddAbsorb(
            out, builder, CallRoleV12::AbsorbBatchCoefficientVector,
            aht::RoleV12::TranscriptBatchCoefficient,
            PayloadSourceV12::BatchCoefficientFeedback, 0,
            static_cast<uint32_t>(columns),
            static_cast<uint32_t>(coefficient_lanes), why) ||
        !AddAbsorb(
            out, builder, CallRoleV12::BindZ1Candidates,
            aht::RoleV12::TranscriptOodZ1,
            PayloadSourceV12::DrawDescriptor, 0,
            kOodCandidatesPerPointV12, 2, why) ||
        !AddSqueeze(
            out, builder, CallRoleV12::SqueezeZ1Candidates,
            aht::RoleV12::TranscriptOodZ1, 0,
            kOodCandidatesPerPointV12,
            3 * kOodCandidatesPerPointV12, why) ||
        !AddAbsorb(
            out, builder, CallRoleV12::BindZ2Candidates,
            aht::RoleV12::TranscriptOodZ2,
            PayloadSourceV12::DrawDescriptor, 0,
            kOodCandidatesPerPointV12, 2, why) ||
        !AddSqueeze(
            out, builder, CallRoleV12::SqueezeZ2Candidates,
            aht::RoleV12::TranscriptOodZ2, 0,
            kOodCandidatesPerPointV12,
            3 * kOodCandidatesPerPointV12, why) ||
        !AddAbsorb(
            out, builder, CallRoleV12::AbsorbSelectedZ1,
            aht::RoleV12::TranscriptOodZ1,
            PayloadSourceV12::SelectedZ1Feedback, 0, 1, 3, why) ||
        !AddAbsorb(
            out, builder, CallRoleV12::AbsorbSelectedZ2,
            aht::RoleV12::TranscriptOodZ2,
            PayloadSourceV12::SelectedZ2Feedback, 0, 1, 3, why) ||
        !AddAbsorb(
            out, builder,
            CallRoleV12::AbsorbOodEvaluationCommitment,
            aht::RoleV12::TranscriptOodEvaluations,
            PayloadSourceV12::OodEvaluationCommitment,
            0, 1, 4, why) ||
        !AddAbsorb(
            out, builder, CallRoleV12::BindDeepWeights,
            aht::RoleV12::TranscriptDeepWeight,
            PayloadSourceV12::DrawDescriptor, 0, 2, 2, why) ||
        !AddSqueeze(
            out, builder, CallRoleV12::SqueezeDeepWeights,
            aht::RoleV12::TranscriptDeepWeight, 0, 2, 6, why) ||
        !AddAbsorb(
            out, builder, CallRoleV12::AbsorbDeepWeights,
            aht::RoleV12::TranscriptDeepWeight,
            PayloadSourceV12::DeepWeightFeedback, 0, 2, 6, why)) {
        out = {};
        return false;
    }

    for (uint32_t fold = 0; fold <= shape.n_folds; ++fold) {
        if (!AddAbsorb(
                out, builder, CallRoleV12::AbsorbFoldRoot,
                aht::RoleV12::TranscriptFoldState,
                PayloadSourceV12::FoldRoot, fold, 1, 4, why)) {
            out = {};
            return false;
        }
        if (fold < shape.n_folds &&
            (!AddAbsorb(
                out, builder, CallRoleV12::BindFoldBeta,
                aht::RoleV12::TranscriptFoldBeta,
                PayloadSourceV12::DrawDescriptor,
                fold, 1, 2, why) ||
             !AddSqueeze(
                out, builder, CallRoleV12::SqueezeFoldBeta,
                aht::RoleV12::TranscriptFoldBeta,
                fold, 1, 3, why))) {
            out = {};
            return false;
        }
    }

    if (!AddAbsorb(
            out, builder, CallRoleV12::BindQueryVector,
            aht::RoleV12::TranscriptQuerySeed,
            PayloadSourceV12::DrawDescriptor, 0,
            kQueryCandidatesPerLaneV12, 2, why) ||
        !AddSqueeze(
            out, builder, CallRoleV12::SqueezeQueryVector,
            aht::RoleV12::TranscriptQueryCandidate, 0,
            kQueryCandidatesPerLaneV12,
            3 * kQueryCandidatesPerLaneV12, why) ||
        !builder.Build(out.typed_domain, out.safe_manifest, why)) {
        out = {};
        return false;
    }
    out.valid = true;
    return true;
}

inline bool ValidShape(const ShapeV12& shape, std::string* why)
{
    if (shape.child_w == 0 ||
        shape.child_w >= UINT32_C(1) << 20 ||
        shape.child_n_rows < 2 ||
        !IsPowerOfTwo(shape.child_n_rows) ||
        shape.child_quotient_len == 0 ||
        !IsPowerOfTwo(shape.child_quotient_len) ||
        !IsPowerOfTwo(shape.n_coeffs) ||
        shape.n_coeffs > (UINT32_C(1) << 27) ||
        shape.n_folds != Log2Exact(shape.n_coeffs)) {
        return Fail(why, "noncanonical shape");
    }
    const uint64_t n_lde =
        static_cast<uint64_t>(shape.n_coeffs) * kFriBlowupV12;
    if (n_lde > std::numeric_limits<uint32_t>::max() ||
        n_lde < 128 ||
        shape.n_lde != n_lde ||
        !IsPowerOfTwo(shape.n_lde)) {
        return Fail(why, "noncanonical LDE shape");
    }
    return true;
}

inline std::vector<gf::Fp> Header(
    const CallSpecV12& spec)
{
    return {
        kEventHeaderMagicV12,
        gf::FromU64(static_cast<uint32_t>(spec.role)),
        gf::FromU64(spec.ordinal),
        gf::FromU64(static_cast<uint32_t>(spec.typed_role)),
        gf::FromU64(spec.payload_lanes),
    };
}

struct DerivedV12 {
    std::vector<gf::Fp> batch_coefficients;
    std::array<gf::Fp3, kOodCandidatesPerPointV12> z1_candidate{};
    std::array<gf::Fp3, kOodCandidatesPerPointV12> z2_candidate{};
    gf::Fp3 z1{};
    gf::Fp3 z2{};
    bool z1_selected{false};
    bool z2_selected{false};
    std::vector<gf::Fp> deep_weights;
};

inline bool SelectZ1(DerivedV12& derived)
{
    for (const gf::Fp3& value : derived.z1_candidate) {
        if (!gf::IsZero(gf::Fp3{0, value.c1, value.c2})) {
            derived.z1 = value;
            derived.z1_selected = true;
            return true;
        }
    }
    return false;
}

inline bool SelectZ2(DerivedV12& derived)
{
    for (const gf::Fp3& value : derived.z2_candidate) {
        if (gf::IsZero(gf::Fp3{0, value.c1, value.c2}) ||
            gf::Eq(value, derived.z1)) {
            continue;
        }
        derived.z2 = value;
        derived.z2_selected = true;
        return true;
    }
    return false;
}

inline bool RecordSqueeze(
    const CallSpecV12& spec, const ShapeV12& shape,
    const std::vector<gf::Fp>& values, DerivedV12& derived,
    std::vector<uint32_t>& query_indices, std::string* why)
{
    if (values.size() != spec.elements) {
        return Fail(why, "squeeze width mismatch");
    }
    switch (spec.role) {
    case CallRoleV12::SqueezeBatchCoefficientVector:
        derived.batch_coefficients = values;
        return true;
    case CallRoleV12::SqueezeZ1Candidates:
        for (uint32_t i = 0; i < kOodCandidatesPerPointV12; ++i) {
            derived.z1_candidate[i] = Fp3At(values, 3 * i);
        }
        return SelectZ1(derived) ||
            Fail(why, "bounded z1 candidates exhausted");
    case CallRoleV12::SqueezeZ2Candidates:
        for (uint32_t i = 0; i < kOodCandidatesPerPointV12; ++i) {
            derived.z2_candidate[i] = Fp3At(values, 3 * i);
        }
        return SelectZ2(derived) ||
            Fail(why, "bounded z2 candidates exhausted");
    case CallRoleV12::SqueezeDeepWeights:
        derived.deep_weights = values;
        return true;
    case CallRoleV12::SqueezeQueryVector:
        return qsampler::SelectFirstDistinctV12(
            values, shape.n_lde, query_indices, nullptr, why);
    default:
        return true;
    }
}

inline bool BuildAbsorbValues(
    const CallSpecV12& spec, const ShapeV12& shape,
    const TranscriptInputsV12& inputs, uint32_t lane,
    const DerivedV12& derived, std::vector<gf::Fp>& values,
    std::string* why)
{
    values = Header(spec);
    auto require_digest = [&](const ah::Digest& digest) {
        if (!CanonicalDigest(digest)) {
            return Fail(why, "noncanonical digest lane");
        }
        AppendDigest(values, digest);
        return true;
    };

    switch (spec.payload_source) {
    case PayloadSourceV12::AirStatement:
        if (!require_digest(
                inputs.parent_statement.parent_fs_seed) ||
            !require_digest(inputs.proof_witness.trace_commit)) {
            return false;
        }
        values.push_back(gf::FromU64(shape.child_n_rows));
        values.push_back(gf::FromU64(shape.child_quotient_len));
        values.push_back(gf::FromU64(shape.child_w));
        break;
    case PayloadSourceV12::FriPreamble: {
        const ProofWitnessInputsV12::FriLaneV12& in =
            inputs.proof_witness.fri_lane.at(lane);
        // Both lanes are anchored to the same parent seed. Their typed
        // channel/lane domains then derive distinct SAFE initial states; no
        // caller-free lane seed exists.
        if (!require_digest(
                inputs.parent_statement.parent_fs_seed)) {
            return false;
        }
        values.push_back(
            gf::FromU64(static_cast<uint32_t>(in.pow_grind_nonce)));
        values.push_back(
            gf::FromU64(
                static_cast<uint32_t>(in.pow_grind_nonce >> 32)));
        values.push_back(gf::FromU64(kFriBlowupV12));
        values.push_back(gf::FromU64(shape.n_coeffs));
        values.push_back(gf::FromU64(kProtocolVersionV12));
        values.push_back(gf::FromU64(shape.child_w + 1));
        if (!require_digest(in.shape_commit) ||
            !require_digest(in.row_root)) {
            return false;
        }
        break;
    }
    case PayloadSourceV12::DrawDescriptor:
        values.push_back(gf::FromU64(spec.items));
        switch (spec.role) {
        case CallRoleV12::BindAirLambda:
        case CallRoleV12::BindFoldBeta:
            values.push_back(gf::FromU64(3));
            break;
        case CallRoleV12::BindBatchCoefficientVector:
            values.push_back(gf::FromU64(3 * spec.items));
            break;
        case CallRoleV12::BindZ1Candidates:
        case CallRoleV12::BindZ2Candidates:
            values.push_back(gf::FromU64(3 * spec.items));
            break;
        case CallRoleV12::BindDeepWeights:
            values.push_back(gf::FromU64(6));
            break;
        case CallRoleV12::BindQueryVector:
            values.push_back(gf::FromU64(3 * spec.items));
            break;
        default:
            return Fail(why, "unknown draw descriptor");
        }
        break;
    case PayloadSourceV12::BatchCoefficientFeedback:
        if (derived.batch_coefficients.size() != spec.payload_lanes) {
            return Fail(why, "batch feedback unavailable");
        }
        values.insert(
            values.end(), derived.batch_coefficients.begin(),
            derived.batch_coefficients.end());
        break;
    case PayloadSourceV12::SelectedZ1Feedback:
        if (!derived.z1_selected) {
            return Fail(why, "z1 feedback unavailable");
        }
        AppendFp3(values, derived.z1);
        break;
    case PayloadSourceV12::SelectedZ2Feedback:
        if (!derived.z2_selected) {
            return Fail(why, "z2 feedback unavailable");
        }
        AppendFp3(values, derived.z2);
        break;
    case PayloadSourceV12::OodEvaluationCommitment:
        if (!require_digest(
                inputs.proof_witness.fri_lane.at(lane).
                    ood_evaluation_commit)) {
            return false;
        }
        break;
    case PayloadSourceV12::DeepWeightFeedback:
        if (derived.deep_weights.size() != spec.payload_lanes) {
            return Fail(why, "weight feedback unavailable");
        }
        values.insert(
            values.end(), derived.deep_weights.begin(),
            derived.deep_weights.end());
        break;
    case PayloadSourceV12::FoldRoot: {
        const auto& roots =
            inputs.proof_witness.fri_lane.at(lane).fold_roots;
        if (spec.ordinal >= roots.size() ||
            !require_digest(roots[spec.ordinal])) {
            return false;
        }
        break;
    }
    case PayloadSourceV12::None:
        return Fail(why, "absorb without payload source");
    }

    if (values.size() != spec.elements) {
        return Fail(why, "resolved absorb width mismatch");
    }
    return true;
}

inline bool ValidInputs(
    const ManifestV12& manifest, const TranscriptInputsV12& inputs,
    std::string* why)
{
    if (!CanonicalDigest(
            inputs.parent_statement.parent_fs_seed) ||
        !CanonicalDigest(inputs.proof_witness.trace_commit)) {
        return Fail(why, "noncanonical AIR statement digest");
    }
    for (uint32_t lane = 0; lane < kFriLaneCountV12; ++lane) {
        const ProofWitnessInputsV12::FriLaneV12& in =
            inputs.proof_witness.fri_lane[lane];
        if (!CanonicalDigest(in.shape_commit) ||
            !CanonicalDigest(in.row_root) ||
            !CanonicalDigest(in.ood_evaluation_commit) ||
            in.fold_roots.size() !=
                static_cast<uint64_t>(manifest.shape.n_folds) + 1) {
            return Fail(why, "noncanonical FRI lane input");
        }
        for (const ah::Digest& root : in.fold_roots) {
            if (!CanonicalDigest(root)) {
                return Fail(why, "noncanonical fold root");
            }
        }
    }
    return true;
}

inline bool ExecuteNativeChannel(
    const ManifestV12& manifest,
    const ChannelManifestV12& channel_manifest,
    const TranscriptInputsV12& inputs, uint32_t lane,
    ChannelExecutionV12& out, std::string* why)
{
    out = {};
    out.channel = channel_manifest.channel;
    out.lane = lane;
    safe::SafeTranscriptV12 transcript;
    if (!transcript.Start(
            channel_manifest.safe_manifest.canonical_pattern,
            channel_manifest.typed_domain, nullptr, why)) {
        return false;
    }

    DerivedV12 derived;
    for (uint32_t call_index = 0;
         call_index < channel_manifest.calls.size(); ++call_index) {
        const CallSpecV12& spec = channel_manifest.calls[call_index];
        CallTraceV12 trace;
        trace.spec = spec;
        trace.before = transcript.Snapshot();
        if (spec.io_kind == safe::IoKindV12::Absorb) {
            if (!BuildAbsorbValues(
                    spec, manifest.shape, inputs, lane, derived,
                    trace.values, why) ||
                !transcript.Absorb(trace.values, why)) {
                return false;
            }
        } else {
            if (!transcript.Squeeze(
                    spec.elements, trace.values, why) ||
                !RecordSqueeze(
                    spec, manifest.shape, trace.values, derived,
                    out.query_indices, why)) {
                return false;
            }
        }
        trace.after = transcript.Snapshot();
        out.calls.push_back(std::move(trace));
    }
    const safe::SafeStateSnapshotV12 terminal =
        transcript.Snapshot();
    out.final_state = terminal.state;
    out.permutation_calls = terminal.permutation_calls;
    if (!transcript.Finish(why)) return false;
    out.completed = true;
    return true;
}

class AirMachineV12
{
private:
    ah::State m_state{};
    uint32_t m_absorb_pos{0};
    uint32_t m_squeeze_pos{0};
    uint32_t m_call_index{0};
    uint64_t m_permutation_calls{0};
    ChannelV12 m_channel{ChannelV12::AirQuotient};
    std::vector<PermutationRowV12>* m_rows{nullptr};

    bool Permute(uint32_t call_index)
    {
        const p2air::Layout layout = p2air::CanonicalLayout();
        const p2air::Witness witness =
            p2air::BuildWitness(layout, m_state);
        PermutationRowV12 row;
        row.channel = m_channel;
        row.call_index = call_index;
        row.input = m_state;
        row.output = witness.output;
        row.decomposed_row = witness.row;
        row.constraints_zero = true;
        const auto constraints = p2air::BuildFixedConstraints(layout);
        for (const auto& constraint : constraints) {
            if (!gf::IsZero(constraint.eval(
                    row.decomposed_row, row.decomposed_row))) {
                row.constraints_zero = false;
                break;
            }
        }
        m_rows->push_back(std::move(row));
        m_state = witness.output;
        ++m_permutation_calls;
        return m_rows->back().constraints_zero;
    }

public:
    bool Start(
        ChannelV12 channel,
        const std::array<gf::Fp, safe::kSafeCapacityV12>& tag,
        std::vector<PermutationRowV12>& rows)
    {
        m_channel = channel;
        m_rows = &rows;
        m_state = {};
        std::copy(
            tag.begin(), tag.end(),
            m_state.begin() + safe::kSafeRateV12);
        return true;
    }

    safe::SafeStateSnapshotV12 Snapshot() const
    {
        return {
            m_state,
            safe::LifecycleV12::Active,
            m_call_index,
            0,
            m_absorb_pos,
            m_squeeze_pos,
            m_permutation_calls,
        };
    }

    bool Absorb(
        const std::vector<gf::Fp>& lanes, uint32_t call_index,
        std::string* why)
    {
        for (gf::Fp value : lanes) {
            if (value >= gf::kP) {
                return Fail(why, "AIR absorb noncanonical lane");
            }
            if (m_absorb_pos == safe::kSafeRateV12) {
                if (!Permute(call_index)) {
                    return Fail(why, "Poseidon AIR constraint violation");
                }
                m_absorb_pos = 0;
            }
            m_state[m_absorb_pos] =
                gf::Add(m_state[m_absorb_pos], value);
            ++m_absorb_pos;
        }
        if (!lanes.empty()) m_squeeze_pos = safe::kSafeRateV12;
        ++m_call_index;
        return true;
    }

    bool Squeeze(
        uint32_t elements, uint32_t call_index,
        std::vector<gf::Fp>& lanes, std::string* why)
    {
        lanes.clear();
        lanes.reserve(elements);
        for (uint32_t i = 0; i < elements; ++i) {
            if (m_squeeze_pos == safe::kSafeRateV12) {
                if (!Permute(call_index)) {
                    return Fail(why, "Poseidon AIR constraint violation");
                }
                m_squeeze_pos = 0;
                m_absorb_pos = 0;
            }
            lanes.push_back(m_state[m_squeeze_pos]);
            ++m_squeeze_pos;
        }
        ++m_call_index;
        return true;
    }
};

inline bool BuildAirChannel(
    const ManifestV12& manifest,
    const ChannelManifestV12& channel_manifest,
    const TranscriptInputsV12& inputs, uint32_t lane,
    AirChannelWitnessV12& out, std::string* why)
{
    out = {};
    out.projected_execution.channel = channel_manifest.channel;
    out.projected_execution.lane = lane;
    AirMachineV12 machine;
    machine.Start(
        channel_manifest.channel,
        channel_manifest.safe_manifest.tag,
        out.permutation_rows);
    DerivedV12 derived;
    for (uint32_t call_index = 0;
         call_index < channel_manifest.calls.size(); ++call_index) {
        const CallSpecV12& spec = channel_manifest.calls[call_index];
        CallTraceV12 trace;
        trace.spec = spec;
        trace.before = machine.Snapshot();
        if (spec.io_kind == safe::IoKindV12::Absorb) {
            if (!BuildAbsorbValues(
                    spec, manifest.shape, inputs, lane, derived,
                    trace.values, why) ||
                !machine.Absorb(trace.values, call_index, why)) {
                return false;
            }
        } else {
            if (!machine.Squeeze(
                    spec.elements, call_index, trace.values, why) ||
                !RecordSqueeze(
                    spec, manifest.shape, trace.values, derived,
                    out.projected_execution.query_indices, why)) {
                return false;
            }
            if (spec.role == CallRoleV12::SqueezeQueryVector) {
                if (!qsampler::BuildQuerySamplerAirV12(
                        lane, manifest.shape.n_lde, trace.values,
                        out.query_sampler_air, why) ||
                    !qsampler::ValidateQuerySamplerAirV12(
                        lane, manifest.shape.n_lde, trace.values,
                        out.query_sampler_air, why) ||
                    out.query_sampler_air.selected_indices !=
                        out.projected_execution.query_indices) {
                    return Fail(
                        why, "without-replacement sampler AIR mismatch");
                }
                out.query_sampler_air_valid = true;
                out.query_sampler_source_call_typed =
                    spec.typed_role ==
                    aht::RoleV12::TranscriptQueryCandidate;
            }
        }
        trace.after = machine.Snapshot();
        out.projected_execution.calls.push_back(std::move(trace));
    }
    const safe::SafeStateSnapshotV12 terminal = machine.Snapshot();
    out.projected_execution.final_state = terminal.state;
    out.projected_execution.permutation_calls =
        terminal.permutation_calls;
    out.projected_execution.completed = true;
    out.poseidon_constraints_zero =
        std::all_of(
            out.permutation_rows.begin(), out.permutation_rows.end(),
            [](const PermutationRowV12& row) {
                return row.constraints_zero;
            });
    out.io_wiring_checked = true;
    return out.poseidon_constraints_zero;
}

inline bool SameExecution(
    const ChannelExecutionV12& left,
    const ChannelExecutionV12& right)
{
    if (left.channel != right.channel ||
        left.lane != right.lane ||
        left.final_state != right.final_state ||
        left.permutation_calls != right.permutation_calls ||
        left.query_indices != right.query_indices ||
        left.completed != right.completed ||
        left.calls.size() != right.calls.size()) {
        return false;
    }
    for (size_t i = 0; i < left.calls.size(); ++i) {
        const CallTraceV12& a = left.calls[i];
        const CallTraceV12& b = right.calls[i];
        if (a.spec != b.spec || a.values != b.values ||
            !SameSnapshot(a.before, b.before) ||
            !SameSnapshot(a.after, b.after)) {
            return false;
        }
    }
    return true;
}

inline bool SamePermutation(
    const PermutationRowV12& left,
    const PermutationRowV12& right)
{
    if (left.channel != right.channel ||
        left.call_index != right.call_index ||
        left.input != right.input ||
        left.output != right.output ||
        left.constraints_zero != right.constraints_zero ||
        left.decomposed_row.size() !=
            right.decomposed_row.size()) {
        return false;
    }
    for (size_t i = 0; i < left.decomposed_row.size(); ++i) {
        if (!gf::Eq(
                left.decomposed_row[i],
                right.decomposed_row[i])) {
            return false;
        }
    }
    return true;
}

inline bool SameAirChannel(
    const AirChannelWitnessV12& left,
    const AirChannelWitnessV12& right)
{
    if (!SameExecution(
            left.projected_execution,
            right.projected_execution) ||
        left.poseidon_constraints_zero !=
            right.poseidon_constraints_zero ||
        left.io_wiring_checked != right.io_wiring_checked ||
        left.query_sampler_air_valid !=
            right.query_sampler_air_valid ||
        left.query_sampler_source_call_typed !=
            right.query_sampler_source_call_typed ||
        left.permutation_rows.size() !=
            right.permutation_rows.size()) {
        return false;
    }
    if (left.query_sampler_air_valid &&
        !qsampler::SameQuerySamplerAirV12(
            left.query_sampler_air,
            right.query_sampler_air)) {
        return false;
    }
    for (size_t i = 0; i < left.permutation_rows.size(); ++i) {
        if (!SamePermutation(
                left.permutation_rows[i],
                right.permutation_rows[i])) {
            return false;
        }
    }
    return true;
}

} // namespace detail

bool IsMerkleRoleV12(aht::RoleV12 role)
{
    return role == aht::RoleV12::MerkleRowLeaf ||
        role == aht::RoleV12::MerkleFoldLeaf ||
        role == aht::RoleV12::MerkleInternalNode;
}

bool IsFiatShamirRoleV12(aht::RoleV12 role)
{
    return role >= aht::RoleV12::TranscriptShapeCommit &&
        role <= aht::RoleV12::TranscriptPadding;
}

bool BuildManifestV12(
    const ShapeV12& shape, ManifestV12& out, std::string* why)
{
    out = {};
    if (!detail::ValidShape(shape, why)) return false;
    out.shape = shape;
    if (!detail::BuildAirChannel(shape, out.air_quotient, why)) {
        out = {};
        return false;
    }
    for (uint32_t lane = 0; lane < kFriLaneCountV12; ++lane) {
        if (!detail::BuildFriChannel(
                shape, lane, out.fri_lane[lane], why)) {
            out = {};
            return false;
        }
    }

    constexpr std::array<aht::RoleV12, 3> merkle_roles{{
        aht::RoleV12::MerkleRowLeaf,
        aht::RoleV12::MerkleFoldLeaf,
        aht::RoleV12::MerkleInternalNode,
    }};
    constexpr std::array<aht::RoleV12, 2> fs_roles{{
        aht::RoleV12::TranscriptAirLambda,
        aht::RoleV12::TranscriptFriSeed,
    }};
    for (uint32_t i = 0; i < merkle_roles.size(); ++i) {
        if (!aht::CapacityIvForRoleV12(
                merkle_roles[i], out.merkle_capacity[i], why)) {
            out = {};
            return false;
        }
    }
    for (uint32_t i = 0; i < fs_roles.size(); ++i) {
        if (!aht::CapacityIvForRoleV12(
                fs_roles[i], out.fs_capacity[i], why)) {
            out = {};
            return false;
        }
    }
    out.merkle_fs_capacity_classes_disjoint = true;
    for (const auto& merkle : out.merkle_capacity) {
        for (const auto& fs : out.fs_capacity) {
            out.merkle_fs_capacity_classes_disjoint &=
                merkle != fs;
        }
    }
    out.q96_lanes_domain_independent =
        out.fri_lane[0].typed_domain !=
            out.fri_lane[1].typed_domain &&
        out.fri_lane[0].safe_manifest.tag !=
            out.fri_lane[1].safe_manifest.tag;
    out.lane_seeds_derived_from_common_parent = true;
    out.proof_witness_cells_not_preprocessed = true;
    out.proof_dependent_preprocessed_columns = 0;
    out.air_quotient_poseidon_rows =
        out.air_quotient.safe_manifest.online_poseidon_air_rows;
    for (uint32_t lane = 0; lane < kFriLaneCountV12; ++lane) {
        out.fri_lane_poseidon_rows[lane] =
            out.fri_lane[lane].
                safe_manifest.online_poseidon_air_rows;
        out.total_poseidon_air_rows +=
            out.fri_lane_poseidon_rows[lane];
        out.query_sampler_air_rows[lane] =
            qsampler::kTraceRowsV12;
        out.total_query_sampler_air_rows +=
            out.query_sampler_air_rows[lane];
    }
    out.total_poseidon_air_rows +=
        out.air_quotient_poseidon_rows;
    out.total_recursive_air_rows =
        out.total_poseidon_air_rows +
        out.total_query_sampler_air_rows;
    out.fits_static_domain_headroom =
        out.total_recursive_air_rows <=
        out.static_domain_headroom_rows;
    out.static_domain_margin_rows =
        out.fits_static_domain_headroom
        ? out.static_domain_headroom_rows -
            out.total_recursive_air_rows
        : 0;
    out.production_reference_shape =
        shape.child_w + 1 == kProductionBatchColumnsV12 &&
        shape.n_folds == kProductionFoldsV12;
    out.production_reference_cost_pinned =
        !out.production_reference_shape ||
        (out.total_poseidon_air_rows ==
             kProductionExpectedSafeAirRowsV12 &&
         out.total_query_sampler_air_rows ==
             kProductionExpectedQuerySamplerAirRowsV12 &&
         out.total_recursive_air_rows ==
             kProductionExpectedTotalRecursiveAirRowsV12 &&
         out.query_sampler_air_columns ==
             qsampler::kAirColumnsV12 &&
         out.production_query_exhaustion_bound_bits ==
             qsampler::kProductionExhaustionBoundBitsV12);
    out.proof_independent = true;
    out.exact_pr95_roles = true;
    out.valid =
        out.merkle_fs_capacity_classes_disjoint &&
        out.q96_lanes_domain_independent &&
        out.lane_seeds_derived_from_common_parent &&
        out.proof_witness_cells_not_preprocessed &&
        out.proof_dependent_preprocessed_columns == 0 &&
        out.fits_static_domain_headroom &&
        out.production_reference_cost_pinned;
    out.note = out.valid
        ? "stage3:safe_v12_fs_air:shape_fixed_dual_q96_manifest"
        : "stage3:safe_v12_fs_air:domain_separation_failure";
    return out.valid;
}

bool ValidateManifestV12(
    const ManifestV12& manifest, std::string* why)
{
    if (!manifest.valid) {
        return detail::Fail(why, "manifest not valid");
    }
    ManifestV12 expected;
    if (!BuildManifestV12(manifest.shape, expected, why)) {
        return false;
    }
    if (!detail::SameChannelManifest(
            manifest.air_quotient, expected.air_quotient)) {
        return detail::Fail(why, "AIR channel manifest mismatch");
    }
    for (uint32_t lane = 0; lane < kFriLaneCountV12; ++lane) {
        if (!detail::SameChannelManifest(
                manifest.fri_lane[lane],
                expected.fri_lane[lane])) {
            return detail::Fail(why, "FRI lane manifest mismatch");
        }
    }
    if (manifest.merkle_capacity != expected.merkle_capacity ||
        manifest.fs_capacity != expected.fs_capacity ||
        manifest.proof_independent != expected.proof_independent ||
        manifest.exact_pr95_roles != expected.exact_pr95_roles ||
        manifest.q96_lanes_domain_independent !=
            expected.q96_lanes_domain_independent ||
        manifest.merkle_fs_capacity_classes_disjoint !=
            expected.merkle_fs_capacity_classes_disjoint ||
        manifest.lane_seeds_derived_from_common_parent !=
            expected.lane_seeds_derived_from_common_parent ||
        manifest.proof_witness_cells_not_preprocessed !=
            expected.proof_witness_cells_not_preprocessed ||
        manifest.proof_dependent_preprocessed_columns != 0 ||
        manifest.air_quotient_poseidon_rows !=
            expected.air_quotient_poseidon_rows ||
        manifest.fri_lane_poseidon_rows !=
            expected.fri_lane_poseidon_rows ||
        manifest.total_poseidon_air_rows !=
            expected.total_poseidon_air_rows ||
        manifest.query_sampler_air_rows !=
            expected.query_sampler_air_rows ||
        manifest.total_query_sampler_air_rows !=
            expected.total_query_sampler_air_rows ||
        manifest.total_recursive_air_rows !=
            expected.total_recursive_air_rows ||
        manifest.query_sampler_air_columns !=
            expected.query_sampler_air_columns ||
        manifest.production_query_exhaustion_bound_bits !=
            expected.production_query_exhaustion_bound_bits ||
        manifest.static_domain_headroom_rows !=
            expected.static_domain_headroom_rows ||
        manifest.static_domain_margin_rows !=
            expected.static_domain_margin_rows ||
        manifest.fits_static_domain_headroom !=
            expected.fits_static_domain_headroom ||
        manifest.production_reference_shape !=
            expected.production_reference_shape ||
        manifest.production_reference_cost_pinned !=
            expected.production_reference_cost_pinned) {
        return detail::Fail(why, "manifest metadata mismatch");
    }
    return true;
}

bool ExecuteNativeV12(
    const ManifestV12& manifest, const TranscriptInputsV12& inputs,
    NativeExecutionV12& out, std::string* why)
{
    out = {};
    if (!ValidateManifestV12(manifest, why) ||
        !detail::ValidInputs(manifest, inputs, why)) {
        return false;
    }
    if (!detail::ExecuteNativeChannel(
            manifest, manifest.air_quotient, inputs, 0,
            out.air_quotient, why)) {
        out = {};
        return false;
    }
    for (uint32_t lane = 0; lane < kFriLaneCountV12; ++lane) {
        if (!detail::ExecuteNativeChannel(
                manifest, manifest.fri_lane[lane], inputs, lane,
                out.fri_lane[lane], why)) {
            out = {};
            return false;
        }
    }
    out.independent_lane_tags =
        manifest.fri_lane[0].safe_manifest.tag !=
        manifest.fri_lane[1].safe_manifest.tag;
    out.valid = out.independent_lane_tags;
    out.note = out.valid
        ? "stage3:safe_v12_fs_air:native_ok"
        : "stage3:safe_v12_fs_air:lane_tag_collision";
    return out.valid;
}

bool BuildAirWitnessV12(
    const ManifestV12& manifest, const TranscriptInputsV12& inputs,
    AirWitnessV12& out, std::string* why)
{
    out = {};
    NativeExecutionV12 native;
    if (!ExecuteNativeV12(manifest, inputs, native, why)) {
        return false;
    }
    if (!detail::BuildAirChannel(
            manifest, manifest.air_quotient, inputs, 0,
            out.air_quotient, why)) {
        out = {};
        return false;
    }
    for (uint32_t lane = 0; lane < kFriLaneCountV12; ++lane) {
        if (!detail::BuildAirChannel(
                manifest, manifest.fri_lane[lane], inputs, lane,
                out.fri_lane[lane], why)) {
            out = {};
            return false;
        }
    }
    out.native_differential_equal =
        detail::SameExecution(
            native.air_quotient,
            out.air_quotient.projected_execution);
    for (uint32_t lane = 0; lane < kFriLaneCountV12; ++lane) {
        out.native_differential_equal &=
            detail::SameExecution(
                native.fri_lane[lane],
                out.fri_lane[lane].projected_execution);
    }
    out.lane_order_bound =
        out.fri_lane[0].projected_execution.final_state !=
        out.fri_lane[1].projected_execution.final_state;
    out.valid =
        out.native_differential_equal &&
        out.lane_order_bound &&
        out.air_quotient.poseidon_constraints_zero &&
        out.air_quotient.io_wiring_checked &&
        out.fri_lane[0].poseidon_constraints_zero &&
        out.fri_lane[1].poseidon_constraints_zero &&
        out.fri_lane[0].query_sampler_air_valid &&
        out.fri_lane[1].query_sampler_air_valid &&
        out.fri_lane[0].query_sampler_source_call_typed &&
        out.fri_lane[1].query_sampler_source_call_typed &&
        out.fri_lane[0].io_wiring_checked &&
        out.fri_lane[1].io_wiring_checked;
    out.note = out.valid
        ? "stage3:safe_v12_fs_air:native_air_differential_ok"
        : "stage3:safe_v12_fs_air:native_air_differential_failure";
    return out.valid;
}

bool ValidateAirWitnessV12(
    const ManifestV12& manifest, const TranscriptInputsV12& inputs,
    const AirWitnessV12& witness, std::string* why)
{
    AirWitnessV12 expected;
    if (!BuildAirWitnessV12(manifest, inputs, expected, why)) {
        return false;
    }
    if (witness.native_differential_equal !=
            expected.native_differential_equal ||
        witness.lane_order_bound != expected.lane_order_bound ||
        witness.valid != expected.valid ||
        !detail::SameAirChannel(
            witness.air_quotient, expected.air_quotient)) {
        return detail::Fail(why, "AIR witness top-level mismatch");
    }
    for (uint32_t lane = 0; lane < kFriLaneCountV12; ++lane) {
        if (!detail::SameAirChannel(
                witness.fri_lane[lane],
                expected.fri_lane[lane])) {
            return detail::Fail(why, "AIR witness lane mismatch");
        }
    }
    return true;
}

} // namespace matmul::v4::rc::stage3_safe_v12_fs_air
