// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_v13_occurrence_manifest.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <map>

namespace matmul::v4::rc::stage3_v13_occurrence_manifest {
namespace {

namespace aq = air_quotient;
namespace aht = alg_hash_typed;
namespace gf = gkr_field;

using Cell = bridge::TypedSafeMessageCellProgramV13;
using Event = bridge::TypedSafeEventProgramV13;
using Binding = bridge::TypedSafeMessageBindingV13;
using Kind = bridge::TypedSafeChallengeKindV13;
using Role = aht::RoleV12;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:v13_occurrence_manifest:" + detail;
    }
    return false;
}

uint32_t Log2Exact(uint32_t value)
{
    if (value < 2 || (value & (value - 1)) != 0) return 0;
    uint32_t out = 0;
    while (value > 1) {
        value >>= 1;
        ++out;
    }
    return out;
}

Cell ProofCell()
{
    Cell out;
    out.binding = Binding::ProofOwned;
    return out;
}

Cell ConstantCell(gf::Fp value)
{
    Cell out;
    out.binding = Binding::Constant;
    out.constant = value;
    return out;
}

Cell QuerySeedCell(uint32_t lane)
{
    Cell out;
    out.binding = Binding::QuerySeedLane;
    out.query_seed_lane = lane;
    return out;
}

gf::Fp PackedBytes(
    const unsigned char* bytes, size_t size, size_t offset)
{
    uint32_t packed = 0;
    for (uint32_t byte = 0;
         byte < 4 && offset + byte < size; ++byte) {
        packed |=
            static_cast<uint32_t>(bytes[offset + byte])
            << (8 * byte);
    }
    return gf::FromU64(packed);
}

Role RoleForKind(Kind kind)
{
    switch (kind) {
    case Kind::AirLambda:
        return Role::TranscriptAirLambda;
    case Kind::BatchCoefficient:
        return Role::TranscriptBatchCoefficient;
    case Kind::OodZ1:
        return Role::TranscriptOodZ1;
    case Kind::OodZ2:
        return Role::TranscriptOodZ2;
    case Kind::DeepWeight1:
    case Kind::DeepWeight2:
        return Role::TranscriptDeepWeight;
    case Kind::FoldBeta:
        return Role::TranscriptFoldBeta;
    case Kind::QueryCandidate:
        return Role::TranscriptQueryCandidate;
    case Kind::QuerySeed:
        return Role::TranscriptQuerySeed;
    case Kind::FriSeed:
        return Role::TranscriptFriSeed;
    }
    return Role::TranscriptPadding;
}

Event OuterEvent(
    Kind kind, Role role, uint32_t message_size)
{
    Event out;
    out.kind = kind;
    out.role = role;
    static constexpr char kDomain[] =
        "BTX_RC_AIRQ_SPLIT_RAP_SAFE_V2";
    out.application_domain.assign(
        reinterpret_cast<const uint8_t*>(kDomain),
        reinterpret_cast<const uint8_t*>(kDomain) +
            sizeof(kDomain) - 1);
    out.message.assign(message_size, ProofCell());
    return out;
}

Event TranscriptEvent(
    Kind kind, const char* label, uint32_t index,
    uint32_t transcript_bytes)
{
    Event out;
    out.kind = kind;
    out.role = RoleForKind(kind);
    static constexpr char kDomain[] =
        "BTX_RC_FRIB3ALG_Q192_SAFE_K2_V13_CHALLENGE";
    out.application_domain.assign(
        reinterpret_cast<const uint8_t*>(kDomain),
        reinterpret_cast<const uint8_t*>(kDomain) +
            sizeof(kDomain) - 1);
    out.application_domain.push_back(0);
    const size_t label_size = std::strlen(label);
    out.application_domain.insert(
        out.application_domain.end(),
        reinterpret_cast<const uint8_t*>(label),
        reinterpret_cast<const uint8_t*>(label) +
            label_size);

    out.message.push_back(
        ConstantCell(gf::FromU64(UINT32_C(0x53414645))));
    out.message.push_back(
        ConstantCell(gf::FromU64(
            kRCFri3AlgSafeQ192K2ProofVersionV13)));
    out.message.push_back(
        ConstantCell(gf::FromU64(
            static_cast<uint32_t>(out.role))));
    out.message.push_back(
        ConstantCell(gf::FromU64(transcript_bytes)));
    const uint32_t proof_words =
        (transcript_bytes + 3) / 4;
    out.message.insert(
        out.message.end(), proof_words, ProofCell());
    out.message.push_back(
        ConstantCell(gf::FromU64(label_size)));
    for (size_t offset = 0;
         offset < label_size; offset += 4) {
        out.message.push_back(
            ConstantCell(PackedBytes(
                reinterpret_cast<const unsigned char*>(
                    label),
                label_size, offset)));
    }
    out.message.push_back(
        ConstantCell(gf::FromU64(index)));
    return out;
}

Event QueryCandidateEvent(uint32_t index)
{
    Event out;
    out.kind = Kind::QueryCandidate;
    out.role = Role::TranscriptQueryCandidate;
    static constexpr char kDomain[] =
        "BTX_RC_FRIB3ALG_Q192_SAFE_K2_V13_QUERY_CANDIDATE";
    out.application_domain.assign(
        reinterpret_cast<const uint8_t*>(kDomain),
        reinterpret_cast<const uint8_t*>(kDomain) +
            sizeof(kDomain) - 1);
    out.message = {
        ConstantCell(gf::FromU64(UINT32_C(0x53414645))),
        ConstantCell(gf::FromU64(
            kRCFri3AlgSafeQ192K2ProofVersionV13)),
        ConstantCell(gf::FromU64(
            static_cast<uint32_t>(
                Role::TranscriptQueryCandidate))),
        ConstantCell(gf::FromU64(4)),
        QuerySeedCell(0),
        QuerySeedCell(1),
        QuerySeedCell(2),
        QuerySeedCell(3),
        ConstantCell(gf::FromU64(index)),
    };
    return out;
}

struct ByteOrigin {
    ByteSourceKindV1 kind{
        ByteSourceKindV1::ProtocolConstant};
    abi::SourceKeyV1 key{};
    uint32_t address{UINT32_MAX};
    uint8_t byte_in_word{0};
    bool abi_source{false};
    uint32_t event_begin{kNoEventV1};
    uint32_t event_end{kNoEventV1};
    uint8_t output_lane{0};
    uint8_t byte_in_output_lane{0};
    SelectorFamilyV1 selector{SelectorFamilyV1::None};
    bool prior_output{false};
    bool outer_fri_seed{false};
    uint32_t derived_lane{0};
    uint8_t byte_in_derived_lane{0};
    bool derived{false};
};

struct ProgramRows {
    std::vector<std::vector<uint32_t>> event_rows;
};

ProgramRows BuildProgramRows(
    const std::vector<Event>& program)
{
    ProgramRows out;
    out.event_rows.resize(program.size());
    uint32_t row = 1; // V14 receipt header.
    for (uint32_t event = 0;
         event < program.size(); ++event) {
        const uint32_t blocks =
            static_cast<uint32_t>(
                (program[event].message.size() + 7) / 8);
        out.event_rows[event].resize(blocks);
        for (uint32_t block = 0; block < blocks; ++block) {
            out.event_rows[event][block] = row++;
            bool proof_owned = false;
            for (uint32_t lane = 0; lane < 8; ++lane) {
                const uint32_t ordinal = 8 * block + lane;
                if (ordinal < program[event].message.size() &&
                    program[event].message[ordinal].binding ==
                        Binding::ProofOwned) {
                    proof_owned = true;
                }
            }
            if (proof_owned) ++row; // ReceiptMessage row.
            if (block + 1 == blocks) ++row; // ReceiptOutput row.
        }
    }
    return out;
}

bool SameManifest(
    const ManifestV1& left, const ManifestV1& right)
{
    return left.shape == right.shape &&
        left.canonical_program == right.canonical_program &&
        left.program_root == right.program_root &&
        left.byte_occurrences == right.byte_occurrences &&
        left.field_occurrences == right.field_occurrences &&
        left.selectors == right.selectors &&
        left.derived_hashes == right.derived_hashes &&
        left.canonical_abi_byte_occurrences ==
            right.canonical_abi_byte_occurrences &&
        left.prior_event_output_byte_occurrences ==
            right.prior_event_output_byte_occurrences &&
        left.derived_hash_byte_occurrences ==
            right.derived_hash_byte_occurrences &&
        left.protocol_constant_byte_occurrences ==
            right.protocol_constant_byte_occurrences &&
        left.outer_fri_seed_feedback_byte_occurrences ==
            right.outer_fri_seed_feedback_byte_occurrences &&
        left.query_seed_feedback_field_occurrences ==
            right.query_seed_feedback_field_occurrences &&
        left.proof_tape_schedule_regenerated ==
            right.proof_tape_schedule_regenerated &&
        left.canonical_program_rebuilt_from_shape ==
            right.canonical_program_rebuilt_from_shape &&
        left.public_program_exact_match ==
            right.public_program_exact_match &&
        left.every_abi_address_resolved ==
            right.every_abi_address_resolved &&
        left.every_consumer_destination_resolved ==
            right.every_consumer_destination_resolved &&
        left.no_native_verify_or_replay ==
            right.no_native_verify_or_replay &&
        left.selected_ood_ordinal_public ==
            right.selected_ood_ordinal_public &&
        left.selector_air_executed ==
            right.selector_air_executed &&
        left.derived_hash_air_executed ==
            right.derived_hash_air_executed &&
        left.consumer_equalities_executed ==
            right.consumer_equalities_executed &&
        left.recursively_consumed ==
            right.recursively_consumed &&
        left.recursive_authority_ready ==
            right.recursive_authority_ready &&
        left.valid == right.valid;
}

} // namespace

bool BuildCanonicalTypedProgramV1(
    const tape::PublicShapeV1& shape,
    std::vector<Event>& out,
    std::string* why)
{
    out.clear();
    tape::PublicBindingV1 binding;
    binding.program_root = uint256::ONE;
    binding.statement_root = uint256::ONE;
    binding.public_fs_seed = uint256::ONE;
    binding.proof_wire_root = uint256::ONE;
    if (!tape::BuildScheduleV1(shape, binding).valid) {
        return Fail(why, "typed_program_shape");
    }
    const uint32_t folds = Log2Exact(shape.n_coeffs);
    if (folds == 0) {
        return Fail(why, "typed_program_folds");
    }
    std::vector<uint32_t> extra{
        shape.trace_rows,
        shape.trace_columns,
        shape.quotient_len,
        shape.n_coeffs,
        static_cast<uint32_t>(
            shape.base_column_indices.size()),
    };
    extra.insert(
        extra.end(),
        shape.base_column_indices.begin(),
        shape.base_column_indices.end());
    const auto lambda_lanes =
        aq::AirChallengeP2Lanes(
            uint256::ONE,
            "airq_split_rap_constraint_safe_v2",
            {uint256::ONE, uint256::ONE}, extra);
    const auto fri_lanes =
        aq::AirChallengeP2Lanes(
            uint256::ONE,
            "airq_split_rap_fri_seed_safe_v2",
            {uint256::ONE, uint256::ONE, uint256::ONE},
            extra);
    out.push_back(OuterEvent(
        Kind::AirLambda, Role::TranscriptAirLambda,
        static_cast<uint32_t>(lambda_lanes.size())));
    out.push_back(OuterEvent(
        Kind::FriSeed, Role::TranscriptFriSeed,
        static_cast<uint32_t>(fri_lanes.size())));

    static constexpr char kMultiRowDomain[] =
        "BTX_RC_FRI3ALG_MULTI_ROW_RAP_SAFE_Q192_K2_V13";
    uint32_t prefix_bytes =
        sizeof(kMultiRowDomain) - 1 +
        32 + // child FS seed
        8 +  // PoW grind nonce
        4 * 4 + // blowup, n_coeffs, version, group count
        3 * (4 * 4 + 32) + // group shape and root
        4 +  // column count
        32;  // shape commitment
    const uint32_t ood_k =
        kRCFri3AlgSafeQ192K2OodCandidatesV13;
    for (uint32_t draw = 0; draw < 2 * ood_k; ++draw) {
        out.push_back(TranscriptEvent(
            draw < ood_k ? Kind::OodZ1 : Kind::OodZ2,
            "fra3_z", draw, prefix_bytes));
    }
    prefix_bytes += 2 * 3 * 8 + 32;
    out.push_back(TranscriptEvent(
        Kind::BatchCoefficient,
        "fra3_lambda", 0, prefix_bytes));
    prefix_bytes += 3 * 8;
    out.push_back(TranscriptEvent(
        Kind::DeepWeight1,
        "fra3_w", 0, prefix_bytes));
    out.push_back(TranscriptEvent(
        Kind::DeepWeight2,
        "fra3_w", 1, prefix_bytes));
    prefix_bytes += 2 * 3 * 8;
    for (uint32_t fold = 0; fold < folds; ++fold) {
        prefix_bytes += 32;
        out.push_back(TranscriptEvent(
            Kind::FoldBeta,
            "fra3_fold", fold, prefix_bytes));
    }
    prefix_bytes += 32;
    out.push_back(TranscriptEvent(
        Kind::QuerySeed,
        "fra3_query", 0, prefix_bytes));
    for (uint32_t query = 0;
         query < kRCFri3AlgNumQueries; ++query) {
        out.push_back(QueryCandidateEvent(query));
    }
    if (why != nullptr) {
        *why =
            "stage3:v13_occurrence_manifest:"
            "canonical_typed_program";
    }
    return true;
}

bool BuildCanonicalOccurrenceManifestV1(
    const tape::PublicShapeV1& shape,
    const std::vector<Event>& public_v14_program,
    ManifestV1& out,
    std::string* why)
{
    out = {};
    out.shape = shape;

    // BuildScheduleV1 currently also accepts public binding values although
    // its semantic key/address inventory depends only on shape.  Fixed,
    // non-null verifier constants make that separation explicit here.
    tape::PublicBindingV1 schedule_binding;
    schedule_binding.program_root = uint256::ONE;
    schedule_binding.statement_root = uint256::ONE;
    schedule_binding.public_fs_seed = uint256::ONE;
    schedule_binding.proof_wire_root = uint256::ONE;
    const tape::ScheduleV1 schedule =
        tape::BuildScheduleV1(shape, schedule_binding);
    if (!schedule.valid ||
        !schedule.semantic_schedule_regenerated ||
        !schedule.stable_addresses) {
        return Fail(why, "proof_tape_schedule");
    }
    out.proof_tape_schedule_regenerated = true;

    std::map<abi::SourceKeyV1, uint32_t> addresses;
    for (const auto& source : schedule.semantic_sources) {
        if (!addresses.emplace(source.key, source.address).second) {
            return Fail(why, "duplicate_abi_key");
        }
    }
    const auto address_of =
        [&](const abi::SourceKeyV1& key,
            uint32_t& address) {
            const auto found = addresses.find(key);
            if (found == addresses.end()) return false;
            address = found->second;
            return true;
        };

    std::vector<Event> expected;
    expected.reserve(
        2 + 2 * kRCFri3AlgSafeQ192K2OodCandidatesV13 +
        4 + Log2Exact(shape.n_coeffs) +
        kRCFri3AlgNumQueries);
    const std::vector<uint32_t> outer_extra = [&] {
        std::vector<uint32_t> extra{
            shape.trace_rows,
            shape.trace_columns,
            shape.quotient_len,
            shape.n_coeffs,
            static_cast<uint32_t>(
                shape.base_column_indices.size()),
        };
        extra.insert(
            extra.end(),
            shape.base_column_indices.begin(),
            shape.base_column_indices.end());
        return extra;
    }();
    const auto lambda_lanes =
        aq::AirChallengeP2Lanes(
            uint256::ONE,
            "airq_split_rap_constraint_safe_v2",
            {uint256::ONE, uint256::ONE},
            outer_extra);
    const auto fri_seed_lanes =
        aq::AirChallengeP2Lanes(
            uint256::ONE,
            "airq_split_rap_fri_seed_safe_v2",
            {uint256::ONE, uint256::ONE, uint256::ONE},
            outer_extra);
    expected.push_back(OuterEvent(
        Kind::AirLambda, Role::TranscriptAirLambda,
        static_cast<uint32_t>(lambda_lanes.size())));
    expected.push_back(OuterEvent(
        Kind::FriSeed, Role::TranscriptFriSeed,
        static_cast<uint32_t>(fri_seed_lanes.size())));

    std::vector<ByteOrigin> prefix;
    const auto append_constant_bytes =
        [&](size_t count) {
            prefix.insert(prefix.end(), count, ByteOrigin{});
        };
    const auto append_abi_u32 =
        [&](abi::SourceKeyV1 key,
            bool outer_feedback) {
            uint32_t address = UINT32_MAX;
            if (!address_of(key, address)) return false;
            for (uint32_t byte = 0; byte < 4; ++byte) {
                ByteOrigin source;
                source.kind = ByteSourceKindV1::CanonicalAbi;
                source.key = key;
                source.address = address;
                source.byte_in_word =
                    static_cast<uint8_t>(byte);
                source.abi_source = true;
                if (outer_feedback) {
                    const uint32_t absolute =
                        4 * key.a + byte;
                    source.event_begin = 1;
                    source.event_end = 1;
                    source.output_lane =
                        static_cast<uint8_t>(absolute / 8);
                    source.byte_in_output_lane =
                        static_cast<uint8_t>(absolute % 8);
                    source.prior_output = true;
                    source.outer_fri_seed = true;
                }
                prefix.push_back(source);
            }
            return true;
        };
    const auto append_abi_u64 =
        [&](abi::SourceKeyV1 key) {
            for (uint32_t limb = 0; limb < 2; ++limb) {
                auto part = key;
                part.limb = static_cast<uint8_t>(limb);
                if (!append_abi_u32(part, false)) return false;
            }
            return true;
        };
    const auto append_abi_digest =
        [&](abi::FieldKindV1 kind, uint32_t item) {
            for (uint32_t lane = 0; lane < 4; ++lane) {
                abi::SourceKeyV1 key{
                    kind, item, 0, 0, lane, 0};
                if (!append_abi_u64(key)) return false;
            }
            return true;
        };
    const auto append_derived =
        [&](ByteSourceKindV1 kind) {
            for (uint32_t lane = 0; lane < 4; ++lane) {
                for (uint32_t byte = 0; byte < 8; ++byte) {
                    ByteOrigin source;
                    source.kind = kind;
                    source.derived_lane = lane;
                    source.byte_in_derived_lane =
                        static_cast<uint8_t>(byte);
                    source.derived = true;
                    prefix.push_back(source);
                }
            }
        };
    const auto append_prior_fp3 =
        [&](uint32_t first, uint32_t last,
            SelectorFamilyV1 selector) {
            for (uint32_t lane = 0; lane < 3; ++lane) {
                for (uint32_t byte = 0; byte < 8; ++byte) {
                    ByteOrigin source;
                    source.kind =
                        ByteSourceKindV1::PriorEventOutput;
                    source.event_begin = first;
                    source.event_end = last;
                    source.output_lane =
                        static_cast<uint8_t>(lane);
                    source.byte_in_output_lane =
                        static_cast<uint8_t>(byte);
                    source.selector = selector;
                    source.prior_output = true;
                    prefix.push_back(source);
                }
            }
        };

    static constexpr char kMultiRowDomain[] =
        "BTX_RC_FRI3ALG_MULTI_ROW_RAP_SAFE_Q192_K2_V13";
    append_constant_bytes(sizeof(kMultiRowDomain) - 1);
    for (uint32_t word = 0; word < 8; ++word) {
        if (!append_abi_u32(
                {abi::FieldKindV1::PublicFsSeed,
                 word, 0, 0, 0, 0},
                true)) {
            return Fail(why, "public_seed_abi");
        }
    }
    if (!append_abi_u64(
            {abi::FieldKindV1::PowGrindNonce}) ||
        !append_abi_u32(
            {abi::FieldKindV1::Blowup}, false) ||
        !append_abi_u32(
            {abi::FieldKindV1::NCoeffs}, false) ||
        !append_abi_u32(
            {abi::FieldKindV1::BatchVersion}, false) ||
        !append_abi_u32(
            {abi::FieldKindV1::GroupCount}, false)) {
        return Fail(why, "initial_scalar_abi");
    }
    for (uint32_t group = 0; group < 3; ++group) {
        if (!append_abi_u32(
                {abi::FieldKindV1::GroupRole,
                 group, 0, 0, 0, 0}, false) ||
            !append_abi_u32(
                {abi::FieldKindV1::GroupFirstColumn,
                 group, 0, 0, 0, 0}, false) ||
            !append_abi_u32(
                {abi::FieldKindV1::GroupColumnCount,
                 group, 0, 0, 0, 0}, false) ||
            !append_abi_u32(
                {abi::FieldKindV1::GroupLeaves,
                 group, 0, 0, 0, 0}, false) ||
            !append_abi_digest(
                abi::FieldKindV1::GroupRoot, group)) {
            return Fail(why, "group_abi");
        }
    }
    if (!append_abi_u32(
            {abi::FieldKindV1::ColumnCount}, false)) {
        return Fail(why, "column_count_abi");
    }
    append_derived(ByteSourceKindV1::DerivedShapeCommit);

    std::vector<std::vector<ByteOrigin>> event_prefix;
    const auto add_transcript_event =
        [&](Kind kind, const char* label,
            uint32_t index) {
            expected.push_back(
                TranscriptEvent(
                    kind, label, index,
                    static_cast<uint32_t>(
                        prefix.size())));
            event_prefix.push_back(prefix);
        };

    const uint32_t ood_k =
        kRCFri3AlgSafeQ192K2OodCandidatesV13;
    for (uint32_t draw = 0; draw < 2 * ood_k; ++draw) {
        add_transcript_event(
            draw < ood_k ? Kind::OodZ1 : Kind::OodZ2,
            "fra3_z", draw);
    }
    // Program event indices include the two outer events.
    append_prior_fp3(
        kOuterEventCountV1,
        kOuterEventCountV1 + ood_k - 1,
        SelectorFamilyV1::OodZ1FirstAcceptable);
    append_prior_fp3(
        kOuterEventCountV1 + ood_k,
        kOuterEventCountV1 + 2 * ood_k - 1,
        SelectorFamilyV1::
            OodZ2FirstAcceptableDistinctFromZ1);
    append_derived(
        ByteSourceKindV1::DerivedOodEvalCommit);

    const uint32_t lambda_event =
        kOuterEventCountV1 + 2 * ood_k;
    add_transcript_event(
        Kind::BatchCoefficient,
        "fra3_lambda", 0);
    append_prior_fp3(
        lambda_event, lambda_event,
        SelectorFamilyV1::None);

    const uint32_t w1_event = lambda_event + 1;
    const uint32_t w2_event = lambda_event + 2;
    add_transcript_event(Kind::DeepWeight1, "fra3_w", 0);
    add_transcript_event(Kind::DeepWeight2, "fra3_w", 1);
    append_prior_fp3(
        w1_event, w1_event, SelectorFamilyV1::None);
    append_prior_fp3(
        w2_event, w2_event, SelectorFamilyV1::None);

    const uint32_t folds = Log2Exact(shape.n_coeffs);
    if (folds == 0) {
        return Fail(why, "fold_shape");
    }
    for (uint32_t fold = 0; fold < folds; ++fold) {
        if (!append_abi_digest(
                abi::FieldKindV1::FoldRoot, fold)) {
            return Fail(why, "fold_root_abi");
        }
        add_transcript_event(
            Kind::FoldBeta, "fra3_fold", fold);
    }
    if (!append_abi_digest(
            abi::FieldKindV1::FoldRoot, folds)) {
        return Fail(why, "terminal_fold_root_abi");
    }
    const uint32_t query_seed_event =
        static_cast<uint32_t>(expected.size());
    add_transcript_event(
        Kind::QuerySeed, "fra3_query", 0);

    const uint32_t first_query_event =
        static_cast<uint32_t>(expected.size());
    for (uint32_t query = 0;
         query < kRCFri3AlgNumQueries; ++query) {
        expected.push_back(QueryCandidateEvent(query));
    }
    std::vector<Event> shape_program;
    if (!BuildCanonicalTypedProgramV1(
            shape, shape_program, why) ||
        shape_program != expected) {
        return Fail(why, "independent_program_rebuild");
    }
    out.canonical_program_rebuilt_from_shape = true;
    if (expected != public_v14_program) {
        return Fail(why, "public_program_mismatch");
    }
    out.public_program_exact_match = true;
    out.canonical_program = expected;
    out.program_root =
        bridge::CommitTypedSafeEventProgramV13(expected);
    if (out.program_root == alg_hash::Digest{}) {
        return Fail(why, "program_root");
    }

    const ProgramRows rows = BuildProgramRows(expected);
    const bridge::TypedSafeDirectParentLayoutV14 layout;
    if (event_prefix.size() !=
        query_seed_event - kOuterEventCountV1 + 1) {
        return Fail(why, "event_prefix_inventory");
    }
    for (uint32_t child_event = 0;
         child_event < event_prefix.size(); ++child_event) {
        const uint32_t event =
            child_event + kOuterEventCountV1;
        const auto& sources = event_prefix[child_event];
        for (uint32_t offset = 0;
             offset < sources.size(); ++offset) {
            const uint32_t ordinal = 4 + offset / 4;
            if (ordinal >= expected[event].message.size() ||
                expected[event].message[ordinal].binding !=
                    Binding::ProofOwned) {
                return Fail(why, "consumer_program_cell");
            }
            const auto& source = sources[offset];
            ByteOccurrenceV1 occurrence;
            occurrence.source_kind = source.kind;
            occurrence.abi_key = source.key;
            occurrence.abi_source_address = source.address;
            occurrence.byte_in_abi_word =
                source.byte_in_word;
            occurrence.canonical_abi_source =
                source.abi_source;
            occurrence.source_event_begin =
                source.event_begin;
            occurrence.source_event_end =
                source.event_end;
            occurrence.source_output_lane =
                source.output_lane;
            occurrence.byte_in_output_lane =
                source.byte_in_output_lane;
            occurrence.selector_family =
                source.selector;
            occurrence.prior_event_output_source =
                source.prior_output;
            occurrence.outer_fri_seed_feedback_source =
                source.outer_fri_seed;
            occurrence.derived_output_lane =
                source.derived_lane;
            occurrence.byte_in_derived_lane =
                source.byte_in_derived_lane;
            occurrence.derived_hash_source =
                source.derived;
            occurrence.consumer_event = event;
            occurrence.consumer_message_ordinal =
                ordinal;
            occurrence.byte_in_message_word =
                static_cast<uint8_t>(offset % 4);
            occurrence.consumer_row =
                rows.event_rows[event][ordinal / 8];
            occurrence.consumer_column =
                layout.Message(ordinal % 8);
            out.byte_occurrences.push_back(
                occurrence);

            if (source.abi_source) {
                ++out.canonical_abi_byte_occurrences;
            } else if (source.derived) {
                ++out.derived_hash_byte_occurrences;
            } else if (source.prior_output) {
                ++out.prior_event_output_byte_occurrences;
            } else {
                ++out.protocol_constant_byte_occurrences;
            }
            if (source.outer_fri_seed) {
                ++out
                    .outer_fri_seed_feedback_byte_occurrences;
            }
        }
    }
    for (uint32_t query = 0;
         query < kRCFri3AlgNumQueries; ++query) {
        const uint32_t event = first_query_event + query;
        for (uint32_t lane = 0; lane < 4; ++lane) {
            const uint32_t ordinal = 4 + lane;
            out.field_occurrences.push_back({
                query_seed_event,
                static_cast<uint8_t>(lane),
                event,
                ordinal,
                rows.event_rows[event][ordinal / 8],
                layout.Message(ordinal % 8),
            });
            ++out.query_seed_feedback_field_occurrences;
        }
    }

    out.selectors = {{
        {
            SelectorFamilyV1::OodZ1FirstAcceptable,
            {kOuterEventCountV1,
             kOuterEventCountV1 + ood_k - 1},
            true, true, true,
        },
        {
            SelectorFamilyV1::
                OodZ2FirstAcceptableDistinctFromZ1,
            {kOuterEventCountV1 + ood_k,
             kOuterEventCountV1 + 2 * ood_k - 1},
            true, true, true,
        },
    }};

    auto shape_hash = DerivedHashV1{};
    shape_hash.kind = DerivedHashKindV1::ShapeCommit;
    shape_hash.direct_input_keys.push_back(
        {abi::FieldKindV1::NCoeffs});
    for (uint32_t column = 0;
         column < shape.trace_columns + 1; ++column) {
        shape_hash.direct_input_keys.push_back({
            abi::FieldKindV1::ColumnLen,
            column, 0, 0, 0, 0});
    }
    shape_hash.input_inventory_shape_derived = true;

    auto ood_hash = DerivedHashV1{};
    ood_hash.kind =
        DerivedHashKindV1::OodEvaluationCommit;
    const auto append_fp3_keys =
        [](std::vector<abi::SourceKeyV1>& keys,
           abi::FieldKindV1 kind,
           uint32_t item) {
            for (uint32_t coordinate = 0;
                 coordinate < 3; ++coordinate) {
                for (uint32_t limb = 0; limb < 2; ++limb) {
                    keys.push_back({
                        kind, item, 0, 0,
                        coordinate,
                        static_cast<uint8_t>(limb)});
                }
            }
        };
    append_fp3_keys(
        ood_hash.direct_input_keys,
        abi::FieldKindV1::Z1, 0);
    append_fp3_keys(
        ood_hash.direct_input_keys,
        abi::FieldKindV1::Z2, 0);
    ood_hash.direct_input_keys.push_back(
        {abi::FieldKindV1::EvalZ1Count});
    ood_hash.direct_input_keys.push_back(
        {abi::FieldKindV1::EvalZ2Count});
    for (uint32_t column = 0;
         column < shape.trace_columns + 1; ++column) {
        append_fp3_keys(
            ood_hash.direct_input_keys,
            abi::FieldKindV1::EvalZ1, column);
        append_fp3_keys(
            ood_hash.direct_input_keys,
            abi::FieldKindV1::EvalZ2, column);
    }
    ood_hash.selected_event_inputs = {
        SelectorFamilyV1::OodZ1FirstAcceptable,
        SelectorFamilyV1::
            OodZ2FirstAcceptableDistinctFromZ1,
    };
    ood_hash.input_inventory_shape_derived = true;
    out.derived_hashes = {
        std::move(shape_hash),
        std::move(ood_hash),
    };

    bool all_hash_inputs_resolved = true;
    for (const auto& hash : out.derived_hashes) {
        for (const auto& key : hash.direct_input_keys) {
            all_hash_inputs_resolved &=
                addresses.count(key) == 1;
        }
    }
    out.every_abi_address_resolved =
        out.canonical_abi_byte_occurrences > 0 &&
        all_hash_inputs_resolved &&
        std::all_of(
            out.byte_occurrences.begin(),
            out.byte_occurrences.end(),
            [&](const ByteOccurrenceV1& occurrence) {
                if (!occurrence.canonical_abi_source) {
                    return true;
                }
                const auto found =
                    addresses.find(occurrence.abi_key);
                return found != addresses.end() &&
                    found->second ==
                        occurrence.abi_source_address;
            });
    out.every_consumer_destination_resolved =
        !out.byte_occurrences.empty() &&
        !out.field_occurrences.empty() &&
        std::all_of(
            out.byte_occurrences.begin(),
            out.byte_occurrences.end(),
            [&](const ByteOccurrenceV1& occurrence) {
                return occurrence.consumer_event <
                        expected.size() &&
                    occurrence.consumer_message_ordinal <
                        expected[occurrence.consumer_event]
                            .message.size();
            });
    out.no_native_verify_or_replay = true;
    out.selected_ood_ordinal_public = false;
    out.selector_air_executed = false;
    out.derived_hash_air_executed = false;
    out.consumer_equalities_executed = false;
    out.recursively_consumed = false;
    out.recursive_authority_ready = false;
    out.valid =
        out.proof_tape_schedule_regenerated &&
        out.canonical_program_rebuilt_from_shape &&
        out.public_program_exact_match &&
        out.every_abi_address_resolved &&
        out.every_consumer_destination_resolved &&
        out.no_native_verify_or_replay &&
        !out.selected_ood_ordinal_public &&
        out.outer_fri_seed_feedback_byte_occurrences ==
            32 * event_prefix.size() &&
        out.query_seed_feedback_field_occurrences ==
            4 * kRCFri3AlgNumQueries &&
        !out.selector_air_executed &&
        !out.derived_hash_air_executed &&
        !out.consumer_equalities_executed &&
        !out.recursively_consumed &&
        !out.recursive_authority_ready;
    out.note = out.valid
        ? "verifier-owned V13/V14 occurrence manifest; selector, "
          "derived-hash and consumer equality AIRs remain explicit"
        : "occurrence manifest incomplete";
    if (!out.valid) {
        return Fail(
            why,
            "incomplete:"
            "tape=" +
                std::to_string(
                    out.proof_tape_schedule_regenerated) +
            ":program=" +
                std::to_string(
                    out.canonical_program_rebuilt_from_shape) +
            ":match=" +
                std::to_string(
                    out.public_program_exact_match) +
            ":abi=" +
                std::to_string(
                    out.every_abi_address_resolved) +
            ":consumer=" +
                std::to_string(
                    out.every_consumer_destination_resolved) +
            ":outer=" +
                std::to_string(
                    out.outer_fri_seed_feedback_byte_occurrences) +
            ":query=" +
                std::to_string(
                    out.query_seed_feedback_field_occurrences));
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool ValidateCanonicalOccurrenceManifestV1(
    const tape::PublicShapeV1& shape,
    const std::vector<Event>& public_v14_program,
    const ManifestV1& claimed,
    std::string* why)
{
    ManifestV1 rebuilt;
    std::string build_why;
    if (!BuildCanonicalOccurrenceManifestV1(
            shape, public_v14_program,
            rebuilt, &build_why)) {
        return Fail(
            why, "rebuild:" + build_why);
    }
    if (!SameManifest(rebuilt, claimed)) {
        return Fail(why, "claimed_manifest_mismatch");
    }
    if (why != nullptr) {
        *why =
            "stage3:v13_occurrence_manifest:validated";
    }
    return true;
}

} // namespace matmul::v4::rc::stage3_v13_occurrence_manifest
