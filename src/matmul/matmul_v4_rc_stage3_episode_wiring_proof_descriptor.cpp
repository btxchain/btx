// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#include <matmul/matmul_v4_rc_stage3_episode_wiring_proof_descriptor.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_gkr_wiring.h>

#include <algorithm>
#include <limits>

namespace matmul::v4::rc::stage3_episode_wiring_proof_descriptor {
namespace {

using gf::Fp3;
using LegacyProof = aq::AirQuotientProof<Fp3>;
using AirCs = aq::AirConstraintSystem<Fp3>;

constexpr char SCHEDULE_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_WIRING_PROOF_DESCRIPTOR_SCHEDULE_V1";
constexpr char WIRE_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_WIRING_PROOF_DESCRIPTOR_WIRE_V1";
constexpr char CHALLENGE_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_WIRING_PROOF_DESCRIPTOR_CHALLENGE_V1";
constexpr char PROOF_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_WIRING_PROOF_DESCRIPTOR_PROOF_V1";

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:episode_wiring_proof_descriptor:" +
            detail;
    }
    return false;
}

uint32_t ReadU32(const unsigned char* bytes)
{
    return static_cast<uint32_t>(bytes[0]) |
        (static_cast<uint32_t>(bytes[1]) << 8) |
        (static_cast<uint32_t>(bytes[2]) << 16) |
        (static_cast<uint32_t>(bytes[3]) << 24);
}

uint32_t NextPowerOfTwo(uint64_t value)
{
    if (value == 0 || value > (uint64_t{1} << 31)) {
        return 0;
    }
    uint64_t out = 2;
    while (out < value) out <<= 1;
    return static_cast<uint32_t>(out);
}

bool Push(
    std::vector<RecordV1>& records,
    const OwnerV1& owner,
    RecordKindV1 kind,
    std::array<uint32_t, 4> coordinate,
    uint32_t value)
{
    if (records.size() >= kMaxRecordsV1 ||
        records.size() >
            std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    RecordV1 record;
    record.ordinal =
        static_cast<uint32_t>(records.size());
    record.owner = owner;
    record.kind = kind;
    record.coordinate = coordinate;
    record.value = value;
    records.push_back(record);
    return true;
}

bool PushU64(
    std::vector<RecordV1>& records,
    const OwnerV1& owner,
    RecordKindV1 kind,
    uint32_t field,
    uint32_t a,
    uint32_t b,
    uint64_t value)
{
    return
        Push(records, owner, kind, {field, a, b, 0},
             static_cast<uint32_t>(value)) &&
        Push(records, owner, kind, {field, a, b, 1},
             static_cast<uint32_t>(value >> 32));
}

bool PushHash(
    std::vector<RecordV1>& records,
    const OwnerV1& owner,
    RecordKindV1 kind,
    uint32_t field,
    uint32_t a,
    uint32_t b,
    const uint256& value)
{
    for (uint32_t limb = 0; limb < 8; ++limb) {
        if (!Push(
                records, owner, kind,
                {field, a, b, limb},
                ReadU32(value.data() + 4 * limb))) {
            return false;
        }
    }
    return true;
}

bool PushFp3(
    std::vector<RecordV1>& records,
    const OwnerV1& owner,
    RecordKindV1 kind,
    uint32_t field,
    uint32_t a,
    const Fp3& value)
{
    const std::array<uint64_t, 3> components{{
        gf::Canonical(value.c0),
        gf::Canonical(value.c1),
        gf::Canonical(value.c2),
    }};
    for (uint32_t component = 0;
         component < components.size(); ++component) {
        const uint64_t canonical =
            components[component];
        uint64_t decoded = 0;
        const uint32_t low =
            static_cast<uint32_t>(canonical);
        const uint32_t high =
            static_cast<uint32_t>(canonical >> 32);
        if (!DecodeCanonicalFpWordPairV1(
                low, high, decoded) ||
            decoded != canonical ||
            !Push(
                records, owner, kind,
                {field, a, component, 0}, low) ||
            !Push(
                records, owner, kind,
                {field, a, component, 1}, high)) {
            return false;
        }
    }
    return true;
}

bool PushLength(
    std::vector<RecordV1>& records,
    const OwnerV1& owner,
    uint32_t field,
    uint32_t a,
    uint32_t b,
    size_t value)
{
    return
        value <= std::numeric_limits<uint32_t>::max() &&
        Push(
            records, owner,
            RecordKindV1::ProofVectorLength,
            {field, a, b, 0},
            static_cast<uint32_t>(value));
}

bool AppendPin(
    const OwnerV1& owner,
    const RCStage3EpisodeWiringAirPin& pin,
    std::vector<RecordV1>& records)
{
    if (!Push(
            records, owner, RecordKindV1::EdgePinField,
            {0, 0, 0, 0}, pin.version) ||
        !Push(
            records, owner, RecordKindV1::EdgePinField,
            {1, 0, 0, 0},
            static_cast<uint32_t>(pin.endpoint)) ||
        !PushHash(
            records, owner, RecordKindV1::EdgePinField,
            2, 0, 0, pin.statement_commitment) ||
        !PushHash(
            records, owner, RecordKindV1::EdgePinField,
            3, 0, 0, pin.manifest_commitment) ||
        !Push(
            records, owner, RecordKindV1::EdgePinField,
            {4, 0, 0, 0}, pin.schedule_index) ||
        !Push(
            records, owner, RecordKindV1::EdgePinField,
            {5, 0, 0, 0}, pin.logical_rows) ||
        !Push(
            records, owner, RecordKindV1::EdgePinField,
            {6, 0, 0, 0}, pin.n_rows) ||
        !PushHash(
            records, owner, RecordKindV1::EdgePinField,
            7, 0, 0, pin.challenge_seed) ||
        !PushLength(
            records, owner, 8, 0, 0,
            pin.column_roots.size())) {
        return false;
    }
    for (uint32_t i = 0;
         i < pin.column_roots.size(); ++i) {
        if (!Push(
                records, owner,
                RecordKindV1::EdgePinField,
                {9, i, 0, 0},
                pin.column_roots[i].column) ||
            !PushHash(
                records, owner,
                RecordKindV1::EdgePinField,
                10, i, 0,
                pin.column_roots[i].root)) {
            return false;
        }
    }
    return PushHash(
        records, owner, RecordKindV1::EdgePinField,
        11, 0, 0, pin.pin_commitment);
}

bool AppendMemoryManifest(
    const OwnerV1& owner,
    const RCStage3EpisodeSemanticMemoryManifest& manifest,
    std::vector<RecordV1>& records)
{
    return
        Push(records, owner,
             RecordKindV1::MemoryManifestField,
             {0, 0, 0, 0}, manifest.magic) &&
        Push(records, owner,
             RecordKindV1::MemoryManifestField,
             {1, 0, 0, 0}, manifest.version) &&
        Push(records, owner,
             RecordKindV1::MemoryManifestField,
             {2, 0, 0, 0},
             static_cast<uint32_t>(manifest.endpoint)) &&
        Push(records, owner,
             RecordKindV1::MemoryManifestField,
             {3, 0, 0, 0},
             static_cast<uint32_t>(manifest.role)) &&
        PushHash(records, owner,
                 RecordKindV1::MemoryManifestField,
                 4, 0, 0,
                 manifest.statement_commitment) &&
        PushU64(records, owner,
                RecordKindV1::MemoryManifestField,
                5, 0, 0, manifest.instance_count) &&
        Push(records, owner,
             RecordKindV1::MemoryManifestField,
             {6, 0, 0, 0}, manifest.logical_rows) &&
        Push(records, owner,
             RecordKindV1::MemoryManifestField,
             {7, 0, 0, 0}, manifest.n_rows) &&
        PushU64(records, owner,
                RecordKindV1::MemoryManifestField,
                8, 0, 0, manifest.address_begin) &&
        PushU64(records, owner,
                RecordKindV1::MemoryManifestField,
                9, 0, 0, manifest.address_stride) &&
        PushHash(records, owner,
                 RecordKindV1::MemoryManifestField,
                 10, 0, 0,
                 manifest.canonical_value_root) &&
        PushHash(records, owner,
                 RecordKindV1::MemoryManifestField,
                 11, 0, 0,
                 manifest.schedule_commitment) &&
        PushHash(records, owner,
                 RecordKindV1::MemoryManifestField,
                 12, 0, 0,
                 manifest.manifest_commitment);
}

bool AppendMemoryBundle(
    OwnerFamilyV1 family,
    OwnerSectionV1 section,
    uint32_t edge_ordinal,
    const RCStage3EpisodeSemanticMemoryBundle& bundle,
    std::vector<RecordV1>& records,
    uint32_t& proof_count,
    std::string* why)
{
    OwnerV1 bundle_owner{
        family, section, edge_ordinal, UINT32_MAX};
    if (!Push(records, bundle_owner,
              RecordKindV1::MemoryBundleField,
              {0, 0, 0, 0}, bundle.version) ||
        !Push(records, bundle_owner,
              RecordKindV1::MemoryBundleField,
              {1, 0, 0, 0},
              static_cast<uint32_t>(bundle.endpoint)) ||
        !PushHash(records, bundle_owner,
                  RecordKindV1::MemoryBundleField,
                  2, 0, 0,
                  bundle.statement_commitment) ||
        !PushU64(records, bundle_owner,
                 RecordKindV1::MemoryBundleField,
                 3, 0, 0,
                 bundle.total_instance_count) ||
        !PushU64(records, bundle_owner,
                 RecordKindV1::MemoryBundleField,
                 4, 0, 0, bundle.address_begin) ||
        !PushU64(records, bundle_owner,
                 RecordKindV1::MemoryBundleField,
                 5, 0, 0, bundle.address_stride) ||
        !PushLength(records, bundle_owner, 6, 0, 0,
                    bundle.shards.size())) {
        return Fail(why, "memory_bundle_envelope");
    }
    for (uint32_t shard_index = 0;
         shard_index < bundle.shards.size();
         ++shard_index) {
        const auto& shard = bundle.shards[shard_index];
        OwnerV1 owner{
            family, section, edge_ordinal, shard_index};
        if (shard.shard_index != shard_index ||
            !Push(records, owner,
                  RecordKindV1::MemoryShardField,
                  {0, 0, 0, 0}, shard.shard_index) ||
            !PushU64(records, owner,
                     RecordKindV1::MemoryShardField,
                     1, 0, 0, shard.value_begin) ||
            !AppendMemoryManifest(
                owner, shard.manifest, records) ||
            !Push(records, owner,
                  RecordKindV1::MemoryProofField,
                  {0, 0, 0, 0},
                  shard.proof.version) ||
            !PushHash(records, owner,
                      RecordKindV1::MemoryProofField,
                      1, 0, 0,
                      shard.proof.manifest_commitment) ||
            !AppendCanonicalLegacyProofRecordsV1(
                owner, shard.proof.quotient,
                records, why)) {
            return Fail(
                why,
                "memory_shard:" +
                    std::to_string(shard_index));
        }
        ++proof_count;
    }
    return PushHash(
        records, bundle_owner,
        RecordKindV1::MemoryBundleField,
        7, 0, 0, bundle.bundle_commitment);
}

template <typename Schedule>
bool AppendScheduleCommon(
    const OwnerV1& owner,
    const Schedule& schedule,
    std::vector<RecordV1>& records)
{
    return Push(
        records, owner, RecordKindV1::EdgeScheduleField,
        {0, 0, 0, 0}, schedule.schedule_index);
}

bool AppendTransposeSchedule(
    const OwnerV1& owner,
    const RCStage3EpisodeWiringTransposeSchedule& schedule,
    std::vector<RecordV1>& records)
{
    return
        AppendScheduleCommon(owner, schedule, records) &&
        Push(records, owner,
             RecordKindV1::EdgeScheduleField,
             {1, 0, 0, 0}, schedule.layer_ordinal) &&
        Push(records, owner,
             RecordKindV1::EdgeScheduleField,
             {2, 0, 0, 0},
             static_cast<uint32_t>(schedule.slot)) &&
        Push(records, owner,
             RecordKindV1::EdgeScheduleField,
             {3, 0, 0, 0}, schedule.first_column) &&
        Push(records, owner,
             RecordKindV1::EdgeScheduleField,
             {4, 0, 0, 0}, schedule.n_chunks) &&
        Push(records, owner,
             RecordKindV1::EdgeScheduleField,
             {5, 0, 0, 0}, schedule.source_rows) &&
        Push(records, owner,
             RecordKindV1::EdgeScheduleField,
             {6, 0, 0, 0}, schedule.source_cols) &&
        PushU64(records, owner,
                RecordKindV1::EdgeScheduleField,
                7, 0, 0, schedule.value_count) &&
        PushHash(records, owner,
                 RecordKindV1::EdgeScheduleField,
                 8, 0, 0,
                 schedule.registered_source_root);
}

bool AppendResidualSchedule(
    const OwnerV1& owner,
    const RCStage3EpisodeWiringResidualSchedule& schedule,
    std::vector<RecordV1>& records)
{
    return
        AppendScheduleCommon(owner, schedule, records) &&
        Push(records, owner,
             RecordKindV1::EdgeScheduleField,
             {1, 0, 0, 0}, schedule.layer_ordinal) &&
        Push(records, owner,
             RecordKindV1::EdgeScheduleField,
             {2, 0, 0, 0},
             schedule.residual_first_column) &&
        Push(records, owner,
             RecordKindV1::EdgeScheduleField,
             {3, 0, 0, 0},
             schedule.residual_n_chunks) &&
        PushU64(records, owner,
                RecordKindV1::EdgeScheduleField,
                4, 0, 0, schedule.value_count) &&
        PushHash(records, owner,
                 RecordKindV1::EdgeScheduleField,
                 5, 0, 0,
                 schedule.registered_y_root) &&
        PushHash(records, owner,
                 RecordKindV1::EdgeScheduleField,
                 6, 0, 0,
                 schedule.registered_residual_root);
}

bool AppendOrderSchedule(
    const OwnerV1& owner,
    const RCStage3EpisodeWiringRoundOrderSchedule& schedule,
    std::vector<RecordV1>& records)
{
    return
        AppendScheduleCommon(owner, schedule, records) &&
        Push(records, owner,
             RecordKindV1::EdgeScheduleField,
             {1, 0, 0, 0},
             schedule.producer_layer_ordinal) &&
        Push(records, owner,
             RecordKindV1::EdgeScheduleField,
             {2, 0, 0, 0},
             schedule.consumer_layer_ordinal) &&
        Push(records, owner,
             RecordKindV1::EdgeScheduleField,
             {3, 0, 0, 0}, schedule.round_index) &&
        Push(records, owner,
             RecordKindV1::EdgeScheduleField,
             {4, 0, 0, 0}, schedule.first_column) &&
        Push(records, owner,
             RecordKindV1::EdgeScheduleField,
             {5, 0, 0, 0}, schedule.n_chunks) &&
        PushU64(records, owner,
                RecordKindV1::EdgeScheduleField,
                6, 0, 0, schedule.value_count) &&
        PushHash(records, owner,
                 RecordKindV1::EdgeScheduleField,
                 7, 0, 0,
                 schedule.registered_consumer_root);
}

void HashOwner(HashWriter& hash, const OwnerV1& owner)
{
    hash << static_cast<uint8_t>(owner.family);
    hash << static_cast<uint8_t>(owner.section);
    hash << owner.edge_ordinal;
    hash << owner.shard_ordinal;
}

void HashRecordMetadata(
    HashWriter& hash,
    const RecordV1& record)
{
    hash << record.ordinal;
    HashOwner(hash, record.owner);
    hash << static_cast<uint16_t>(record.kind);
    for (uint32_t coordinate : record.coordinate) {
        hash << coordinate;
    }
}

uint256 DeriveProofSeed(
    const ManifestV1& manifest,
    const std::array<Fp3, kTerminalLanesV1>& terminal)
{
    HashWriter hash;
    hash << PROOF_DOMAIN;
    hash << kVersionV1;
    hash << manifest.product_commitment;
    hash << manifest.statement_commitment;
    hash << manifest.schedule_root;
    hash << manifest.proof_wire_root;
    hash << static_cast<uint32_t>(manifest.records.size());
    for (const Fp3& lane : terminal) {
        hash << gf::Canonical(lane.c0);
        hash << gf::Canonical(lane.c1);
        hash << gf::Canonical(lane.c2);
    }
    return hash.GetHash();
}

bool AddPreprocessed(
    AirCs& cs,
    uint32_t column,
    std::vector<Fp3> values)
{
    if (column >= cs.n_columns ||
        values.size() != cs.n_rows) {
        return false;
    }
    cs.preprocessed.emplace_back(
        column, std::move(values));
    return true;
}

void AddConstraint(
    AirCs& cs,
    const char* name,
    aq::AirKind kind,
    uint32_t degree,
    std::function<Fp3(
        const std::vector<Fp3>&,
        const std::vector<Fp3>&)> eval)
{
    aq::AirConstraint<Fp3> constraint;
    constraint.name = name;
    constraint.kind = kind;
    constraint.alg_degree = degree;
    constraint.eval = std::move(eval);
    cs.constraints.push_back(std::move(constraint));
}

uint32_t CountViolations(
    const AirCs& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() != cs.n_columns) {
        return UINT32_MAX;
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) {
            return UINT32_MAX;
        }
    }
    uint32_t violations = 0;
    std::vector<Fp3> current(cs.n_columns);
    std::vector<Fp3> next(cs.n_columns);
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        for (uint32_t column = 0;
             column < cs.n_columns; ++column) {
            current[column] = columns[column][row];
            next[column] =
                columns[column][(row + 1) % cs.n_rows];
        }
        for (const auto& constraint : cs.constraints) {
            const bool applies =
                constraint.kind == aq::AirKind::kEverywhere ||
                (constraint.kind == aq::AirKind::kTransition &&
                 row + 1 < cs.n_rows) ||
                (constraint.kind == aq::AirKind::kFirstRow &&
                 row == 0) ||
                (constraint.kind == aq::AirKind::kLastRow &&
                 row + 1 == cs.n_rows);
            if (applies &&
                !gf::IsZero(
                    constraint.eval(current, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

bool CanonicalProof(
    const AirQuotientProofAlg& proof,
    std::vector<unsigned char>& bytes,
    std::string* why)
{
    bytes.clear();
    if (!SerializeAirQuotientProofAlg(
            proof, bytes, why)) {
        return false;
    }
    const auto decoded =
        DeserializeAirQuotientProofAlg(bytes, why);
    if (!decoded.has_value()) {
        return false;
    }
    std::vector<unsigned char> again;
    return
        SerializeAirQuotientProofAlg(
            *decoded, again, why) &&
        again == bytes;
}

bool SameTerminal(
    const std::array<Fp3, kTerminalLanesV1>& lhs,
    const std::array<Fp3, kTerminalLanesV1>& rhs)
{
    for (uint32_t lane = 0;
         lane < kTerminalLanesV1; ++lane) {
        if (!gf::Eq(lhs[lane], rhs[lane])) {
            return false;
        }
    }
    return true;
}

} // namespace

bool DecodeCanonicalFpWordPairV1(
    uint32_t low,
    uint32_t high,
    uint64_t& out)
{
    out = uint64_t{low} | (uint64_t{high} << 32);
    if (out >= gf::kP) {
        out = 0;
        return false;
    }
    return true;
}

bool AppendCanonicalLegacyProofRecordsV1(
    const OwnerV1& owner,
    const LegacyProof& proof,
    std::vector<RecordV1>& records,
    std::string* why)
{
    const auto& batch = proof.batch;
    if (!Push(records, owner, RecordKindV1::BatchHeader,
              {0, 0, 0, 0}, batch.version) ||
        !PushU64(records, owner,
                 RecordKindV1::BatchHeader,
                 1, 0, 0, batch.pow_grind_nonce) ||
        !Push(records, owner, RecordKindV1::BatchHeader,
              {2, 0, 0, 0}, batch.blowup) ||
        !Push(records, owner, RecordKindV1::BatchHeader,
              {3, 0, 0, 0}, batch.n_coeffs) ||
        !PushLength(records, owner, 0, 0, 0,
                    batch.columns.size())) {
        return Fail(why, "batch_header");
    }
    for (uint32_t column = 0;
         column < batch.columns.size(); ++column) {
        if (!PushHash(
                records, owner,
                RecordKindV1::ColumnRoot,
                0, column, 0,
                batch.columns[column].root) ||
            !Push(
                records, owner,
                RecordKindV1::ColumnLeaves,
                {0, column, 0, 0},
                batch.columns[column].n_leaves)) {
            return Fail(why, "column_commitment");
        }
    }
    if (!PushLength(records, owner, 1, 0, 0,
                    batch.column_len.size())) {
        return Fail(why, "column_len_count");
    }
    for (uint32_t column = 0;
         column < batch.column_len.size(); ++column) {
        if (!Push(records, owner,
                  RecordKindV1::ColumnLength,
                  {0, column, 0, 0},
                  batch.column_len[column])) {
            return Fail(why, "column_len");
        }
    }
    if (!PushFp3(records, owner,
                 RecordKindV1::BatchChallenge,
                 0, 0, batch.lambda) ||
        !PushFp3(records, owner,
                 RecordKindV1::BatchChallenge,
                 1, 0, batch.z1) ||
        !PushFp3(records, owner,
                 RecordKindV1::BatchChallenge,
                 2, 0, batch.z2) ||
        !PushLength(records, owner, 2, 0, 0,
                    batch.evals_z1.size())) {
        return Fail(why, "batch_challenges");
    }
    for (uint32_t column = 0;
         column < batch.evals_z1.size(); ++column) {
        if (!PushFp3(records, owner,
                     RecordKindV1::OodEvaluation,
                     0, column,
                     batch.evals_z1[column])) {
            return Fail(why, "eval_z1");
        }
    }
    if (!PushLength(records, owner, 3, 0, 0,
                    batch.evals_z2.size())) {
        return Fail(why, "eval_z2_count");
    }
    for (uint32_t column = 0;
         column < batch.evals_z2.size(); ++column) {
        if (!PushFp3(records, owner,
                     RecordKindV1::OodEvaluation,
                     1, column,
                     batch.evals_z2[column])) {
            return Fail(why, "eval_z2");
        }
    }
    if (!PushFp3(records, owner,
                 RecordKindV1::BatchChallenge,
                 3, 0, batch.w1) ||
        !PushFp3(records, owner,
                 RecordKindV1::BatchChallenge,
                 4, 0, batch.w2) ||
        !PushLength(records, owner, 4, 0, 0,
                    batch.fold_layers.size())) {
        return Fail(why, "deep_weights");
    }
    for (uint32_t layer = 0;
         layer < batch.fold_layers.size(); ++layer) {
        if (!PushHash(
                records, owner,
                RecordKindV1::FoldRoot,
                0, layer, 0,
                batch.fold_layers[layer].root) ||
            !Push(
                records, owner,
                RecordKindV1::FoldLeaves,
                {0, layer, 0, 0},
                batch.fold_layers[layer].n_leaves)) {
            return Fail(why, "fold_layer");
        }
    }
    if (!PushFp3(records, owner,
                 RecordKindV1::FinalValue,
                 0, 0, batch.final_value) ||
        !PushLength(records, owner, 5, 0, 0,
                    batch.fold_challenges.size())) {
        return Fail(why, "fold_final");
    }
    for (uint32_t layer = 0;
         layer < batch.fold_challenges.size(); ++layer) {
        if (!PushFp3(
                records, owner,
                RecordKindV1::FoldChallenge,
                0, layer,
                batch.fold_challenges[layer])) {
            return Fail(why, "fold_challenge");
        }
    }
    if (!PushLength(records, owner, 6, 0, 0,
                    batch.queries.size())) {
        return Fail(why, "query_count");
    }
    for (uint32_t query = 0;
         query < batch.queries.size(); ++query) {
        const auto& q = batch.queries[query];
        if (!Push(records, owner,
                  RecordKindV1::QueryIndex,
                  {query, 0, 0, 0}, q.index) ||
            !PushLength(records, owner, 7, query, 0,
                        q.columns.size())) {
            return Fail(why, "query_header");
        }
        for (uint32_t column = 0;
             column < q.columns.size(); ++column) {
            const auto& opening = q.columns[column];
            if (!PushFp3(
                    records, owner,
                    RecordKindV1::QueryOpeningValue,
                    query, column, opening.value) ||
                !PushLength(
                    records, owner, 8, query, column,
                    opening.siblings.size())) {
                return Fail(why, "query_column");
            }
            for (uint32_t sibling = 0;
                 sibling < opening.siblings.size();
                 ++sibling) {
                if (!PushHash(
                        records, owner,
                        RecordKindV1::QueryOpeningSibling,
                        query, column, sibling,
                        opening.siblings[sibling])) {
                    return Fail(why, "query_sibling");
                }
            }
        }
        if (!PushLength(records, owner, 9, query, 0,
                        q.steps.size())) {
            return Fail(why, "step_count");
        }
        for (uint32_t step = 0;
             step < q.steps.size(); ++step) {
            const auto& fold = q.steps[step];
            if (!Push(
                    records, owner,
                    RecordKindV1::FoldStepIndex,
                    {query, step, 0, 0},
                    fold.even_index) ||
                !Push(
                    records, owner,
                    RecordKindV1::FoldStepIndex,
                    {query, step, 1, 0},
                    fold.odd_index) ||
                !PushFp3(
                    records, owner,
                    RecordKindV1::FoldStepValue,
                    query, 2 * step, fold.even) ||
                !PushFp3(
                    records, owner,
                    RecordKindV1::FoldStepValue,
                    query, 2 * step + 1, fold.odd) ||
                !PushLength(
                    records, owner, 10, query, 2 * step,
                    fold.even_siblings.size())) {
                return Fail(why, "fold_step");
            }
            for (uint32_t sibling = 0;
                 sibling < fold.even_siblings.size();
                 ++sibling) {
                if (!PushHash(
                        records, owner,
                        RecordKindV1::FoldStepSibling,
                        query, 2 * step, sibling,
                        fold.even_siblings[sibling])) {
                    return Fail(
                        why, "fold_even_sibling");
                }
            }
            if (!PushLength(
                    records, owner, 10, query,
                    2 * step + 1,
                    fold.odd_siblings.size())) {
                return Fail(why, "fold_odd_count");
            }
            for (uint32_t sibling = 0;
                 sibling < fold.odd_siblings.size();
                 ++sibling) {
                if (!PushHash(
                        records, owner,
                        RecordKindV1::FoldStepSibling,
                        query, 2 * step + 1, sibling,
                        fold.odd_siblings[sibling])) {
                    return Fail(
                        why, "fold_odd_sibling");
                }
            }
        }
    }
    if (!PushHash(records, owner,
                  RecordKindV1::TraceCommit,
                  0, 0, 0, proof.trace_commit) ||
        !PushLength(records, owner, 11, 0, 0,
                    proof.next_openings.size())) {
        return Fail(why, "next_envelope");
    }
    for (uint32_t query = 0;
         query < proof.next_openings.size(); ++query) {
        const auto& paths = proof.next_openings[query];
        if (!PushLength(records, owner, 12, query, 0,
                        paths.size())) {
            return Fail(why, "next_path_count");
        }
        for (uint32_t path = 0;
             path < paths.size(); ++path) {
            const auto& opening = paths[path];
            if (!Push(
                    records, owner,
                    RecordKindV1::NextOpeningIndex,
                    {query, path, 0, 0},
                    opening.index) ||
                !PushFp3(
                    records, owner,
                    RecordKindV1::NextOpeningValue,
                    query, path, opening.leaf) ||
                !PushLength(
                    records, owner, 13, query, path,
                    opening.siblings.size())) {
                return Fail(why, "next_path");
            }
            for (uint32_t sibling = 0;
                 sibling < opening.siblings.size();
                 ++sibling) {
                if (!PushHash(
                        records, owner,
                        RecordKindV1::NextOpeningSibling,
                        query, path, sibling,
                        opening.siblings[sibling])) {
                    return Fail(
                        why, "next_sibling");
                }
            }
        }
    }
    return true;
}

uint256 ComputeScheduleRootV1(
    const std::vector<RecordV1>& records)
{
    HashWriter hash;
    hash << SCHEDULE_DOMAIN;
    hash << kVersionV1;
    hash << static_cast<uint64_t>(records.size());
    for (const auto& record : records) {
        HashRecordMetadata(hash, record);
    }
    return hash.GetHash();
}

uint256 ComputeProofWireRootV1(
    const std::vector<RecordV1>& records)
{
    HashWriter hash;
    hash << WIRE_DOMAIN;
    hash << kVersionV1;
    hash << static_cast<uint64_t>(records.size());
    for (const auto& record : records) {
        HashRecordMetadata(hash, record);
        hash << record.value;
    }
    return hash.GetHash();
}

bool BuildManifestV1(
    const RCStage3EpisodeWiringProduct& product,
    ManifestV1& out,
    std::string* why)
{
    out = {};
    if (product.version !=
            kRCStage3EpisodeWiringProductVersion ||
        product.statement_commitment.IsNull() ||
        product.product_commitment.IsNull()) {
        return Fail(why, "product_public");
    }
    out.magic = kMagicV1;
    out.version = kVersionV1;
    out.product_commitment =
        product.product_commitment;
    out.statement_commitment =
        product.statement_commitment;
    OwnerV1 product_owner{};
    auto& records = out.records;
    if (!Push(records, product_owner,
              RecordKindV1::ProductField,
              {0, 0, 0, 0}, product.version) ||
        !PushHash(records, product_owner,
                  RecordKindV1::ProductField,
                  1, 0, 0,
                  product.statement_commitment) ||
        !PushHash(records, product_owner,
                  RecordKindV1::ProductField,
                  2, 0, 0,
                  product.manifest_commitment) ||
        !PushHash(records, product_owner,
                  RecordKindV1::ProductField,
                  3, 0, 0,
                  product.gemm_product_commitment) ||
        !PushHash(records, product_owner,
                  RecordKindV1::ProductField,
                  4, 0, 0,
                  product.extract_product_commitment) ||
        !PushLength(records, product_owner, 14, 0, 0,
                    product.transpose_edges.size()) ||
        !PushLength(records, product_owner, 15, 0, 0,
                    product.residual_edges.size()) ||
        !PushLength(records, product_owner, 16, 0, 0,
                    product.round_order_edges.size())) {
        return Fail(why, "product_envelope");
    }

    for (uint32_t i = 0;
         i < product.transpose_edges.size(); ++i) {
        const auto& edge = product.transpose_edges[i];
        const OwnerV1 schedule_owner{
            OwnerFamilyV1::Transpose,
            OwnerSectionV1::EdgeSchedule, i,
            UINT32_MAX};
        const OwnerV1 pin_owner{
            OwnerFamilyV1::Transpose,
            OwnerSectionV1::EdgePin, i,
            UINT32_MAX};
        const OwnerV1 proof_owner{
            OwnerFamilyV1::Transpose,
            OwnerSectionV1::EdgeProof, i,
            UINT32_MAX};
        const OwnerV1 edge_owner{
            OwnerFamilyV1::Transpose,
            OwnerSectionV1::EdgeEnvelope, i,
            UINT32_MAX};
        if (edge.schedule.schedule_index != i ||
            !AppendTransposeSchedule(
                schedule_owner, edge.schedule, records) ||
            !AppendPin(pin_owner, edge.pin, records) ||
            !AppendCanonicalLegacyProofRecordsV1(
                proof_owner, edge.proof, records, why) ||
            !AppendMemoryBundle(
                OwnerFamilyV1::Transpose,
                OwnerSectionV1::MemoryBundle0, i,
                edge.source_memory, records,
                out.memory_proofs, why) ||
            !AppendMemoryBundle(
                OwnerFamilyV1::Transpose,
                OwnerSectionV1::MemoryBundle1, i,
                edge.destination_memory, records,
                out.memory_proofs, why) ||
            !PushHash(records, edge_owner,
                      RecordKindV1::EdgeEnvelopeField,
                      0, 0, 0,
                      edge.transposed_vector_root) ||
            !PushHash(records, edge_owner,
                      RecordKindV1::EdgeEnvelopeField,
                      1, 0, 0,
                      edge.edge_commitment)) {
            return Fail(
                why, "transpose_edge:" +
                    std::to_string(i));
        }
        ++out.relation_proofs;
    }

    for (uint32_t i = 0;
         i < product.residual_edges.size(); ++i) {
        const auto& edge = product.residual_edges[i];
        const OwnerV1 schedule_owner{
            OwnerFamilyV1::Residual,
            OwnerSectionV1::EdgeSchedule, i,
            UINT32_MAX};
        const OwnerV1 pin_owner{
            OwnerFamilyV1::Residual,
            OwnerSectionV1::EdgePin, i,
            UINT32_MAX};
        const OwnerV1 proof_owner{
            OwnerFamilyV1::Residual,
            OwnerSectionV1::EdgeProof, i,
            UINT32_MAX};
        const OwnerV1 edge_owner{
            OwnerFamilyV1::Residual,
            OwnerSectionV1::EdgeEnvelope, i,
            UINT32_MAX};
        if (edge.schedule.schedule_index != i ||
            !AppendResidualSchedule(
                schedule_owner, edge.schedule, records) ||
            !AppendPin(pin_owner, edge.pin, records) ||
            !AppendCanonicalLegacyProofRecordsV1(
                proof_owner, edge.proof, records, why) ||
            !AppendMemoryBundle(
                OwnerFamilyV1::Residual,
                OwnerSectionV1::MemoryBundle0, i,
                edge.y_memory, records,
                out.memory_proofs, why) ||
            !AppendMemoryBundle(
                OwnerFamilyV1::Residual,
                OwnerSectionV1::MemoryBundle1, i,
                edge.residual_memory, records,
                out.memory_proofs, why) ||
            !AppendMemoryBundle(
                OwnerFamilyV1::Residual,
                OwnerSectionV1::MemoryBundle2, i,
                edge.extract_input_memory, records,
                out.memory_proofs, why) ||
            !PushHash(records, edge_owner,
                      RecordKindV1::EdgeEnvelopeField,
                      0, 0, 0,
                      edge.edge_commitment)) {
            return Fail(
                why, "residual_edge:" +
                    std::to_string(i));
        }
        ++out.relation_proofs;
    }

    for (uint32_t i = 0;
         i < product.round_order_edges.size(); ++i) {
        const auto& edge =
            product.round_order_edges[i];
        const OwnerV1 schedule_owner{
            OwnerFamilyV1::RoundOrder,
            OwnerSectionV1::EdgeSchedule, i,
            UINT32_MAX};
        const OwnerV1 pin_owner{
            OwnerFamilyV1::RoundOrder,
            OwnerSectionV1::EdgePin, i,
            UINT32_MAX};
        const OwnerV1 proof_owner{
            OwnerFamilyV1::RoundOrder,
            OwnerSectionV1::EdgeProof, i,
            UINT32_MAX};
        const OwnerV1 edge_owner{
            OwnerFamilyV1::RoundOrder,
            OwnerSectionV1::EdgeEnvelope, i,
            UINT32_MAX};
        if (edge.schedule.schedule_index != i ||
            !AppendOrderSchedule(
                schedule_owner, edge.schedule, records) ||
            !AppendPin(pin_owner, edge.pin, records) ||
            !AppendCanonicalLegacyProofRecordsV1(
                proof_owner, edge.proof, records, why) ||
            !AppendMemoryBundle(
                OwnerFamilyV1::RoundOrder,
                OwnerSectionV1::MemoryBundle0, i,
                edge.producer_memory, records,
                out.memory_proofs, why) ||
            !AppendMemoryBundle(
                OwnerFamilyV1::RoundOrder,
                OwnerSectionV1::MemoryBundle1, i,
                edge.consumer_memory, records,
                out.memory_proofs, why) ||
            !PushHash(records, edge_owner,
                      RecordKindV1::EdgeEnvelopeField,
                      0, 0, 0,
                      edge.edge_commitment)) {
            return Fail(
                why, "order_edge:" +
                    std::to_string(i));
        }
        ++out.relation_proofs;
    }
    if (!PushHash(records, product_owner,
                  RecordKindV1::ProductField,
                  17, 0, 0,
                  product.product_commitment)) {
        return Fail(why, "product_commitment");
    }
    for (uint32_t i = 0; i < records.size(); ++i) {
        if (records[i].ordinal != i) {
            return Fail(why, "noncanonical_ordinal");
        }
        switch (records[i].kind) {
        case RecordKindV1::ColumnRoot:
        case RecordKindV1::FoldRoot:
        case RecordKindV1::TraceCommit:
            ++out.root_words;
            break;
        case RecordKindV1::QueryOpeningValue:
        case RecordKindV1::QueryOpeningSibling:
        case RecordKindV1::FoldStepValue:
        case RecordKindV1::FoldStepSibling:
        case RecordKindV1::NextOpeningValue:
        case RecordKindV1::NextOpeningSibling:
            ++out.opening_words;
            break;
        default:
            break;
        }
    }
    out.schedule_root =
        ComputeScheduleRootV1(records);
    out.proof_wire_root =
        ComputeProofWireRootV1(records);
    out.exact_product_envelope = true;
    out.exact_edge_order = true;
    out.exact_memory_shard_order = true;
    out.every_verifier_read_classified =
        out.relation_proofs ==
            product.transpose_edges.size() +
            product.residual_edges.size() +
            product.round_order_edges.size() &&
        out.root_words != 0 &&
        out.opening_words != 0;
    out.canonical_u32_words = true;
    out.valid =
        !out.schedule_root.IsNull() &&
        !out.proof_wire_root.IsNull() &&
        out.every_verifier_read_classified &&
        records.size() < kMaxRecordsV1;
    out.note = out.valid
        ? "stage3:episode_wiring_proof_descriptor:"
          "exact_legacy_verifier_tape"
        : "stage3:episode_wiring_proof_descriptor:"
          "incomplete_legacy_verifier_tape";
    return out.valid ||
        Fail(why, "manifest_incomplete");
}

bool ValidateManifestV1(
    const RCStage3EpisodeWiringProduct& product,
    const ManifestV1& claimed,
    std::string* why)
{
    ManifestV1 expected;
    if (!BuildManifestV1(product, expected, why)) {
        return false;
    }
    if (claimed != expected) {
        return Fail(why, "manifest_mismatch");
    }
    return true;
}

bool DeriveChallengesV1(
    const ManifestV1& manifest,
    ChallengesV1& out)
{
    out = {};
    if (!manifest.valid ||
        manifest.schedule_root.IsNull() ||
        manifest.proof_wire_root.IsNull()) {
        return false;
    }
    HashWriter hash;
    hash << CHALLENGE_DOMAIN;
    hash << kVersionV1;
    hash << manifest.product_commitment;
    hash << manifest.statement_commitment;
    hash << manifest.schedule_root;
    hash << manifest.proof_wire_root;
    hash << static_cast<uint32_t>(
        manifest.records.size());
    const uint256 seed = hash.GetHash();
    if (seed.IsNull()) return false;
    for (uint32_t lane = 0;
         lane < kTerminalLanesV1; ++lane) {
        out.gamma[lane] = WiringChallengeFp3(
            seed, "wiring_descriptor_gamma", 0, lane);
        out.alpha[lane] = WiringChallengeFp3(
            seed, "wiring_descriptor_alpha", 0, lane);
    }
    return true;
}

ProductV1 BuildProductV1(
    const ManifestV1& manifest)
{
    ProductV1 out;
    out.manifest = manifest;
    if (!manifest.valid ||
        manifest.records.empty() ||
        manifest.records.size() >= kMaxRecordsV1 ||
        manifest.schedule_root !=
            ComputeScheduleRootV1(manifest.records) ||
        manifest.proof_wire_root !=
            ComputeProofWireRootV1(manifest.records) ||
        !DeriveChallengesV1(
            manifest, out.challenges)) {
        out.note =
            "stage3:episode_wiring_proof_descriptor:"
            "product_manifest";
        return out;
    }
    out.active_rows =
        static_cast<uint32_t>(
            manifest.records.size());
    out.trace_rows =
        NextPowerOfTwo(out.active_rows);
    if (out.trace_rows == 0) {
        out.note =
            "stage3:episode_wiring_proof_descriptor:"
            "product_rows";
        return out;
    }
    out.layout = {};
    out.cs.n_rows = out.trace_rows;
    out.cs.n_columns = out.layout.End();
    out.cs.preprocessed_pin_ood = true;
    out.columns.assign(
        out.cs.n_columns,
        std::vector<Fp3>(
            out.trace_rows, Fp3::Zero()));

    std::vector<Fp3> active(
        out.trace_rows, Fp3::Zero());
    std::vector<Fp3> ordinal(
        out.trace_rows, Fp3::Zero());
    for (uint32_t row = 0;
         row < out.active_rows; ++row) {
        const auto& record =
            manifest.records[row];
        if (record.ordinal != row) {
            out.note =
                "stage3:episode_wiring_proof_descriptor:"
                "product_ordinal";
            return out;
        }
        active[row] = Fp3::One();
        ordinal[row] =
            gf::FromU64_3(row);
        out.columns[out.layout.active][row] =
            active[row];
        out.columns[out.layout.ordinal][row] =
            ordinal[row];
        out.columns[out.layout.value][row] =
            gf::FromU64_3(record.value);
        for (uint32_t bit = 0; bit < 32; ++bit) {
            out.columns[
                out.layout.ValueBit(bit)][row] =
                gf::FromU64_3(
                    (record.value >> bit) & 1U);
        }
    }
    if (!AddPreprocessed(
            out.cs, out.layout.active, active) ||
        !AddPreprocessed(
            out.cs, out.layout.ordinal, ordinal)) {
        out.note =
            "stage3:episode_wiring_proof_descriptor:"
            "product_preprocessed";
        return out;
    }
    AddConstraint(
        out.cs, "wiring_descriptor.value_bits",
        aq::AirKind::kEverywhere, 1,
        [layout = out.layout](
            const auto& cur, const auto&) {
            Fp3 reconstructed = Fp3::Zero();
            for (uint32_t bit = 0; bit < 32; ++bit) {
                reconstructed = gf::Add(
                    reconstructed,
                    gf::Mul(
                        gf::FromU64_3(uint64_t{1} << bit),
                        cur[layout.ValueBit(bit)]));
            }
            return gf::Sub(
                cur[layout.value], reconstructed);
        });
    for (uint32_t bit = 0; bit < 32; ++bit) {
        AddConstraint(
            out.cs, "wiring_descriptor.value_bit_boolean",
            aq::AirKind::kEverywhere, 2,
            [layout = out.layout, bit](
                const auto& cur, const auto&) {
                const Fp3 value =
                    cur[layout.ValueBit(bit)];
                return gf::Mul(
                    value,
                    gf::Sub(value, Fp3::One()));
            });
    }
    AddConstraint(
        out.cs, "wiring_descriptor.padding_value_zero",
        aq::AirKind::kEverywhere, 2,
        [layout = out.layout](
            const auto& cur, const auto&) {
            return gf::Mul(
                gf::Sub(
                    Fp3::One(),
                    cur[layout.active]),
                cur[layout.value]);
        });

    for (uint32_t lane = 0;
         lane < kTerminalLanesV1; ++lane) {
        Fp3 running = Fp3::Zero();
        for (uint32_t row = 0;
             row < out.trace_rows; ++row) {
            if (row < out.active_rows) {
                const Fp3 denominator =
                    gf::Add(
                        out.columns[
                            out.layout.value][row],
                        gf::Add(
                            gf::Mul(
                                out.challenges.alpha[lane],
                                out.columns[
                                    out.layout.ordinal][row]),
                            out.challenges.gamma[lane]));
                if (gf::IsZero(denominator)) {
                    out.note =
                        "stage3:episode_wiring_proof_descriptor:"
                        "terminal_collision";
                    return out;
                }
                out.columns[
                    out.layout.Inverse(lane)][row] =
                    gf::Inv(denominator);
                running = gf::Add(
                    running,
                    out.columns[
                        out.layout.Inverse(lane)][row]);
            }
            out.columns[
                out.layout.Running(lane)][row] =
                running;
        }
        out.source_terminal[lane] = running;
        std::vector<Fp3> expected(
            out.trace_rows, running);
        out.columns[
            out.layout.ExpectedTerminal(lane)] =
            expected;
        if (!AddPreprocessed(
                out.cs,
                out.layout.ExpectedTerminal(lane),
                expected)) {
            out.note =
                "stage3:episode_wiring_proof_descriptor:"
                "terminal_preprocessed";
            return out;
        }
        AddConstraint(
            out.cs, "wiring_descriptor.inverse",
            aq::AirKind::kEverywhere, 2,
            [layout = out.layout,
             challenges = out.challenges,
             lane](const auto& cur, const auto&) {
                const Fp3 denominator =
                    gf::Add(
                        cur[layout.value],
                        gf::Add(
                            gf::Mul(
                                challenges.alpha[lane],
                                cur[layout.ordinal]),
                            challenges.gamma[lane]));
                return gf::Mul(
                    cur[layout.active],
                    gf::Sub(
                        gf::Mul(
                            denominator,
                            cur[layout.Inverse(lane)]),
                        Fp3::One()));
            });
        AddConstraint(
            out.cs, "wiring_descriptor.padding_inverse_zero",
            aq::AirKind::kEverywhere, 2,
            [layout = out.layout, lane](
                const auto& cur, const auto&) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        cur[layout.active]),
                    cur[layout.Inverse(lane)]);
            });
        AddConstraint(
            out.cs, "wiring_descriptor.running_first",
            aq::AirKind::kFirstRow, 2,
            [layout = out.layout, lane](
                const auto& cur, const auto&) {
                return gf::Sub(
                    cur[layout.Running(lane)],
                    gf::Mul(
                        cur[layout.active],
                        cur[layout.Inverse(lane)]));
            });
        AddConstraint(
            out.cs, "wiring_descriptor.running_transition",
            aq::AirKind::kTransition, 2,
            [layout = out.layout, lane](
                const auto& cur,
                const auto& next) {
                return gf::Sub(
                    next[layout.Running(lane)],
                    gf::Add(
                        cur[layout.Running(lane)],
                        gf::Mul(
                            next[layout.active],
                            next[layout.Inverse(lane)])));
            });
        AddConstraint(
            out.cs, "wiring_descriptor.terminal",
            aq::AirKind::kLastRow, 1,
            [layout = out.layout, lane](
                const auto& cur, const auto&) {
                return gf::Sub(
                    cur[layout.Running(lane)],
                    cur[layout.ExpectedTerminal(lane)]);
            });
    }
    out.violations =
        CountViolations(out.cs, out.columns);
    out.exact_public_schedule_preprocessed = true;
    out.canonical_u32_decomposition_air = true;
    out.dual_fp3_source_terminal_air = true;
    out.parent_terminal_cancelled = false;
    out.recursively_consumed = false;
    out.semantic_sites_credited = false;
    out.valid =
        out.violations == 0 &&
        out.cs.n_columns == out.layout.End();
    out.note = out.valid
        ? "stage3:episode_wiring_proof_descriptor:"
          "descriptor_air_ready_for_parent_join"
        : "stage3:episode_wiring_proof_descriptor:"
          "descriptor_air_invalid";
    return out;
}

bool ProveV1(
    const ProductV1& product,
    ProofV1& out,
    std::string* why)
{
    out = {};
    if (!product.valid ||
        product.parent_terminal_cancelled ||
        product.recursively_consumed ||
        product.semantic_sites_credited ||
        product.violations != 0) {
        return Fail(why, "prove_product");
    }
    const uint256 seed =
        DeriveProofSeed(
            product.manifest,
            product.source_terminal);
    const auto proved =
        aq::AirQuotientProveRows(
            product.cs, product.columns, seed);
    if (!proved.ok || !proved.division_exact) {
        return Fail(
            why, "prove_air:" + proved.note);
    }
    out.version = kVersionV1;
    out.schedule_root =
        product.manifest.schedule_root;
    out.proof_wire_root =
        product.manifest.proof_wire_root;
    out.source_terminal =
        product.source_terminal;
    out.proof.batch = proved.proof.batch;
    out.proof.next_openings =
        proved.proof.next_openings;
    out.proof.trace_commit =
        proved.proof.trace_commit;
    out.active_rows = product.active_rows;
    out.trace_rows = product.trace_rows;
    out.parent_terminal_cancelled = false;
    out.recursively_consumed = false;
    out.semantic_sites_credited = false;
    if (!CanonicalProof(
            out.proof,
            out.canonical_proof_bytes, why) ||
        !VerifyV1(product.manifest, out, why)) {
        out = {};
        return false;
    }
    out.locally_verified = true;
    return true;
}

bool VerifyV1(
    const ManifestV1& expected_manifest,
    const ProofV1& proof,
    std::string* why)
{
    if (proof.version != kVersionV1 ||
        !expected_manifest.valid ||
        proof.schedule_root !=
            expected_manifest.schedule_root ||
        proof.proof_wire_root !=
            expected_manifest.proof_wire_root ||
        proof.active_rows !=
            expected_manifest.records.size() ||
        proof.parent_terminal_cancelled ||
        proof.recursively_consumed ||
        proof.semantic_sites_credited) {
        return Fail(why, "verify_envelope");
    }
    const ProductV1 expected =
        BuildProductV1(expected_manifest);
    if (!expected.valid ||
        proof.trace_rows != expected.trace_rows ||
        !SameTerminal(
            proof.source_terminal,
            expected.source_terminal)) {
        return Fail(why, "verify_statement");
    }
    std::vector<unsigned char> canonical;
    if (!CanonicalProof(
            proof.proof, canonical, why) ||
        canonical != proof.canonical_proof_bytes) {
        return Fail(why, "verify_codec");
    }
    std::string air_why;
    if (!aq::AirQuotientVerify<
            Fp3, aq::AirFriBackendAlg<Fp3>>(
            expected.cs, proof.proof,
            DeriveProofSeed(
                expected_manifest,
                proof.source_terminal),
            &air_why)) {
        return Fail(
            why, "verify_air:" + air_why);
    }
    return true;
}

} // namespace matmul::v4::rc::stage3_episode_wiring_proof_descriptor
