// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_semantic_source_alg.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>

#include <algorithm>
#include <limits>
#include <numeric>

namespace matmul::v4::rc::episode_semantic_source_alg {
namespace {

using gf::Fp3;
using AirCs = aq::AirConstraintSystem<Fp3>;
using AirConstraint = aq::AirConstraint<Fp3>;

constexpr char SHAPE_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_SOURCE_SHAPE_V1";
constexpr char SCHEDULE_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_SOURCE_SCHEDULE_V1";
constexpr char CS_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_SOURCE_CS_V1";
constexpr char MANIFEST_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_SOURCE_MANIFEST_V1";
constexpr char FS_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_SOURCE_FS_V1";
constexpr char PROOF_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_SOURCE_PROOF_V1";
constexpr char CONTEXT_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_SOURCE_CONTEXT_V1";
constexpr char RECEIPT_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_SOURCE_RECEIPT_V1";
constexpr char CTL_TRANSCRIPT_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_SOURCE_CTL_TRANSCRIPT_V1";
constexpr char CTL_SCHEDULE_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_SOURCE_CTL_SCHEDULE_V1";
constexpr char CTL_FS_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_SOURCE_CTL_FS_V1";
constexpr char CTL_PROOF_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_SOURCE_CTL_PROOF_V1";
constexpr char CTL_JOIN_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_SOURCE_CTL_JOIN_V1";
constexpr char COVERAGE_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_SOURCE_COVERAGE_V1";
constexpr char BUNDLE_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_SOURCE_BUNDLE_V1";
constexpr uint32_t kSameParentCtlBusIdV1 = 0x45534231U;
constexpr uint32_t kReceiverColumnBaseV1 = kTotalColumnsV1;
constexpr uint32_t kReceiverColumnsV1 =
    kRCStage3EpisodeMemoryColumns;
constexpr uint32_t kCtlDependentBaseV1 =
    kReceiverColumnBaseV1 + kReceiverColumnsV1;
constexpr uint32_t kCtlDependentColumnsPerSideV1 = 6;
constexpr uint32_t kSameParentCtlColumnsV1 =
    kCtlDependentBaseV1 +
    2 * kCtlDependentColumnsPerSideV1;

enum CtlDependentOffsetV1 : uint32_t {
    kCtlInverse1V1 = 0,
    kCtlInverse2V1,
    kCtlTerm1V1,
    kCtlTerm2V1,
    kCtlRunning1V1,
    kCtlRunning2V1,
};

Fp3 U64(uint64_t value)
{
    return gf::FromU64_3(value);
}

Fp3 Signed(int64_t value)
{
    return gf::FromSigned3(value);
}

bool PowerOfTwo(uint32_t value)
{
    return value != 0 && (value & (value - 1)) == 0;
}

uint32_t NextPowerOfTwo(uint64_t value)
{
    if (value == 0 ||
        value > (uint64_t{1} << 31)) {
        return 0;
    }
    uint64_t out = 1;
    while (out < value) out <<= 1;
    return static_cast<uint32_t>(out);
}

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) {
        *why =
            "stage3:episode_semantic_source_alg:" + message;
    }
    return false;
}

class ProgramBuilder {
public:
    ProgramBuilder(
        RCStage3RelationRole role,
        uint32_t ordinal,
        aq::AirKind kind,
        uint32_t degree,
        uint32_t width)
    {
        m_program.role = role;
        m_program.constraint_ordinal = ordinal;
        m_program.kind = kind;
        m_program.declared_degree = degree;
        m_program.current_width = width;
        m_program.next_width = width;
        m_program.challenge_width = 0;
    }

    uint32_t Current(uint32_t column)
    {
        return Emit({
            cb::Opcode::Current, column, 0, Fp3::Zero()});
    }

    uint32_t Next(uint32_t column)
    {
        return Emit({
            cb::Opcode::Next, column, 0, Fp3::Zero()});
    }

    uint32_t Constant(const Fp3& value)
    {
        return Emit({
            cb::Opcode::Constant, 0, 0, value});
    }

    uint32_t Add(uint32_t lhs, uint32_t rhs)
    {
        return Emit({
            cb::Opcode::Add, lhs, rhs, Fp3::Zero()});
    }

    uint32_t Sub(uint32_t lhs, uint32_t rhs)
    {
        return Emit({
            cb::Opcode::Sub, lhs, rhs, Fp3::Zero()});
    }

    uint32_t Mul(uint32_t lhs, uint32_t rhs)
    {
        return Emit({
            cb::Opcode::Mul, lhs, rhs, Fp3::Zero()});
    }

    cb::Program Take()
    {
        return std::move(m_program);
    }

private:
    uint32_t Emit(cb::Instruction instruction)
    {
        const uint32_t index =
            static_cast<uint32_t>(
                m_program.instructions.size());
        m_program.instructions.push_back(
            std::move(instruction));
        return index;
    }

    cb::Program m_program;
};

template <typename Build>
void Append(
    cb::ProgramTable& table,
    aq::AirKind kind,
    uint32_t degree,
    Build&& build)
{
    ProgramBuilder builder(
        table.role,
        static_cast<uint32_t>(table.programs.size()),
        kind, degree, table.current_width);
    build(builder);
    table.programs.push_back(builder.Take());
}

void AppendBoolean(
    cb::ProgramTable& table,
    uint32_t column)
{
    Append(
        table, aq::AirKind::kEverywhere, 2,
        [column](ProgramBuilder& b) {
            const uint32_t value = b.Current(column);
            b.Mul(
                value,
                b.Sub(value, b.Constant(Fp3::One())));
        });
}

bool ShapeFieldsValid(
    const LayerShapeV1& shape,
    std::string* why)
{
    const uint64_t expected_tiles =
        shape.n == 0
            ? 0
            : uint64_t{shape.m} *
                (shape.n / kRCMxBlockLen);
    const uint64_t logical_rows =
        uint64_t{shape.k} * kRCMxBlockLen;
    if (shape.magic != kMagicV1 ||
        shape.version != kVersionV1 ||
        shape.statement_commitment.IsNull() ||
        shape.gemm_manifest_commitment.IsNull() ||
        shape.m == 0 || shape.n == 0 || shape.k == 0 ||
        shape.n % kRCMxBlockLen != 0 ||
        logical_rows >
            std::numeric_limits<uint32_t>::max() ||
        NextPowerOfTwo(logical_rows) == 0 ||
        shape.tile_count != expected_tiles ||
        shape.tile_count == 0) {
        return Fail(why, "shape_fields");
    }
    return true;
}

uint64_t EndpointTotal(
    const LayerShapeV1& shape,
    uint32_t slot)
{
    switch (slot) {
    case kOperandASlotV1:
        return uint64_t{shape.m} * shape.k;
    case kOperandBSlotV1:
        return uint64_t{shape.k} * shape.n;
    case kOutputYSlotV1:
        return uint64_t{shape.m} * shape.n;
    default:
        return 0;
    }
}

uint32_t TilesPerShard(
    const LayerShapeV1& shape)
{
    const uint64_t tile_rows =
        uint64_t{shape.k} * kRCMxBlockLen;
    if (tile_rows == 0 ||
        tile_rows > kMaxTraceRowsPerShardV1) {
        return 0;
    }
    return static_cast<uint32_t>(
        kMaxTraceRowsPerShardV1 / tile_rows);
}

uint64_t ExpectedLeafCount(
    const LayerShapeV1& shape)
{
    const uint32_t capacity =
        TilesPerShard(shape);
    if (capacity == 0) return 0;
    return (shape.tile_count + capacity - 1) /
        capacity;
}

uint64_t BOrdinal(
    const LayerShapeV1& shape,
    uint32_t column,
    uint32_t contraction)
{
    return shape.b_transpose
        ? uint64_t{column} * shape.k + contraction
        : uint64_t{contraction} * shape.n + column;
}

bool SemanticOccurrence(
    const LeafManifestV1& manifest,
    uint32_t slot,
    uint32_t trace_row,
    bool& active,
    uint64_t& ordinal)
{
    active = false;
    ordinal = 0;
    if (trace_row >= manifest.logical_rows ||
        manifest.shape.k == 0 ||
        manifest.tile_rows == 0) {
        return true;
    }
    const uint32_t local_tile =
        trace_row / manifest.tile_rows;
    const uint32_t tile_trace_row =
        trace_row % manifest.tile_rows;
    if (local_tile >= manifest.tile_count) {
        return false;
    }
    const uint64_t layer_tile =
        manifest.tile_begin + local_tile;
    const uint32_t blocks_per_row =
        manifest.shape.n / kRCMxBlockLen;
    const uint32_t output_row =
        layer_tile / blocks_per_row;
    const uint32_t output_block =
        layer_tile % blocks_per_row;
    const uint32_t lane =
        tile_trace_row / manifest.shape.k;
    const uint32_t contraction =
        tile_trace_row % manifest.shape.k;
    const uint32_t column =
        output_block * kRCMxBlockLen + lane;
    if (lane >= kRCMxBlockLen ||
        column >= manifest.shape.n) {
        return false;
    }

    switch (slot) {
    case kOperandASlotV1:
        active =
            output_block == 0 && lane == 0;
        ordinal =
            uint64_t{output_row} *
                manifest.shape.k +
            contraction;
        return true;
    case kOperandBSlotV1:
        active = output_row == 0;
        ordinal = BOrdinal(
            manifest.shape, column, contraction);
        return true;
    case kOutputYSlotV1:
        active =
            contraction + 1 == manifest.shape.k;
        ordinal =
            uint64_t{output_row} *
                manifest.shape.n +
            column;
        return true;
    default:
        return false;
    }
}

bool FillSchedule(
    const LeafManifestV1& manifest,
    std::vector<std::vector<Fp3>>& columns,
    bool initialize,
    std::string* why)
{
    if (!PowerOfTwo(manifest.n_rows) ||
        manifest.logical_rows == 0 ||
        manifest.logical_rows > manifest.n_rows ||
        columns.size() != kTotalColumnsV1) {
        return Fail(why, "schedule_shape");
    }
    if (initialize) {
        for (auto& column : columns) {
            column.assign(
                manifest.n_rows, Fp3::Zero());
        }
    } else if (!std::all_of(
                   columns.begin(), columns.end(),
                   [&manifest](const auto& column) {
                       return column.size() ==
                           manifest.n_rows;
                   })) {
        return Fail(why, "schedule_columns");
    }

    const auto& projections =
        CanonicalSourceProjectionsV1();
    for (uint32_t slot = 0;
         slot < projections.size(); ++slot) {
        const auto& projection = projections[slot];
        const uint64_t total =
            EndpointTotal(manifest.shape, slot);
        const auto role =
            RCStage3EpisodeEndpointRole(
                projection.endpoint);
        if (!role.has_value() || total == 0) {
            return Fail(why, "schedule_endpoint");
        }
        for (uint32_t row = 0;
             row < manifest.n_rows; ++row) {
            columns[projection.endpoint_column][row] =
                U64(static_cast<uint16_t>(
                    projection.endpoint));
            columns[projection.role_column][row] =
                U64(static_cast<uint16_t>(*role));
            bool active = false;
            uint64_t ordinal = 0;
            if (!SemanticOccurrence(
                    manifest, slot, row,
                    active, ordinal)) {
                return Fail(why, "schedule_occurrence");
            }
            if (!active) continue;
            if (ordinal >= total) {
                return Fail(why, "schedule_ordinal");
            }
            const uint64_t address =
                episode_semantic_alg::CanonicalAddressV2(
                    projection.endpoint,
                    manifest.shape.layer_ordinal,
                    ordinal);
            if (address == 0) {
                return Fail(why, "schedule_address");
            }
            columns[projection.active_column][row] =
                Fp3::One();
            columns[projection.address_column][row] =
                U64(address);
            columns[projection.remaining_column][row] =
                U64(total - ordinal);
        }
    }
    return true;
}

uint256 ScheduleCommitment(
    const LeafManifestV1& manifest)
{
    std::vector<std::vector<Fp3>> columns(
        kTotalColumnsV1);
    if (!FillSchedule(
            manifest, columns, true, nullptr)) {
        return {};
    }
    HashWriter hash;
    hash << SCHEDULE_DOMAIN << kVersionV1;
    hash << manifest.shape.shape_commitment;
    hash << manifest.tile_begin;
    hash << manifest.tile_count;
    hash << manifest.tile_rows;
    hash << manifest.logical_rows << manifest.n_rows;
    for (const auto& projection :
         CanonicalSourceProjectionsV1()) {
        hash << static_cast<uint16_t>(
            projection.endpoint);
        for (uint32_t column : {
                 projection.active_column,
                 projection.address_column,
                 projection.remaining_column,
                 projection.endpoint_column,
                 projection.role_column}) {
            hash << column;
            for (const Fp3& value : columns[column]) {
                hash << gf::Canonical(value.c0);
                hash << gf::Canonical(value.c1);
                hash << gf::Canonical(value.c2);
            }
        }
        hash << projection.value_column;
        hash << projection.semantic_value_column;
        hash << projection.export_column;
    }
    return hash.GetHash();
}

uint256 ExpectedCsCommitment(
    const LeafManifestV1& manifest)
{
    if (manifest.program_table_sha256d.IsNull() ||
        manifest.program_table_alg.IsNull() ||
        manifest.schedule_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << CS_DOMAIN << kVersionV1;
    hash << manifest.shape.shape_commitment;
    hash << manifest.tile_begin;
    hash << manifest.tile_count;
    hash << manifest.tile_rows;
    hash << manifest.logical_rows << manifest.n_rows;
    hash << kTotalColumnsV1;
    hash << manifest.program_table_sha256d;
    hash << manifest.program_table_alg;
    hash << manifest.schedule_commitment;
    for (const auto& projection :
         CanonicalSourceProjectionsV1()) {
        hash << static_cast<uint16_t>(
            projection.endpoint);
        hash << projection.active_column;
        hash << projection.address_column;
        hash << projection.remaining_column;
        hash << projection.endpoint_column;
        hash << projection.role_column;
        hash << projection.value_column;
        hash << projection.semantic_value_column;
        hash << projection.export_column;
    }
    return hash.GetHash();
}

uint256 LeafManifestCommitment(
    const LeafManifestV1& manifest)
{
    if (manifest.shape.shape_commitment.IsNull() ||
        manifest.program_table_sha256d.IsNull() ||
        manifest.program_table_alg.IsNull() ||
        manifest.schedule_commitment.IsNull() ||
        manifest.expected_cs_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << MANIFEST_DOMAIN << manifest.magic;
    hash << manifest.version;
    hash << manifest.shape.shape_commitment;
    hash << manifest.tile_begin;
    hash << manifest.tile_count;
    hash << manifest.tile_rows;
    hash << manifest.logical_rows;
    hash << manifest.n_rows;
    hash << manifest.program_table_sha256d;
    hash << manifest.program_table_alg;
    hash << manifest.schedule_commitment;
    hash << manifest.expected_cs_commitment;
    return hash.GetHash();
}

bool ManifestValid(
    const LeafManifestV1& manifest,
    std::string* why)
{
    if (manifest.magic != kMagicV1 ||
        manifest.version != kVersionV1 ||
        !ShapeFieldsValid(manifest.shape, why) ||
        manifest.shape.shape_commitment !=
            ComputeLayerShapeCommitmentV1(
                manifest.shape) ||
        manifest.tile_count == 0 ||
        manifest.tile_begin >=
            manifest.shape.tile_count ||
        manifest.tile_count >
            manifest.shape.tile_count -
                manifest.tile_begin) {
        return Fail(why, "manifest_shape");
    }
    const uint64_t tile_rows =
        uint64_t{manifest.shape.k} *
            kRCMxBlockLen;
    if (tile_rows == 0 ||
        tile_rows >
            std::numeric_limits<uint32_t>::max() ||
        manifest.tile_rows != tile_rows ||
        manifest.logical_rows !=
            tile_rows * manifest.tile_count ||
        manifest.logical_rows >
            kMaxTraceRowsPerShardV1 ||
        manifest.n_rows !=
            NextPowerOfTwo(
                manifest.logical_rows)) {
        return Fail(why, "manifest_tile");
    }
    cb::ProgramTable table;
    if (!BuildCanonicalProgramTableV1(
            table, why)) {
        return false;
    }
    const auto keys =
        cb::CommitProgramTableForExternalAndRecursiveUse(
            table);
    if (!keys.same_canonical_serialization ||
        manifest.program_table_sha256d !=
            keys.external_sha256d ||
        manifest.program_table_alg !=
            aq::AirFriBackendAlg<Fp3>::PackDigest(
                keys.recursive_alg_hash) ||
        manifest.schedule_commitment !=
            ScheduleCommitment(manifest) ||
        manifest.expected_cs_commitment !=
            ExpectedCsCommitment(manifest) ||
        manifest.manifest_commitment !=
            LeafManifestCommitment(manifest)) {
        return Fail(why, "manifest_commitment");
    }
    return true;
}

uint256 FsSeed(const LeafManifestV1& manifest)
{
    if (!ManifestValid(manifest, nullptr)) {
        return {};
    }
    HashWriter hash;
    hash << FS_DOMAIN << manifest.manifest_commitment;
    hash << manifest.shape.statement_commitment;
    hash << manifest.shape.gemm_manifest_commitment;
    hash << manifest.program_table_alg;
    hash << manifest.expected_cs_commitment;
    return hash.GetHash();
}

uint256 ProofBytesCommitment(
    const std::vector<unsigned char>& bytes)
{
    if (bytes.empty()) return {};
    HashWriter hash;
    hash << PROOF_DOMAIN << kVersionV1;
    hash << static_cast<uint64_t>(bytes.size());
    hash << bytes;
    return hash.GetHash();
}

uint256 ProofContextCommitment(
    const LeafManifestV1& manifest,
    const uint256& fs_seed)
{
    if (!ManifestValid(manifest, nullptr) ||
        fs_seed.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << CONTEXT_DOMAIN << kVersionV1;
    hash << manifest.manifest_commitment;
    hash << manifest.shape.statement_commitment;
    hash << manifest.shape.gemm_manifest_commitment;
    hash << manifest.program_table_alg;
    hash << manifest.expected_cs_commitment;
    hash << fs_seed;
    return hash.GetHash();
}

void WriteFp3(HashWriter& hash, const Fp3& value)
{
    hash << gf::Canonical(value.c0);
    hash << gf::Canonical(value.c1);
    hash << gf::Canonical(value.c2);
}

bool CanonicalFp3(const Fp3& value)
{
    return value.c0 < gf::kP &&
        value.c1 < gf::kP &&
        value.c2 < gf::kP;
}

void CopyConstraintFamily(
    const AirCs& source,
    uint32_t offset,
    AirCs& destination)
{
    for (const auto& source_constraint :
         source.constraints) {
        AirConstraint copied;
        copied.name = source_constraint.name;
        copied.kind = source_constraint.kind;
        copied.alg_degree =
            source_constraint.alg_degree;
        const uint32_t width =
            source.n_columns;
        const auto eval =
            source_constraint.eval;
        copied.eval =
            [offset, width, eval](
                const std::vector<Fp3>& current,
                const std::vector<Fp3>& next) {
                std::vector<Fp3> local_current(
                    current.begin() + offset,
                    current.begin() + offset + width);
                std::vector<Fp3> local_next(
                    next.begin() + offset,
                    next.begin() + offset + width);
                return eval(
                    local_current, local_next);
            };
        destination.constraints.push_back(
            std::move(copied));
    }
    for (const auto& [column, values] :
         source.preprocessed) {
        destination.preprocessed.push_back(
            {offset + column, values});
    }
    for (const auto& [column, root] :
         source.preprocessed_roots) {
        destination.preprocessed_roots.push_back(
            {offset + column, root});
    }
}

uint256 CtlScheduleCommitment(
    const LeafManifestV1& manifest,
    const SourceProjectionV1& projection,
    int8_t multiplicity)
{
    if (!ManifestValid(manifest, nullptr) ||
        (multiplicity != 1 &&
         multiplicity != -1)) {
        return {};
    }
    HashWriter hash;
    hash << CTL_SCHEDULE_DOMAIN << kVersionV1;
    hash << manifest.manifest_commitment;
    hash << static_cast<uint16_t>(
        projection.endpoint);
    hash << projection.active_column;
    hash << projection.address_column;
    hash << projection.remaining_column;
    hash << projection.endpoint_column;
    hash << projection.role_column;
    hash << projection.semantic_value_column;
    hash << static_cast<int32_t>(multiplicity);
    hash << manifest.n_rows;
    return hash.GetHash();
}

uint256 CtlTranscriptSeed(
    const LeafManifestV1& manifest,
    uint32_t projection_slot)
{
    if (!ManifestValid(manifest, nullptr) ||
        projection_slot >= kEndpointCountV1) {
        return {};
    }
    HashWriter hash;
    hash << CTL_TRANSCRIPT_DOMAIN << kVersionV1;
    hash << manifest.manifest_commitment;
    hash << manifest.shape.statement_commitment;
    hash << manifest.expected_cs_commitment;
    hash << projection_slot;
    return hash.GetHash();
}

bool BuildCtlChallengeMaterial(
    const LeafManifestV1& leaf_manifest,
    uint32_t projection_slot,
    const uint256& base_row_commitment,
    RCStage3CtlManifest& ctl_manifest,
    std::vector<RCStage3CtlChildPin>& pins,
    RCStage3CtlChallenges& challenges,
    std::string* why)
{
    ctl_manifest = {};
    pins.clear();
    challenges = {};
    if (!ManifestValid(leaf_manifest, why) ||
        projection_slot >= kEndpointCountV1 ||
        base_row_commitment.IsNull()) {
        return Fail(why, "ctl_challenge_shape");
    }
    const auto& projection =
        CanonicalSourceProjectionsV1()[
            projection_slot];
    const uint256 send_schedule =
        CtlScheduleCommitment(
            leaf_manifest, projection, 1);
    const uint256 receive_schedule =
        CtlScheduleCommitment(
            leaf_manifest, projection, -1);
    ctl_manifest.bus_id =
        kSameParentCtlBusIdV1 +
        projection_slot;
    ctl_manifest.transcript_seed =
        CtlTranscriptSeed(
            leaf_manifest, projection_slot);
    ctl_manifest.participants = {
        {
            RCStage3RelationRole::EpisodeGemm,
            leaf_manifest.n_rows,
            leaf_manifest.n_rows,
            0,
            send_schedule,
        },
        {
            RCStage3RelationRole::CompositionLink,
            leaf_manifest.n_rows,
            0,
            leaf_manifest.n_rows,
            receive_schedule,
        },
    };
    if (ctl_manifest.transcript_seed.IsNull() ||
        send_schedule.IsNull() ||
        receive_schedule.IsNull()) {
        return Fail(why, "ctl_challenge_manifest");
    }
    pins.resize(2);
    for (uint32_t i = 0; i < pins.size(); ++i) {
        const auto& participant =
            ctl_manifest.participants[i];
        auto& pin = pins[i];
        pin.role = participant.role;
        pin.bus_id = ctl_manifest.bus_id;
        pin.event_count =
            participant.event_count;
        pin.send_count =
            participant.send_count;
        pin.receive_count =
            participant.receive_count;
        pin.schedule_commitment =
            participant.schedule_commitment;
        // Both relations occupy one R0 group.  The same root therefore
        // commits the producer and receiver before gamma/alpha exist.
        pin.trace_commitment =
            base_row_commitment;
    }
    if (!DeriveRCStage3CtlChallenges(
            ctl_manifest, pins,
            challenges, why)) {
        return false;
    }
    return true;
}

struct TupleColumnsV1 {
    uint32_t endpoint{0};
    uint32_t role{0};
    uint32_t address{0};
    uint32_t remaining{0};
    uint32_t value{0};
};

Fp3 CompressTuple(
    const std::vector<Fp3>& row,
    const TupleColumnsV1& columns,
    const Fp3& gamma)
{
    const Fp3 gamma2 =
        gf::Mul(gamma, gamma);
    const Fp3 gamma3 =
        gf::Mul(gamma2, gamma);
    const Fp3 gamma4 =
        gf::Mul(gamma3, gamma);
    return gf::Add(
        row[columns.endpoint],
        gf::Add(
            gf::Mul(
                gamma, row[columns.role]),
            gf::Add(
                gf::Mul(
                    gamma2,
                    row[columns.address]),
                gf::Add(
                    gf::Mul(
                        gamma3,
                        row[columns.remaining]),
                    gf::Mul(
                        gamma4,
                        row[columns.value])))));
}

bool BuildReceiverConstraintSystem(
    const LeafManifestV1& manifest,
    const SourceProjectionV1& projection,
    AirCs& out,
    std::string* why)
{
    out = {};
    const auto role =
        RCStage3EpisodeEndpointRole(
            projection.endpoint);
    cb::ProgramTable table;
    if (!role.has_value() ||
        !BuildRCStage3EpisodeSemanticMemoryProgramTable(
            *role, table, why) ||
        !cb::BuildAirConstraintSystemFromProgramTable(
            table, manifest.n_rows, out, why) ||
        out.n_columns !=
            kReceiverColumnsV1) {
        out = {};
        return Fail(why, "receiver_program");
    }
    std::vector<std::vector<Fp3>> schedule(
        kTotalColumnsV1);
    if (!FillSchedule(
            manifest, schedule, true, why)) {
        out = {};
        return false;
    }
    out.preprocessed = {
        {
            kRCStage3EpisodeMemoryActive,
            schedule[projection.active_column],
        },
        {
            kRCStage3EpisodeMemoryAddress,
            schedule[projection.address_column],
        },
        {
            kRCStage3EpisodeMemoryRemaining,
            schedule[projection.remaining_column],
        },
        {
            kRCStage3EpisodeMemoryEndpoint,
            schedule[projection.endpoint_column],
        },
        {
            kRCStage3EpisodeMemoryRole,
            schedule[projection.role_column],
        },
    };
    out.preprocessed_pin_ood = true;
    return true;
}

void AddCtlSideConstraints(
    AirCs& out,
    const char* name_prefix,
    const TupleColumnsV1& tuple,
    uint32_t dependent_base,
    int8_t multiplicity,
    const RCStage3CtlChallenges& challenges,
    const RCStage3CtlTerminal& terminal)
{
    const uint32_t inverse1 =
        dependent_base + kCtlInverse1V1;
    const uint32_t inverse2 =
        dependent_base + kCtlInverse2V1;
    const uint32_t term1 =
        dependent_base + kCtlTerm1V1;
    const uint32_t term2 =
        dependent_base + kCtlTerm2V1;
    const uint32_t running1 =
        dependent_base + kCtlRunning1V1;
    const uint32_t running2 =
        dependent_base + kCtlRunning2V1;
    const Fp3 sign =
        Signed(multiplicity);
    const auto add =
        [&](const char*,
            aq::AirKind kind,
            uint32_t degree,
            auto eval) {
            out.constraints.push_back({
                name_prefix,
                kind, degree, std::move(eval)});
        };
    add(
        ".inverse1", aq::AirKind::kEverywhere, 2,
        [tuple, inverse1, challenges](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Sub(
                gf::Mul(
                    row[inverse1],
                    gf::Sub(
                        challenges.alpha1,
                        CompressTuple(
                            row, tuple,
                            challenges.gamma1))),
                Fp3::One());
        });
    add(
        ".inverse2", aq::AirKind::kEverywhere, 2,
        [tuple, inverse2, challenges](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Sub(
                gf::Mul(
                    row[inverse2],
                    gf::Sub(
                        challenges.alpha2,
                        CompressTuple(
                            row, tuple,
                            challenges.gamma2))),
                Fp3::One());
        });
    add(
        ".term1", aq::AirKind::kEverywhere, 1,
        [inverse1, term1, sign](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Sub(
                row[term1],
                gf::Mul(sign, row[inverse1]));
        });
    add(
        ".term2", aq::AirKind::kEverywhere, 1,
        [inverse2, term2, sign](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Sub(
                row[term2],
                gf::Mul(sign, row[inverse2]));
        });
    add(
        ".running1.first", aq::AirKind::kFirstRow, 1,
        [running1](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return row[running1];
        });
    add(
        ".running2.first", aq::AirKind::kFirstRow, 1,
        [running2](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return row[running2];
        });
    add(
        ".running1.transition",
        aq::AirKind::kTransition, 1,
        [running1, term1](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>& next) {
            return gf::Sub(
                next[running1],
                gf::Add(
                    row[running1], row[term1]));
        });
    add(
        ".running2.transition",
        aq::AirKind::kTransition, 1,
        [running2, term2](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>& next) {
            return gf::Sub(
                next[running2],
                gf::Add(
                    row[running2], row[term2]));
        });
    add(
        ".running1.last", aq::AirKind::kLastRow, 1,
        [running1, term1, terminal](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Sub(
                gf::Add(
                    row[running1], row[term1]),
                terminal.alpha1_sum);
        });
    add(
        ".running2.last", aq::AirKind::kLastRow, 1,
        [running2, term2, terminal](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Sub(
                gf::Add(
                    row[running2], row[term2]),
                terminal.alpha2_sum);
        });
}

bool BuildSameParentConstraintSystem(
    const LeafManifestV1& manifest,
    uint32_t projection_slot,
    const RCStage3CtlChallenges& challenges,
    const RCStage3CtlTerminal& source_terminal,
    const RCStage3CtlTerminal& receiver_terminal,
    AirCs& out,
    std::string* why)
{
    out = {};
    if (!ManifestValid(manifest, why) ||
        projection_slot >= kEndpointCountV1 ||
        !CanonicalFp3(challenges.gamma1) ||
        !CanonicalFp3(challenges.gamma2) ||
        !CanonicalFp3(challenges.alpha1) ||
        !CanonicalFp3(challenges.alpha2) ||
        gf::IsZero(challenges.gamma1) ||
        gf::IsZero(challenges.gamma2) ||
        gf::Eq(
            challenges.gamma1,
            challenges.gamma2) ||
        gf::Eq(
            challenges.alpha1,
            challenges.alpha2) ||
        !CanonicalFp3(
            source_terminal.alpha1_sum) ||
        !CanonicalFp3(
            source_terminal.alpha2_sum) ||
        !CanonicalFp3(
            receiver_terminal.alpha1_sum) ||
        !CanonicalFp3(
            receiver_terminal.alpha2_sum)) {
        return Fail(why, "join_cs_shape");
    }
    AirCs source;
    AirCs receiver;
    const auto& projection =
        CanonicalSourceProjectionsV1()[
            projection_slot];
    if (!BuildExpectedConstraintSystemV1(
            manifest, source, why) ||
        !BuildReceiverConstraintSystem(
            manifest, projection,
            receiver, why)) {
        return false;
    }
    out.n_rows = manifest.n_rows;
    out.n_columns =
        kSameParentCtlColumnsV1;
    out.preprocessed_pin_ood = true;
    CopyConstraintFamily(source, 0, out);
    CopyConstraintFamily(
        receiver, kReceiverColumnBaseV1, out);

    const TupleColumnsV1 source_tuple{
        projection.endpoint_column,
        projection.role_column,
        projection.address_column,
        projection.remaining_column,
        projection.semantic_value_column,
    };
    const TupleColumnsV1 receiver_tuple{
        kReceiverColumnBaseV1 +
            kRCStage3EpisodeMemoryEndpoint,
        kReceiverColumnBaseV1 +
            kRCStage3EpisodeMemoryRole,
        kReceiverColumnBaseV1 +
            kRCStage3EpisodeMemoryAddress,
        kReceiverColumnBaseV1 +
            kRCStage3EpisodeMemoryRemaining,
        kReceiverColumnBaseV1 +
            kRCStage3EpisodeMemoryValue,
    };
    AddCtlSideConstraints(
        out, "stage3.episode_source_ctl.source",
        source_tuple, kCtlDependentBaseV1, 1,
        challenges, source_terminal);
    const uint32_t receiver_dependent =
        kCtlDependentBaseV1 +
        kCtlDependentColumnsPerSideV1;
    AddCtlSideConstraints(
        out, "stage3.episode_source_ctl.receiver",
        receiver_tuple, receiver_dependent, -1,
        challenges, receiver_terminal);

    for (uint32_t lane = 0; lane < 2; ++lane) {
        const uint32_t source_running =
            kCtlDependentBaseV1 +
            (lane == 0
                 ? kCtlRunning1V1
                 : kCtlRunning2V1);
        const uint32_t source_term =
            kCtlDependentBaseV1 +
            (lane == 0
                 ? kCtlTerm1V1
                 : kCtlTerm2V1);
        const uint32_t receiver_running =
            receiver_dependent +
            (lane == 0
                 ? kCtlRunning1V1
                 : kCtlRunning2V1);
        const uint32_t receiver_term =
            receiver_dependent +
            (lane == 0
                 ? kCtlTerm1V1
                 : kCtlTerm2V1);
        out.constraints.push_back({
            "stage3.episode_source_ctl."
            "same_parent_terminal_cancel",
            aq::AirKind::kLastRow,
            1,
            [source_running, source_term,
             receiver_running, receiver_term](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Add(
                    gf::Add(
                        row[source_running],
                        row[source_term]),
                    gf::Add(
                        row[receiver_running],
                        row[receiver_term]));
            },
        });
    }
    return out.QuotientLen() != 0 ||
        Fail(why, "join_cs_empty");
}

std::vector<uint32_t> SameParentBaseIndices()
{
    std::vector<uint32_t> out(
        kCtlDependentBaseV1);
    std::iota(out.begin(), out.end(), 0);
    return out;
}

bool BuildSameParentBaseColumns(
    const LeafManifestV1& manifest,
    uint32_t projection_slot,
    const std::vector<std::vector<Fp3>>&
        source_columns,
    std::vector<std::vector<Fp3>>& out,
    std::string* why)
{
    out.assign(
        kSameParentCtlColumnsV1,
        std::vector<Fp3>(
            manifest.n_rows, Fp3::Zero()));
    if (projection_slot >= kEndpointCountV1 ||
        source_columns.size() !=
            kTotalColumnsV1 ||
        !std::all_of(
            source_columns.begin(),
            source_columns.end(),
            [&manifest](const auto& column) {
                return column.size() ==
                    manifest.n_rows;
            })) {
        out = {};
        return Fail(why, "join_base_columns_shape");
    }
    std::copy(
        source_columns.begin(),
        source_columns.end(),
        out.begin());
    const auto& projection =
        CanonicalSourceProjectionsV1()[
            projection_slot];
    const std::array<
        std::pair<uint32_t, uint32_t>, 5>
        metadata{{
            {
                kRCStage3EpisodeMemoryActive,
                projection.active_column,
            },
            {
                kRCStage3EpisodeMemoryAddress,
                projection.address_column,
            },
            {
                kRCStage3EpisodeMemoryRemaining,
                projection.remaining_column,
            },
            {
                kRCStage3EpisodeMemoryEndpoint,
                projection.endpoint_column,
            },
            {
                kRCStage3EpisodeMemoryRole,
                projection.role_column,
            },
        }};
    for (const auto& [receiver, source] :
         metadata) {
        out[kReceiverColumnBaseV1 + receiver] =
            source_columns[source];
    }
    out[
        kReceiverColumnBaseV1 +
        kRCStage3EpisodeMemoryValue] =
        source_columns[
            projection.semantic_value_column];
    out[
        kReceiverColumnBaseV1 +
        kRCStage3EpisodeMemoryExport] =
        source_columns[
            projection.semantic_value_column];
    return true;
}

bool PopulateCtlSideWitness(
    const TupleColumnsV1& tuple,
    uint32_t dependent_base,
    int8_t multiplicity,
    const RCStage3CtlChallenges& challenges,
    std::vector<std::vector<Fp3>>& columns,
    RCStage3CtlTerminal& terminal,
    std::string* why)
{
    terminal = {};
    const Fp3 sign =
        Signed(multiplicity);
    Fp3 running1 = Fp3::Zero();
    Fp3 running2 = Fp3::Zero();
    for (uint32_t row = 0;
         row < columns.front().size(); ++row) {
        std::vector<Fp3> current(
            columns.size(), Fp3::Zero());
        for (uint32_t column :
             {tuple.endpoint, tuple.role,
              tuple.address, tuple.remaining,
              tuple.value}) {
            current[column] =
                columns[column][row];
        }
        const Fp3 denominator1 =
            gf::Sub(
                challenges.alpha1,
                CompressTuple(
                    current, tuple,
                    challenges.gamma1));
        const Fp3 denominator2 =
            gf::Sub(
                challenges.alpha2,
                CompressTuple(
                    current, tuple,
                    challenges.gamma2));
        if (gf::IsZero(denominator1) ||
            gf::IsZero(denominator2)) {
            return Fail(
                why, "join_ctl_zero_denominator");
        }
        const Fp3 inverse1 =
            gf::Inv(denominator1);
        const Fp3 inverse2 =
            gf::Inv(denominator2);
        const Fp3 term1 =
            gf::Mul(sign, inverse1);
        const Fp3 term2 =
            gf::Mul(sign, inverse2);
        columns[
            dependent_base +
            kCtlInverse1V1][row] = inverse1;
        columns[
            dependent_base +
            kCtlInverse2V1][row] = inverse2;
        columns[
            dependent_base +
            kCtlTerm1V1][row] = term1;
        columns[
            dependent_base +
            kCtlTerm2V1][row] = term2;
        columns[
            dependent_base +
            kCtlRunning1V1][row] = running1;
        columns[
            dependent_base +
            kCtlRunning2V1][row] = running2;
        running1 =
            gf::Add(running1, term1);
        running2 =
            gf::Add(running2, term2);
    }
    terminal.alpha1_sum = running1;
    terminal.alpha2_sum = running2;
    return true;
}

bool BuildSameParentFinalColumns(
    const LeafManifestV1& manifest,
    uint32_t projection_slot,
    const std::vector<std::vector<Fp3>>&
        source_columns,
    const RCStage3CtlChallenges& challenges,
    std::vector<std::vector<Fp3>>& out,
    RCStage3CtlTerminal& source_terminal,
    RCStage3CtlTerminal& receiver_terminal,
    std::string* why)
{
    if (!BuildSameParentBaseColumns(
            manifest, projection_slot,
            source_columns, out, why)) {
        return false;
    }
    const auto& projection =
        CanonicalSourceProjectionsV1()[
            projection_slot];
    const TupleColumnsV1 source_tuple{
        projection.endpoint_column,
        projection.role_column,
        projection.address_column,
        projection.remaining_column,
        projection.semantic_value_column,
    };
    const TupleColumnsV1 receiver_tuple{
        kReceiverColumnBaseV1 +
            kRCStage3EpisodeMemoryEndpoint,
        kReceiverColumnBaseV1 +
            kRCStage3EpisodeMemoryRole,
        kReceiverColumnBaseV1 +
            kRCStage3EpisodeMemoryAddress,
        kReceiverColumnBaseV1 +
            kRCStage3EpisodeMemoryRemaining,
        kReceiverColumnBaseV1 +
            kRCStage3EpisodeMemoryValue,
    };
    if (!PopulateCtlSideWitness(
            source_tuple, kCtlDependentBaseV1,
            1, challenges, out,
            source_terminal, why) ||
        !PopulateCtlSideWitness(
            receiver_tuple,
            kCtlDependentBaseV1 +
                kCtlDependentColumnsPerSideV1,
            -1, challenges, out,
            receiver_terminal, why) ||
        !gf::IsZero(gf::Add(
            source_terminal.alpha1_sum,
            receiver_terminal.alpha1_sum)) ||
        !gf::IsZero(gf::Add(
            source_terminal.alpha2_sum,
            receiver_terminal.alpha2_sum))) {
        out = {};
        return Fail(why, "join_terminal_cancel");
    }
    return true;
}

uint256 SameParentFsSeed(
    const LeafManifestV1& manifest,
    uint32_t projection_slot,
    const uint256& base_row_commitment,
    const RCStage3CtlChallenges& challenges)
{
    if (!ManifestValid(manifest, nullptr) ||
        projection_slot >= kEndpointCountV1 ||
        base_row_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << CTL_FS_DOMAIN << kVersionV1;
    hash << manifest.manifest_commitment;
    hash << projection_slot;
    hash << base_row_commitment;
    hash << CommitRCStage3CtlChallenges(
        challenges);
    return hash.GetHash();
}

uint256 SameParentProofCommitment(
    const aq::AirQuotientSplitRapRowsProof& proof)
{
    std::vector<unsigned char> bytes;
    if (aq::SerializeAirQuotientSplitRapRowsProof(
            proof, bytes) == 0 ||
        bytes.empty()) {
        return {};
    }
    HashWriter hash;
    hash << CTL_PROOF_DOMAIN << kVersionV1;
    hash << static_cast<uint64_t>(bytes.size());
    hash << bytes;
    return hash.GetHash();
}

uint256 SameParentJoinCommitment(
    const LeafManifestV1& manifest,
    const SameParentCtlJoinV1& join)
{
    if (!ManifestValid(manifest, nullptr) ||
        join.version != kVersionV1 ||
        join.projection_slot >= kEndpointCountV1 ||
        join.endpoint !=
            CanonicalSourceProjectionsV1()[
                join.projection_slot].endpoint ||
        join.public_fs_seed.IsNull() ||
        join.base_row_commitment.IsNull() ||
        join.proof_commitment.IsNull() ||
        !join.source_value_same_trace_constrained ||
        !join.receiver_semantic_memory_executed ||
        !join.proof_owned_dual_alpha_terminal ||
        !join.same_parent_terminal_cancellation) {
        return {};
    }
    HashWriter hash;
    hash << CTL_JOIN_DOMAIN << join.version;
    hash << manifest.manifest_commitment;
    hash << static_cast<uint16_t>(
        join.endpoint);
    hash << join.projection_slot;
    WriteFp3(hash, join.challenges.gamma1);
    WriteFp3(hash, join.challenges.gamma2);
    WriteFp3(hash, join.challenges.alpha1);
    WriteFp3(hash, join.challenges.alpha2);
    WriteFp3(
        hash, join.source_terminal.alpha1_sum);
    WriteFp3(
        hash, join.source_terminal.alpha2_sum);
    WriteFp3(
        hash, join.receiver_terminal.alpha1_sum);
    WriteFp3(
        hash, join.receiver_terminal.alpha2_sum);
    hash << join.public_fs_seed;
    hash << join.base_row_commitment;
    hash << static_cast<uint32_t>(
        join.base_column_indices.size());
    for (uint32_t column :
         join.base_column_indices) {
        hash << column;
    }
    hash << join.proof_commitment;
    hash << join.source_value_same_trace_constrained;
    hash << join.receiver_semantic_memory_executed;
    hash << join.proof_owned_dual_alpha_terminal;
    hash << join.same_parent_terminal_cancellation;
    return hash.GetHash();
}

bool ProveSameParentCtlJoin(
    const LeafManifestV1& manifest,
    const std::vector<std::vector<Fp3>>&
        source_columns,
    uint32_t projection_slot,
    SameParentCtlJoinV1& out,
    std::string* why)
{
    out = {};
    if (projection_slot >= kEndpointCountV1) {
        return Fail(why, "join_prove_slot");
    }
    const RCStage3CtlChallenges placeholder{
        U64(2), U64(3), U64(5), U64(7)};
    const RCStage3CtlTerminal zero_terminal{};
    AirCs placeholder_cs;
    std::vector<std::vector<Fp3>>
        base_columns;
    const std::vector<uint32_t> base_indices =
        SameParentBaseIndices();
    if (!BuildSameParentConstraintSystem(
            manifest, projection_slot,
            placeholder, zero_terminal,
            zero_terminal, placeholder_cs, why) ||
        !BuildSameParentBaseColumns(
            manifest, projection_slot,
            source_columns, base_columns, why)) {
        return false;
    }
    const auto r0 =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            placeholder_cs, base_columns,
            base_indices);
    if (!r0.valid ||
        r0.base_row_commitment.IsNull()) {
        return Fail(
            why, "join_prove_r0:" + r0.note);
    }
    RCStage3CtlManifest ctl_manifest;
    std::vector<RCStage3CtlChildPin> pins;
    RCStage3CtlChallenges challenges;
    if (!BuildCtlChallengeMaterial(
            manifest, projection_slot,
            r0.base_row_commitment,
            ctl_manifest, pins,
            challenges, why)) {
        return false;
    }
    std::vector<std::vector<Fp3>>
        final_columns;
    RCStage3CtlTerminal source_terminal;
    RCStage3CtlTerminal receiver_terminal;
    AirCs final_cs;
    if (!BuildSameParentFinalColumns(
            manifest, projection_slot,
            source_columns, challenges,
            final_columns, source_terminal,
            receiver_terminal, why) ||
        !BuildSameParentConstraintSystem(
            manifest, projection_slot,
            challenges, source_terminal,
            receiver_terminal,
            final_cs, why)) {
        return false;
    }
    const uint256 public_fs_seed =
        SameParentFsSeed(
            manifest, projection_slot,
            r0.base_row_commitment,
            challenges);
    if (public_fs_seed.IsNull()) {
        return Fail(why, "join_prove_seed");
    }
    const auto proved =
        aq::AirQuotientProveRowsSplitRapSafeV2(
            final_cs, final_columns,
            base_indices, public_fs_seed,
            {}, &r0);
    if (!proved.ok ||
        !proved.division_exact) {
        return Fail(
            why, "join_prove_air:" + proved.note);
    }
    std::string verify_why;
    if (!aq::AirQuotientVerifyRowsSplitRapSafeV2(
            final_cs, proved.proof,
            base_indices, public_fs_seed,
            &verify_why)) {
        return Fail(
            why, "join_prove_verify:" +
                verify_why);
    }

    out.version = kVersionV1;
    out.endpoint =
        CanonicalSourceProjectionsV1()[
            projection_slot].endpoint;
    out.projection_slot = projection_slot;
    out.challenges = challenges;
    out.source_terminal = source_terminal;
    out.receiver_terminal = receiver_terminal;
    out.public_fs_seed = public_fs_seed;
    out.base_row_commitment =
        r0.base_row_commitment;
    out.base_column_indices =
        base_indices;
    out.proof = proved.proof;
    out.proof_commitment =
        SameParentProofCommitment(out.proof);
    out.source_value_same_trace_constrained =
        true;
    out.receiver_semantic_memory_executed =
        true;
    out.proof_owned_dual_alpha_terminal =
        true;
    out.same_parent_terminal_cancellation =
        true;
    out.join_commitment =
        SameParentJoinCommitment(manifest, out);
    if (out.proof_commitment.IsNull() ||
        out.join_commitment.IsNull()) {
        out = {};
        return Fail(why, "join_prove_commitment");
    }
    return true;
}

uint256 ExactCoverageCommitment(
    const LayerShapeV1& shape,
    const std::vector<LeafReceiptV1>& leaves)
{
    if (!ShapeFieldsValid(shape, nullptr) ||
        shape.shape_commitment !=
            ComputeLayerShapeCommitmentV1(shape) ||
        leaves.size() != ExpectedLeafCount(shape)) {
        return {};
    }
    HashWriter hash;
    hash << COVERAGE_DOMAIN << kVersionV1;
    hash << shape.shape_commitment;
    hash << shape.tile_count;
    hash << TilesPerShard(shape);
    hash << ExpectedLeafCount(shape);
    hash << EndpointTotal(shape, kOperandASlotV1);
    hash << EndpointTotal(shape, kOperandBSlotV1);
    hash << EndpointTotal(shape, kOutputYSlotV1);
    const uint32_t capacity = TilesPerShard(shape);
    uint64_t next_tile = 0;
    for (uint64_t shard = 0;
         shard < leaves.size(); ++shard) {
        const uint32_t count =
            static_cast<uint32_t>(
                std::min<uint64_t>(
                    capacity,
                    shape.tile_count - next_tile));
        if (leaves[shard].manifest.tile_begin !=
                next_tile ||
            leaves[shard].manifest.tile_count != count ||
            leaves[shard].receipt_commitment.IsNull()) {
            return {};
        }
        hash << shard;
        hash << next_tile;
        hash << count;
        hash << leaves[shard].manifest.schedule_commitment;
        hash << leaves[shard].node_root;
        hash << leaves[shard].receipt_commitment;
        next_tile += count;
    }
    if (next_tile != shape.tile_count) return {};
    return hash.GetHash();
}

} // namespace

const std::array<SourceProjectionV1, kEndpointCountV1>&
CanonicalSourceProjectionsV1()
{
    static const std::array<
        SourceProjectionV1, kEndpointCountV1> projections{{
        {
            RCStage3RelationEndpoint::EpisodeGemmOperandA,
            kMetadataColumnBaseV1 + 0,
            kMetadataColumnBaseV1 + 1,
            kMetadataColumnBaseV1 + 2,
            kMetadataColumnBaseV1 + 3,
            kMetadataColumnBaseV1 + 4,
            kRCStage3GemmDotA,
            kMetadataColumnBaseV1 + 5,
            kMetadataColumnBaseV1 + 6,
        },
        {
            RCStage3RelationEndpoint::EpisodeGemmOperandB,
            kMetadataColumnBaseV1 + 7,
            kMetadataColumnBaseV1 + 8,
            kMetadataColumnBaseV1 + 9,
            kMetadataColumnBaseV1 + 10,
            kMetadataColumnBaseV1 + 11,
            kRCStage3GemmDotB,
            kMetadataColumnBaseV1 + 12,
            kMetadataColumnBaseV1 + 13,
        },
        {
            RCStage3RelationEndpoint::EpisodeGemmOutputY,
            kMetadataColumnBaseV1 + 14,
            kMetadataColumnBaseV1 + 15,
            kMetadataColumnBaseV1 + 16,
            kMetadataColumnBaseV1 + 17,
            kMetadataColumnBaseV1 + 18,
            kRCStage3GemmDotY,
            kMetadataColumnBaseV1 + 19,
            kMetadataColumnBaseV1 + 20,
        },
    }};
    return projections;
}

uint256 ComputeLayerShapeCommitmentV1(
    const LayerShapeV1& shape)
{
    if (!ShapeFieldsValid(shape, nullptr)) {
        return {};
    }
    HashWriter hash;
    hash << SHAPE_DOMAIN << shape.magic;
    hash << shape.version;
    hash << shape.statement_commitment;
    hash << shape.gemm_manifest_commitment;
    hash << shape.layer_ordinal;
    hash << shape.m << shape.n << shape.k;
    hash << shape.b_transpose;
    hash << shape.tile_count;
    return hash.GetHash();
}

bool BuildLayerShapeV1(
    const uint256& statement_commitment,
    const uint256& gemm_manifest_commitment,
    const RCStage3GemmExtractLayerManifest& spec,
    LayerShapeV1& out,
    std::string* why)
{
    out = {};
    out.statement_commitment = statement_commitment;
    out.gemm_manifest_commitment =
        gemm_manifest_commitment;
    out.layer_ordinal = spec.ordinal;
    out.m = spec.m;
    out.n = spec.n;
    out.k = spec.k;
    out.b_transpose = spec.b.transpose;
    out.tile_count = spec.extract_tile_count;
    if (!ShapeFieldsValid(out, why) ||
        spec.extract_tile_count !=
            uint64_t{spec.m} *
                (spec.n / kRCMxBlockLen) ||
        spec.gemm_cell_count !=
            uint64_t{spec.m} * spec.n) {
        out = {};
        return Fail(why, "build_shape");
    }
    out.shape_commitment =
        ComputeLayerShapeCommitmentV1(out);
    if (out.shape_commitment.IsNull()) {
        out = {};
        return Fail(why, "build_shape_commitment");
    }
    return true;
}

bool BuildCanonicalProgramTableV1(
    cb::ProgramTable& out,
    std::string* why)
{
    out = {};
    out.role = RCStage3RelationRole::EpisodeGemm;
    out.current_width = kTotalColumnsV1;
    out.next_width = kTotalColumnsV1;
    out.challenge_width = 0;

    for (uint32_t column : {
             kRCStage3GemmDotActive,
             kRCStage3GemmDotStart,
             kRCStage3GemmDotEnd}) {
        AppendBoolean(out, column);
    }
    Append(
        out, aq::AirKind::kEverywhere, 3,
        [](ProgramBuilder& b) {
            b.Mul(
                b.Current(kRCStage3GemmDotActive),
                b.Sub(
                    b.Current(kRCStage3GemmDotProduct),
                    b.Mul(
                        b.Current(kRCStage3GemmDotA),
                        b.Current(kRCStage3GemmDotB))));
        });
    Append(
        out, aq::AirKind::kEverywhere, 2,
        [](ProgramBuilder& b) {
            b.Mul(
                b.Current(kRCStage3GemmDotActive),
                b.Sub(
                    b.Current(
                        kRCStage3GemmDotAccumulatorAfter),
                    b.Add(
                        b.Current(
                            kRCStage3GemmDotAccumulatorBefore),
                        b.Current(
                            kRCStage3GemmDotProduct))));
        });
    Append(
        out, aq::AirKind::kEverywhere, 2,
        [](ProgramBuilder& b) {
            b.Mul(
                b.Current(kRCStage3GemmDotStart),
                b.Current(
                    kRCStage3GemmDotAccumulatorBefore));
        });
    Append(
        out, aq::AirKind::kEverywhere, 2,
        [](ProgramBuilder& b) {
            b.Mul(
                b.Current(kRCStage3GemmDotEnd),
                b.Sub(
                    b.Current(kRCStage3GemmDotY),
                    b.Current(
                        kRCStage3GemmDotAccumulatorAfter)));
        });
    Append(
        out, aq::AirKind::kEverywhere, 2,
        [](ProgramBuilder& b) {
            b.Mul(
                b.Current(kRCStage3GemmDotEnd),
                b.Sub(
                    b.Current(
                        kRCStage3GemmDotExtractInput),
                    b.Add(
                        b.Current(kRCStage3GemmDotY),
                        b.Current(
                            kRCStage3GemmDotResidual))));
        });
    Append(
        out, aq::AirKind::kTransition, 3,
        [](ProgramBuilder& b) {
            b.Mul(
                b.Mul(
                    b.Current(kRCStage3GemmDotActive),
                    b.Sub(
                        b.Constant(Fp3::One()),
                        b.Current(kRCStage3GemmDotEnd))),
                b.Sub(
                    b.Next(
                        kRCStage3GemmDotAccumulatorBefore),
                    b.Current(
                        kRCStage3GemmDotAccumulatorAfter)));
        });
    for (uint32_t column : {
             kRCStage3GemmDotProduct,
             kRCStage3GemmDotAccumulatorBefore,
             kRCStage3GemmDotAccumulatorAfter}) {
        Append(
            out, aq::AirKind::kEverywhere, 2,
            [column](ProgramBuilder& b) {
                b.Mul(
                    b.Sub(
                        b.Constant(Fp3::One()),
                        b.Current(
                            kRCStage3GemmDotActive)),
                    b.Current(column));
            });
    }

    for (const auto& projection :
         CanonicalSourceProjectionsV1()) {
        AppendBoolean(out, projection.active_column);
        const uint32_t required_control =
            projection.endpoint ==
                    RCStage3RelationEndpoint::
                        EpisodeGemmOutputY
                ? kRCStage3GemmDotEnd
                : kRCStage3GemmDotActive;
        Append(
            out, aq::AirKind::kEverywhere, 2,
            [projection,
             required_control](ProgramBuilder& b) {
                b.Mul(
                    b.Current(
                        projection.active_column),
                    b.Sub(
                        b.Constant(Fp3::One()),
                        b.Current(required_control)));
            });
        Append(
            out, aq::AirKind::kEverywhere, 2,
            [projection](ProgramBuilder& b) {
                b.Sub(
                    b.Current(
                        projection.semantic_value_column),
                    b.Mul(
                        b.Current(
                            projection.active_column),
                        b.Current(
                            projection.value_column)));
            });
        Append(
            out, aq::AirKind::kEverywhere, 1,
            [projection](ProgramBuilder& b) {
                b.Sub(
                    b.Current(
                        projection.export_column),
                    b.Current(
                        projection.semantic_value_column));
            });
    }

    std::string validation_why;
    if (!cb::ValidateProgramTable(
            out, &validation_why) ||
        out.current_width != kTotalColumnsV1 ||
        out.challenge_width != 0 ||
        !cb::ProgramTableIsChallengeIndependent(out)) {
        for (uint32_t ordinal = 0;
             ordinal < out.programs.size();
             ++ordinal) {
            std::string program_why;
            if (!cb::ValidateProgram(
                    out.programs[ordinal],
                    &program_why)) {
                validation_why +=
                    ":ordinal=" +
                    std::to_string(ordinal) +
                    ":" + program_why;
                break;
            }
        }
        out = {};
        return Fail(
            why, "program_table:" +
                validation_why);
    }
    return true;
}

bool BuildLeafManifestV1(
    const LayerShapeV1& shape,
    uint64_t tile_begin,
    uint32_t tile_count,
    LeafManifestV1& out,
    std::string* why)
{
    out = {};
    if (!ShapeFieldsValid(shape, why) ||
        shape.shape_commitment !=
            ComputeLayerShapeCommitmentV1(shape) ||
        tile_count == 0 ||
        tile_begin >= shape.tile_count ||
        tile_count > shape.tile_count - tile_begin) {
        return Fail(why, "build_manifest_shape");
    }
    cb::ProgramTable table;
    if (!BuildCanonicalProgramTableV1(
            table, why)) {
        return false;
    }
    const auto keys =
        cb::CommitProgramTableForExternalAndRecursiveUse(
            table);
    if (!keys.same_canonical_serialization) {
        return Fail(why, "build_manifest_program");
    }

    out.shape = shape;
    out.tile_begin = tile_begin;
    out.tile_count = tile_count;
    out.tile_rows =
        shape.k * kRCMxBlockLen;
    const uint64_t logical_rows =
        uint64_t{out.tile_rows} * tile_count;
    if (logical_rows >
        kMaxTraceRowsPerShardV1) {
        out = {};
        return Fail(why, "build_manifest_shard_rows");
    }
    out.logical_rows =
        static_cast<uint32_t>(logical_rows);
    out.n_rows =
        NextPowerOfTwo(out.logical_rows);
    out.program_table_sha256d =
        keys.external_sha256d;
    out.program_table_alg =
        aq::AirFriBackendAlg<Fp3>::PackDigest(
            keys.recursive_alg_hash);
    out.schedule_commitment =
        ScheduleCommitment(out);
    out.expected_cs_commitment =
        ExpectedCsCommitment(out);
    out.manifest_commitment =
        LeafManifestCommitment(out);
    if (!ManifestValid(out, why)) {
        out = {};
        return false;
    }
    return true;
}

bool BuildExpectedConstraintSystemV1(
    const LeafManifestV1& manifest,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    out = {};
    if (!ManifestValid(manifest, why)) {
        return false;
    }
    cb::ProgramTable table;
    if (!BuildCanonicalProgramTableV1(
            table, why) ||
        !cb::BuildAirConstraintSystemFromProgramTable(
            table, manifest.n_rows, out, why) ||
        out.n_columns != kTotalColumnsV1) {
        out = {};
        return Fail(why, "expected_cs_program");
    }

    std::vector<std::vector<Fp3>> schedule(
        kTotalColumnsV1);
    if (!FillSchedule(
            manifest, schedule, true, why)) {
        out = {};
        return false;
    }
    for (uint32_t column : {
             kRCStage3GemmDotActive,
             kRCStage3GemmDotStart,
             kRCStage3GemmDotEnd}) {
        std::vector<Fp3> values(
            manifest.n_rows, Fp3::Zero());
        for (uint32_t row = 0;
             row < manifest.logical_rows; ++row) {
            const uint32_t contraction =
                row % manifest.shape.k;
            if (column == kRCStage3GemmDotActive) {
                values[row] = Fp3::One();
            } else if (
                column == kRCStage3GemmDotStart &&
                contraction == 0) {
                values[row] = Fp3::One();
            } else if (
                column == kRCStage3GemmDotEnd &&
                contraction + 1 ==
                    manifest.shape.k) {
                values[row] = Fp3::One();
            }
        }
        out.preprocessed.emplace_back(
            column, std::move(values));
    }
    for (const auto& projection :
         CanonicalSourceProjectionsV1()) {
        for (uint32_t column : {
                 projection.active_column,
                 projection.address_column,
                 projection.remaining_column,
                 projection.endpoint_column,
                 projection.role_column}) {
            out.preprocessed.emplace_back(
                column, std::move(schedule[column]));
        }
    }
    out.preprocessed_pin_ood = true;
    return true;
}

bool BuildLeafWitnessV1(
    const LeafManifestV1& manifest,
    const RCStage3EpisodeGemmLayerProduct& layer,
    const RCStage3EpisodeExtractProduct& extract,
    uint64_t extract_tile_begin,
    std::vector<std::vector<Fp3>>& out,
    std::string* why)
{
    out.assign(
        kTotalColumnsV1,
        std::vector<Fp3>(
            manifest.n_rows, Fp3::Zero()));
    if (!ManifestValid(manifest, why) ||
        layer.layer_ordinal !=
            manifest.shape.layer_ordinal ||
        layer.operand_a.size() !=
            uint64_t{manifest.shape.m} *
                manifest.shape.k ||
        layer.operand_b.size() !=
            uint64_t{manifest.shape.k} *
                manifest.shape.n ||
        layer.gemm_y.size() !=
            uint64_t{manifest.shape.m} *
                manifest.shape.n ||
        (!layer.residual.empty() &&
         layer.residual.size() !=
            layer.gemm_y.size()) ||
        extract_tile_begin >
            std::numeric_limits<uint64_t>::max() -
                manifest.tile_begin ||
        extract_tile_begin +
                manifest.tile_begin >=
            extract.tiles.size() ||
        manifest.tile_count >
            extract.tiles.size() -
                (extract_tile_begin +
                 manifest.tile_begin)) {
        out = {};
        return Fail(why, "witness_shape");
    }
    if (!FillSchedule(
            manifest, out, false, why)) {
        out = {};
        return false;
    }
    const uint32_t blocks_per_row =
        manifest.shape.n / kRCMxBlockLen;
    for (uint32_t local_tile = 0;
         local_tile < manifest.tile_count;
         ++local_tile) {
        const uint64_t layer_tile =
            manifest.tile_begin + local_tile;
        const uint32_t output_row =
            layer_tile / blocks_per_row;
        const uint32_t output_block =
            layer_tile % blocks_per_row;
        if (output_row >= manifest.shape.m) {
            out = {};
            return Fail(why, "witness_tile_row");
        }
        const auto& extract_tile =
            extract.tiles[
                extract_tile_begin + layer_tile];
        const uint32_t trace_base =
            local_tile * manifest.tile_rows;
        for (uint32_t lane = 0;
             lane < kRCMxBlockLen; ++lane) {
            const uint32_t column =
                output_block *
                    kRCMxBlockLen +
                lane;
            int64_t accumulator = 0;
            for (uint32_t contraction = 0;
                 contraction < manifest.shape.k;
                 ++contraction) {
                const uint32_t trace_row =
                    trace_base +
                    lane * manifest.shape.k +
                    contraction;
                const int64_t a =
                    layer.operand_a[
                        uint64_t{output_row} *
                            manifest.shape.k +
                        contraction];
                const uint64_t b_ordinal =
                    BOrdinal(
                        manifest.shape, column,
                        contraction);
                const int64_t b =
                    layer.operand_b[b_ordinal];
                if (a < -48 || a > 48 ||
                    b < -48 || b > 48) {
                    out = {};
                    return Fail(
                        why, "witness_operand_range");
                }
                const int64_t product = a * b;
                if ((product > 0 &&
                     accumulator >
                         std::numeric_limits<int64_t>::
                                 max() -
                             product) ||
                    (product < 0 &&
                     accumulator <
                         std::numeric_limits<int64_t>::
                                 min() -
                             product)) {
                    out = {};
                    return Fail(
                        why, "witness_accumulator");
                }
                out[kRCStage3GemmDotActive][trace_row] =
                    Fp3::One();
                out[kRCStage3GemmDotStart][trace_row] =
                    contraction == 0
                        ? Fp3::One()
                        : Fp3::Zero();
                out[kRCStage3GemmDotEnd][trace_row] =
                    contraction + 1 ==
                            manifest.shape.k
                        ? Fp3::One()
                        : Fp3::Zero();
                out[kRCStage3GemmDotA][trace_row] =
                    Signed(a);
                out[kRCStage3GemmDotB][trace_row] =
                    Signed(b);
                out[kRCStage3GemmDotProduct][trace_row] =
                    Signed(product);
                out[
                    kRCStage3GemmDotAccumulatorBefore]
                    [trace_row] = Signed(accumulator);
                accumulator += product;
                out[
                    kRCStage3GemmDotAccumulatorAfter]
                    [trace_row] = Signed(accumulator);
            }
            const uint64_t y_ordinal =
                uint64_t{output_row} *
                    manifest.shape.n +
                column;
            const int64_t y =
                layer.gemm_y[y_ordinal];
            const int64_t residual =
                layer.residual.empty()
                    ? 0
                    : layer.residual[y_ordinal];
            if (y != accumulator ||
                extract_tile.input[lane] !=
                    y + residual) {
                out = {};
                return Fail(why, "witness_y_extract");
            }
            const uint32_t end_row =
                trace_base +
                lane * manifest.shape.k +
                manifest.shape.k - 1;
            out[kRCStage3GemmDotY][end_row] =
                Signed(y);
            out[kRCStage3GemmDotResidual][end_row] =
                Signed(residual);
            out[kRCStage3GemmDotExtractInput][end_row] =
                Signed(extract_tile.input[lane]);
        }
    }
    for (const auto& projection :
         CanonicalSourceProjectionsV1()) {
        for (uint32_t row = 0;
             row < manifest.n_rows; ++row) {
            if (gf::Eq(
                    out[projection.active_column][row],
                    Fp3::One())) {
                out[projection.semantic_value_column][row] =
                    out[projection.value_column][row];
                out[projection.export_column][row] =
                    out[projection.value_column][row];
            }
        }
    }

    aq::AirConstraintSystem<Fp3> cs;
    if (!BuildExpectedConstraintSystemV1(
            manifest, cs, why)) {
        out = {};
        return false;
    }
    for (const auto& [column, values] :
         cs.preprocessed) {
        if (column >= out.size() ||
            values.size() != out[column].size() ||
            !std::equal(
                values.begin(), values.end(),
                out[column].begin(),
                [](const Fp3& lhs, const Fp3& rhs) {
                    return gf::Eq(lhs, rhs);
                })) {
            out = {};
            return Fail(why, "witness_preprocessed");
        }
    }
    return true;
}

uint256 ComputeLeafReceiptCommitmentV1(
    const LeafReceiptV1& receipt)
{
    if (receipt.version != kVersionV1 ||
        receipt.manifest.manifest_commitment.IsNull() ||
        receipt.public_fs_seed.IsNull() ||
        receipt.node_root.IsNull() ||
        receipt.program_root.IsNull() ||
        receipt.proof_context_root.IsNull() ||
        receipt.proof_commitment.IsNull() ||
        receipt.canonical_proof_bytes.empty() ||
        receipt.active_rows == 0 ||
        receipt.n_lde == 0 ||
        !receipt.quotient_division_exact ||
        !receipt.locally_verified) {
        return {};
    }
    for (uint32_t slot = 0;
         slot < receipt.same_parent_ctl_joins.size();
         ++slot) {
        const auto& join =
            receipt.same_parent_ctl_joins[slot];
        if (join.projection_slot != slot ||
            join.join_commitment.IsNull() ||
            join.join_commitment !=
                SameParentJoinCommitment(
                    receipt.manifest, join)) {
            return {};
        }
    }
    HashWriter hash;
    hash << RECEIPT_DOMAIN << receipt.version;
    hash << receipt.manifest.manifest_commitment;
    hash << receipt.public_fs_seed;
    hash << receipt.node_root;
    hash << receipt.program_root;
    hash << receipt.proof_context_root;
    hash << receipt.proof_commitment;
    hash << receipt.active_rows;
    hash << receipt.n_lde;
    for (const auto& join :
         receipt.same_parent_ctl_joins) {
        hash << join.join_commitment;
    }
    return hash.GetHash();
}

bool ProveLeafV1(
    const LeafManifestV1& manifest,
    const RCStage3EpisodeGemmLayerProduct& layer,
    const RCStage3EpisodeExtractProduct& extract,
    uint64_t extract_tile_begin,
    LeafReceiptV1& out,
    std::string* why)
{
    out = {};
    aq::AirConstraintSystem<Fp3> cs;
    std::vector<std::vector<Fp3>> columns;
    if (!BuildExpectedConstraintSystemV1(
            manifest, cs, why) ||
        !BuildLeafWitnessV1(
            manifest, layer, extract,
            extract_tile_begin, columns, why)) {
        return false;
    }
    const uint256 fs_seed = FsSeed(manifest);
    if (fs_seed.IsNull()) {
        return Fail(why, "prove_seed");
    }
    const auto proved =
        aq::AirQuotientProve<
            Fp3, aq::AirFriBackendAlg<Fp3>>(
            cs, columns, fs_seed, {});
    if (!proved.ok ||
        !proved.division_exact) {
        return Fail(
            why, "prove_quotient:" + proved.note);
    }
    std::string verify_why;
    if (!aq::AirQuotientVerify<
            Fp3, aq::AirFriBackendAlg<Fp3>>(
            cs, proved.proof, fs_seed,
            &verify_why)) {
        return Fail(
            why, "prove_verify:" + verify_why);
    }

    out.version = kVersionV1;
    out.manifest = manifest;
    out.public_fs_seed = fs_seed;
    out.proof = proved.proof;
    if (!SerializeAirQuotientProofAlg(
            out.proof,
            out.canonical_proof_bytes, why) ||
        out.canonical_proof_bytes.empty()) {
        out = {};
        return Fail(why, "prove_codec");
    }
    out.node_root = out.proof.trace_commit;
    out.program_root = manifest.program_table_alg;
    out.proof_context_root =
        ProofContextCommitment(manifest, fs_seed);
    out.proof_commitment =
        ProofBytesCommitment(
            out.canonical_proof_bytes);
    for (uint32_t slot = 0;
         slot < out.same_parent_ctl_joins.size();
         ++slot) {
        if (!ProveSameParentCtlJoin(
                manifest, columns, slot,
                out.same_parent_ctl_joins[slot],
                why)) {
            out = {};
            return false;
        }
    }
    out.active_rows = manifest.logical_rows;
    const uint64_t n_lde =
        uint64_t{out.proof.batch.n_coeffs} *
        out.proof.batch.blowup;
    if (n_lde == 0 ||
        n_lde >
            std::numeric_limits<uint32_t>::max()) {
        out = {};
        return Fail(why, "prove_lde");
    }
    out.n_lde = static_cast<uint32_t>(n_lde);
    out.quotient_division_exact = true;
    out.locally_verified = true;
    out.receipt_commitment =
        ComputeLeafReceiptCommitmentV1(out);
    if (out.receipt_commitment.IsNull() ||
        !VerifyLeafV1(
            manifest.shape,
            manifest.tile_begin,
            manifest.tile_count,
            out, why)) {
        out = {};
        return false;
    }
    return true;
}

SameParentCtlVerificationInputV1
BuildSameParentCtlVerificationInputV1(
    const LeafManifestV1& manifest,
    const SameParentCtlJoinV1& join)
{
    SameParentCtlVerificationInputV1 out;
    std::string why;
    if (!ManifestValid(manifest, &why) ||
        join.version != kVersionV1 ||
        join.projection_slot >= kEndpointCountV1 ||
        join.endpoint !=
            CanonicalSourceProjectionsV1()[
                join.projection_slot].endpoint ||
        join.base_column_indices !=
            SameParentBaseIndices() ||
        !BuildSameParentConstraintSystem(
            manifest, join.projection_slot,
            join.challenges,
            join.source_terminal,
            join.receiver_terminal,
            out.expected_cs, &why)) {
        out.note = why.empty()
            ? "stage3:episode_semantic_source_alg:"
              "join_input_shape"
            : why;
        return out;
    }
    out.proof = &join.proof;
    out.expected_base_column_indices =
        SameParentBaseIndices();
    out.public_fs_seed =
        SameParentFsSeed(
            manifest, join.projection_slot,
            join.base_row_commitment,
            join.challenges);
    out.valid =
        out.proof != nullptr &&
        !out.public_fs_seed.IsNull() &&
        out.expected_cs.n_rows ==
            manifest.n_rows &&
        out.expected_cs.n_columns ==
            kSameParentCtlColumnsV1;
    out.note = out.valid
        ? "stage3:episode_semantic_source_alg:"
          "join_input_ok"
        : "stage3:episode_semantic_source_alg:"
          "join_input_invalid";
    return out;
}

bool VerifySameParentCtlJoinV1(
    const LeafManifestV1& manifest,
    const SameParentCtlJoinV1& join,
    std::string* why)
{
    if (!ManifestValid(manifest, why) ||
        join.version != kVersionV1 ||
        join.projection_slot >= kEndpointCountV1 ||
        join.endpoint !=
            CanonicalSourceProjectionsV1()[
                join.projection_slot].endpoint ||
        join.base_column_indices !=
            SameParentBaseIndices() ||
        join.proof.batch.groups.size() != 3 ||
        Fri3AlgDigestToUint256(
            join.proof.batch.groups[0]
                .row_commit.root) !=
            join.base_row_commitment ||
        join.proof_commitment !=
            SameParentProofCommitment(
                join.proof) ||
        !join.source_value_same_trace_constrained ||
        !join.receiver_semantic_memory_executed ||
        !join.proof_owned_dual_alpha_terminal ||
        !join.same_parent_terminal_cancellation ||
        !gf::IsZero(gf::Add(
            join.source_terminal.alpha1_sum,
            join.receiver_terminal.alpha1_sum)) ||
        !gf::IsZero(gf::Add(
            join.source_terminal.alpha2_sum,
            join.receiver_terminal.alpha2_sum))) {
        return Fail(why, "join_verify_binding");
    }
    RCStage3CtlManifest ctl_manifest;
    std::vector<RCStage3CtlChildPin> pins;
    RCStage3CtlChallenges expected_challenges;
    if (!BuildCtlChallengeMaterial(
            manifest, join.projection_slot,
            join.base_row_commitment,
            ctl_manifest, pins,
            expected_challenges, why) ||
        !(expected_challenges ==
          join.challenges) ||
        join.public_fs_seed !=
            SameParentFsSeed(
                manifest,
                join.projection_slot,
                join.base_row_commitment,
                expected_challenges) ||
        join.join_commitment !=
            SameParentJoinCommitment(
                manifest, join)) {
        return Fail(
            why, "join_verify_transcript");
    }
    const auto input =
        BuildSameParentCtlVerificationInputV1(
            manifest, join);
    if (!input.valid ||
        input.proof == nullptr) {
        return Fail(
            why, "join_verify_input:" +
                input.note);
    }
    std::string proof_why;
    if (!aq::AirQuotientVerifyRowsSplitRapSafeV2(
            input.expected_cs,
            *input.proof,
            input.expected_base_column_indices,
            input.public_fs_seed,
            &proof_why)) {
        return Fail(
            why, "join_verify_air:" +
                proof_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:episode_semantic_source_alg:"
            "same_parent_ctl_join_ok";
    }
    return true;
}

bool VerifyLeafV1(
    const LayerShapeV1& expected_shape,
    uint64_t expected_tile_begin,
    uint32_t expected_tile_count,
    const LeafReceiptV1& receipt,
    std::string* why)
{
    LeafManifestV1 expected_manifest;
    if (!BuildLeafManifestV1(
            expected_shape,
            expected_tile_begin,
            expected_tile_count,
            expected_manifest, why) ||
        receipt.version != kVersionV1 ||
        receipt.manifest != expected_manifest ||
        receipt.public_fs_seed !=
            FsSeed(expected_manifest) ||
        receipt.node_root.IsNull() ||
        receipt.node_root !=
            receipt.proof.trace_commit ||
        receipt.program_root !=
            expected_manifest.program_table_alg ||
        receipt.proof_context_root !=
            ProofContextCommitment(
                expected_manifest,
                receipt.public_fs_seed) ||
        receipt.proof_commitment !=
            ProofBytesCommitment(
                receipt.canonical_proof_bytes) ||
        receipt.active_rows !=
            expected_manifest.logical_rows ||
        receipt.canonical_proof_bytes.empty() ||
        !receipt.quotient_division_exact ||
        !receipt.locally_verified) {
        return Fail(why, "verify_receipt");
    }
    for (uint32_t slot = 0;
         slot < receipt.same_parent_ctl_joins.size();
         ++slot) {
        if (receipt.same_parent_ctl_joins[slot]
                .projection_slot != slot ||
            !VerifySameParentCtlJoinV1(
                expected_manifest,
                receipt.same_parent_ctl_joins[slot],
                why)) {
            return Fail(
                why, "verify_ctl_join_" +
                    std::to_string(slot));
        }
    }
    const uint64_t n_lde =
        uint64_t{receipt.proof.batch.n_coeffs} *
        receipt.proof.batch.blowup;
    if (n_lde == 0 ||
        n_lde >
            std::numeric_limits<uint32_t>::max() ||
        receipt.n_lde != n_lde ||
        receipt.receipt_commitment !=
            ComputeLeafReceiptCommitmentV1(receipt)) {
        return Fail(why, "verify_shape_commitment");
    }

    std::vector<unsigned char> encoded;
    std::string codec_why;
    const auto decoded =
        DeserializeAirQuotientProofAlg(
            receipt.canonical_proof_bytes,
            &codec_why);
    if (!SerializeAirQuotientProofAlg(
            receipt.proof, encoded, &codec_why) ||
        encoded != receipt.canonical_proof_bytes ||
        !decoded.has_value() ||
        !SerializeAirQuotientProofAlg(
            *decoded, encoded, &codec_why) ||
        encoded != receipt.canonical_proof_bytes) {
        return Fail(
            why, "verify_codec:" + codec_why);
    }

    aq::AirConstraintSystem<Fp3> cs;
    if (!BuildExpectedConstraintSystemV1(
            expected_manifest, cs, why) ||
        !aq::AirQuotientVerify<
            Fp3, aq::AirFriBackendAlg<Fp3>>(
            cs, receipt.proof,
            receipt.public_fs_seed, why)) {
        return Fail(why, "verify_alg_air");
    }
    return true;
}

VerificationInputV1 BuildVerificationInputV1(
    const LeafReceiptV1& receipt)
{
    VerificationInputV1 out;
    std::string why;
    if (!VerifyLeafV1(
            receipt.manifest.shape,
            receipt.manifest.tile_begin,
            receipt.manifest.tile_count,
            receipt, &why) ||
        !BuildExpectedConstraintSystemV1(
            receipt.manifest,
            out.expected_cs, &why)) {
        out.note = why;
        return out;
    }
    out.proof = &receipt.proof;
    out.public_fs_seed = receipt.public_fs_seed;
    out.node_root = receipt.node_root;
    out.program_root = receipt.program_root;
    out.proof_context_root =
        receipt.proof_context_root;
    out.statement_commitment =
        receipt.manifest.shape.statement_commitment;
    out.expected_cs_commitment =
        receipt.manifest.expected_cs_commitment;
    out.proof_commitment =
        receipt.proof_commitment;
    out.canonical_proof_bytes =
        receipt.canonical_proof_bytes;
    out.active_rows = receipt.active_rows;
    out.n_lde = receipt.n_lde;
    out.valid =
        out.proof != nullptr &&
        !out.public_fs_seed.IsNull() &&
        !out.node_root.IsNull() &&
        !out.program_root.IsNull() &&
        !out.proof_context_root.IsNull() &&
        !out.statement_commitment.IsNull() &&
        !out.expected_cs_commitment.IsNull() &&
        !out.proof_commitment.IsNull() &&
        !out.canonical_proof_bytes.empty() &&
        out.active_rows != 0 &&
        out.n_lde != 0;
    out.note = out.valid
        ? "stage3:episode_semantic_source_alg:"
          "ordinary_alg_verifier_leaf"
        : "stage3:episode_semantic_source_alg:"
          "verification_input";
    return out;
}

uint256 ComputeLayerBundleCommitmentV1(
    const LayerBundleV1& bundle)
{
    if (bundle.version != kVersionV1 ||
        bundle.shape.shape_commitment.IsNull() ||
        bundle.exact_coverage_commitment.IsNull() ||
        bundle.leaves.size() !=
            ExpectedLeafCount(bundle.shape)) {
        return {};
    }
    HashWriter hash;
    hash << BUNDLE_DOMAIN << bundle.version;
    hash << bundle.shape.shape_commitment;
    hash << bundle.exact_coverage_commitment;
    hash << static_cast<uint64_t>(
        bundle.leaves.size());
    for (const auto& leaf : bundle.leaves) {
        if (leaf.receipt_commitment.IsNull()) {
            return {};
        }
        hash << leaf.receipt_commitment;
    }
    return hash.GetHash();
}

bool ProveLayerBundleV1(
    const LayerShapeV1& shape,
    const RCStage3EpisodeGemmLayerProduct& layer,
    const RCStage3EpisodeExtractProduct& extract,
    uint64_t extract_tile_begin,
    LayerBundleV1& out,
    std::string* why)
{
    out = {};
    if (!ShapeFieldsValid(shape, why) ||
        shape.shape_commitment !=
            ComputeLayerShapeCommitmentV1(shape)) {
        return Fail(why, "prove_bundle_shape");
    }
    out.shape = shape;
    const uint32_t capacity =
        TilesPerShard(shape);
    const uint64_t leaf_count =
        ExpectedLeafCount(shape);
    if (capacity == 0 || leaf_count == 0) {
        return Fail(why, "prove_bundle_capacity");
    }
    out.leaves.reserve(leaf_count);
    uint64_t tile_begin = 0;
    while (tile_begin < shape.tile_count) {
        const uint32_t tile_count =
            static_cast<uint32_t>(
                std::min<uint64_t>(
                    capacity,
                    shape.tile_count - tile_begin));
        LeafManifestV1 manifest;
        LeafReceiptV1 receipt;
        if (!BuildLeafManifestV1(
                shape, tile_begin, tile_count,
                manifest, why) ||
            !ProveLeafV1(
                manifest, layer, extract,
                extract_tile_begin, receipt, why)) {
            out = {};
            return false;
        }
        out.leaves.push_back(std::move(receipt));
        tile_begin += tile_count;
    }
    out.exact_coverage_commitment =
        ExactCoverageCommitment(
            shape, out.leaves);
    out.bundle_commitment =
        ComputeLayerBundleCommitmentV1(out);
    const BundleAuditV1 audit =
        VerifyLayerBundleV1(shape, out);
    if (!audit.accepted) {
        out = {};
        return Fail(
            why, "prove_bundle_verify:" + audit.note);
    }
    return true;
}

BundleAuditV1 VerifyLayerBundleV1(
    const LayerShapeV1& expected_shape,
    const LayerBundleV1& bundle)
{
    BundleAuditV1 out;
    std::string why;
    if (!ShapeFieldsValid(expected_shape, &why) ||
        expected_shape.shape_commitment !=
            ComputeLayerShapeCommitmentV1(
                expected_shape) ||
        bundle.version != kVersionV1 ||
        bundle.shape != expected_shape ||
        bundle.leaves.size() !=
            ExpectedLeafCount(expected_shape)) {
        out.note =
            "stage3:episode_semantic_source_alg:"
            "bundle_shape:" + why;
        return out;
    }

    cb::ProgramTable table;
    out.canonical_program =
        BuildCanonicalProgramTableV1(
            table, &why);
    const auto& projections =
        CanonicalSourceProjectionsV1();
    out.direct_physical_value_aliases =
        projections[kOperandASlotV1].value_column ==
            kRCStage3GemmDotA &&
        projections[kOperandBSlotV1].value_column ==
            kRCStage3GemmDotB &&
        projections[kOutputYSlotV1].value_column ==
            kRCStage3GemmDotY &&
        projections[kOperandASlotV1].value_column <
            kMetadataColumnBaseV1 &&
        projections[kOperandBSlotV1].value_column <
            kMetadataColumnBaseV1 &&
        projections[kOutputYSlotV1].value_column <
            kMetadataColumnBaseV1;
    out.exact_tile_order = true;
    out.every_alg_air_proof_verified = true;
    out.ordinary_recursive_leaf_compatible = true;
    out.receiver_owned = true;
    out.dual_alpha_ctl_terminal = true;
    out.terminal_join = true;
    const uint32_t capacity =
        TilesPerShard(expected_shape);
    uint64_t next_tile = 0;
    for (uint64_t shard = 0;
         shard < bundle.leaves.size(); ++shard) {
        const auto& leaf = bundle.leaves[shard];
        const uint32_t count =
            static_cast<uint32_t>(
                std::min<uint64_t>(
                    capacity,
                    expected_shape.tile_count -
                        next_tile));
        if (leaf.manifest.tile_begin != next_tile ||
            leaf.manifest.tile_count != count) {
            out.exact_tile_order = false;
        }
        if (!VerifyLeafV1(
                expected_shape, next_tile, count,
                leaf, &why)) {
            out.every_alg_air_proof_verified = false;
            out.ordinary_recursive_leaf_compatible = false;
            out.receiver_owned = false;
            out.dual_alpha_ctl_terminal = false;
            out.terminal_join = false;
            break;
        }
        for (const auto& join :
             leaf.same_parent_ctl_joins) {
            if (!VerifySameParentCtlJoinV1(
                    leaf.manifest, join, &why)) {
                out.receiver_owned = false;
                out.dual_alpha_ctl_terminal = false;
                out.terminal_join = false;
                break;
            }
        }
        if (!out.terminal_join) break;
        const VerificationInputV1 input =
            BuildVerificationInputV1(leaf);
        if (!input.valid ||
            input.proof == nullptr) {
            out.ordinary_recursive_leaf_compatible = false;
            break;
        }
        out.verified_tiles += count;
        next_tile += count;
    }
    out.covered_operand_a =
        EndpointTotal(
            expected_shape, kOperandASlotV1);
    out.covered_operand_b =
        EndpointTotal(
            expected_shape, kOperandBSlotV1);
    out.covered_output_y =
        EndpointTotal(
            expected_shape, kOutputYSlotV1);
    out.exact_address_partition =
        out.exact_tile_order &&
        out.verified_tiles ==
            expected_shape.tile_count &&
        next_tile == expected_shape.tile_count &&
        bundle.exact_coverage_commitment ==
            ExactCoverageCommitment(
                expected_shape, bundle.leaves);
    out.source_owned =
        out.direct_physical_value_aliases &&
        out.exact_address_partition &&
        out.every_alg_air_proof_verified &&
        out.terminal_join;
    out.receiver_owned =
        out.receiver_owned &&
        out.exact_address_partition &&
        out.every_alg_air_proof_verified;
    out.dual_alpha_ctl_terminal =
        out.dual_alpha_ctl_terminal &&
        out.receiver_owned;
    out.terminal_join =
        out.terminal_join &&
        out.dual_alpha_ctl_terminal;
    out.source_terminal_proof_owned =
        out.terminal_join &&
        std::all_of(
            bundle.leaves.begin(),
            bundle.leaves.end(),
            [](const LeafReceiptV1& leaf) {
                return std::all_of(
                    leaf.same_parent_ctl_joins.begin(),
                    leaf.same_parent_ctl_joins.end(),
                    [](const SameParentCtlJoinV1& join) {
                        return
                            join.proof_owned_dual_alpha_terminal &&
                            !join.proof_commitment.IsNull() &&
                            !join.join_commitment.IsNull();
                    });
            });
    // A local receiver mirrors the source tuple so that the source terminal
    // is proof-owned.  It does not authenticate the upstream producer.  That
    // edge closes only when the normalized parent verifies the real producer
    // receipt and constrains the two exported terminals to cancel.
    out.external_producer_terminal_joined = false;
    out.strict_transitive_provenance =
        out.source_terminal_proof_owned &&
        out.external_producer_terminal_joined;
    // This closes the local proof-owned source -> semantic-memory receiver.
    // It intentionally remains non-production until every shard receipt is
    // consumed by the normalized recursive parent and the real producer
    // terminal is joined there.
    out.production_source_closed =
        out.strict_transitive_provenance &&
        kRecursiveConsumptionReadyV1;
    out.accepted =
        out.canonical_program &&
        out.source_owned &&
        out.ordinary_recursive_leaf_compatible &&
        bundle.bundle_commitment ==
            ComputeLayerBundleCommitmentV1(bundle);
    out.note = out.accepted
        ? "stage3:episode_semantic_source_alg:"
          "direct_A_B_Y_source_cells_and_exact_coverage_ok"
        : "stage3:episode_semantic_source_alg:"
          "bundle_rejected:" + why;
    return out;
}

} // namespace matmul::v4::rc::episode_semantic_source_alg
