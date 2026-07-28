// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_gemm_range_ctl_v3.h>

#include <hash.h>

#include <algorithm>
#include <array>
#include <limits>

namespace matmul::v4::rc::coupled_gemm_range_ctl_v3 {
namespace {

namespace gated = gated_ctl_alias;
using gf::Fp3;
using CS = aq::AirConstraintSystem<Fp3>;

constexpr uint32_t kNamespaceV3 = 0x47594f55U; // "GYOU"
constexpr uint32_t kStageV3 = 33;
constexpr char kScheduleDomain[] =
    "BTX_RC_STAGE3_COUPLED_GEMM_RANGE_CTL_SCHEDULE_V3";
constexpr char kTraceDomain[] =
    "BTX_RC_STAGE3_COUPLED_GEMM_RANGE_CTL_R0_V3";
constexpr char kSeedDomain[] =
    "BTX_RC_STAGE3_COUPLED_GEMM_RANGE_CTL_CHILD_FS_V3";
constexpr char kProofDomain[] =
    "BTX_RC_STAGE3_COUPLED_GEMM_RANGE_CTL_PROOF_V3";
constexpr char kShardDomain[] =
    "BTX_RC_STAGE3_COUPLED_GEMM_RANGE_CTL_SHARD_V3";
constexpr char kProductDomain[] =
    "BTX_RC_STAGE3_COUPLED_GEMM_RANGE_CTL_PRODUCT_V3";

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:coupled_gemm_range_ctl_v3:" + detail;
    }
    return false;
}

uint32_t NextPowerOfTwo(uint64_t value)
{
    if (value < 2) return 2;
    if (value > (uint64_t{1} << 31)) return 0;
    uint64_t out = 1;
    while (out < value) out <<= 1;
    return static_cast<uint32_t>(out);
}

Fp3 U(uint64_t value) { return gf::FromU64_3(value); }
Fp3 S(int64_t value) { return gf::FromSigned3(value); }

uint256 CommitProof(
    const aq::AirQuotientSplitRapRowsProof& proof)
{
    std::vector<unsigned char> bytes;
    if (aq::SerializeAirQuotientSplitRapRowsProof(
            proof, bytes) == 0 ||
        bytes.empty()) {
        return {};
    }
    HashWriter hash;
    hash << kProofDomain
         << static_cast<uint64_t>(bytes.size())
         << bytes;
    return hash.GetHash();
}

uint256 AggregateRoots(
    uint32_t shard,
    RCStage3RelationRole role,
    const std::vector<uint256>& roots)
{
    if (roots.empty()) return {};
    HashWriter hash;
    hash << kTraceDomain << kVersionV3
         << shard << static_cast<uint16_t>(role)
         << static_cast<uint32_t>(roots.size());
    for (uint32_t i = 0; i < roots.size(); ++i) {
        if (roots[i].IsNull()) return {};
        hash << i << roots[i];
    }
    return hash.GetHash();
}

uint256 ScheduleCommitment(
    const uint256& statement,
    const uint256& shape,
    uint32_t shard,
    uint64_t cell_begin,
    uint32_t logical_rows,
    RCStage3RelationRole role,
    int8_t sign)
{
    if (statement.IsNull() || shape.IsNull() ||
        logical_rows == 0 ||
        (sign != 1 && sign != -1)) {
        return {};
    }
    HashWriter hash;
    hash << kScheduleDomain << kVersionV3
         << statement << shape
         << shard << cell_begin << logical_rows
         << static_cast<uint16_t>(role)
         << sign;
    return hash.GetHash();
}

uint256 TranscriptSeed(
    const uint256& statement,
    const uint256& shape,
    const uint256& gemm_schedule,
    const uint256& range_manifest,
    uint32_t shard)
{
    if (statement.IsNull() || shape.IsNull() ||
        gemm_schedule.IsNull() || range_manifest.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << std::string{
                "BTX_RC_STAGE3_COUPLED_GEMM_RANGE_CTL_TRANSCRIPT_V3"}
         << statement << shape << gemm_schedule
         << range_manifest << shard;
    return hash.GetHash();
}

RCStage3CtlParticipantSpec Participant(
    RCStage3RelationRole role,
    uint64_t events,
    const uint256& schedule,
    bool producer)
{
    return {
        role,
        events,
        producer ? events : 0,
        producer ? 0 : events,
        schedule};
}

RCStage3CtlChildPin RolePin(
    const RCStage3CtlParticipantSpec& participant,
    uint32_t bus_id,
    const uint256& trace)
{
    RCStage3CtlChildPin pin;
    pin.role = participant.role;
    pin.bus_id = bus_id;
    pin.event_count = participant.event_count;
    pin.send_count = participant.send_count;
    pin.receive_count = participant.receive_count;
    pin.schedule_commitment =
        participant.schedule_commitment;
    pin.trace_commitment = trace;
    return pin;
}

uint256 ChildSeed(
    const ShardProofV3& shard,
    RCStage3RelationRole role,
    uint64_t ordinal,
    const uint256& base_root,
    const uint256& relation_commitment)
{
    const uint256 challenges =
        CommitRCStage3CtlChallenges(shard.challenges);
    if (shard.manifest.transcript_seed.IsNull() ||
        challenges.IsNull() || base_root.IsNull() ||
        relation_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << kSeedDomain << kVersionV3
         << shard.manifest.transcript_seed
         << shard.shard_index
         << static_cast<uint16_t>(role)
         << ordinal << base_root
         << relation_commitment << challenges;
    return hash.GetHash();
}

uint256 CommitChildren(
    RCStage3RelationRole role,
    const std::vector<GemmChildV3>& children)
{
    if (children.empty()) return {};
    HashWriter hash;
    hash << std::string{
                "BTX_RC_STAGE3_COUPLED_GEMM_RANGE_CTL_CHILDREN_V3"}
         << static_cast<uint16_t>(role)
         << static_cast<uint32_t>(children.size());
    for (uint32_t i = 0; i < children.size(); ++i) {
        const auto& child = children[i];
        if (child.proof_commitment.IsNull()) return {};
        hash << i << child.global_tile_ordinal
             << child.schedule_index
             << child.output_tile_index
             << child.dot_pin.pin_commitment
             << child.base_row_commitment
             << child.proof_commitment;
    }
    return hash.GetHash();
}

uint256 CommitRangeChild(const RangeChildV3& child)
{
    if (child.proof_commitment.IsNull() ||
        child.base_row_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << std::string{
                "BTX_RC_STAGE3_COUPLED_GEMM_RANGE_CTL_RANGE_CHILD_V3"}
         << child.pin.shard_index
         << child.pin.cell_begin
         << child.pin.logical_rows
         << ComputeRCStage3SignedRangePinCommitment(
                child.pin)
         << child.base_row_commitment
         << child.proof_commitment;
    return hash.GetHash();
}

uint256 CommitShard(const ShardProofV3& shard)
{
    if (!shard.terminal_sum_zero ||
        shard.manifest.transcript_seed.IsNull() ||
        shard.gemm_role.auxiliary_commitment.IsNull() ||
        shard.range_role.auxiliary_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << kShardDomain << kVersionV3
         << shard.shard_index << shard.cell_begin
         << shard.logical_rows
         << shard.manifest.transcript_seed
         << CommitRCStage3CtlChallenges(shard.challenges)
         << shard.gemm_role.trace_commitment
         << shard.gemm_role.auxiliary_commitment
         << shard.range_role.trace_commitment
         << shard.range_role.auxiliary_commitment
         << static_cast<uint32_t>(shard.gemm_children.size());
    return hash.GetHash();
}

bool SameRangeShape(
    const RCStage3SignedRangePin& actual,
    const RCStage3SignedRangePin& expected)
{
    return actual.statement_commitment == expected.statement_commitment &&
        actual.manifest_commitment == expected.manifest_commitment &&
        actual.layer_ordinal == expected.layer_ordinal &&
        actual.shard_index == expected.shard_index &&
        actual.shard_count == expected.shard_count &&
        actual.cell_begin == expected.cell_begin &&
        actual.logical_rows == expected.logical_rows &&
        actual.n_rows == expected.n_rows &&
        actual.max_abs == expected.max_abs &&
        actual.column_roots.size() ==
            kRCStage3SignedRangeColumns;
}

bool BuildTileColumns(
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledGemmOpening& opening,
    uint64_t tile_index,
    uint32_t n_rows,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    const uint32_t width = shape.lobe_width;
    const uint32_t rows = shape.rows_per_lobe;
    const uint32_t blocks = width / kRCMxBlockLen;
    if (width == 0 || width % kRCMxBlockLen != 0 ||
        opening.operand_a.size() != uint64_t{rows} * width ||
        opening.operand_b.size() != uint64_t{width} * width ||
        opening.output_y.size() != uint64_t{rows} * width ||
        tile_index >= uint64_t{rows} * blocks ||
        n_rows < uint64_t{width} * kRCMxBlockLen) {
        return Fail(why, "tile_witness_shape");
    }
    columns.assign(
        kRCStage3CoupledGemmColumns,
        std::vector<Fp3>(n_rows, Fp3::Zero()));
    const uint32_t output_row = tile_index / blocks;
    const uint32_t output_block = tile_index % blocks;
    for (uint32_t lane = 0; lane < kRCMxBlockLen; ++lane) {
        const uint32_t output_column =
            output_block * kRCMxBlockLen + lane;
        int64_t accumulator = 0;
        for (uint32_t contraction = 0;
             contraction < width;
             ++contraction) {
            const uint32_t trace_row =
                lane * width + contraction;
            const int8_t a = opening.operand_a[
                uint64_t{output_row} * width + contraction];
            const int8_t b = opening.operand_b[
                uint64_t{contraction} * width + output_column];
            if (a < -48 || a > 48 || b < -48 || b > 48) {
                return Fail(why, "tile_operand_range");
            }
            const int64_t product =
                static_cast<int64_t>(a) * b;
            columns[kRCStage3CoupledGemmActive][trace_row] =
                Fp3::One();
            columns[kRCStage3CoupledGemmStart][trace_row] =
                U(contraction == 0);
            columns[kRCStage3CoupledGemmEnd][trace_row] =
                U(contraction + 1 == width);
            columns[kRCStage3CoupledGemmA][trace_row] = S(a);
            columns[kRCStage3CoupledGemmB][trace_row] = S(b);
            columns[kRCStage3CoupledGemmProduct][trace_row] =
                S(product);
            columns[kRCStage3CoupledGemmAccumulatorBefore]
                [trace_row] = S(accumulator);
            accumulator += product;
            columns[kRCStage3CoupledGemmAccumulatorAfter]
                [trace_row] = S(accumulator);
            if (contraction + 1 == width) {
                columns[kRCStage3CoupledGemmY][trace_row] =
                    S(opening.output_y[
                        uint64_t{output_row} * width +
                        output_column]);
            }
        }
    }
    return true;
}

RCStage3CoupledGemmDotPin BuildDotPin(
    const uint256& statement,
    const uint256& shape_commitment,
    const uint256& schedule_commitment,
    uint64_t schedule_index,
    uint64_t tile_index,
    uint32_t width,
    const std::vector<std::vector<Fp3>>& columns)
{
    RCStage3CoupledGemmDotPin pin;
    pin.statement_commitment = statement;
    pin.shape_commitment = shape_commitment;
    pin.schedule_commitment = schedule_commitment;
    pin.schedule_index = schedule_index;
    pin.output_tile_index = tile_index;
    pin.contraction_size = width;
    pin.logical_rows = uint64_t{width} * kRCMxBlockLen;
    pin.n_rows = static_cast<uint32_t>(columns.front().size());
    pin.n_coeffs = pin.n_rows;
    pin.column_roots.resize(columns.size());
    for (uint32_t column = 0; column < columns.size(); ++column) {
        pin.column_roots[column] = {
            column,
            aq::AirCommittedValuesRoot<Fp3>(
                columns[column], pin.n_coeffs)};
    }
    pin.pin_commitment =
        ComputeRCStage3CoupledGemmDotPinCommitment(pin);
    return pin;
}

bool ResolveDotRelation(
    const RCStage3CoupledGemmDotPin& pin,
    CS& cs,
    std::string* why)
{
    if (!BuildRCStage3CoupledGemmDotConstraintSystem(
            pin, cs, why)) {
        return false;
    }
    cs.preprocessed_roots.clear();
    return true;
}

std::vector<uint32_t> GemmAddresses(
    const RCStage3CoupledShape& shape,
    uint64_t global_tile,
    uint32_t n_rows)
{
    std::vector<uint32_t> addresses(n_rows, 0);
    const uint64_t first_cell =
        global_tile * kRCMxBlockLen;
    for (uint32_t lane = 0; lane < kRCMxBlockLen; ++lane) {
        const uint32_t row =
            lane * shape.lobe_width +
            shape.lobe_width - 1;
        addresses[row] =
            static_cast<uint32_t>(first_cell + lane);
    }
    return addresses;
}

std::vector<uint32_t> RangeAddresses(
    const RCStage3SignedRangePin& pin)
{
    std::vector<uint32_t> addresses(pin.n_rows, 0);
    for (uint32_t row = 0; row < pin.logical_rows; ++row) {
        addresses[row] =
            static_cast<uint32_t>(pin.cell_begin + row);
    }
    return addresses;
}

RCStage3CtlTerminal AddTerminal(
    const RCStage3CtlTerminal& a,
    const RCStage3CtlTerminal& b)
{
    return {
        gf::Add(a.alpha1_sum, b.alpha1_sum),
        gf::Add(a.alpha2_sum, b.alpha2_sum)};
}

bool Zero(const RCStage3CtlTerminal& terminal)
{
    return gf::IsZero(terminal.alpha1_sum) &&
        gf::IsZero(terminal.alpha2_sum);
}

uint256 GroupBaseRoot(
    const aq::AirQuotientSplitRapRowsProof& proof)
{
    if (proof.batch.groups.size() != 3 ||
        proof.batch.groups[0].role !=
            Fri3AlgMultiRowGroupRole::MainTrace) {
        return {};
    }
    return Fri3AlgDigestToUint256(
        proof.batch.groups[0].row_commit.root);
}

bool BuildRangeRelation(
    const RCStage3SignedRangePin& pin,
    CS& relation,
    std::string* why)
{
    if (!ResolveRCStage3SignedRangeKernelConstraintSystem(
            pin, relation, why)) {
        return false;
    }
    relation.preprocessed_roots.clear();
    return true;
}

bool BuildRangeValues(
    const std::vector<RCStage3CoupledGemmOpening>& openings,
    uint64_t begin,
    uint32_t count,
    std::vector<int64_t>& out)
{
    out.clear();
    out.reserve(count);
    uint64_t cursor = 0;
    const uint64_t end = begin + count;
    for (const auto& opening : openings) {
        const uint64_t next =
            cursor + opening.output_y.size();
        if (next > begin && cursor < end) {
            const uint64_t local_begin =
                begin > cursor ? begin - cursor : 0;
            const uint64_t local_end =
                std::min<uint64_t>(
                    opening.output_y.size(),
                    end - cursor);
            out.insert(
                out.end(),
                opening.output_y.begin() + local_begin,
                opening.output_y.begin() + local_end);
        }
        cursor = next;
        if (cursor >= end) break;
    }
    return out.size() == count;
}

void HashFp3(HashWriter& hash, const Fp3& value)
{
    const auto limb = gf::ToU64Triple(value);
    hash << limb[0] << limb[1] << limb[2];
}

uint256 RetainedStatementRoot(
    RCStage3RelationRole role,
    uint32_t shard_index,
    uint64_t child_ordinal,
    const uint256& relation_commitment,
    const uint256& base_row_commitment,
    const uint256& fs_seed,
    const uint256& challenge_commitment)
{
    if (relation_commitment.IsNull() ||
        base_row_commitment.IsNull() ||
        fs_seed.IsNull() ||
        challenge_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << std::string{
                "BTX_RC_STAGE3_COUPLED_GEMM_RANGE_CTL_"
                "RETAINED_STATEMENT_V3"}
         << static_cast<uint16_t>(role)
         << shard_index << child_ordinal
         << relation_commitment
         << base_row_commitment
         << fs_seed
         << challenge_commitment;
    return hash.GetHash();
}

uint256 CommitParentRoleReceipt(
    const ParentRoleReceiptV3& receipt)
{
    if (receipt.bus_id != kBusIdV3 ||
        receipt.manifest.commitment.IsNull() ||
        receipt.nodes.empty() ||
        receipt.trace_commitment.IsNull() ||
        receipt.auxiliary_commitment.IsNull() ||
        receipt.challenge_commitment.IsNull() ||
        !receipt.exact_child_coverage ||
        !receipt.every_native_child_verified ||
        !receipt.dual_fp3_terminal_exported) {
        return {};
    }
    HashWriter hash;
    hash << std::string{
                "BTX_RC_STAGE3_COUPLED_GEMM_RANGE_CTL_"
                "PARENT_ROLE_RECEIPT_V3"}
         << static_cast<uint16_t>(receipt.role)
         << receipt.bus_id
         << receipt.manifest.commitment
         << receipt.trace_commitment
         << receipt.auxiliary_commitment
         << receipt.challenge_commitment
         << static_cast<uint32_t>(receipt.nodes.size());
    for (const auto& node : receipt.nodes) {
        if (!node.valid || node.node_root.IsNull()) return {};
        hash << node.node_root;
    }
    HashFp3(hash, receipt.terminal.alpha1_sum);
    HashFp3(hash, receipt.terminal.alpha2_sum);
    return hash.GetHash();
}

uint256 CommitParentShardReceipts(
    const ParentShardReceiptsV3& receipt)
{
    if (!receipt.exact_role_order ||
        !receipt.dual_fp3_terminal_cancellation ||
        receipt.role[0].role !=
            RCStage3RelationRole::CoupledGemm ||
        receipt.role[1].role !=
            RCStage3RelationRole::CompositionLink ||
        receipt.role[0].receipt_commitment.IsNull() ||
        receipt.role[1].receipt_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << std::string{
                "BTX_RC_STAGE3_COUPLED_GEMM_RANGE_CTL_"
                "PARENT_SHARD_RECEIPTS_V3"}
         << receipt.shard_index
         << receipt.role[0].receipt_commitment
         << receipt.role[1].receipt_commitment;
    return hash.GetHash();
}

uint256 CommitParentReceiptBundle(
    const ParentReceiptBundleV3& bundle)
{
    if (bundle.version != kVersionV3 ||
        bundle.product_commitment.IsNull() ||
        bundle.shards.empty() ||
        !bundle.every_split_rap_child_verified ||
        !bundle.every_dual_fp3_terminal_exported ||
        !bundle.every_shard_terminal_cancelled ||
        bundle.normalized_parent_consumed) {
        return {};
    }
    HashWriter hash;
    hash << std::string{
                "BTX_RC_STAGE3_COUPLED_GEMM_RANGE_CTL_"
                "PARENT_RECEIPT_BUNDLE_V3"}
         << bundle.version
         << bundle.product_commitment
         << static_cast<uint32_t>(bundle.shards.size());
    for (uint32_t i = 0; i < bundle.shards.size(); ++i) {
        if (bundle.shards[i].shard_index != i ||
            bundle.shards[i].receipt_pair_commitment.IsNull()) {
            return {};
        }
        hash << bundle.shards[i].receipt_pair_commitment;
    }
    hash << bundle.normalized_parent_consumed;
    return hash.GetHash();
}

} // namespace

uint256 CommitProductV3(const ProductV3& proof)
{
    if (proof.version != kVersionV3 ||
        proof.statement_commitment.IsNull() ||
        proof.shape_commitment.IsNull() ||
        proof.gemm_schedule_commitment.IsNull() ||
        proof.range_manifest_commitment.IsNull() ||
        proof.shards.empty() ||
        !proof.every_cell_partitioned ||
        !proof.every_child_proof_verified ||
        !proof.every_terminal_sum_zero ||
        proof.normalized_parent_consumed ||
        proof.production_authority) {
        return {};
    }
    HashWriter hash;
    hash << kProductDomain << proof.version
         << proof.statement_commitment
         << proof.shape_commitment
         << proof.gemm_schedule_commitment
         << proof.range_manifest_commitment
         << proof.expected_gemms
         << proof.expected_output_tiles
         << proof.expected_output_cells
         << static_cast<uint32_t>(proof.shards.size());
    for (uint32_t i = 0; i < proof.shards.size(); ++i) {
        if (proof.shards[i].shard_index != i ||
            proof.shards[i].shard_commitment.IsNull()) {
            return {};
        }
        hash << proof.shards[i].shard_commitment;
    }
    hash << proof.normalized_parent_consumed
         << proof.production_authority;
    return hash.GetHash();
}

bool ProveV3(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<RCStage3CoupledGemmOpening>& openings,
    ProductV3& out,
    std::string* why)
{
    out = {};
    const uint256 statement_commitment =
        CommitRCStage3CoupledStatement(
            statement.public_inputs);
    const uint256 shape_commitment =
        CommitRCStage3CoupledShape(shape);
    std::vector<RCStage3CoupledGemmScheduleEntry> schedule;
    uint256 schedule_commitment;
    RCStage3CoupledSignedRangeManifest range_manifest;
    if (statement_commitment.IsNull() ||
        shape_commitment.IsNull() ||
        !BuildRCStage3CoupledGemmSchedule(
            statement, shape, schedule,
            schedule_commitment, why) ||
        !BuildRCStage3CoupledSignedRangeManifest(
            statement, shape, range_manifest, why) ||
        openings.size() != schedule.size()) {
        return Fail(why, "public_shape_or_openings");
    }
    const uint64_t cells_per_gemm =
        uint64_t{shape.rows_per_lobe} *
        shape.lobe_width;
    const uint64_t tiles_per_gemm =
        cells_per_gemm / kRCMxBlockLen;
    if (cells_per_gemm == 0 ||
        cells_per_gemm % kRCMxBlockLen != 0 ||
        range_manifest.total_output_cells !=
            cells_per_gemm * schedule.size()) {
        return Fail(why, "canonical_counts");
    }

    out.version = kVersionV3;
    out.statement_commitment = statement_commitment;
    out.shape_commitment = shape_commitment;
    out.gemm_schedule_commitment = schedule_commitment;
    out.range_manifest_commitment =
        range_manifest.commitment;
    out.expected_gemms = schedule.size();
    out.expected_output_tiles =
        tiles_per_gemm * schedule.size();
    out.expected_output_cells =
        range_manifest.total_output_cells;
    out.shards.resize(range_manifest.shard_count);

    const RCStage3CtlChallenges placeholder{
        U(2), U(3), U(5), U(7)};
    for (uint32_t shard_index = 0;
         shard_index < range_manifest.shard_count;
         ++shard_index) {
        auto& shard = out.shards[shard_index];
        RCStage3SignedRangePin range_pin;
        if (!MakeRCStage3CoupledSignedRangePin(
                range_manifest, shard_index,
                range_pin, why)) {
            return false;
        }
        shard.shard_index = shard_index;
        shard.cell_begin = range_pin.cell_begin;
        shard.logical_rows = range_pin.logical_rows;

        const uint64_t first_tile =
            range_pin.cell_begin / kRCMxBlockLen;
        const uint64_t tile_count =
            range_pin.logical_rows / kRCMxBlockLen;
        if (range_pin.cell_begin % kRCMxBlockLen != 0 ||
            range_pin.logical_rows % kRCMxBlockLen != 0 ||
            first_tile + tile_count >
                out.expected_output_tiles) {
            return Fail(why, "shard_tile_partition");
        }
        shard.gemm_children.resize(tile_count);
        std::vector<uint256> gemm_base_roots;
        gemm_base_roots.reserve(tile_count);

        for (uint64_t local = 0; local < tile_count; ++local) {
            const uint64_t global_tile = first_tile + local;
            const uint64_t schedule_index =
                global_tile / tiles_per_gemm;
            const uint64_t output_tile =
                global_tile % tiles_per_gemm;
            const uint32_t trace_rows =
                NextPowerOfTwo(
                    uint64_t{shape.lobe_width} *
                    kRCMxBlockLen);
            std::vector<std::vector<Fp3>> relation_columns;
            if (trace_rows == 0 ||
                !BuildTileColumns(
                    shape, openings[schedule_index],
                    output_tile, trace_rows,
                    relation_columns, why)) {
                return false;
            }
            auto& child = shard.gemm_children[local];
            child.global_tile_ordinal = global_tile;
            child.schedule_index = schedule_index;
            child.output_tile_index = output_tile;
            child.dot_pin = BuildDotPin(
                statement_commitment, shape_commitment,
                schedule_commitment, schedule_index,
                output_tile, shape.lobe_width,
                relation_columns);
            CS relation;
            if (child.dot_pin.pin_commitment.IsNull() ||
                !ResolveDotRelation(
                    child.dot_pin, relation, why)) {
                return Fail(why, "gemm_relation");
            }
            gated::SpecV1 spec;
            spec.namespace_id = kNamespaceV3;
            spec.stage = kStageV3;
            spec.sign = 1;
            spec.source_column =
                kRCStage3CoupledGemmY;
            spec.selector_column =
                kRCStage3CoupledGemmEnd;
            spec.addresses =
                GemmAddresses(shape, global_tile, trace_rows);
            spec.challenges = placeholder;
            gated::LayoutV1 layout;
            CS combined;
            std::vector<std::vector<Fp3>> prechallenge;
            if (!gated::BuildConstraintSystemV1(
                    relation, spec, combined,
                    layout, why) ||
                !gated::BuildPrechallengeColumnsV1(
                    relation_columns, spec, layout,
                    prechallenge, why)) {
                return false;
            }
            const auto session =
                aq::AirQuotientBuildTwoEpochBaseRowSession(
                    combined, prechallenge,
                    layout.base_column_indices);
            if (!session.valid) {
                return Fail(
                    why, "gemm_r0:" + session.note);
            }
            child.base_row_commitment =
                session.base_row_commitment;
            gemm_base_roots.push_back(
                child.base_row_commitment);
        }

        std::vector<int64_t> range_values;
        if (!BuildRangeValues(
                openings, range_pin.cell_begin,
                range_pin.logical_rows,
                range_values)) {
            return Fail(why, "range_values");
        }
        std::vector<std::vector<Fp3>> range_columns;
        if (!BuildRCStage3SignedRangeColumns(
                range_pin, range_values,
                range_columns, why)) {
            return false;
        }
        range_pin.column_roots.resize(
            kRCStage3SignedRangeColumns);
        for (uint32_t column = 0;
             column < range_columns.size();
             ++column) {
            range_pin.column_roots[column] = {
                column,
                aq::AirCommittedValuesRoot<Fp3>(
                    range_columns[column],
                    range_pin.n_rows)};
        }
        shard.range_child.pin = range_pin;
        CS range_relation;
        if (!BuildRangeRelation(
                range_pin, range_relation, why)) {
            return false;
        }
        gated::SpecV1 range_spec;
        range_spec.namespace_id = kNamespaceV3;
        range_spec.stage = kStageV3;
        range_spec.sign = -1;
        range_spec.source_column =
            kRCStage3RangeValue;
        range_spec.selector_column =
            kRCStage3RangeActive;
        range_spec.addresses =
            RangeAddresses(range_pin);
        range_spec.challenges = placeholder;
        gated::LayoutV1 range_layout;
        CS range_combined;
        std::vector<std::vector<Fp3>> range_prechallenge;
        if (!gated::BuildConstraintSystemV1(
                range_relation, range_spec,
                range_combined, range_layout, why) ||
            !gated::BuildPrechallengeColumnsV1(
                range_columns, range_spec,
                range_layout,
                range_prechallenge, why)) {
            return false;
        }
        const auto range_session =
            aq::AirQuotientBuildTwoEpochBaseRowSession(
                range_combined, range_prechallenge,
                range_layout.base_column_indices);
        if (!range_session.valid) {
            return Fail(
                why, "range_r0:" + range_session.note);
        }
        shard.range_child.base_row_commitment =
            range_session.base_row_commitment;

        const uint256 gemm_schedule =
            ScheduleCommitment(
                statement_commitment,
                shape_commitment, shard_index,
                range_pin.cell_begin,
                range_pin.logical_rows,
                RCStage3RelationRole::CoupledGemm, 1);
        const uint256 receiver_schedule =
            ScheduleCommitment(
                statement_commitment,
                shape_commitment, shard_index,
                range_pin.cell_begin,
                range_pin.logical_rows,
                RCStage3RelationRole::CompositionLink, -1);
        shard.manifest.bus_id = kBusIdV3;
        shard.manifest.transcript_seed =
            TranscriptSeed(
                statement_commitment, shape_commitment,
                schedule_commitment,
                range_manifest.commitment,
                shard_index);
        shard.manifest.participants = {
            Participant(
                RCStage3RelationRole::CoupledGemm,
                range_pin.logical_rows,
                gemm_schedule, true),
            Participant(
                RCStage3RelationRole::CompositionLink,
                range_pin.logical_rows,
                receiver_schedule, false)};
        shard.gemm_role = RolePin(
            shard.manifest.participants[0],
            kBusIdV3,
            AggregateRoots(
                shard_index,
                RCStage3RelationRole::CoupledGemm,
                gemm_base_roots));
        shard.range_role = RolePin(
            shard.manifest.participants[1],
            kBusIdV3,
            AggregateRoots(
                shard_index,
                RCStage3RelationRole::CompositionLink,
                {shard.range_child.base_row_commitment}));
        std::vector<RCStage3CtlChildPin> prechallenge_pins{
            shard.gemm_role, shard.range_role};
        if (shard.gemm_role.trace_commitment.IsNull() ||
            shard.range_role.trace_commitment.IsNull() ||
            !DeriveRCStage3CtlChallenges(
                shard.manifest,
                prechallenge_pins,
                shard.challenges, why)) {
            return Fail(why, "derive_challenges");
        }

        RCStage3CtlTerminal gemm_terminal;
        for (uint64_t local = 0; local < tile_count; ++local) {
            auto& child = shard.gemm_children[local];
            const uint64_t schedule_index =
                child.schedule_index;
            const uint64_t output_tile =
                child.output_tile_index;
            const uint32_t trace_rows =
                child.dot_pin.n_rows;
            std::vector<std::vector<Fp3>> relation_columns;
            if (!BuildTileColumns(
                    shape, openings[schedule_index],
                    output_tile, trace_rows,
                    relation_columns, why)) {
                return false;
            }
            CS relation;
            if (!ResolveDotRelation(
                    child.dot_pin, relation, why)) {
                return false;
            }
            gated::SpecV1 spec;
            spec.namespace_id = kNamespaceV3;
            spec.stage = kStageV3;
            spec.sign = 1;
            spec.source_column =
                kRCStage3CoupledGemmY;
            spec.selector_column =
                kRCStage3CoupledGemmEnd;
            spec.addresses =
                GemmAddresses(
                    shape,
                    child.global_tile_ordinal,
                    trace_rows);
            spec.challenges = shard.challenges;
            gated::LayoutV1 layout;
            CS placeholder_cs;
            if (!gated::BuildConstraintSystemV1(
                    relation, spec, placeholder_cs,
                    layout, why)) {
                return false;
            }
            const auto witness =
                gated::BuildWitnessV1(
                    relation_columns, spec, layout);
            if (!witness.valid) {
                return Fail(
                    why, "gemm_witness:" + witness.note);
            }
            child.terminal = witness.terminal;
            spec.expected_terminal = child.terminal;
            CS combined;
            if (!gated::BuildConstraintSystemV1(
                    relation, spec, combined,
                    layout, why)) {
                return false;
            }
            std::vector<std::vector<Fp3>> prechallenge;
            if (!gated::BuildPrechallengeColumnsV1(
                    relation_columns, spec, layout,
                    prechallenge, why)) {
                return false;
            }
            const auto session =
                aq::AirQuotientBuildTwoEpochBaseRowSession(
                    combined, prechallenge,
                    layout.base_column_indices);
            if (!session.valid ||
                session.base_row_commitment !=
                    child.base_row_commitment) {
                return Fail(why, "gemm_r0_drift");
            }
            const uint256 seed =
                ChildSeed(
                    shard,
                    RCStage3RelationRole::CoupledGemm,
                    local,
                    child.base_row_commitment,
                    child.dot_pin.pin_commitment);
            const auto proved =
                aq::AirQuotientProveRowsSplitRapSafeV2(
                    combined, witness.columns,
                    layout.base_column_indices,
                    seed, {}, &session);
            if (!proved.ok || !proved.division_exact) {
                return Fail(
                    why, "gemm_prove:" + proved.note);
            }
            child.proof = proved.proof;
            child.proof_commitment =
                CommitProof(child.proof);
            gemm_terminal =
                AddTerminal(gemm_terminal, child.terminal);
        }
        shard.gemm_role.terminal = gemm_terminal;
        shard.gemm_role.auxiliary_commitment =
            CommitChildren(
                RCStage3RelationRole::CoupledGemm,
                shard.gemm_children);

        range_spec.challenges = shard.challenges;
        if (!gated::BuildConstraintSystemV1(
                range_relation, range_spec,
                range_combined, range_layout, why)) {
            return false;
        }
        const auto range_witness =
            gated::BuildWitnessV1(
                range_columns, range_spec,
                range_layout);
        if (!range_witness.valid) {
            return Fail(
                why, "range_witness:" +
                    range_witness.note);
        }
        shard.range_child.terminal =
            range_witness.terminal;
        range_spec.expected_terminal =
            range_witness.terminal;
        if (!gated::BuildConstraintSystemV1(
                range_relation, range_spec,
                range_combined, range_layout, why) ||
            !gated::BuildPrechallengeColumnsV1(
                range_columns, range_spec,
                range_layout,
                range_prechallenge, why)) {
            return false;
        }
        const auto final_range_session =
            aq::AirQuotientBuildTwoEpochBaseRowSession(
                range_combined, range_prechallenge,
                range_layout.base_column_indices);
        if (!final_range_session.valid ||
            final_range_session.base_row_commitment !=
                shard.range_child.base_row_commitment) {
            return Fail(why, "range_r0_drift");
        }
        const uint256 range_seed =
            ChildSeed(
                shard,
                RCStage3RelationRole::CompositionLink,
                0,
                shard.range_child.base_row_commitment,
                ComputeRCStage3SignedRangePinCommitment(
                    shard.range_child.pin));
        const auto range_proved =
            aq::AirQuotientProveRowsSplitRapSafeV2(
                range_combined,
                range_witness.columns,
                range_layout.base_column_indices,
                range_seed, {},
                &final_range_session);
        if (!range_proved.ok ||
            !range_proved.division_exact) {
            return Fail(
                why, "range_prove:" +
                    range_proved.note);
        }
        shard.range_child.proof =
            range_proved.proof;
        shard.range_child.proof_commitment =
            CommitProof(shard.range_child.proof);
        shard.range_role.terminal =
            shard.range_child.terminal;
        shard.range_role.auxiliary_commitment =
            CommitRangeChild(shard.range_child);
        const uint256 challenge_commitment =
            CommitRCStage3CtlChallenges(
                shard.challenges);
        shard.gemm_role.challenge_commitment =
            challenge_commitment;
        shard.range_role.challenge_commitment =
            challenge_commitment;
        shard.terminal_sum_zero =
            Zero(AddTerminal(
                shard.gemm_role.terminal,
                shard.range_role.terminal));
        if (!shard.terminal_sum_zero ||
            !VerifyRCStage3CtlPublicPinComposition(
                shard.manifest,
                {shard.gemm_role,
                 shard.range_role},
                why)) {
            return Fail(why, "terminal_composition");
        }
        shard.shard_commitment =
            CommitShard(shard);
        if (shard.shard_commitment.IsNull()) {
            return Fail(why, "shard_commitment");
        }
    }
    out.every_cell_partitioned = true;
    out.every_child_proof_verified = false;
    out.every_terminal_sum_zero = true;
    out.normalized_parent_consumed = false;
    out.production_authority = false;

    ProductV3 candidate = out;
    candidate.every_child_proof_verified = true;
    candidate.product_commitment =
        CommitProductV3(candidate);
    if (candidate.product_commitment.IsNull() ||
        !VerifyV3(statement, shape, candidate, why)) {
        return Fail(why, "self_verify");
    }
    out = std::move(candidate);
    return true;
}

bool VerifyV3(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const ProductV3& proof,
    std::string* why)
{
    const uint256 statement_commitment =
        CommitRCStage3CoupledStatement(
            statement.public_inputs);
    const uint256 shape_commitment =
        CommitRCStage3CoupledShape(shape);
    std::vector<RCStage3CoupledGemmScheduleEntry> schedule;
    uint256 schedule_commitment;
    RCStage3CoupledSignedRangeManifest range_manifest;
    if (!BuildRCStage3CoupledGemmSchedule(
            statement, shape, schedule,
            schedule_commitment, why) ||
        !BuildRCStage3CoupledSignedRangeManifest(
            statement, shape, range_manifest, why)) {
        return false;
    }
    const uint64_t cells_per_gemm =
        uint64_t{shape.rows_per_lobe} *
        shape.lobe_width;
    const uint64_t tiles_per_gemm =
        cells_per_gemm / kRCMxBlockLen;
    if (proof.version != kVersionV3 ||
        proof.statement_commitment !=
            statement_commitment ||
        proof.shape_commitment != shape_commitment ||
        proof.gemm_schedule_commitment !=
            schedule_commitment ||
        proof.range_manifest_commitment !=
            range_manifest.commitment ||
        proof.expected_gemms != schedule.size() ||
        proof.expected_output_tiles !=
            tiles_per_gemm * schedule.size() ||
        proof.expected_output_cells !=
            range_manifest.total_output_cells ||
        proof.shards.size() !=
            range_manifest.shard_count ||
        !proof.every_cell_partitioned ||
        !proof.every_child_proof_verified ||
        !proof.every_terminal_sum_zero ||
        proof.normalized_parent_consumed ||
        proof.production_authority) {
        return Fail(why, "product_public_binding");
    }

    uint64_t expected_global_tile = 0;
    for (uint32_t shard_index = 0;
         shard_index < proof.shards.size();
         ++shard_index) {
        const auto& shard = proof.shards[shard_index];
        RCStage3SignedRangePin expected_range;
        if (!MakeRCStage3CoupledSignedRangePin(
                range_manifest, shard_index,
                expected_range, why)) {
            return false;
        }
        const uint64_t tile_count =
            expected_range.logical_rows /
            kRCMxBlockLen;
        if (shard.shard_index != shard_index ||
            shard.cell_begin !=
                expected_range.cell_begin ||
            shard.logical_rows !=
                expected_range.logical_rows ||
            shard.gemm_children.size() !=
                tile_count ||
            shard.gemm_children.empty() ||
            !SameRangeShape(
                shard.range_child.pin,
                expected_range)) {
            return Fail(why, "shard_shape");
        }

        const uint256 gemm_schedule =
            ScheduleCommitment(
                statement_commitment,
                shape_commitment, shard_index,
                expected_range.cell_begin,
                expected_range.logical_rows,
                RCStage3RelationRole::CoupledGemm, 1);
        const uint256 receiver_schedule =
            ScheduleCommitment(
                statement_commitment,
                shape_commitment, shard_index,
                expected_range.cell_begin,
                expected_range.logical_rows,
                RCStage3RelationRole::CompositionLink, -1);
        RCStage3CtlManifest expected_manifest;
        expected_manifest.bus_id = kBusIdV3;
        expected_manifest.transcript_seed =
            TranscriptSeed(
                statement_commitment, shape_commitment,
                schedule_commitment,
                range_manifest.commitment,
                shard_index);
        expected_manifest.participants = {
            Participant(
                RCStage3RelationRole::CoupledGemm,
                expected_range.logical_rows,
                gemm_schedule, true),
            Participant(
                RCStage3RelationRole::CompositionLink,
                expected_range.logical_rows,
                receiver_schedule, false)};
        if (shard.manifest != expected_manifest) {
            return Fail(why, "manifest");
        }
        std::vector<uint256> gemm_roots;
        RCStage3CtlTerminal gemm_terminal;
        for (uint64_t local = 0; local < tile_count; ++local) {
            const auto& child =
                shard.gemm_children[local];
            const uint64_t global_tile =
                expected_global_tile + local;
            const uint64_t schedule_index =
                global_tile / tiles_per_gemm;
            const uint64_t output_tile =
                global_tile % tiles_per_gemm;
            if (child.global_tile_ordinal != global_tile ||
                child.schedule_index != schedule_index ||
                child.output_tile_index != output_tile ||
                child.dot_pin.statement_commitment !=
                    statement_commitment ||
                child.dot_pin.shape_commitment !=
                    shape_commitment ||
                child.dot_pin.schedule_commitment !=
                    schedule_commitment ||
                child.dot_pin.schedule_index !=
                    schedule_index ||
                child.dot_pin.output_tile_index !=
                    output_tile ||
                child.dot_pin.contraction_size !=
                    shape.lobe_width ||
                child.dot_pin.logical_rows !=
                    uint64_t{shape.lobe_width} *
                        kRCMxBlockLen ||
                child.dot_pin.pin_commitment !=
                    ComputeRCStage3CoupledGemmDotPinCommitment(
                        child.dot_pin) ||
                child.proof_commitment !=
                    CommitProof(child.proof) ||
                GroupBaseRoot(child.proof) !=
                    child.base_row_commitment) {
                return Fail(why, "gemm_child_identity");
            }
            CS relation;
            if (!ResolveDotRelation(
                    child.dot_pin, relation, why)) {
                return false;
            }
            gated::SpecV1 spec;
            spec.namespace_id = kNamespaceV3;
            spec.stage = kStageV3;
            spec.sign = 1;
            spec.source_column =
                kRCStage3CoupledGemmY;
            spec.selector_column =
                kRCStage3CoupledGemmEnd;
            spec.addresses =
                GemmAddresses(
                    shape, global_tile,
                    child.dot_pin.n_rows);
            spec.challenges = shard.challenges;
            spec.expected_terminal = child.terminal;
            gated::LayoutV1 layout;
            CS combined;
            if (!gated::BuildConstraintSystemV1(
                    relation, spec, combined,
                    layout, why)) {
                return false;
            }
            const uint256 seed =
                ChildSeed(
                    shard,
                    RCStage3RelationRole::CoupledGemm,
                    local,
                    child.base_row_commitment,
                    child.dot_pin.pin_commitment);
            std::string air_why;
            if (!aq::AirQuotientVerifyRowsSplitRapSafeV2(
                    combined, child.proof,
                    layout.base_column_indices,
                    seed, &air_why)) {
                return Fail(
                    why, "gemm_child_air:" +
                        air_why);
            }
            gemm_roots.push_back(
                child.base_row_commitment);
            gemm_terminal =
                AddTerminal(
                    gemm_terminal,
                    child.terminal);
        }
        expected_global_tile += tile_count;

        CS range_relation;
        if (!BuildRangeRelation(
                shard.range_child.pin,
                range_relation, why)) {
            return false;
        }
        gated::SpecV1 range_spec;
        range_spec.namespace_id = kNamespaceV3;
        range_spec.stage = kStageV3;
        range_spec.sign = -1;
        range_spec.source_column =
            kRCStage3RangeValue;
        range_spec.selector_column =
            kRCStage3RangeActive;
        range_spec.addresses =
            RangeAddresses(shard.range_child.pin);
        range_spec.challenges = shard.challenges;
        range_spec.expected_terminal =
            shard.range_child.terminal;
        gated::LayoutV1 range_layout;
        CS range_combined;
        if (!gated::BuildConstraintSystemV1(
                range_relation, range_spec,
                range_combined, range_layout, why) ||
            shard.range_child.proof_commitment !=
                CommitProof(shard.range_child.proof) ||
            GroupBaseRoot(shard.range_child.proof) !=
                shard.range_child.base_row_commitment) {
            return Fail(why, "range_child_identity");
        }

        RCStage3CtlChildPin expected_gemm =
            RolePin(
                expected_manifest.participants[0],
                kBusIdV3,
                AggregateRoots(
                    shard_index,
                    RCStage3RelationRole::CoupledGemm,
                    gemm_roots));
        RCStage3CtlChildPin expected_range_role =
            RolePin(
                expected_manifest.participants[1],
                kBusIdV3,
                AggregateRoots(
                    shard_index,
                    RCStage3RelationRole::CompositionLink,
                    {shard.range_child.base_row_commitment}));
        RCStage3CtlChallenges expected_challenges;
        if (!DeriveRCStage3CtlChallenges(
                expected_manifest,
                {expected_gemm, expected_range_role},
                expected_challenges, why) ||
            !(expected_challenges == shard.challenges)) {
            return Fail(why, "challenge_replay");
        }
        const uint256 range_seed =
            ChildSeed(
                shard,
                RCStage3RelationRole::CompositionLink,
                0,
                shard.range_child.base_row_commitment,
                ComputeRCStage3SignedRangePinCommitment(
                    shard.range_child.pin));
        std::string range_why;
        if (!aq::AirQuotientVerifyRowsSplitRapSafeV2(
                range_combined,
                shard.range_child.proof,
                range_layout.base_column_indices,
                range_seed, &range_why)) {
            return Fail(
                why, "range_child_air:" +
                    range_why);
        }

        const uint256 challenges =
            CommitRCStage3CtlChallenges(
                shard.challenges);
        expected_gemm.terminal = gemm_terminal;
        expected_gemm.auxiliary_commitment =
            CommitChildren(
                RCStage3RelationRole::CoupledGemm,
                shard.gemm_children);
        expected_gemm.challenge_commitment = challenges;
        expected_range_role.terminal =
            shard.range_child.terminal;
        expected_range_role.auxiliary_commitment =
            CommitRangeChild(shard.range_child);
        expected_range_role.challenge_commitment =
            challenges;
        if (!(shard.gemm_role == expected_gemm) ||
            !(shard.range_role ==
                expected_range_role) ||
            !Zero(AddTerminal(
                expected_gemm.terminal,
                expected_range_role.terminal)) ||
            !shard.terminal_sum_zero ||
            !VerifyRCStage3CtlPublicPinComposition(
                expected_manifest,
                {expected_gemm,
                 expected_range_role},
                why) ||
            shard.shard_commitment !=
                CommitShard(shard)) {
            return Fail(why, "role_or_terminal_composition");
        }
    }
    if (expected_global_tile !=
            proof.expected_output_tiles ||
        proof.product_commitment !=
            CommitProductV3(proof)) {
        return Fail(why, "global_partition_or_commitment");
    }
    if (why != nullptr) {
        *why =
            "stage3:coupled_gemm_range_ctl_v3:"
            "all_cells_proof_owned_and_verified;"
            "normalized_parent_consumption_pending";
    }
    return true;
}

bool BuildVerifiedParentReceiptsV3(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const ProductV3& proof,
    ParentReceiptBundleV3& out,
    std::string* why)
{
    out = {};
    std::string verify_why;
    if (!VerifyV3(
            statement, shape, proof, &verify_why)) {
        return Fail(
            why, "parent_receipt_product_verify:" +
                verify_why);
    }

    std::vector<RCStage3CoupledGemmScheduleEntry> schedule;
    uint256 schedule_commitment;
    RCStage3CoupledSignedRangeManifest range_manifest;
    if (!BuildRCStage3CoupledGemmSchedule(
            statement, shape, schedule,
            schedule_commitment, why) ||
        !BuildRCStage3CoupledSignedRangeManifest(
            statement, shape, range_manifest, why)) {
        return false;
    }
    const uint64_t cells_per_gemm =
        uint64_t{shape.rows_per_lobe} *
        shape.lobe_width;
    const uint64_t tiles_per_gemm =
        cells_per_gemm / kRCMxBlockLen;
    if (tiles_per_gemm == 0) {
        return Fail(why, "parent_receipt_tile_shape");
    }

    out.version = kVersionV3;
    out.product_commitment = proof.product_commitment;
    out.shards.resize(proof.shards.size());
    for (uint32_t shard_index = 0;
         shard_index < proof.shards.size();
         ++shard_index) {
        const auto& shard = proof.shards[shard_index];
        auto& parent_shard = out.shards[shard_index];
        parent_shard.shard_index = shard_index;

        // Reconstruct every GEMM child statement before constructing the
        // exact ordinal manifest.  No statement descriptor is accepted from
        // the retained-node artifact.
        std::vector<CS> gemm_css;
        std::vector<std::vector<uint32_t>>
            gemm_base_indices;
        std::vector<uint256> gemm_seeds;
        std::vector<
            recursive_hierarchy::ShardOrdinalEntryV1>
            gemm_entries;
        gemm_css.reserve(shard.gemm_children.size());
        gemm_base_indices.reserve(
            shard.gemm_children.size());
        gemm_seeds.reserve(shard.gemm_children.size());
        gemm_entries.reserve(shard.gemm_children.size());
        for (uint32_t local = 0;
             local < shard.gemm_children.size();
             ++local) {
            const auto& child =
                shard.gemm_children[local];
            CS relation;
            if (!ResolveDotRelation(
                    child.dot_pin, relation, why)) {
                return false;
            }
            gated::SpecV1 spec;
            spec.namespace_id = kNamespaceV3;
            spec.stage = kStageV3;
            spec.sign = 1;
            spec.source_column =
                kRCStage3CoupledGemmY;
            spec.selector_column =
                kRCStage3CoupledGemmEnd;
            spec.addresses =
                GemmAddresses(
                    shape,
                    child.global_tile_ordinal,
                    child.dot_pin.n_rows);
            spec.challenges = shard.challenges;
            spec.expected_terminal = child.terminal;
            gated::LayoutV1 layout;
            CS combined;
            if (!gated::BuildConstraintSystemV1(
                    relation, spec, combined,
                    layout, why)) {
                return false;
            }
            const uint256 seed =
                ChildSeed(
                    shard,
                    RCStage3RelationRole::CoupledGemm,
                    local,
                    child.base_row_commitment,
                    child.dot_pin.pin_commitment);
            const uint256 statement_root =
                RetainedStatementRoot(
                    RCStage3RelationRole::CoupledGemm,
                    shard_index, local,
                    child.dot_pin.pin_commitment,
                    child.base_row_commitment,
                    seed,
                    shard.gemm_role
                        .challenge_commitment);
            if (statement_root.IsNull()) {
                return Fail(
                    why,
                    "parent_receipt_gemm_statement");
            }
            gemm_css.push_back(std::move(combined));
            gemm_base_indices.push_back(
                layout.base_column_indices);
            gemm_seeds.push_back(seed);
            gemm_entries.push_back({
                local, local, 1, statement_root});
        }
        auto& gemm_receipt = parent_shard.role[0];
        gemm_receipt.role =
            RCStage3RelationRole::CoupledGemm;
        gemm_receipt.bus_id = kBusIdV3;
        gemm_receipt.manifest =
            recursive_hierarchy::
                BuildShardOrdinalManifestV1(
                    gemm_entries.size(),
                    gemm_entries);
        if (!recursive_hierarchy::
                ValidateShardOrdinalManifestV1(
                    gemm_receipt.manifest, why)) {
            return false;
        }
        gemm_receipt.nodes.reserve(
            shard.gemm_children.size());
        for (uint32_t local = 0;
             local < shard.gemm_children.size();
             ++local) {
            const auto coverage =
                recursive_hierarchy::
                    BuildShardOrdinalCoverageV1(
                        gemm_receipt.manifest,
                        local, 1);
            auto retained =
                recursive_hierarchy::
                    RetainVerifiedSplitRapHierarchyNodeV2(
                        gemm_receipt.manifest,
                        coverage, 0, local,
                        gemm_css[local],
                        shard.gemm_children[local].proof,
                        gemm_base_indices[local],
                        gemm_seeds[local]);
            if (!retained.valid) {
                return Fail(
                    why,
                    "parent_receipt_gemm_retain:" +
                        retained.note);
            }
            const uint256 expected_cs_commitment =
                recursive_hierarchy::
                    ComputeHierarchyConstraintSystemCommitmentV1(
                        gemm_css[local]);
            if (retained.constraint_system_commitment !=
                    expected_cs_commitment) {
                return Fail(
                    why,
                    "parent_receipt_gemm_cs_drift");
            }
            if (recursive_hierarchy::
                    ComputeHierarchyConstraintSystemCommitmentV1(
                        retained.constraint_system) !=
                    expected_cs_commitment) {
                return Fail(
                    why,
                    "parent_receipt_gemm_retained_cs_drift");
            }
            if (retained.base_column_indices !=
                    gemm_base_indices[local]) {
                return Fail(
                    why,
                    "parent_receipt_gemm_r0_drift");
            }
            if (retained.fs_seed != gemm_seeds[local]) {
                return Fail(
                    why,
                    "parent_receipt_gemm_fs_drift");
            }
            gemm_receipt.nodes.push_back(
                std::move(retained));
        }
        if (!recursive_hierarchy::
                ValidateRetainedSplitRapHierarchyLevelV2(
                    gemm_receipt.manifest,
                    gemm_css, gemm_base_indices,
                    gemm_seeds,
                    gemm_receipt.nodes, why)) {
            return false;
        }
        gemm_receipt.trace_commitment =
            shard.gemm_role.trace_commitment;
        gemm_receipt.auxiliary_commitment =
            shard.gemm_role.auxiliary_commitment;
        gemm_receipt.challenge_commitment =
            shard.gemm_role.challenge_commitment;
        gemm_receipt.terminal =
            shard.gemm_role.terminal;
        gemm_receipt.exact_child_coverage = true;
        gemm_receipt.every_native_child_verified =
            std::all_of(
                gemm_receipt.nodes.begin(),
                gemm_receipt.nodes.end(),
                [](const auto& node) {
                    return node.valid &&
                        node.native_proof_verified &&
                        node.cryptographic_child;
                });
        gemm_receipt.dual_fp3_terminal_exported = true;
        gemm_receipt.receipt_commitment =
            CommitParentRoleReceipt(gemm_receipt);
        if (gemm_receipt.receipt_commitment.IsNull()) {
            return Fail(
                why,
                "parent_receipt_gemm_commitment");
        }

        // Reconstruct and retain the signed-range receiver as the second
        // role receipt.  Its one ordinal covers the complete shard.
        const auto& range_child = shard.range_child;
        CS range_relation;
        if (!BuildRangeRelation(
                range_child.pin,
                range_relation, why)) {
            return false;
        }
        gated::SpecV1 range_spec;
        range_spec.namespace_id = kNamespaceV3;
        range_spec.stage = kStageV3;
        range_spec.sign = -1;
        range_spec.source_column =
            kRCStage3RangeValue;
        range_spec.selector_column =
            kRCStage3RangeActive;
        range_spec.addresses =
            RangeAddresses(range_child.pin);
        range_spec.challenges = shard.challenges;
        range_spec.expected_terminal =
            range_child.terminal;
        gated::LayoutV1 range_layout;
        CS range_combined;
        if (!gated::BuildConstraintSystemV1(
                range_relation, range_spec,
                range_combined, range_layout, why)) {
            return false;
        }
        const uint256 range_pin_commitment =
            ComputeRCStage3SignedRangePinCommitment(
                range_child.pin);
        const uint256 range_seed =
            ChildSeed(
                shard,
                RCStage3RelationRole::CompositionLink,
                0, range_child.base_row_commitment,
                range_pin_commitment);
        const uint256 range_statement_root =
            RetainedStatementRoot(
                RCStage3RelationRole::CompositionLink,
                shard_index, 0,
                range_pin_commitment,
                range_child.base_row_commitment,
                range_seed,
                shard.range_role
                    .challenge_commitment);
        auto& range_receipt = parent_shard.role[1];
        range_receipt.role =
            RCStage3RelationRole::CompositionLink;
        range_receipt.bus_id = kBusIdV3;
        range_receipt.manifest =
            recursive_hierarchy::
                BuildShardOrdinalManifestV1(
                    1, {{0, 0, 1,
                         range_statement_root}});
        if (!recursive_hierarchy::
                ValidateShardOrdinalManifestV1(
                    range_receipt.manifest, why)) {
            return false;
        }
        const auto range_coverage =
            recursive_hierarchy::
                BuildShardOrdinalCoverageV1(
                    range_receipt.manifest, 0, 1);
        auto retained_range =
            recursive_hierarchy::
                RetainVerifiedSplitRapHierarchyNodeV2(
                    range_receipt.manifest,
                    range_coverage, 0, 0,
                    range_combined,
                    range_child.proof,
                    range_layout.base_column_indices,
                    range_seed);
        if (!retained_range.valid) {
            return Fail(
                why,
                "parent_receipt_range_retain:" +
                    retained_range.note);
        }
        range_receipt.nodes.push_back(
            std::move(retained_range));
        if (!recursive_hierarchy::
                ValidateRetainedSplitRapHierarchyLevelV2(
                    range_receipt.manifest,
                    {range_combined},
                    {range_layout.base_column_indices},
                    {range_seed},
                    range_receipt.nodes, why)) {
            return false;
        }
        range_receipt.trace_commitment =
            shard.range_role.trace_commitment;
        range_receipt.auxiliary_commitment =
            shard.range_role.auxiliary_commitment;
        range_receipt.challenge_commitment =
            shard.range_role.challenge_commitment;
        range_receipt.terminal =
            shard.range_role.terminal;
        range_receipt.exact_child_coverage = true;
        range_receipt.every_native_child_verified =
            range_receipt.nodes[0].valid &&
            range_receipt.nodes[0]
                .native_proof_verified &&
            range_receipt.nodes[0]
                .cryptographic_child;
        range_receipt.dual_fp3_terminal_exported = true;
        range_receipt.receipt_commitment =
            CommitParentRoleReceipt(range_receipt);
        if (range_receipt.receipt_commitment.IsNull()) {
            return Fail(
                why,
                "parent_receipt_range_commitment");
        }

        parent_shard.exact_role_order = true;
        parent_shard.dual_fp3_terminal_cancellation =
            Zero(AddTerminal(
                gemm_receipt.terminal,
                range_receipt.terminal));
        parent_shard.receipt_pair_commitment =
            CommitParentShardReceipts(parent_shard);
        if (parent_shard.receipt_pair_commitment.IsNull()) {
            return Fail(
                why,
                "parent_receipt_pair_commitment");
        }
    }
    out.every_split_rap_child_verified =
        std::all_of(
            out.shards.begin(), out.shards.end(),
            [](const auto& shard) {
                return shard.role[0]
                           .every_native_child_verified &&
                    shard.role[1]
                           .every_native_child_verified;
            });
    out.every_dual_fp3_terminal_exported =
        std::all_of(
            out.shards.begin(), out.shards.end(),
            [](const auto& shard) {
                return shard.role[0]
                           .dual_fp3_terminal_exported &&
                    shard.role[1]
                           .dual_fp3_terminal_exported;
            });
    out.every_shard_terminal_cancelled =
        std::all_of(
            out.shards.begin(), out.shards.end(),
            [](const auto& shard) {
                return shard
                    .dual_fp3_terminal_cancellation;
            });
    out.normalized_parent_consumed = false;
    out.bundle_commitment =
        CommitParentReceiptBundle(out);
    if (out.bundle_commitment.IsNull()) {
        return Fail(
            why, "parent_receipt_bundle_commitment");
    }
    if (why != nullptr) {
        *why =
            "stage3:coupled_gemm_range_ctl_v3:"
            "native_split_rap_role_receipts_verified;"
            "dual_fp3_terminals_exported;"
            "normalized_parent_consumption_pending";
    }
    return true;
}

bool ValidateParentReceiptsV3(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const ProductV3& proof,
    const ParentReceiptBundleV3& receipts,
    std::string* why)
{
    ParentReceiptBundleV3 expected;
    if (!BuildVerifiedParentReceiptsV3(
            statement, shape, proof, expected, why)) {
        return false;
    }
    if (receipts.version != kVersionV3 ||
        receipts.product_commitment !=
            proof.product_commitment ||
        receipts.shards.size() !=
            expected.shards.size() ||
        !receipts.every_split_rap_child_verified ||
        !receipts.every_dual_fp3_terminal_exported ||
        !receipts.every_shard_terminal_cancelled ||
        receipts.normalized_parent_consumed) {
        return Fail(
            why, "parent_receipt_bundle_shape");
    }
    for (uint32_t shard_index = 0;
         shard_index < receipts.shards.size();
         ++shard_index) {
        const auto& actual_shard =
            receipts.shards[shard_index];
        const auto& expected_shard =
            expected.shards[shard_index];
        if (actual_shard.shard_index != shard_index ||
            !actual_shard.exact_role_order ||
            !actual_shard
                .dual_fp3_terminal_cancellation) {
            return Fail(
                why, "parent_receipt_shard_shape");
        }
        for (uint32_t role_index = 0;
             role_index < 2; ++role_index) {
            const auto& actual =
                actual_shard.role[role_index];
            const auto& want =
                expected_shard.role[role_index];
            if (actual.role != want.role ||
                actual.bus_id != want.bus_id ||
                !(actual.manifest == want.manifest) ||
                actual.nodes.size() !=
                    want.nodes.size() ||
                actual.trace_commitment !=
                    want.trace_commitment ||
                actual.auxiliary_commitment !=
                    want.auxiliary_commitment ||
                actual.challenge_commitment !=
                    want.challenge_commitment ||
                !(actual.terminal == want.terminal) ||
                !actual.exact_child_coverage ||
                !actual.every_native_child_verified ||
                !actual.dual_fp3_terminal_exported) {
                return Fail(
                    why,
                    "parent_receipt_role_binding");
            }
            for (uint32_t node = 0;
                 node < actual.nodes.size();
                 ++node) {
                if (!recursive_hierarchy::
                        ValidateRetainedSplitRapHierarchyNodeV2(
                            want.manifest,
                            want.nodes[node]
                                .constraint_system,
                            want.nodes[node]
                                .base_column_indices,
                            want.nodes[node].fs_seed,
                            actual.nodes[node],
                            why)) {
                    return false;
                }
            }
            if (actual.receipt_commitment !=
                    CommitParentRoleReceipt(actual) ||
                actual.receipt_commitment !=
                    want.receipt_commitment) {
                return Fail(
                    why,
                    "parent_receipt_role_commitment");
            }
        }
        if (!Zero(AddTerminal(
                actual_shard.role[0].terminal,
                actual_shard.role[1].terminal)) ||
            actual_shard.receipt_pair_commitment !=
                CommitParentShardReceipts(
                    actual_shard) ||
            actual_shard.receipt_pair_commitment !=
                expected_shard
                    .receipt_pair_commitment) {
            return Fail(
                why,
                "parent_receipt_pair_binding");
        }
    }
    if (receipts.bundle_commitment !=
            CommitParentReceiptBundle(receipts) ||
        receipts.bundle_commitment !=
            expected.bundle_commitment) {
        return Fail(
            why, "parent_receipt_bundle_binding");
    }
    if (why != nullptr) {
        *why =
            "stage3:coupled_gemm_range_ctl_v3:"
            "parent_receipts_native_verified";
    }
    return true;
}

} // namespace matmul::v4::rc::coupled_gemm_range_ctl_v3
