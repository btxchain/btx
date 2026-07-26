// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_builder_trace.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>

#include <algorithm>
#include <limits>
#include <optional>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
using gf::Fp3;
using AirCS = aq::AirConstraintSystem<Fp3>;

constexpr char PRODUCT_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_BUILDER_TRACE_PRODUCT_V1";
constexpr char LAYOUT_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_BUILDER_TRACE_LAYOUT_V1";
constexpr char SOURCE_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_BUILDER_TRACE_SOURCE_V1";
constexpr char EXPANSION_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_BUILDER_TRACE_EXPANSION_V1";
constexpr char TRACE_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_BUILDER_TRACE_ROOT_V1";
constexpr char AIR_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_BUILDER_TRACE_AIR_SEED_V1";
constexpr uint32_t UNUSED_INDEX =
    std::numeric_limits<uint32_t>::max();
constexpr uint64_t ROOT_MEMORY_ADDRESS =
    UINT64_C(0x4550000400000000);

enum TraceColumn : uint32_t {
    kColMantissa = 0,
    kColRepeatedScale,
    kColScaleBit0,
    kColScaleBit1,
    kColScaleFactor,
    kColOutput,
    kTraceColumns,
};

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:episode_builder_trace:" + detail;
    }
    return false;
}

bool SameParams(
    const RCEpisodeParams& a,
    const RCEpisodeParams& b)
{
    return a.rounds == b.rounds &&
           a.d_head == b.d_head &&
           a.n_q == b.n_q &&
           a.n_ctx == b.n_ctx &&
           a.L_lyr == b.L_lyr &&
           a.d_model == b.d_model &&
           a.d_ff == b.d_ff &&
           a.b_seq == b.b_seq &&
           a.T_leaf == b.T_leaf;
}

void HashParams(HashWriter& hash, const RCEpisodeParams& params)
{
    hash << params.rounds << params.d_head << params.n_q;
    hash << params.n_ctx << params.L_lyr << params.d_model;
    hash << params.d_ff << params.b_seq << params.T_leaf;
}

bool IsLeafTensor(
    const RCGkrColumnInfo& column,
    const RCGkrLayout& layout)
{
    switch (column.tensor) {
    case RCGkrTensor::Q:
    case RCGkrTensor::K:
    case RCGkrTensor::V:
    case RCGkrTensor::Wup:
    case RCGkrTensor::Wdn:
        return true;
    case RCGkrTensor::X:
        // Lambda records a DOWN output with the producing layer number, so
        // the first produced X also has layer==0. Identity as X0 is instead
        // defined by absence from every verifier-derived output range.
        return std::none_of(
            layout.layers.begin(), layout.layers.end(),
            [&](const auto& layer) {
                return column.id >= layer.out_first_column &&
                       column.id <
                           layer.out_first_column +
                               layer.out_chunks;
            });
    default:
        return false;
    }
}

RCStage3EpisodeOperandKind OperandKind(RCGkrTensor tensor)
{
    switch (tensor) {
    case RCGkrTensor::Q:
        return RCStage3EpisodeOperandKind::Q;
    case RCGkrTensor::K:
        return RCStage3EpisodeOperandKind::K;
    case RCGkrTensor::V:
        return RCStage3EpisodeOperandKind::V;
    case RCGkrTensor::X:
        return RCStage3EpisodeOperandKind::X0;
    case RCGkrTensor::Wup:
        return RCStage3EpisodeOperandKind::WUp;
    case RCGkrTensor::Wdn:
        return RCStage3EpisodeOperandKind::WDown;
    default:
        return {};
    }
}

uint256 ComputeLayoutScheduleRoot(const RCEpisodeParams& params)
{
    if (!ValidateRCEpisodeParams(params)) return {};
    const auto layout = RCGkrTraceLayout(params);
    if (layout.columns.empty() || layout.layers.empty()) return {};
    HashWriter hash;
    hash << LAYOUT_DOMAIN << kRCStage3EpisodeBuilderTraceVersion;
    HashParams(hash, params);
    hash << static_cast<uint32_t>(layout.columns.size());
    for (const auto& column : layout.columns) {
        hash << column.id << static_cast<uint8_t>(column.tensor);
        hash << column.round << column.layer;
        hash << column.rows << column.cols;
        hash << column.chunk << column.n_chunks;
        hash << column.chunk_offset << column.len;
        hash << column.int64_cells;
    }
    hash << static_cast<uint32_t>(layout.layers.size());
    for (const auto& layer : layout.layers) {
        hash << static_cast<uint32_t>(layer.kind);
        hash << layer.round << layer.layer;
        hash << layer.m << layer.n << layer.k;
        hash << layer.a.first_column << layer.a.n_chunks;
        hash << layer.a.transpose;
        hash << layer.b.first_column << layer.b.n_chunks;
        hash << layer.b.transpose;
        hash << layer.y_first_column << layer.y_chunks;
        hash << layer.out_first_column << layer.out_chunks;
        hash << layer.residual_first_column;
    }
    return hash.GetHash();
}

struct ExpansionSpec {
    RCStage3EpisodeOperandKind kind{};
    uint32_t round{UNUSED_INDEX};
    uint32_t layer{UNUSED_INDEX};
    bool shared{false};
    uint32_t rows{0};
    uint32_t cols{0};
    std::vector<uint32_t> source_indices;
};

bool ExpectedExpansionSpecs(
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderOperandXofProduct& operand_xof,
    std::vector<ExpansionSpec>& out,
    std::string* why)
{
    out.clear();
    uint32_t cursor = 0;
    while (cursor < operand_xof.instances.size()) {
        const auto& source = operand_xof.instances[cursor];
        ExpansionSpec spec;
        spec.kind = source.kind;
        spec.round = source.round_index;
        spec.layer = source.layer_index;
        spec.shared = source.episode_shared;
        spec.rows = source.rows;
        spec.cols = source.cols;
        if (source.kind == RCStage3EpisodeOperandKind::X0 &&
            source.row_block != UNUSED_INDEX) {
            if (!UseDatacenterRowBlockX0(params) ||
                source.row_block != 0 ||
                source.rows != kRCX0RowBlockRows ||
                source.cols != params.d_model) {
                return Fail(why, "row_block_begin");
            }
            const uint32_t count =
                params.b_seq / kRCX0RowBlockRows;
            spec.rows = params.b_seq;
            for (uint32_t block = 0; block < count; ++block) {
                if (cursor + block >= operand_xof.instances.size()) {
                    return Fail(why, "row_block_omission");
                }
                const auto& part =
                    operand_xof.instances[cursor + block];
                if (part.kind !=
                        RCStage3EpisodeOperandKind::X0 ||
                    part.round_index != source.round_index ||
                    part.layer_index != UNUSED_INDEX ||
                    part.row_block != block ||
                    part.episode_shared ||
                    part.rows != kRCX0RowBlockRows ||
                    part.cols != params.d_model) {
                    return Fail(why, "row_block_order");
                }
                spec.source_indices.push_back(cursor + block);
            }
            cursor += count;
        } else {
            if (source.row_block != UNUSED_INDEX) {
                return Fail(why, "unexpected_row_block");
            }
            spec.source_indices.push_back(cursor++);
        }
        out.push_back(std::move(spec));
    }
    return !out.empty() || Fail(why, "empty_expansions");
}

uint256 ComputeSourceLinkRoot(
    const RCStage3EpisodeBuilderOperandXofProduct& operand_xof,
    const ExpansionSpec& spec)
{
    if (operand_xof.product_commitment.IsNull() ||
        spec.source_indices.empty()) {
        return {};
    }
    HashWriter hash;
    hash << SOURCE_DOMAIN << kRCStage3EpisodeBuilderTraceVersion;
    hash << operand_xof.product_commitment;
    hash << static_cast<uint8_t>(spec.kind);
    hash << spec.round << spec.layer << spec.shared;
    hash << spec.rows << spec.cols;
    hash << static_cast<uint32_t>(spec.source_indices.size());
    for (uint32_t index : spec.source_indices) {
        if (index >= operand_xof.instances.size()) return {};
        const auto& source = operand_xof.instances[index];
        if (source.schedule_index != index ||
            source.seed_derivations.empty() ||
            source.mantissa.commitment.IsNull() ||
            source.scale.commitment.IsNull()) {
            return {};
        }
        hash << index << source.source;
        hash << static_cast<uint32_t>(
            source.seed_derivations.size());
        for (const auto& derivation : source.seed_derivations) {
            hash << derivation.sha.commitment;
            hash << derivation.sha.digest;
        }
        hash << source.mantissa.commitment;
        hash << source.scale.commitment;
    }
    return hash.GetHash();
}

bool ExpansionMaterial(
    const RCStage3EpisodeBuilderOperandXofProduct& operand_xof,
    const ExpansionSpec& spec,
    std::vector<Fp3>& mantissa,
    std::vector<Fp3>& repeated_scale,
    std::vector<Fp3>* bit0,
    std::vector<Fp3>* bit1,
    std::vector<Fp3>* scale_factor,
    std::vector<Fp3>* output,
    std::string* why)
{
    mantissa.clear();
    repeated_scale.clear();
    if (bit0 != nullptr) bit0->clear();
    if (bit1 != nullptr) bit1->clear();
    if (scale_factor != nullptr) scale_factor->clear();
    if (output != nullptr) output->clear();
    const uint64_t expected =
        static_cast<uint64_t>(spec.rows) * spec.cols;
    if (expected == 0 ||
        expected > std::numeric_limits<size_t>::max()) {
        return Fail(why, "material_size");
    }
    mantissa.reserve(expected);
    repeated_scale.reserve(expected);
    if (bit0 != nullptr) bit0->reserve(expected);
    if (bit1 != nullptr) bit1->reserve(expected);
    if (scale_factor != nullptr) scale_factor->reserve(expected);
    if (output != nullptr) output->reserve(expected);
    for (uint32_t source_index : spec.source_indices) {
        if (source_index >= operand_xof.instances.size()) {
            return Fail(why, "material_source_index");
        }
        const auto& source = operand_xof.instances[source_index];
        const uint64_t cells =
            static_cast<uint64_t>(source.rows) * source.cols;
        const uint64_t scale_cells =
            static_cast<uint64_t>(source.rows) *
            (source.cols / kRCMxBlockLen);
        if (source.mantissa.output.size() != cells ||
            source.scale.output.size() != scale_cells) {
            return Fail(why, "material_source_shape");
        }
        for (uint64_t cell = 0; cell < cells; ++cell) {
            const uint8_t mu_byte = source.mantissa.output[cell];
            const int64_t mu = mu_byte < 128
                ? mu_byte
                : static_cast<int64_t>(mu_byte) - 256;
            const uint8_t scale =
                source.scale.output[cell / kRCMxBlockLen];
            if (scale > 3) return Fail(why, "material_scale");
            const int64_t expanded = mu * (int64_t{1} << scale);
            if (expanded < -128 || expanded > 127) {
                return Fail(why, "material_int8_range");
            }
            mantissa.push_back(
                Fp3::FromFp(gf::FromSigned(mu)));
            repeated_scale.push_back(
                Fp3::FromFp(gf::FromU64(scale)));
            if (bit0 != nullptr) {
                bit0->push_back(Fp3::FromFp(
                    gf::FromU64(scale & 1U)));
            }
            if (bit1 != nullptr) {
                bit1->push_back(Fp3::FromFp(
                    gf::FromU64(scale >> 1)));
            }
            if (scale_factor != nullptr) {
                scale_factor->push_back(Fp3::FromFp(
                    gf::FromU64(uint64_t{1} << scale)));
            }
            if (output != nullptr) {
                output->push_back(
                    Fp3::FromFp(gf::FromSigned(expanded)));
            }
        }
    }
    const bool exact =
        mantissa.size() == expected &&
        repeated_scale.size() == expected &&
        (bit0 == nullptr || bit0->size() == expected) &&
        (bit1 == nullptr || bit1->size() == expected) &&
        (scale_factor == nullptr ||
         scale_factor->size() == expected) &&
        (output == nullptr || output->size() == expected);
    return exact || Fail(why, "material_total");
}

AirCS BuildDequantConstraintSystem(uint32_t n_rows)
{
    constraint_bytecode::ProgramTable table;
    AirCS cs;
    if (!BuildRCStage3EpisodeBuilderTraceProgramTable(
            table) ||
        table.current_width != kTraceColumns ||
        !constraint_bytecode::
            BuildAirConstraintSystemFromProgramTable(
                table, n_rows, cs)) {
        return {};
    }
    return cs;
}

uint256 ComputeAirSeed(
    const RCStage3EpisodeBuilderTraceProduct& product,
    const RCStage3EpisodeBuilderTraceExpansion& expansion,
    const RCStage3EpisodeBuilderTraceAirShard& shard)
{
    if (product.statement_commitment.IsNull() ||
        product.operand_xof_product_commitment.IsNull() ||
        expansion.source_link_root.IsNull() ||
        shard.logical_rows == 0 || shard.n_rows == 0) {
        return {};
    }
    HashWriter hash;
    hash << AIR_SEED_DOMAIN << product.version;
    hash << product.statement_commitment;
    hash << product.params_manifest_commitment;
    hash << product.seed_chain_product_commitment;
    hash << product.operand_xof_product_commitment;
    hash << expansion.expansion_index;
    hash << static_cast<uint8_t>(expansion.kind);
    hash << expansion.round_index << expansion.layer_index;
    hash << expansion.episode_shared;
    hash << expansion.rows << expansion.cols;
    hash << expansion.source_link_root;
    hash << shard.shard_index << shard.value_begin;
    hash << shard.logical_rows << shard.n_rows;
    return hash.GetHash();
}

uint256 ComputeExpansionCommitment(
    const RCStage3EpisodeBuilderTraceExpansion& expansion)
{
    if (expansion.source_link_root.IsNull() ||
        expansion.operand_xof_indices.empty() ||
        expansion.shards.empty()) {
        return {};
    }
    HashWriter hash;
    hash << EXPANSION_DOMAIN << kRCStage3EpisodeBuilderTraceVersion;
    hash << expansion.expansion_index;
    hash << static_cast<uint8_t>(expansion.kind);
    hash << expansion.round_index << expansion.layer_index;
    hash << expansion.episode_shared;
    hash << expansion.rows << expansion.cols;
    hash << static_cast<uint32_t>(
        expansion.operand_xof_indices.size());
    for (uint32_t index : expansion.operand_xof_indices) {
        hash << index;
    }
    hash << expansion.source_link_root;
    hash << static_cast<uint32_t>(expansion.shards.size());
    for (uint32_t i = 0; i < expansion.shards.size(); ++i) {
        const auto& shard = expansion.shards[i];
        if (shard.shard_index != i ||
            shard.logical_rows == 0 ||
            shard.output_root.IsNull()) {
            return {};
        }
        hash << shard.shard_index << shard.value_begin;
        hash << shard.logical_rows << shard.n_rows;
        hash << shard.output_root;
    }
    return hash.GetHash();
}

std::optional<uint32_t> FindExpansion(
    const std::vector<RCStage3EpisodeBuilderTraceExpansion>& expansions,
    const RCGkrColumnInfo& column)
{
    const auto kind = OperandKind(column.tensor);
    for (uint32_t i = 0; i < expansions.size(); ++i) {
        const auto& expansion = expansions[i];
        if (expansion.kind != kind ||
            expansion.rows != column.rows ||
            expansion.cols != column.cols) {
            continue;
        }
        if (expansion.episode_shared) return i;
        if (expansion.round_index != column.round) continue;
        if ((kind == RCStage3EpisodeOperandKind::WUp ||
             kind == RCStage3EpisodeOperandKind::WDown) &&
            expansion.layer_index != column.layer) {
            continue;
        }
        return i;
    }
    return std::nullopt;
}

bool BuildTraceColumns(
    const RCEpisodeParams& params,
    const uint256& statement_commitment,
    const std::vector<RCStage3EpisodeBuilderTraceExpansion>& expansions,
    std::vector<RCStage3EpisodeBuilderTraceColumn>& out,
    std::string* why)
{
    out.clear();
    const auto layout = RCGkrTraceLayout(params);
    for (const auto& column : layout.columns) {
        if (column.chunk != 0 ||
            !IsLeafTensor(column, layout)) {
            continue;
        }
        const auto expansion_index =
            FindExpansion(expansions, column);
        if (!expansion_index.has_value()) {
            return Fail(why, "trace_missing_expansion");
        }
        const auto& expansion = expansions[*expansion_index];
        std::vector<uint256> output_roots;
        output_roots.reserve(expansion.shards.size());
        for (const auto& shard : expansion.shards) {
            output_roots.push_back(shard.output_root);
        }
        RCStage3EpisodeBuilderTraceColumn trace;
        trace.trace_index = out.size();
        trace.tensor = column.tensor;
        trace.round_index = column.round;
        trace.layer_index = column.layer;
        trace.rows = column.rows;
        trace.cols = column.cols;
        trace.first_column = column.id;
        trace.n_chunks = column.n_chunks;
        trace.expansion_index = *expansion_index;
        trace.wiring_vector_root =
            ComputeRCStage3EpisodeWiringVectorRoot(
                statement_commitment, trace.first_column,
                trace.n_chunks,
                static_cast<uint64_t>(trace.rows) * trace.cols,
                output_roots);
        if (trace.wiring_vector_root.IsNull()) {
            return Fail(why, "trace_vector_root");
        }
        out.push_back(std::move(trace));
    }
    return !out.empty() || Fail(why, "empty_trace_columns");
}

uint256 ComputeBuilderTraceRoot(
    const RCStage3EpisodeBuilderTraceProduct& product)
{
    if (product.version != kRCStage3EpisodeBuilderTraceVersion ||
        product.statement_commitment.IsNull() ||
        product.params_manifest_commitment.IsNull() ||
        product.seed_chain_product_commitment.IsNull() ||
        product.operand_xof_product_commitment.IsNull() ||
        product.layout_schedule_root.IsNull() ||
        product.expansions.empty() ||
        product.trace_columns.empty()) {
        return {};
    }
    HashWriter hash;
    hash << TRACE_DOMAIN << product.version;
    hash << product.statement_commitment;
    hash << product.params_manifest_commitment;
    hash << product.seed_chain_product_commitment;
    hash << product.operand_xof_product_commitment;
    hash << product.layout_schedule_root;
    hash << static_cast<uint32_t>(product.expansions.size());
    for (const auto& expansion : product.expansions) {
        if (expansion.expansion_commitment.IsNull()) return {};
        hash << expansion.expansion_commitment;
    }
    hash << static_cast<uint32_t>(product.trace_columns.size());
    for (uint32_t i = 0; i < product.trace_columns.size(); ++i) {
        const auto& trace = product.trace_columns[i];
        if (trace.trace_index != i ||
            trace.expansion_index >= product.expansions.size() ||
            trace.n_chunks == 0 ||
            trace.wiring_vector_root.IsNull()) {
            return {};
        }
        hash << trace.trace_index;
        hash << static_cast<uint8_t>(trace.tensor);
        hash << trace.round_index << trace.layer_index;
        hash << trace.rows << trace.cols;
        hash << trace.first_column << trace.n_chunks;
        hash << trace.expansion_index;
        hash << trace.wiring_vector_root;
    }
    return hash.GetHash();
}

std::vector<Fp3> RootWords(const uint256& root)
{
    std::vector<Fp3> out(8);
    for (uint32_t word = 0; word < 8; ++word) {
        uint32_t value{0};
        for (uint32_t byte = 0; byte < 4; ++byte) {
            value |= static_cast<uint32_t>(
                root.data()[word * 4 + byte]) << (8 * byte);
        }
        out[word] = Fp3::FromFp(gf::FromU64(value));
    }
    return out;
}

bool ExpectedSourceRoots(
    const RCStage3EpisodeBuilderOperandXofProduct& operand_xof,
    const ExpansionSpec& spec,
    std::vector<uint256>& mantissa_roots,
    std::vector<uint256>& scale_roots,
    std::string* why)
{
    std::vector<Fp3> mantissa;
    std::vector<Fp3> scale;
    if (!ExpansionMaterial(
            operand_xof, spec, mantissa, scale,
            nullptr, nullptr, nullptr, nullptr, why)) {
        return false;
    }
    mantissa_roots.clear();
    scale_roots.clear();
    for (uint64_t begin = 0; begin < mantissa.size();
         begin += kRCStage3EpisodeSemanticMaxRows) {
        const uint32_t logical_rows = static_cast<uint32_t>(
            std::min<uint64_t>(
                kRCStage3EpisodeSemanticMaxRows,
                mantissa.size() - begin));
        const uint32_t n_rows = FriNextPow2(logical_rows);
        std::vector<Fp3> mu(
            mantissa.begin() + begin,
            mantissa.begin() + begin + logical_rows);
        std::vector<Fp3> sc(
            scale.begin() + begin,
            scale.begin() + begin + logical_rows);
        const auto mu_root =
            ComputeRCStage3EpisodeSemanticValueRoot(
                mu, logical_rows, n_rows, why);
        const auto scale_root =
            ComputeRCStage3EpisodeSemanticValueRoot(
                sc, logical_rows, n_rows, why);
        if (!mu_root.has_value() || !scale_root.has_value()) {
            return false;
        }
        mantissa_roots.push_back(*mu_root);
        scale_roots.push_back(*scale_root);
    }
    return true;
}

bool VerifyLocalAir(
    const RCStage3EpisodeBuilderTraceProduct& product,
    const RCStage3EpisodeBuilderTraceExpansion& expansion,
    const RCStage3EpisodeBuilderTraceAirShard& shard,
    std::string* why)
{
    const auto& proof = shard.proof;
    if (proof.batch.columns.size() != kTraceColumns + 1 ||
        proof.batch.column_len.size() != kTraceColumns + 1 ||
        proof.batch.n_coeffs <
            BuildDequantConstraintSystem(shard.n_rows)
                .QuotientLen()) {
        return Fail(
            why, "air_proof_shape_" +
                std::to_string(proof.batch.columns.size()) + "_" +
                std::to_string(proof.batch.column_len.size()) + "_" +
                std::to_string(proof.batch.n_coeffs) + "_" +
                std::to_string(shard.n_rows));
    }
    const std::array<uint256, kTraceColumns> roots{
        shard.mantissa_root,
        shard.repeated_scale_root,
        shard.scale_bit0_root,
        shard.scale_bit1_root,
        shard.scale_factor_root,
        shard.output_root,
    };
    for (uint32_t column = 0; column < roots.size(); ++column) {
        if (roots[column].IsNull() ||
            proof.batch.columns[column].root != roots[column]) {
            return Fail(why, "air_column_root");
        }
    }
    const AirCS cs = BuildDequantConstraintSystem(shard.n_rows);
    std::string air_why;
    if (!aq::AirQuotientVerify<Fp3>(
            cs, proof,
            ComputeAirSeed(product, expansion, shard),
            &air_why)) {
        return Fail(why, "air:" + air_why);
    }
    return true;
}

bool StructuralParents(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderParamsProduct& params_product,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    const RCStage3EpisodeBuilderOperandXofProduct& operand_xof,
    std::string* why)
{
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    if (statement_commitment.IsNull() ||
        !ValidateRCEpisodeParams(params) ||
        params_product.memory_manifest.manifest_commitment.IsNull() ||
        seed_chain.params_product.memory_manifest.manifest_commitment !=
            params_product.memory_manifest.manifest_commitment ||
        seed_chain.product_commitment !=
            ComputeRCStage3EpisodeBuilderSeedChainProductCommitment(
                seed_chain) ||
        operand_xof.seed_chain_product_commitment !=
            seed_chain.product_commitment ||
        !ValidateRCStage3EpisodeBuilderOperandXofSchedule(
            statement, params, seed_chain, operand_xof, why)) {
        return Fail(why, "structural_parents");
    }
    return true;
}

bool ValidateProductSkeleton(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderParamsProduct& params_product,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    const RCStage3EpisodeBuilderOperandXofProduct& operand_xof,
    const RCStage3EpisodeBuilderTraceProduct& product,
    std::vector<ExpansionSpec>& specs,
    std::string* why)
{
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    if (!StructuralParents(
            statement, params, params_product, seed_chain,
            operand_xof, why) ||
        product.version != kRCStage3EpisodeBuilderTraceVersion ||
        product.statement_commitment != statement_commitment ||
        product.params_manifest_commitment !=
            params_product.memory_manifest.manifest_commitment ||
        product.seed_chain_product_commitment !=
            seed_chain.product_commitment ||
        product.operand_xof_product_commitment !=
            operand_xof.product_commitment ||
        product.layout_schedule_root !=
            ComputeLayoutScheduleRoot(params) ||
        !ExpectedExpansionSpecs(params, operand_xof, specs, why) ||
        product.expansions.size() != specs.size()) {
        return Fail(why, "product_skeleton");
    }
    return true;
}

} // namespace

uint256 ComputeRCStage3EpisodeBuilderTraceProductCommitment(
    const RCStage3EpisodeBuilderTraceProduct& product)
{
    if (product.version != kRCStage3EpisodeBuilderTraceVersion ||
        product.statement_commitment.IsNull() ||
        product.params_manifest_commitment.IsNull() ||
        product.seed_chain_product_commitment.IsNull() ||
        product.operand_xof_product_commitment.IsNull() ||
        product.layout_schedule_root.IsNull() ||
        product.builder_trace_root.IsNull() ||
        product.expansions.empty() ||
        product.trace_columns.empty() ||
        product.root_memory.bundle_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << PRODUCT_DOMAIN << product.version;
    hash << product.statement_commitment;
    hash << product.params_manifest_commitment;
    hash << product.seed_chain_product_commitment;
    hash << product.operand_xof_product_commitment;
    hash << product.layout_schedule_root;
    hash << static_cast<uint32_t>(product.expansions.size());
    for (const auto& expansion : product.expansions) {
        if (expansion.expansion_commitment.IsNull()) return {};
        hash << expansion.expansion_commitment;
    }
    hash << static_cast<uint32_t>(product.trace_columns.size());
    for (const auto& trace : product.trace_columns) {
        if (trace.wiring_vector_root.IsNull()) return {};
        hash << trace.trace_index << trace.wiring_vector_root;
    }
    hash << product.builder_trace_root;
    hash << product.root_memory.bundle_commitment;
    return hash.GetHash();
}

bool MaterializeRCStage3EpisodeBuilderTraceLeafOpenings(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderParamsProduct& params_product,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    const RCStage3EpisodeBuilderOperandXofProduct& operand_xof,
    const RCStage3EpisodeBuilderTraceProduct& product,
    std::vector<RCStage3EpisodeBuilderTraceLeafOpening>& out,
    std::string* why)
{
    out.clear();
    if (!ValidateRCStage3EpisodeBuilderTraceSchedule(
            statement, params, params_product, seed_chain,
            operand_xof, product, why)) {
        return Fail(why, "materialize_schedule");
    }
    std::vector<ExpansionSpec> specs;
    if (!ExpectedExpansionSpecs(
            params, operand_xof, specs, why) ||
        specs.size() != product.expansions.size()) {
        return Fail(why, "materialize_specs");
    }
    std::vector<std::vector<int8_t>> expanded(specs.size());
    for (uint32_t expansion = 0;
         expansion < specs.size(); ++expansion) {
        std::vector<Fp3> mantissa;
        std::vector<Fp3> scale;
        std::vector<Fp3> values;
        if (!ExpansionMaterial(
                operand_xof, specs[expansion],
                mantissa, scale, nullptr, nullptr,
                nullptr, &values, why)) {
            out.clear();
            return Fail(why, "materialize_values");
        }
        auto& bytes = expanded[expansion];
        bytes.reserve(values.size());
        for (const Fp3& value : values) {
            if (gf::Canonical(value.c1) != 0 ||
                gf::Canonical(value.c2) != 0) {
                out.clear();
                return Fail(why, "materialize_extension_value");
            }
            const uint64_t scalar = gf::Canonical(value.c0);
            int64_t signed_value{0};
            if (scalar <= 127U) {
                signed_value = static_cast<int64_t>(scalar);
            } else {
                const uint64_t magnitude = gf::kP - scalar;
                if (magnitude == 0 || magnitude > 128U) {
                    out.clear();
                    return Fail(why, "materialize_int8_value");
                }
                signed_value = -static_cast<int64_t>(magnitude);
            }
            bytes.push_back(static_cast<int8_t>(signed_value));
        }
    }

    out.reserve(product.trace_columns.size());
    for (const auto& trace : product.trace_columns) {
        if (trace.expansion_index >= expanded.size() ||
            expanded[trace.expansion_index].size() !=
                uint64_t{trace.rows} * trace.cols) {
            out.clear();
            return Fail(why, "materialize_trace_shape");
        }
        RCStage3EpisodeBuilderTraceLeafOpening opening;
        opening.tensor = trace.tensor;
        opening.round_index = trace.round_index;
        opening.layer_index = trace.layer_index;
        opening.first_column = trace.first_column;
        opening.n_chunks = trace.n_chunks;
        opening.values = expanded[trace.expansion_index];
        out.push_back(std::move(opening));
    }
    return true;
}

bool BuildRCStage3EpisodeBuilderTraceProduct(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderParamsProduct& params_product,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    const RCStage3EpisodeBuilderOperandXofProduct& operand_xof,
    RCStage3EpisodeBuilderTraceProduct& out,
    std::string* why)
{
    out = {};
    std::vector<ExpansionSpec> specs;
    if (!StructuralParents(
            statement, params, params_product, seed_chain,
            operand_xof, why) ||
        !ExpectedExpansionSpecs(params, operand_xof, specs, why)) {
        return Fail(why, "build_parents_or_specs");
    }
    out.version = kRCStage3EpisodeBuilderTraceVersion;
    out.statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    out.params_manifest_commitment =
        params_product.memory_manifest.manifest_commitment;
    out.seed_chain_product_commitment =
        seed_chain.product_commitment;
    out.operand_xof_product_commitment =
        operand_xof.product_commitment;
    out.layout_schedule_root = ComputeLayoutScheduleRoot(params);
    if (out.layout_schedule_root.IsNull()) {
        return Fail(why, "build_layout_root");
    }
    out.expansions.reserve(specs.size());
    for (uint32_t expansion_index = 0;
         expansion_index < specs.size(); ++expansion_index) {
        const auto& spec = specs[expansion_index];
        std::vector<Fp3> mantissa;
        std::vector<Fp3> scale;
        std::vector<Fp3> bit0;
        std::vector<Fp3> bit1;
        std::vector<Fp3> scale_factor;
        std::vector<Fp3> output;
        if (!ExpansionMaterial(
                operand_xof, spec, mantissa, scale,
                &bit0, &bit1, &scale_factor, &output, why)) {
            return Fail(why, "build_material");
        }
        RCStage3EpisodeBuilderTraceExpansion expansion;
        expansion.expansion_index = expansion_index;
        expansion.kind = spec.kind;
        expansion.round_index = spec.round;
        expansion.layer_index = spec.layer;
        expansion.episode_shared = spec.shared;
        expansion.rows = spec.rows;
        expansion.cols = spec.cols;
        expansion.operand_xof_indices = spec.source_indices;
        expansion.source_link_root =
            ComputeSourceLinkRoot(operand_xof, spec);
        if (expansion.source_link_root.IsNull()) {
            return Fail(why, "build_source_root");
        }
        const uint32_t shard_count = static_cast<uint32_t>(
            (mantissa.size() +
             kRCStage3EpisodeSemanticMaxRows - 1) /
            kRCStage3EpisodeSemanticMaxRows);
        expansion.shards.reserve(shard_count);
        for (uint32_t shard_index = 0;
             shard_index < shard_count; ++shard_index) {
            const uint64_t begin =
                static_cast<uint64_t>(shard_index) *
                kRCStage3EpisodeSemanticMaxRows;
            const uint32_t logical_rows = static_cast<uint32_t>(
                std::min<uint64_t>(
                    kRCStage3EpisodeSemanticMaxRows,
                    mantissa.size() - begin));
            const uint32_t n_rows = FriNextPow2(logical_rows);
            std::vector<std::vector<Fp3>> columns(
                kTraceColumns,
                std::vector<Fp3>(n_rows, Fp3::Zero()));
            const std::array<const std::vector<Fp3>*, kTraceColumns>
                sources{
                    &mantissa, &scale, &bit0, &bit1,
                    &scale_factor, &output};
            for (uint32_t column = 0;
                 column < kTraceColumns; ++column) {
                std::copy_n(
                    sources[column]->begin() + begin,
                    logical_rows, columns[column].begin());
            }
            RCStage3EpisodeBuilderTraceAirShard shard;
            shard.shard_index = shard_index;
            shard.value_begin = begin;
            shard.logical_rows = logical_rows;
            shard.n_rows = n_rows;
            shard.mantissa_root =
                aq::AirCommittedValuesRoot<Fp3>(
                    columns[kColMantissa], n_rows);
            shard.repeated_scale_root =
                aq::AirCommittedValuesRoot<Fp3>(
                    columns[kColRepeatedScale], n_rows);
            shard.scale_bit0_root =
                aq::AirCommittedValuesRoot<Fp3>(
                    columns[kColScaleBit0], n_rows);
            shard.scale_bit1_root =
                aq::AirCommittedValuesRoot<Fp3>(
                    columns[kColScaleBit1], n_rows);
            shard.scale_factor_root =
                aq::AirCommittedValuesRoot<Fp3>(
                    columns[kColScaleFactor], n_rows);
            shard.output_root =
                aq::AirCommittedValuesRoot<Fp3>(
                    columns[kColOutput], n_rows);
            // The FS seed contains the expansion identity and source-link
            // root. Trace roots are absorbed by AirQuotient itself.
            const AirCS cs = BuildDequantConstraintSystem(n_rows);
            const auto proved = aq::AirQuotientProve<Fp3>(
                cs, columns,
                ComputeAirSeed(out, expansion, shard));
            if (!proved.ok || !proved.division_exact) {
                return Fail(
                    why, "build_air:" + proved.note);
            }
            shard.proof = proved.proof;
            expansion.shards.push_back(std::move(shard));
        }
        expansion.expansion_commitment =
            ComputeExpansionCommitment(expansion);
        if (expansion.expansion_commitment.IsNull()) {
            return Fail(why, "build_expansion_commitment");
        }
        out.expansions.push_back(std::move(expansion));
    }
    if (!BuildTraceColumns(
            params, out.statement_commitment,
            out.expansions, out.trace_columns, why)) {
        return false;
    }
    out.builder_trace_root = ComputeBuilderTraceRoot(out);
    if (out.builder_trace_root.IsNull() ||
        !ProveRCStage3EpisodeSemanticMemoryBundle(
            RCStage3RelationEndpoint::EpisodeBuilderTrace,
            out.statement_commitment, ROOT_MEMORY_ADDRESS, 1,
            RootWords(out.builder_trace_root),
            out.root_memory, why)) {
        return Fail(why, "build_root_memory");
    }
    out.product_commitment =
        ComputeRCStage3EpisodeBuilderTraceProductCommitment(out);
    return !out.product_commitment.IsNull() ||
           Fail(why, "build_product_commitment");
}

bool ProveRCStage3EpisodeBuilderTraceProduct(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderParamsProduct& params_product,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    const RCStage3EpisodeBuilderOperandXofProduct& operand_xof,
    RCStage3EpisodeBuilderTraceProduct& out,
    std::string* why)
{
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    if (!VerifyRCStage3EpisodeBuilderParamsProduct(
            statement_commitment, params, params_product, why) ||
        !VerifyRCStage3EpisodeBuilderSeedChainProduct(
            statement, params, seed_chain, why) ||
        !VerifyRCStage3EpisodeBuilderOperandXofProduct(
            statement, params, seed_chain, operand_xof, why)) {
        return Fail(why, "prove_parent");
    }
    return BuildRCStage3EpisodeBuilderTraceProduct(
        statement, params, params_product, seed_chain,
        operand_xof, out, why);
}

bool ValidateRCStage3EpisodeBuilderTraceSchedule(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderParamsProduct& params_product,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    const RCStage3EpisodeBuilderOperandXofProduct& operand_xof,
    const RCStage3EpisodeBuilderTraceProduct& product,
    std::string* why)
{
    std::vector<ExpansionSpec> specs;
    if (!ValidateProductSkeleton(
            statement, params, params_product, seed_chain,
            operand_xof, product, specs, why)) {
        return false;
    }
    for (uint32_t expansion_index = 0;
         expansion_index < specs.size(); ++expansion_index) {
        const auto& spec = specs[expansion_index];
        const auto& expansion =
            product.expansions[expansion_index];
        const uint64_t value_count =
            static_cast<uint64_t>(spec.rows) * spec.cols;
        const uint32_t shard_count = static_cast<uint32_t>(
            (value_count +
             kRCStage3EpisodeSemanticMaxRows - 1) /
            kRCStage3EpisodeSemanticMaxRows);
        if (expansion.expansion_index != expansion_index ||
            expansion.kind != spec.kind ||
            expansion.round_index != spec.round ||
            expansion.layer_index != spec.layer ||
            expansion.episode_shared != spec.shared ||
            expansion.rows != spec.rows ||
            expansion.cols != spec.cols ||
            expansion.operand_xof_indices !=
                spec.source_indices ||
            expansion.source_link_root !=
                ComputeSourceLinkRoot(operand_xof, spec) ||
            expansion.shards.size() != shard_count) {
            return Fail(
                why, "expansion_shape_" +
                    std::to_string(expansion_index));
        }
        std::vector<uint256> mantissa_roots;
        std::vector<uint256> scale_roots;
        if (!ExpectedSourceRoots(
                operand_xof, spec, mantissa_roots,
                scale_roots, why) ||
            mantissa_roots.size() != shard_count ||
            scale_roots.size() != shard_count) {
            return Fail(why, "expected_source_roots");
        }
        for (uint32_t shard_index = 0;
             shard_index < shard_count; ++shard_index) {
            const auto& shard = expansion.shards[shard_index];
            const uint64_t begin =
                static_cast<uint64_t>(shard_index) *
                kRCStage3EpisodeSemanticMaxRows;
            const uint32_t logical_rows = static_cast<uint32_t>(
                std::min<uint64_t>(
                    kRCStage3EpisodeSemanticMaxRows,
                    value_count - begin));
            if (shard.shard_index != shard_index ||
                shard.value_begin != begin ||
                shard.logical_rows != logical_rows ||
                shard.n_rows != FriNextPow2(logical_rows) ||
                shard.mantissa_root !=
                    mantissa_roots[shard_index] ||
                shard.repeated_scale_root !=
                    scale_roots[shard_index] ||
                shard.scale_bit0_root.IsNull() ||
                shard.scale_bit1_root.IsNull() ||
                shard.scale_factor_root.IsNull() ||
                shard.output_root.IsNull()) {
                return Fail(
                    why, "shard_shape_" +
                        std::to_string(expansion_index));
            }
        }
        if (expansion.expansion_commitment !=
            ComputeExpansionCommitment(expansion)) {
            return Fail(why, "expansion_commitment");
        }
    }
    std::vector<RCStage3EpisodeBuilderTraceColumn>
        expected_columns;
    if (!BuildTraceColumns(
            params, product.statement_commitment,
            product.expansions, expected_columns, why) ||
        product.trace_columns != expected_columns) {
        return Fail(why, "trace_column_schedule");
    }
    if (product.builder_trace_root !=
            ComputeBuilderTraceRoot(product)) {
        return Fail(why, "builder_trace_root");
    }
    const auto root_values = RootWords(product.builder_trace_root);
    std::vector<uint256> expected_root_roots;
    const auto root = ComputeRCStage3EpisodeSemanticValueRoot(
        root_values, root_values.size(),
        FriNextPow2(root_values.size()), why);
    if (!root.has_value()) return false;
    expected_root_roots.push_back(*root);
    if (product.root_memory.endpoint !=
            RCStage3RelationEndpoint::EpisodeBuilderTrace ||
        product.root_memory.statement_commitment !=
            product.statement_commitment ||
        product.root_memory.total_instance_count !=
            root_values.size() ||
        product.root_memory.address_begin != ROOT_MEMORY_ADDRESS ||
        product.root_memory.address_stride != 1 ||
        product.root_memory.shards.size() != 1 ||
        product.root_memory.shards[0].manifest
                .canonical_value_root != *root ||
        product.product_commitment !=
            ComputeRCStage3EpisodeBuilderTraceProductCommitment(
                product)) {
        return Fail(why, "root_memory_or_product");
    }
    return true;
}

bool VerifyRCStage3EpisodeBuilderTraceLocalProduct(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderParamsProduct& params_product,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    const RCStage3EpisodeBuilderOperandXofProduct& operand_xof,
    const RCStage3EpisodeBuilderTraceProduct& product,
    std::string* why)
{
    if (!ValidateRCStage3EpisodeBuilderTraceSchedule(
            statement, params, params_product, seed_chain,
            operand_xof, product, why)) {
        return Fail(why, "verify_local_schedule");
    }
    for (const auto& expansion : product.expansions) {
        for (const auto& shard : expansion.shards) {
            if (!VerifyLocalAir(
                    product, expansion, shard, why)) {
                return false;
            }
        }
    }
    const auto root_values = RootWords(product.builder_trace_root);
    std::vector<uint256> roots{
        product.root_memory.shards[0]
            .manifest.canonical_value_root};
    if (!VerifyRCStage3EpisodeSemanticMemoryBundle(
            RCStage3RelationEndpoint::EpisodeBuilderTrace,
            product.statement_commitment, root_values.size(),
            ROOT_MEMORY_ADDRESS, 1, roots,
            product.root_memory, why)) {
        return Fail(why, "verify_root_memory");
    }
    return true;
}

bool VerifyRCStage3EpisodeBuilderTraceProduct(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderParamsProduct& params_product,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    const RCStage3EpisodeBuilderOperandXofProduct& operand_xof,
    const RCStage3EpisodeBuilderTraceProduct& product,
    std::string* why)
{
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    if (!VerifyRCStage3EpisodeBuilderParamsProduct(
            statement_commitment, params, params_product, why) ||
        !VerifyRCStage3EpisodeBuilderSeedChainProduct(
            statement, params, seed_chain, why) ||
        !VerifyRCStage3EpisodeBuilderOperandXofProduct(
            statement, params, seed_chain, operand_xof, why)) {
        return Fail(why, "verify_parent");
    }
    return VerifyRCStage3EpisodeBuilderTraceLocalProduct(
        statement, params, params_product, seed_chain,
        operand_xof, product, why);
}

bool VerifyRCStage3EpisodeBuilderTraceManifestBinding(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderTraceProduct& product,
    const RCStage3GemmExtractManifest& manifest,
    std::string* why)
{
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    if (statement_commitment.IsNull() ||
        product.version != kRCStage3EpisodeBuilderTraceVersion ||
        product.statement_commitment != statement_commitment ||
        product.layout_schedule_root !=
            ComputeLayoutScheduleRoot(params) ||
        product.builder_trace_root !=
            ComputeBuilderTraceRoot(product) ||
        product.product_commitment !=
            ComputeRCStage3EpisodeBuilderTraceProductCommitment(
                product) ||
        !ValidateRCStage3GemmExtractManifestBinding(
            statement, manifest, why) ||
        !SameParams(manifest.params, params)) {
        return Fail(why, "manifest_public_binding");
    }
    const auto find_trace =
        [&](uint32_t first_column)
            -> const RCStage3EpisodeBuilderTraceColumn* {
            const auto it = std::find_if(
                product.trace_columns.begin(),
                product.trace_columns.end(),
                [&](const auto& trace) {
                    return trace.first_column == first_column;
                });
            return it == product.trace_columns.end()
                ? nullptr : &*it;
        };
    std::vector<bool> consumed(
        product.trace_columns.size(), false);
    for (const auto& layer : manifest.layers) {
        const std::array<std::pair<RCGkrOperandRef, uint256>, 2>
            operands{{
                {layer.a, layer.bindings.operand_a_root},
                {layer.b, layer.bindings.operand_b_root},
            }};
        for (const auto& [ref, registered_root] : operands) {
            const auto* trace = find_trace(ref.first_column);
            if (trace == nullptr) continue;
            if (trace->n_chunks != ref.n_chunks ||
                trace->wiring_vector_root != registered_root) {
                return Fail(why, "manifest_leaf_root");
            }
            consumed[trace->trace_index] = true;
        }
    }
    if (std::any_of(
            consumed.begin(), consumed.end(),
            [](bool value) { return !value; })) {
        return Fail(why, "manifest_leaf_omission");
    }
    const auto wiring_schedule =
        BuildRCStage3EpisodeWiringCopySchedule(manifest, why);
    if (!wiring_schedule.has_value()) return false;
    for (const auto& edge : *wiring_schedule) {
        const auto* trace = find_trace(edge.first_column);
        if (trace != nullptr &&
            edge.registered_vector_root !=
                trace->wiring_vector_root) {
            return Fail(why, "wiring_leaf_root");
        }
    }
    return true;
}

RCStage3EpisodeBuilderTraceAudit
CurrentRCStage3EpisodeBuilderTraceAudit(
    bool endpoint1_ancestor_complete,
    bool endpoint2_ancestor_complete,
    bool endpoint3_ancestor_complete)
{
    RCStage3EpisodeBuilderTraceAudit out;
    out.verifier_derived_layout_schedule = true;
    out.exact_endpoint_1_3_composition = true;
    out.all_dequant_children_executable = true;
    out.every_generated_source_linked = true;
    out.gemm_wiring_manifest_binding_executable = true;
    out.canonical_trace_root_memory_executable = true;
    out.bounded_local_relation_complete =
        kRCStage3EpisodeBuilderTraceBoundedLocalExecutable;
    out.endpoint1_ancestor_complete =
        endpoint1_ancestor_complete;
    out.endpoint2_ancestor_complete =
        endpoint2_ancestor_complete;
    out.endpoint3_ancestor_complete =
        endpoint3_ancestor_complete;
    out.producer_provenance_complete =
        endpoint1_ancestor_complete &&
        endpoint2_ancestor_complete &&
        endpoint3_ancestor_complete;
    out.semantic_complete =
        out.bounded_local_relation_complete &&
        out.producer_provenance_complete;
    out.production_streaming_complete =
        kRCStage3EpisodeBuilderTraceProductionStreamingComplete;
    out.recursively_consumed =
        kRCStage3EpisodeBuilderTraceRecursivelyConsumed;
    if (!out.semantic_complete) {
        out.remaining =
            "the unified graph must close endpoint-1, endpoint-2 and "
            "endpoint-3 ancestry";
    } else if (!out.production_streaming_complete) {
        out.remaining =
            "production requires counter-range endpoint-3 manifests and "
            "streamed dequant quotient construction; normalized recursive "
            "consumption remains";
    } else if (!out.recursively_consumed) {
        out.remaining =
            "normalized recursive child consumption remains";
    }
    return out;
}

static_assert(kRCStage3EpisodeBuilderTraceBoundedLocalExecutable);
static_assert(!kRCStage3EpisodeBuilderTraceProductionStreamingComplete);
static_assert(!kRCStage3EpisodeBuilderTraceRecursivelyConsumed);

} // namespace matmul::v4::rc
