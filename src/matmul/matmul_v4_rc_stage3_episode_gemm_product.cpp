// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_gemm_product.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>

#include <hash.h>

#include <algorithm>
#include <limits>
#include <optional>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
using gf::Fp3;

constexpr char PIN_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_GEMM_DOT_PIN_V1";
constexpr char SEED_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_GEMM_DOT_AIR_V1";
constexpr char LAYER_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_GEMM_LAYER_PRODUCT_V1";
constexpr char COLLECTION_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_GEMM_PRODUCT_V1";

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:episode_gemm_product:" + detail;
    }
    return false;
}

bool IsPowerOfTwo(uint32_t value)
{
    return value >= 2 && (value & (value - 1)) == 0;
}

uint32_t NextPowerOfTwo(uint64_t value)
{
    if (value < 2 || value > (uint64_t{1} << 31)) return 0;
    uint64_t out = 1;
    while (out < value) out <<= 1;
    return static_cast<uint32_t>(out);
}

Fp3 U(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

Fp3 S(int64_t value)
{
    return Fp3::FromFp(gf::FromSigned(value));
}

void AddConstraint(
    aq::AirConstraintSystem<Fp3>& cs,
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

bool IsEpisodeStatement(const RCStage3SuccinctProof& statement)
{
    return statement.statement == RCStage3StatementKind::Episode ||
           statement.statement == RCStage3StatementKind::Composed;
}

std::vector<Fp3> ToField(const std::vector<int8_t>& values)
{
    std::vector<Fp3> out;
    out.reserve(values.size());
    for (int8_t value : values) out.push_back(S(value));
    return out;
}

std::vector<Fp3> ToField(const std::vector<int64_t>& values)
{
    std::vector<Fp3> out;
    out.reserve(values.size());
    for (int64_t value : values) out.push_back(S(value));
    return out;
}

uint256 VectorRoot(
    const uint256& statement_commitment,
    const RCGkrOperandRef& ref,
    const std::vector<Fp3>& values,
    std::string* why)
{
    const auto root =
        ComputeRCStage3EpisodeWiringVectorRootFromValues(
            statement_commitment, ref.first_column,
            ref.n_chunks, values, why);
    return root.has_value() ? *root : uint256{};
}

std::optional<uint32_t> FindProducer(
    const RCStage3GemmExtractManifest& manifest,
    const RCGkrOperandRef& ref,
    uint32_t before_layer)
{
    for (uint32_t i = 0;
         i < before_layer && i < manifest.layers.size(); ++i) {
        const auto& producer = manifest.layers[i];
        if (producer.out_first_column == ref.first_column &&
            producer.out_chunks == ref.n_chunks) {
            return i;
        }
    }
    return std::nullopt;
}

struct RegisteredOperand {
    RCGkrOperandRef ref;
    uint256 root;
};

std::optional<RegisteredOperand> FindRegisteredOperand(
    const RCStage3GemmExtractManifest& manifest,
    uint32_t first_column,
    uint32_t through_layer)
{
    const uint32_t end = std::min<uint32_t>(
        through_layer + 1, manifest.layers.size());
    for (uint32_t i = 0; i < end; ++i) {
        const auto& layer = manifest.layers[i];
        if (layer.a.first_column == first_column) {
            return RegisteredOperand{
                layer.a, layer.bindings.operand_a_root};
        }
        if (layer.b.first_column == first_column) {
            return RegisteredOperand{
                layer.b, layer.bindings.operand_b_root};
        }
    }
    return std::nullopt;
}

bool ValuesMatchExtractProducer(
    const std::vector<int8_t>& values,
    uint32_t producer_ordinal,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeExtractProduct& extract,
    std::string* why)
{
    if (producer_ordinal >= manifest.layers.size()) {
        return Fail(why, "producer_ordinal");
    }
    const auto& producer = manifest.layers[producer_ordinal];
    if (values.size() != producer.gemm_cell_count ||
        producer.extract_tile_count !=
            values.size() / kRCMxBlockLen) {
        return Fail(why, "producer_value_shape");
    }
    for (uint64_t tile_index = 0;
         tile_index < producer.extract_tile_count; ++tile_index) {
        const uint64_t global =
            producer.extract_tile_begin + tile_index;
        if (global >= extract.tiles.size()) {
            return Fail(why, "producer_tile_omission");
        }
        const auto& sampler = extract.tiles[global].sampler_pin;
        if (sampler.n_rows < kRCMxBlockLen ||
            sampler.column_roots.size() !=
                aq::kRcSamplerNumCols) {
            return Fail(why, "producer_sampler_shape");
        }
        std::vector<Fp3> expected(
            sampler.n_rows, Fp3::Zero());
        for (uint32_t i = 0; i < kRCMxBlockLen; ++i) {
            expected[i] = S(values[
                tile_index * kRCMxBlockLen + i]);
        }
        const uint256 root =
            aq::AirCommittedValuesRoot<Fp3>(
                expected, sampler.n_coeffs);
        if (root != sampler.column_roots[aq::kColOut].root) {
            return Fail(
                why, "producer_output_root_" +
                         std::to_string(tile_index));
        }
    }
    return true;
}

bool ExpectedTileColumns(
    const RCStage3GemmExtractLayerManifest& spec,
    const RCStage3EpisodeGemmLayerProduct& layer,
    uint64_t layer_tile,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeGemmDotPin& pin,
    std::vector<std::vector<Fp3>>& out,
    std::string* why)
{
    if (spec.n % kRCMxBlockLen != 0 ||
        layer_tile >= spec.extract_tile_count ||
        pin.contraction_size != spec.k ||
        pin.logical_rows !=
            uint64_t{spec.k} * kRCMxBlockLen ||
        pin.n_rows != NextPowerOfTwo(pin.logical_rows)) {
        return Fail(why, "tile_shape");
    }
    const uint32_t blocks_per_row =
        spec.n / kRCMxBlockLen;
    const uint32_t row = layer_tile / blocks_per_row;
    const uint32_t block = layer_tile % blocks_per_row;
    if (row >= spec.m ||
        layer.operand_a.size() !=
            uint64_t{spec.m} * spec.k ||
        layer.operand_b.size() !=
            uint64_t{spec.k} * spec.n ||
        layer.gemm_y.size() !=
            uint64_t{spec.m} * spec.n ||
        (!layer.residual.empty() &&
         layer.residual.size() != layer.gemm_y.size())) {
        return Fail(why, "layer_vector_shape");
    }
    const uint64_t extract_global =
        spec.extract_tile_begin + layer_tile;
    if (extract_global >= extract.tiles.size()) {
        return Fail(why, "extract_input_tile");
    }

    out.assign(
        kRCStage3GemmDotColumns,
        std::vector<Fp3>(pin.n_rows, Fp3::Zero()));
    for (uint32_t lane = 0;
         lane < kRCMxBlockLen; ++lane) {
        const uint32_t column =
            block * kRCMxBlockLen + lane;
        const int64_t y =
            layer.gemm_y[uint64_t{row} * spec.n + column];
        const int64_t residual = layer.residual.empty()
            ? 0
            : layer.residual[
                  uint64_t{row} * spec.n + column];
        const int64_t input =
            extract.tiles[extract_global].input[lane];
        if (y < -static_cast<int64_t>(spec.signed_max_abs) ||
            y > static_cast<int64_t>(spec.signed_max_abs) ||
            input != y + residual) {
            return Fail(why, "signed_bound_or_extract_input");
        }
        for (uint32_t contraction = 0;
             contraction < spec.k; ++contraction) {
            const uint32_t trace_row =
                lane * spec.k + contraction;
            const int8_t a = layer.operand_a[
                uint64_t{row} * spec.k + contraction];
            const int8_t b = spec.b.transpose
                ? layer.operand_b[
                      uint64_t{column} * spec.k +
                      contraction]
                : layer.operand_b[
                      uint64_t{contraction} * spec.n +
                      column];
            if (a < -48 || a > 48 || b < -48 || b > 48) {
                return Fail(why, "operand_range");
            }
            out[kRCStage3GemmDotActive][trace_row] = U(1);
            out[kRCStage3GemmDotStart][trace_row] =
                U(contraction == 0 ? 1 : 0);
            out[kRCStage3GemmDotEnd][trace_row] =
                U(contraction + 1 == spec.k ? 1 : 0);
            out[kRCStage3GemmDotA][trace_row] = S(a);
            out[kRCStage3GemmDotB][trace_row] = S(b);
            if (contraction + 1 == spec.k) {
                out[kRCStage3GemmDotY][trace_row] = S(y);
                out[kRCStage3GemmDotResidual][trace_row] =
                    S(residual);
                out[kRCStage3GemmDotExtractInput][trace_row] =
                    S(input);
            }
        }
    }
    return true;
}

} // namespace

uint256 ComputeRCStage3EpisodeGemmDotPinCommitment(
    const RCStage3EpisodeGemmDotPin& pin)
{
    if (pin.version != kRCStage3EpisodeGemmProductVersion ||
        pin.statement_commitment.IsNull() ||
        pin.manifest_commitment.IsNull() ||
        pin.contraction_size == 0 ||
        pin.logical_rows !=
            uint64_t{pin.contraction_size} *
                kRCMxBlockLen ||
        !IsPowerOfTwo(pin.n_rows) ||
        pin.n_rows < pin.logical_rows ||
        pin.n_coeffs != pin.n_rows ||
        pin.column_roots.size() !=
            kRCStage3GemmDotColumns) {
        return {};
    }
    HashWriter hash;
    hash << PIN_DOMAIN;
    hash << pin.version << pin.statement_commitment;
    hash << pin.manifest_commitment;
    hash << pin.layer_ordinal << pin.layer_tile_index;
    hash << pin.contraction_size << pin.logical_rows;
    hash << pin.n_rows << pin.n_coeffs;
    for (uint32_t i = 0; i < pin.column_roots.size(); ++i) {
        if (pin.column_roots[i].column != i ||
            pin.column_roots[i].root.IsNull()) {
            return {};
        }
        hash << i << pin.column_roots[i].root;
    }
    return hash.GetHash();
}

uint256 ComputeRCStage3EpisodeGemmDotSeed(
    const RCStage3EpisodeGemmDotPin& pin)
{
    const uint256 commitment =
        ComputeRCStage3EpisodeGemmDotPinCommitment(pin);
    if (commitment.IsNull()) return {};
    HashWriter hash;
    hash << SEED_DOMAIN << commitment;
    return hash.GetHash();
}

bool BuildRCStage3EpisodeGemmDotConstraintSystem(
    const RCStage3EpisodeGemmDotPin& pin,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    out = {};
    if (pin.pin_commitment !=
            ComputeRCStage3EpisodeGemmDotPinCommitment(pin) ||
        pin.pin_commitment.IsNull()) {
        return Fail(why, "dot_pin");
    }
    out.n_rows = pin.n_rows;
    out.n_columns = kRCStage3GemmDotColumns;
    for (uint32_t column : {
             kRCStage3GemmDotActive,
             kRCStage3GemmDotStart,
             kRCStage3GemmDotEnd}) {
        AddConstraint(
            out, "gemm.dot.boolean", aq::AirKind::kEverywhere, 2,
            [column](const std::vector<Fp3>& row,
                     const std::vector<Fp3>&) {
                return gf::Mul(
                    row[column],
                    gf::Sub(row[column], Fp3::One()));
            });
    }
    AddConstraint(
        out, "gemm.dot.product", aq::AirKind::kEverywhere, 2,
        [](const std::vector<Fp3>& row,
           const std::vector<Fp3>&) {
            return gf::Mul(
                row[kRCStage3GemmDotActive],
                gf::Sub(
                    row[kRCStage3GemmDotProduct],
                    gf::Mul(
                        row[kRCStage3GemmDotA],
                        row[kRCStage3GemmDotB])));
        });
    AddConstraint(
        out, "gemm.dot.accumulate", aq::AirKind::kEverywhere, 1,
        [](const std::vector<Fp3>& row,
           const std::vector<Fp3>&) {
            return gf::Mul(
                row[kRCStage3GemmDotActive],
                gf::Sub(
                    row[kRCStage3GemmDotAccumulatorAfter],
                    gf::Add(
                        row[kRCStage3GemmDotAccumulatorBefore],
                        row[kRCStage3GemmDotProduct])));
        });
    AddConstraint(
        out, "gemm.dot.start_zero", aq::AirKind::kEverywhere, 2,
        [](const std::vector<Fp3>& row,
           const std::vector<Fp3>&) {
            return gf::Mul(
                row[kRCStage3GemmDotStart],
                row[kRCStage3GemmDotAccumulatorBefore]);
        });
    AddConstraint(
        out, "gemm.dot.end_y", aq::AirKind::kEverywhere, 2,
        [](const std::vector<Fp3>& row,
           const std::vector<Fp3>&) {
            return gf::Mul(
                row[kRCStage3GemmDotEnd],
                gf::Sub(
                    row[kRCStage3GemmDotY],
                    row[kRCStage3GemmDotAccumulatorAfter]));
        });
    AddConstraint(
        out, "gemm.dot.extract_input", aq::AirKind::kEverywhere, 2,
        [](const std::vector<Fp3>& row,
           const std::vector<Fp3>&) {
            return gf::Mul(
                row[kRCStage3GemmDotEnd],
                gf::Sub(
                    row[kRCStage3GemmDotExtractInput],
                    gf::Add(
                        row[kRCStage3GemmDotY],
                        row[kRCStage3GemmDotResidual])));
        });
    AddConstraint(
        out, "gemm.dot.chain", aq::AirKind::kTransition, 2,
        [](const std::vector<Fp3>& row,
           const std::vector<Fp3>& next) {
            return gf::Mul(
                gf::Mul(
                    row[kRCStage3GemmDotActive],
                    gf::Sub(
                        Fp3::One(),
                        row[kRCStage3GemmDotEnd])),
                gf::Sub(
                    next[kRCStage3GemmDotAccumulatorBefore],
                    row[kRCStage3GemmDotAccumulatorAfter]));
        });
    for (uint32_t column : {
             kRCStage3GemmDotProduct,
             kRCStage3GemmDotAccumulatorBefore,
             kRCStage3GemmDotAccumulatorAfter}) {
        AddConstraint(
            out, "gemm.dot.padding_zero",
            aq::AirKind::kEverywhere, 2,
            [column](const std::vector<Fp3>& row,
                     const std::vector<Fp3>&) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        row[kRCStage3GemmDotActive]),
                    row[column]);
            });
    }
    for (const auto& root : pin.column_roots) {
        out.preprocessed_roots.emplace_back(
            root.column, root.root);
    }
    return true;
}

bool VerifyRCStage3EpisodeGemmDotProof(
    const RCStage3EpisodeGemmDotPin& pin,
    const aq::AirQuotientProof<Fp3>& proof,
    std::string* why)
{
    aq::AirConstraintSystem<Fp3> cs;
    if (!BuildRCStage3EpisodeGemmDotConstraintSystem(
            pin, cs, why) ||
        proof.batch.columns.size() !=
            kRCStage3GemmDotColumns + 1 ||
        proof.batch.column_len.size() !=
            kRCStage3GemmDotColumns + 1 ||
        proof.batch.n_coeffs != pin.n_coeffs) {
        return Fail(why, "dot_proof_shape");
    }
    for (uint32_t i = 0; i < pin.column_roots.size(); ++i) {
        if (proof.batch.columns[i].root !=
            pin.column_roots[i].root) {
            return Fail(why, "dot_proof_root");
        }
    }
    std::string air_why;
    if (!aq::AirQuotientVerify<Fp3>(
            cs, proof, ComputeRCStage3EpisodeGemmDotSeed(pin),
            &air_why)) {
        return Fail(why, "dot_air:" + air_why);
    }
    return true;
}

uint256 ComputeRCStage3EpisodeGemmLayerReceiptCommitment(
    const RCStage3EpisodeGemmLayerProduct& layer)
{
    if (layer.operand_a.empty() || layer.operand_b.empty() ||
        layer.gemm_y.empty() || layer.tiles.empty()) {
        return {};
    }
    HashWriter hash;
    hash << LAYER_DOMAIN << layer.layer_ordinal;
    hash << static_cast<uint64_t>(layer.operand_a.size());
    for (int8_t value : layer.operand_a) {
        hash << static_cast<uint8_t>(value);
    }
    hash << static_cast<uint64_t>(layer.operand_b.size());
    for (int8_t value : layer.operand_b) {
        hash << static_cast<uint8_t>(value);
    }
    hash << static_cast<uint64_t>(layer.gemm_y.size());
    for (int64_t value : layer.gemm_y) hash << value;
    hash << static_cast<uint64_t>(layer.residual.size());
    for (int8_t value : layer.residual) {
        hash << static_cast<uint8_t>(value);
    }
    hash << static_cast<uint64_t>(layer.tiles.size());
    for (uint64_t i = 0; i < layer.tiles.size(); ++i) {
        const auto& tile = layer.tiles[i];
        const uint256 pin =
            ComputeRCStage3EpisodeGemmDotPinCommitment(tile.pin);
        if (tile.layer_tile_index != i || pin.IsNull()) return {};
        hash << tile.layer_tile_index << pin;
    }
    return hash.GetHash();
}

uint256 ComputeRCStage3EpisodeGemmCollectionCommitment(
    const RCStage3EpisodeGemmProduct& product)
{
    if (product.version != kRCStage3EpisodeGemmProductVersion ||
        product.statement_commitment.IsNull() ||
        product.manifest_commitment.IsNull() ||
        product.layers.empty()) {
        return {};
    }
    HashWriter hash;
    hash << COLLECTION_DOMAIN << product.version;
    hash << product.statement_commitment << product.manifest_commitment;
    hash << static_cast<uint32_t>(product.layers.size());
    for (uint32_t i = 0; i < product.layers.size(); ++i) {
        if (product.layers[i].layer_ordinal != i ||
            product.layers[i].layer_receipt_commitment.IsNull()) {
            return {};
        }
        hash << product.layers[i].layer_receipt_commitment;
    }
    hash << product.wiring.closure_commitment;
    return hash.GetHash();
}

bool BindRCStage3EpisodeGemmAlgAuthorityRoots(
    RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& product,
    const RCStage3EpisodeExtractProduct& extract,
    std::string* why)
{
    if (product.layers.size() != manifest.layers.size() ||
        extract.tiles.size() != manifest.total_extract_tiles) {
        return Fail(why, "alg_authority_public_shape");
    }
    for (uint32_t ordinal = 0;
         ordinal < manifest.layers.size(); ++ordinal) {
        auto& spec = manifest.layers[ordinal];
        const auto& layer = product.layers[ordinal];
        if (layer.layer_ordinal != ordinal ||
            layer.operand_a.size() !=
                uint64_t{spec.m} * spec.k ||
            layer.operand_b.size() !=
                uint64_t{spec.k} * spec.n ||
            layer.gemm_y.size() !=
                uint64_t{spec.m} * spec.n) {
            return Fail(
                why, "alg_authority_layer_" +
                         std::to_string(ordinal) + "_shape");
        }
        std::vector<gf::Fp3> extract_input;
        extract_input.reserve(layer.gemm_y.size());
        for (uint64_t tile = 0;
             tile < spec.extract_tile_count; ++tile) {
            const uint64_t global =
                spec.extract_tile_begin + tile;
            if (global >= extract.tiles.size()) {
                return Fail(why, "alg_authority_extract_inventory");
            }
            for (const int64_t value : extract.tiles[global].input) {
                extract_input.push_back(S(value));
            }
        }
        if (extract_input.size() != layer.gemm_y.size()) {
            return Fail(why, "alg_authority_extract_shape");
        }
        spec.bindings.operand_a_root_alg =
            RCStage3VectorRootAlgCommitment(
                ToField(layer.operand_a));
        spec.bindings.operand_b_root_alg =
            RCStage3VectorRootAlgCommitment(
                ToField(layer.operand_b));
        spec.bindings.gemm_y_root_alg =
            RCStage3VectorRootAlgCommitment(
                ToField(layer.gemm_y));
        spec.bindings.extract_input_root_alg =
            RCStage3VectorRootAlgCommitment(extract_input);
        if (spec.bindings.operand_a_root_alg.IsNull() ||
            spec.bindings.operand_b_root_alg.IsNull() ||
            spec.bindings.gemm_y_root_alg.IsNull() ||
            spec.bindings.extract_input_root_alg.IsNull()) {
            return Fail(why, "alg_authority_null_root");
        }
    }
    return true;
}

bool ValidateRCStage3EpisodeGemmAlgAuthorityRoots(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& product,
    const RCStage3EpisodeExtractProduct& extract,
    std::string* why)
{
    RCStage3GemmExtractManifest expected = manifest;
    if (!BindRCStage3EpisodeGemmAlgAuthorityRoots(
            expected, product, extract, why)) {
        return false;
    }
    for (uint32_t ordinal = 0;
         ordinal < manifest.layers.size(); ++ordinal) {
        const auto& actual =
            manifest.layers[ordinal].bindings;
        const auto& want =
            expected.layers[ordinal].bindings;
        if (actual.operand_a_root_alg !=
                want.operand_a_root_alg ||
            actual.operand_b_root_alg !=
                want.operand_b_root_alg ||
            actual.gemm_y_root_alg !=
                want.gemm_y_root_alg ||
            actual.extract_input_root_alg !=
                want.extract_input_root_alg) {
            return Fail(
                why, "alg_authority_layer_" +
                         std::to_string(ordinal) +
                         "_root_mismatch");
        }
    }
    return true;
}

bool ProveRCStage3EpisodeGemmProduct(
    const RCStage3SuccinctProof& statement,
    RCStage3GemmExtractManifest& manifest,
    const std::vector<RCStage3EpisodeGemmLayerWitness>& witnesses,
    RCStage3EpisodeExtractProduct& extract,
    RCStage3EpisodeTileStreamProduct& tile_stream,
    RCStage3EpisodeGemmProduct& out,
    std::string* why)
{
    out = {};
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    if (!IsEpisodeStatement(statement) ||
        statement_commitment.IsNull() ||
        !ValidateRCStage3GemmExtractManifestBinding(
            statement, manifest, why) ||
        witnesses.size() != manifest.layers.size() ||
        extract.tiles.size() != manifest.total_extract_tiles) {
        return Fail(why, "prove_product_shape");
    }
    out.statement_commitment = statement_commitment;
    out.layers.resize(manifest.layers.size());

    // First materialize all vectors and update every opening root. The
    // manifest commitment is computed only after this pass.
    for (uint32_t ordinal = 0;
         ordinal < manifest.layers.size(); ++ordinal) {
        auto& spec = manifest.layers[ordinal];
        const auto& witness = witnesses[ordinal];
        auto& layer = out.layers[ordinal];
        layer.layer_ordinal = ordinal;
        layer.operand_a = witness.operand_a;
        layer.operand_b = witness.operand_b;
        layer.residual = witness.residual;
        if (layer.operand_a.size() !=
                uint64_t{spec.m} * spec.k ||
            layer.operand_b.size() !=
                uint64_t{spec.k} * spec.n ||
            (spec.residual_first_column < 0
                 ? !layer.residual.empty()
                 : layer.residual.size() !=
                       uint64_t{spec.m} * spec.n)) {
            out = {};
            return Fail(
                why, "prove_layer_shape_" +
                         std::to_string(ordinal));
        }
        layer.gemm_y.assign(
            uint64_t{spec.m} * spec.n, 0);
        for (uint32_t row = 0; row < spec.m; ++row) {
            for (uint32_t column = 0;
                 column < spec.n; ++column) {
                int64_t sum = 0;
                for (uint32_t contraction = 0;
                     contraction < spec.k; ++contraction) {
                    const int8_t a = layer.operand_a[
                        uint64_t{row} * spec.k +
                        contraction];
                    const int8_t b = spec.b.transpose
                        ? layer.operand_b[
                              uint64_t{column} * spec.k +
                              contraction]
                        : layer.operand_b[
                              uint64_t{contraction} * spec.n +
                              column];
                    if (a < -48 || a > 48 ||
                        b < -48 || b > 48) {
                        out = {};
                        return Fail(
                            why, "prove_operand_range");
                    }
                    sum += static_cast<int64_t>(a) * b;
                }
                if (sum < -static_cast<int64_t>(
                              spec.signed_max_abs) ||
                    sum > static_cast<int64_t>(
                              spec.signed_max_abs)) {
                    out = {};
                    return Fail(why, "prove_signed_bound");
                }
                layer.gemm_y[
                    uint64_t{row} * spec.n + column] =
                    sum;
            }
        }
        for (uint64_t tile_index = 0;
             tile_index < spec.extract_tile_count;
             ++tile_index) {
            const uint64_t global =
                spec.extract_tile_begin + tile_index;
            const uint64_t cell_begin =
                tile_index * kRCMxBlockLen;
            if (global >= extract.tiles.size() ||
                cell_begin + kRCMxBlockLen >
                    layer.gemm_y.size()) {
                out = {};
                return Fail(why, "prove_extract_inventory");
            }
            for (uint32_t lane = 0;
                 lane < kRCMxBlockLen; ++lane) {
                const int64_t residual =
                    layer.residual.empty()
                    ? 0
                    : layer.residual[cell_begin + lane];
                if (extract.tiles[global].input[lane] !=
                    layer.gemm_y[cell_begin + lane] +
                        residual) {
                    out = {};
                    return Fail(
                        why, "prove_extract_input_equality");
                }
            }
        }
        spec.bindings.operand_a_root = VectorRoot(
            statement_commitment, spec.a,
            ToField(layer.operand_a), why);
        spec.bindings.operand_b_root = VectorRoot(
            statement_commitment, spec.b,
            ToField(layer.operand_b), why);
        RCGkrOperandRef y_ref;
        y_ref.first_column = spec.y_first_column;
        y_ref.n_chunks = spec.y_chunks;
        spec.bindings.gemm_y_root = VectorRoot(
            statement_commitment, y_ref,
            ToField(layer.gemm_y), why);
        if (spec.bindings.operand_a_root.IsNull() ||
            spec.bindings.operand_b_root.IsNull() ||
            spec.bindings.gemm_y_root.IsNull()) {
            out = {};
            return Fail(why, "prove_opening_roots");
        }
    }

    if (!BindRCStage3EpisodeGemmAlgAuthorityRoots(
            manifest, out, extract, why)) {
        out = {};
        return false;
    }

    out.manifest_commitment =
        ComputeRCStage3GemmExtractManifestCommitment(manifest);
    if (out.manifest_commitment.IsNull()) {
        out = {};
        return Fail(why, "prove_manifest_commitment");
    }
    // Extract proof seeds do not absorb the GEMM-owned roots, but their outer
    // product identities do absorb the complete manifest commitment.
    extract.manifest_commitment = out.manifest_commitment;
    extract.collection_commitment =
        ComputeRCStage3EpisodeExtractCollectionCommitment(
            extract);
    tile_stream.gemm_extract_manifest_commitment =
        out.manifest_commitment;
    tile_stream.collection_commitment =
        ComputeRCStage3EpisodeTileStreamCollectionCommitment(
            tile_stream);
    if (extract.collection_commitment.IsNull() ||
        tile_stream.collection_commitment.IsNull()) {
        out = {};
        return Fail(why, "prove_dependent_product_refresh");
    }

    // Build and prove every 32-output dot-product tile.
    for (uint32_t ordinal = 0;
         ordinal < manifest.layers.size(); ++ordinal) {
        const auto& spec = manifest.layers[ordinal];
        auto& layer = out.layers[ordinal];
        layer.tiles.reserve(spec.extract_tile_count);
        for (uint64_t tile_index = 0;
             tile_index < spec.extract_tile_count;
             ++tile_index) {
            RCStage3EpisodeGemmTileProof tile;
            tile.layer_tile_index = tile_index;
            auto& pin = tile.pin;
            pin.statement_commitment = statement_commitment;
            pin.manifest_commitment =
                out.manifest_commitment;
            pin.layer_ordinal = ordinal;
            pin.layer_tile_index = tile_index;
            pin.contraction_size = spec.k;
            pin.logical_rows =
                spec.k * kRCMxBlockLen;
            pin.n_rows =
                NextPowerOfTwo(pin.logical_rows);
            pin.n_coeffs = pin.n_rows;
            std::vector<std::vector<Fp3>> columns;
            if (pin.n_rows == 0 ||
                !ExpectedTileColumns(
                    spec, layer, tile_index,
                    extract, pin, columns, why)) {
                out = {};
                return Fail(why, "prove_dot_columns");
            }
            const uint32_t blocks_per_row =
                spec.n / kRCMxBlockLen;
            const uint32_t output_row =
                tile_index / blocks_per_row;
            const uint32_t output_block =
                tile_index % blocks_per_row;
            for (uint32_t lane = 0;
                 lane < kRCMxBlockLen; ++lane) {
                const uint32_t output_column =
                    output_block * kRCMxBlockLen + lane;
                int64_t accumulator = 0;
                for (uint32_t contraction = 0;
                     contraction < spec.k; ++contraction) {
                    const uint32_t trace_row =
                        lane * spec.k + contraction;
                    const int64_t a = layer.operand_a[
                        uint64_t{output_row} * spec.k +
                        contraction];
                    const int64_t b = spec.b.transpose
                        ? layer.operand_b[
                              uint64_t{output_column} *
                                  spec.k +
                              contraction]
                        : layer.operand_b[
                              uint64_t{contraction} *
                                  spec.n +
                              output_column];
                    const int64_t product = a * b;
                    columns[kRCStage3GemmDotProduct]
                        [trace_row] = S(product);
                    columns[
                        kRCStage3GemmDotAccumulatorBefore]
                        [trace_row] = S(accumulator);
                    accumulator += product;
                    columns[
                        kRCStage3GemmDotAccumulatorAfter]
                        [trace_row] = S(accumulator);
                }
            }
            pin.column_roots.resize(columns.size());
            for (uint32_t column = 0;
                 column < columns.size(); ++column) {
                pin.column_roots[column] = {
                    column,
                    aq::AirCommittedValuesRoot<Fp3>(
                        columns[column],
                        pin.n_coeffs)};
            }
            pin.pin_commitment =
                ComputeRCStage3EpisodeGemmDotPinCommitment(
                    pin);
            aq::AirConstraintSystem<Fp3> cs;
            if (pin.pin_commitment.IsNull() ||
                !BuildRCStage3EpisodeGemmDotConstraintSystem(
                    pin, cs, why)) {
                out = {};
                return Fail(why, "prove_dot_pin");
            }
            auto proved = aq::AirQuotientProve<Fp3>(
                cs, columns,
                ComputeRCStage3EpisodeGemmDotSeed(pin));
            if (!proved.ok || !proved.division_exact) {
                out = {};
                return Fail(
                    why, proved.note.empty()
                        ? "prove_dot_quotient"
                        : proved.note);
            }
            tile.proof = std::move(proved.proof);
            layer.tiles.push_back(std::move(tile));
        }
        layer.layer_receipt_commitment =
            ComputeRCStage3EpisodeGemmLayerReceiptCommitment(
                layer);
        if (layer.layer_receipt_commitment.IsNull()) {
            out = {};
            return Fail(why, "prove_layer_receipt");
        }
    }

    const auto schedule =
        BuildRCStage3EpisodeWiringCopySchedule(manifest, why);
    if (!schedule.has_value()) {
        out = {};
        return Fail(why, "prove_wiring_schedule");
    }
    out.wiring.statement_commitment =
        statement_commitment;
    out.wiring.manifest_commitment =
        out.manifest_commitment;
    out.wiring.edges.reserve(schedule->size());
    for (const auto& edge : *schedule) {
        if (edge.layer_ordinal >= out.layers.size()) {
            out = {};
            return Fail(why, "prove_wiring_layer");
        }
        const auto& layer =
            out.layers[edge.layer_ordinal];
        const std::vector<Fp3> values =
            edge.slot ==
                    RCStage3EpisodeWiringOperandSlot::A
                ? ToField(layer.operand_a)
                : ToField(layer.operand_b);
        RCStage3EpisodeWiringCopyEdgeProduct product;
        if (!ProveRCStage3EpisodeWiringCopyEdgeProduct(
                statement, manifest, edge, values,
                values, product, why)) {
            out = {};
            return Fail(why, "prove_wiring_edge");
        }
        out.wiring.edges.push_back(
            std::move(product));
    }
    out.wiring.closure_commitment =
        ComputeRCStage3EpisodeWiringCopyClosureCommitment(
            out.wiring);
    out.collection_commitment =
        ComputeRCStage3EpisodeGemmCollectionCommitment(out);
    if (out.wiring.closure_commitment.IsNull() ||
        out.collection_commitment.IsNull() ||
        !VerifyRCStage3EpisodeExtractProduct(
            statement, manifest, extract,
            tile_stream, why) ||
        !VerifyRCStage3EpisodeGemmProduct(
            statement, manifest, out, extract, why)) {
        out = {};
        return Fail(why, "prove_product_self_verify");
    }
    return true;
}

bool ValidateRCStage3EpisodeGemmSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& product,
    const RCStage3EpisodeExtractProduct& extract,
    std::string* why)
{
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    const uint256 manifest_commitment =
        ComputeRCStage3GemmExtractManifestCommitment(manifest);
    if (!IsEpisodeStatement(statement) ||
        !ValidateRCStage3GemmExtractManifestBinding(
            statement, manifest, why) ||
        product.version != kRCStage3EpisodeGemmProductVersion ||
        product.statement_commitment != statement_commitment ||
        product.manifest_commitment != manifest_commitment ||
        product.layers.size() != manifest.layers.size() ||
        extract.statement_commitment != statement_commitment ||
        extract.manifest_commitment != manifest_commitment ||
        extract.tiles.size() != manifest.total_extract_tiles) {
        return Fail(why, "public_shape");
    }

    for (uint32_t ordinal = 0;
         ordinal < manifest.layers.size(); ++ordinal) {
        const auto& spec = manifest.layers[ordinal];
        const auto& layer = product.layers[ordinal];
        if (layer.layer_ordinal != ordinal ||
            layer.tiles.size() != spec.extract_tile_count ||
            layer.operand_a.size() !=
                uint64_t{spec.m} * spec.k ||
            layer.operand_b.size() !=
                uint64_t{spec.k} * spec.n ||
            layer.gemm_y.size() !=
                uint64_t{spec.m} * spec.n ||
            (spec.residual_first_column < 0
                 ? !layer.residual.empty()
                 : layer.residual.size() != layer.gemm_y.size())) {
            return Fail(
                why, "layer_" + std::to_string(ordinal) +
                         "_shape");
        }

        const uint256 a_root = VectorRoot(
            statement_commitment, spec.a,
            ToField(layer.operand_a), why);
        const uint256 b_root = VectorRoot(
            statement_commitment, spec.b,
            ToField(layer.operand_b), why);
        RCGkrOperandRef y_ref;
        y_ref.first_column = spec.y_first_column;
        y_ref.n_chunks = spec.y_chunks;
        const uint256 y_root = VectorRoot(
            statement_commitment, y_ref,
            ToField(layer.gemm_y), why);
        if (a_root.IsNull() || b_root.IsNull() || y_root.IsNull() ||
            a_root != spec.bindings.operand_a_root ||
            b_root != spec.bindings.operand_b_root ||
            y_root != spec.bindings.gemm_y_root) {
            return Fail(
                why, "layer_" + std::to_string(ordinal) +
                         "_opening_root");
        }

        if (const auto producer =
                FindProducer(manifest, spec.a, ordinal);
            producer.has_value() &&
            !ValuesMatchExtractProducer(
                layer.operand_a, *producer, manifest,
                extract, why)) {
            return false;
        }
        if (const auto producer =
                FindProducer(manifest, spec.b, ordinal);
            producer.has_value() &&
            !ValuesMatchExtractProducer(
                layer.operand_b, *producer, manifest,
                extract, why)) {
            return false;
        }
        if (spec.residual_first_column >= 0) {
            const auto registered = FindRegisteredOperand(
                manifest,
                static_cast<uint32_t>(
                    spec.residual_first_column),
                ordinal);
            if (!registered.has_value()) {
                return Fail(why, "residual_unregistered");
            }
            const uint256 residual_root = VectorRoot(
                statement_commitment, registered->ref,
                ToField(layer.residual), why);
            if (residual_root.IsNull() ||
                residual_root != registered->root) {
                return Fail(why, "residual_opening_root");
            }
            if (const auto producer = FindProducer(
                    manifest, registered->ref, ordinal);
                producer.has_value() &&
                !ValuesMatchExtractProducer(
                    layer.residual, *producer, manifest,
                    extract, why)) {
                return false;
            }
        }

        for (uint64_t tile_index = 0;
             tile_index < spec.extract_tile_count; ++tile_index) {
            const auto& tile = layer.tiles[tile_index];
            const auto& pin = tile.pin;
            if (tile.layer_tile_index != tile_index ||
                pin.statement_commitment != statement_commitment ||
                pin.manifest_commitment != manifest_commitment ||
                pin.layer_ordinal != ordinal ||
                pin.layer_tile_index != tile_index ||
                pin.pin_commitment !=
                    ComputeRCStage3EpisodeGemmDotPinCommitment(pin)) {
                return Fail(why, "dot_pin_identity");
            }
            std::vector<std::vector<Fp3>> expected;
            if (!ExpectedTileColumns(
                    spec, layer, tile_index, extract,
                    pin, expected, why)) {
                return false;
            }
            for (uint32_t column = 0;
                 column <= kRCStage3GemmDotExtractInput;
                 ++column) {
                const uint256 root =
                    aq::AirCommittedValuesRoot<Fp3>(
                        expected[column], pin.n_coeffs);
                if (pin.column_roots[column].root != root) {
                    return Fail(
                        why, "dot_opening_root_" +
                                 std::to_string(column));
                }
            }
        }
        if (layer.layer_receipt_commitment !=
            ComputeRCStage3EpisodeGemmLayerReceiptCommitment(
                layer)) {
            return Fail(why, "layer_receipt");
        }
    }
    const uint256 collection =
        ComputeRCStage3EpisodeGemmCollectionCommitment(product);
    if (collection.IsNull() ||
        collection != product.collection_commitment) {
        return Fail(why, "collection_commitment");
    }
    return true;
}

bool VerifyRCStage3EpisodeGemmProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& product,
    const RCStage3EpisodeExtractProduct& extract,
    std::string* why)
{
    if (!ValidateRCStage3EpisodeGemmSchedule(
            statement, manifest, product, extract, why)) {
        return false;
    }
    for (const auto& layer : product.layers) {
        for (const auto& tile : layer.tiles) {
            if (!VerifyRCStage3EpisodeGemmDotProof(
                    tile.pin, tile.proof, why)) {
                return Fail(
                    why, "layer_" +
                             std::to_string(layer.layer_ordinal) +
                             "_tile_" +
                             std::to_string(
                                 tile.layer_tile_index) +
                             "_dot_proof");
            }
        }
    }
    if (!ValidateRCStage3EpisodeGemmAlgAuthorityRoots(
            manifest, product, extract, why)) {
        return false;
    }
    if (!VerifyRCStage3EpisodeWiringCopyClosure(
            statement, manifest, product.wiring, why)) {
        return Fail(why, "wiring_producer_closure");
    }
    if (why != nullptr) {
        *why =
            "stage3:episode_gemm_product:endpoints_5_8_exact_flat_"
            "product_ok;external_builder_and_recursion_pending";
    }
    return true;
}

RCStage3EpisodeGemmProductAudit
CurrentRCStage3EpisodeGemmProductAudit()
{
    RCStage3EpisodeGemmProductAudit out;
    out.immutable_full_lambda_schedule = true;
    out.all_operand_openings_bound = true;
    out.every_dot_product_air_executed = true;
    out.complete_signed_arithmetic_identity = true;
    out.y_root_bound = true;
    out.y_residual_to_extract_input_equality = true;
    out.internal_extract_and_wiring_producers_linked = true;
    out.endpoints_5_through_8_locally_complete = true;
    out.external_builder_provenance_complete = false;
    out.production_streaming_complete = false;
    out.recursively_consumed = false;
    out.transitively_complete = false;
    out.remaining =
        "external Q/K/V/X0/W_up/W_down openings are not yet equality-linked "
        "to the builder XOF/dequant product; V1 retains flat vectors and one "
        "proof per output tile, and no normalized parent consumes them";
    return out;
}

static_assert(kRCStage3EpisodeGemmLocalRelationExecutable);
static_assert(!kRCStage3EpisodeGemmTransitivelyComplete);

} // namespace matmul::v4::rc
