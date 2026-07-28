// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_gemm_product.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>

#include <hash.h>

#include <algorithm>
#include <limits>
#include <mutex>
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

std::mutex g_episode_witness_store_mutex;
uint256 g_episode_witness_store_header{};
std::shared_ptr<
    const RCStage3EpisodeWitnessCapture>
    g_episode_witness_store_capture;

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

RCStage3EpisodeWitnessCapture::RCStage3EpisodeWitnessCapture(
    const RCEpisodeParams& params)
    : m_params(params)
{
    if (!ValidateRCEpisodeParams(params)) {
        Reject("capture_invalid_params");
        return;
    }
    m_layout = RCGkrTraceLayout(params);
    const size_t layers = m_layout.layers.size();
    m_layers.resize(layers);
    m_layer_extract_inputs.resize(layers);
    m_layer_extract_outputs.resize(layers);
    m_layer_tile_begin.resize(layers);
    m_next_layer_tile.assign(layers, 0);
    m_extract_prfs.resize(layers);
    m_operands_seen.assign(layers, false);
    m_gemm_seen.assign(layers, false);
    m_extract_seen.assign(layers, false);
    uint64_t tile_cursor = 0;
    for (uint32_t ordinal = 0; ordinal < layers; ++ordinal) {
        const auto& layer = m_layout.layers[ordinal];
        if (layer.n == 0 ||
            layer.n % kRCMxBlockLen != 0) {
            Reject("capture_layout_tile_shape");
            return;
        }
        m_layer_tile_begin[ordinal] = tile_cursor;
        const uint64_t layer_tiles =
            uint64_t{layer.m} *
            (layer.n / kRCMxBlockLen);
        if (layer_tiles >
            std::numeric_limits<uint64_t>::max() -
                tile_cursor) {
            Reject("capture_tile_overflow");
            return;
        }
        tile_cursor += layer_tiles;
    }
}

void RCStage3EpisodeWitnessCapture::Reject(
    const char* why)
{
    if (m_error.empty()) m_error = why;
}

uint32_t RCStage3EpisodeWitnessCapture::RoundBase(
    uint32_t round) const
{
    return round * (2 + 2 * m_params.L_lyr);
}

uint32_t RCStage3EpisodeWitnessCapture::FfnOrdinal(
    uint32_t round, uint32_t layer,
    RCFfnProjection projection) const
{
    return RoundBase(round) + 2 + 2 * layer +
        (projection == RCFfnProjection::Down ? 1 : 0);
}

void RCStage3EpisodeWitnessCapture::AppendExtractTiles(
    uint32_t ordinal, const int64_t* input,
    const int8_t* output, uint64_t cells,
    const uint256& prf)
{
    if (!m_error.empty()) return;
    if (ordinal >= m_layout.layers.size() ||
        input == nullptr || output == nullptr ||
        prf.IsNull() || cells == 0 ||
        cells % kRCMxBlockLen != 0) {
        Reject("capture_extract_arguments");
        return;
    }
    const auto& spec = m_layout.layers[ordinal];
    const uint64_t layer_tiles =
        uint64_t{spec.m} *
        (spec.n / kRCMxBlockLen);
    const uint64_t incoming_tiles =
        cells / kRCMxBlockLen;
    if (m_next_layer_tile[ordinal] + incoming_tiles >
            layer_tiles) {
        Reject("capture_extract_order");
        return;
    }
    if (m_extract_prfs[ordinal].IsNull()) {
        m_extract_prfs[ordinal] = prf;
    } else if (m_extract_prfs[ordinal] != prf) {
        Reject("capture_extract_prf");
        return;
    }
    for (uint64_t tile = 0;
         tile < incoming_tiles; ++tile) {
        std::array<int64_t, kRCMxBlockLen> in{};
        std::array<int8_t, kRCMxBlockLen> out{};
        std::copy_n(
            input + tile * kRCMxBlockLen,
            kRCMxBlockLen, in.begin());
        std::copy_n(
            output + tile * kRCMxBlockLen,
            kRCMxBlockLen, out.begin());
        m_layer_extract_inputs[ordinal].push_back(
            std::move(in));
        m_layer_extract_outputs[ordinal].push_back(
            std::move(out));
    }
    m_extract_flattened = false;
    m_next_layer_tile[ordinal] += incoming_tiles;
    if (m_next_layer_tile[ordinal] == layer_tiles) {
        m_extract_seen[ordinal] = true;
    }
}

void RCStage3EpisodeWitnessCapture::FlattenExtractTiles() const
{
    if (m_extract_flattened) return;
    m_extract_inputs.clear();
    m_extract_outputs.clear();
    uint64_t total_tiles = 0;
    for (const auto& layer : m_layer_extract_inputs) {
        total_tiles += layer.size();
    }
    m_extract_inputs.reserve(total_tiles);
    m_extract_outputs.reserve(total_tiles);
    for (uint32_t ordinal = 0;
         ordinal < m_layer_extract_inputs.size(); ++ordinal) {
        m_extract_inputs.insert(
            m_extract_inputs.end(),
            m_layer_extract_inputs[ordinal].begin(),
            m_layer_extract_inputs[ordinal].end());
        m_extract_outputs.insert(
            m_extract_outputs.end(),
            m_layer_extract_outputs[ordinal].begin(),
            m_layer_extract_outputs[ordinal].end());
    }
    m_extract_flattened = true;
}

void RCStage3EpisodeWitnessCapture::OnPhase1Operands(
    const RCPhase1OperandsWitnessView& view)
{
    if (!m_error.empty()) return;
    if (view.round_ordinal >= m_params.rounds ||
        view.n_q != m_params.n_q ||
        view.n_ctx != m_params.n_ctx ||
        view.d_head != m_params.d_head ||
        view.q == nullptr || view.k == nullptr ||
        view.v == nullptr) {
        Reject("capture_phase1_operands_shape");
        return;
    }
    const uint32_t qkt = RoundBase(view.round_ordinal);
    const uint32_t sv = qkt + 1;
    if (sv >= m_layers.size() ||
        m_operands_seen[qkt] || m_operands_seen[sv] ||
        view.q->size() !=
            uint64_t{m_params.n_q} * m_params.d_head ||
        view.k->size() !=
            uint64_t{m_params.n_ctx} * m_params.d_head ||
        view.v->size() !=
            uint64_t{m_params.n_ctx} * m_params.d_head) {
        Reject("capture_phase1_operands_order");
        return;
    }
    m_layers[qkt].operand_a = *view.q;
    m_layers[qkt].operand_b = *view.k;
    m_layers[sv].operand_b = *view.v;
    m_layers[sv].operand_a.reserve(
        uint64_t{m_params.n_q} * m_params.n_ctx);
    m_operands_seen[qkt] = true;
    m_operands_seen[sv] = true;
}

void RCStage3EpisodeWitnessCapture::OnPhase1QKtTile(
    const RCPhase1QKtTileWitnessView& view)
{
    if (!m_error.empty()) return;
    if (view.round_ordinal >= m_params.rounds ||
        view.query_row >= m_params.n_q ||
        view.tile_len != kRCMxBlockLen ||
        view.contraction_size != m_params.d_head ||
        view.context_begin >= m_params.n_ctx ||
        view.context_begin % kRCMxBlockLen != 0 ||
        view.context_begin + kRCMxBlockLen >
            m_params.n_ctx ||
        view.operand_a == nullptr ||
        view.operand_b == nullptr ||
        view.gemm_y == nullptr ||
        view.extract_output == nullptr) {
        Reject("capture_qkt_shape");
        return;
    }
    const uint32_t ordinal = RoundBase(view.round_ordinal);
    const uint64_t tile =
        uint64_t{view.query_row} *
            (m_params.n_ctx / kRCMxBlockLen) +
        view.context_begin / kRCMxBlockLen;
    if (ordinal >= m_layers.size() ||
        !m_operands_seen[ordinal] ||
        m_next_layer_tile[ordinal] != tile) {
        Reject("capture_qkt_order");
        return;
    }
    auto& qkt = m_layers[ordinal];
    auto& sv = m_layers[ordinal + 1];
    qkt.gemm_y.insert(
        qkt.gemm_y.end(), view.gemm_y,
        view.gemm_y + kRCMxBlockLen);
    sv.operand_a.insert(
        sv.operand_a.end(), view.extract_output,
        view.extract_output + kRCMxBlockLen);
    AppendExtractTiles(
        ordinal, view.gemm_y, view.extract_output,
        kRCMxBlockLen, view.prf_key);
    if (!m_error.empty()) return;
    if (m_extract_seen[ordinal]) {
        m_gemm_seen[ordinal] = true;
    }
}

void RCStage3EpisodeWitnessCapture::OnPhase1SVRow(
    const RCPhase1SVRowWitnessView& view)
{
    if (!m_error.empty()) return;
    if (view.round_ordinal >= m_params.rounds ||
        view.query_row >= m_params.n_q ||
        view.n_ctx != m_params.n_ctx ||
        view.d_head != m_params.d_head ||
        view.operand_a == nullptr ||
        view.operand_b == nullptr ||
        view.gemm_y == nullptr ||
        view.extract_output == nullptr) {
        Reject("capture_sv_shape");
        return;
    }
    const uint32_t ordinal =
        RoundBase(view.round_ordinal) + 1;
    const uint64_t expected_tile =
        uint64_t{view.query_row} *
        (m_params.d_head / kRCMxBlockLen);
    const uint64_t qkt_tiles_through_row =
        uint64_t{view.query_row + 1} *
        (m_params.n_ctx / kRCMxBlockLen);
    if (ordinal >= m_layers.size() ||
        !m_operands_seen[ordinal] ||
        m_next_layer_tile[ordinal - 1] !=
            qkt_tiles_through_row ||
        m_next_layer_tile[ordinal] != expected_tile) {
        Reject("capture_sv_order");
        return;
    }
    auto& sv = m_layers[ordinal];
    const uint64_t row_begin =
        uint64_t{view.query_row} * m_params.n_ctx;
    if (sv.operand_a.size() <
            row_begin + m_params.n_ctx ||
        !std::equal(
            sv.operand_a.begin() + row_begin,
            sv.operand_a.begin() + row_begin +
                m_params.n_ctx,
            view.operand_a)) {
        Reject("capture_sv_qkt_link");
        return;
    }
    sv.gemm_y.insert(
        sv.gemm_y.end(), view.gemm_y,
        view.gemm_y + m_params.d_head);
    AppendExtractTiles(
        ordinal, view.gemm_y, view.extract_output,
        m_params.d_head, view.prf_key);
    if (!m_error.empty()) return;
    if (m_extract_seen[ordinal]) {
        m_gemm_seen[ordinal] = true;
    }
}

void RCStage3EpisodeWitnessCapture::OnFfnGemm(
    const RCFfnGemmWitnessView& view)
{
    if (!m_error.empty()) return;
    if (view.round_ordinal >= m_params.rounds ||
        view.layer_ordinal >= m_params.L_lyr ||
        view.operand_a == nullptr ||
        view.operand_b == nullptr ||
        view.gemm_y == nullptr) {
        Reject("capture_ffn_gemm_arguments");
        return;
    }
    const uint32_t ordinal = FfnOrdinal(
        view.round_ordinal, view.layer_ordinal,
        view.projection);
    if (ordinal >= m_layout.layers.size() ||
        m_gemm_seen[ordinal]) {
        Reject("capture_ffn_gemm_order");
        return;
    }
    const auto& spec = m_layout.layers[ordinal];
    if (view.m != spec.m || view.k != spec.k ||
        view.n != spec.n ||
        view.operand_a->size() !=
            uint64_t{spec.m} * spec.k ||
        view.operand_b->size() !=
            uint64_t{spec.k} * spec.n ||
        view.gemm_y->size() !=
            uint64_t{spec.m} * spec.n ||
        (spec.residual_first_column < 0
             ? view.residual != nullptr
             : view.residual == nullptr ||
                   view.residual->size() !=
                       uint64_t{spec.m} * spec.n)) {
        Reject("capture_ffn_gemm_shape");
        return;
    }
    auto& layer = m_layers[ordinal];
    layer.operand_a = *view.operand_a;
    layer.operand_b = *view.operand_b;
    layer.gemm_y = *view.gemm_y;
    if (view.residual != nullptr) {
        layer.residual = *view.residual;
    }
    m_operands_seen[ordinal] = true;
    m_gemm_seen[ordinal] = true;
}

void RCStage3EpisodeWitnessCapture::OnFfnExtract(
    const RCFfnExtractWitnessView& view)
{
    if (!m_error.empty()) return;
    if (view.round_ordinal >= m_params.rounds ||
        view.layer_ordinal >= m_params.L_lyr ||
        view.input == nullptr || view.output == nullptr) {
        Reject("capture_ffn_extract_arguments");
        return;
    }
    const uint32_t ordinal = FfnOrdinal(
        view.round_ordinal, view.layer_ordinal,
        view.projection);
    if (ordinal >= m_layout.layers.size() ||
        !m_gemm_seen[ordinal] ||
        m_extract_seen[ordinal]) {
        Reject("capture_ffn_extract_order");
        return;
    }
    const auto& spec = m_layout.layers[ordinal];
    const uint64_t cells = uint64_t{spec.m} * spec.n;
    if (view.rows != spec.m ||
        view.columns != spec.n ||
        view.input->size() != cells ||
        view.output->size() != cells ||
        (spec.residual_first_column < 0
             ? view.residual != nullptr
             : view.residual == nullptr ||
                   view.residual->size() != cells)) {
        Reject("capture_ffn_extract_shape");
        return;
    }
    AppendExtractTiles(
        ordinal, view.input->data(),
        view.output->data(), cells, view.prf_key);
}

bool RCStage3EpisodeWitnessCapture::Complete(
    std::string* why) const
{
    if (!m_error.empty()) {
        return Fail(why, m_error);
    }
    if (m_layout.layers.empty() ||
        m_layers.size() != m_layout.layers.size()) {
        return Fail(why, "capture_incomplete_shape");
    }
    uint64_t total_tiles = 0;
    for (uint32_t ordinal = 0;
         ordinal < m_layout.layers.size(); ++ordinal) {
        const auto& spec = m_layout.layers[ordinal];
        const auto& layer = m_layers[ordinal];
        const uint64_t cells =
            uint64_t{spec.m} * spec.n;
        const uint64_t tiles =
            cells / kRCMxBlockLen;
        if (!m_operands_seen[ordinal] ||
            !m_gemm_seen[ordinal] ||
            !m_extract_seen[ordinal] ||
            m_extract_prfs[ordinal].IsNull() ||
            layer.operand_a.size() !=
                uint64_t{spec.m} * spec.k ||
            layer.operand_b.size() !=
                uint64_t{spec.k} * spec.n ||
            layer.gemm_y.size() != cells ||
            (spec.residual_first_column < 0
                 ? !layer.residual.empty()
                 : layer.residual.size() != cells) ||
            m_next_layer_tile[ordinal] != tiles ||
            m_layer_extract_inputs[ordinal].size() != tiles ||
            m_layer_extract_outputs[ordinal].size() != tiles ||
            m_layer_tile_begin[ordinal] != total_tiles) {
            return Fail(
                why, "capture_incomplete_layer_" +
                         std::to_string(ordinal));
        }
        total_tiles += tiles;
    }
    FlattenExtractTiles();
    if (m_extract_inputs.size() != total_tiles) {
        return Fail(why, "capture_incomplete_tiles");
    }
    return true;
}

bool RCStage3EpisodeWitnessCapture::ValidateManifest(
    const RCStage3GemmExtractManifest& manifest,
    std::string* why) const
{
    const bool same_params =
        manifest.params.rounds == m_params.rounds &&
        manifest.params.d_head == m_params.d_head &&
        manifest.params.n_q == m_params.n_q &&
        manifest.params.n_ctx == m_params.n_ctx &&
        manifest.params.L_lyr == m_params.L_lyr &&
        manifest.params.d_model == m_params.d_model &&
        manifest.params.d_ff == m_params.d_ff &&
        manifest.params.b_seq == m_params.b_seq &&
        manifest.params.T_leaf == m_params.T_leaf;
    if (!Complete(why) ||
        !ValidateRCStage3GemmExtractManifest(
            manifest, why) ||
        !same_params ||
        manifest.layers.size() != m_layers.size()) {
        return Fail(why, "capture_manifest_shape");
    }
    for (uint32_t ordinal = 0;
         ordinal < manifest.layers.size(); ++ordinal) {
        if (manifest.layers[ordinal]
                .bindings.extract_prf !=
            m_extract_prfs[ordinal]) {
            return Fail(
                why, "capture_manifest_prf_" +
                         std::to_string(ordinal));
        }
    }
    return true;
}

bool RCStage3EpisodeWitnessCapture::
ValidateExtractProductOutputs(
    const RCStage3EpisodeExtractProduct& extract,
    std::string* why) const
{
    if (!Complete(why) ||
        extract.tiles.size() != m_extract_outputs.size()) {
        return Fail(why, "capture_extract_product_shape");
    }
    for (uint64_t tile_index = 0;
         tile_index < extract.tiles.size(); ++tile_index) {
        const auto& tile = extract.tiles[tile_index];
        const auto& pin = tile.sampler_pin;
        if (tile.global_tile != tile_index ||
            pin.n_rows < kRCMxBlockLen ||
            pin.n_coeffs != pin.n_rows ||
            pin.column_roots.size() <= aq::kColOut ||
            pin.column_roots[aq::kColOut].column !=
                aq::kColOut) {
            return Fail(
                why, "capture_extract_output_pin_" +
                         std::to_string(tile_index));
        }
        std::vector<Fp3> expected(
            pin.n_rows, Fp3::Zero());
        for (uint32_t lane = 0;
             lane < kRCMxBlockLen; ++lane) {
            expected[lane] =
                S(m_extract_outputs[tile_index][lane]);
        }
        if (aq::AirCommittedValuesRoot<Fp3>(
                expected, pin.n_coeffs) !=
            pin.column_roots[aq::kColOut].root) {
            return Fail(
                why, "capture_extract_output_root_" +
                         std::to_string(tile_index));
        }
    }
    return true;
}

bool RCStage3EpisodeWitnessStorePut(
    const uint256& final_header_hash,
    std::shared_ptr<
        const RCStage3EpisodeWitnessCapture> capture,
    std::string* why)
{
    if (final_header_hash.IsNull() ||
        capture == nullptr ||
        !capture->Complete(why)) {
        return Fail(why, "witness_store_incomplete");
    }
    std::lock_guard<std::mutex> lock(
        g_episode_witness_store_mutex);
    g_episode_witness_store_header =
        final_header_hash;
    g_episode_witness_store_capture =
        std::move(capture);
    return true;
}

std::shared_ptr<const RCStage3EpisodeWitnessCapture>
RCStage3EpisodeWitnessStoreGet(
    const uint256& final_header_hash)
{
    if (final_header_hash.IsNull()) return {};
    std::lock_guard<std::mutex> lock(
        g_episode_witness_store_mutex);
    if (g_episode_witness_store_capture == nullptr ||
        g_episode_witness_store_header !=
            final_header_hash) {
        return {};
    }
    return g_episode_witness_store_capture;
}

void RCStage3EpisodeWitnessStoreErase(
    const uint256& final_header_hash)
{
    std::lock_guard<std::mutex> lock(
        g_episode_witness_store_mutex);
    if (g_episode_witness_store_header ==
            final_header_hash) {
        g_episode_witness_store_header.SetNull();
        g_episode_witness_store_capture.reset();
    }
}

void RCStage3EpisodeWitnessStoreClearForTest()
{
    std::lock_guard<std::mutex> lock(
        g_episode_witness_store_mutex);
    g_episode_witness_store_header.SetNull();
    g_episode_witness_store_capture.reset();
}

bool ProveRCStage3EpisodeProductsFromCapture(
    const RCStage3SuccinctProof& statement,
    RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeWitnessCapture& capture,
    RCStage3EpisodeExtractProduct& extract,
    RCStage3EpisodeTileStreamProduct& tile_stream,
    RCStage3EpisodeGemmProduct& gemm,
    std::string* why)
{
    extract = {};
    tile_stream = {};
    gemm = {};
    if (!capture.ValidateManifest(manifest, why) ||
        !ValidateRCStage3GemmExtractManifestBinding(
            statement, manifest, why)) {
        return Fail(why, "capture_product_binding");
    }
    if (!ProveRCStage3EpisodeExtractAndTileStreamProductsVertical(
            statement, manifest, capture.ExtractInputs(),
            extract, tile_stream, why)) {
        extract = {};
        tile_stream = {};
        return Fail(why, "capture_extract_proof");
    }
    if (!capture.ValidateExtractProductOutputs(extract, why)) {
        extract = {};
        tile_stream = {};
        return Fail(why, "capture_extract_output_mismatch");
    }
    if (!ProveRCStage3EpisodeGemmProduct(
            statement, manifest, capture.LayerWitnesses(),
            extract, tile_stream, gemm, why)) {
        extract = {};
        tile_stream = {};
        gemm = {};
        return Fail(why, "capture_gemm_proof");
    }
    return true;
}

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
        layer.gemm_y = witness.gemm_y;
        layer.residual = witness.residual;
        if (layer.operand_a.size() !=
                uint64_t{spec.m} * spec.k ||
            layer.operand_b.size() !=
                uint64_t{spec.k} * spec.n ||
            (!layer.gemm_y.empty() &&
             layer.gemm_y.size() !=
                 uint64_t{spec.m} * spec.n) ||
            (spec.residual_first_column < 0
                 ? !layer.residual.empty()
                 : layer.residual.size() !=
                       uint64_t{spec.m} * spec.n)) {
            out = {};
            return Fail(
                why, "prove_layer_shape_" +
                         std::to_string(ordinal));
        }
        for (int8_t value : layer.operand_a) {
            if (value < -48 || value > 48) {
                out = {};
                return Fail(why, "prove_operand_range");
            }
        }
        for (int8_t value : layer.operand_b) {
            if (value < -48 || value > 48) {
                out = {};
                return Fail(why, "prove_operand_range");
            }
        }
        if (layer.gemm_y.empty()) {
            // Legacy/R&D fallback.  Production miners provide the exact Y
            // emitted by the solver and therefore never enter this replay.
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
                        sum += static_cast<int64_t>(a) * b;
                    }
                    layer.gemm_y[
                        uint64_t{row} * spec.n + column] =
                        sum;
                }
            }
        }
        for (int64_t value : layer.gemm_y) {
            if (value < -static_cast<int64_t>(
                            spec.signed_max_abs) ||
                value > static_cast<int64_t>(
                            spec.signed_max_abs)) {
                out = {};
                return Fail(why, "prove_signed_bound");
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
