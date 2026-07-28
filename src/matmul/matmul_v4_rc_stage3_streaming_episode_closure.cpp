// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_streaming_episode_closure.h>

#include <hash.h>

#include <algorithm>
#include <limits>

namespace matmul::v4::rc::streaming_episode_closure {
namespace {

namespace gf = gkr_field;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:streaming_episode_closure:" +
            detail;
    }
    return false;
}

bool CheckedAdd(uint64_t a, uint64_t b, uint64_t& out)
{
    if (b > std::numeric_limits<uint64_t>::max() - a) {
        return false;
    }
    out = a + b;
    return true;
}

bool CheckedMul(uint64_t a, uint64_t b, uint64_t& out)
{
    if (a != 0 &&
        b > std::numeric_limits<uint64_t>::max() / a) {
        return false;
    }
    out = a * b;
    return true;
}

template <typename T>
std::vector<gf::Fp3> ToField(const std::vector<T>& values)
{
    std::vector<gf::Fp3> out;
    out.reserve(values.size());
    for (const T value : values) {
        out.push_back(gf::FromSigned3(
            static_cast<int64_t>(value)));
    }
    return out;
}

uint64_t SignedBound(const RCGkrLayerSpec& spec)
{
    uint64_t out{0};
    if (!CheckedMul(
            spec.k,
            static_cast<uint64_t>(kRCMxOperandAbsMax) *
                kRCMxOperandAbsMax,
            out)) {
        return 0;
    }
    if (spec.residual_first_column >= 0 &&
        !CheckedAdd(out, kRCMxOperandAbsMax, out)) {
        return 0;
    }
    return out;
}

bool IsEpisodeStatement(
    const RCStage3SuccinctProof& statement)
{
    return
        statement.statement ==
            RCStage3StatementKind::Episode ||
        statement.statement ==
            RCStage3StatementKind::Composed;
}

bool NoLateBindings(
    const RCStage3GemmExtractLayerBindings& bindings)
{
    return
        bindings.extract_prf.IsNull() &&
        bindings.operand_a_root.IsNull() &&
        bindings.operand_b_root.IsNull() &&
        bindings.gemm_y_root.IsNull() &&
        bindings.extract_input_root.IsNull() &&
        bindings.extract_output_root.IsNull() &&
        bindings.gemm_proof_root.IsNull() &&
        bindings.extract_recursive_root.IsNull() &&
        bindings.scale_schedule_root.IsNull() &&
        bindings.ctl_terminal_root.IsNull() &&
        bindings.operand_a_root_alg.IsNull() &&
        bindings.operand_b_root_alg.IsNull() &&
        bindings.gemm_y_root_alg.IsNull() &&
        bindings.extract_input_root_alg.IsNull() &&
        bindings.scale_schedule_root_alg.IsNull();
}

} // namespace

uint256 ComputeImmutableEpisodeScheduleCommitmentV1(
    const ImmutableEpisodeScheduleV1& schedule)
{
    if (schedule.version != kScheduleVersionV1 ||
        schedule.statement_commitment.IsNull() ||
        !ValidateRCEpisodeParams(schedule.params) ||
        schedule.layers.empty()) {
        return {};
    }
    HashWriter hash;
    hash << std::string{
                "BTX_RC_STAGE3_STREAMING_EPISODE_SCHEDULE_V1"}
         << schedule.version
         << schedule.statement_commitment
         << schedule.params.rounds
         << schedule.params.d_head
         << schedule.params.n_q
         << schedule.params.n_ctx
         << schedule.params.L_lyr
         << schedule.params.d_model
         << schedule.params.d_ff
         << schedule.params.b_seq
         << schedule.params.T_leaf
         << schedule.total_gemm_cells
         << schedule.total_extract_tiles
         << static_cast<uint32_t>(
                schedule.layers.size());
    for (const auto& layer : schedule.layers) {
        hash << layer.ordinal
             << static_cast<uint32_t>(layer.kind)
             << layer.round
             << layer.layer
             << layer.m
             << layer.n
             << layer.k
             << layer.a.first_column
             << layer.a.n_chunks
             << layer.a.transpose
             << layer.b.first_column
             << layer.b.n_chunks
             << layer.b.transpose
             << layer.y_first_column
             << layer.y_chunks
             << layer.out_first_column
             << layer.out_chunks
             << layer.residual_first_column
             << layer.gemm_cell_begin
             << layer.gemm_cell_count
             << layer.extract_tile_begin
             << layer.extract_tile_count
             << layer.signed_max_abs;
    }
    return hash.GetSHA256();
}

bool BuildImmutableEpisodeScheduleV1(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    ImmutableEpisodeScheduleV1& out,
    std::string* why)
{
    out = {};
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    if (!IsEpisodeStatement(statement) ||
        statement_commitment.IsNull() ||
        !ValidateRCEpisodeParams(params)) {
        return Fail(why, "schedule_statement");
    }
    const auto layout = RCGkrTraceLayout(params);
    if (layout.layers.empty() ||
        layout.layers.size() >
            kRCStage3GemmExtractMaxLayers) {
        return Fail(why, "schedule_layer_count");
    }
    out.statement_commitment =
        statement_commitment;
    out.params = params;
    out.layers.reserve(layout.layers.size());
    uint64_t gemm_cursor{0};
    uint64_t tile_cursor{0};
    for (uint32_t ordinal = 0;
         ordinal < layout.layers.size();
         ++ordinal) {
        const auto& src = layout.layers[ordinal];
        uint64_t cells{0};
        uint64_t tiles{0};
        const uint64_t signed_bound =
            SignedBound(src);
        if (src.n % kRCMxBlockLen != 0 ||
            !CheckedMul(src.m, src.n, cells) ||
            !CheckedMul(
                src.m,
                src.n / kRCMxBlockLen,
                tiles) ||
            signed_bound == 0 ||
            signed_bound >=
                (uint64_t{1} <<
                    kRCStage3SignedRangeBits)) {
            out = {};
            return Fail(
                why,
                "schedule_layer_" +
                    std::to_string(ordinal));
        }
        RCStage3GemmExtractLayerManifest layer;
        layer.ordinal = ordinal;
        layer.kind = src.kind;
        layer.round = src.round;
        layer.layer = src.layer;
        layer.m = src.m;
        layer.n = src.n;
        layer.k = src.k;
        layer.a = src.a;
        layer.b = src.b;
        layer.y_first_column = src.y_first_column;
        layer.y_chunks = src.y_chunks;
        layer.out_first_column =
            src.out_first_column;
        layer.out_chunks = src.out_chunks;
        layer.residual_first_column =
            src.residual_first_column;
        layer.gemm_cell_begin = gemm_cursor;
        layer.gemm_cell_count = cells;
        layer.extract_tile_begin = tile_cursor;
        layer.extract_tile_count = tiles;
        layer.signed_max_abs = signed_bound;
        out.layers.push_back(std::move(layer));
        if (!CheckedAdd(
                gemm_cursor, cells, gemm_cursor) ||
            !CheckedAdd(
                tile_cursor, tiles, tile_cursor)) {
            out = {};
            return Fail(why, "schedule_total");
        }
    }
    out.total_gemm_cells = gemm_cursor;
    out.total_extract_tiles = tile_cursor;
    out.schedule_commitment =
        ComputeImmutableEpisodeScheduleCommitmentV1(
            out);
    if (out.schedule_commitment.IsNull() ||
        !ValidateImmutableEpisodeScheduleV1(
            out, why)) {
        out = {};
        return Fail(why, "schedule_commitment");
    }
    return true;
}

bool ValidateImmutableEpisodeScheduleV1(
    const ImmutableEpisodeScheduleV1& schedule,
    std::string* why)
{
    if (schedule.version != kScheduleVersionV1 ||
        schedule.statement_commitment.IsNull() ||
        !ValidateRCEpisodeParams(schedule.params) ||
        schedule.layers.empty()) {
        return Fail(why, "validate_schedule_header");
    }
    const auto layout =
        RCGkrTraceLayout(schedule.params);
    if (layout.layers.size() !=
        schedule.layers.size()) {
        return Fail(why, "validate_schedule_count");
    }
    uint64_t gemm_cursor{0};
    uint64_t tile_cursor{0};
    for (uint32_t ordinal = 0;
         ordinal < layout.layers.size();
         ++ordinal) {
        const auto& expected =
            layout.layers[ordinal];
        const auto& actual =
            schedule.layers[ordinal];
        uint64_t cells{0};
        uint64_t tiles{0};
        const uint64_t signed_bound =
            SignedBound(expected);
        if (expected.n % kRCMxBlockLen != 0 ||
            !CheckedMul(
                expected.m, expected.n, cells) ||
            !CheckedMul(
                expected.m,
                expected.n / kRCMxBlockLen,
                tiles) ||
            actual.ordinal != ordinal ||
            actual.kind != expected.kind ||
            actual.round != expected.round ||
            actual.layer != expected.layer ||
            actual.m != expected.m ||
            actual.n != expected.n ||
            actual.k != expected.k ||
            actual.a.first_column !=
                expected.a.first_column ||
            actual.a.n_chunks !=
                expected.a.n_chunks ||
            actual.a.transpose !=
                expected.a.transpose ||
            actual.b.first_column !=
                expected.b.first_column ||
            actual.b.n_chunks !=
                expected.b.n_chunks ||
            actual.b.transpose !=
                expected.b.transpose ||
            actual.y_first_column !=
                expected.y_first_column ||
            actual.y_chunks !=
                expected.y_chunks ||
            actual.out_first_column !=
                expected.out_first_column ||
            actual.out_chunks !=
                expected.out_chunks ||
            actual.residual_first_column !=
                expected.residual_first_column ||
            actual.gemm_cell_begin !=
                gemm_cursor ||
            actual.gemm_cell_count != cells ||
            actual.extract_tile_begin !=
                tile_cursor ||
            actual.extract_tile_count != tiles ||
            actual.signed_max_abs !=
                signed_bound ||
            !NoLateBindings(actual.bindings)) {
            return Fail(
                why,
                "validate_schedule_layer_" +
                    std::to_string(ordinal));
        }
        if (!CheckedAdd(
                gemm_cursor, cells, gemm_cursor) ||
            !CheckedAdd(
                tile_cursor, tiles, tile_cursor)) {
            return Fail(
                why, "validate_schedule_overflow");
        }
    }
    if (schedule.total_gemm_cells !=
            gemm_cursor ||
        schedule.total_extract_tiles !=
            tile_cursor ||
        schedule.schedule_commitment !=
            ComputeImmutableEpisodeScheduleCommitmentV1(
                schedule)) {
        return Fail(why, "validate_schedule_totals");
    }
    return true;
}

uint256 ComputeStreamedLayerClosureCommitmentV1(
    const StreamedLayerClosureV1& layer)
{
    if (layer.version != kLayerVersionV1 ||
        layer.shape.shape_commitment.IsNull() ||
        layer.consumer_bundle
            .bundle_commitment.IsNull() ||
        layer.closure.closure_commitment.IsNull() ||
        layer.extract_prf.IsNull() ||
        layer.gemm_y_vector_root_alg.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << std::string{
                "BTX_RC_STAGE3_STREAMED_LAYER_CLOSURE_V1"}
         << layer.version
         << layer.layer_ordinal
         << layer.shape.shape_commitment
         << layer.consumer_leaf_begin
         << layer.consumer_bundle.bundle_commitment
         << layer.closure.closure_commitment
         << layer.extract_prf
         << layer.gemm_y_vector_root_alg
         << layer.extract_role_proof_consumed
         << layer.production_authority;
    return hash.GetSHA256();
}

uint256 ComputeStreamingEpisodeClosureReceiptCommitmentV1(
    const StreamingEpisodeClosureReceiptV1& receipt)
{
    if (receipt.version != kReceiptVersionV1 ||
        receipt.schedule.schedule_commitment.IsNull() ||
        receipt.layers.empty() ||
        receipt.round_roots.empty() ||
        receipt.episode_digest.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << std::string{
                "BTX_RC_STAGE3_STREAMING_EPISODE_CLOSURE_RECEIPT_V1"}
         << receipt.version
         << receipt.schedule.schedule_commitment
         << static_cast<uint32_t>(
                receipt.layers.size());
    for (const auto& layer : receipt.layers) {
        if (layer.retained_commitment.IsNull()) {
            return {};
        }
        hash << layer.retained_commitment;
    }
    hash << static_cast<uint32_t>(
                receipt.round_roots.size());
    for (const auto& root : receipt.round_roots) {
        if (root.IsNull()) return {};
        hash << root;
    }
    hash << receipt.episode_digest
         << receipt.every_gemm_child_verified
         << receipt.extract_role_children_consumed
         << receipt.normalized_parent_consumed
         << receipt.production_authority;
    return hash.GetSHA256();
}

bool VerifyStreamedLayerClosureV1(
    const ImmutableEpisodeScheduleV1& schedule,
    uint32_t expected_consumer_leaf_begin,
    const StreamedLayerClosureV1& layer,
    std::string* why)
{
    if (!ValidateImmutableEpisodeScheduleV1(
            schedule, why) ||
        layer.version != kLayerVersionV1 ||
        layer.layer_ordinal >=
            schedule.layers.size() ||
        layer.layer_ordinal !=
            layer.shape.layer_ordinal ||
        layer.consumer_leaf_begin !=
            expected_consumer_leaf_begin ||
        layer.shape.statement_commitment !=
            schedule.statement_commitment ||
        layer.shape.gemm_manifest_commitment !=
            schedule.schedule_commitment ||
        layer.extract_prf.IsNull() ||
        layer.gemm_y_vector_root_alg !=
            layer.closure.output_y_vector_root_alg ||
        layer.extract_role_proof_consumed ||
        layer.production_authority ||
        layer.retained_commitment !=
            ComputeStreamedLayerClosureCommitmentV1(
                layer)) {
        return Fail(why, "verify_layer_statement");
    }
    source::LayerShapeV1 expected_shape;
    if (!source::BuildLayerShapeV1(
            schedule.statement_commitment,
            schedule.schedule_commitment,
            schedule.layers[layer.layer_ordinal],
            expected_shape, why) ||
        expected_shape != layer.shape) {
        return Fail(why, "verify_layer_shape");
    }
    const auto audit = source::VerifyLayerBundleV1(
        expected_shape, layer.consumer_bundle);
    if (!audit.accepted) {
        return Fail(
            why, "verify_layer_bundle:" +
                     audit.note);
    }
    if (!aggregate::VerifyLayerClosureV1(
            expected_shape,
            layer.consumer_bundle,
            expected_consumer_leaf_begin,
            layer.closure
                .operand_a_vector_root_alg,
            layer.closure
                .operand_b_vector_root_alg,
            layer.closure
                .output_y_vector_root_alg,
            layer.closure, why)) {
        return false;
    }
    return true;
}

StreamingEpisodeClosureSink::
StreamingEpisodeClosureSink(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params)
{
    std::string why;
    if (!BuildImmutableEpisodeScheduleV1(
            statement, params,
            m_schedule, &why)) {
        m_error = why;
        return;
    }
    m_layout = RCGkrTraceLayout(params);
    m_pending.resize(m_layout.layers.size());
    for (uint32_t ordinal = 0;
         ordinal < m_pending.size();
         ++ordinal) {
        m_pending[ordinal].layer.layer_ordinal =
            ordinal;
    }
    m_finalized.reserve(m_layout.layers.size());
    m_round_roots.reserve(params.rounds);
    m_round_merkle =
        std::make_unique<RoundMerkleStream>(
            params.T_leaf);
}

void StreamingEpisodeClosureSink::Reject(
    const std::string& detail)
{
    if (m_error.empty()) m_error = detail;
}

uint32_t StreamingEpisodeClosureSink::RoundBase(
    uint32_t round) const
{
    return round *
        (2 + 2 * m_schedule.params.L_lyr);
}

uint32_t StreamingEpisodeClosureSink::FfnOrdinal(
    uint32_t round,
    uint32_t layer,
    RCFfnProjection projection) const
{
    return RoundBase(round) + 2 + 2 * layer +
        (projection == RCFfnProjection::Down
             ? 1U
             : 0U);
}

uint64_t
StreamingEpisodeClosureSink::RetainedNativeBytes() const
{
    uint64_t total{0};
    for (const auto& pending : m_pending) {
        total += pending.layer.operand_a.size();
        total += pending.layer.operand_b.size();
        total += pending.layer.residual.size();
        total +=
            uint64_t{pending.layer.gemm_y.size()} *
            sizeof(int64_t);
        total +=
            uint64_t{pending.extract.tiles.size()} *
            (kRCMxBlockLen * sizeof(int64_t));
        total += pending.extract_output.size();
    }
    return total;
}

void StreamingEpisodeClosureSink::
UpdatePeakRetainedBytes()
{
    m_peak_retained_native_bytes =
        std::max(
            m_peak_retained_native_bytes,
            RetainedNativeBytes());
}

bool StreamingEpisodeClosureSink::AppendExtract(
    uint32_t ordinal,
    const int64_t* input,
    const int8_t* output,
    uint64_t cells,
    const uint256& prf)
{
    if (ordinal >= m_pending.size() ||
        input == nullptr || output == nullptr ||
        prf.IsNull() ||
        cells == 0 ||
        cells % kRCMxBlockLen != 0) {
        Reject("append_extract_arguments");
        return false;
    }
    auto& pending = m_pending[ordinal];
    if (pending.extract_prf.IsNull()) {
        pending.extract_prf = prf;
    } else if (pending.extract_prf != prf) {
        Reject("append_extract_prf_change");
        return false;
    }
    const uint64_t incoming =
        cells / kRCMxBlockLen;
    const uint64_t expected =
        m_schedule.layers[ordinal]
            .extract_tile_count;
    if (pending.extract_seen ||
        incoming > expected - pending.next_tile) {
        Reject("append_extract_coverage");
        return false;
    }
    pending.extract.expected_tiles = expected;
    pending.extract.tiles.reserve(
        static_cast<size_t>(expected));
    for (uint64_t tile = 0; tile < incoming;
         ++tile) {
        RCStage3EpisodeExtractTileProduct item;
        item.global_tile = pending.next_tile;
        item.layer_ordinal = ordinal;
        item.layer_tile_index =
            pending.next_tile;
        std::copy_n(
            input + tile * kRCMxBlockLen,
            kRCMxBlockLen,
            item.input.begin());
        pending.extract_output.insert(
            pending.extract_output.end(),
            output + tile * kRCMxBlockLen,
            output +
                (tile + 1) * kRCMxBlockLen);
        pending.extract.tiles.push_back(
            std::move(item));
        ++pending.next_tile;
    }
    pending.extract_seen =
        pending.next_tile == expected;
    UpdatePeakRetainedBytes();
    return true;
}

bool StreamingEpisodeClosureSink::FinalizeLayer(
    uint32_t ordinal)
{
    if (!m_error.empty() ||
        ordinal != m_next_finalized_layer ||
        ordinal >= m_pending.size()) {
        Reject("finalize_order");
        return false;
    }
    auto& pending = m_pending[ordinal];
    const auto& scheduled =
        m_schedule.layers[ordinal];
    if (!pending.operands_seen ||
        !pending.gemm_seen ||
        !pending.extract_seen ||
        pending.layer.operand_a.size() !=
            uint64_t{scheduled.m} * scheduled.k ||
        pending.layer.operand_b.size() !=
            uint64_t{scheduled.k} * scheduled.n ||
        pending.layer.gemm_y.size() !=
            scheduled.gemm_cell_count ||
        pending.extract.tiles.size() !=
            scheduled.extract_tile_count) {
        Reject("finalize_incomplete");
        return false;
    }

    StreamedLayerClosureV1 retained;
    retained.layer_ordinal = ordinal;
    retained.consumer_leaf_begin =
        m_next_consumer_leaf;
    std::string why;
    if (!source::BuildLayerShapeV1(
            m_schedule.statement_commitment,
            m_schedule.schedule_commitment,
            scheduled, retained.shape, &why) ||
        !source::ProveLayerBundleV1(
            retained.shape, pending.layer,
            pending.extract, 0,
            retained.consumer_bundle, &why)) {
        Reject("finalize_bundle:" + why);
        return false;
    }
    auto local_spec = scheduled;
    local_spec.extract_tile_begin = 0;
    local_spec.bindings.extract_prf =
        pending.extract_prf;
    if (!aggregate::ProveLayerClosureV1(
            retained.shape, local_spec,
            pending.layer, pending.extract, 0,
            retained.consumer_bundle,
            retained.consumer_leaf_begin,
            retained.closure, &why)) {
        Reject("finalize_closure:" + why);
        return false;
    }

    const std::vector<int8_t>& extract_output =
        pending.extract_output;
    retained.gemm_y_vector_root_alg =
        RCStage3VectorRootAlgCommitment(
            ToField(pending.layer.gemm_y));
    retained.extract_prf =
        pending.extract_prf;
    retained.retained_commitment =
        ComputeStreamedLayerClosureCommitmentV1(
            retained);
    if (retained.retained_commitment.IsNull() ||
        !VerifyStreamedLayerClosureV1(
            m_schedule, m_next_consumer_leaf,
            retained, &why)) {
        Reject("finalize_verify:" + why);
        return false;
    }

    if (RCStage3EpisodeLayerIsStreamed(
            scheduled.kind)) {
        if (m_round_merkle == nullptr ||
            extract_output.empty()) {
            Reject("finalize_round_stream");
            return false;
        }
        m_round_merkle->Absorb(extract_output);
    }

    if (retained.consumer_bundle.leaves.size() >
            std::numeric_limits<uint32_t>::max() -
                m_next_consumer_leaf) {
        Reject("finalize_leaf_overflow");
        return false;
    }
    m_next_consumer_leaf +=
        static_cast<uint32_t>(
            retained.consumer_bundle
                .leaves.size());
    m_finalized.push_back(
        std::move(retained));
    pending = {};
    pending.layer.layer_ordinal = ordinal;
    ++m_next_finalized_layer;
    return true;
}

void StreamingEpisodeClosureSink::OnPhase1Operands(
    const RCPhase1OperandsWitnessView& view)
{
    if (!m_error.empty()) return;
    const auto& params = m_schedule.params;
    const uint32_t qkt = RoundBase(
        view.round_ordinal);
    const uint32_t sv = qkt + 1;
    if (view.round_ordinal >= params.rounds ||
        qkt != m_next_finalized_layer ||
        sv >= m_pending.size() ||
        view.n_q != params.n_q ||
        view.n_ctx != params.n_ctx ||
        view.d_head != params.d_head ||
        view.q == nullptr || view.k == nullptr ||
        view.v == nullptr ||
        m_pending[qkt].operands_seen ||
        m_pending[sv].operands_seen ||
        view.q->size() !=
            uint64_t{params.n_q} * params.d_head ||
        view.k->size() !=
            uint64_t{params.n_ctx} * params.d_head ||
        view.v->size() !=
            uint64_t{params.n_ctx} * params.d_head) {
        Reject("phase1_operands_order");
        return;
    }
    m_pending[qkt].layer.operand_a = *view.q;
    m_pending[qkt].layer.operand_b = *view.k;
    m_pending[qkt].operands_seen = true;
    m_pending[sv].layer.operand_b = *view.v;
    m_pending[sv].layer.operand_a.reserve(
        uint64_t{params.n_q} * params.n_ctx);
    m_pending[sv].operands_seen = true;
    UpdatePeakRetainedBytes();
}

void StreamingEpisodeClosureSink::OnPhase1QKtTile(
    const RCPhase1QKtTileWitnessView& view)
{
    if (!m_error.empty()) return;
    const auto& params = m_schedule.params;
    const uint32_t ordinal =
        RoundBase(view.round_ordinal);
    const uint64_t tile =
        uint64_t{view.query_row} *
            (params.n_ctx / kRCMxBlockLen) +
        view.context_begin / kRCMxBlockLen;
    if (view.round_ordinal >= params.rounds ||
        ordinal != m_next_finalized_layer ||
        view.query_row >= params.n_q ||
        view.tile_len != kRCMxBlockLen ||
        view.contraction_size != params.d_head ||
        view.context_begin >= params.n_ctx ||
        view.context_begin % kRCMxBlockLen != 0 ||
        view.context_begin + kRCMxBlockLen >
            params.n_ctx ||
        view.operand_a == nullptr ||
        view.operand_b == nullptr ||
        view.gemm_y == nullptr ||
        view.extract_output == nullptr ||
        !m_pending[ordinal].operands_seen ||
        m_pending[ordinal].next_tile != tile) {
        Reject("qkt_order");
        return;
    }
    auto& qkt = m_pending[ordinal];
    auto& sv = m_pending[ordinal + 1];
    qkt.layer.gemm_y.insert(
        qkt.layer.gemm_y.end(),
        view.gemm_y,
        view.gemm_y + kRCMxBlockLen);
    sv.layer.operand_a.insert(
        sv.layer.operand_a.end(),
        view.extract_output,
        view.extract_output + kRCMxBlockLen);
    if (!AppendExtract(
            ordinal, view.gemm_y,
            view.extract_output,
            kRCMxBlockLen, view.prf_key)) {
        return;
    }
    if (qkt.extract_seen) {
        qkt.gemm_seen = true;
        (void)FinalizeLayer(ordinal);
    }
}

void StreamingEpisodeClosureSink::OnPhase1SVRow(
    const RCPhase1SVRowWitnessView& view)
{
    if (!m_error.empty()) return;
    const auto& params = m_schedule.params;
    const uint32_t ordinal =
        RoundBase(view.round_ordinal) + 1;
    const uint64_t expected_tile =
        uint64_t{view.query_row} *
        (params.d_head / kRCMxBlockLen);
    const uint64_t qkt_through_row =
        uint64_t{view.query_row + 1} *
        (params.n_ctx / kRCMxBlockLen);
    if (view.round_ordinal >= params.rounds ||
        (m_next_finalized_layer != ordinal &&
         m_next_finalized_layer + 1 != ordinal) ||
        view.query_row >= params.n_q ||
        view.n_ctx != params.n_ctx ||
        view.d_head != params.d_head ||
        view.operand_a == nullptr ||
        view.operand_b == nullptr ||
        view.gemm_y == nullptr ||
        view.extract_output == nullptr ||
        !m_pending[ordinal].operands_seen ||
        m_pending[ordinal - 1].next_tile <
            qkt_through_row ||
        m_pending[ordinal].next_tile !=
            expected_tile) {
        Reject("sv_order");
        return;
    }
    auto& sv = m_pending[ordinal];
    const uint64_t row_begin =
        uint64_t{view.query_row} *
        params.n_ctx;
    if (sv.layer.operand_a.size() <
            row_begin + params.n_ctx ||
        !std::equal(
            sv.layer.operand_a.begin() +
                row_begin,
            sv.layer.operand_a.begin() +
                row_begin + params.n_ctx,
            view.operand_a)) {
        Reject("sv_qkt_link");
        return;
    }
    sv.layer.gemm_y.insert(
        sv.layer.gemm_y.end(),
        view.gemm_y,
        view.gemm_y + params.d_head);
    if (!AppendExtract(
            ordinal, view.gemm_y,
            view.extract_output,
            params.d_head, view.prf_key)) {
        return;
    }
    if (sv.extract_seen) {
        sv.gemm_seen = true;
        (void)FinalizeLayer(ordinal);
    }
}

void StreamingEpisodeClosureSink::OnFfnGemm(
    const RCFfnGemmWitnessView& view)
{
    if (!m_error.empty()) return;
    const auto& params = m_schedule.params;
    const uint32_t ordinal = FfnOrdinal(
        view.round_ordinal,
        view.layer_ordinal,
        view.projection);
    if (view.round_ordinal >= params.rounds ||
        view.layer_ordinal >= params.L_lyr ||
        ordinal != m_next_finalized_layer ||
        ordinal >= m_pending.size() ||
        view.operand_a == nullptr ||
        view.operand_b == nullptr ||
        view.gemm_y == nullptr) {
        Reject("ffn_gemm_order");
        return;
    }
    const auto& spec = m_schedule.layers[ordinal];
    auto& pending = m_pending[ordinal];
    if (pending.gemm_seen ||
        view.m != spec.m ||
        view.k != spec.k ||
        view.n != spec.n ||
        view.operand_a->size() !=
            uint64_t{spec.m} * spec.k ||
        view.operand_b->size() !=
            uint64_t{spec.k} * spec.n ||
        view.gemm_y->size() !=
            spec.gemm_cell_count ||
        (spec.residual_first_column < 0
             ? view.residual != nullptr
             : view.residual == nullptr ||
                   view.residual->size() !=
                       spec.gemm_cell_count)) {
        Reject("ffn_gemm_shape");
        return;
    }
    pending.layer.operand_a = *view.operand_a;
    pending.layer.operand_b = *view.operand_b;
    pending.layer.gemm_y = *view.gemm_y;
    if (view.residual != nullptr) {
        pending.layer.residual =
            *view.residual;
    }
    pending.operands_seen = true;
    pending.gemm_seen = true;
    UpdatePeakRetainedBytes();
}

void StreamingEpisodeClosureSink::OnFfnExtract(
    const RCFfnExtractWitnessView& view)
{
    if (!m_error.empty()) return;
    const auto& params = m_schedule.params;
    const uint32_t ordinal = FfnOrdinal(
        view.round_ordinal,
        view.layer_ordinal,
        view.projection);
    if (view.round_ordinal >= params.rounds ||
        view.layer_ordinal >= params.L_lyr ||
        ordinal != m_next_finalized_layer ||
        ordinal >= m_pending.size() ||
        !m_pending[ordinal].gemm_seen ||
        view.input == nullptr ||
        view.output == nullptr) {
        Reject("ffn_extract_order");
        return;
    }
    const auto& spec = m_schedule.layers[ordinal];
    if (view.rows != spec.m ||
        view.columns != spec.n ||
        view.input->size() !=
            spec.gemm_cell_count ||
        view.output->size() !=
            spec.gemm_cell_count ||
        (spec.residual_first_column < 0
             ? view.residual != nullptr
             : view.residual == nullptr ||
                   view.residual->size() !=
                       spec.gemm_cell_count) ||
        !AppendExtract(
            ordinal, view.input->data(),
            view.output->data(),
            spec.gemm_cell_count,
            view.prf_key)) {
        if (m_error.empty()) {
            Reject("ffn_extract_shape");
        }
        return;
    }
    (void)FinalizeLayer(ordinal);
}

void StreamingEpisodeClosureSink::OnRoundRoot(
    uint32_t round_ordinal,
    const uint256& round_root)
{
    if (!m_error.empty()) return;
    const uint32_t expected_layer =
        RoundBase(round_ordinal) +
        2 + 2 * m_schedule.params.L_lyr;
    if (round_ordinal >=
            m_schedule.params.rounds ||
        round_ordinal != m_round_roots.size() ||
        m_next_finalized_layer != expected_layer ||
        round_root.IsNull() ||
        m_round_merkle == nullptr ||
        m_round_merkle->FinalizeRoot() !=
            round_root) {
        Reject("round_root_order_or_value");
        return;
    }
    m_round_roots.push_back(round_root);
    if (m_round_roots.size() <
        m_schedule.params.rounds) {
        m_round_merkle =
            std::make_unique<RoundMerkleStream>(
                m_schedule.params.T_leaf);
    } else {
        m_round_merkle.reset();
    }
}

void StreamingEpisodeClosureSink::OnEpisodeDigest(
    const uint256& episode_digest)
{
    if (!m_error.empty()) return;
    if (m_episode_digest_seen ||
        episode_digest.IsNull() ||
        m_round_roots.size() !=
            m_schedule.params.rounds ||
        ComputeRCEpisodeDigestFromRoundRoots(
            m_round_roots) != episode_digest) {
        Reject("episode_digest_order_or_value");
        return;
    }
    m_episode_digest = episode_digest;
    m_episode_digest_seen = true;
}

bool VerifyStreamingEpisodeClosureV1(
    const ImmutableEpisodeScheduleV1& schedule,
    const std::vector<StreamedLayerClosureV1>& layers,
    const std::vector<uint256>& round_roots,
    const uint256& episode_digest,
    std::string* why)
{
    if (!ValidateImmutableEpisodeScheduleV1(
            schedule, why) ||
        layers.size() != schedule.layers.size() ||
        round_roots.size() !=
            schedule.params.rounds ||
        episode_digest.IsNull() ||
        ComputeRCEpisodeDigestFromRoundRoots(
            round_roots) != episode_digest) {
        return Fail(why, "verify_episode_statement");
    }
    uint32_t leaf_cursor{0};
    for (uint32_t ordinal = 0;
         ordinal < layers.size();
         ++ordinal) {
        if (layers[ordinal].layer_ordinal !=
                ordinal ||
            !VerifyStreamedLayerClosureV1(
                schedule, leaf_cursor,
                layers[ordinal], why)) {
            return false;
        }
        const size_t leaf_count =
            layers[ordinal]
                .consumer_bundle.leaves.size();
        if (leaf_count >
            std::numeric_limits<uint32_t>::max() -
                leaf_cursor) {
            return Fail(
                why, "verify_episode_leaf_overflow");
        }
        leaf_cursor +=
            static_cast<uint32_t>(leaf_count);
    }
    return true;
}

bool StreamingEpisodeClosureSink::Complete(
    std::string* why) const
{
    if (!m_error.empty()) {
        return Fail(why, m_error);
    }
    if (!m_episode_digest_seen ||
        m_next_finalized_layer !=
            m_schedule.layers.size() ||
        m_finalized.size() !=
            m_schedule.layers.size() ||
        RetainedNativeBytes() != 0) {
        return Fail(why, "incomplete");
    }
    return VerifyStreamingEpisodeClosureV1(
        m_schedule, m_finalized,
        m_round_roots, m_episode_digest, why);
}

bool StreamingEpisodeClosureSink::BuildReceipt(
    StreamingEpisodeClosureReceiptV1& out,
    std::string* why) const
{
    out = {};
    if (!Complete(why)) return false;
    out.schedule = m_schedule;
    out.layers = m_finalized;
    out.round_roots = m_round_roots;
    out.episode_digest = m_episode_digest;
    out.every_gemm_child_verified = true;
    out.extract_role_children_consumed = false;
    out.normalized_parent_consumed = false;
    out.production_authority = false;
    out.receipt_commitment =
        ComputeStreamingEpisodeClosureReceiptCommitmentV1(
            out);
    if (out.receipt_commitment.IsNull() ||
        !VerifyStreamingEpisodeClosureReceiptV1(
            out, why)) {
        out = {};
        return false;
    }
    return true;
}

bool VerifyStreamingEpisodeClosureReceiptV1(
    const StreamingEpisodeClosureReceiptV1& receipt,
    std::string* why)
{
    if (receipt.version != kReceiptVersionV1 ||
        !receipt.every_gemm_child_verified ||
        receipt.extract_role_children_consumed ||
        receipt.normalized_parent_consumed ||
        receipt.production_authority ||
        receipt.receipt_commitment !=
            ComputeStreamingEpisodeClosureReceiptCommitmentV1(
                receipt)) {
        return Fail(why, "verify_receipt_statement");
    }
    return VerifyStreamingEpisodeClosureV1(
        receipt.schedule, receipt.layers,
        receipt.round_roots,
        receipt.episode_digest, why);
}

} // namespace matmul::v4::rc::streaming_episode_closure
