// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_gemm_extract.h>

#include <crypto/sha256.h>
#include <matmul/matmul_v4_lt.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
using gf::Fp3;

constexpr size_t MANIFEST_HEADER_BYTES =
    4 + 2 + 2 + 32 + 9 * 4 + 2 * 8 + 4;
constexpr size_t MANIFEST_LAYER_BYTES =
    4 + 4 + 5 * 4 + (2 * (4 + 4 + 4)) + 5 * 4 +
    5 * 8 + 15 * 32; // v3: 10 SHA transport + 5 Poseidon VectorRootAlg authority roots
bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) *why = "stage3:gemm_extract:" + message;
    return false;
}

template <typename T>
std::optional<T> FailOptional(std::string* why, const std::string& message)
{
    Fail(why, message);
    return std::nullopt;
}

bool CheckedAdd(uint64_t a, uint64_t b, uint64_t& out)
{
    if (b > std::numeric_limits<uint64_t>::max() - a) return false;
    out = a + b;
    return true;
}

bool CheckedMul(uint64_t a, uint64_t b, uint64_t& out)
{
    if (a != 0 && b > std::numeric_limits<uint64_t>::max() / a) return false;
    out = a * b;
    return true;
}

bool SignedAccumulatorBound(const RCGkrLayerSpec& layer, uint64_t& out)
{
    if (!CheckedMul(layer.k,
                    static_cast<uint64_t>(kRCMxOperandAbsMax) *
                        kRCMxOperandAbsMax,
                    out)) {
        return false;
    }
    if (layer.residual_first_column >= 0) {
        return CheckedAdd(out, kRCMxOperandAbsMax, out);
    }
    return true;
}

bool ManifestParamsSafe(const RCEpisodeParams& p)
{
    uint64_t per_round{0};
    if (!CheckedMul(p.L_lyr, 2, per_round) ||
        !CheckedAdd(per_round, 2, per_round)) {
        return false;
    }
    uint64_t layer_count{0};
    if (!CheckedMul(p.rounds, per_round, layer_count) ||
        layer_count == 0 ||
        layer_count > kRCStage3GemmExtractMaxLayers) {
        return false;
    }
    // Reject before RCGkrTraceLayout allocates.  Every distinct tensor used by
    // Λ is one of these shapes.  The cap is deliberately well above profile
    // 2 (its largest tensor uses six κ chunks) while bounding adversarial
    // column-vector construction.
    constexpr uint64_t MAX_TENSOR_CELLS =
        uint64_t{64} * kRCGkrColumnMaxCoeffs;
    const std::array<std::pair<uint32_t, uint32_t>, 7> shapes{{
        {p.n_q, p.d_head},
        {p.n_ctx, p.d_head},
        {p.n_q, p.n_ctx},
        {p.b_seq, p.d_model},
        {p.d_model, p.d_ff},
        {p.b_seq, p.d_ff},
        {p.d_ff, p.d_model},
    }};
    for (const auto [rows, cols] : shapes) {
        uint64_t cells{0};
        if (!CheckedMul(rows, cols, cells) ||
            cells == 0 || cells > MAX_TENSOR_CELLS) {
            return false;
        }
    }
    return true;
}

uint32_t NextPowerOfTwo(uint64_t value)
{
    if (value < 2) return 2;
    if (value > (uint64_t{1} << 31)) return 0;
    uint64_t out = 1;
    while (out < value) out <<= 1;
    return static_cast<uint32_t>(out);
}

bool SameRef(const RCGkrOperandRef& a, const RCGkrOperandRef& b)
{
    return a.first_column == b.first_column &&
           a.n_chunks == b.n_chunks &&
           a.transpose == b.transpose;
}

bool AllBindingsNonNull(const RCStage3GemmExtractLayerBindings& b)
{
    return !b.extract_prf.IsNull() &&
           !b.operand_a_root.IsNull() &&
           !b.operand_b_root.IsNull() &&
           !b.gemm_y_root.IsNull() &&
           !b.extract_input_root.IsNull() &&
           !b.extract_output_root.IsNull() &&
           !b.gemm_proof_root.IsNull() &&
           !b.extract_recursive_root.IsNull() &&
           !b.scale_schedule_root.IsNull() &&
           !b.ctl_terminal_root.IsNull();
}

class Writer {
public:
    void U8(uint8_t value) { m_bytes.push_back(value); }
    void U16(uint16_t value)
    {
        for (unsigned i = 0; i < 2; ++i) U8(value >> (8 * i));
    }
    void U32(uint32_t value)
    {
        for (unsigned i = 0; i < 4; ++i) U8(value >> (8 * i));
    }
    void U64(uint64_t value)
    {
        for (unsigned i = 0; i < 8; ++i) U8(value >> (8 * i));
    }
    void Uint256(const uint256& value)
    {
        m_bytes.insert(m_bytes.end(), value.data(), value.data() + value.size());
    }
    std::vector<unsigned char> Take() { return std::move(m_bytes); }

private:
    std::vector<unsigned char> m_bytes;
};

class Reader {
public:
    explicit Reader(const std::vector<unsigned char>& bytes)
        : m_pos(bytes.data()), m_end(bytes.data() + bytes.size())
    {
    }

    bool U8(uint8_t& value)
    {
        if (Remaining() < 1) return false;
        value = *m_pos++;
        return true;
    }
    bool U16(uint16_t& value)
    {
        if (Remaining() < 2) return false;
        value = static_cast<uint16_t>(m_pos[0]) |
                (static_cast<uint16_t>(m_pos[1]) << 8);
        m_pos += 2;
        return true;
    }
    bool U32(uint32_t& value)
    {
        if (Remaining() < 4) return false;
        value = 0;
        for (unsigned i = 0; i < 4; ++i) {
            value |= static_cast<uint32_t>(m_pos[i]) << (8 * i);
        }
        m_pos += 4;
        return true;
    }
    bool U64(uint64_t& value)
    {
        if (Remaining() < 8) return false;
        value = 0;
        for (unsigned i = 0; i < 8; ++i) {
            value |= static_cast<uint64_t>(m_pos[i]) << (8 * i);
        }
        m_pos += 8;
        return true;
    }
    bool Uint256(uint256& value)
    {
        if (Remaining() < value.size()) return false;
        std::copy_n(m_pos, value.size(), value.data());
        m_pos += value.size();
        return true;
    }
    size_t Remaining() const
    {
        return static_cast<size_t>(m_end - m_pos);
    }

private:
    const unsigned char* m_pos;
    const unsigned char* m_end;
};

uint256 Sha256d(const std::vector<unsigned char>& bytes)
{
    unsigned char first[CSHA256::OUTPUT_SIZE];
    uint256 out;
    CSHA256().Write(bytes.data(), bytes.size()).Finalize(first);
    CSHA256().Write(first, sizeof(first)).Finalize(out.data());
    return out;
}

uint256 TaggedHash(const char* domain,
                   const std::vector<unsigned char>& payload)
{
    std::vector<unsigned char> bytes;
    bytes.insert(bytes.end(), domain, domain + std::strlen(domain));
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return Sha256d(bytes);
}

void WriteParams(Writer& w, const RCEpisodeParams& p)
{
    w.U32(p.rounds);
    w.U32(p.d_head);
    w.U32(p.n_q);
    w.U32(p.n_ctx);
    w.U32(p.L_lyr);
    w.U32(p.d_model);
    w.U32(p.d_ff);
    w.U32(p.b_seq);
    w.U32(p.T_leaf);
}

bool ReadParams(Reader& r, RCEpisodeParams& p)
{
    return r.U32(p.rounds) && r.U32(p.d_head) &&
           r.U32(p.n_q) && r.U32(p.n_ctx) &&
           r.U32(p.L_lyr) && r.U32(p.d_model) &&
           r.U32(p.d_ff) && r.U32(p.b_seq) &&
           r.U32(p.T_leaf);
}

void WriteRef(Writer& w, const RCGkrOperandRef& ref)
{
    w.U32(ref.first_column);
    w.U32(ref.n_chunks);
    w.U8(ref.transpose ? 1 : 0);
    w.U8(0);
    w.U8(0);
    w.U8(0);
}

bool ReadRef(Reader& r, RCGkrOperandRef& ref)
{
    uint8_t transposed{0};
    uint8_t reserved[3]{};
    if (!r.U32(ref.first_column) || !r.U32(ref.n_chunks) ||
        !r.U8(transposed) || !r.U8(reserved[0]) ||
        !r.U8(reserved[1]) || !r.U8(reserved[2])) {
        return false;
    }
    if (transposed > 1 || reserved[0] != 0 ||
        reserved[1] != 0 || reserved[2] != 0) {
        return false;
    }
    ref.transpose = transposed != 0;
    return true;
}

void WriteBindings(Writer& w, const RCStage3GemmExtractLayerBindings& b)
{
    w.Uint256(b.extract_prf);
    w.Uint256(b.operand_a_root);
    w.Uint256(b.operand_b_root);
    w.Uint256(b.gemm_y_root);
    w.Uint256(b.extract_input_root);
    w.Uint256(b.extract_output_root);
    w.Uint256(b.gemm_proof_root);
    w.Uint256(b.extract_recursive_root);
    w.Uint256(b.scale_schedule_root);
    w.Uint256(b.ctl_terminal_root);
    // Poseidon VectorRootAlg authority roots (version 3).
    w.Uint256(b.operand_a_root_alg);
    w.Uint256(b.operand_b_root_alg);
    w.Uint256(b.gemm_y_root_alg);
    w.Uint256(b.extract_input_root_alg);
    w.Uint256(b.scale_schedule_root_alg);
}

bool ReadBindings(Reader& r, RCStage3GemmExtractLayerBindings& b)
{
    return r.Uint256(b.extract_prf) &&
           r.Uint256(b.operand_a_root) &&
           r.Uint256(b.operand_b_root) &&
           r.Uint256(b.gemm_y_root) &&
           r.Uint256(b.extract_input_root) &&
           r.Uint256(b.extract_output_root) &&
           r.Uint256(b.gemm_proof_root) &&
           r.Uint256(b.extract_recursive_root) &&
           r.Uint256(b.scale_schedule_root) &&
           r.Uint256(b.ctl_terminal_root) &&
           r.Uint256(b.operand_a_root_alg) &&
           r.Uint256(b.operand_b_root_alg) &&
           r.Uint256(b.gemm_y_root_alg) &&
           r.Uint256(b.extract_input_root_alg) &&
           r.Uint256(b.scale_schedule_root_alg);
}

bool ValidateRangePinShape(const RCStage3GemmExtractManifest& manifest,
                           const RCStage3SignedRangePin& pin,
                           bool require_roots,
                           std::string* why)
{
    if (!ValidateRCStage3GemmExtractManifest(manifest, why)) return false;
    if (pin.statement_commitment != manifest.statement_commitment) {
        return Fail(why, "range_statement_commitment");
    }
    const uint256 manifest_commitment =
        ComputeRCStage3GemmExtractManifestCommitment(manifest);
    if (manifest_commitment.IsNull() ||
        pin.manifest_commitment != manifest_commitment) {
        return Fail(why, "range_manifest_commitment");
    }
    if (pin.layer_ordinal >= manifest.layers.size()) {
        return Fail(why, "range_layer");
    }
    const auto& layer = manifest.layers[pin.layer_ordinal];
    const uint64_t shard_count64 =
        (layer.gemm_cell_count + kRCStage3SignedRangeMaxShardRows - 1) /
        kRCStage3SignedRangeMaxShardRows;
    if (shard_count64 == 0 ||
        shard_count64 > std::numeric_limits<uint32_t>::max() ||
        pin.shard_count != shard_count64 ||
        pin.shard_index >= pin.shard_count) {
        return Fail(why, "range_shard_position");
    }
    const uint64_t offset =
        static_cast<uint64_t>(pin.shard_index) *
        kRCStage3SignedRangeMaxShardRows;
    const uint64_t expected_begin = layer.gemm_cell_begin + offset;
    const uint64_t remaining = layer.gemm_cell_count - offset;
    const uint32_t expected_logical = static_cast<uint32_t>(
        std::min<uint64_t>(remaining, kRCStage3SignedRangeMaxShardRows));
    if (pin.cell_begin != expected_begin ||
        pin.logical_rows != expected_logical ||
        pin.n_rows != NextPowerOfTwo(expected_logical) ||
        pin.max_abs != layer.signed_max_abs) {
        return Fail(why, "range_noncanonical_partition");
    }
    if (pin.column_roots.size() != kRCStage3SignedRangeColumns) {
        return Fail(why, "range_root_count");
    }
    for (uint32_t i = 0; i < pin.column_roots.size(); ++i) {
        if (pin.column_roots[i].column != i) {
            return Fail(why, "range_root_order");
        }
        if (require_roots && pin.column_roots[i].root.IsNull()) {
            return Fail(why, "range_null_root");
        }
    }
    return true;
}

uint32_t ExpectedRangeShardCount(
    const RCStage3GemmExtractLayerManifest& layer)
{
    const uint64_t count =
        (layer.gemm_cell_count + kRCStage3SignedRangeMaxShardRows - 1) /
        kRCStage3SignedRangeMaxShardRows;
    if (count == 0 || count > std::numeric_limits<uint32_t>::max()) {
        return 0;
    }
    return static_cast<uint32_t>(count);
}

uint32_t MerkleTreeWidth(uint32_t leaf_count)
{
    if (leaf_count == 0) return 0;
    uint32_t width = 1;
    while (width < leaf_count) {
        if (width > std::numeric_limits<uint32_t>::max() / 2) return 0;
        width <<= 1;
    }
    return width;
}

void WriteExtractInputLayerIdentity(
    Writer& w,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3GemmExtractLayerManifest& layer)
{
    w.Uint256(manifest.statement_commitment);
    w.U32(layer.ordinal);
    w.U8(static_cast<uint8_t>(layer.kind));
    w.U32(layer.round);
    w.U32(layer.layer);
    w.U32(layer.m);
    w.U32(layer.n);
    w.U32(layer.k);
    w.U64(layer.gemm_cell_begin);
    w.U64(layer.gemm_cell_count);
}

uint256 ExtractInputActualLeaf(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3GemmExtractLayerManifest& layer,
    uint32_t shard_index,
    uint32_t shard_count,
    const uint256& shard_root)
{
    if (shard_root.IsNull() || shard_index >= shard_count) return {};
    const uint64_t offset =
        static_cast<uint64_t>(shard_index) *
        kRCStage3SignedRangeMaxShardRows;
    if (offset >= layer.gemm_cell_count) return {};
    const uint32_t logical_rows = static_cast<uint32_t>(
        std::min<uint64_t>(
            layer.gemm_cell_count - offset,
            kRCStage3SignedRangeMaxShardRows));
    Writer w;
    WriteExtractInputLayerIdentity(w, manifest, layer);
    w.U32(shard_index);
    w.U32(shard_count);
    w.U64(layer.gemm_cell_begin + offset);
    w.U32(logical_rows);
    w.Uint256(shard_root);
    return TaggedHash("BTX_RC_STAGE3_EXTRACT_INPUT_LEAF_V1", w.Take());
}

uint256 ExtractInputPaddingLeaf(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3GemmExtractLayerManifest& layer,
    uint32_t padding_index,
    uint32_t shard_count)
{
    Writer w;
    WriteExtractInputLayerIdentity(w, manifest, layer);
    w.U32(padding_index);
    w.U32(shard_count);
    return TaggedHash("BTX_RC_STAGE3_EXTRACT_INPUT_PAD_V1", w.Take());
}

uint256 ExtractInputParent(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3GemmExtractLayerManifest& layer,
    uint32_t level,
    const uint256& left,
    const uint256& right)
{
    if (left.IsNull() || right.IsNull()) return {};
    Writer w;
    WriteExtractInputLayerIdentity(w, manifest, layer);
    w.U32(level);
    w.Uint256(left);
    w.Uint256(right);
    return TaggedHash("BTX_RC_STAGE3_EXTRACT_INPUT_NODE_V1", w.Take());
}

uint256 WrapExtractInputLayerRoot(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3GemmExtractLayerManifest& layer,
    uint32_t shard_count,
    const uint256& tree_root)
{
    if (tree_root.IsNull()) return {};
    Writer w;
    WriteExtractInputLayerIdentity(w, manifest, layer);
    w.U32(shard_count);
    w.Uint256(tree_root);
    return TaggedHash("BTX_RC_STAGE3_EXTRACT_INPUT_LAYER_V1", w.Take());
}

Fp3 U64(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

} // namespace

std::optional<RCStage3GemmExtractManifest>
BuildRCStage3GemmExtractManifest(
    const RCEpisodeParams& params,
    const uint256& statement_commitment,
    const std::vector<RCStage3GemmExtractLayerBindings>& bindings,
    std::string* why)
{
    if (!ValidateRCEpisodeParams(params) || !ManifestParamsSafe(params)) {
        return FailOptional<RCStage3GemmExtractManifest>(
            why, "invalid_params");
    }
    if (statement_commitment.IsNull()) {
        return FailOptional<RCStage3GemmExtractManifest>(
            why, "null_statement_commitment");
    }
    const RCGkrLayout layout = RCGkrTraceLayout(params);
    if (layout.layers.empty() ||
        layout.layers.size() > kRCStage3GemmExtractMaxLayers ||
        bindings.size() != layout.layers.size()) {
        return FailOptional<RCStage3GemmExtractManifest>(
            why, "binding_count");
    }

    RCStage3GemmExtractManifest out;
    out.statement_commitment = statement_commitment;
    out.params = params;
    out.layers.reserve(layout.layers.size());
    uint64_t gemm_cursor{0};
    uint64_t tile_cursor{0};
    for (uint32_t ordinal = 0; ordinal < layout.layers.size(); ++ordinal) {
        if (!AllBindingsNonNull(bindings[ordinal])) {
            return FailOptional<RCStage3GemmExtractManifest>(
                why, "null_binding");
        }
        const auto& src = layout.layers[ordinal];
        uint64_t cells{0};
        if (!CheckedMul(src.m, src.n, cells) ||
            src.n % kRCMxBlockLen != 0) {
            return FailOptional<RCStage3GemmExtractManifest>(
                why, "layer_overflow");
        }
        uint64_t tiles{0};
        if (!CheckedMul(src.m, src.n / kRCMxBlockLen, tiles)) {
            return FailOptional<RCStage3GemmExtractManifest>(
                why, "tile_overflow");
        }
        uint64_t max_abs{0};
        if (!SignedAccumulatorBound(src, max_abs) ||
            max_abs >= (uint64_t{1} << kRCStage3SignedRangeBits)) {
            return FailOptional<RCStage3GemmExtractManifest>(
                why, "signed_bound");
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
        layer.out_first_column = src.out_first_column;
        layer.out_chunks = src.out_chunks;
        layer.residual_first_column = src.residual_first_column;
        layer.gemm_cell_begin = gemm_cursor;
        layer.gemm_cell_count = cells;
        layer.extract_tile_begin = tile_cursor;
        layer.extract_tile_count = tiles;
        layer.signed_max_abs = max_abs;
        layer.bindings = bindings[ordinal];
        out.layers.push_back(std::move(layer));
        if (!CheckedAdd(gemm_cursor, cells, gemm_cursor) ||
            !CheckedAdd(tile_cursor, tiles, tile_cursor)) {
            return FailOptional<RCStage3GemmExtractManifest>(
                why, "total_overflow");
        }
    }
    out.total_gemm_cells = gemm_cursor;
    out.total_extract_tiles = tile_cursor;
    if (!ValidateRCStage3GemmExtractManifest(out, why)) return std::nullopt;
    return out;
}

bool ValidateRCStage3GemmExtractManifest(
    const RCStage3GemmExtractManifest& manifest,
    std::string* why)
{
    if (manifest.magic != kRCStage3GemmExtractManifestMagic) {
        return Fail(why, "bad_manifest_magic");
    }
    if (manifest.version != kRCStage3GemmExtractManifestVersion) {
        return Fail(why, "bad_manifest_version");
    }
    if (manifest.statement_commitment.IsNull()) {
        return Fail(why, "null_statement_commitment");
    }
    if (!ValidateRCEpisodeParams(manifest.params) ||
        !ManifestParamsSafe(manifest.params)) {
        return Fail(why, "invalid_params");
    }
    const RCGkrLayout layout = RCGkrTraceLayout(manifest.params);
    if (layout.layers.empty() ||
        layout.layers.size() > kRCStage3GemmExtractMaxLayers ||
        manifest.layers.size() != layout.layers.size()) {
        return Fail(why, "layer_count");
    }
    uint64_t gemm_cursor{0};
    uint64_t tile_cursor{0};
    for (uint32_t ordinal = 0; ordinal < layout.layers.size(); ++ordinal) {
        const auto& expected = layout.layers[ordinal];
        const auto& actual = manifest.layers[ordinal];
        uint64_t cells{0};
        uint64_t tiles{0};
        uint64_t max_abs{0};
        if (!CheckedMul(expected.m, expected.n, cells) ||
            expected.n % kRCMxBlockLen != 0 ||
            !CheckedMul(expected.m, expected.n / kRCMxBlockLen, tiles) ||
            !SignedAccumulatorBound(expected, max_abs) ||
            max_abs >= (uint64_t{1} << kRCStage3SignedRangeBits)) {
            return Fail(why, "expected_overflow");
        }
        if (actual.ordinal != ordinal ||
            actual.kind != expected.kind ||
            actual.round != expected.round ||
            actual.layer != expected.layer ||
            actual.m != expected.m ||
            actual.n != expected.n ||
            actual.k != expected.k ||
            !SameRef(actual.a, expected.a) ||
            !SameRef(actual.b, expected.b) ||
            actual.y_first_column != expected.y_first_column ||
            actual.y_chunks != expected.y_chunks ||
            actual.out_first_column != expected.out_first_column ||
            actual.out_chunks != expected.out_chunks ||
            actual.residual_first_column != expected.residual_first_column) {
            return Fail(why, "layout_mismatch");
        }
        if (actual.gemm_cell_begin != gemm_cursor ||
            actual.gemm_cell_count != cells ||
            actual.extract_tile_begin != tile_cursor ||
            actual.extract_tile_count != tiles ||
            actual.signed_max_abs != max_abs) {
            return Fail(why, "coverage_partition");
        }
        if (!AllBindingsNonNull(actual.bindings)) {
            return Fail(why, "null_binding");
        }
        if (!CheckedAdd(gemm_cursor, cells, gemm_cursor) ||
            !CheckedAdd(tile_cursor, tiles, tile_cursor)) {
            return Fail(why, "total_overflow");
        }
    }
    if (manifest.total_gemm_cells != gemm_cursor ||
        manifest.total_extract_tiles != tile_cursor) {
        return Fail(why, "total_mismatch");
    }
    return true;
}

bool ValidateRCStage3GemmExtractManifestBinding(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    std::string* why)
{
    if (!ValidateRCStage3GemmExtractManifest(manifest, why)) return false;
    if (statement.statement == RCStage3StatementKind::Coupled) {
        return Fail(why, "coupled_only_statement");
    }
    if (manifest.statement_commitment !=
        RCStage3EpisodeStatementCommitment(statement)) {
        return Fail(why, "statement_commitment_mismatch");
    }
    return true;
}

bool ValidateRCStage3GemmExtractLayerProvenance(
    const RCStage3GemmExtractManifest& manifest,
    const std::vector<RCGkrSampledLayerProv>& provenance,
    std::string* why)
{
    if (!ValidateRCStage3GemmExtractManifest(manifest, why)) return false;
    if (provenance.size() != manifest.layers.size()) {
        return Fail(why, "provenance_layer_count");
    }
    for (uint32_t i = 0; i < provenance.size(); ++i) {
        const auto& layer = manifest.layers[i];
        const auto& actual = provenance[i];
        if (actual.kind != layer.kind ||
            actual.round != layer.round ||
            actual.layer != layer.layer ||
            actual.m != layer.m || actual.n != layer.n ||
            actual.k != layer.k ||
            actual.extract_prf != layer.bindings.extract_prf ||
            actual.fwd_residual !=
                (layer.residual_first_column >= 0)) {
            return Fail(why, "provenance_layer_mismatch");
        }
    }
    return true;
}

bool SerializeRCStage3GemmExtractManifest(
    const RCStage3GemmExtractManifest& manifest,
    std::vector<unsigned char>& out,
    std::string* why)
{
    out.clear();
    if (!ValidateRCStage3GemmExtractManifest(manifest, why)) return false;
    Writer w;
    w.U32(manifest.magic);
    w.U16(manifest.version);
    w.U16(0);
    w.Uint256(manifest.statement_commitment);
    WriteParams(w, manifest.params);
    w.U64(manifest.total_gemm_cells);
    w.U64(manifest.total_extract_tiles);
    w.U32(static_cast<uint32_t>(manifest.layers.size()));
    for (const auto& layer : manifest.layers) {
        w.U32(layer.ordinal);
        w.U8(static_cast<uint8_t>(layer.kind));
        w.U8(0);
        w.U8(0);
        w.U8(0);
        w.U32(layer.round);
        w.U32(layer.layer);
        w.U32(layer.m);
        w.U32(layer.n);
        w.U32(layer.k);
        WriteRef(w, layer.a);
        WriteRef(w, layer.b);
        w.U32(layer.y_first_column);
        w.U32(layer.y_chunks);
        w.U32(layer.out_first_column);
        w.U32(layer.out_chunks);
        w.U32(static_cast<uint32_t>(layer.residual_first_column));
        w.U64(layer.gemm_cell_begin);
        w.U64(layer.gemm_cell_count);
        w.U64(layer.extract_tile_begin);
        w.U64(layer.extract_tile_count);
        w.U64(layer.signed_max_abs);
        WriteBindings(w, layer.bindings);
    }
    out = w.Take();
    return true;
}

std::optional<RCStage3GemmExtractManifest>
DeserializeRCStage3GemmExtractManifest(
    const std::vector<unsigned char>& bytes,
    std::string* why)
{
    if (bytes.size() < MANIFEST_HEADER_BYTES ||
        bytes.size() > MANIFEST_HEADER_BYTES +
                           kRCStage3GemmExtractMaxLayers *
                               MANIFEST_LAYER_BYTES) {
        return FailOptional<RCStage3GemmExtractManifest>(
            why, "manifest_size");
    }
    Reader r(bytes);
    RCStage3GemmExtractManifest out;
    uint16_t reserved{0};
    uint32_t layers{0};
    if (!r.U32(out.magic) || !r.U16(out.version) ||
        !r.U16(reserved) || !r.Uint256(out.statement_commitment) ||
        !ReadParams(r, out.params) ||
        !r.U64(out.total_gemm_cells) ||
        !r.U64(out.total_extract_tiles) || !r.U32(layers)) {
        return FailOptional<RCStage3GemmExtractManifest>(
            why, "truncated_manifest");
    }
    if (reserved != 0 || layers == 0 ||
        layers > kRCStage3GemmExtractMaxLayers ||
        r.Remaining() != static_cast<size_t>(layers) *
                             MANIFEST_LAYER_BYTES) {
        return FailOptional<RCStage3GemmExtractManifest>(
            why, "manifest_shape");
    }
    out.layers.resize(layers);
    for (auto& layer : out.layers) {
        uint8_t kind{0};
        uint8_t layer_reserved[3]{};
        uint32_t residual{0};
        if (!r.U32(layer.ordinal) || !r.U8(kind) ||
            !r.U8(layer_reserved[0]) || !r.U8(layer_reserved[1]) ||
            !r.U8(layer_reserved[2]) ||
            !r.U32(layer.round) || !r.U32(layer.layer) ||
            !r.U32(layer.m) || !r.U32(layer.n) || !r.U32(layer.k) ||
            !ReadRef(r, layer.a) || !ReadRef(r, layer.b) ||
            !r.U32(layer.y_first_column) || !r.U32(layer.y_chunks) ||
            !r.U32(layer.out_first_column) || !r.U32(layer.out_chunks) ||
            !r.U32(residual) || !r.U64(layer.gemm_cell_begin) ||
            !r.U64(layer.gemm_cell_count) ||
            !r.U64(layer.extract_tile_begin) ||
            !r.U64(layer.extract_tile_count) ||
            !r.U64(layer.signed_max_abs) ||
            !ReadBindings(r, layer.bindings)) {
            return FailOptional<RCStage3GemmExtractManifest>(
                why, "truncated_layer");
        }
        if (layer_reserved[0] != 0 || layer_reserved[1] != 0 ||
            layer_reserved[2] != 0) {
            return FailOptional<RCStage3GemmExtractManifest>(
                why, "nonzero_reserved");
        }
        layer.kind = static_cast<RCGkrLayerKind>(kind);
        layer.residual_first_column = static_cast<int32_t>(residual);
    }
    if (r.Remaining() != 0 ||
        !ValidateRCStage3GemmExtractManifest(out, why)) {
        return std::nullopt;
    }
    std::vector<unsigned char> canonical;
    if (!SerializeRCStage3GemmExtractManifest(out, canonical, why) ||
        canonical != bytes) {
        return FailOptional<RCStage3GemmExtractManifest>(
            why, "noncanonical_manifest");
    }
    return out;
}

uint256 ComputeRCStage3GemmExtractManifestCommitment(
    const RCStage3GemmExtractManifest& manifest)
{
    std::vector<unsigned char> bytes;
    if (!SerializeRCStage3GemmExtractManifest(manifest, bytes, nullptr)) {
        return {};
    }
    return TaggedHash("BTX_RC_STAGE3_GEMM_EXTRACT_MANIFEST_V1", bytes);
}

namespace {

bool ScaleShardShape(const RCStage3GemmExtractManifest& manifest,
                     const RCStage3ScaleScheduleShard& shard,
                     std::string* why)
{
    if (!ValidateRCStage3GemmExtractManifest(manifest, why)) return false;
    if (shard.layer_ordinal >= manifest.layers.size()) {
        return Fail(why, "scale_layer");
    }
    const auto& layer = manifest.layers[shard.layer_ordinal];
    const uint64_t count64 =
        (layer.extract_tile_count + kRCStage3ScaleScheduleMaxShardTiles - 1) /
        kRCStage3ScaleScheduleMaxShardTiles;
    if (count64 == 0 || count64 > std::numeric_limits<uint32_t>::max() ||
        shard.shard_count != count64 ||
        shard.shard_index >= shard.shard_count) {
        return Fail(why, "scale_shard_position");
    }
    const uint64_t offset =
        static_cast<uint64_t>(shard.shard_index) *
        kRCStage3ScaleScheduleMaxShardTiles;
    const uint32_t expected_count = static_cast<uint32_t>(
        std::min<uint64_t>(layer.extract_tile_count - offset,
                           kRCStage3ScaleScheduleMaxShardTiles));
    if (shard.tile_begin != layer.extract_tile_begin + offset ||
        shard.tile_count != expected_count) {
        return Fail(why, "scale_partition");
    }
    return true;
}

uint256 ComputeScaleShardCommitment(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3ScaleScheduleShard& shard)
{
    if (!ScaleShardShape(manifest, shard, nullptr)) return {};
    const auto& layer = manifest.layers[shard.layer_ordinal];
    const uint64_t local_begin =
        shard.tile_begin - layer.extract_tile_begin;
    const uint32_t blocks_per_row = layer.n / kRCMxBlockLen;
    Writer w;
    w.Uint256(manifest.statement_commitment);
    w.U32(shard.layer_ordinal);
    w.U32(layer.round);
    w.U32(layer.layer);
    w.U32(layer.m);
    w.U32(layer.n);
    w.Uint256(layer.bindings.extract_prf);
    w.U32(shard.shard_index);
    w.U32(shard.shard_count);
    w.U64(shard.tile_begin);
    w.U32(shard.tile_count);
    for (uint32_t t = 0; t < shard.tile_count; ++t) {
        const uint64_t local = local_begin + t;
        const uint32_t row = static_cast<uint32_t>(
            local / blocks_per_row);
        const uint32_t block = static_cast<uint32_t>(
            local % blocks_per_row);
        w.U8(lt::DeriveMatExpandMxScale(
            layer.bindings.extract_prf, row, block));
    }
    return TaggedHash("BTX_RC_STAGE3_SCALE_SCHEDULE_SHARD_V1",
                      w.Take());
}

uint256 RangeCtlTraceCommitment(const RCStage3SignedRangePin& pin)
{
    if (pin.column_roots.size() != kRCStage3SignedRangeColumns ||
        pin.column_roots[kRCStage3RangeValue].root.IsNull()) {
        return {};
    }
    Writer w;
    w.Uint256(ComputeRCStage3SignedRangePinCommitment(pin));
    w.Uint256(pin.column_roots[kRCStage3RangeValue].root);
    w.U64(pin.cell_begin);
    w.U32(pin.logical_rows);
    return TaggedHash("BTX_RC_STAGE3_RANGE_CTL_TRACE_V1", w.Take());
}

uint256 ExtractCtlTraceCommitment(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    const RCStage3SignedRangeCtlBinding& binding)
{
    const uint256 obligation = ComputeRCStage3ExtractInputShardObligation(
        manifest, pin, binding.extract_input_shard_root,
        binding.extract_input_opening_commitment);
    if (obligation.IsNull()) return {};
    Writer w;
    w.Uint256(obligation);
    w.Uint256(binding.extract_input_shard_root);
    return TaggedHash("BTX_RC_STAGE3_EXTRACT_CTL_TRACE_V1", w.Take());
}

} // namespace

std::optional<RCStage3ScaleScheduleShard>
BuildRCStage3ScaleScheduleShard(
    const RCStage3GemmExtractManifest& manifest,
    uint32_t layer_ordinal,
    uint32_t shard_index,
    std::string* why)
{
    if (!ValidateRCStage3GemmExtractManifest(manifest, why)) {
        return std::nullopt;
    }
    if (layer_ordinal >= manifest.layers.size()) {
        return FailOptional<RCStage3ScaleScheduleShard>(
            why, "scale_layer");
    }
    const auto& layer = manifest.layers[layer_ordinal];
    const uint64_t count64 =
        (layer.extract_tile_count + kRCStage3ScaleScheduleMaxShardTiles - 1) /
        kRCStage3ScaleScheduleMaxShardTiles;
    if (count64 == 0 || count64 > std::numeric_limits<uint32_t>::max() ||
        shard_index >= count64) {
        return FailOptional<RCStage3ScaleScheduleShard>(
            why, "scale_shard_position");
    }
    const uint64_t offset =
        static_cast<uint64_t>(shard_index) *
        kRCStage3ScaleScheduleMaxShardTiles;
    RCStage3ScaleScheduleShard out;
    out.layer_ordinal = layer_ordinal;
    out.shard_index = shard_index;
    out.shard_count = static_cast<uint32_t>(count64);
    out.tile_begin = layer.extract_tile_begin + offset;
    out.tile_count = static_cast<uint32_t>(
        std::min<uint64_t>(layer.extract_tile_count - offset,
                           kRCStage3ScaleScheduleMaxShardTiles));
    out.scale_commitment = ComputeScaleShardCommitment(manifest, out);
    if (out.scale_commitment.IsNull()) {
        return FailOptional<RCStage3ScaleScheduleShard>(
            why, "scale_commitment");
    }
    return out;
}

bool VerifyRCStage3ScaleScheduleShard(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3ScaleScheduleShard& shard,
    std::string* why)
{
    if (!ScaleShardShape(manifest, shard, why)) return false;
    if (shard.scale_commitment.IsNull() ||
        shard.scale_commitment !=
            ComputeScaleShardCommitment(manifest, shard)) {
        return Fail(why, "scale_commitment");
    }
    return true;
}

uint256 ComputeRCStage3ScaleScheduleLayerRoot(
    const RCStage3GemmExtractManifest& manifest,
    uint32_t layer_ordinal,
    const std::vector<RCStage3ScaleScheduleShard>& shards,
    std::string* why)
{
    if (!ValidateRCStage3GemmExtractManifest(manifest, why) ||
        layer_ordinal >= manifest.layers.size()) {
        return {};
    }
    const auto& layer = manifest.layers[layer_ordinal];
    const uint64_t count64 =
        (layer.extract_tile_count + kRCStage3ScaleScheduleMaxShardTiles - 1) /
        kRCStage3ScaleScheduleMaxShardTiles;
    if (count64 != shards.size()) {
        Fail(why, "scale_layer_shard_count");
        return {};
    }
    Writer w;
    w.Uint256(manifest.statement_commitment);
    w.U32(layer_ordinal);
    w.Uint256(layer.bindings.extract_prf);
    w.U64(layer.extract_tile_begin);
    w.U64(layer.extract_tile_count);
    w.U32(static_cast<uint32_t>(shards.size()));
    for (uint32_t i = 0; i < shards.size(); ++i) {
        if (shards[i].layer_ordinal != layer_ordinal ||
            shards[i].shard_index != i ||
            !ScaleShardShape(manifest, shards[i], why) ||
            shards[i].scale_commitment.IsNull()) {
            Fail(why, "scale_layer_order");
            return {};
        }
        w.U64(shards[i].tile_begin);
        w.U32(shards[i].tile_count);
        w.Uint256(shards[i].scale_commitment);
    }
    return TaggedHash("BTX_RC_STAGE3_SCALE_SCHEDULE_LAYER_V1",
                      w.Take());
}

bool VerifyRCStage3ScaleScheduleClosure(
    const RCStage3GemmExtractManifest& manifest,
    const std::vector<RCStage3ScaleScheduleShard>& shards,
    bool replay_public_scales,
    std::string* why)
{
    if (!ValidateRCStage3GemmExtractManifest(manifest, why)) return false;
    size_t cursor{0};
    for (uint32_t layer = 0; layer < manifest.layers.size(); ++layer) {
        const uint64_t count64 =
            (manifest.layers[layer].extract_tile_count +
             kRCStage3ScaleScheduleMaxShardTiles - 1) /
            kRCStage3ScaleScheduleMaxShardTiles;
        if (count64 > shards.size() - cursor) {
            return Fail(why, "scale_closure_shard_count");
        }
        std::vector<RCStage3ScaleScheduleShard> group(
            shards.begin() + cursor,
            shards.begin() + cursor + static_cast<size_t>(count64));
        for (const auto& shard : group) {
            if (replay_public_scales) {
                if (!VerifyRCStage3ScaleScheduleShard(
                        manifest, shard, why)) {
                    return false;
                }
            } else if (!ScaleShardShape(manifest, shard, why) ||
                       shard.scale_commitment.IsNull()) {
                return false;
            }
        }
        const uint256 root = ComputeRCStage3ScaleScheduleLayerRoot(
            manifest, layer, group, why);
        if (root.IsNull() ||
            root !=
                manifest.layers[layer].bindings.scale_schedule_root) {
            return Fail(why, "scale_closure_layer_root");
        }
        cursor += static_cast<size_t>(count64);
    }
    if (cursor != shards.size()) {
        return Fail(why, "scale_closure_trailing_shards");
    }
    if (why != nullptr) {
        *why = replay_public_scales
            ? "stage3:gemm_extract:scale_schedule_public_replay_ok_"
              "hash_air_pending"
            : "stage3:gemm_extract:scale_schedule_structure_ok_"
              "proof_execution_pending";
    }
    return true;
}

std::optional<RCStage3SignedRangePin>
MakeRCStage3SignedRangePin(
    const RCStage3GemmExtractManifest& manifest,
    uint32_t layer_ordinal,
    uint32_t shard_index,
    std::string* why)
{
    if (!ValidateRCStage3GemmExtractManifest(manifest, why)) {
        return std::nullopt;
    }
    if (layer_ordinal >= manifest.layers.size()) {
        return FailOptional<RCStage3SignedRangePin>(why, "range_layer");
    }
    const auto& layer = manifest.layers[layer_ordinal];
    const uint64_t count =
        (layer.gemm_cell_count + kRCStage3SignedRangeMaxShardRows - 1) /
        kRCStage3SignedRangeMaxShardRows;
    if (count == 0 || count > std::numeric_limits<uint32_t>::max() ||
        shard_index >= count) {
        return FailOptional<RCStage3SignedRangePin>(
            why, "range_shard_position");
    }
    const uint64_t offset =
        static_cast<uint64_t>(shard_index) *
        kRCStage3SignedRangeMaxShardRows;
    const uint32_t logical = static_cast<uint32_t>(
        std::min<uint64_t>(layer.gemm_cell_count - offset,
                           kRCStage3SignedRangeMaxShardRows));
    RCStage3SignedRangePin pin;
    pin.statement_commitment = manifest.statement_commitment;
    pin.manifest_commitment =
        ComputeRCStage3GemmExtractManifestCommitment(manifest);
    pin.layer_ordinal = layer_ordinal;
    pin.shard_index = shard_index;
    pin.shard_count = static_cast<uint32_t>(count);
    pin.cell_begin = layer.gemm_cell_begin + offset;
    pin.logical_rows = logical;
    pin.n_rows = NextPowerOfTwo(logical);
    pin.max_abs = layer.signed_max_abs;
    pin.column_roots.resize(kRCStage3SignedRangeColumns);
    for (uint32_t i = 0; i < pin.column_roots.size(); ++i) {
        pin.column_roots[i].column = i;
    }
    if (!ValidateRangePinShape(manifest, pin, false, why)) {
        return std::nullopt;
    }
    return pin;
}

bool SerializeRCStage3SignedRangePin(
    const RCStage3SignedRangePin& pin,
    std::vector<unsigned char>& out,
    std::string* why)
{
    out.clear();
    if (pin.statement_commitment.IsNull() ||
        pin.manifest_commitment.IsNull() ||
        pin.shard_count == 0 || pin.shard_index >= pin.shard_count ||
        pin.logical_rows == 0 || pin.logical_rows > pin.n_rows ||
        pin.n_rows != NextPowerOfTwo(pin.n_rows) ||
        pin.max_abs >= (uint64_t{1} << kRCStage3SignedRangeBits) ||
        pin.column_roots.size() != kRCStage3SignedRangeColumns) {
        return Fail(why, "range_pin_shape");
    }
    for (uint32_t i = 0; i < pin.column_roots.size(); ++i) {
        if (pin.column_roots[i].column != i ||
            pin.column_roots[i].root.IsNull()) {
            return Fail(why, "range_pin_root");
        }
    }
    Writer w;
    w.Uint256(pin.statement_commitment);
    w.Uint256(pin.manifest_commitment);
    w.U32(pin.layer_ordinal);
    w.U32(pin.shard_index);
    w.U32(pin.shard_count);
    w.U64(pin.cell_begin);
    w.U32(pin.logical_rows);
    w.U32(pin.n_rows);
    w.U64(pin.max_abs);
    w.U32(static_cast<uint32_t>(pin.column_roots.size()));
    for (const auto& root : pin.column_roots) {
        w.U32(root.column);
        w.Uint256(root.root);
    }
    out = w.Take();
    return true;
}

uint256 ComputeRCStage3SignedRangePinCommitment(
    const RCStage3SignedRangePin& pin)
{
    std::vector<unsigned char> bytes;
    if (!SerializeRCStage3SignedRangePin(pin, bytes, nullptr)) return {};
    return TaggedHash("BTX_RC_STAGE3_SIGNED_RANGE_PIN_V1", bytes);
}

uint256 ComputeRCStage3SignedRangeSeed(
    const RCStage3SignedRangePin& pin)
{
    std::vector<unsigned char> bytes;
    if (!SerializeRCStage3SignedRangePin(pin, bytes, nullptr)) return {};
    return TaggedHash("BTX_RC_STAGE3_SIGNED_RANGE_FS_V1", bytes);
}

bool BuildRCStage3SignedRangeColumns(
    const RCStage3SignedRangePin& pin,
    const std::vector<int64_t>& values,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    columns.clear();
    if (pin.logical_rows == 0 || pin.logical_rows != values.size() ||
        pin.logical_rows > pin.n_rows ||
        pin.n_rows != NextPowerOfTwo(pin.n_rows) ||
        pin.max_abs >= (uint64_t{1} << kRCStage3SignedRangeBits)) {
        return Fail(why, "range_witness_shape");
    }
    columns.assign(kRCStage3SignedRangeColumns,
                   std::vector<Fp3>(pin.n_rows, Fp3::Zero()));
    for (uint32_t row = 0; row < pin.n_rows; ++row) {
        columns[kRCStage3RangeActive][row] =
            row < pin.logical_rows ? Fp3::One() : Fp3::Zero();
        columns[kRCStage3RangeRemaining][row] =
            U64(row < pin.logical_rows ? pin.logical_rows - row : 0);
    }
    for (uint32_t row = 0; row < pin.logical_rows; ++row) {
        const int64_t value = values[row];
        const bool negative = value < 0;
        const uint64_t magnitude =
            negative ? -static_cast<uint64_t>(value)
                     : static_cast<uint64_t>(value);
        if (magnitude > pin.max_abs) {
            columns.clear();
            return Fail(why, "range_witness_out_of_range");
        }
        const uint64_t difference = pin.max_abs - magnitude;
        columns[kRCStage3RangeValue][row] = gf::FromSigned3(value);
        columns[kRCStage3RangeSign][row] =
            U64(negative && magnitude != 0 ? 1 : 0);
        columns[kRCStage3RangeZero][row] =
            U64(magnitude == 0 ? 1 : 0);
        columns[kRCStage3RangeMagnitudeInverse][row] =
            magnitude == 0 ? Fp3::Zero() : gf::Inv(U64(magnitude));
        columns[kRCStage3RangeMagnitude][row] = U64(magnitude);
        for (uint32_t bit = 0; bit < kRCStage3SignedRangeBits; ++bit) {
            columns[kRCStage3RangeMagnitudeBits + bit][row] =
                U64((magnitude >> bit) & 1U);
            columns[kRCStage3RangeDifferenceBits + bit][row] =
                U64((difference >> bit) & 1U);
        }
    }
    // Padding rows are the unique canonical representation of positive zero.
    for (uint32_t row = pin.logical_rows; row < pin.n_rows; ++row) {
        columns[kRCStage3RangeZero][row] = Fp3::One();
        const uint64_t difference = pin.max_abs;
        for (uint32_t bit = 0; bit < kRCStage3SignedRangeBits; ++bit) {
            columns[kRCStage3RangeDifferenceBits + bit][row] =
                U64((difference >> bit) & 1U);
        }
    }
    return true;
}

bool ResolveRCStage3SignedRangeConstraintSystem(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    if (!ValidateRangePinShape(manifest, pin, true, why)) return false;
    return ResolveRCStage3SignedRangeKernelConstraintSystem(
        pin, out, why);
}

bool ResolveRCStage3SignedRangeKernelConstraintSystem(
    const RCStage3SignedRangePin& pin,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    out = {};
    std::vector<unsigned char> encoded;
    if (!SerializeRCStage3SignedRangePin(pin, encoded, why)) {
        return false;
    }
    out.n_rows = pin.n_rows;
    out.n_columns = kRCStage3SignedRangeColumns;

    auto add_at = [&](const char* name, aq::AirKind kind, uint32_t degree,
                      std::function<Fp3(const std::vector<Fp3>&,
                                        const std::vector<Fp3>&)> eval) {
        aq::AirConstraint<Fp3> c;
        c.name = name;
        c.kind = kind;
        c.alg_degree = degree;
        c.eval = std::move(eval);
        out.constraints.push_back(std::move(c));
    };
    auto add = [&](const char* name, uint32_t degree,
                   std::function<Fp3(const std::vector<Fp3>&,
                                     const std::vector<Fp3>&)> eval) {
        add_at(name, aq::AirKind::kEverywhere, degree, std::move(eval));
    };
    auto boolean = [&](const char* name, uint32_t column) {
        add(name, 2, [column](const std::vector<Fp3>& row,
                             const std::vector<Fp3>&) {
            return gf::Mul(row[column],
                           gf::Sub(row[column], Fp3::One()));
        });
    };
    boolean("stage3.range.active.bool", kRCStage3RangeActive);
    boolean("stage3.range.sign.bool", kRCStage3RangeSign);
    boolean("stage3.range.zero.bool", kRCStage3RangeZero);
    for (uint32_t bit = 0; bit < kRCStage3SignedRangeBits; ++bit) {
        boolean("stage3.range.magnitude_bit.bool",
                kRCStage3RangeMagnitudeBits + bit);
        boolean("stage3.range.difference_bit.bool",
                kRCStage3RangeDifferenceBits + bit);
    }
    add("stage3.range.magnitude.reconstruct", 1,
        [](const std::vector<Fp3>& row, const std::vector<Fp3>&) {
            Fp3 sum = Fp3::Zero();
            uint64_t weight = 1;
            for (uint32_t bit = 0; bit < kRCStage3SignedRangeBits; ++bit) {
                sum = gf::Add(
                    sum, gf::Mul(U64(weight),
                                 row[kRCStage3RangeMagnitudeBits + bit]));
                weight <<= 1;
            }
            return gf::Sub(row[kRCStage3RangeMagnitude], sum);
        });
    add("stage3.range.value.signed", 2,
        [](const std::vector<Fp3>& row, const std::vector<Fp3>&) {
            const Fp3 signed_factor = gf::Sub(
                Fp3::One(), gf::Mul(U64(2), row[kRCStage3RangeSign]));
            return gf::Sub(
                row[kRCStage3RangeValue],
                gf::Mul(row[kRCStage3RangeMagnitude], signed_factor));
        });
    add("stage3.range.zero.product", 2,
        [](const std::vector<Fp3>& row, const std::vector<Fp3>&) {
            return gf::Mul(row[kRCStage3RangeMagnitude],
                           row[kRCStage3RangeZero]);
        });
    add("stage3.range.zero.inverse", 2,
        [](const std::vector<Fp3>& row, const std::vector<Fp3>&) {
            return gf::Sub(
                gf::Mul(row[kRCStage3RangeMagnitude],
                        row[kRCStage3RangeMagnitudeInverse]),
                gf::Sub(Fp3::One(), row[kRCStage3RangeZero]));
        });
    add("stage3.range.zero.positive", 2,
        [](const std::vector<Fp3>& row, const std::vector<Fp3>&) {
            return gf::Mul(row[kRCStage3RangeSign],
                           row[kRCStage3RangeZero]);
        });
    const uint64_t max_abs = pin.max_abs;
    add("stage3.range.upper_bound", 1,
        [max_abs](const std::vector<Fp3>& row,
                  const std::vector<Fp3>&) {
            Fp3 difference = Fp3::Zero();
            uint64_t weight = 1;
            for (uint32_t bit = 0; bit < kRCStage3SignedRangeBits; ++bit) {
                difference = gf::Add(
                    difference,
                    gf::Mul(U64(weight),
                            row[kRCStage3RangeDifferenceBits + bit]));
                weight <<= 1;
            }
            return gf::Sub(
                gf::Add(row[kRCStage3RangeMagnitude], difference),
                U64(max_abs));
        });
    add_at("stage3.range.active.prefix", aq::AirKind::kTransition, 2,
           [](const std::vector<Fp3>& row,
              const std::vector<Fp3>& next) {
               return gf::Mul(
                   next[kRCStage3RangeActive],
                   gf::Sub(Fp3::One(), row[kRCStage3RangeActive]));
           });
    add_at("stage3.range.remaining.step", aq::AirKind::kTransition, 1,
           [](const std::vector<Fp3>& row,
              const std::vector<Fp3>& next) {
               return gf::Sub(
                   next[kRCStage3RangeRemaining],
                   gf::Sub(row[kRCStage3RangeRemaining],
                           row[kRCStage3RangeActive]));
           });
    const uint32_t logical_rows = pin.logical_rows;
    add_at("stage3.range.remaining.first", aq::AirKind::kFirstRow, 1,
           [logical_rows](const std::vector<Fp3>& row,
                          const std::vector<Fp3>&) {
               return gf::Sub(row[kRCStage3RangeRemaining],
                              U64(logical_rows));
           });
    add_at("stage3.range.active.first", aq::AirKind::kFirstRow, 1,
           [](const std::vector<Fp3>& row,
              const std::vector<Fp3>&) {
               return gf::Sub(row[kRCStage3RangeActive], Fp3::One());
           });
    add_at("stage3.range.remaining.last", aq::AirKind::kLastRow, 1,
           [](const std::vector<Fp3>& row,
              const std::vector<Fp3>&) {
               return gf::Sub(row[kRCStage3RangeRemaining],
                              row[kRCStage3RangeActive]);
           });

    // A unique positive-zero encoding for padding prevents two valid proof
    // byte strings for the same logical shard.  The active-prefix/count
    // constraints above prove which rows are padding without verifier-linear
    // preprocessed selectors.
    auto inactive_value = [&](const char* name, uint32_t column,
                              uint64_t expected) {
        add(name, 2,
            [column, expected](const std::vector<Fp3>& row,
                               const std::vector<Fp3>&) {
                return gf::Mul(
                    gf::Sub(Fp3::One(), row[kRCStage3RangeActive]),
                    gf::Sub(row[column], U64(expected)));
            });
    };
    inactive_value("stage3.range.padding.value", kRCStage3RangeValue, 0);
    inactive_value("stage3.range.padding.sign", kRCStage3RangeSign, 0);
    inactive_value("stage3.range.padding.zero", kRCStage3RangeZero, 1);
    inactive_value("stage3.range.padding.inverse",
                   kRCStage3RangeMagnitudeInverse, 0);
    inactive_value("stage3.range.padding.magnitude",
                   kRCStage3RangeMagnitude, 0);
    for (uint32_t bit = 0; bit < kRCStage3SignedRangeBits; ++bit) {
        inactive_value("stage3.range.padding.magnitude_bit",
                       kRCStage3RangeMagnitudeBits + bit, 0);
        inactive_value("stage3.range.padding.difference_bit",
                       kRCStage3RangeDifferenceBits + bit,
                       (pin.max_abs >> bit) & 1U);
    }
    out.preprocessed_roots.reserve(pin.column_roots.size());
    for (const auto& root : pin.column_roots) {
        out.preprocessed_roots.emplace_back(root.column, root.root);
    }
    if (out.QuotientLen() > pin.n_rows) {
        out = {};
        return Fail(why, "range_degree");
    }
    return true;
}

bool VerifyRCStage3SignedRangeShard(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    const aq::AirQuotientProof<Fp3>& proof,
    std::string* why)
{
    aq::AirConstraintSystem<Fp3> cs;
    if (!ResolveRCStage3SignedRangeConstraintSystem(
            manifest, pin, cs, why)) {
        return false;
    }
    if (proof.batch.columns.size() != kRCStage3SignedRangeColumns + 1 ||
        proof.batch.column_len.size() !=
            kRCStage3SignedRangeColumns + 1 ||
        proof.batch.n_coeffs != pin.n_rows) {
        return Fail(why, "range_proof_shape");
    }
    for (uint32_t i = 0; i < pin.column_roots.size(); ++i) {
        if (proof.batch.columns[i].root != pin.column_roots[i].root) {
            return Fail(why, "range_proof_root");
        }
    }
    const uint256 seed = ComputeRCStage3SignedRangeSeed(pin);
    if (seed.IsNull()) return Fail(why, "range_seed");
    std::string air_why;
    if (!aq::AirQuotientVerify<Fp3>(cs, proof, seed, &air_why)) {
        return Fail(why, "range_air:" + air_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:gemm_extract:signed_range_ok_ctl_extract_input_link_pending";
    }
    return true;
}

namespace {

uint256 EpisodeSignedRangeSplitRapSeed(
    const RCStage3SignedRangePin& pin,
    const uint256& value_export_root)
{
    const uint256 pin_commitment =
        ComputeRCStage3SignedRangePinCommitment(pin);
    if (pin_commitment.IsNull() ||
        value_export_root.IsNull()) {
        return {};
    }
    Writer w;
    w.U16(1);
    w.Uint256(pin_commitment);
    w.Uint256(value_export_root);
    w.U32(kRCStage3SignedRangeColumns);
    w.U32(kRCStage3RangeValue);
    return TaggedHash(
        "BTX_RC_STAGE3_EPISODE_SIGNED_RANGE_SPLIT_RAP_V1",
        w.Take());
}

bool ResolveEpisodeSignedRangeSplitRapConstraintSystem(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    if (!ResolveRCStage3SignedRangeConstraintSystem(
            manifest, pin, out, why)) {
        return false;
    }

    // Split-RAP authenticates the complete trace through its ordered R0/Rdep
    // row commitments.  The legacy per-column SHA roots remain part of the
    // immutable public pin and FS seed, but are not verifier-trusted
    // preprocessed oracles in this proof system.
    out.preprocessed_roots.clear();
    return true;
}

uint256 SignedRangeSplitRapValueRootFromColumns(
    const RCStage3SignedRangePin& pin,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() !=
            kRCStage3SignedRangeColumns ||
        columns[kRCStage3RangeValue].size() !=
            pin.n_rows) {
        return {};
    }
    return aq::AirCommittedValuesRoot<
        Fp3, aq::AirFriBackendAlg<Fp3>>(
            columns[kRCStage3RangeValue],
            pin.n_rows);
}

} // namespace

const std::vector<uint32_t>&
RCStage3EpisodeSignedRangeSplitRapBaseColumns()
{
    static const std::vector<uint32_t>
        columns{kRCStage3RangeValue};
    return columns;
}

uint256
ComputeRCStage3EpisodeSignedRangeSplitRapValueExportRoot(
    const RCStage3SignedRangePin& pin,
    const std::vector<int64_t>& values,
    std::string* why)
{
    std::vector<std::vector<Fp3>> columns;
    if (!BuildRCStage3SignedRangeColumns(
            pin, values, columns, why)) {
        return {};
    }
    const uint256 root =
        SignedRangeSplitRapValueRootFromColumns(
            pin, columns);
    if (root.IsNull()) {
        Fail(why, "episode_range_split_rap_value_root");
    }
    return root;
}

bool ProveRCStage3EpisodeSignedRangeSplitRapShard(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    const std::vector<int64_t>& values,
    RCStage3EpisodeSignedRangeSplitRapShardProof& out,
    std::string* why)
{
    out = {};
    if (!ValidateRangePinShape(
            manifest, pin, true, why)) {
        return false;
    }
    std::vector<std::vector<Fp3>> columns;
    if (!BuildRCStage3SignedRangeColumns(
            pin, values, columns, why)) {
        return false;
    }

    // Preserve the legacy pin contract: the canary accepts only the same
    // fully-rooted witness that the existing per-column prover accepts.
    for (uint32_t column = 0;
         column < columns.size(); ++column) {
        const uint256 canonical =
            aq::AirCommittedValuesRoot<Fp3>(
                columns[column],
                pin.n_rows);
        if (canonical.IsNull() ||
            pin.column_roots[column].root !=
                canonical) {
            return Fail(
                why,
                "episode_range_split_rap_legacy_root_" +
                    std::to_string(column));
        }
    }

    const uint256 value_export_root =
        SignedRangeSplitRapValueRootFromColumns(
            pin, columns);
    const uint256 seed =
        EpisodeSignedRangeSplitRapSeed(
            pin, value_export_root);
    if (value_export_root.IsNull() ||
        seed.IsNull()) {
        return Fail(
            why,
            "episode_range_split_rap_seed_or_export");
    }

    aq::AirConstraintSystem<Fp3> cs;
    if (!ResolveEpisodeSignedRangeSplitRapConstraintSystem(
            manifest, pin, cs, why)) {
        return false;
    }
    const auto& base_columns =
        RCStage3EpisodeSignedRangeSplitRapBaseColumns();
    const auto result =
        aq::AirQuotientProveRowsSplitRap(
            cs, columns, base_columns, seed);
    if (!result.ok ||
        !result.division_exact ||
        result.proof.batch.groups.size() !=
            3 ||
        result.proof.batch.groups[0]
                .column_count != 1 ||
        Fri3AlgDigestToUint256(
            result.proof.batch.groups[0]
                .row_commit.root) !=
            value_export_root) {
        return Fail(
            why,
            "episode_range_split_rap_prove:" +
                result.note);
    }

    out.version = 1;
    out.pin = pin;
    out.value_export_root =
        value_export_root;
    out.quotient = result.proof;
    if (why != nullptr) {
        *why =
            "stage3:gemm_extract:"
            "episode_range_split_rap_prove_ok;"
            "value_export_exact;"
            "recursive_consumption_pending";
    }
    return true;
}

bool VerifyRCStage3EpisodeSignedRangeSplitRapShard(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& expected_pin,
    const uint256& expected_value_export_root,
    const RCStage3EpisodeSignedRangeSplitRapShardProof& proof,
    std::string* why)
{
    if (proof.version != 1 ||
        proof.pin != expected_pin ||
        expected_value_export_root.IsNull() ||
        proof.value_export_root !=
            expected_value_export_root) {
        return Fail(
            why,
            "episode_range_split_rap_public_binding");
    }
    if (!ValidateRangePinShape(
            manifest, expected_pin, true, why)) {
        return false;
    }

    const auto& base_columns =
        RCStage3EpisodeSignedRangeSplitRapBaseColumns();
    const auto& quotient = proof.quotient;
    if (base_columns.size() != 1 ||
        base_columns[0] !=
            kRCStage3RangeValue ||
        quotient.base_column_indices !=
            base_columns ||
        quotient.batch.groups.size() != 3 ||
        quotient.batch.groups[0].role !=
            Fri3AlgMultiRowGroupRole::
                MainTrace ||
        quotient.batch.groups[0]
                .column_count != 1 ||
        Fri3AlgDigestToUint256(
            quotient.batch.groups[0]
                .row_commit.root) !=
            proof.value_export_root) {
        return Fail(
            why,
            "episode_range_split_rap_value_export");
    }

    aq::AirConstraintSystem<Fp3> cs;
    if (!ResolveEpisodeSignedRangeSplitRapConstraintSystem(
            manifest, expected_pin, cs, why)) {
        return false;
    }
    const uint256 seed =
        EpisodeSignedRangeSplitRapSeed(
            expected_pin,
            expected_value_export_root);
    std::string air_why;
    if (seed.IsNull() ||
        !aq::AirQuotientVerifyRowsSplitRap(
            cs, quotient, base_columns,
            seed, &air_why)) {
        return Fail(
            why,
            "episode_range_split_rap_air:" +
                air_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:gemm_extract:"
            "episode_range_split_rap_verify_ok;"
            "public_cs_reconstructed;"
            "value_export_exact;"
            "recursive_consumption_pending";
    }
    return true;
}

bool ResolveRCStage3SignedRangeCtlAlignedConstraintSystem(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    if (!ResolveRCStage3SignedRangeConstraintSystem(
            manifest, pin, out, why)) {
        return false;
    }

    aq::AirConstraint<Fp3> alignment;
    alignment.name = "stage3.range.ctl_alignment.active_boolean_square";
    alignment.kind = aq::AirKind::kEverywhere;
    alignment.alg_degree = 4;
    alignment.eval = [](const std::vector<Fp3>& row,
                        const std::vector<Fp3>&) {
        const Fp3 boolean_identity =
            gf::Mul(row[kRCStage3RangeActive],
                    gf::Sub(row[kRCStage3RangeActive], Fp3::One()));
        return gf::Mul(boolean_identity, boolean_identity);
    };
    out.constraints.push_back(std::move(alignment));

    const uint64_t expected_quotient =
        3 * static_cast<uint64_t>(pin.n_rows) - 3;
    if (expected_quotient > std::numeric_limits<uint32_t>::max() ||
        out.QuotientLen() != expected_quotient) {
        out = {};
        return Fail(why, "range_ctl_alignment_degree");
    }
    return true;
}

bool VerifyRCStage3SignedRangeCtlAlignedShard(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    const aq::AirQuotientProof<Fp3>& proof,
    std::string* why)
{
    aq::AirConstraintSystem<Fp3> cs;
    if (!ResolveRCStage3SignedRangeCtlAlignedConstraintSystem(
            manifest, pin, cs, why)) {
        return false;
    }
    const uint32_t n_coeffs =
        NextPowerOfTwo(3 * static_cast<uint64_t>(pin.n_rows) - 3);
    if (n_coeffs == 0 ||
        proof.batch.columns.size() !=
            kRCStage3SignedRangeColumns + 1 ||
        proof.batch.column_len.size() !=
            kRCStage3SignedRangeColumns + 1 ||
        proof.batch.n_coeffs != n_coeffs) {
        return Fail(why, "range_ctl_aligned_proof_shape");
    }
    for (uint32_t i = 0; i < pin.column_roots.size(); ++i) {
        if (proof.batch.columns[i].root != pin.column_roots[i].root) {
            return Fail(why, "range_ctl_aligned_proof_root");
        }
    }
    const uint256 seed = ComputeRCStage3SignedRangeSeed(pin);
    if (seed.IsNull()) return Fail(why, "range_ctl_aligned_seed");
    std::string air_why;
    if (!aq::AirQuotientVerify<Fp3>(cs, proof, seed, &air_why)) {
        return Fail(why, "range_ctl_aligned_air:" + air_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:gemm_extract:signed_range_ctl_domain_aligned_ok";
    }
    return true;
}

uint32_t RCStage3SignedRangeGlobalShardOrdinal(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin)
{
    if (!ValidateRangePinShape(manifest, pin, true, nullptr)) {
        return std::numeric_limits<uint32_t>::max();
    }
    uint64_t ordinal = pin.shard_index;
    for (uint32_t layer = 0; layer < pin.layer_ordinal; ++layer) {
        ordinal +=
            (manifest.layers[layer].gemm_cell_count +
             kRCStage3SignedRangeMaxShardRows - 1) /
            kRCStage3SignedRangeMaxShardRows;
    }
    if (ordinal >
        std::numeric_limits<uint32_t>::max() -
            kRCStage3RangeCtlBusBase - 1) {
        return std::numeric_limits<uint32_t>::max();
    }
    return static_cast<uint32_t>(ordinal);
}

RCStage3CtlSchedule BuildRCStage3SignedRangeCtlSchedule(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    bool producer)
{
    RCStage3CtlSchedule out;
    if (RCStage3SignedRangeGlobalShardOrdinal(manifest, pin) ==
        std::numeric_limits<uint32_t>::max()) {
        return out;
    }
    out.events.reserve(pin.logical_rows);
    for (uint32_t address = 0; address < pin.logical_rows; ++address) {
        out.events.push_back(
            {kRCStage3RangeCtlNamespace, pin.layer_ordinal, address,
             static_cast<int8_t>(producer ? 1 : -1)});
    }
    return out;
}

uint256 CommitRCStage3SignedRangeCtlScheduleDescriptor(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    bool producer)
{
    const RCStage3CtlSchedule schedule =
        BuildRCStage3SignedRangeCtlSchedule(manifest, pin, producer);
    return CommitRCStage3CtlSchedule(schedule);
}

uint256 ComputeRCStage3ExtractInputShardObligation(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    const uint256& extract_input_shard_root,
    const uint256& extract_input_opening_commitment)
{
    if (!ValidateRangePinShape(manifest, pin, true, nullptr) ||
        extract_input_shard_root.IsNull() ||
        extract_input_opening_commitment.IsNull()) {
        return {};
    }
    const auto& layer = manifest.layers[pin.layer_ordinal];
    Writer w;
    w.Uint256(ComputeRCStage3GemmExtractManifestCommitment(manifest));
    w.Uint256(layer.bindings.extract_input_root);
    w.Uint256(extract_input_shard_root);
    w.Uint256(extract_input_opening_commitment);
    w.U32(pin.layer_ordinal);
    w.U32(pin.shard_index);
    w.U32(pin.shard_count);
    w.U64(pin.cell_begin);
    w.U32(pin.logical_rows);
    return TaggedHash("BTX_RC_STAGE3_EXTRACT_INPUT_SHARD_V1",
                      w.Take());
}

uint256 ComputeRCStage3SignedRangeCtlTraceCommitment(
    const RCStage3SignedRangePin& pin)
{
    return RangeCtlTraceCommitment(pin);
}

uint256 ComputeRCStage3ExtractCtlTraceCommitment(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    const RCStage3SignedRangeCtlBinding& binding)
{
    return ExtractCtlTraceCommitment(manifest, pin, binding);
}

RCStage3CtlManifest BuildRCStage3SignedRangeCtlManifest(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    const RCStage3SignedRangeCtlBinding& binding)
{
    RCStage3CtlManifest out;
    const uint32_t ordinal =
        RCStage3SignedRangeGlobalShardOrdinal(manifest, pin);
    if (ordinal == std::numeric_limits<uint32_t>::max()) return out;
    const uint256 obligation = ComputeRCStage3ExtractInputShardObligation(
        manifest, pin, binding.extract_input_shard_root,
        binding.extract_input_opening_commitment);
    if (obligation.IsNull()) return out;
    out.bus_id = kRCStage3RangeCtlBusBase + ordinal + 1;
    out.transcript_seed = obligation;
    out.participants = {
        {RCStage3RelationRole::EpisodeGemm, pin.logical_rows,
         pin.logical_rows, 0,
         CommitRCStage3SignedRangeCtlScheduleDescriptor(
             manifest, pin, true)},
        {RCStage3RelationRole::EpisodeExtract, pin.logical_rows,
         0, pin.logical_rows,
         CommitRCStage3SignedRangeCtlScheduleDescriptor(
             manifest, pin, false)},
    };
    return out;
}

bool VerifyRCStage3SignedRangeCtlBinding(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    const RCStage3SignedRangeCtlBinding& binding,
    std::string* why)
{
    if (!ValidateRangePinShape(manifest, pin, true, why)) return false;
    const RCStage3CtlManifest ctl_manifest =
        BuildRCStage3SignedRangeCtlManifest(manifest, pin, binding);
    if (ctl_manifest.bus_id == 0 ||
        ctl_manifest.participants.size() != 2) {
        return Fail(why, "ctl_manifest");
    }
    const uint256 expected_range_trace = RangeCtlTraceCommitment(pin);
    const uint256 expected_extract_trace =
        ExtractCtlTraceCommitment(manifest, pin, binding);
    if (expected_range_trace.IsNull() ||
        expected_extract_trace.IsNull()) {
        return Fail(why, "ctl_trace_commitment");
    }
    const auto exact_child = [&](const RCStage3CtlChildPin& child,
                                 const RCStage3CtlParticipantSpec& spec,
                                 const uint256& trace,
                                 bool producer) {
        return child.role == spec.role &&
               child.bus_id == ctl_manifest.bus_id &&
               child.event_count == pin.logical_rows &&
               child.send_count ==
                   (producer ? pin.logical_rows : 0) &&
               child.receive_count ==
                   (producer ? 0 : pin.logical_rows) &&
               child.schedule_commitment ==
                   spec.schedule_commitment &&
               child.trace_commitment == trace;
    };
    if (!exact_child(binding.range_child,
                     ctl_manifest.participants[0],
                     expected_range_trace, true) ||
        !exact_child(binding.extract_child,
                     ctl_manifest.participants[1],
                     expected_extract_trace, false)) {
        return Fail(why, "ctl_child_binding");
    }
    if (!VerifyRCStage3CtlPublicPinComposition(
            ctl_manifest,
            {binding.range_child, binding.extract_child}, why)) {
        return Fail(why, "ctl_composition");
    }
    if (why != nullptr) {
        *why = "stage3:gemm_extract:range_extract_ctl_pins_ok_"
               "recursive_air_execution_pending";
    }
    return true;
}

bool VerifyRCStage3SignedRangeCtlClosure(
    const RCStage3GemmExtractManifest& manifest,
    const std::vector<RCStage3SignedRangeCtlShard>& shards,
    std::string* why)
{
    if (!ValidateRCStage3GemmExtractManifest(manifest, why)) return false;
    uint64_t expected_count{0};
    for (const auto& layer : manifest.layers) {
        expected_count +=
            (layer.gemm_cell_count +
             kRCStage3SignedRangeMaxShardRows - 1) /
            kRCStage3SignedRangeMaxShardRows;
    }
    if (expected_count != shards.size()) {
        return Fail(why, "ctl_closure_shard_count");
    }
    size_t cursor{0};
    for (uint32_t layer = 0; layer < manifest.layers.size(); ++layer) {
        const uint32_t count = static_cast<uint32_t>(
            (manifest.layers[layer].gemm_cell_count +
             kRCStage3SignedRangeMaxShardRows - 1) /
            kRCStage3SignedRangeMaxShardRows);
        for (uint32_t shard = 0; shard < count; ++shard, ++cursor) {
            if (shards[cursor].pin.layer_ordinal != layer ||
                shards[cursor].pin.shard_index != shard) {
                return Fail(why, "ctl_closure_order");
            }
            if (!VerifyRCStage3SignedRangeCtlBinding(
                    manifest, shards[cursor].pin,
                    shards[cursor].binding, why)) {
                return false;
            }
        }
    }
    if (why != nullptr) {
        *why = "stage3:gemm_extract:all_range_extract_ctl_pins_ok_"
               "recursive_air_execution_pending";
    }
    return true;
}

uint256 ComputeRCStage3SignedRangeCtlLayerCommitment(
    const RCStage3GemmExtractManifest& manifest,
    uint32_t layer_ordinal,
    const std::vector<RCStage3SignedRangeCtlShard>& shards,
    bool range_children,
    std::string* why)
{
    if (!ValidateRCStage3GemmExtractManifest(manifest, why) ||
        layer_ordinal >= manifest.layers.size()) {
        return {};
    }
    const uint32_t expected = static_cast<uint32_t>(
        (manifest.layers[layer_ordinal].gemm_cell_count +
         kRCStage3SignedRangeMaxShardRows - 1) /
        kRCStage3SignedRangeMaxShardRows);
    std::vector<const RCStage3SignedRangeCtlShard*> group;
    for (const auto& shard : shards) {
        if (shard.pin.layer_ordinal == layer_ordinal) {
            group.push_back(&shard);
        }
    }
    if (group.size() != expected) {
        Fail(why, "ctl_layer_shard_count");
        return {};
    }
    Writer w;
    w.Uint256(ComputeRCStage3GemmExtractManifestCommitment(manifest));
    w.U32(layer_ordinal);
    w.U8(range_children ? 1 : 0);
    w.U32(expected);
    for (uint32_t i = 0; i < group.size(); ++i) {
        if (group[i]->pin.shard_index != i) {
            Fail(why, "ctl_layer_order");
            return {};
        }
        const auto& child = range_children
            ? group[i]->binding.range_child
            : group[i]->binding.extract_child;
        const uint256 commitment = CommitRCStage3CtlChildPin(child);
        if (commitment.IsNull()) {
            Fail(why, "ctl_layer_child");
            return {};
        }
        w.Uint256(commitment);
    }
    return TaggedHash(
        range_children
            ? "BTX_RC_STAGE3_RANGE_CTL_LAYER_V1"
            : "BTX_RC_STAGE3_EXTRACT_CTL_LAYER_V1",
        w.Take());
}

bool VerifyRCStage3SignedRangeClosure(
    const RCStage3GemmExtractManifest& manifest,
    const std::vector<RCStage3SignedRangeShardProof>& shards,
    std::string* why)
{
    if (!ValidateRCStage3GemmExtractManifest(manifest, why)) return false;
    uint64_t expected_count{0};
    for (const auto& layer : manifest.layers) {
        expected_count +=
            (layer.gemm_cell_count + kRCStage3SignedRangeMaxShardRows - 1) /
            kRCStage3SignedRangeMaxShardRows;
    }
    if (expected_count != shards.size()) {
        return Fail(why, "range_closure_shard_count");
    }
    size_t cursor{0};
    for (uint32_t layer = 0; layer < manifest.layers.size(); ++layer) {
        const uint32_t count = static_cast<uint32_t>(
            (manifest.layers[layer].gemm_cell_count +
             kRCStage3SignedRangeMaxShardRows - 1) /
            kRCStage3SignedRangeMaxShardRows);
        for (uint32_t shard = 0; shard < count; ++shard, ++cursor) {
            if (shards[cursor].pin.layer_ordinal != layer ||
                shards[cursor].pin.shard_index != shard) {
                return Fail(why, "range_closure_order");
            }
            if (!VerifyRCStage3SignedRangeShard(
                    manifest, shards[cursor].pin,
                    shards[cursor].proof, why)) {
                return false;
            }
        }
    }
    if (why != nullptr) {
        *why =
            "stage3:gemm_extract:all_accumulator_cells_range_proved_"
            "ctl_extract_input_link_pending";
    }
    return true;
}

bool VerifyRCStage3SignedRangeProofCtlClosure(
    const RCStage3GemmExtractManifest& manifest,
    const std::vector<RCStage3SignedRangeShardProof>& range_shards,
    const std::vector<RCStage3SignedRangeCtlShard>& ctl_shards,
    std::string* why)
{
    if (range_shards.size() != ctl_shards.size()) {
        return Fail(why, "range_ctl_closure_count");
    }
    for (size_t i = 0; i < range_shards.size(); ++i) {
        if (!(range_shards[i].pin == ctl_shards[i].pin)) {
            return Fail(why, "range_ctl_closure_pin");
        }
    }
    if (!VerifyRCStage3SignedRangeClosure(
            manifest, range_shards, why) ||
        !VerifyRCStage3SignedRangeCtlClosure(
            manifest, ctl_shards, why)) {
        return false;
    }
    if (why != nullptr) {
        *why = "stage3:gemm_extract:range_proofs_ctl_pins_bound_"
               "recursive_ctl_air_execution_pending";
    }
    return true;
}

uint256 ComputeRCStage3ExtractInputLayerRoot(
    const RCStage3GemmExtractManifest& manifest,
    uint32_t layer_ordinal,
    const std::vector<uint256>& ordered_shard_roots,
    std::string* why)
{
    if (!ValidateRCStage3GemmExtractManifest(manifest, why) ||
        layer_ordinal >= manifest.layers.size()) {
        Fail(why, "extract_opening_layer");
        return {};
    }
    const auto& layer = manifest.layers[layer_ordinal];
    const uint32_t shard_count = ExpectedRangeShardCount(layer);
    if (shard_count == 0 ||
        ordered_shard_roots.size() != shard_count) {
        Fail(why, "extract_opening_shard_count");
        return {};
    }
    const uint32_t tree_width = MerkleTreeWidth(shard_count);
    if (tree_width == 0) {
        Fail(why, "extract_opening_tree_width");
        return {};
    }
    std::vector<uint256> level;
    level.reserve(tree_width);
    for (uint32_t i = 0; i < tree_width; ++i) {
        const uint256 leaf =
            i < shard_count
                ? ExtractInputActualLeaf(
                      manifest, layer, i, shard_count,
                      ordered_shard_roots[i])
                : ExtractInputPaddingLeaf(
                      manifest, layer, i, shard_count);
        if (leaf.IsNull()) {
            Fail(why, "extract_opening_null_leaf");
            return {};
        }
        level.push_back(leaf);
    }
    uint32_t depth = 0;
    while (level.size() > 1) {
        std::vector<uint256> parents;
        parents.reserve(level.size() / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            const uint256 parent = ExtractInputParent(
                manifest, layer, depth, level[i], level[i + 1]);
            if (parent.IsNull()) {
                Fail(why, "extract_opening_null_parent");
                return {};
            }
            parents.push_back(parent);
        }
        level = std::move(parents);
        ++depth;
    }
    return WrapExtractInputLayerRoot(
        manifest, layer, shard_count, level.front());
}

std::optional<RCStage3ExtractInputShardOpening>
BuildRCStage3ExtractInputShardOpening(
    const RCStage3GemmExtractManifest& manifest,
    uint32_t layer_ordinal,
    const std::vector<uint256>& ordered_shard_roots,
    uint32_t shard_index,
    std::string* why)
{
    if (!ValidateRCStage3GemmExtractManifest(manifest, why) ||
        layer_ordinal >= manifest.layers.size()) {
        return FailOptional<RCStage3ExtractInputShardOpening>(
            why, "extract_opening_layer");
    }
    const auto& layer = manifest.layers[layer_ordinal];
    const uint32_t shard_count = ExpectedRangeShardCount(layer);
    if (shard_count == 0 ||
        ordered_shard_roots.size() != shard_count ||
        shard_index >= shard_count) {
        return FailOptional<RCStage3ExtractInputShardOpening>(
            why, "extract_opening_shard_count");
    }
    const uint32_t tree_width = MerkleTreeWidth(shard_count);
    if (tree_width == 0) {
        return FailOptional<RCStage3ExtractInputShardOpening>(
            why, "extract_opening_tree_width");
    }

    std::vector<uint256> level;
    level.reserve(tree_width);
    for (uint32_t i = 0; i < tree_width; ++i) {
        const uint256 leaf =
            i < shard_count
                ? ExtractInputActualLeaf(
                      manifest, layer, i, shard_count,
                      ordered_shard_roots[i])
                : ExtractInputPaddingLeaf(
                      manifest, layer, i, shard_count);
        if (leaf.IsNull()) {
            return FailOptional<RCStage3ExtractInputShardOpening>(
                why, "extract_opening_null_leaf");
        }
        level.push_back(leaf);
    }

    RCStage3ExtractInputShardOpening opening;
    opening.layer_ordinal = layer_ordinal;
    opening.shard_index = shard_index;
    opening.shard_count = shard_count;
    const uint64_t offset =
        static_cast<uint64_t>(shard_index) *
        kRCStage3SignedRangeMaxShardRows;
    opening.cell_begin = layer.gemm_cell_begin + offset;
    opening.logical_rows = static_cast<uint32_t>(
        std::min<uint64_t>(
            layer.gemm_cell_count - offset,
            kRCStage3SignedRangeMaxShardRows));
    opening.shard_root = ordered_shard_roots[shard_index];

    uint32_t cursor = shard_index;
    uint32_t depth = 0;
    while (level.size() > 1) {
        opening.authentication_path.push_back(level[cursor ^ 1U]);
        std::vector<uint256> parents;
        parents.reserve(level.size() / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            const uint256 parent = ExtractInputParent(
                manifest, layer, depth, level[i], level[i + 1]);
            if (parent.IsNull()) {
                return FailOptional<RCStage3ExtractInputShardOpening>(
                    why, "extract_opening_null_parent");
            }
            parents.push_back(parent);
        }
        level = std::move(parents);
        cursor >>= 1;
        ++depth;
    }
    return opening;
}

bool VerifyRCStage3ExtractInputShardOpening(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3ExtractInputShardOpening& opening,
    std::string* why)
{
    if (!ValidateRCStage3GemmExtractManifest(manifest, why) ||
        opening.layer_ordinal >= manifest.layers.size()) {
        return Fail(why, "extract_opening_layer");
    }
    const auto& layer = manifest.layers[opening.layer_ordinal];
    const uint32_t shard_count = ExpectedRangeShardCount(layer);
    if (shard_count == 0 ||
        opening.shard_count != shard_count ||
        opening.shard_index >= shard_count ||
        opening.shard_root.IsNull()) {
        return Fail(why, "extract_opening_position");
    }
    const uint64_t offset =
        static_cast<uint64_t>(opening.shard_index) *
        kRCStage3SignedRangeMaxShardRows;
    const uint32_t expected_rows = static_cast<uint32_t>(
        std::min<uint64_t>(
            layer.gemm_cell_count - offset,
            kRCStage3SignedRangeMaxShardRows));
    if (opening.cell_begin != layer.gemm_cell_begin + offset ||
        opening.logical_rows != expected_rows) {
        return Fail(why, "extract_opening_interval");
    }
    uint32_t tree_width = MerkleTreeWidth(shard_count);
    size_t expected_depth = 0;
    for (uint32_t width = tree_width; width > 1; width >>= 1) {
        ++expected_depth;
    }
    if (tree_width == 0 ||
        opening.authentication_path.size() != expected_depth) {
        return Fail(why, "extract_opening_path_length");
    }
    uint256 node = ExtractInputActualLeaf(
        manifest, layer, opening.shard_index, shard_count,
        opening.shard_root);
    uint32_t cursor = opening.shard_index;
    for (uint32_t depth = 0;
         depth < opening.authentication_path.size();
         ++depth) {
        const uint256& sibling = opening.authentication_path[depth];
        if (sibling.IsNull()) {
            return Fail(why, "extract_opening_null_sibling");
        }
        node = (cursor & 1U) == 0
            ? ExtractInputParent(
                  manifest, layer, depth, node, sibling)
            : ExtractInputParent(
                  manifest, layer, depth, sibling, node);
        if (node.IsNull()) {
            return Fail(why, "extract_opening_parent");
        }
        cursor >>= 1;
    }
    const uint256 root = WrapExtractInputLayerRoot(
        manifest, layer, shard_count, node);
    if (root.IsNull() ||
        root != layer.bindings.extract_input_root) {
        return Fail(why, "extract_opening_layer_root");
    }
    if (why != nullptr) {
        *why =
            "stage3:gemm_extract:extract_input_shard_authenticated_to_"
            "layer_root_hash_air_and_recursive_consumption_pending";
    }
    return true;
}

bool VerifyRCStage3ExtractInputLayerOpeningClosure(
    const RCStage3GemmExtractManifest& manifest,
    uint32_t layer_ordinal,
    const std::vector<RCStage3ExtractInputShardOpening>& openings,
    std::string* why)
{
    if (!ValidateRCStage3GemmExtractManifest(manifest, why) ||
        layer_ordinal >= manifest.layers.size()) {
        return Fail(why, "extract_opening_closure_layer");
    }
    const uint32_t expected =
        ExpectedRangeShardCount(manifest.layers[layer_ordinal]);
    if (expected == 0 || openings.size() != expected) {
        return Fail(why, "extract_opening_closure_count");
    }
    std::vector<uint256> roots;
    roots.reserve(expected);
    for (uint32_t i = 0; i < expected; ++i) {
        const auto& opening = openings[i];
        if (opening.layer_ordinal != layer_ordinal ||
            opening.shard_index != i) {
            return Fail(why, "extract_opening_closure_order");
        }
        if (!VerifyRCStage3ExtractInputShardOpening(
                manifest, opening, why)) {
            return false;
        }
        roots.push_back(opening.shard_root);
    }
    const uint256 root = ComputeRCStage3ExtractInputLayerRoot(
        manifest, layer_ordinal, roots, why);
    if (root.IsNull() ||
        root != manifest.layers[layer_ordinal]
                    .bindings.extract_input_root) {
        return Fail(why, "extract_opening_closure_root");
    }
    if (why != nullptr) {
        *why =
            "stage3:gemm_extract:all_extract_input_shards_opened_to_"
            "layer_root_hash_air_and_recursive_consumption_pending";
    }
    return true;
}

uint256 ComputeRCStage3ExtractInputShardOpeningCommitment(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    const RCStage3ExtractInputShardOpening& opening)
{
    if (!ValidateRangePinShape(manifest, pin, true, nullptr) ||
        pin.layer_ordinal != opening.layer_ordinal ||
        pin.shard_index != opening.shard_index ||
        pin.shard_count != opening.shard_count ||
        pin.cell_begin != opening.cell_begin ||
        pin.logical_rows != opening.logical_rows ||
        pin.column_roots[kRCStage3RangeValue].root !=
            opening.shard_root ||
        !VerifyRCStage3ExtractInputShardOpening(
            manifest, opening, nullptr)) {
        return {};
    }
    Writer w;
    w.Uint256(ComputeRCStage3GemmExtractManifestCommitment(manifest));
    w.Uint256(ComputeRCStage3SignedRangePinCommitment(pin));
    w.U32(opening.layer_ordinal);
    w.U32(opening.shard_index);
    w.U32(opening.shard_count);
    w.U64(opening.cell_begin);
    w.U32(opening.logical_rows);
    w.Uint256(opening.shard_root);
    w.U32(static_cast<uint32_t>(
        opening.authentication_path.size()));
    for (const auto& sibling : opening.authentication_path) {
        w.Uint256(sibling);
    }
    return TaggedHash(
        "BTX_RC_STAGE3_EXTRACT_INPUT_OPENING_V1", w.Take());
}

bool VerifyRCStage3SignedRangeExecutedCtlShard(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangeExecutedCtlShardProof& shard,
    std::string* why)
{
    if (!VerifyRCStage3SignedRangeCtlAlignedShard(
            manifest, shard.pin, shard.range_proof, why)) {
        return false;
    }

    RCStage3SignedRangeCtlBinding manifest_binding;
    manifest_binding.extract_input_shard_root =
        shard.binding.extract_input_shard_root;
    manifest_binding.extract_input_opening_commitment =
        shard.binding.extract_input_opening_commitment;
    const RCStage3CtlManifest ctl_manifest =
        BuildRCStage3SignedRangeCtlManifest(
            manifest, shard.pin, manifest_binding);
    if (ctl_manifest.participants.size() != 2 ||
        ctl_manifest.bus_id == 0) {
        return Fail(why, "executed_ctl_manifest");
    }
    const std::vector<RCStage3CtlSchedule> schedules{
        BuildRCStage3SignedRangeCtlSchedule(
            manifest, shard.pin, true),
        BuildRCStage3SignedRangeCtlSchedule(
            manifest, shard.pin, false),
    };
    const std::vector<RCStage3CtlChildPin> pins{
        shard.binding.range_child,
        shard.binding.extract_child,
    };
    const std::vector<RCStage3CtlAirProof> proofs{
        shard.range_ctl_proof,
        shard.extract_ctl_proof,
    };

    using namespace stage3_ctl_col;
    if (shard.range_ctl_proof.batch.columns.size() <= VALUE ||
        shard.extract_ctl_proof.batch.columns.size() <= VALUE ||
        shard.pin.column_roots.size() <= kRCStage3RangeValue) {
        return Fail(why, "executed_ctl_proof_shape");
    }
    const uint256& range_value_root =
        shard.pin.column_roots[kRCStage3RangeValue].root;
    if (shard.range_ctl_proof.batch.columns[VALUE].root !=
        range_value_root) {
        return Fail(why, "executed_ctl_range_value_root");
    }
    if (shard.extract_ctl_proof.batch.columns[VALUE].root !=
        shard.binding.extract_input_shard_root) {
        return Fail(why, "executed_ctl_extract_value_root");
    }

    std::string ctl_why;
    if (!VerifyRCStage3CtlBusAirProofs(
            ctl_manifest, pins, schedules, proofs, &ctl_why)) {
        return Fail(why, "executed_ctl_air:" + ctl_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:gemm_extract:range_value_root_equals_executed_ctl_"
            "producer_and_extract_shard_root_equals_executed_ctl_consumer_"
            "extract_opening_and_recursive_consumption_pending";
    }
    return true;
}

bool VerifyRCStage3SignedRangeExecutedCtlClosure(
    const RCStage3GemmExtractManifest& manifest,
    const std::vector<RCStage3SignedRangeExecutedCtlShardProof>& shards,
    std::string* why)
{
    if (!ValidateRCStage3GemmExtractManifest(manifest, why)) return false;
    uint64_t expected_count = 0;
    for (const auto& layer : manifest.layers) {
        expected_count +=
            (layer.gemm_cell_count +
             kRCStage3SignedRangeMaxShardRows - 1) /
            kRCStage3SignedRangeMaxShardRows;
    }
    if (expected_count != shards.size()) {
        return Fail(why, "executed_ctl_closure_shard_count");
    }
    size_t cursor = 0;
    for (uint32_t layer = 0; layer < manifest.layers.size(); ++layer) {
        const uint32_t count = static_cast<uint32_t>(
            (manifest.layers[layer].gemm_cell_count +
             kRCStage3SignedRangeMaxShardRows - 1) /
            kRCStage3SignedRangeMaxShardRows);
        for (uint32_t shard_index = 0;
             shard_index < count;
             ++shard_index, ++cursor) {
            if (shards[cursor].pin.layer_ordinal != layer ||
                shards[cursor].pin.shard_index != shard_index) {
                return Fail(why, "executed_ctl_closure_order");
            }
            if (!VerifyRCStage3SignedRangeExecutedCtlShard(
                    manifest, shards[cursor], why)) {
                return false;
            }
        }
    }
    if (why != nullptr) {
        *why =
            "stage3:gemm_extract:all_range_ctl_value_roots_executed_"
            "extract_openings_and_recursive_consumption_pending";
    }
    return true;
}

bool VerifyRCStage3SignedRangeExecutedCtlOpenedShard(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangeExecutedCtlOpenedShardProof& shard,
    std::string* why)
{
    if (!VerifyRCStage3SignedRangeExecutedCtlShard(
            manifest, shard.relation, why)) {
        return false;
    }
    const auto& pin = shard.relation.pin;
    const auto& binding = shard.relation.binding;
    const auto& opening = shard.extract_input_opening;
    if (pin.layer_ordinal != opening.layer_ordinal ||
        pin.shard_index != opening.shard_index ||
        pin.shard_count != opening.shard_count ||
        pin.cell_begin != opening.cell_begin ||
        pin.logical_rows != opening.logical_rows ||
        binding.extract_input_shard_root != opening.shard_root) {
        return Fail(why, "opened_ctl_interval_or_root");
    }
    if (!VerifyRCStage3ExtractInputShardOpening(
            manifest, opening, why)) {
        return false;
    }
    const uint256 commitment =
        ComputeRCStage3ExtractInputShardOpeningCommitment(
            manifest, pin, opening);
    if (commitment.IsNull() ||
        binding.extract_input_opening_commitment != commitment) {
        return Fail(why, "opened_ctl_opening_commitment");
    }
    if (why != nullptr) {
        *why =
            "stage3:gemm_extract:signed_range_and_executed_ctl_value_"
            "root_authenticated_to_layer_extract_input_root_"
            "hash_air_and_recursive_consumption_pending";
    }
    return true;
}

bool VerifyRCStage3SignedRangeExecutedCtlOpenedClosure(
    const RCStage3GemmExtractManifest& manifest,
    const std::vector<RCStage3SignedRangeExecutedCtlOpenedShardProof>& shards,
    std::string* why)
{
    if (!ValidateRCStage3GemmExtractManifest(manifest, why)) return false;
    uint64_t expected_total = 0;
    for (const auto& layer : manifest.layers) {
        expected_total += ExpectedRangeShardCount(layer);
    }
    if (expected_total != shards.size()) {
        return Fail(why, "opened_ctl_closure_count");
    }

    size_t cursor = 0;
    for (uint32_t layer = 0; layer < manifest.layers.size(); ++layer) {
        const uint32_t count =
            ExpectedRangeShardCount(manifest.layers[layer]);
        std::vector<RCStage3ExtractInputShardOpening> openings;
        openings.reserve(count);
        for (uint32_t shard_index = 0;
             shard_index < count;
             ++shard_index, ++cursor) {
            const auto& shard = shards[cursor];
            if (shard.relation.pin.layer_ordinal != layer ||
                shard.relation.pin.shard_index != shard_index ||
                shard.extract_input_opening.layer_ordinal != layer ||
                shard.extract_input_opening.shard_index != shard_index) {
                return Fail(why, "opened_ctl_closure_order");
            }
            if (!VerifyRCStage3SignedRangeExecutedCtlOpenedShard(
                    manifest, shard, why)) {
                return false;
            }
            openings.push_back(shard.extract_input_opening);
        }
        if (!VerifyRCStage3ExtractInputLayerOpeningClosure(
                manifest, layer, openings, why)) {
            return false;
        }
    }
    if (why != nullptr) {
        *why =
            "stage3:gemm_extract:all_executed_range_ctl_shards_"
            "authenticated_to_layer_roots_hash_air_and_recursive_"
            "consumption_pending";
    }
    return true;
}

bool ValidateRCStage3GemmExtractObligationManifest(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3GemmExtractObligationManifest& obligations,
    std::string* why)
{
    if (!ValidateRCStage3GemmExtractManifest(manifest, why)) return false;
    const uint256 manifest_commitment =
        ComputeRCStage3GemmExtractManifestCommitment(manifest);
    if (obligations.statement_commitment !=
            manifest.statement_commitment ||
        obligations.manifest_commitment != manifest_commitment) {
        return Fail(why, "obligation_manifest_binding");
    }
    if (obligations.layers.size() != manifest.layers.size()) {
        return Fail(why, "obligation_layer_count");
    }
    for (uint32_t i = 0; i < obligations.layers.size(); ++i) {
        const auto& expected = manifest.layers[i];
        const auto& actual = obligations.layers[i];
        if (actual.layer_ordinal != i ||
            actual.operand_a_root != expected.bindings.operand_a_root ||
            actual.operand_b_root != expected.bindings.operand_b_root ||
            actual.gemm_y_root != expected.bindings.gemm_y_root ||
            actual.extract_input_root !=
                expected.bindings.extract_input_root ||
            actual.extract_output_root !=
                expected.bindings.extract_output_root ||
            actual.sumcheck_commitment !=
                expected.bindings.gemm_proof_root ||
            actual.extract_recursive_proof_commitment !=
                expected.bindings.extract_recursive_root ||
            actual.scale_schedule_proof_commitment !=
                expected.bindings.scale_schedule_root) {
            return Fail(why, "obligation_root_substitution");
        }
        if (actual.operand_a_opening_commitment.IsNull() ||
            actual.operand_b_opening_commitment.IsNull() ||
            actual.gemm_y_opening_commitment.IsNull() ||
            actual.signed_range_closure_commitment.IsNull() ||
            actual.range_ctl_child_commitment.IsNull() ||
            actual.extract_ctl_child_commitment.IsNull()) {
            return Fail(why, "obligation_missing_proof");
        }
    }
    return true;
}

uint256 ComputeRCStage3GemmExtractObligationCommitment(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3GemmExtractObligationManifest& obligations)
{
    if (!ValidateRCStage3GemmExtractObligationManifest(
            manifest, obligations, nullptr)) {
        return {};
    }
    Writer w;
    w.Uint256(obligations.statement_commitment);
    w.Uint256(obligations.manifest_commitment);
    w.U32(static_cast<uint32_t>(obligations.layers.size()));
    for (const auto& layer : obligations.layers) {
        w.U32(layer.layer_ordinal);
        w.Uint256(layer.operand_a_root);
        w.Uint256(layer.operand_b_root);
        w.Uint256(layer.gemm_y_root);
        w.Uint256(layer.extract_input_root);
        w.Uint256(layer.extract_output_root);
        w.Uint256(layer.operand_a_opening_commitment);
        w.Uint256(layer.operand_b_opening_commitment);
        w.Uint256(layer.gemm_y_opening_commitment);
        w.Uint256(layer.sumcheck_commitment);
        w.Uint256(layer.signed_range_closure_commitment);
        w.Uint256(layer.extract_recursive_proof_commitment);
        w.Uint256(layer.scale_schedule_proof_commitment);
        w.Uint256(layer.range_ctl_child_commitment);
        w.Uint256(layer.extract_ctl_child_commitment);
    }
    return TaggedHash("BTX_RC_STAGE3_GEMM_EXTRACT_OBLIGATIONS_V1",
                      w.Take());
}

bool ValidateRCStage3GemmExtractObligationCtlBinding(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3GemmExtractObligationManifest& obligations,
    const std::vector<RCStage3SignedRangeCtlShard>& ctl_shards,
    std::string* why)
{
    if (!ValidateRCStage3GemmExtractObligationManifest(
            manifest, obligations, why) ||
        !VerifyRCStage3SignedRangeCtlClosure(
            manifest, ctl_shards, why)) {
        return false;
    }
    for (uint32_t layer = 0; layer < obligations.layers.size(); ++layer) {
        const uint256 range =
            ComputeRCStage3SignedRangeCtlLayerCommitment(
                manifest, layer, ctl_shards, true, why);
        const uint256 extract =
            ComputeRCStage3SignedRangeCtlLayerCommitment(
                manifest, layer, ctl_shards, false, why);
        if (range.IsNull() || extract.IsNull() ||
            obligations.layers[layer].range_ctl_child_commitment !=
                range ||
            obligations.layers[layer].extract_ctl_child_commitment !=
                extract) {
            return Fail(why, "obligation_ctl_commitment");
        }
    }
    if (why != nullptr) {
        *why = "stage3:gemm_extract:obligation_ctl_pins_bound_"
               "recursive_air_execution_pending";
    }
    return true;
}

} // namespace matmul::v4::rc
