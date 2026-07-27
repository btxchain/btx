// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_recursive.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <matmul/matmul_v4_rc_stage3_composition.h>
#include <matmul/matmul_v4_rc_stage3_global_soundness_ledger.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>

#include <algorithm>
#include <array>
#include <limits>
#include <utility>

namespace matmul::v4::rc {
namespace {

using AlgB3 = air_quotient::AirFriBackendAlg<gkr_field::Fp3>;
using AirProof = air_quotient::AirQuotientProof<gkr_field::Fp3, AlgB3>;
using ChildPI = air_recurse::ChildPublicInputs;
using gkr_field::Fp3;

// V3: the role seed now absorbs the node's tree position (node_id, slot_index)
// so distinct recursion nodes derive distinct FS bases (soundness blocker P4).
constexpr char RECURSIVE_SEED_DOMAIN[] = "BTX_RC_STAGE3_RECURSIVE_ROLE_V3";
constexpr char CHILD_PINS_DOMAIN[] = "BTX_RC_STAGE3_RECURSIVE_PINS_V2";
constexpr char CHILD_FS_POINT_DOMAIN[] =
    "BTX_RC_STAGE3_RECURSIVE_CHILD_FS_V1";
constexpr uint32_t MAX_VECTOR_ITEMS = kRCFri3AlgBatchMaxColumns;
constexpr uint32_t MAX_PATH_DEPTH = 64;

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) *why = "stage3:recursive:" + message;
    return false;
}

template <typename T>
std::optional<T> FailOptional(std::string* why, const std::string& message)
{
    Fail(why, message);
    return std::nullopt;
}

bool IsPowerOfTwo(uint32_t value)
{
    return value != 0 && (value & (value - 1)) == 0;
}

uint32_t Log2Exact(uint32_t value)
{
    uint32_t out = 0;
    while (value > 1) {
        value >>= 1;
        ++out;
    }
    return out;
}

bool IsKnownRole(RCStage3RelationRole role)
{
    const auto roles = RequiredRCStage3RelationRoles(RCStage3StatementKind::Composed);
    return std::find(roles.begin(), roles.end(), role) != roles.end();
}

bool IsCanonical(const Fp3& value)
{
    return value.c0 < gkr_field::kP && value.c1 < gkr_field::kP &&
           value.c2 < gkr_field::kP;
}

bool IsCanonical(const Fri3AlgDigest& value)
{
    return std::all_of(value.begin(), value.end(),
                       [](gkr_field::Fp limb) { return limb < gkr_field::kP; });
}

class Writer {
public:
    void U8(uint8_t value) { m_out.push_back(value); }
    void U16(uint16_t value)
    {
        for (unsigned i = 0; i < 2; ++i) U8(static_cast<uint8_t>(value >> (8 * i)));
    }
    void U32(uint32_t value)
    {
        for (unsigned i = 0; i < 4; ++i) U8(static_cast<uint8_t>(value >> (8 * i)));
    }
    void U64(uint64_t value)
    {
        for (unsigned i = 0; i < 8; ++i) U8(static_cast<uint8_t>(value >> (8 * i)));
    }
    void Uint256(const uint256& value)
    {
        m_out.insert(m_out.end(), value.data(), value.data() + value.size());
    }
    void Fp3Value(const Fp3& value)
    {
        U64(value.c0);
        U64(value.c1);
        U64(value.c2);
    }
    void Digest(const Fri3AlgDigest& value)
    {
        for (gkr_field::Fp limb : value) U64(limb);
    }
    void Bytes(const std::vector<unsigned char>& value)
    {
        m_out.insert(m_out.end(), value.begin(), value.end());
    }
    std::vector<unsigned char> Take() { return std::move(m_out); }

private:
    std::vector<unsigned char> m_out;
};

class Reader {
public:
    explicit Reader(const std::vector<unsigned char>& bytes)
        : m_pos(bytes.data()), m_end(bytes.data() + bytes.size())
    {
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
    bool Fp3Value(Fp3& value)
    {
        return U64(value.c0) && U64(value.c1) && U64(value.c2) &&
               IsCanonical(value);
    }
    bool Digest(Fri3AlgDigest& value)
    {
        for (gkr_field::Fp& limb : value) {
            if (!U64(limb) || limb >= gkr_field::kP) return false;
        }
        return true;
    }
    bool Bytes(size_t count, std::vector<unsigned char>& value)
    {
        if (count > Remaining()) return false;
        value.assign(m_pos, m_pos + count);
        m_pos += count;
        return true;
    }
    size_t Remaining() const { return static_cast<size_t>(m_end - m_pos); }

private:
    const unsigned char* m_pos;
    const unsigned char* m_end;
};

template <typename T, typename WriteElement>
void WriteVector(Writer& writer, const std::vector<T>& values, WriteElement write)
{
    writer.U32(static_cast<uint32_t>(values.size()));
    for (const T& value : values) write(value);
}

template <typename T, typename ReadElement>
bool ReadVector(Reader& reader, std::vector<T>& values, uint32_t max_items,
                size_t min_item_bytes, ReadElement read)
{
    uint32_t count{0};
    if (!reader.U32(count) || count > max_items) return false;
    if (min_item_bytes != 0 && count > reader.Remaining() / min_item_bytes) return false;
    values.resize(count);
    for (T& value : values) {
        if (!read(value)) return false;
    }
    return true;
}

void WriteChildPI(Writer& writer, const ChildPI& pi)
{
    writer.U32(pi.child_n_rows);
    writer.U32(pi.child_w);
    writer.U32(pi.child_quotient_len);
    writer.U32(pi.child_n_coeffs);
    writer.U32(pi.child_n_lde);
    writer.U32(pi.merkle_depth);
    writer.U32(pi.n_folds);
    writer.Digest(pi.row_commit_root);
    writer.Digest(pi.rt_root);
    WriteVector(writer, pi.fold_roots,
                [&](const Fri3AlgDigest& value) { writer.Digest(value); });
    writer.Fp3Value(pi.fri_lambda);
    writer.Fp3Value(pi.z1);
    writer.Fp3Value(pi.z2);
    writer.Fp3Value(pi.w1);
    writer.Fp3Value(pi.w2);
    writer.Fp3Value(pi.final_value);
    writer.Fp3Value(pi.air_lambda);
    WriteVector(writer, pi.fold_challenges,
                [&](const Fp3& value) { writer.Fp3Value(value); });
    WriteVector(writer, pi.column_len,
                [&](uint32_t value) { writer.U32(value); });
    WriteVector(writer, pi.evals_z1,
                [&](const Fp3& value) { writer.Fp3Value(value); });
    WriteVector(writer, pi.evals_z2,
                [&](const Fp3& value) { writer.Fp3Value(value); });
    WriteVector(writer, pi.query_index,
                [&](uint32_t value) { writer.U32(value); });
    WriteVector(writer, pi.endpoint_authority_roots,
                [&](const Fri3AlgDigest& value) { writer.Digest(value); });
}

bool ReadChildPI(Reader& reader, ChildPI& pi)
{
    if (!reader.U32(pi.child_n_rows) || !reader.U32(pi.child_w) ||
        !reader.U32(pi.child_quotient_len) || !reader.U32(pi.child_n_coeffs) ||
        !reader.U32(pi.child_n_lde) || !reader.U32(pi.merkle_depth) ||
        !reader.U32(pi.n_folds) || !reader.Digest(pi.row_commit_root) ||
        !reader.Digest(pi.rt_root)) {
        return false;
    }
    if (!ReadVector(reader, pi.fold_roots, kRCFriMaxFoldLayersHard, 32,
                    [&](Fri3AlgDigest& value) { return reader.Digest(value); }) ||
        !reader.Fp3Value(pi.fri_lambda) || !reader.Fp3Value(pi.z1) ||
        !reader.Fp3Value(pi.z2) || !reader.Fp3Value(pi.w1) ||
        !reader.Fp3Value(pi.w2) || !reader.Fp3Value(pi.final_value) ||
        !reader.Fp3Value(pi.air_lambda) ||
        !ReadVector(reader, pi.fold_challenges, kRCFriMaxFoldLayersHard, 24,
                    [&](Fp3& value) { return reader.Fp3Value(value); }) ||
        !ReadVector(reader, pi.column_len, MAX_VECTOR_ITEMS, 4,
                    [&](uint32_t& value) { return reader.U32(value); }) ||
        !ReadVector(reader, pi.evals_z1, MAX_VECTOR_ITEMS, 24,
                    [&](Fp3& value) { return reader.Fp3Value(value); }) ||
        !ReadVector(reader, pi.evals_z2, MAX_VECTOR_ITEMS, 24,
                    [&](Fp3& value) { return reader.Fp3Value(value); }) ||
        !ReadVector(reader, pi.query_index, kRCFri3AlgMaxQueriesHard, 4,
                    [&](uint32_t& value) { return reader.U32(value); }) ||
        !ReadVector(reader, pi.endpoint_authority_roots,
                    kRCStage3RelationClosureEndpointCount, 32,
                    [&](Fri3AlgDigest& value) { return reader.Digest(value); })) {
        return false;
    }
    pi.child_constraints.clear();
    pi.ok = true;
    pi.note.clear();
    return true;
}

bool ValidateChildPI(const ChildPI& pi, std::string* why)
{
    if (!pi.child_constraints.empty()) return Fail(why, "serialized_constraints_forbidden");
    if (!pi.ok || !pi.note.empty()) return Fail(why, "noncanonical_child_status");
    if (!IsPowerOfTwo(pi.child_n_rows) || pi.child_n_rows > kRCFriMaxCoeffsHard) {
        return Fail(why, "child_rows");
    }
    if (pi.child_w == 0 || pi.child_w + 1 > kRCFri3AlgBatchMaxColumns) {
        return Fail(why, "child_width");
    }
    if (pi.child_quotient_len == 0 ||
        pi.child_quotient_len > (uint64_t{1} << kRCFriMaxColumnLog2)) {
        return Fail(why, "child_quotient_len");
    }
    if (!IsPowerOfTwo(pi.child_n_coeffs) ||
        pi.child_n_coeffs > kRCFriMaxCoeffsHard) {
        return Fail(why, "child_n_coeffs");
    }
    const uint64_t expected_lde =
        static_cast<uint64_t>(pi.child_n_coeffs) * kRCFriBlowup;
    if (expected_lde != pi.child_n_lde ||
        expected_lde > (uint64_t{1} << kRCFriMaxLdeLog2)) {
        return Fail(why, "child_n_lde");
    }
    if (pi.merkle_depth != Log2Exact(pi.child_n_lde) ||
        pi.n_folds != Log2Exact(pi.child_n_coeffs) ||
        pi.n_folds == 0 || pi.n_folds > kRCFriMaxFoldLayersHard) {
        return Fail(why, "child_depths");
    }
    if (!IsCanonical(pi.row_commit_root) || !IsCanonical(pi.rt_root)) {
        return Fail(why, "child_digest_noncanonical");
    }
    if (pi.fold_roots.size() != pi.n_folds ||
        pi.fold_challenges.size() != pi.n_folds) {
        return Fail(why, "child_fold_vector_size");
    }
    if (!std::all_of(pi.fold_roots.begin(), pi.fold_roots.end(),
                     [](const Fri3AlgDigest& value) { return IsCanonical(value); })) {
        return Fail(why, "child_fold_root_noncanonical");
    }
    const size_t columns = static_cast<size_t>(pi.child_w) + 1;
    if (pi.column_len.size() != columns || pi.evals_z1.size() != columns ||
        pi.evals_z2.size() != columns) {
        return Fail(why, "child_column_vector_size");
    }
    if (pi.column_len.back() != pi.child_quotient_len ||
        !std::all_of(pi.column_len.begin(), pi.column_len.end(),
                     [&](uint32_t len) { return len != 0 && len <= pi.child_n_coeffs; })) {
        return Fail(why, "child_column_len");
    }
    const std::array<Fp3, 7> scalars{pi.fri_lambda, pi.z1, pi.z2, pi.w1,
                                     pi.w2, pi.final_value, pi.air_lambda};
    if (!std::all_of(scalars.begin(), scalars.end(),
                     [](const Fp3& value) { return IsCanonical(value); }) ||
        !std::all_of(pi.fold_challenges.begin(), pi.fold_challenges.end(),
                     [](const Fp3& value) { return IsCanonical(value); }) ||
        !std::all_of(pi.evals_z1.begin(), pi.evals_z1.end(),
                     [](const Fp3& value) { return IsCanonical(value); }) ||
        !std::all_of(pi.evals_z2.begin(), pi.evals_z2.end(),
                     [](const Fp3& value) { return IsCanonical(value); })) {
        return Fail(why, "child_field_noncanonical");
    }
    if (pi.query_index.size() != kRCFri3AlgNumQueries ||
        !std::all_of(pi.query_index.begin(), pi.query_index.end(),
                     [&](uint32_t index) { return index < pi.child_n_lde; })) {
        return Fail(why, "child_queries");
    }
    return true;
}

void WriteRowPath(Writer& writer, const air_quotient::AirAlgRowPath& path)
{
    writer.U32(path.index);
    WriteVector(writer, path.values,
                [&](const Fp3& value) { writer.Fp3Value(value); });
    WriteVector(writer, path.siblings,
                [&](const Fri3AlgDigest& value) { writer.Digest(value); });
}

bool ReadRowPath(Reader& reader, air_quotient::AirAlgRowPath& path)
{
    return reader.U32(path.index) &&
           ReadVector(reader, path.values, MAX_VECTOR_ITEMS, 24,
                      [&](Fp3& value) { return reader.Fp3Value(value); }) &&
           ReadVector(reader, path.siblings, MAX_PATH_DEPTH, 32,
                      [&](Fri3AlgDigest& value) { return reader.Digest(value); });
}

bool ValidateRowPath(const air_quotient::AirAlgRowPath& path)
{
    return path.values.size() <= MAX_VECTOR_ITEMS &&
           path.siblings.size() <= MAX_PATH_DEPTH &&
           std::all_of(path.values.begin(), path.values.end(),
                       [](const Fp3& value) { return IsCanonical(value); }) &&
           std::all_of(path.siblings.begin(), path.siblings.end(),
                       [](const Fri3AlgDigest& value) { return IsCanonical(value); });
}

bool ReadAlgBatchProof(Reader& reader, Fri3AlgBatchProof& proof)
{
    uint32_t size{0};
    if (!reader.U32(size) || size == 0 || size > kRCFriMaxProofBytesHard ||
        size > reader.Remaining()) {
        return false;
    }
    std::vector<unsigned char> bytes;
    if (!reader.Bytes(size, bytes)) return false;
    const unsigned char* p = bytes.data();
    Reader nested(bytes);
    uint32_t magic{0};
    if (!nested.U32(magic) || magic != kRCFri3AlgBatchProofMagic ||
        !nested.U32(proof.version) ||
        proof.version != kRCFri3AlgActiveBatchProofVersion ||
        !nested.U64(proof.pow_grind_nonce) || !nested.U32(proof.blowup) ||
        !nested.U32(proof.n_coeffs) || !nested.Digest(proof.row_commit.root) ||
        !nested.U32(proof.row_commit.n_leaves) ||
        !ReadVector(nested, proof.column_len, kRCFri3AlgBatchMaxColumns, 4,
                    [&](uint32_t& value) { return nested.U32(value); }) ||
        proof.column_len.empty() || !nested.Fp3Value(proof.lambda) ||
        !nested.Fp3Value(proof.z1) || !nested.Fp3Value(proof.z2) ||
        !ReadVector(nested, proof.evals_z1, kRCFri3AlgBatchMaxColumns, 24,
                    [&](Fp3& value) { return nested.Fp3Value(value); }) ||
        !ReadVector(nested, proof.evals_z2, kRCFri3AlgBatchMaxColumns, 24,
                    [&](Fp3& value) { return nested.Fp3Value(value); }) ||
        !nested.Fp3Value(proof.w1) || !nested.Fp3Value(proof.w2) ||
        !ReadVector(nested, proof.fold_layers, MAX_PATH_DEPTH, 36,
                    [&](Fri3AlgLayerCommit& layer) {
                        return nested.Digest(layer.root) &&
                               nested.U32(layer.n_leaves);
                    }) ||
        !nested.Fp3Value(proof.final_value) ||
        !ReadVector(nested, proof.fold_challenges, MAX_PATH_DEPTH, 24,
                    [&](Fp3& value) { return nested.Fp3Value(value); }) ||
        !ReadVector(nested, proof.queries, kRCFri3AlgMaxQueriesHard, 8,
                    [&](Fri3AlgBatchQuery& query) {
                        if (!nested.U32(query.index) ||
                            !ReadVector(nested, query.row.values,
                                        kRCFri3AlgBatchMaxColumns, 24,
                                        [&](Fp3& value) {
                                            return nested.Fp3Value(value);
                                        }) ||
                            !ReadVector(nested, query.row.siblings,
                                        MAX_PATH_DEPTH, 32,
                                        [&](Fri3AlgDigest& value) {
                                            return nested.Digest(value);
                                        })) {
                            return false;
                        }
                        return ReadVector(
                            nested, query.steps, MAX_PATH_DEPTH, 64,
                            [&](Fri3AlgFoldStep& step) {
                                return nested.U32(step.even_index) &&
                                       nested.U32(step.odd_index) &&
                                       nested.Fp3Value(step.even) &&
                                       nested.Fp3Value(step.odd) &&
                                       ReadVector(nested, step.even_siblings,
                                                  MAX_PATH_DEPTH, 32,
                                                  [&](Fri3AlgDigest& value) {
                                                      return nested.Digest(value);
                                                  }) &&
                                       ReadVector(nested, step.odd_siblings,
                                                  MAX_PATH_DEPTH, 32,
                                                  [&](Fri3AlgDigest& value) {
                                                      return nested.Digest(value);
                                                  });
                            });
                    }) ||
        nested.Remaining() != 0) {
        return false;
    }
    (void)p;
    return true;
}

bool ValidateAirProofStructure(const AirProof& proof, std::string* why)
{
    const auto& batch = proof.batch;
    const size_t columns = batch.column_len.size();
    if (batch.version != kRCFri3AlgActiveBatchProofVersion ||
        batch.blowup != kRCFriBlowup || !IsPowerOfTwo(batch.n_coeffs) ||
        batch.n_coeffs > kRCFriMaxCoeffsHard || columns == 0 ||
        columns > kRCFri3AlgBatchMaxColumns) {
        return Fail(why, "root_batch_shape");
    }
    const uint64_t n_lde = static_cast<uint64_t>(batch.n_coeffs) * batch.blowup;
    if (n_lde > (uint64_t{1} << kRCFriMaxLdeLog2) ||
        batch.row_commit.n_leaves != n_lde ||
        !IsCanonical(batch.row_commit.root)) {
        return Fail(why, "root_batch_domain");
    }
    const uint32_t n_folds = Log2Exact(batch.n_coeffs);
    // Fri3AlgBatchProof commits the initial DEEP-composition codeword and
    // then one layer after every fold.  The final entry is therefore the
    // blowup-sized constant layer: there are n_folds + 1 roots but only
    // n_folds challenges.  Requiring equal vector lengths made the recursive
    // carrier codec accept a synthetic shape that the real FRI verifier
    // rejects, while rejecting every honest aggregate proof.
    if (batch.evals_z1.size() != columns || batch.evals_z2.size() != columns ||
        batch.fold_layers.size() != static_cast<size_t>(n_folds) + 1 ||
        batch.fold_challenges.size() != n_folds ||
        batch.queries.size() != kRCFri3AlgNumQueries) {
        return Fail(why, "root_batch_vectors");
    }
    for (uint32_t layer = 0; layer < batch.fold_layers.size(); ++layer) {
        if (batch.fold_layers[layer].n_leaves !=
                (static_cast<uint32_t>(n_lde) >> layer) ||
            !IsCanonical(batch.fold_layers[layer].root)) {
            return Fail(why, "root_fold_layer_shape");
        }
    }
    if (batch.fold_layers.back().n_leaves != batch.blowup) {
        return Fail(why, "root_terminal_layer_shape");
    }
    if (!std::all_of(batch.column_len.begin(), batch.column_len.end(),
                     [&](uint32_t len) { return len != 0 && len <= batch.n_coeffs; })) {
        return Fail(why, "root_column_len");
    }
    if (proof.next_openings.size() != batch.queries.size()) {
        return Fail(why, "root_next_opening_count");
    }
    const uint32_t depth = Log2Exact(static_cast<uint32_t>(n_lde));
    for (const auto& paths : proof.next_openings) {
        if (paths.size() != 2 || !ValidateRowPath(paths[0]) ||
            !ValidateRowPath(paths[1]) ||
            paths[0].values.size() != columns || !paths[1].values.empty() ||
            paths[0].siblings.size() != depth ||
            paths[1].siblings.size() != depth) {
            return Fail(why, "root_row_path_shape");
        }
    }
    if (proof.trace_commit.IsNull() ||
        !Fri3AlgDigestFromUint256(proof.trace_commit).has_value()) {
        return Fail(why, "root_trace_commit");
    }
    return true;
}

bool ValidateCarrierStructure(const RCStage3RecursiveProof& proof, std::string* why)
{
    if (proof.magic != kRCStage3RecursiveMagic) return Fail(why, "bad_magic");
    if (proof.version != kRCStage3RecursiveVersion) return Fail(why, "bad_version");
    if (proof.registry_version != kRCStage3ConstraintRegistryVersion) {
        return Fail(why, "bad_registry_version");
    }
    if (!IsKnownRole(proof.role)) return Fail(why, "unknown_role");
    if (proof.fixed_role_commitment.IsNull()) return Fail(why, "null_fixed_commitment");
    if (proof.ctl_child_commitment.IsNull()) {
        return Fail(why, "null_ctl_child_commitment");
    }
    if (proof.children.empty() ||
        proof.children.size() > kRCStage3RecursiveMaxChildren) {
        return Fail(why, "child_count");
    }
    for (const auto& child : proof.children) {
        if (!ValidateChildPI(child.public_inputs, why)) return false;
    }
    return ValidateAirProofStructure(proof.root, why);
}

void AddGap(RCStage3RecursiveReadiness& out, RCStage3RecursiveGapCode code,
            RCStage3RelationRole role, std::string detail)
{
    out.gaps.push_back({code, role, std::move(detail)});
}

bool SameConstraintShape(
    const air_quotient::AirConstraintSystem<Fp3>& a,
    const air_quotient::AirConstraintSystem<Fp3>& b)
{
    if (a.n_rows != b.n_rows || a.n_columns != b.n_columns ||
        a.constraints.size() != b.constraints.size()) {
        return false;
    }
    for (size_t i = 0; i < a.constraints.size(); ++i) {
        const auto& ac = a.constraints[i];
        const auto& bc = b.constraints[i];
        if (ac.kind != bc.kind || ac.alg_degree != bc.alg_degree ||
            std::string(ac.name ? ac.name : "") !=
                std::string(bc.name ? bc.name : "")) {
            return false;
        }
    }
    return true;
}

} // namespace

bool RCStage3RecursiveChildPin::operator==(
    const RCStage3RecursiveChildPin& other) const
{
    Writer a;
    Writer b;
    WriteChildPI(a, public_inputs);
    WriteChildPI(b, other.public_inputs);
    return a.Take() == b.Take();
}

bool ResolveCurrentRCStage3RelationConstraintSystem(
    RCStage3RelationRole role,
    const ChildPI& pin,
    air_quotient::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    out = {};
    if (!IsKnownRole(role)) return Fail(why, "registry:unknown_role");

    // Real C_ρ for the fully-scalar-openable composable-kernel coupled roles
    // (CoupledPermutation, CoupledMix): the column-shifted direct product of the
    // role's fragment kernel and one alg_hash opening block per required
    // endpoint, each block pinned to the endpoint AUTHORITY ROOT the child pin
    // committed — never a canonical stand-in. That root is bound (not free) via
    // ComputeRCStage3RecursiveChildPinsCommitment -> fixed_role_commitment,
    // absorbed before any Fiat-Shamir challenge. The opening trace has
    // path_len+1 == child_n_rows rows (fixed T-BIND).
    if (RCStage3RoleIsInCsClosable(role)) {
        if (pin.child_n_rows < 2 || !IsPowerOfTwo(pin.child_n_rows)) {
            return Fail(why, std::string("registry:") +
                                 RCStage3RelationRoleName(role) + ":pin_rows");
        }
        const uint32_t path_len = pin.child_n_rows - 1;
        std::string awhy;
        air_quotient::AirConstraintSystem<Fp3> cs;
        bool built = false;
        if (role == RCStage3RelationRole::CompositionLink) {
            // The fifteenth relation. Two §4 leg bindings + the sponge ledger
            // fold that ties them to the committed link digest. It takes no
            // path_len: its C_rho is 2 rows like the other §4 stream closers.
            built = BuildRCStage3CompositionLinkRoleAirCS(
                pin.endpoint_authority_roots, cs, &awhy);
        } else if (RCStage3RoleIsPureStream(role)) {
            built = BuildRCStage3PureStreamRoleAirCS(
                role, pin.endpoint_authority_roots, cs, &awhy);
        } else if (role == RCStage3RelationRole::CoupledGemm) {
            built = BuildRCStage3CoupledGemmRoleAirCS(
                pin.endpoint_authority_roots, path_len, cs, &awhy);
        } else if (role == RCStage3RelationRole::EpisodeGemm) {
            built = BuildRCStage3EpisodeGemmRoleAirCS(
                pin.endpoint_authority_roots, path_len, cs, &awhy);
        } else if (role == RCStage3RelationRole::EpisodeWiring) {
            built = BuildRCStage3EpisodeWiringRoleAirCS(
                pin.endpoint_authority_roots, path_len, cs, &awhy);
        } else if (role == RCStage3RelationRole::CoupledExchange ||
                   role == RCStage3RelationRole::CoupledBank) {
            built = BuildRCStage3CoupledMixedRoleAirCS(
                role, pin.endpoint_authority_roots, path_len, cs, &awhy);
        } else if (role ==
                       RCStage3RelationRole::EpisodeDeterministicBuilder ||
                   role == RCStage3RelationRole::CoupledExtract ||
                   role == RCStage3RelationRole::EpisodeExtract) {
            built = BuildRCStage3NoKernelRoleAirCS(
                role, pin.endpoint_authority_roots, path_len, cs, &awhy);
        } else {
            built = BuildRCStage3CoupledScalarRoleAirCS(
                role, pin.endpoint_authority_roots, path_len, cs, &awhy);
        }
        if (built) {
            out = std::move(cs);
            return true;
        }
        return Fail(why, std::string("registry:") +
                             RCStage3RelationRoleName(role) + ":" + awhy);
    }

    return Fail(why, std::string("registry:") +
                         RCStage3RelationRoleName(role) +
                         ":complete_air_unavailable");
}

bool SerializeRCStage3RoleAirProof(const AirProof& proof,
                                   std::vector<unsigned char>& out,
                                   std::string* why)
{
    out.clear();
    if (!ValidateAirProofStructure(proof, why)) return false;

    Writer writer;
    std::vector<unsigned char> batch;
    const size_t batch_size = SerializeFri3AlgBatchProof(proof.batch, batch);
    if (batch_size != batch.size() || batch_size > kRCFriMaxProofBytesHard) {
        return Fail(why, "role_air_batch_serialize");
    }
    writer.U32(static_cast<uint32_t>(batch.size()));
    writer.Bytes(batch);
    writer.Uint256(proof.trace_commit);
    writer.U32(static_cast<uint32_t>(proof.next_openings.size()));
    for (const auto& paths : proof.next_openings) {
        writer.U32(static_cast<uint32_t>(paths.size()));
        for (const auto& path : paths) WriteRowPath(writer, path);
    }
    out = writer.Take();
    if (out.size() > kRCStage3RecursiveMaxBytes) {
        out.clear();
        return Fail(why, "role_air_oversize");
    }
    return true;
}

std::optional<AirProof>
DeserializeRCStage3RoleAirProof(const std::vector<unsigned char>& bytes,
                                std::string* why)
{
    if (bytes.empty()) return FailOptional<AirProof>(why, "role_air_empty");
    if (bytes.size() > kRCStage3RecursiveMaxBytes) {
        return FailOptional<AirProof>(why, "role_air_oversize");
    }
    Reader reader(bytes);
    AirProof proof;
    if (!ReadAlgBatchProof(reader, proof.batch) ||
        !reader.Uint256(proof.trace_commit)) {
        return FailOptional<AirProof>(why, "role_air_bad_body");
    }
    if (!ReadVector(reader, proof.next_openings, kRCFri3AlgMaxQueriesHard, 4,
                    [&](std::vector<air_quotient::AirAlgRowPath>& paths) {
                        return ReadVector(reader, paths, 2, 8,
                                          [&](air_quotient::AirAlgRowPath& path) {
                                              return ReadRowPath(reader, path);
                                          });
                    }) ||
        reader.Remaining() != 0) {
        return FailOptional<AirProof>(why, "role_air_bad_openings");
    }
    if (!ValidateAirProofStructure(proof, why)) return std::nullopt;

    std::vector<unsigned char> canonical;
    if (!SerializeRCStage3RoleAirProof(proof, canonical, why) ||
        canonical != bytes) {
        return FailOptional<AirProof>(why, "role_air_noncanonical");
    }
    return proof;
}

bool SerializeRCStage3RecursiveProof(const RCStage3RecursiveProof& proof,
                                     std::vector<unsigned char>& out,
                                     std::string* why)
{
    out.clear();
    if (!ValidateCarrierStructure(proof, why)) return false;

    Writer writer;
    writer.U32(proof.magic);
    writer.U16(proof.version);
    writer.U16(proof.registry_version);
    writer.U16(static_cast<uint16_t>(proof.role));
    writer.U16(0);
    writer.Uint256(proof.fixed_role_commitment);
    writer.Uint256(proof.ctl_child_commitment);
    writer.U32(static_cast<uint32_t>(proof.children.size()));
    for (const auto& child : proof.children) WriteChildPI(writer, child.public_inputs);

    std::vector<unsigned char> batch;
    const size_t batch_size =
        SerializeFri3AlgBatchProof(proof.root.batch, batch);
    if (batch_size != batch.size() ||
        batch_size > kRCFriMaxProofBytesHard) {
        return Fail(why, "root_batch_serialize");
    }
    writer.U32(static_cast<uint32_t>(batch.size()));
    writer.Bytes(batch);
    writer.Uint256(proof.root.trace_commit);
    writer.U32(static_cast<uint32_t>(proof.root.next_openings.size()));
    for (const auto& paths : proof.root.next_openings) {
        writer.U32(static_cast<uint32_t>(paths.size()));
        for (const auto& path : paths) WriteRowPath(writer, path);
    }
    out = writer.Take();
    if (out.size() > kRCStage3RecursiveMaxBytes) {
        out.clear();
        return Fail(why, "oversize");
    }
    return true;
}

std::optional<RCStage3RecursiveProof>
DeserializeRCStage3RecursiveProof(const std::vector<unsigned char>& bytes,
                                  std::string* why)
{
    if (bytes.empty()) return FailOptional<RCStage3RecursiveProof>(why, "empty");
    if (bytes.size() > kRCStage3RecursiveMaxBytes) {
        return FailOptional<RCStage3RecursiveProof>(why, "oversize");
    }
    Reader reader(bytes);
    RCStage3RecursiveProof proof;
    uint16_t role{0};
    uint16_t reserved{0};
    uint32_t children{0};
    if (!reader.U32(proof.magic) || !reader.U16(proof.version) ||
        !reader.U16(proof.registry_version) || !reader.U16(role) ||
        !reader.U16(reserved) || reserved != 0 ||
        !reader.Uint256(proof.fixed_role_commitment) ||
        !reader.Uint256(proof.ctl_child_commitment) ||
        !reader.U32(children) || children == 0 ||
        children > kRCStage3RecursiveMaxChildren) {
        return FailOptional<RCStage3RecursiveProof>(why, "truncated_header");
    }
    proof.role = static_cast<RCStage3RelationRole>(role);
    proof.children.resize(children);
    for (auto& child : proof.children) {
        if (!ReadChildPI(reader, child.public_inputs)) {
            return FailOptional<RCStage3RecursiveProof>(why, "bad_child_pin");
        }
    }
    if (!ReadAlgBatchProof(reader, proof.root.batch) ||
        !reader.Uint256(proof.root.trace_commit)) {
        return FailOptional<RCStage3RecursiveProof>(why, "bad_root");
    }
    if (!ReadVector(reader, proof.root.next_openings,
                    kRCFri3AlgMaxQueriesHard, 4,
                    [&](std::vector<air_quotient::AirAlgRowPath>& paths) {
                        return ReadVector(reader, paths, 2, 8,
                                          [&](air_quotient::AirAlgRowPath& path) {
                                              return ReadRowPath(reader, path);
                                          });
                    }) ||
        reader.Remaining() != 0) {
        return FailOptional<RCStage3RecursiveProof>(why, "bad_root_openings");
    }
    if (!ValidateCarrierStructure(proof, why)) return std::nullopt;

    std::vector<unsigned char> canonical;
    if (!SerializeRCStage3RecursiveProof(proof, canonical, why) ||
        canonical != bytes) {
        return FailOptional<RCStage3RecursiveProof>(why, "noncanonical");
    }
    return proof;
}

uint256 ComputeRCStage3RecursiveRoleSeed(
    const RCStage3SuccinctProof& statement,
    RCStage3RelationRole role,
    const uint256& fixed_role_commitment,
    const RCStage3RecursivePosition& position)
{
    HashWriter hash;
    hash << RECURSIVE_SEED_DOMAIN;
    hash << ComputeRCStage3AggregationSeed(statement);
    hash << kRCStage3ConstraintRegistryVersion;
    hash << static_cast<uint16_t>(role);
    hash << fixed_role_commitment;
    // P4 position binding: node identity + slot make the FS base position-unique
    // across the recursion tree, so two nodes cannot share an FS point.
    hash << position.node_id;
    hash << position.slot_index;
    return hash.GetHash();
}

uint256 ComputeRCStage3RecursiveChildFsPoint(
    const uint256& base_child_fs_seed,
    RCStage3RelationRole role,
    const RCStage3RecursivePosition& position)
{
    HashWriter hash;
    hash << CHILD_FS_POINT_DOMAIN;
    hash << kRCStage3ConstraintRegistryVersion;
    hash << static_cast<uint16_t>(role);
    hash << base_child_fs_seed;
    hash << position.node_id;
    hash << position.slot_index;
    return hash.GetHash();
}

bool VerifyRCStage3RecursiveChildFsBinding(
    const uint256& base_child_fs_seed,
    RCStage3RelationRole role,
    const RCStage3RecursivePosition& position,
    const ChildPI& pin,
    std::string* why)
{
    // Re-derive the child's AIR-batching challenge from the position-bound FS
    // point exactly as air_recurse::ExtractChildPublicInputs derives it from the
    // raw seed (label "airq_lambda" over the trace-commit root and child dims).
    const uint256 point =
        ComputeRCStage3RecursiveChildFsPoint(base_child_fs_seed, role, position);
    const uint256 trace_commit = Fri3AlgDigestToUint256(pin.rt_root);
    const std::vector<uint256> roots{trace_commit};
    const uint256 digest = air_quotient::AirChallengeDigest(
        point, "airq_lambda", roots,
        {pin.child_n_rows, pin.child_quotient_len, pin.child_w});
    const Fp3 expected = gkr_field::FromChallengeBytes3(digest.data());
    if (!gkr_field::Eq(pin.air_lambda, expected)) {
        return Fail(why, "child_fs_binding:air_lambda_position_mismatch");
    }
    return true;
}

uint256 ComputeRCStage3RecursiveChildPinsCommitment(
    RCStage3RelationRole role,
    const uint256& ctl_child_commitment,
    const std::vector<RCStage3RecursiveChildPin>& children)
{
    HashWriter hash;
    hash << CHILD_PINS_DOMAIN;
    hash << kRCStage3ConstraintRegistryVersion;
    hash << static_cast<uint16_t>(role);
    hash << ctl_child_commitment;
    hash << static_cast<uint32_t>(children.size());
    for (const auto& child : children) {
        Writer writer;
        WriteChildPI(writer, child.public_inputs);
        const std::vector<unsigned char> bytes = writer.Take();
        hash << static_cast<uint32_t>(bytes.size());
        for (unsigned char byte : bytes) hash << byte;
    }
    return hash.GetHash();
}

bool ValidateRCStage3RecursiveCtlBinding(
    const RCStage3RecursiveProof& proof,
    const RCStage3CtlChildPin& ctl_pin,
    std::string* why)
{
    if (proof.role != ctl_pin.role) {
        return Fail(why, "ctl_binding:role");
    }
    const uint256 commitment = CommitRCStage3CtlChildPin(ctl_pin);
    if (commitment.IsNull()) {
        return Fail(why, "ctl_binding:invalid_pin");
    }
    if (proof.ctl_child_commitment != commitment) {
        return Fail(why, "ctl_binding:commitment");
    }
    if (why != nullptr) *why = "stage3:recursive:ok";
    return true;
}

RCStage3TwoLevelRootVerifyBudgetV1
CurrentRCStage3TwoLevelRootVerifyBudgetV1()
{
    RCStage3TwoLevelRootVerifyBudgetV1 out;

    // ---- COMPUTED: is a PRODUCTION two-level root representable at all? ----
    // "Root verify" is air_recurse::VerifyAggregate = BuildVerifierAIRPinned(k,
    // pis) + exactly ONE AirQuotientVerify. So the question "can a two-level
    // root verify come in under 900 ms" is downstream of a prior question that
    // had never been asked: can a two-level root V_CS be COMMITTED at all?
    //
    // The k-child verifier AIR width is monotone non-decreasing in the child
    // trace width (each additional child column contributes a fixed DEEP /
    // per-point / row-leaf cell budget and removes none), and it crosses
    // kRCFri3AlgBatchMaxColumns at the MEASURED child width below. That ladder
    // is remeasured from freshly built V_CS instances — not fitted, not
    // extrapolated — by matmul_v4_rc_stage3_two_level_root_verify_tests, which
    // also pins this constant and reproduces the tree's own MEASURED four-slot
    // toy width (16176 columns at child W=1).
    //
    // A LEVEL-2 root ingests four LEVEL-1 parents, and the level-1 parent's own
    // trace width at the real-role child shape is the MEASURED 384,984 columns
    // (bec2c48, AIRQ_SHAPE W=384984) — two orders of magnitude past the
    // crossover.
    constexpr uint32_t kMeasuredRealRoleParentColumns = 384984;
    out.production_shape_representable =
        kMeasuredRealRoleParentColumns <
        kRCStage3MeasuredLevel2CapCrossoverChildColumns;

    // ---- MEASURED: has a full-family level-2 root proof ever committed? ----
    // No. The only two-level attempt in the tree
    // (matmul_v4_rc_air_recurse_tests.cpp:1085) proves a level-2 root and never
    // verifies it, and the level-2 V_CS exceeds the backend column cap at every
    // shape tried so far. The one working two-level chain
    // (matmul_v4_rc_stage3_coupled_bank_stream_tests.cpp:400) disables EVERY
    // V_CS mirror family, so its wall-clock is a lower bound on a real root
    // verify and is deliberately NOT recorded as one here.
    out.full_family_root_proof_produced = false;
    out.root_verify_wall_clock_measured = false;
    out.measured_root_verify_micros = 0;

    // ---- MEASURED: the SINGLE-level floor. ----
    // This is the number that changes what the gap means. A k=2 aggregate over
    // the SMALLEST child the verifier mirror admits (W=1 toy child; V_CS 8,088
    // columns x 256 rows; Q=192) was proved and then VERIFIED in 5.006 s, on
    // this box, with the full mirror families, AFTER the Goldilocks fast-reduce
    // port. Pinned and remeasured by
    // matmul_v4_rc_stage3_two_level_root_verify_tests under BTX_G2_TWO_LEVEL_HEAVY.
    //
    // So the 900 ms relay budget is already missed by 5.56x at the smallest
    // aggregation shape that exists — before widening to the production child
    // (V_CS 350,092 columns at W=544, ~43x wider) and before adding a second
    // level at all. The two-level question is not the binding one.
    out.measured_single_level_verify_micros = 5005620;
    out.measured_single_level_vcs_columns = 8088;
    out.single_level_within_relay_budget =
        out.measured_single_level_verify_micros != 0 &&
        out.measured_single_level_verify_micros <=
            static_cast<uint64_t>(out.relay_budget_millis) * 1000ULL;

    // ---- MEASURED: the NARROW multi-child node, on a REAL block. ----
    // recursive_fixedpoint::BuildFoldBusCompositionMulti packs an ARITY-N
    // node's hash-opening/fold/scalar buses vertically: the V_CS column
    // count does not grow with arity or child width, so arity is paid in
    // rows, not columns (see that header's zero-expansion measurement).
    // matmul_v4_rc_stage3_narrow_recurse_tests.cpp,
    // real_block_narrow_multi_child_root, default roles {episode:tiletree,
    // episode:digest} (BTX_BLK_ROLES="4,5"): a two-child node over REAL
    // role-section proofs of a real block, 575 V_CS columns x 32,768 rows,
    // proved and verified with the real unmodified row-wise verifier
    // (AirQuotientVerifyRows, cross-checked against the ordinary
    // AirQuotientVerify view of the same proof) in 683 ms — INSIDE the
    // 900 ms relay budget and a 9.98x reduction versus the dense single-level
    // floor measured on the same box (6.8135 s under
    // BTX_G2_TWO_LEVEL_HEAVY). This is real evidence for the narrow path this
    // struct's own doc comment asks for, not a toy shape.
    //
    // It CANNOT retire the gap by itself: recursive_fixedpoint::
    // kCompleteRecursiveFixedPointExecutable is false, so an accepted narrow
    // node is a PARTIAL verifier mirror (arbitrary per-point child-constraint
    // evaluation and the SHA256d Fiat-Shamir transcript chip are not joined),
    // exactly like the descendant-free lower bound recorded above.
    //
    // Representability is row-sum-, not arity-, bounded: adding all six real
    // roles in natural order (real_block_narrow_root_shape_probe) crosses
    // kRCFriMaxLdeLog2 at the THIRD role (builder+gemm fits exactly at 2^24;
    // +extract needs 2^25), and combining all six directly reproduces that as
    // a MEASURED prove-time failure (BTX_BLK_ROLES="0,1,2,3,4,5":
    // "Fri3AlgBuildRowTreeCacheStreaming: shape"). The two smallest real
    // roles fit with headroom; the two largest do not fit together at all.
    out.measured_narrow_multichild_verify_micros = 683000;
    out.measured_narrow_multichild_vcs_columns = 575;
    out.measured_narrow_multichild_arity = 2;
    out.narrow_multichild_within_relay_budget =
        out.measured_narrow_multichild_verify_micros != 0 &&
        out.measured_narrow_multichild_verify_micros <=
            static_cast<uint64_t>(out.relay_budget_millis) * 1000ULL;
    // Always false today; see kCompleteRecursiveFixedPointExecutable.
    out.narrow_multichild_complete_verifier_mirror = false;

    // ---- The only conjunction that may retire the gap. ----
    out.within_relay_budget =
        out.production_shape_representable &&
        out.full_family_root_proof_produced &&
        out.root_verify_wall_clock_measured &&
        out.measured_root_verify_micros != 0 &&
        out.measured_root_verify_micros <=
            static_cast<uint64_t>(out.relay_budget_millis) * 1000ULL;

    out.note =
        "stage3:two_level_root_verify:"
        "level1_parent_columns=" +
        std::to_string(kMeasuredRealRoleParentColumns) +
        ";vcs_cap_crossover_child_columns=" +
        std::to_string(kRCStage3MeasuredLevel2CapCrossoverChildColumns) +
        ";backend_column_cap=" + std::to_string(kRCFri3AlgBatchMaxColumns) +
        (out.production_shape_representable
             ? ";representable"
             : ";NOT_representable_no_artifact_to_verify") +
        ";root_verify_wall_clock=unmeasured"
        ";single_level_floor_measured_us=" +
        std::to_string(out.measured_single_level_verify_micros) +
        ";single_level_vcs_columns=" +
        std::to_string(out.measured_single_level_vcs_columns) +
        ";relay_budget_us=" +
        std::to_string(static_cast<uint64_t>(out.relay_budget_millis) * 1000ULL) +
        (out.single_level_within_relay_budget
             ? ";single_level_within_budget"
             : ";single_level_ALREADY_OVER_BUDGET") +
        ";narrow_multichild_arity=" +
        std::to_string(out.measured_narrow_multichild_arity) +
        ";narrow_multichild_vcs_columns=" +
        std::to_string(out.measured_narrow_multichild_vcs_columns) +
        ";narrow_multichild_verify_measured_us=" +
        std::to_string(out.measured_narrow_multichild_verify_micros) +
        (out.narrow_multichild_within_relay_budget
             ? ";narrow_multichild_within_budget"
             : ";narrow_multichild_ALREADY_OVER_BUDGET") +
        ";narrow_multichild_complete_verifier_mirror=" +
        (out.narrow_multichild_complete_verifier_mirror ? "true" : "false");
    return out;
}

RCStage3RecursiveReadiness AssessRCStage3RecursiveReadiness(
    const RCStage3SuccinctProof& statement,
    const RCStage3RecursiveProof& proof,
    const RCStage3ConstraintResolver& resolver)
{
    RCStage3RecursiveReadiness out;
    out.soundness_bits = static_cast<uint32_t>(
        std::max(0, Fri3AlgSoundnessBoundBits()));
    std::string why;
    if (!ValidateCarrierStructure(proof, &why)) {
        AddGap(out, RCStage3RecursiveGapCode::MalformedCarrier, proof.role, why);
        return out;
    }
    out.structurally_valid = true;

    const auto required = RequiredRCStage3RelationRoles(statement.statement);
    if (std::find(required.begin(), required.end(), proof.role) == required.end()) {
        AddGap(out, RCStage3RecursiveGapCode::RoleNotRequired, proof.role,
               "role is not present in the statement registry");
    }
    if (ComputeRCStage3RecursiveChildPinsCommitment(
            proof.role, proof.ctl_child_commitment,
            proof.children) != proof.fixed_role_commitment) {
        AddGap(out, RCStage3RecursiveGapCode::FixedCommitmentMismatch,
               proof.role,
               "pre-proof role commitment does not match canonical child pins");
    }

    std::vector<ChildPI> materialized;
    materialized.reserve(proof.children.size());
    bool all_resolved = true;
    for (const auto& child : proof.children) {
        air_quotient::AirConstraintSystem<Fp3> cs;
        std::string registry_why;
        const bool resolved =
            resolver && resolver(proof.role, child.public_inputs, cs,
                                 &registry_why);
        // Completeness gate (closes the shape-only fabrication gap): a resolved
        // C_ρ for a scalar-openable role must carry one in-trace opening block
        // per required endpoint — not merely be a non-empty AIR of the right
        // shape. Roles with no in-CS opening requirement (required_openings == 0)
        // are still gated by `resolved` above; they cannot flip until their
        // stream/wired closers are composed and accounted here.
        const uint32_t required_openings =
            RCStage3RequiredInCsOpeningBlocks(proof.role);
        const bool openings_complete =
            required_openings == 0 ||
            RCStage3CountInCsClosers(cs) == required_openings;
        if (!resolved || cs.constraints.empty() ||
            cs.n_rows != child.public_inputs.child_n_rows ||
            cs.n_columns != child.public_inputs.child_w ||
            !openings_complete) {
            all_resolved = false;
            AddGap(out,
                   RCStage3RecursiveGapCode::ConstraintRegistryUnavailable,
                   proof.role,
                   !resolved
                       ? (registry_why.empty()
                              ? "registry returned an empty or shape-mismatched "
                                "AIR"
                              : registry_why)
                       : (!openings_complete
                              ? "resolved AIR is missing required endpoint "
                                "opening blocks"
                              : "resolved AIR shape mismatch"));
            continue;
        }
        ChildPI pi = child.public_inputs;
        pi.child_constraints = cs.constraints;
        materialized.push_back(std::move(pi));
    }
    out.constraints_resolved =
        all_resolved && materialized.size() == proof.children.size();

    std::vector<ChildPI> shapes;
    shapes.reserve(proof.children.size());
    for (const auto& child : proof.children) shapes.push_back(child.public_inputs);
    out.measurement = air_recurse::MeasureVerifierAIR(
        static_cast<uint32_t>(shapes.size()), shapes,
        RCStage3MandatoryVerifierAirFamilies());
    out.backend_shape_supported = true;
    if (out.measurement.n_columns > kRCFri3AlgBatchMaxColumns) {
        out.backend_shape_supported = false;
        AddGap(out, RCStage3RecursiveGapCode::BackendColumnCapExceeded,
               proof.role,
               "V_CS columns=" +
                   std::to_string(out.measurement.n_columns) +
                   " cap=" + std::to_string(kRCFri3AlgBatchMaxColumns));
    }
    const uint32_t root_coeffs = FriNextPow2(std::max(
        out.measurement.n_rows, out.measurement.quotient_len));
    if (static_cast<uint64_t>(root_coeffs) * kRCFriBlowup >
        (uint64_t{1} << kRCFriMaxLdeLog2)) {
        out.backend_shape_supported = false;
        AddGap(out, RCStage3RecursiveGapCode::BackendLdeCapExceeded,
               proof.role, "root quotient LDE exceeds executable cap");
    }
    const bool soundness_target_met =
        out.soundness_bits >=
        kRCStage3RecursiveTargetSoundnessBits;
    if (!soundness_target_met) {
        AddGap(out, RCStage3RecursiveGapCode::SoundnessTargetNotMet,
               proof.role,
               "current bound=" + std::to_string(out.soundness_bits) +
                   " target=" +
                   std::to_string(kRCStage3RecursiveTargetSoundnessBits));
    }
    // These are mathematical verifier conditions, not activation policy.
    // Keep them explicit until the normalized verifier exports executable
    // completion flags; never replace them with the consensus authority gate.
    //
    // child_fiat_shamir_replay_closed is not a hard-coded literal: it is
    // COMPUTED by the executable global soundness ledger, which delegates to
    // the single source of truth for this obligation,
    // recursive_parent_air::AssessChildFsReplayClosureV1() (see
    // matmul_v4_rc_stage3_global_soundness_ledger.cpp, out.fiat_shamir_replay_
    // complete). Never replace this with a literal `true`.
    //
    // This line gates recursive verification for the whole system, so if you
    // are here asking "why is recursion still closed?", read that assessor's
    // `note`: it enumerates exactly which conjunct is still open, and it is
    // live rather than a snapshot that rots in this comment. As of this
    // writing the binding constraints are:
    //
    //   * CHALLENGE-KIND coverage, not slot coverage: 1 of the 8 Challenge*
    //     variants of FiatShamirEventKind (matmul_v4_rc_stage3_verifier_air.h
    //     :218-232) is replayed. The other seven are blocked by the
    //     transcript-length wall. Parent-slot coverage is NOT what blocks
    //     closure.
    //   * FRI-proof-level discharge is PARTIAL: the lane relation is
    //     FRI-proven (lane_relation_fri_proven, recursive_parent_air.cpp:4563)
    //     but neither bus endpoint is yet (producer_endpoint_fri_proven /
    //     consumer_endpoint_fri_proven, .cpp:4568-4569, pending runs).
    //
    // Do not re-introduce a claim about the normalized-universal-parent
    // scaffold here: it no longer carries the FS-replay flag at all.
    const bool child_fiat_shamir_replay_closed =
        global_soundness_ledger::AssessExecutableGlobalSoundnessLedgerV1()
            .composition_gate.child_fiat_shamir_replay_closed;
    // PR-89 rung-4: a recursion parent now proves ITSELF —
    // ProveParentOwnFriV1 runs AirQuotientProve<Fp3, AirFriBackendAlg<Fp3>> over
    // a parent V_CS and AirQuotientVerify round-trips it (produce -> verify ->
    // tamper-reject -> wrong-seed-reject, exercised in the recursive_parent_air
    // tests). parent_own_fri_proof_reduced_shape records the demonstrated
    // reduced-arity + compact-V_CS round-trip.
    constexpr bool parent_own_fri_proof_reduced_shape{true};
    // The arity-4 four-slot V_CS is ~16996 columns at the toy child shape, and
    // 384k-712k columns with REAL role children. rung-5 raised the alg batch cap
    // 2^15 -> 2^20 = 1048576 (kRCFri3AlgBatchMaxColumns) so the REAL-child V_CS
    // FITS the backend. SOUNDNESS: the gate-scored query-proximity bound
    // Fri3AlgSoundnessBoundBits()=135 is genuinely W-independent (reads only Q);
    // the field/batching term is NOT W-independent on the shipped SinglePower
    // path (independent_batching_coefficients held FALSE) — it loses log2(W-1)
    // bits, but only logarithmically, leaving field_rbr ~107-126 bits > 100-bit
    // target at W=2^20 (see kRCFri3AlgBatchMaxColumns header for the derivation
    // and the correction of the prior false "W-independent 2^-177 RLC" note).
    // Its own FRI proof is thus PRODUCIBLE at real width
    // (within_backend_column_cap == true). The former hard structural residual is
    // CLOSED. What remained for the full-arity self-proof was purely COMPUTE: the
    // ~17k-column (vcs 16176), 192-query single-threaded CPU prove exceeds the
    // reaper window even at the toy child shape. That round-trip is now OBSERVED
    // to complete: on the multi-threaded (OpenMP, 28-thread) prover the full
    // arity-4 four-slot parent self-proves AND verifies in 21m37s wall
    // (31626 CPU-s / ~24.4 effective cores, peak RSS 14.8 GiB) — the
    // four_slot_self_similar_parent_own_fri_fits_alg_column_cap test under
    // BTX_RUN_HEAVY_PARENT_FRI, which asserts prove_ok && division_exact &&
    // verify_ok && parent_own_fri_proof_produced AND the tamper-reject (mutated
    // FRI step -> verify false) and wrong-seed-reject (Seed 0xe3 -> verify false)
    // paths, all passing ("*** No errors detected"). The four-slot self-similar
    // node genuinely proves its own FRI and verifies — the recursion-node
    // round-trip. This is the observed full-arity closure, no longer a residual.
    constexpr bool parent_own_fri_proof_full_arity_cap_admits{true};
    constexpr bool parent_own_fri_proof_produced_full_arity{true};
    // self_similar_fixed_point_closed stays FALSE: closing it requires BOTH the
    // observed full-arity parent-own-FRI round-trip AND child_fiat_shamir_replay_closed
    // (the in-parent SHA-FS chip that replays the child gamma/alpha transcript
    // from a proof-independent role seed), a separate lane still false.
    // const, not constexpr: it now depends on the computed ledger value above.
    const bool self_similar_fixed_point_closed{
        parent_own_fri_proof_produced_full_arity &&
        child_fiat_shamir_replay_closed};
    static_assert(parent_own_fri_proof_reduced_shape,
                  "rung-4 reduced-arity self-proof round-trips");
    static_assert(parent_own_fri_proof_full_arity_cap_admits,
                  "rung-4 raised the alg column cap so the four-slot V_CS fits");
    if (!child_fiat_shamir_replay_closed) {
        AddGap(out,
               RCStage3RecursiveGapCode::ChildFiatShamirReplayNotClosed,
               proof.role,
               "V_CS pins child FS scalars but does not reconstruct their "
               "full transcript from a proof-independent role seed");
    }
    if (!self_similar_fixed_point_closed) {
        AddGap(out,
               RCStage3RecursiveGapCode::SelfSimilarFixedPointNotClosed,
               proof.role,
               "the full arity-4 four-slot parent now produces AND verifies its "
               "own FRI proof (observed: 21m37s wall on the 28-thread OpenMP "
               "prover, tamper- and wrong-seed-reject asserted), so "
               "parent_own_fri_proof_produced_full_arity is closed; the "
               "self-similar fixed point remains open ONLY on the child "
               "Fiat-Shamir replay (in-parent SHA-FS chip) lane, still false");
    }
    out.cryptographic_verification_ready =
        out.structurally_valid &&
        out.mandatory_families &&
        out.constraints_resolved &&
        out.backend_shape_supported &&
        soundness_target_met &&
        child_fiat_shamir_replay_closed &&
        self_similar_fixed_point_closed;
    // g2 performance half. This was an UNCONDITIONAL AddGap with no field for a
    // measurement to land in, so it could neither be cleared by a benchmark nor
    // reopened by a regression. It is now sourced from the recorded verdict and
    // is strictly fail-closed: the gap is emitted unless a PRODUCTION-shape
    // two-level root proof is representable, was produced, and its verify was
    // timed inside the relay budget.
    const RCStage3TwoLevelRootVerifyBudgetV1 two_level_budget =
        CurrentRCStage3TwoLevelRootVerifyBudgetV1();
    if (!two_level_budget.within_relay_budget) {
        AddGap(out, RCStage3RecursiveGapCode::ProductionPerformanceUnmeasured,
               proof.role,
               "production two-level root verification has no <=900ms result: " +
                   two_level_budget.note);
    }
    if (!kRCStage3RecursiveAggregationReady ||
        !kRCStage3SuccinctAuthorityReady) {
        AddGap(out, RCStage3RecursiveGapCode::AuthorityDisabled, proof.role,
               "recursive and Stage-3 authority gates remain false");
    }
    out.production_ready = out.gaps.empty();
    return out;
}

bool VerifyRCStage3RecursiveProof(const RCStage3SuccinctProof& statement,
                                  const RCStage3RecursiveProof& proof,
                                  std::string* why,
                                  const RCStage3RecursivePosition& position)
{
    const RCStage3RecursiveReadiness readiness =
        AssessRCStage3RecursiveReadiness(statement, proof);
    if (!readiness.cryptographic_verification_ready) {
        const std::string detail =
            readiness.gaps.empty() ? "not_ready" : readiness.gaps.front().detail;
        return Fail(why, "cryptographic_not_ready:" + detail);
    }

    std::vector<ChildPI> pis;
    pis.reserve(proof.children.size());
    for (const auto& child : proof.children) {
        air_quotient::AirConstraintSystem<Fp3> cs;
        std::string registry_why;
        if (!ResolveCurrentRCStage3RelationConstraintSystem(
                proof.role, child.public_inputs, cs, &registry_why)) {
            return Fail(why, registry_why);
        }
        ChildPI pi = child.public_inputs;
        pi.child_constraints = std::move(cs.constraints);
        pis.push_back(std::move(pi));
    }
    const uint256 seed = ComputeRCStage3RecursiveRoleSeed(
        statement, proof.role, proof.fixed_role_commitment, position);
    // P4 cross-slot replay gate: every child receipt's pinned FS challenge must
    // re-derive from the position-bound child FS point. A pin proved for another
    // (node_id, slot_index) fails here before the aggregate verify.
    for (uint32_t slot = 0; slot < pis.size(); ++slot) {
        const RCStage3RecursivePosition child_position{position.node_id, slot};
        if (!VerifyRCStage3RecursiveChildFsBinding(
                seed, proof.role, child_position, pis[slot], why)) {
            return false;
        }
    }
    std::string aggregate_why;
    if (!air_recurse::VerifyAggregate(
            proof.root, pis, seed,
            static_cast<uint32_t>(pis.size()),
            RCStage3MandatoryVerifierAirFamilies(), &aggregate_why)) {
        return Fail(why, "aggregate:" + aggregate_why);
    }
    return true;
}

RCStage3RecursiveProveResult ProveRCStage3RecursiveProof(
    const RCStage3SuccinctProof& statement,
    RCStage3RelationRole role,
    const uint256& fixed_role_commitment,
    const uint256& ctl_child_commitment,
    const std::vector<AirProof>& children,
    const uint256& child_fs_seed,
    const ChildPI& child_shape,
    const RCStage3ConstraintResolver& resolver,
    const RCStage3RecursivePosition& position)
{
    RCStage3RecursiveProveResult out;
    out.proof.role = role;
    out.proof.ctl_child_commitment = ctl_child_commitment;
    if (ctl_child_commitment.IsNull()) {
        out.note = "stage3:recursive:null_ctl_child_commitment";
        return out;
    }
    if (children.empty() ||
        children.size() > kRCStage3RecursiveMaxChildren) {
        out.note = "stage3:recursive:prover_child_count";
        return out;
    }
    air_quotient::AirConstraintSystem<Fp3> child_cs;
    std::string registry_why;
    if (!resolver ||
        !resolver(role, child_shape, child_cs, &registry_why) ||
        child_cs.constraints.empty() ||
        child_cs.n_rows != child_shape.child_n_rows ||
        child_cs.n_columns != child_shape.child_w) {
        out.note = "stage3:recursive:" +
                   (registry_why.empty() ? std::string("registry_unavailable")
                                         : registry_why);
        return out;
    }
    std::vector<RCStage3RecursiveChildPin> preliminary_pins;
    preliminary_pins.reserve(children.size());
    for (const AirProof& child : children) {
        ChildPI pi = air_recurse::ExtractChildPublicInputs(
            child_cs, child, child_fs_seed);
        pi.child_constraints.clear();
        pi.ok = true;
        pi.note.clear();
        preliminary_pins.push_back({std::move(pi)});
    }
    const uint256 expected_fixed =
        ComputeRCStage3RecursiveChildPinsCommitment(
            role, ctl_child_commitment, preliminary_pins);
    if (fixed_role_commitment != expected_fixed) {
        out.note = "stage3:recursive:fixed_commitment_mismatch";
        return out;
    }
    out.proof.fixed_role_commitment = fixed_role_commitment;
    const uint256 seed = ComputeRCStage3RecursiveRoleSeed(
        statement, role, fixed_role_commitment, position);
    air_recurse::AggregateResult aggregate = air_recurse::ProveAggregate(
        child_cs, children, child_fs_seed, seed,
        RCStage3MandatoryVerifierAirFamilies());
    if (!aggregate.ok || !aggregate.witness_satisfies) {
        out.note = "stage3:recursive:aggregate:" + aggregate.note;
        return out;
    }
    out.proof.root = std::move(aggregate.proof);
    out.proof.children.reserve(aggregate.pis.size());
    for (auto& pi : aggregate.pis) {
        pi.child_constraints.clear();
        pi.ok = true;
        pi.note.clear();
        out.proof.children.push_back({std::move(pi)});
    }

    // Confirm every extracted child resolves to the same immutable registry
    // shape before returning even an R&D carrier.
    for (const auto& pin : out.proof.children) {
        air_quotient::AirConstraintSystem<Fp3> resolved;
        if (!resolver(role, pin.public_inputs, resolved, &registry_why) ||
            !SameConstraintShape(child_cs, resolved)) {
            out.note = "stage3:recursive:registry_shape_changed";
            out.proof = {};
            return out;
        }
    }
    out.readiness =
        AssessRCStage3RecursiveReadiness(statement, out.proof, resolver);
    out.ok = out.readiness.structurally_valid &&
             out.readiness.constraints_resolved &&
             out.readiness.backend_shape_supported;
    out.note = out.ok ? "stage3:recursive:research_proof_emitted_authority_off"
                      : "stage3:recursive:readiness_gaps";
    return out;
}

} // namespace matmul::v4::rc
