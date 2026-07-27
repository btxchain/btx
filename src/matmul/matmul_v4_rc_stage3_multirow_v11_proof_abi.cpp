// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_proof_abi.h>

#include <algorithm>
#include <limits>
#include <set>
#include <tuple>

namespace matmul::v4::rc::stage3_multirow_v11_proof_abi {
namespace {

using gf::Fp;
using gf::Fp3;

bool PowerOfTwo(uint32_t value)
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

bool CanonicalFp(Fp value)
{
    return value < gf::kP;
}

bool CanonicalFp3(const Fp3& value)
{
    return CanonicalFp(value.c0) &&
        CanonicalFp(value.c1) &&
        CanonicalFp(value.c2);
}

bool CanonicalDigest(const Fri3AlgDigest& value)
{
    return std::all_of(
        value.begin(), value.end(), CanonicalFp);
}

SourceKeyV1 K(
    FieldKindV1 kind,
    uint32_t a = 0,
    uint32_t b = 0,
    uint32_t c = 0,
    uint32_t d = 0,
    uint8_t limb = 0)
{
    return {kind, a, b, c, d, limb};
}

OwnershipClassV1 OwnershipFor(FieldKindV1 kind)
{
    switch (kind) {
    case FieldKindV1::PublicFsSeed:
    case FieldKindV1::TraceRows:
    case FieldKindV1::TraceColumns:
    case FieldKindV1::QuotientLen:
    case FieldKindV1::BaseColumnCount:
    case FieldKindV1::BaseColumnIndex:
    case FieldKindV1::AirConstraintLambda:
        return OwnershipClassV1::PublicStatement;
    case FieldKindV1::QueryCandidateCount:
    case FieldKindV1::QueryCandidateDigest:
    case FieldKindV1::QuerySelectedCandidate:
        return OwnershipClassV1::DerivedTranscript;
    default:
        return OwnershipClassV1::ChildProofEnvelope;
    }
}

class Cursor {
public:
    explicit Cursor(std::vector<uint32_t>& words)
        : m_out(&words)
    {
        words.clear();
        words.resize(kFieldAbiHeaderWordsV1);
    }

    explicit Cursor(const std::vector<uint32_t>& words)
        : m_in(&words)
    {
        if (words.size() >= kFieldAbiHeaderWordsV1) {
            m_expected_cells = words[5];
        }
    }

    [[nodiscard]] bool Decoding() const { return m_in != nullptr; }
    [[nodiscard]] bool Good() const { return m_good; }
    [[nodiscard]] const std::string& Why() const { return m_why; }
    [[nodiscard]] const std::vector<SourceCellV1>& Sources() const
    {
        return m_sources;
    }

    bool U32(uint32_t& value, const SourceKeyV1& key)
    {
        if (!m_good ||
            m_address >= kFieldAbiMaxSourceCellsV1) {
            return Fail("source_cell_cap");
        }
        if (Decoding()) {
            const size_t position =
                kFieldAbiHeaderWordsV1 +
                size_t{m_address} * 2;
            if (position + 2 > m_in->size() ||
                (*m_in)[position] != m_address) {
                return Fail("source_address_order");
            }
            value = (*m_in)[position + 1];
        } else {
            m_out->push_back(m_address);
            m_out->push_back(value);
        }
        m_sources.push_back({
            m_address, key, value, OwnershipFor(key.kind)});
        ++m_address;
        return true;
    }

    bool U64(uint64_t& value, const SourceKeyV1& key)
    {
        uint32_t lo = static_cast<uint32_t>(value);
        uint32_t hi = static_cast<uint32_t>(value >> 32);
        if (!U32(lo, WithLimb(key, 0)) ||
            !U32(hi, WithLimb(key, 1))) {
            return false;
        }
        if (Decoding()) {
            value = uint64_t{lo} | (uint64_t{hi} << 32);
        }
        return true;
    }

    bool Field(Fp& value, const SourceKeyV1& key)
    {
        uint64_t raw = value;
        if (!U64(raw, key)) return false;
        if (raw >= gf::kP) return Fail("noncanonical_fp");
        value = raw;
        return true;
    }

    bool Field3(Fp3& value, const SourceKeyV1& key)
    {
        return Field(value.c0, WithD(key, 0)) &&
            Field(value.c1, WithD(key, 1)) &&
            Field(value.c2, WithD(key, 2));
    }

    bool Digest(Fri3AlgDigest& value, const SourceKeyV1& key)
    {
        for (uint32_t i = 0; i < value.size(); ++i) {
            if (!Field(value[i], WithD(key, i))) return false;
        }
        return true;
    }

    bool Finish()
    {
        if (!m_good) return false;
        if (Decoding()) {
            if (m_address != m_expected_cells ||
                m_in->size() !=
                    kFieldAbiHeaderWordsV1 +
                    size_t{m_expected_cells} * 2) {
                return Fail("trailing_or_missing_cells");
            }
        } else {
            (*m_out)[0] = kFieldAbiMagicV1;
            (*m_out)[1] = kFieldAbiVersionV1;
            (*m_out)[2] = kMultiRowProtocolVersionV11;
            (*m_out)[3] =
                static_cast<uint32_t>(kMultiRowProtocolDomainV11);
            (*m_out)[4] =
                static_cast<uint32_t>(kMultiRowProtocolDomainV11 >> 32);
            (*m_out)[5] = m_address;
        }
        return true;
    }

private:
    static SourceKeyV1 WithLimb(SourceKeyV1 key, uint8_t limb)
    {
        key.limb = limb;
        return key;
    }

    static SourceKeyV1 WithD(SourceKeyV1 key, uint32_t d)
    {
        key.d = d;
        return key;
    }

    bool Fail(const char* why)
    {
        if (m_good) m_why = why;
        m_good = false;
        return false;
    }

    std::vector<uint32_t>* m_out{nullptr};
    const std::vector<uint32_t>* m_in{nullptr};
    uint32_t m_expected_cells{0};
    uint32_t m_address{0};
    bool m_good{true};
    std::string m_why;
    std::vector<SourceCellV1> m_sources;
};

bool HeaderValid(const std::vector<uint32_t>& words, std::string* why)
{
    const uint32_t domain_lo =
        static_cast<uint32_t>(kMultiRowProtocolDomainV11);
    const uint32_t domain_hi =
        static_cast<uint32_t>(kMultiRowProtocolDomainV11 >> 32);
    if (words.size() < kFieldAbiHeaderWordsV1 ||
        words[0] != kFieldAbiMagicV1 ||
        words[1] != kFieldAbiVersionV1 ||
        words[2] != kMultiRowProtocolVersionV11 ||
        words[3] != domain_lo ||
        words[4] != domain_hi ||
        words[5] > kFieldAbiMaxSourceCellsV1 ||
        words.size() !=
            kFieldAbiHeaderWordsV1 + size_t{words[5]} * 2) {
        if (why) *why = "stage3:multirow_v11_abi:header_or_length";
        return false;
    }
    return true;
}

bool ValidateShape(const EnvelopeV1& envelope, std::string* why)
{
    const auto fail = [&](const char* detail) {
        if (why) {
            *why = std::string{"stage3:multirow_v11_abi:"} + detail;
        }
        return false;
    };
    const auto& split = envelope.split;
    const auto& batch = split.batch;
    if (split.version != 1 ||
        split.trace_rows < 2 ||
        !PowerOfTwo(split.trace_rows) ||
        batch.version != kRCFri3AlgMultiRowBatchProofVersion ||
        batch.blowup != kRCFriBlowup ||
        batch.n_coeffs < 2 ||
        !PowerOfTwo(batch.n_coeffs) ||
        uint64_t{batch.n_coeffs} * batch.blowup >
            (uint64_t{1} << kRCFriMaxLdeLog2) ||
        batch.groups.size() != 3 ||
        batch.column_len.size() < 3 ||
        batch.column_len.size() > kRCFri3AlgBatchMaxColumns) {
        return fail("outer_shape");
    }
    const uint32_t n_lde = batch.n_coeffs * batch.blowup;
    const uint32_t width =
        static_cast<uint32_t>(batch.column_len.size() - 1);
    if (envelope.trace_columns != width ||
        envelope.quotient_len != batch.column_len.back() ||
        split.base_column_indices.empty() ||
        split.base_column_indices.size() >= width ||
        split.base_column_indices.size() !=
            batch.groups[0].column_count) {
        return fail("statement_shape");
    }
    uint32_t previous = 0;
    for (uint32_t i = 0; i < split.base_column_indices.size(); ++i) {
        const uint32_t index = split.base_column_indices[i];
        if (index >= width || (i != 0 && index <= previous)) {
            return fail("base_indices");
        }
        previous = index;
    }
    const std::array<Fri3AlgMultiRowGroupRole, 3> roles{
        Fri3AlgMultiRowGroupRole::MainTrace,
        Fri3AlgMultiRowGroupRole::AuxiliaryTrace,
        Fri3AlgMultiRowGroupRole::Quotient};
    uint32_t first = 0;
    for (uint32_t g = 0; g < 3; ++g) {
        const auto& group = batch.groups[g];
        if (group.role != roles[g] ||
            group.first_column != first ||
            group.column_count == 0 ||
            group.column_count >
                batch.column_len.size() - first ||
            group.row_commit.n_leaves != n_lde ||
            !CanonicalDigest(group.row_commit.root)) {
            return fail("group_shape");
        }
        first += group.column_count;
    }
    if (first != batch.column_len.size() ||
        batch.groups[0].column_count !=
            split.base_column_indices.size() ||
        batch.groups[1].first_column !=
            split.base_column_indices.size() ||
        batch.groups[1].column_count !=
            width - split.base_column_indices.size() ||
        batch.groups[2].first_column != width ||
        batch.groups[2].column_count != 1) {
        return fail("group_partition");
    }
    uint32_t max_len = 0;
    for (uint32_t c = 0; c < batch.column_len.size(); ++c) {
        const uint32_t length = batch.column_len[c];
        if (length == 0 || length > batch.n_coeffs ||
            (c < width && length != split.trace_rows)) {
            return fail("column_lengths");
        }
        max_len = std::max(max_len, length);
    }
    uint32_t padded = 1;
    while (padded < max_len) padded <<= 1;
    if (padded != batch.n_coeffs ||
        envelope.quotient_len == 0 ||
        !CanonicalFp3(split.air_constraint_lambda) ||
        !CanonicalFp3(batch.lambda) ||
        !CanonicalFp3(batch.z1) ||
        !CanonicalFp3(batch.z2) ||
        !CanonicalFp3(batch.w1) ||
        !CanonicalFp3(batch.w2) ||
        !CanonicalFp3(batch.final_value) ||
        batch.evals_z1.size() != batch.column_len.size() ||
        batch.evals_z2.size() != batch.column_len.size()) {
        return fail("claim_shape");
    }
    for (const auto& value : batch.evals_z1) {
        if (!CanonicalFp3(value)) return fail("eval_z1_canonical");
    }
    for (const auto& value : batch.evals_z2) {
        if (!CanonicalFp3(value)) return fail("eval_z2_canonical");
    }
    const uint32_t folds = Log2Exact(batch.n_coeffs);
    const uint32_t row_depth = Log2Exact(n_lde);
    if (batch.fold_layers.size() != size_t{folds} + 1 ||
        batch.fold_challenges.size() != folds ||
        batch.queries.size() != kQueryCountV11 ||
        split.next_trace_group_rows.size() != kQueryCountV11) {
        return fail("fri_shape");
    }
    for (uint32_t f = 0; f < batch.fold_layers.size(); ++f) {
        if (batch.fold_layers[f].n_leaves != (n_lde >> f) ||
            !CanonicalDigest(batch.fold_layers[f].root)) {
            return fail("fold_layer");
        }
    }
    for (const auto& beta : batch.fold_challenges) {
        if (!CanonicalFp3(beta)) return fail("fold_beta_canonical");
    }
    for (uint32_t q = 0; q < kQueryCountV11; ++q) {
        const auto& query = batch.queries[q];
        if (query.index >= n_lde ||
            query.group_rows.size() != 3 ||
            query.steps.size() != folds) {
            return fail("query_index_or_shape");
        }
        for (uint32_t g = 0; g < 3; ++g) {
            const auto& row = query.group_rows[g];
            if (row.values.size() != batch.groups[g].column_count ||
                row.siblings.size() != row_depth) {
                return fail("current_row_shape");
            }
            for (const auto& value : row.values) {
                if (!CanonicalFp3(value)) return fail("current_value_canonical");
            }
            for (const auto& digest : row.siblings) {
                if (!CanonicalDigest(digest)) {
                    return fail("current_path_canonical");
                }
            }
        }
        uint32_t index = query.index;
        for (uint32_t f = 0; f < folds; ++f) {
            const auto& step = query.steps[f];
            const uint32_t half = (n_lde >> f) / 2;
            const uint32_t even = index % half;
            if (step.even_index != even ||
                step.odd_index != even + half ||
                step.even_siblings.size() != row_depth - f ||
                step.odd_siblings.size() != row_depth - f ||
                !CanonicalFp3(step.even) ||
                !CanonicalFp3(step.odd)) {
                return fail("fold_step_shape");
            }
            for (const auto& digest : step.even_siblings) {
                if (!CanonicalDigest(digest)) return fail("even_path_canonical");
            }
            for (const auto& digest : step.odd_siblings) {
                if (!CanonicalDigest(digest)) return fail("odd_path_canonical");
            }
            index %= half;
        }
        const auto& next = split.next_trace_group_rows[q];
        if (next.size() != 2) return fail("next_group_count");
        for (uint32_t g = 0; g < 2; ++g) {
            if (next[g].values.size() != batch.groups[g].column_count ||
                next[g].siblings.size() != row_depth) {
                return fail("next_row_shape");
            }
            for (const auto& value : next[g].values) {
                if (!CanonicalFp3(value)) return fail("next_value_canonical");
            }
            for (const auto& digest : next[g].siblings) {
                if (!CanonicalDigest(digest)) return fail("next_path_canonical");
            }
        }
    }
    return true;
}

bool Walk(Cursor& cursor, EnvelopeV1& envelope)
{
    auto& split = envelope.split;
    auto& batch = split.batch;
    for (uint32_t i = 0; i < envelope.public_fs_seed.size(); ++i) {
        if (!cursor.U32(
                envelope.public_fs_seed[i],
                K(FieldKindV1::PublicFsSeed, i))) return false;
    }
    uint32_t split_version = split.version;
    if (!cursor.U32(split_version, K(FieldKindV1::SplitVersion))) return false;
    if (cursor.Decoding()) split.version = static_cast<uint16_t>(split_version);
    if (!cursor.U32(split.trace_rows, K(FieldKindV1::TraceRows)) ||
        !cursor.U32(
            envelope.trace_columns, K(FieldKindV1::TraceColumns)) ||
        !cursor.U32(
            envelope.quotient_len, K(FieldKindV1::QuotientLen))) return false;
    uint32_t base_count =
        static_cast<uint32_t>(split.base_column_indices.size());
    if (!cursor.U32(base_count, K(FieldKindV1::BaseColumnCount))) return false;
    if (cursor.Decoding()) {
        if (base_count == 0 || base_count > kRCFri3AlgBatchMaxColumns) {
            return false;
        }
        split.base_column_indices.resize(base_count);
    }
    for (uint32_t i = 0; i < base_count; ++i) {
        if (!cursor.U32(
                split.base_column_indices[i],
                K(FieldKindV1::BaseColumnIndex, i))) return false;
    }
    if (!cursor.Field3(
            split.air_constraint_lambda,
            K(FieldKindV1::AirConstraintLambda))) return false;

    if (!cursor.U32(batch.version, K(FieldKindV1::BatchVersion)) ||
        !cursor.U64(
            batch.pow_grind_nonce, K(FieldKindV1::PowGrindNonce)) ||
        !cursor.U32(batch.blowup, K(FieldKindV1::Blowup)) ||
        !cursor.U32(batch.n_coeffs, K(FieldKindV1::NCoeffs))) return false;
    uint32_t group_count = static_cast<uint32_t>(batch.groups.size());
    if (!cursor.U32(group_count, K(FieldKindV1::GroupCount))) return false;
    if (cursor.Decoding()) {
        if (group_count != 3) return false;
        batch.groups.resize(group_count);
    }
    for (uint32_t g = 0; g < group_count; ++g) {
        auto& group = batch.groups[g];
        uint32_t role = static_cast<uint32_t>(group.role);
        if (!cursor.U32(role, K(FieldKindV1::GroupRole, g)) ||
            !cursor.U32(
                group.first_column, K(FieldKindV1::GroupFirstColumn, g)) ||
            !cursor.U32(
                group.column_count, K(FieldKindV1::GroupColumnCount, g)) ||
            !cursor.Digest(
                group.row_commit.root, K(FieldKindV1::GroupRoot, g)) ||
            !cursor.U32(
                group.row_commit.n_leaves,
                K(FieldKindV1::GroupLeaves, g))) return false;
        if (cursor.Decoding()) {
            group.role = static_cast<Fri3AlgMultiRowGroupRole>(role);
        }
    }
    uint32_t column_count = static_cast<uint32_t>(batch.column_len.size());
    if (!cursor.U32(column_count, K(FieldKindV1::ColumnCount))) return false;
    if (cursor.Decoding()) {
        if (column_count < 3 || column_count > kRCFri3AlgBatchMaxColumns) {
            return false;
        }
        batch.column_len.resize(column_count);
    }
    for (uint32_t c = 0; c < column_count; ++c) {
        if (!cursor.U32(
                batch.column_len[c], K(FieldKindV1::ColumnLen, c))) return false;
    }
    if (!cursor.Field3(batch.lambda, K(FieldKindV1::Lambda)) ||
        !cursor.Field3(batch.z1, K(FieldKindV1::Z1)) ||
        !cursor.Field3(batch.z2, K(FieldKindV1::Z2))) return false;
    uint32_t eval_count = static_cast<uint32_t>(batch.evals_z1.size());
    if (!cursor.U32(eval_count, K(FieldKindV1::EvalZ1Count))) return false;
    if (cursor.Decoding()) {
        if (eval_count != column_count) return false;
        batch.evals_z1.resize(eval_count);
    }
    for (uint32_t c = 0; c < eval_count; ++c) {
        if (!cursor.Field3(
                batch.evals_z1[c], K(FieldKindV1::EvalZ1, c))) return false;
    }
    eval_count = static_cast<uint32_t>(batch.evals_z2.size());
    if (!cursor.U32(eval_count, K(FieldKindV1::EvalZ2Count))) return false;
    if (cursor.Decoding()) {
        if (eval_count != column_count) return false;
        batch.evals_z2.resize(eval_count);
    }
    for (uint32_t c = 0; c < eval_count; ++c) {
        if (!cursor.Field3(
                batch.evals_z2[c], K(FieldKindV1::EvalZ2, c))) return false;
    }
    if (!cursor.Field3(batch.w1, K(FieldKindV1::DeepWeight1)) ||
        !cursor.Field3(batch.w2, K(FieldKindV1::DeepWeight2))) return false;
    uint32_t fold_layers = static_cast<uint32_t>(batch.fold_layers.size());
    if (!cursor.U32(
            fold_layers, K(FieldKindV1::FoldLayerCount))) return false;
    if (cursor.Decoding()) {
        if (fold_layers < 2 || fold_layers > kRCFriMaxLdeLog2 + 1) {
            return false;
        }
        batch.fold_layers.resize(fold_layers);
    }
    for (uint32_t f = 0; f < fold_layers; ++f) {
        if (!cursor.Digest(
                batch.fold_layers[f].root,
                K(FieldKindV1::FoldRoot, f)) ||
            !cursor.U32(
                batch.fold_layers[f].n_leaves,
                K(FieldKindV1::FoldLeaves, f))) return false;
    }
    if (!cursor.Field3(batch.final_value, K(FieldKindV1::FinalValue))) {
        return false;
    }
    uint32_t fold_challenges =
        static_cast<uint32_t>(batch.fold_challenges.size());
    if (!cursor.U32(
            fold_challenges,
            K(FieldKindV1::FoldChallengeCount))) return false;
    if (cursor.Decoding()) {
        if (fold_challenges > kRCFriMaxLdeLog2) return false;
        batch.fold_challenges.resize(fold_challenges);
    }
    for (uint32_t f = 0; f < fold_challenges; ++f) {
        if (!cursor.Field3(
                batch.fold_challenges[f],
                K(FieldKindV1::FoldChallenge, f))) return false;
    }
    uint32_t queries = static_cast<uint32_t>(batch.queries.size());
    if (!cursor.U32(queries, K(FieldKindV1::QueryCount))) return false;
    if (cursor.Decoding()) {
        if (queries != kQueryCountV11) return false;
        batch.queries.resize(queries);
    }
    for (uint32_t q = 0; q < queries; ++q) {
        auto& query = batch.queries[q];
        if (!cursor.U32(query.index, K(FieldKindV1::QueryIndex, q))) return false;
        uint32_t opened_groups =
            static_cast<uint32_t>(query.group_rows.size());
        if (!cursor.U32(
                opened_groups, K(FieldKindV1::QueryGroupCount, q))) return false;
        if (cursor.Decoding()) {
            if (opened_groups != 3) return false;
            query.group_rows.resize(opened_groups);
        }
        for (uint32_t g = 0; g < opened_groups; ++g) {
            auto& row = query.group_rows[g];
            uint32_t values = static_cast<uint32_t>(row.values.size());
            if (!cursor.U32(
                    values,
                    K(FieldKindV1::QueryRowValueCount, q, g))) return false;
            if (cursor.Decoding()) {
                if (g >= batch.groups.size() ||
                    values != batch.groups[g].column_count) return false;
                row.values.resize(values);
            }
            for (uint32_t v = 0; v < values; ++v) {
                if (!cursor.Field3(
                        row.values[v],
                        K(FieldKindV1::QueryRowValue, q, g, v))) return false;
            }
            uint32_t siblings = static_cast<uint32_t>(row.siblings.size());
            if (!cursor.U32(
                    siblings,
                    K(FieldKindV1::QueryRowSiblingCount, q, g))) return false;
            if (cursor.Decoding()) {
                if (siblings > kRCFriMaxLdeLog2) return false;
                row.siblings.resize(siblings);
            }
            for (uint32_t s = 0; s < siblings; ++s) {
                if (!cursor.Digest(
                        row.siblings[s],
                        K(FieldKindV1::QueryRowSibling, q, g, s))) return false;
            }
        }
        uint32_t steps = static_cast<uint32_t>(query.steps.size());
        if (!cursor.U32(
                steps, K(FieldKindV1::QueryStepCount, q))) return false;
        if (cursor.Decoding()) {
            if (steps > kRCFriMaxLdeLog2) return false;
            query.steps.resize(steps);
        }
        for (uint32_t f = 0; f < steps; ++f) {
            auto& step = query.steps[f];
            if (!cursor.U32(
                    step.even_index,
                    K(FieldKindV1::QueryStepEvenIndex, q, f)) ||
                !cursor.U32(
                    step.odd_index,
                    K(FieldKindV1::QueryStepOddIndex, q, f)) ||
                !cursor.Field3(
                    step.even, K(FieldKindV1::QueryStepEven, q, f)) ||
                !cursor.Field3(
                    step.odd, K(FieldKindV1::QueryStepOdd, q, f))) return false;
            uint32_t siblings =
                static_cast<uint32_t>(step.even_siblings.size());
            if (!cursor.U32(
                    siblings,
                    K(FieldKindV1::QueryStepEvenSiblingCount, q, f))) {
                return false;
            }
            if (cursor.Decoding()) {
                if (siblings > kRCFriMaxLdeLog2) return false;
                step.even_siblings.resize(siblings);
            }
            for (uint32_t s = 0; s < siblings; ++s) {
                if (!cursor.Digest(
                        step.even_siblings[s],
                        K(FieldKindV1::QueryStepEvenSibling, q, f, s))) {
                    return false;
                }
            }
            siblings = static_cast<uint32_t>(step.odd_siblings.size());
            if (!cursor.U32(
                    siblings,
                    K(FieldKindV1::QueryStepOddSiblingCount, q, f))) {
                return false;
            }
            if (cursor.Decoding()) {
                if (siblings > kRCFriMaxLdeLog2) return false;
                step.odd_siblings.resize(siblings);
            }
            for (uint32_t s = 0; s < siblings; ++s) {
                if (!cursor.Digest(
                        step.odd_siblings[s],
                        K(FieldKindV1::QueryStepOddSibling, q, f, s))) {
                    return false;
                }
            }
        }
    }
    uint32_t next_queries =
        static_cast<uint32_t>(split.next_trace_group_rows.size());
    if (!cursor.U32(next_queries, K(FieldKindV1::NextQueryCount))) return false;
    if (cursor.Decoding()) {
        if (next_queries != kQueryCountV11) return false;
        split.next_trace_group_rows.resize(next_queries);
    }
    for (uint32_t q = 0; q < next_queries; ++q) {
        auto& next = split.next_trace_group_rows[q];
        uint32_t groups = static_cast<uint32_t>(next.size());
        if (!cursor.U32(
                groups, K(FieldKindV1::NextGroupCount, q))) return false;
        if (cursor.Decoding()) {
            if (groups != 2) return false;
            next.resize(groups);
        }
        for (uint32_t g = 0; g < groups; ++g) {
            auto& row = next[g];
            uint32_t values = static_cast<uint32_t>(row.values.size());
            if (!cursor.U32(
                    values,
                    K(FieldKindV1::NextRowValueCount, q, g))) return false;
            if (cursor.Decoding()) {
                if (g >= batch.groups.size() ||
                    values != batch.groups[g].column_count) return false;
                row.values.resize(values);
            }
            for (uint32_t v = 0; v < values; ++v) {
                if (!cursor.Field3(
                        row.values[v],
                        K(FieldKindV1::NextRowValue, q, g, v))) return false;
            }
            uint32_t siblings = static_cast<uint32_t>(row.siblings.size());
            if (!cursor.U32(
                    siblings,
                    K(FieldKindV1::NextRowSiblingCount, q, g))) return false;
            if (cursor.Decoding()) {
                if (siblings > kRCFriMaxLdeLog2) return false;
                row.siblings.resize(siblings);
            }
            for (uint32_t s = 0; s < siblings; ++s) {
                if (!cursor.Digest(
                        row.siblings[s],
                        K(FieldKindV1::NextRowSibling, q, g, s))) return false;
            }
        }
    }
    return cursor.Finish();
}

} // namespace

bool SourceKeyV1::operator<(const SourceKeyV1& other) const
{
    return std::tie(kind, a, b, c, d, limb) <
        std::tie(
            other.kind, other.a, other.b, other.c,
            other.d, other.limb);
}

bool ValidateSourceCellsV1(
    const std::vector<SourceCellV1>& sources,
    std::string* why)
{
    std::set<uint32_t> addresses;
    std::set<SourceKeyV1> keys;
    for (uint32_t i = 0; i < sources.size(); ++i) {
        if (sources[i].address != i ||
            !addresses.insert(sources[i].address).second) {
            if (why) *why = "stage3:multirow_v11_abi:address_collision";
            return false;
        }
        if (!keys.insert(sources[i].key).second) {
            if (why) *why = "stage3:multirow_v11_abi:semantic_key_collision";
            return false;
        }
    }
    if (why) *why = "stage3:multirow_v11_abi:sources_unique";
    return true;
}

std::optional<uint32_t> FindSourceAddressV1(
    const std::vector<SourceCellV1>& sources,
    const SourceKeyV1& key)
{
    std::optional<uint32_t> found;
    for (const auto& source : sources) {
        if (source.key == key) {
            if (found.has_value()) return std::nullopt;
            found = source.address;
        }
    }
    return found;
}

DerivedTranscriptExportsV1 BuildDerivedQueryCandidateExportsV1(
    const DecodedV1& decoded,
    const std::array<QueryCandidatesV1, kQueryCountV11>& candidates)
{
    DerivedTranscriptExportsV1 out;
    if (!decoded.canonical || !decoded.complete ||
        decoded.envelope.split.batch.queries.size() != kQueryCountV11) {
        out.note = "stage3:multirow_v11_abi:decoded_proof_required";
        return out;
    }
    const uint32_t n_lde =
        decoded.envelope.split.batch.n_coeffs *
        decoded.envelope.split.batch.blowup;
    uint32_t address = kDerivedTranscriptAddressBaseV1;
    out.canonical_candidates = true;
    out.k2_first_valid = true;
    out.selected_indices_match_proof = true;
    for (uint32_t q = 0; q < kQueryCountV11; ++q) {
        bool prior_valid = false;
        uint32_t expected_selected = kQueryCandidatesV11;
        uint32_t expected_index = 0;
        for (uint32_t c = 0; c < kQueryCandidatesV11; ++c) {
            if (!CanonicalDigest(candidates[q].digest[c])) {
                out.canonical_candidates = false;
                out.note =
                    "stage3:multirow_v11_abi:derived_candidate_noncanonical";
                return out;
            }
            for (uint32_t d = 0; d < candidates[q].digest[c].size(); ++d) {
                const uint64_t raw = candidates[q].digest[c][d];
                out.sources.push_back({
                    address++,
                    K(FieldKindV1::QueryCandidateDigest, q, c, 0, d, 0),
                    static_cast<uint32_t>(raw),
                    OwnershipClassV1::DerivedTranscript});
                out.sources.push_back({
                    address++,
                    K(FieldKindV1::QueryCandidateDigest, q, c, 0, d, 1),
                    static_cast<uint32_t>(raw >> 32),
                    OwnershipClassV1::DerivedTranscript});
            }
            const uint64_t raw = candidates[q].digest[c][0];
            const bool valid = raw != gf::kP - 1;
            if (valid && !prior_valid) {
                expected_selected = c;
                expected_index =
                    static_cast<uint32_t>(raw) & (n_lde - 1);
            }
            prior_valid = prior_valid || valid;
        }
        out.sources.push_back({
            address++,
            K(FieldKindV1::QuerySelectedCandidate, q),
            candidates[q].selected_ordinal,
            OwnershipClassV1::DerivedTranscript});
        if (expected_selected == kQueryCandidatesV11 ||
            candidates[q].selected_ordinal != expected_selected) {
            out.k2_first_valid = false;
        }
        if (expected_index !=
            decoded.envelope.split.batch.queries[q].index) {
            out.selected_indices_match_proof = false;
        }
    }
    out.transcript_equality_constrained = false;
    out.recursively_consumed = false;
    out.valid =
        out.canonical_candidates &&
        out.k2_first_valid &&
        out.selected_indices_match_proof;
    out.note = out.valid
        ? "stage3:multirow_v11_abi:derived_candidates_locally_matched;"
          "p2_equality_join_pending"
        : "stage3:multirow_v11_abi:derived_candidate_mismatch";
    return out;
}

PublicStatementJoinV1 BuildPublicStatementJoinV1(
    const DecodedV1& decoded,
    const std::vector<ParentPublicCellV1>& parent)
{
    PublicStatementJoinV1 out;
    if (!decoded.canonical || !decoded.complete) {
        out.note = "stage3:multirow_v11_abi:decoded_public_sources_required";
        return out;
    }
    std::vector<const SourceCellV1*> required;
    for (const auto& source : decoded.sources) {
        if (source.ownership == OwnershipClassV1::PublicStatement) {
            required.push_back(&source);
        }
    }
    out.required_cells = static_cast<uint32_t>(required.size());
    if (parent.size() != required.size()) {
        out.note = "stage3:multirow_v11_abi:public_inventory_size";
        return out;
    }
    std::set<uint32_t> columns;
    std::set<SourceKeyV1> keys;
    out.parent_columns_unique = true;
    out.values_equal = true;
    for (const auto& cell : parent) {
        if (!columns.insert(cell.parent_column).second ||
            !keys.insert(cell.key).second) {
            out.parent_columns_unique = false;
            out.note = "stage3:multirow_v11_abi:public_parent_collision";
            return out;
        }
    }
    for (const SourceCellV1* source : required) {
        const auto found = std::find_if(
            parent.begin(), parent.end(),
            [&](const ParentPublicCellV1& cell) {
                return cell.key == source->key;
            });
        if (found == parent.end()) {
            out.note = "stage3:multirow_v11_abi:public_cell_omitted";
            return out;
        }
        if (found->value != source->value) {
            out.values_equal = false;
            out.note = "stage3:multirow_v11_abi:public_value_mismatch";
            return out;
        }
        out.equalities.push_back({
            source->address, found->parent_column});
        ++out.matched_cells;
    }
    out.exact_public_inventory =
        out.matched_cells == out.required_cells &&
        keys.size() == required.size();
    out.actual_air_constraints_appended = false;
    out.valid =
        out.exact_public_inventory &&
        out.values_equal &&
        out.parent_columns_unique;
    out.note = out.valid
        ? "stage3:multirow_v11_abi:public_join_plan_complete;"
          "air_append_pending"
        : "stage3:multirow_v11_abi:public_join_incomplete";
    return out;
}

bool EncodeCanonicalV1(
    const EnvelopeV1& envelope,
    std::vector<uint32_t>& words,
    std::vector<SourceCellV1>* sources,
    std::string* why)
{
    if (!ValidateShape(envelope, why)) {
        words.clear();
        if (sources) sources->clear();
        return false;
    }
    EnvelopeV1 copy = envelope;
    Cursor cursor(words);
    if (!Walk(cursor, copy)) {
        words.clear();
        if (sources) sources->clear();
        if (why) {
            *why = "stage3:multirow_v11_abi:encode:" + cursor.Why();
        }
        return false;
    }
    std::string source_why;
    if (!ValidateSourceCellsV1(cursor.Sources(), &source_why)) {
        words.clear();
        if (sources) sources->clear();
        if (why) *why = source_why;
        return false;
    }
    if (sources) *sources = cursor.Sources();
    if (why) *why = "stage3:multirow_v11_abi:encoded";
    return true;
}

std::optional<DecodedV1> DecodeCanonicalV1(
    const std::vector<uint32_t>& words,
    std::string* why)
{
    if (!HeaderValid(words, why)) return std::nullopt;
    DecodedV1 out;
    Cursor cursor(words);
    if (!Walk(cursor, out.envelope)) {
        if (why) {
            *why = "stage3:multirow_v11_abi:decode:" + cursor.Why();
        }
        return std::nullopt;
    }
    std::string shape_why;
    if (!ValidateShape(out.envelope, &shape_why)) {
        if (why) *why = shape_why;
        return std::nullopt;
    }
    std::string source_why;
    if (!ValidateSourceCellsV1(cursor.Sources(), &source_why)) {
        if (why) *why = source_why;
        return std::nullopt;
    }
    std::vector<uint32_t> canonical;
    if (!EncodeCanonicalV1(
            out.envelope, canonical, nullptr, nullptr) ||
        canonical != words) {
        if (why) *why = "stage3:multirow_v11_abi:noncanonical_reencode";
        return std::nullopt;
    }
    out.sources = cursor.Sources();
    for (const auto& source : out.sources) {
        switch (source.ownership) {
        case OwnershipClassV1::PublicStatement:
            ++out.public_statement_cells;
            break;
        case OwnershipClassV1::ChildProofEnvelope:
            ++out.child_proof_cells;
            break;
        case OwnershipClassV1::DerivedTranscript:
            ++out.derived_transcript_cells;
            break;
        }
    }
    out.canonical = true;
    out.complete = true;
    out.addresses_unique = true;
    out.semantic_keys_unique = true;
    out.note =
        "stage3:multirow_v11_abi:canonical_complete;"
        "backend_and_authority_pending";
    if (why) *why = out.note;
    return out;
}

} // namespace matmul::v4::rc::stage3_multirow_v11_proof_abi
