// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_p2_transcript.h>

#include <algorithm>
#include <cmath>
#include <functional>
#include <limits>
#include <utility>

namespace matmul::v4::rc::stage3_multirow_p2_transcript {
namespace {

using gf::Fp;
using gf::Fp3;

inline constexpr uint64_t kShapeDomain =
    kRCFri3AlgShapeCommitDomain;
inline constexpr uint64_t kAirLambdaDomain =
    0x4d525032'4149524cull; // "MRP2AIRL"
inline constexpr uint64_t kFriSeedDomain =
    0x4d525032'46524953ull; // "MRP2FRIS"
inline constexpr uint64_t kZ1Domain =
    0x4d525032'5a314b32ull; // "MRP2Z1K2"
inline constexpr uint64_t kZ2Domain =
    0x4d525032'5a324b32ull; // "MRP2Z2K2"
inline constexpr uint64_t kOodDomain =
    kRCFri3AlgOodEvalCommitDomain;
inline constexpr uint64_t kBatchSeedDomain =
    0x4d525032'42415453ull; // "MRP2BATS"
inline constexpr uint64_t kCoefficientDomain =
    0x4d525032'434f4546ull; // "MRP2COEF"
inline constexpr uint64_t kWeightDomain =
    0x4d525032'57454947ull; // "MRP2WEIG"
inline constexpr uint64_t kFoldStateDomain =
    0x4d525032'464f4c53ull; // "MRP2FOLS"
inline constexpr uint64_t kFoldBetaDomain =
    0x4d525032'464f4c42ull; // "MRP2FOLB"
inline constexpr uint64_t kQuerySeedDomain =
    0x4d525032'51534545ull; // "MRP2QSEE"
inline constexpr uint64_t kQueryCandidateDomain =
    0x4d525032'5143414eull; // "MRP2QCAN"
inline constexpr uint64_t kPaddingDomain =
    0x4d525032'50414430ull; // "MRP2PAD0"

struct HashEvent {
    uint64_t domain{0};
    std::vector<Fp> lanes;
    Fri3AlgDigest digest{};
    bool query_candidate{false};
    bool query_first{false};
};

void AppendU32(std::vector<Fp>& out, uint32_t value)
{
    out.push_back(gf::FromU64(value));
}

void AppendU64(std::vector<Fp>& out, uint64_t value)
{
    AppendU32(out, static_cast<uint32_t>(value));
    AppendU32(out, static_cast<uint32_t>(value >> 32));
}

void AppendSeed(std::vector<Fp>& out, const uint256& seed)
{
    for (uint32_t word = 0; word < 4; ++word) {
        const uint64_t value = seed.GetUint64(word);
        AppendU64(out, value);
    }
}

void AppendDigest(std::vector<Fp>& out, const Fri3AlgDigest& digest)
{
    for (Fp value : digest) {
        out.push_back(gf::Canonical(value));
    }
}

void AppendFp3(std::vector<Fp>& out, const Fp3& value)
{
    out.push_back(gf::Canonical(value.c0));
    out.push_back(gf::Canonical(value.c1));
    out.push_back(gf::Canonical(value.c2));
}

Fp3 DigestFp3(const Fri3AlgDigest& digest)
{
    return {
        gf::Canonical(digest[0]),
        gf::Canonical(digest[1]),
        gf::Canonical(digest[2])};
}

bool DigestEqual(const Fri3AlgDigest& a, const Fri3AlgDigest& b)
{
    for (uint32_t i = 0; i < a.size(); ++i) {
        if (gf::Canonical(a[i]) != gf::Canonical(b[i])) {
            return false;
        }
    }
    return true;
}

bool Fp3Equal(const Fp3& a, const Fp3& b)
{
    return gf::Eq(a, b);
}

Fri3AlgDigest Hash(std::vector<HashEvent>* events,
                   uint64_t domain,
                   const std::vector<Fp>& lanes)
{
    const auto digest =
        Fri3AlgAlgebraicTranscriptDigest(lanes, domain);
    if (events != nullptr) {
        events->push_back({domain, lanes, digest});
    }
    return digest;
}

bool PowerOfTwo(uint32_t value)
{
    return value != 0 && (value & (value - 1)) == 0;
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    uint32_t out = 2;
    while (out < value) {
        if (out > std::numeric_limits<uint32_t>::max() / 2) {
            return 0;
        }
        out <<= 1;
    }
    return out;
}

Fp3 Pow(Fp3 base, uint32_t exponent)
{
    Fp3 out = Fp3::One();
    while (exponent != 0) {
        if ((exponent & 1U) != 0) out = gf::Mul(out, base);
        exponent >>= 1;
        if (exponent != 0) base = gf::Mul(base, base);
    }
    return out;
}

bool OodValid(const Fp3& z, uint32_t n_lde)
{
    return !gf::IsZero(z) &&
        (!gf::IsZero(Fp3::FromFp(z.c1)) ||
         !gf::IsZero(Fp3::FromFp(z.c2))) &&
        !gf::Eq(Pow(z, n_lde), Fp3::One());
}

bool StatementShape(const StatementV1& s, uint32_t& n_lde)
{
    if (s.statement_version != kStatementVersionV1 ||
        s.protocol_version != kProtocolVersionV1 ||
        s.protocol_domain != kProtocolDomainV1 ||
        s.public_fs_seed.IsNull() ||
        s.pow_grind_nonce != 0 ||
        s.trace_rows < 2 || !PowerOfTwo(s.trace_rows) ||
        s.trace_columns < 2 ||
        s.quotient_len == 0 ||
        s.n_coeffs == 0 || s.blowup == 0 ||
        uint64_t{s.n_coeffs} * s.blowup >
            std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    const uint32_t expected_coeffs =
        NextPowerOfTwo(std::max(s.trace_rows, s.quotient_len));
    if (expected_coeffs != s.n_coeffs ||
        s.base_column_indices.empty() ||
        s.base_column_indices.size() >= s.trace_columns) {
        return false;
    }
    uint32_t previous = 0;
    for (uint32_t position = 0;
         position < s.base_column_indices.size(); ++position) {
        const uint32_t column = s.base_column_indices[position];
        if (column >= s.trace_columns ||
            (position != 0 && column <= previous)) {
            return false;
        }
        previous = column;
    }
    n_lde = s.n_coeffs * s.blowup;
    if (!PowerOfTwo(n_lde) ||
        n_lde < kMinLdeRowsV1 ||
        n_lde > kMaxLdeRowsV1 ||
        s.column_len.empty() ||
        s.evals_z1.size() != s.column_len.size() ||
        s.evals_z2.size() != s.column_len.size() ||
        s.folds.empty()) {
        return false;
    }
    const std::array<Fri3AlgMultiRowGroupRole, 3> roles{
        Fri3AlgMultiRowGroupRole::MainTrace,
        Fri3AlgMultiRowGroupRole::AuxiliaryTrace,
        Fri3AlgMultiRowGroupRole::Quotient};
    uint32_t cursor = 0;
    for (uint32_t i = 0; i < kGroupsV1; ++i) {
        const auto& group = s.groups[i];
        if (group.role != roles[i] ||
            group.first_column != cursor ||
            group.column_count == 0 ||
            group.n_leaves != n_lde ||
            cursor > s.column_len.size() ||
            group.column_count >
                s.column_len.size() - cursor) {
            return false;
        }
        cursor += group.column_count;
    }
    if (cursor != s.column_len.size() ||
        s.column_len.size() != s.trace_columns + 1 ||
        s.groups[0].column_count != s.base_column_indices.size() ||
        s.groups[1].column_count !=
            s.trace_columns - s.base_column_indices.size() ||
        s.groups[2].column_count != 1) {
        return false;
    }
    for (uint32_t length : s.column_len) {
        if (length == 0 || length > s.n_coeffs) return false;
    }
    uint32_t fold_count = 0;
    for (uint32_t value = s.n_coeffs; value > 1; value >>= 1) {
        ++fold_count;
    }
    if (s.folds.size() != fold_count + 1) return false;
    uint32_t leaves = n_lde;
    for (uint32_t fold = 0; fold < s.folds.size(); ++fold) {
        if (s.folds[fold].n_leaves != leaves ||
            leaves < s.blowup) {
            return false;
        }
        if (fold + 1 < s.folds.size()) leaves >>= 1;
    }
    return leaves == s.blowup &&
        s.folds.back().n_leaves == s.blowup;
}

std::vector<Fp> ShapeLanes(const StatementV1& s)
{
    std::vector<Fp> lanes;
    lanes.reserve(s.column_len.size() + 2);
    AppendU32(lanes, static_cast<uint32_t>(s.column_len.size()));
    AppendU32(lanes, s.n_coeffs);
    for (uint32_t length : s.column_len) AppendU32(lanes, length);
    return lanes;
}

std::vector<Fp> OodLanes(const StatementV1& s, const Fp3& z1,
                         const Fp3& z2)
{
    std::vector<Fp> lanes;
    lanes.reserve(8 + 6 * s.column_len.size());
    AppendU32(lanes, static_cast<uint32_t>(s.evals_z1.size()));
    AppendU32(lanes, static_cast<uint32_t>(s.evals_z2.size()));
    AppendFp3(lanes, z1);
    AppendFp3(lanes, z2);
    for (const auto& value : s.evals_z1) AppendFp3(lanes, value);
    for (const auto& value : s.evals_z2) AppendFp3(lanes, value);
    return lanes;
}

ReceiptV1 DeriveInternal(const StatementV1& s,
                         std::vector<HashEvent>* events)
{
    ReceiptV1 out;
    out.statement_version = s.statement_version;
    out.protocol_version = s.protocol_version;
    out.protocol_domain = s.protocol_domain;
    uint32_t n_lde = 0;
    if (!StatementShape(s, n_lde)) {
        out.note = "stage3:multirow_p2:statement_shape";
        return out;
    }

    out.shape_commit = Hash(events, kShapeDomain, ShapeLanes(s));
    if (!DigestEqual(
            out.shape_commit,
            Fri3AlgShapeCommit(s.n_coeffs, s.column_len))) {
        out.note = "stage3:multirow_p2:shape_commit_mismatch";
        return out;
    }

    std::vector<Fp> lanes;
    AppendU32(lanes, kProtocolVersionV1);
    AppendU64(lanes, kProtocolDomainV1);
    AppendSeed(lanes, s.public_fs_seed);
    AppendU32(lanes, s.trace_rows);
    AppendU32(lanes, s.trace_columns);
    AppendU32(lanes, s.quotient_len);
    AppendU32(lanes, s.n_coeffs);
    AppendU32(lanes, static_cast<uint32_t>(
        s.base_column_indices.size()));
    for (uint32_t index : s.base_column_indices) {
        AppendU32(lanes, index);
    }
    AppendDigest(lanes, s.groups[0].root);
    AppendDigest(lanes, s.groups[1].root);
    out.air_lambda =
        DigestFp3(Hash(events, kAirLambdaDomain, lanes));

    lanes.clear();
    AppendU32(lanes, kProtocolVersionV1);
    AppendSeed(lanes, s.public_fs_seed);
    // Split-RAP fixes this to zero today. It is placed only after Rq exists,
    // so a future taxed nonce cannot grind the AIR-composition lambda.
    AppendU64(lanes, s.pow_grind_nonce);
    AppendFp3(lanes, out.air_lambda);
    AppendU32(lanes, s.trace_rows);
    AppendU32(lanes, s.trace_columns);
    AppendU32(lanes, s.quotient_len);
    AppendU32(lanes, s.n_coeffs);
    AppendU32(lanes, static_cast<uint32_t>(
        s.base_column_indices.size()));
    for (uint32_t index : s.base_column_indices) {
        AppendU32(lanes, index);
    }
    AppendDigest(lanes, out.shape_commit);
    for (const auto& group : s.groups) {
        AppendU32(lanes, static_cast<uint32_t>(group.role));
        AppendU32(lanes, group.first_column);
        AppendU32(lanes, group.column_count);
        AppendU32(lanes, group.n_leaves);
        AppendDigest(lanes, group.root);
    }
    out.fri_seed = Hash(events, kFriSeedDomain, lanes);

    for (uint32_t candidate = 0;
         candidate < kOodCandidatesV1; ++candidate) {
        lanes.clear();
        AppendDigest(lanes, out.fri_seed);
        AppendU32(lanes, n_lde);
        AppendU32(lanes, candidate);
        out.z1_candidates[candidate] =
            DigestFp3(Hash(events, kZ1Domain, lanes));
        if (out.z1_selected == kOodCandidatesV1 &&
            OodValid(out.z1_candidates[candidate], n_lde)) {
            out.z1_selected = candidate;
            out.z1 = out.z1_candidates[candidate];
        }
    }
    if (out.z1_selected == kOodCandidatesV1) {
        out.note = "stage3:multirow_p2:z1_k2_exhausted";
        return out;
    }
    for (uint32_t candidate = 0;
         candidate < kOodCandidatesV1; ++candidate) {
        lanes.clear();
        AppendDigest(lanes, out.fri_seed);
        AppendFp3(lanes, out.z1);
        AppendU32(lanes, n_lde);
        AppendU32(lanes, candidate);
        out.z2_candidates[candidate] =
            DigestFp3(Hash(events, kZ2Domain, lanes));
        if (out.z2_selected == kOodCandidatesV1 &&
            OodValid(out.z2_candidates[candidate], n_lde) &&
            !Fp3Equal(out.z2_candidates[candidate], out.z1)) {
            out.z2_selected = candidate;
            out.z2 = out.z2_candidates[candidate];
        }
    }
    if (out.z2_selected == kOodCandidatesV1) {
        out.note = "stage3:multirow_p2:z2_k2_exhausted";
        return out;
    }

    out.ood_eval_commit =
        Hash(events, kOodDomain, OodLanes(s, out.z1, out.z2));
    if (!DigestEqual(
            out.ood_eval_commit,
            Fri3AlgOodEvalCommit(
                out.z1, out.z2, s.evals_z1, s.evals_z2))) {
        out.note = "stage3:multirow_p2:ood_commit_mismatch";
        return out;
    }

    lanes.clear();
    AppendDigest(lanes, out.fri_seed);
    AppendFp3(lanes, out.z1);
    AppendFp3(lanes, out.z2);
    AppendDigest(lanes, out.ood_eval_commit);
    out.batch_seed = Hash(events, kBatchSeedDomain, lanes);
    out.batching_coefficients.reserve(s.column_len.size());
    for (uint32_t column = 0; column < s.column_len.size(); ++column) {
        lanes.clear();
        AppendDigest(lanes, out.batch_seed);
        AppendU32(lanes, column);
        out.batching_coefficients.push_back(
            DigestFp3(Hash(events, kCoefficientDomain, lanes)));
    }
    lanes.clear();
    AppendDigest(lanes, out.batch_seed);
    AppendU32(lanes, 1);
    out.w1 = DigestFp3(Hash(events, kWeightDomain, lanes));
    lanes.back() = gf::FromU64(2);
    out.w2 = DigestFp3(Hash(events, kWeightDomain, lanes));

    lanes.clear();
    AppendDigest(lanes, out.batch_seed);
    AppendFp3(lanes, out.w1);
    AppendFp3(lanes, out.w2);
    Fri3AlgDigest fold_state =
        Hash(events, kFoldStateDomain, lanes);
    out.fold_challenges.reserve(s.folds.size() - 1);
    for (uint32_t fold = 0; fold < s.folds.size(); ++fold) {
        lanes.clear();
        AppendDigest(lanes, fold_state);
        AppendU32(lanes, fold);
        AppendU32(lanes, s.folds[fold].n_leaves);
        AppendDigest(lanes, s.folds[fold].root);
        fold_state = Hash(events, kFoldStateDomain, lanes);
        // The terminal constant layer is committed and enters the query
        // seed, but there is no fold after it and therefore no beta.
        if (fold + 1 < s.folds.size()) {
            lanes.clear();
            AppendDigest(lanes, fold_state);
            AppendU32(lanes, fold);
            out.fold_challenges.push_back(
                DigestFp3(Hash(events, kFoldBetaDomain, lanes)));
        }
    }

    lanes.clear();
    AppendDigest(lanes, fold_state);
    AppendFp3(lanes, s.final_value);
    AppendU32(lanes, kQueriesV1);
    AppendU32(lanes, kQueryCandidatesV1);
    out.query_seed = Hash(events, kQuerySeedDomain, lanes);

    for (uint32_t query = 0; query < kQueriesV1; ++query) {
        auto& q = out.queries[query];
        for (uint32_t candidate = 0;
             candidate < kQueryCandidatesV1; ++candidate) {
            lanes.clear();
            AppendDigest(lanes, out.query_seed);
            // q < 256 and candidate < 256: one injective u32 schedule word.
            AppendU32(lanes, (query << 8) | candidate);
            q.candidate_digest[candidate] =
                Hash(events, kQueryCandidateDomain, lanes);
            if (events != nullptr) {
                events->back().query_candidate = true;
                events->back().query_first = candidate == 0;
            }
            const uint64_t raw =
                gf::Canonical(q.candidate_digest[candidate][0]);
            // p = 1 (mod 2^k), so rejecting p-1 before masking removes the
            // sole biased residue for every supported power-of-two N.
            (void)raw;
        }
        const auto selection =
            AuditQuerySelectionV1(q.candidate_digest, n_lde);
        if (!selection.valid) {
            out.note = "stage3:multirow_p2:q192_candidate_exhausted";
            return out;
        }
        q.selected_ordinal = selection.selected_ordinal;
        q.index = selection.index;
    }
    out.q192_with_replacement = true;
    out.valid = true;
    out.note = out.valid
        ? "stage3:multirow_p2:q192_k2_with_replacement;"
          "backend_hook_pending"
        : "stage3:multirow_p2:query_sampling";
    return out;
}

bool ReceiptEqual(const ReceiptV1& a, const ReceiptV1& b)
{
    if (a.statement_version != b.statement_version ||
        a.protocol_version != b.protocol_version ||
        a.protocol_domain != b.protocol_domain ||
        !DigestEqual(a.shape_commit, b.shape_commit) ||
        !Fp3Equal(a.air_lambda, b.air_lambda) ||
        !DigestEqual(a.fri_seed, b.fri_seed) ||
        a.z1_selected != b.z1_selected ||
        a.z2_selected != b.z2_selected ||
        !Fp3Equal(a.z1, b.z1) ||
        !Fp3Equal(a.z2, b.z2) ||
        !DigestEqual(a.ood_eval_commit, b.ood_eval_commit) ||
        !DigestEqual(a.batch_seed, b.batch_seed) ||
        a.batching_coefficients.size() !=
            b.batching_coefficients.size() ||
        a.fold_challenges.size() != b.fold_challenges.size() ||
        !Fp3Equal(a.w1, b.w1) || !Fp3Equal(a.w2, b.w2) ||
        !DigestEqual(a.query_seed, b.query_seed) ||
        a.q192_with_replacement != b.q192_with_replacement ||
        a.valid != b.valid) {
        return false;
    }
    for (uint32_t i = 0; i < kOodCandidatesV1; ++i) {
        if (!Fp3Equal(a.z1_candidates[i], b.z1_candidates[i]) ||
            !Fp3Equal(a.z2_candidates[i], b.z2_candidates[i])) {
            return false;
        }
    }
    for (uint32_t i = 0; i < a.batching_coefficients.size(); ++i) {
        if (!Fp3Equal(
                a.batching_coefficients[i],
                b.batching_coefficients[i])) return false;
    }
    for (uint32_t i = 0; i < a.fold_challenges.size(); ++i) {
        if (!Fp3Equal(a.fold_challenges[i], b.fold_challenges[i])) {
            return false;
        }
    }
    for (uint32_t q = 0; q < kQueriesV1; ++q) {
        if (a.queries[q].selected_ordinal !=
                b.queries[q].selected_ordinal ||
            a.queries[q].index != b.queries[q].index) {
            return false;
        }
        for (uint32_t c = 0; c < kQueryCandidatesV1; ++c) {
            if (!DigestEqual(
                    a.queries[q].candidate_digest[c],
                    b.queries[q].candidate_digest[c])) return false;
        }
    }
    return true;
}

void AddConstraint(
    aq::AirConstraintSystem<Fp3>& cs,
    const char* name, aq::AirKind kind, uint32_t degree,
    std::function<Fp3(const std::vector<Fp3>&,
                      const std::vector<Fp3>&)> eval)
{
    aq::AirConstraint<Fp3> c;
    c.name = name;
    c.kind = kind;
    c.alg_degree = degree;
    c.eval = std::move(eval);
    cs.constraints.push_back(std::move(c));
}

bool Applies(aq::AirKind kind, uint32_t row, uint32_t rows)
{
    switch (kind) {
    case aq::AirKind::kEverywhere: return true;
    case aq::AirKind::kTransition: return row + 1 < rows;
    case aq::AirKind::kFirstRow: return row == 0;
    case aq::AirKind::kLastRow: return row + 1 == rows;
    }
    return false;
}

uint64_t CountViolations(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() != cs.n_columns) {
        return std::numeric_limits<uint64_t>::max();
    }
    std::vector<Fp3> cur(cs.n_columns), next(cs.n_columns);
    uint64_t violations = 0;
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        for (uint32_t col = 0; col < cs.n_columns; ++col) {
            if (columns[col].size() != cs.n_rows) {
                return std::numeric_limits<uint64_t>::max();
            }
            cur[col] = columns[col][row];
            next[col] = columns[col][(row + 1) % cs.n_rows];
        }
        for (const auto& constraint : cs.constraints) {
            if (Applies(constraint.kind, row, cs.n_rows) &&
                !gf::IsZero(constraint.eval(cur, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

struct SpongeRow {
    std::array<Fp, alg_hash::kAlgHashRate> absorb{};
    bool terminal{false};
    Fri3AlgDigest digest{};
    bool query_candidate{false};
    bool query_first{false};
};

std::vector<SpongeRow> BuildSpongeRows(const std::vector<HashEvent>& events)
{
    std::vector<SpongeRow> rows;
    for (const auto& event : events) {
        std::vector<Fp> padded;
        padded.reserve(event.lanes.size() + 2 + alg_hash::kAlgHashRate);
        AppendU64(padded, event.domain);
        padded.insert(padded.end(), event.lanes.begin(), event.lanes.end());
        padded.push_back(gf::FromU64(1));
        while (padded.size() % alg_hash::kAlgHashRate != 0) {
            padded.push_back(gf::FromU64(0));
        }
        for (uint32_t off = 0; off < padded.size();
             off += alg_hash::kAlgHashRate) {
            SpongeRow row;
            for (uint32_t lane = 0; lane < alg_hash::kAlgHashRate; ++lane) {
                row.absorb[lane] = padded[off + lane];
            }
            row.terminal =
                off + alg_hash::kAlgHashRate == padded.size();
            row.digest = event.digest;
            row.query_candidate =
                event.query_candidate && row.terminal;
            row.query_first =
                event.query_first && row.terminal;
            rows.push_back(row);
        }
    }
    return rows;
}

void BuildConstraints(const LayoutV1& layout,
                      aq::AirConstraintSystem<Fp3>& cs)
{
    cs.constraints = pa::BuildFixedConstraints(layout.poseidon);
    AddConstraint(
        cs, "stage3.multirow_p2.terminal_boolean",
        aq::AirKind::kEverywhere, 2,
        [column = layout.terminal](const auto& cur, const auto&) {
            return gf::Mul(cur[column],
                           gf::Sub(cur[column], Fp3::One()));
        });
    AddConstraint(
        cs, "stage3.multirow_p2.query_candidate_active_boolean",
        aq::AirKind::kEverywhere, 2,
        [column = layout.query_candidate_active](
            const auto& cur, const auto&) {
            return gf::Mul(
                cur[column], gf::Sub(cur[column], Fp3::One()));
        });
    AddConstraint(
        cs, "stage3.multirow_p2.query_candidate_first_boolean",
        aq::AirKind::kEverywhere, 2,
        [column = layout.query_candidate_first](
            const auto& cur, const auto&) {
            return gf::Mul(
                cur[column], gf::Sub(cur[column], Fp3::One()));
        });
    AddConstraint(
        cs, "stage3.multirow_p2.query_first_implies_active",
        aq::AirKind::kEverywhere, 2,
        [layout](const auto& cur, const auto&) {
            return gf::Mul(
                cur[layout.query_candidate_first],
                gf::Sub(
                    Fp3::One(),
                    cur[layout.query_candidate_active]));
        });
    AddConstraint(
        cs, "stage3.multirow_p2.candidate_valid_boolean",
        aq::AirKind::kEverywhere, 2,
        [column = layout.candidate_valid](
            const auto& cur, const auto&) {
            return gf::Mul(
                cur[column], gf::Sub(cur[column], Fp3::One()));
        });
    AddConstraint(
        cs, "stage3.multirow_p2.candidate_nonminusone_inverse",
        aq::AirKind::kEverywhere, 2,
        [layout](const auto& cur, const auto&) {
            const Fp3 x = gf::Add(
                air_recurse::PermOutputLane(
                    layout.poseidon.perm, cur, 0),
                Fp3::One());
            return gf::Sub(
                gf::Mul(x, cur[layout.candidate_inverse]),
                cur[layout.candidate_valid]);
        });
    AddConstraint(
        cs, "stage3.multirow_p2.candidate_nonminusone_zero_case",
        aq::AirKind::kEverywhere, 2,
        [layout](const auto& cur, const auto&) {
            const Fp3 x = gf::Add(
                air_recurse::PermOutputLane(
                    layout.poseidon.perm, cur, 0),
                Fp3::One());
            return gf::Mul(
                x,
                gf::Sub(
                    Fp3::One(),
                    cur[layout.candidate_valid]));
        });
    AddConstraint(
        cs, "stage3.multirow_p2.candidate_prior_valid_boolean",
        aq::AirKind::kEverywhere, 2,
        [column = layout.candidate_prior_valid](
            const auto& cur, const auto&) {
            return gf::Mul(
                cur[column], gf::Sub(cur[column], Fp3::One()));
        });
    AddConstraint(
        cs, "stage3.multirow_p2.candidate_selected_boolean",
        aq::AirKind::kEverywhere, 2,
        [column = layout.candidate_selected](
            const auto& cur, const auto&) {
            return gf::Mul(
                cur[column], gf::Sub(cur[column], Fp3::One()));
        });
    AddConstraint(
        cs, "stage3.multirow_p2.candidate_first_prior_zero",
        aq::AirKind::kEverywhere, 2,
        [layout](const auto& cur, const auto&) {
            return gf::Mul(
                cur[layout.query_candidate_first],
                cur[layout.candidate_prior_valid]);
        });
    AddConstraint(
        cs, "stage3.multirow_p2.candidate_selected_first_valid",
        aq::AirKind::kEverywhere, 2,
        [layout](const auto& cur, const auto&) {
            return gf::Sub(
                cur[layout.candidate_selected],
                gf::Mul(
                    cur[layout.candidate_valid],
                    gf::Sub(
                        Fp3::One(),
                        cur[layout.candidate_prior_valid])));
        });
    AddConstraint(
        cs, "stage3.multirow_p2.candidate_selected_only_query",
        aq::AirKind::kEverywhere, 2,
        [layout](const auto& cur, const auto&) {
            return gf::Mul(
                cur[layout.candidate_selected],
                gf::Sub(
                    Fp3::One(),
                    cur[layout.query_candidate_active]));
        });
    AddConstraint(
        cs, "stage3.multirow_p2.candidate_second_prior_link",
        aq::AirKind::kTransition, 2,
        [layout](const auto& cur, const auto& next) {
            return gf::Mul(
                cur[layout.query_candidate_first],
                gf::Sub(
                    next[layout.candidate_prior_valid],
                    cur[layout.candidate_valid]));
        });
    AddConstraint(
        cs, "stage3.multirow_p2.candidate_k2_exactly_one",
        aq::AirKind::kTransition, 2,
        [layout](const auto& cur, const auto& next) {
            return gf::Mul(
                cur[layout.query_candidate_first],
                gf::Sub(
                    gf::Add(
                        cur[layout.candidate_selected],
                        next[layout.candidate_selected]),
                    Fp3::One()));
        });
    for (uint32_t lane = 0; lane < alg_hash::kAlgHashT; ++lane) {
        AddConstraint(
            cs, "stage3.multirow_p2.first_sponge_input",
            aq::AirKind::kFirstRow, 1,
            [layout, lane](const auto& cur, const auto&) {
                const Fp3 expected =
                    lane < alg_hash::kAlgHashRate
                    ? cur[layout.Absorb(lane)] : Fp3::Zero();
                return gf::Sub(
                    cur[layout.poseidon.perm.InputCol(lane)], expected);
            });
        AddConstraint(
            cs, "stage3.multirow_p2.sponge_event_transition",
            aq::AirKind::kTransition, 2,
            [layout, lane](const auto& cur, const auto& next) {
                Fp3 expected = Fp3::Zero();
                if (lane < alg_hash::kAlgHashRate) {
                    expected = next[layout.Absorb(lane)];
                }
                expected = gf::Add(
                    expected,
                    gf::Mul(
                        gf::Sub(Fp3::One(), cur[layout.terminal]),
                        air_recurse::PermOutputLane(
                            layout.poseidon.perm, cur, lane)));
                return gf::Sub(
                    next[layout.poseidon.perm.InputCol(lane)], expected);
            });
    }
    for (uint32_t limb = 0; limb < alg_hash::kAlgHashDigestLen; ++limb) {
        AddConstraint(
            cs, "stage3.multirow_p2.event_digest_capture",
            aq::AirKind::kEverywhere, 2,
            [layout, limb](const auto& cur, const auto&) {
                return gf::Mul(
                    cur[layout.terminal],
                    gf::Sub(
                        air_recurse::PermOutputLane(
                            layout.poseidon.perm, cur, limb),
                        cur[layout.DigestClaim(limb)]));
            });
    }
}

} // namespace

ReceiptV1 DeriveV1(const StatementV1& statement)
{
    return DeriveInternal(statement, nullptr);
}

bool VerifyReceiptV1(const StatementV1& statement,
                     const ReceiptV1& receipt,
                     std::string* why)
{
    const auto expected = DeriveV1(statement);
    if (!expected.valid) {
        if (why) *why = expected.note;
        return false;
    }
    if (!ReceiptEqual(expected, receipt)) {
        if (why) *why = "stage3:multirow_p2:receipt_mismatch";
        return false;
    }
    if (why) *why = "stage3:multirow_p2:receipt_verified";
    return true;
}

double QueryExhaustionBitsV1(uint32_t n_lde,
                             uint32_t queries,
                             uint32_t candidates)
{
    if (!PowerOfTwo(n_lde) || n_lde < kMinLdeRowsV1 ||
        n_lde > kMaxLdeRowsV1 || queries == 0 ||
        queries > n_lde || candidates == 0) {
        return 0.0;
    }
    // With-replacement FRI permits duplicates. The only rejection is p-1,
    // hence one fixed K-window exhausts with probability p^-K.
    const long double per_candidate =
        1.0L / static_cast<long double>(gf::kP);
    const long double failure =
        static_cast<long double>(queries) *
        std::pow(per_candidate, candidates);
    return -std::log2(static_cast<double>(failure));
}

QuerySelectionAuditV1 AuditQuerySelectionV1(
    const std::array<Fri3AlgDigest, kQueryCandidatesV1>& candidates,
    uint32_t n_lde)
{
    QuerySelectionAuditV1 out;
    if (!PowerOfTwo(n_lde) ||
        n_lde < kMinLdeRowsV1 ||
        n_lde > kMaxLdeRowsV1) {
        ++out.constraint_violations;
        return out;
    }
    bool prior_valid = false;
    uint32_t selected_count = 0;
    for (uint32_t candidate = 0;
         candidate < kQueryCandidatesV1; ++candidate) {
        const uint64_t raw =
            gf::Canonical(candidates[candidate][0]);
        out.candidate_valid[candidate] = raw != gf::kP - 1;
        out.selected[candidate] =
            out.candidate_valid[candidate] && !prior_valid;
        if (out.selected[candidate]) {
            ++selected_count;
            out.selected_ordinal = candidate;
            out.index =
                static_cast<uint32_t>(raw) & (n_lde - 1);
        }
        prior_valid =
            prior_valid || out.candidate_valid[candidate];
    }
    if (selected_count != 1) ++out.constraint_violations;
    out.valid = out.constraint_violations == 0;
    return out;
}

BackendHookAuditV1 AssessBackendHooksV1()
{
    BackendHookAuditV1 out;
    out.additive_version_and_domain =
        kProtocolVersionV1 != kLegacyMultiRowVersionV2 &&
        kProtocolDomainV1 != 0;
    // Deliberately false until the frozen base gets a new envelope. Listing
    // exact symbols prevents a readiness flag from hiding this dependency.
    out.exact_hooks =
        "1) add a V11 branch beside Fri3AlgMultiRowBatchCommitStreaming "
        "after the three ordered row roots are committed; 2) feed its exact "
        "roots/lengths/evals/folds to DeriveV1 and use the returned z, "
        "independent coefficients, weights, betas and unbiased Q192 indices; "
        "3) add the same replay branch beside Fri3AlgMultiRowBatchVerify; "
        "4) allocate a new magic/version in "
        "Serialize/DeserializeFri3AlgMultiRowBatchProof (never reinterpret "
        "FMR2); 5) version AirQuotientSplitRapRowsProof dispatch so "
        "AirQuotientProve/VerifyRowsSplitRap select that new backend.";
    return out;
}

LayoutV1 CanonicalLayoutV1()
{
    LayoutV1 out;
    out.poseidon = pa::CanonicalLayout(0);
    uint32_t cursor = out.poseidon.End();
    out.absorb_base = cursor;
    cursor += alg_hash::kAlgHashRate;
    out.terminal = cursor++;
    out.digest_claim_base = cursor;
    cursor += alg_hash::kAlgHashDigestLen;
    out.query_candidate_active = cursor++;
    out.query_candidate_first = cursor++;
    out.candidate_valid = cursor++;
    out.candidate_inverse = cursor++;
    out.candidate_prior_valid = cursor++;
    out.candidate_selected = cursor++;
    out.n_columns = cursor;
    return out;
}

ProductV1 BuildProductV1(const StatementV1& statement)
{
    ProductV1 out;
    out.layout = CanonicalLayoutV1();
    out.statement = statement;
    std::vector<HashEvent> events;
    out.receipt = DeriveInternal(statement, &events);
    if (!out.receipt.valid) {
        out.note = out.receipt.note;
        return out;
    }
    out.hash_events = static_cast<uint32_t>(events.size());
    auto rows = BuildSpongeRows(events);
    out.real_sponge_rows = static_cast<uint32_t>(rows.size());
    out.trace_rows = NextPowerOfTwo(out.real_sponge_rows);
    if (out.trace_rows == 0) {
        out.note = "stage3:multirow_p2:trace_rows";
        return out;
    }
    while (rows.size() < out.trace_rows) {
        HashEvent padding;
        padding.domain = kPaddingDomain;
        AppendU32(padding.lanes, static_cast<uint32_t>(rows.size()));
        padding.digest = Fri3AlgAlgebraicTranscriptDigest(
            padding.lanes, padding.domain);
        auto one = BuildSpongeRows({padding});
        if (one.size() != 1) {
            out.note = "stage3:multirow_p2:padding_shape";
            return out;
        }
        rows.push_back(one.front());
    }

    out.cs.n_rows = out.trace_rows;
    out.cs.n_columns = out.layout.n_columns;
    BuildConstraints(out.layout, out.cs);
    out.constraints = static_cast<uint32_t>(out.cs.constraints.size());
    for (const auto& constraint : out.cs.constraints) {
        out.max_constraint_degree =
            std::max(out.max_constraint_degree, constraint.alg_degree);
    }
    out.columns.assign(
        out.layout.n_columns,
        std::vector<Fp3>(out.trace_rows, Fp3::Zero()));
    auto set = [&out](uint32_t col, uint32_t row, const Fp3& value) {
        out.columns[col][row] = value;
    };
    alg_hash::State state{};
    for (uint32_t row = 0; row < out.trace_rows; ++row) {
        if (row == 0 || rows[row - 1].terminal) state = {};
        for (uint32_t lane = 0; lane < alg_hash::kAlgHashRate; ++lane) {
            set(out.layout.Absorb(lane), row,
                Fp3::FromFp(rows[row].absorb[lane]));
            state[lane] = gf::Add(state[lane], rows[row].absorb[lane]);
        }
        const auto witness = pa::BuildWitness(out.layout.poseidon, state);
        for (uint32_t col = 0; col < out.layout.poseidon.End(); ++col) {
            set(col, row, witness.row[col]);
        }
        state = witness.output;
        set(out.layout.terminal, row,
            rows[row].terminal ? Fp3::One() : Fp3::Zero());
        for (uint32_t limb = 0; limb < alg_hash::kAlgHashDigestLen; ++limb) {
            set(out.layout.DigestClaim(limb), row,
                Fp3::FromFp(rows[row].digest[limb]));
        }
        set(out.layout.query_candidate_active, row,
            rows[row].query_candidate ? Fp3::One() : Fp3::Zero());
        set(out.layout.query_candidate_first, row,
            rows[row].query_first ? Fp3::One() : Fp3::Zero());
        const Fp3 x = gf::Add(
            Fp3::FromFp(state[0]), Fp3::One());
        const bool candidate_valid = !gf::IsZero(x);
        set(out.layout.candidate_valid, row,
            candidate_valid ? Fp3::One() : Fp3::Zero());
        set(out.layout.candidate_inverse, row,
            candidate_valid ? gf::Inv(x) : Fp3::Zero());
        bool prior_valid = true;
        if (rows[row].query_candidate) {
            prior_valid = rows[row].query_first
                ? false
                : row != 0 &&
                  gf::Canonical(rows[row - 1].digest[0]) != gf::kP - 1;
        }
        set(out.layout.candidate_prior_valid, row,
            prior_valid ? Fp3::One() : Fp3::Zero());
        const bool selected =
            rows[row].query_candidate &&
            candidate_valid && !prior_valid;
        set(out.layout.candidate_selected, row,
            selected ? Fp3::One() : Fp3::Zero());
    }
    for (uint32_t lane = 0; lane < alg_hash::kAlgHashRate; ++lane) {
        out.preprocessed_columns.push_back(out.layout.Absorb(lane));
    }
    out.preprocessed_columns.push_back(out.layout.terminal);
    for (uint32_t limb = 0; limb < alg_hash::kAlgHashDigestLen; ++limb) {
        out.preprocessed_columns.push_back(out.layout.DigestClaim(limb));
    }
    out.preprocessed_columns.push_back(
        out.layout.query_candidate_active);
    out.preprocessed_columns.push_back(
        out.layout.query_candidate_first);
    for (uint32_t col : out.preprocessed_columns) {
        out.cs.preprocessed.emplace_back(col, out.columns[col]);
    }
    out.cs.preprocessed_pin_ood = true;
    const auto base_session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            out.cs, out.columns, out.preprocessed_columns);
    if (!base_session.valid ||
        base_session.base_row_commitment.IsNull()) {
        out.note = "stage3:multirow_p2:preprocessed_root:" +
            base_session.note;
        return out;
    }
    out.preprocessed_row_group_root =
        base_session.base_row_commitment;
    out.cs.preprocessed_row_group_roots.push_back({
        .version = 1,
        .role = aq::AirPreprocessedRowGroupRole::kR0,
        .ordered_columns = out.preprocessed_columns,
        .root = out.preprocessed_row_group_root,
    });
    out.violations = CountViolations(out.cs, out.columns);
    out.full_root_and_length_binding = true;
    out.full_ood_binding_before_batching = true;
    out.independent_batching_coefficients_host_derived = true;
    out.independent_batching_consumer_air_constrained = false;
    out.k2_ood_selection_host_derived = true;
    out.k2_ood_selection_air_constrained = false;
    out.q192_with_replacement_host_derived =
        out.receipt.q192_with_replacement;
    out.q192_k2_first_valid_air_constrained = true;
    out.q192_selected_index_consumer_air_constrained = false;
    out.canonical_u64_split = true;
    out.exact_host_poseidon_air_equivalence = out.violations == 0;
    out.preprocessed_event_tape_root_pinned = true;
    out.proof_owned_sources_bound = false;
    out.production_authority_ready = false;
    out.valid =
        out.receipt.valid &&
        out.full_root_and_length_binding &&
        out.full_ood_binding_before_batching &&
        out.independent_batching_coefficients_host_derived &&
        out.k2_ood_selection_host_derived &&
        out.q192_with_replacement_host_derived &&
        out.q192_k2_first_valid_air_constrained &&
        out.canonical_u64_split &&
        out.exact_host_poseidon_air_equivalence &&
        out.preprocessed_event_tape_root_pinned &&
        out.frozen_v2_unchanged &&
        out.violations == 0 &&
        !out.proof_owned_sources_bound &&
        !out.production_authority_ready;
    out.note = out.valid
        ? "stage3:multirow_p2:constant_width_replay;"
          "selection_consumer_air_and_backend_pending"
        : "stage3:multirow_p2:constraint_failure";
    return out;
}

} // namespace matmul::v4::rc::stage3_multirow_p2_transcript
