// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_backend.h>

#include <matmul/matmul_v4_rc_alg_hash.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <set>

namespace matmul::v4::rc::stage3_multirow_v11_backend {
namespace {

using gf::Add;
using gf::Canonical;
using gf::Eq;
using gf::Fp;
using gf::Fp3;
using gf::Inv;
using gf::Mul;
using gf::Sub;

constexpr Fp kOmega2_32 = 0x185629dcda58878cULL;

bool PowerOfTwo(uint32_t value)
{
    return value != 0 && (value & (value - 1)) == 0;
}

uint32_t Log2Exact(uint32_t value)
{
    if (!PowerOfTwo(value)) return 0;
    uint32_t out = 0;
    while (value > 1) {
        value >>= 1;
        ++out;
    }
    return out;
}

Fp PowFp(Fp base, uint64_t exponent)
{
    Fp out = 1;
    while (exponent != 0) {
        if ((exponent & 1U) != 0) out = Mul(out, base);
        base = Mul(base, base);
        exponent >>= 1;
    }
    return out;
}

Fp3 PowFp3(Fp3 base, uint64_t exponent)
{
    Fp3 out = Fp3::One();
    while (exponent != 0) {
        if ((exponent & 1U) != 0) out = Mul(out, base);
        base = Mul(base, base);
        exponent >>= 1;
    }
    return out;
}

Fp OmegaForSize(uint32_t n)
{
    const uint32_t logn = Log2Exact(n);
    if (logn == 0 || logn > 32) return 0;
    return PowFp(kOmega2_32, uint64_t{1} << (32 - logn));
}

Fp3 DomainPoint(uint32_t n, uint32_t index)
{
    return Fp3::FromFp(PowFp(OmegaForSize(n), index));
}

void BitReverse(std::vector<Fp3>& values)
{
    size_t j = 0;
    for (size_t i = 1; i < values.size(); ++i) {
        size_t bit = values.size() >> 1;
        for (; (j & bit) != 0; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) std::swap(values[i], values[j]);
    }
}

void Ntt(std::vector<Fp3>& values, bool inverse = false)
{
    const size_t n = values.size();
    if (n <= 1) return;
    BitReverse(values);
    Fp omega = OmegaForSize(static_cast<uint32_t>(n));
    if (inverse) omega = Inv(omega);
    for (size_t len = 2; len <= n; len <<= 1) {
        const Fp step = PowFp(omega, n / len);
        for (size_t base = 0; base < n; base += len) {
            Fp w = 1;
            for (size_t j = 0; j < len / 2; ++j) {
                const Fp3 a = values[base + j];
                const Fp3 b =
                    gf::MulBase(values[base + j + len / 2], w);
                values[base + j] = Add(a, b);
                values[base + j + len / 2] = Sub(a, b);
                w = Mul(w, step);
            }
        }
    }
    if (inverse) {
        const Fp inv_n = Inv(static_cast<Fp>(n));
        for (auto& value : values) value = gf::MulBase(value, inv_n);
    }
}

std::vector<Fp3> Lde(
    const std::vector<Fp3>& coefficients,
    uint32_t blowup)
{
    std::vector<Fp3> values(
        coefficients.size() * blowup, Fp3::Zero());
    std::copy(coefficients.begin(), coefficients.end(), values.begin());
    Ntt(values);
    return values;
}

std::vector<Fp3> Interpolate(std::vector<Fp3> evaluations)
{
    Ntt(evaluations, true);
    return evaluations;
}

std::vector<Fp3> EvalOnSubgroup(
    const std::vector<Fp3>& coefficients,
    uint32_t size)
{
    std::vector<Fp3> out(size, Fp3::Zero());
    std::copy(coefficients.begin(), coefficients.end(), out.begin());
    Ntt(out);
    return out;
}

void CosetShift(std::vector<Fp3>& coefficients)
{
    Fp power = 1;
    for (auto& value : coefficients) {
        value = gf::MulBase(value, power);
        power = Mul(power, air_quotient::kAirCosetShift);
    }
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    if (value <= 1) return 1;
    --value;
    value |= value >> 1;
    value |= value >> 2;
    value |= value >> 4;
    value |= value >> 8;
    value |= value >> 16;
    return value + 1;
}

Fp3 Selector(
    air_quotient::AirKind kind,
    uint32_t rows,
    const Fp3& y,
    const Fp3& first,
    const Fp3& last)
{
    const auto zh_over = [&](const Fp3& at) {
        const Fp3 denominator = Sub(y, at);
        if (!gf::IsZero(denominator)) {
            return Mul(
                Sub(PowFp3(y, rows), Fp3::One()),
                Inv(denominator));
        }
        return Mul(
            Fp3::FromFp(rows), PowFp3(at, rows - 1));
    };
    switch (kind) {
    case air_quotient::AirKind::kEverywhere:
        return Fp3::One();
    case air_quotient::AirKind::kTransition:
        return Sub(y, last);
    case air_quotient::AirKind::kFirstRow:
        return zh_over(first);
    case air_quotient::AirKind::kLastRow:
        return zh_over(last);
    }
    return Fp3::Zero();
}

Fp3 Eval(
    const std::vector<Fp3>& coefficients,
    const Fp3& point)
{
    Fp3 out = Fp3::Zero();
    for (size_t i = coefficients.size(); i-- > 0;) {
        out = Add(Mul(out, point), coefficients[i]);
    }
    return out;
}

std::vector<Fp3> SyntheticQuotient(
    const std::vector<Fp3>& coefficients,
    const Fp3& point,
    const Fp3& value)
{
    if (coefficients.size() <= 1) return {};
    std::vector<Fp3> numerator = coefficients;
    numerator[0] = Sub(numerator[0], value);
    std::vector<Fp3> out(
        numerator.size() - 1, Fp3::Zero());
    out.back() = numerator.back();
    for (size_t k = numerator.size() - 1; k-- > 1;) {
        out[k - 1] = Add(numerator[k], Mul(point, out[k]));
    }
    return out;
}

bool FoldLayer(
    const std::vector<Fp3>& current,
    const Fp3& beta,
    std::vector<Fp3>& next)
{
    if (current.size() < 2 || (current.size() & 1U) != 0) return false;
    const uint32_t half = static_cast<uint32_t>(current.size() / 2);
    const Fp3 inv2 = Inv(Fp3::FromFp(2));
    next.resize(half);
    for (uint32_t i = 0; i < half; ++i) {
        const Fp3 x =
            DomainPoint(static_cast<uint32_t>(current.size()), i);
        if (gf::IsZero(x)) return false;
        const Fp3 even = Mul(Add(current[i], current[i + half]), inv2);
        const Fp3 odd = Mul(
            Sub(current[i], current[i + half]),
            Mul(inv2, Inv(x)));
        next[i] = Add(even, Mul(beta, odd));
    }
    return true;
}

bool FoldPair(
    const Fp3& left,
    const Fp3& right,
    const Fp3& x,
    const Fp3& beta,
    Fp3& out)
{
    if (gf::IsZero(x)) return false;
    const Fp3 inv2 = Inv(Fp3::FromFp(2));
    const Fp3 even = Mul(Add(left, right), inv2);
    const Fp3 odd = Mul(Sub(left, right), Mul(inv2, Inv(x)));
    out = Add(even, Mul(beta, odd));
    return true;
}

struct Tree {
    std::vector<std::vector<Fri3AlgDigest>> levels;
    Fri3AlgDigest root{};
};

Tree BuildTreeFromLeaves(std::vector<Fri3AlgDigest> leaves)
{
    Tree out;
    if (leaves.empty()) return out;
    out.levels.push_back(std::move(leaves));
    while (out.levels.back().size() > 1) {
        const auto& current = out.levels.back();
        const size_t parents = (current.size() + 1) / 2;
        std::vector<Fri3AlgDigest> next(parents);
        for (size_t i = 0; i < parents; ++i) {
            const auto& left = current[2 * i];
            const auto& right =
                2 * i + 1 < current.size() ? current[2 * i + 1] : left;
            next[i] = alg_hash::Compress(left, right);
        }
        out.levels.push_back(std::move(next));
    }
    out.root = out.levels.back().front();
    return out;
}

Tree BuildFoldTree(const std::vector<Fp3>& values)
{
    std::vector<Fri3AlgDigest> leaves(values.size());
    for (uint32_t i = 0; i < values.size(); ++i) {
        leaves[i] = alg_hash::LeafHash(values[i], i);
    }
    return BuildTreeFromLeaves(std::move(leaves));
}

std::vector<Fri3AlgDigest> Path(
    const Tree& tree,
    uint32_t index)
{
    std::vector<Fri3AlgDigest> out;
    uint32_t cursor = index;
    for (size_t level = 0; level + 1 < tree.levels.size(); ++level) {
        const auto& nodes = tree.levels[level];
        const uint32_t sibling = cursor ^ 1U;
        out.push_back(
            sibling < nodes.size() ? nodes[sibling] : nodes[cursor]);
        cursor >>= 1;
    }
    return out;
}

Fri3AlgFoldStep OpenFold(
    const std::vector<Fp3>& values,
    const Tree& tree,
    uint32_t index)
{
    Fri3AlgFoldStep out;
    const uint32_t half = static_cast<uint32_t>(values.size() / 2);
    out.even_index = index % half;
    out.odd_index = out.even_index + half;
    out.even = values[out.even_index];
    out.odd = values[out.odd_index];
    out.even_siblings = Path(tree, out.even_index);
    out.odd_siblings = Path(tree, out.odd_index);
    return out;
}

bool VerifyFold(
    const Fri3AlgFoldStep& step,
    const Fri3AlgLayerCommit& layer,
    const Fp3& beta,
    uint32_t index,
    Fp3& folded)
{
    if (layer.n_leaves < 2 || !PowerOfTwo(layer.n_leaves)) return false;
    const uint32_t half = layer.n_leaves / 2;
    const uint32_t even = index % half;
    if (step.even_index != even ||
        step.odd_index != even + half ||
        !Fri3AlgVerifyPath(
            alg_hash::LeafHash(step.even, step.even_index),
            step.even_index, step.even_siblings,
            layer.root, layer.n_leaves) ||
        !Fri3AlgVerifyPath(
            alg_hash::LeafHash(step.odd, step.odd_index),
            step.odd_index, step.odd_siblings,
            layer.root, layer.n_leaves)) {
        return false;
    }
    return FoldPair(
        step.even, step.odd,
        DomainPoint(layer.n_leaves, even),
        beta, folded);
}

bool DigestEqual(
    const Fri3AlgDigest& a,
    const Fri3AlgDigest& b)
{
    for (uint32_t i = 0; i < a.size(); ++i) {
        if (Canonical(a[i]) != Canonical(b[i])) return false;
    }
    return true;
}

bool Fp3Equal(const Fp3& a, const Fp3& b)
{
    return Eq(a, b);
}

std::array<uint32_t, 8> SeedWords(const uint256& seed)
{
    std::array<uint32_t, 8> out{};
    for (uint32_t i = 0; i < out.size(); ++i) {
        out[i] =
            uint32_t{seed.begin()[4 * i]} |
            (uint32_t{seed.begin()[4 * i + 1]} << 8) |
            (uint32_t{seed.begin()[4 * i + 2]} << 16) |
            (uint32_t{seed.begin()[4 * i + 3]} << 24);
    }
    return out;
}

uint256 SeedFromWords(const std::array<uint32_t, 8>& words)
{
    uint256 out;
    for (uint32_t i = 0; i < words.size(); ++i) {
        const uint32_t value = words[i];
        out.begin()[4 * i] = static_cast<unsigned char>(value);
        out.begin()[4 * i + 1] =
            static_cast<unsigned char>(value >> 8);
        out.begin()[4 * i + 2] =
            static_cast<unsigned char>(value >> 16);
        out.begin()[4 * i + 3] =
            static_cast<unsigned char>(value >> 24);
    }
    return out;
}

std::vector<uint32_t> ColumnLengths(
    uint32_t trace_columns,
    uint32_t trace_rows,
    uint32_t quotient_len)
{
    std::vector<uint32_t> out(trace_columns, trace_rows);
    out.push_back(quotient_len);
    return out;
}

std::vector<uint32_t> FoldSizes(uint32_t n_coeffs)
{
    std::vector<uint32_t> out;
    uint32_t leaves = n_coeffs * kRCFriBlowup;
    for (;;) {
        out.push_back(leaves);
        if (leaves == kRCFriBlowup) break;
        leaves >>= 1;
    }
    return out;
}

p2::TranscriptSkeletonV1 Skeleton(
    const uint256& public_fs_seed,
    uint32_t trace_rows,
    uint32_t trace_columns,
    uint32_t quotient_len,
    uint32_t n_coeffs,
    const std::vector<uint32_t>& base_indices,
    const Fri3AlgDigest& r0,
    const Fri3AlgDigest& rdep,
    const Fri3AlgDigest& rq)
{
    p2::TranscriptSkeletonV1 out;
    out.public_fs_seed = public_fs_seed;
    out.trace_rows = trace_rows;
    out.trace_columns = trace_columns;
    out.quotient_len = quotient_len;
    out.n_coeffs = n_coeffs;
    out.base_column_indices = base_indices;
    out.column_len =
        ColumnLengths(trace_columns, trace_rows, quotient_len);
    out.fold_n_leaves = FoldSizes(n_coeffs);
    const uint32_t dep =
        trace_columns - static_cast<uint32_t>(base_indices.size());
    const uint32_t n_lde = n_coeffs * kRCFriBlowup;
    out.groups = {{
        {Fri3AlgMultiRowGroupRole::MainTrace, 0,
         static_cast<uint32_t>(base_indices.size()), n_lde, r0},
        {Fri3AlgMultiRowGroupRole::AuxiliaryTrace,
         static_cast<uint32_t>(base_indices.size()), dep, n_lde, rdep},
        {Fri3AlgMultiRowGroupRole::Quotient,
         trace_columns, 1, n_lde, rq},
    }};
    return out;
}

p2::StatementV1 Statement(const ProofV1& proof)
{
    const auto& envelope = proof.envelope;
    const auto& split = envelope.split;
    const auto& batch = split.batch;
    p2::StatementV1 out;
    out.public_fs_seed = SeedFromWords(envelope.public_fs_seed);
    out.pow_grind_nonce = batch.pow_grind_nonce;
    out.trace_rows = split.trace_rows;
    out.trace_columns = envelope.trace_columns;
    out.quotient_len = envelope.quotient_len;
    out.n_coeffs = batch.n_coeffs;
    out.blowup = batch.blowup;
    out.base_column_indices = split.base_column_indices;
    for (uint32_t g = 0; g < out.groups.size() && g < batch.groups.size(); ++g) {
        out.groups[g] = {
            batch.groups[g].role,
            batch.groups[g].first_column,
            batch.groups[g].column_count,
            batch.groups[g].row_commit.n_leaves,
            batch.groups[g].row_commit.root};
    }
    out.column_len = batch.column_len;
    out.evals_z1 = batch.evals_z1;
    out.evals_z2 = batch.evals_z2;
    out.folds.reserve(batch.fold_layers.size());
    for (const auto& fold : batch.fold_layers) {
        out.folds.push_back({fold.n_leaves, fold.root});
    }
    out.final_value = batch.final_value;
    return out;
}

bool TranscriptMatches(
    const ProofV1& proof,
    const p2::ReceiptV1& receipt,
    std::string* why)
{
    const auto fail = [&](const char* detail) {
        if (why) *why = std::string{"stage3:v11_verify:"} + detail;
        return false;
    };
    const auto& split = proof.envelope.split;
    const auto& batch = split.batch;
    if (!receipt.valid ||
        !Fp3Equal(split.air_constraint_lambda, receipt.air_lambda) ||
        receipt.batching_coefficients.size() != batch.column_len.size() ||
        receipt.batching_coefficients.empty() ||
        !Fp3Equal(batch.lambda, receipt.batching_coefficients[0]) ||
        !Fp3Equal(batch.z1, receipt.z1) ||
        !Fp3Equal(batch.z2, receipt.z2) ||
        !Fp3Equal(batch.w1, receipt.w1) ||
        !Fp3Equal(batch.w2, receipt.w2) ||
        batch.fold_challenges.size() != receipt.fold_challenges.size() ||
        batch.queries.size() != p2::kQueriesV1 ||
        !receipt.q192_with_replacement) {
        return fail("transcript_scalar");
    }
    for (uint32_t f = 0; f < batch.fold_challenges.size(); ++f) {
        if (!Fp3Equal(
                batch.fold_challenges[f], receipt.fold_challenges[f])) {
            return fail("fold_challenge");
        }
    }
    for (uint32_t q = 0; q < p2::kQueriesV1; ++q) {
        if (batch.queries[q].index != receipt.queries[q].index ||
            receipt.queries[q].selected_ordinal >=
                p2::kQueryCandidatesV1) {
            return fail("query_index");
        }
    }
    return true;
}

void Append32(std::vector<unsigned char>& out, uint32_t value)
{
    for (uint32_t i = 0; i < 4; ++i) {
        out.push_back(static_cast<unsigned char>(value >> (8 * i)));
    }
}

void Append64(std::vector<unsigned char>& out, uint64_t value)
{
    for (uint32_t i = 0; i < 8; ++i) {
        out.push_back(static_cast<unsigned char>(value >> (8 * i)));
    }
}

bool Read32(
    const unsigned char*& cursor,
    const unsigned char* end,
    uint32_t& value)
{
    if (size_t(end - cursor) < 4) return false;
    value = uint32_t{cursor[0]} |
        (uint32_t{cursor[1]} << 8) |
        (uint32_t{cursor[2]} << 16) |
        (uint32_t{cursor[3]} << 24);
    cursor += 4;
    return true;
}

bool Read64(
    const unsigned char*& cursor,
    const unsigned char* end,
    uint64_t& value)
{
    if (size_t(end - cursor) < 8) return false;
    value = 0;
    for (uint32_t i = 0; i < 8; ++i) {
        value |= uint64_t{cursor[i]} << (8 * i);
    }
    cursor += 8;
    return true;
}

} // namespace

TracePrecommitV1 PrecommitTraceV1(
    const std::vector<std::vector<Fp3>>& r0,
    const std::vector<std::vector<Fp3>>& rdep,
    uint32_t trace_rows,
    uint32_t trace_columns,
    uint32_t quotient_len,
    uint32_t n_coeffs,
    const std::vector<uint32_t>& base_column_indices,
    const uint256& public_fs_seed)
{
    TracePrecommitV1 out;
    const auto fail = [&](const std::string& detail) {
        out.note = "stage3:v11_precommit:" + detail;
        return out;
    };
    if (public_fs_seed.IsNull() ||
        !PowerOfTwo(trace_rows) ||
        !PowerOfTwo(n_coeffs) ||
        trace_rows > n_coeffs ||
        quotient_len == 0 ||
        quotient_len > n_coeffs ||
        n_coeffs * uint64_t{kRCFriBlowup} < p2::kMinLdeRowsV1 ||
        r0.empty() || rdep.empty() ||
        r0.size() != base_column_indices.size() ||
        r0.size() + rdep.size() != trace_columns) {
        return fail("shape");
    }
    uint32_t previous = 0;
    for (uint32_t i = 0; i < base_column_indices.size(); ++i) {
        if (base_column_indices[i] >= trace_columns ||
            (i != 0 && base_column_indices[i] <= previous)) {
            return fail("base_indices");
        }
        previous = base_column_indices[i];
    }
    for (const auto& column : r0) {
        if (column.size() != trace_rows) return fail("r0_length");
    }
    for (const auto& column : rdep) {
        if (column.size() != trace_rows) return fail("rdep_length");
    }
    out.r0_cache = std::make_shared<Fri3AlgRowTreeCache>();
    out.rdep_cache = std::make_shared<Fri3AlgRowTreeCache>();
    std::string why;
    if (!Fri3AlgBuildRowTreeCacheStreaming(
            r0, n_coeffs, *out.r0_cache, &why)) {
        return fail("r0_commit:" + why);
    }
    if (!Fri3AlgBuildRowTreeCacheStreaming(
            rdep, n_coeffs, *out.rdep_cache, &why)) {
        return fail("rdep_commit:" + why);
    }

    // Rq is deliberately unavailable. BeginIncremental derives air_lambda
    // solely from R0/Rdep; the placeholder is discarded before any later
    // transcript output is used.
    const Fri3AlgDigest no_quotient_root{};
    const auto provisional = p2::BeginIncrementalV1(Skeleton(
        public_fs_seed, trace_rows, trace_columns, quotient_len,
        n_coeffs, base_column_indices,
        out.r0_cache->root, out.rdep_cache->root, no_quotient_root));
    if (!provisional.valid) return fail("p2:" + provisional.note);

    out.public_fs_seed = public_fs_seed;
    out.trace_rows = trace_rows;
    out.trace_columns = trace_columns;
    out.quotient_len = quotient_len;
    out.n_coeffs = n_coeffs;
    out.base_column_indices = base_column_indices;
    out.r0 = r0;
    out.rdep = rdep;
    out.air_constraint_lambda = provisional.receipt.air_lambda;
    out.transcript_derived_before_quotient = true;
    out.valid = true;
    out.note =
        "stage3:v11_precommit:r0_rdep_bound_air_lambda_before_rq";
    return out;
}

ProveResultV1 CompleteWithQuotientV1(
    const TracePrecommitV1& precommit,
    const std::vector<Fp3>& quotient)
{
    ProveResultV1 out;
    const auto fail = [&](const std::string& detail) {
        out.note = "stage3:v11_prove:" + detail;
        return out;
    };
    if (!precommit.valid ||
        !precommit.transcript_derived_before_quotient ||
        !precommit.r0_cache || !precommit.r0_cache->valid ||
        !precommit.rdep_cache || !precommit.rdep_cache->valid ||
        quotient.size() != precommit.quotient_len) {
        return fail("precommit_or_quotient");
    }
    std::vector<std::vector<Fp3>> rq{quotient};
    auto rq_cache = std::make_shared<Fri3AlgRowTreeCache>();
    std::string why;
    if (!Fri3AlgBuildRowTreeCacheStreaming(
            rq, precommit.n_coeffs, *rq_cache, &why)) {
        return fail("rq_commit:" + why);
    }
    const auto skeleton = Skeleton(
        precommit.public_fs_seed,
        precommit.trace_rows,
        precommit.trace_columns,
        precommit.quotient_len,
        precommit.n_coeffs,
        precommit.base_column_indices,
        precommit.r0_cache->root,
        precommit.rdep_cache->root,
        rq_cache->root);
    auto transcript = p2::BeginIncrementalV1(skeleton);
    if (!transcript.valid ||
        !Fp3Equal(
            transcript.receipt.air_lambda,
            precommit.air_constraint_lambda)) {
        return fail("air_lambda_order_or_replay");
    }

    const std::array<const std::vector<std::vector<Fp3>>*, 3> groups{
        &precommit.r0, &precommit.rdep, &rq};
    const uint32_t width =
        static_cast<uint32_t>(skeleton.column_len.size());
    std::vector<Fp3> evals_z1(width);
    std::vector<Fp3> evals_z2(width);
    uint32_t flat = 0;
    for (const auto* group : groups) {
        for (const auto& column : *group) {
            evals_z1[flat] = Eval(column, transcript.receipt.z1);
            evals_z2[flat] = Eval(column, transcript.receipt.z2);
            ++flat;
        }
    }
    if (!p2::BindEvaluationsV1(transcript, evals_z1, evals_z2)) {
        return fail("evaluations:" + transcript.note);
    }
    if (transcript.receipt.batching_coefficients.size() != width) {
        return fail("coefficient_count");
    }

    std::vector<Fp3> combined(precommit.n_coeffs, Fp3::Zero());
    Fp3 v1 = Fp3::Zero();
    Fp3 v2 = Fp3::Zero();
    flat = 0;
    for (const auto* group : groups) {
        for (const auto& column : *group) {
            const uint32_t shift =
                precommit.n_coeffs - skeleton.column_len[flat];
            for (uint32_t i = 0; i < column.size(); ++i) {
                combined[shift + i] = Add(
                    combined[shift + i],
                    Mul(
                        transcript.receipt.batching_coefficients[flat],
                        column[i]));
            }
            v1 = Add(
                v1,
                Mul(
                    Mul(
                        transcript.receipt.batching_coefficients[flat],
                        PowFp3(transcript.receipt.z1, shift)),
                    evals_z1[flat]));
            v2 = Add(
                v2,
                Mul(
                    Mul(
                        transcript.receipt.batching_coefficients[flat],
                        PowFp3(transcript.receipt.z2, shift)),
                    evals_z2[flat]));
            ++flat;
        }
    }
    auto q1 = SyntheticQuotient(combined, transcript.receipt.z1, v1);
    auto q2 = SyntheticQuotient(combined, transcript.receipt.z2, v2);
    q1.resize(precommit.n_coeffs, Fp3::Zero());
    q2.resize(precommit.n_coeffs, Fp3::Zero());
    std::vector<Fp3> deep(precommit.n_coeffs);
    for (uint32_t i = 0; i < deep.size(); ++i) {
        deep[i] = Add(
            Mul(transcript.receipt.w1, q1[i]),
            Mul(transcript.receipt.w2, q2[i]));
    }

    std::vector<std::vector<Fp3>> fold_values;
    std::vector<Tree> fold_trees;
    std::vector<Fp3> current = Lde(deep, kRCFriBlowup);
    for (;;) {
        Tree tree = BuildFoldTree(current);
        if (tree.levels.empty()) return fail("fold_tree");
        const p2::FoldClaimV1 claim{
            static_cast<uint32_t>(current.size()), tree.root};
        const auto step = p2::AbsorbFoldV1(transcript, claim);
        if (!step.valid) return fail("fold_transcript:" + step.note);
        fold_values.push_back(current);
        fold_trees.push_back(std::move(tree));
        if (!step.beta_derived) {
            for (const auto& value : current) {
                if (!Fp3Equal(value, current.front())) {
                    return fail("terminal_not_constant");
                }
            }
            break;
        }
        std::vector<Fp3> next;
        if (!FoldLayer(current, step.beta, next)) {
            return fail("fold_math");
        }
        current = std::move(next);
    }
    const Fp3 final_value = current.front();
    if (!p2::FinalizeQueriesV1(transcript, final_value)) {
        return fail("queries:" + transcript.note);
    }

    auto& envelope = out.proof.envelope;
    envelope.public_fs_seed = SeedWords(precommit.public_fs_seed);
    envelope.trace_columns = precommit.trace_columns;
    envelope.quotient_len = precommit.quotient_len;
    auto& split = envelope.split;
    split.version = 1;
    split.trace_rows = precommit.trace_rows;
    split.base_column_indices = precommit.base_column_indices;
    split.air_constraint_lambda = transcript.receipt.air_lambda;
    auto& batch = split.batch;
    batch.version = kRCFri3AlgMultiRowBatchProofVersion;
    batch.pow_grind_nonce = 0;
    batch.blowup = kRCFriBlowup;
    batch.n_coeffs = precommit.n_coeffs;
    const uint32_t n_lde = precommit.n_coeffs * kRCFriBlowup;
    batch.groups = {
        {Fri3AlgMultiRowGroupRole::MainTrace, 0,
         static_cast<uint32_t>(precommit.r0.size()),
         {precommit.r0_cache->root, n_lde}},
        {Fri3AlgMultiRowGroupRole::AuxiliaryTrace,
         static_cast<uint32_t>(precommit.r0.size()),
         static_cast<uint32_t>(precommit.rdep.size()),
         {precommit.rdep_cache->root, n_lde}},
        {Fri3AlgMultiRowGroupRole::Quotient,
         precommit.trace_columns, 1, {rq_cache->root, n_lde}},
    };
    batch.column_len = skeleton.column_len;
    batch.lambda = transcript.receipt.batching_coefficients.front();
    batch.z1 = transcript.receipt.z1;
    batch.z2 = transcript.receipt.z2;
    batch.evals_z1 = std::move(evals_z1);
    batch.evals_z2 = std::move(evals_z2);
    batch.w1 = transcript.receipt.w1;
    batch.w2 = transcript.receipt.w2;
    for (uint32_t f = 0; f < fold_values.size(); ++f) {
        batch.fold_layers.push_back({
            fold_trees[f].root,
            static_cast<uint32_t>(fold_values[f].size())});
    }
    batch.final_value = final_value;
    batch.fold_challenges = transcript.receipt.fold_challenges;
    batch.queries.resize(p2::kQueriesV1);
    std::vector<uint32_t> query_indices(p2::kQueriesV1);
    for (uint32_t q = 0; q < p2::kQueriesV1; ++q) {
        query_indices[q] = transcript.receipt.queries[q].index;
        auto& query = batch.queries[q];
        query.index = query_indices[q];
        query.group_rows.resize(3);
        uint32_t index = query.index;
        for (uint32_t f = 0; f < batch.fold_challenges.size(); ++f) {
            query.steps.push_back(
                OpenFold(fold_values[f], fold_trees[f], index));
            index %= static_cast<uint32_t>(fold_values[f].size() / 2);
        }
    }
    const std::array<std::shared_ptr<Fri3AlgRowTreeCache>, 3> caches{
        precommit.r0_cache, precommit.rdep_cache, rq_cache};
    for (uint32_t g = 0; g < groups.size(); ++g) {
        std::vector<Fri3AlgRowOpening> rows;
        if (!Fri3AlgOpenRowsStreamingSharedCached(
                *groups[g], precommit.n_coeffs, query_indices,
                caches[g]->root, *caches[g], rows, &why) ||
            rows.size() != p2::kQueriesV1) {
            return fail("current_open:" + why);
        }
        for (uint32_t q = 0; q < p2::kQueriesV1; ++q) {
            batch.queries[q].group_rows[g] = std::move(rows[q]);
        }
    }

    const uint32_t transition_step = n_lde / precommit.trace_rows;
    std::vector<uint32_t> next_indices(p2::kQueriesV1);
    for (uint32_t q = 0; q < p2::kQueriesV1; ++q) {
        next_indices[q] =
            (query_indices[q] + transition_step) % n_lde;
    }
    std::array<std::vector<Fri3AlgRowOpening>, 2> next_rows;
    if (!Fri3AlgOpenRowsStreamingSharedCached(
            precommit.r0, precommit.n_coeffs, next_indices,
            precommit.r0_cache->root, *precommit.r0_cache,
            next_rows[0], &why) ||
        !Fri3AlgOpenRowsStreamingSharedCached(
            precommit.rdep, precommit.n_coeffs, next_indices,
            precommit.rdep_cache->root, *precommit.rdep_cache,
            next_rows[1], &why)) {
        return fail("next_open:" + why);
    }
    split.next_trace_group_rows.resize(
        p2::kQueriesV1, std::vector<Fri3AlgRowOpening>(2));
    for (uint32_t q = 0; q < p2::kQueriesV1; ++q) {
        split.next_trace_group_rows[q][0] = std::move(next_rows[0][q]);
        split.next_trace_group_rows[q][1] = std::move(next_rows[1][q]);
    }

    std::vector<unsigned char> wire;
    out.proof_bytes = SerializeV1(out.proof, wire);
    if (out.proof_bytes == 0 || out.proof_bytes != wire.size()) {
        return fail("codec");
    }
    std::string verify_why;
    out.self_verified = VerifyV1(out.proof, nullptr, &verify_why);
    if (!out.self_verified) return fail("self_verify:" + verify_why);
    out.transcript = transcript.receipt;
    out.group_caches = {
        precommit.r0_cache, precommit.rdep_cache, rq_cache};
    out.q192_with_replacement =
        transcript.receipt.q192_with_replacement;
    out.ok = true;
    out.note =
        "stage3:v11_prove:two_phase_p2_q192_complete";
    return out;
}

AirProveResultV1 ProveAirQuotientV1(
    const air_quotient::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns,
    const std::vector<uint32_t>& base_column_indices,
    const uint256& public_fs_seed)
{
    AirProveResultV1 out;
    const auto fail = [&](const std::string& detail) {
        out.note = "stage3:v11_air_prove:" + detail;
        return out;
    };
    const uint32_t rows = cs.n_rows;
    const uint32_t width = cs.n_columns;
    if (public_fs_seed.IsNull() ||
        !PowerOfTwo(rows) ||
        width < 2 ||
        columns.size() != width ||
        cs.constraints.empty() ||
        !cs.preprocessed.empty() ||
        !cs.preprocessed_roots.empty() ||
        !cs.preprocessed_row_group_roots.empty() ||
        base_column_indices.empty() ||
        base_column_indices.size() >= width) {
        return fail("shape_or_unsupported_preprocessing");
    }
    for (const auto& column : columns) {
        if (column.size() != rows) return fail("column_rows");
    }
    std::vector<uint8_t> is_base(width, 0);
    uint32_t previous = 0;
    for (uint32_t i = 0; i < base_column_indices.size(); ++i) {
        const uint32_t column = base_column_indices[i];
        if (column >= width || (i != 0 && column <= previous)) {
            return fail("base_indices");
        }
        previous = column;
        is_base[column] = 1;
    }
    const uint32_t quotient_len = cs.QuotientLen();
    const uint32_t n_coeffs =
        NextPowerOfTwo(std::max(rows, quotient_len));
    if (quotient_len == 0 ||
        uint64_t{n_coeffs} * kRCFriBlowup < p2::kMinLdeRowsV1) {
        return fail("domain");
    }

    std::vector<std::vector<Fp3>> shifted(width);
    for (uint32_t column = 0; column < width; ++column) {
        shifted[column] = Interpolate(columns[column]);
        CosetShift(shifted[column]);
    }
    std::vector<std::vector<Fp3>> r0;
    std::vector<std::vector<Fp3>> rdep;
    r0.reserve(base_column_indices.size());
    rdep.reserve(width - base_column_indices.size());
    for (uint32_t column : base_column_indices) {
        r0.push_back(shifted[column]);
    }
    for (uint32_t column = 0; column < width; ++column) {
        if (!is_base[column]) rdep.push_back(shifted[column]);
    }
    auto precommit = PrecommitTraceV1(
        r0, rdep, rows, width, quotient_len,
        n_coeffs, base_column_indices, public_fs_seed);
    if (!precommit.valid) return fail(precommit.note);

    const uint64_t max_degree = cs.MaxComposedDegreeBound();
    if (max_degree + 1 > (uint64_t{1} << 24)) {
        return fail("composed_degree");
    }
    const uint32_t composition_rows = std::max(
        rows,
        NextPowerOfTwo(static_cast<uint32_t>(max_degree + 1)));
    const uint32_t transition_step = composition_rows / rows;
    std::vector<std::vector<Fp3>> extended(width);
    for (uint32_t column = 0; column < width; ++column) {
        extended[column] =
            EvalOnSubgroup(Interpolate(columns[column]), composition_rows);
    }
    const Fp omega_composition = OmegaForSize(composition_rows);
    const Fp omega_rows = OmegaForSize(rows);
    const Fp3 first = Fp3::One();
    const Fp3 last =
        Fp3::FromFp(PowFp(omega_rows, rows - 1));
    std::vector<Fp3> composition(composition_rows, Fp3::Zero());
    std::vector<Fp3> current(width);
    std::vector<Fp3> next(width);
    Fp y_base = 1;
    for (uint32_t row = 0; row < composition_rows; ++row) {
        const Fp3 y = Fp3::FromFp(y_base);
        y_base = Mul(y_base, omega_composition);
        const uint32_t next_row =
            (row + transition_step) % composition_rows;
        for (uint32_t column = 0; column < width; ++column) {
            current[column] = extended[column][row];
            next[column] = extended[column][next_row];
        }
        Fp3 sum = Fp3::Zero();
        Fp3 power = Fp3::One();
        for (const auto& constraint : cs.constraints) {
            const Fp3 value = constraint.eval(current, next);
            sum = Add(
                sum,
                Mul(
                    power,
                    Mul(
                        Selector(
                            constraint.kind, rows, y, first, last),
                        value)));
            power = Mul(power, precommit.air_constraint_lambda);
        }
        composition[row] = sum;
    }

    std::vector<Fp3> remainder = Interpolate(std::move(composition));
    std::vector<Fp3> quotient(
        composition_rows > rows ? composition_rows - rows : 1,
        Fp3::Zero());
    for (uint32_t degree = composition_rows; degree-- > rows;) {
        if (gf::IsZero(remainder[degree])) continue;
        quotient[degree - rows] =
            Add(quotient[degree - rows], remainder[degree]);
        remainder[degree - rows] =
            Add(remainder[degree - rows], remainder[degree]);
        remainder[degree] = Fp3::Zero();
    }
    remainder.resize(rows);
    out.remainder = remainder;
    out.division_exact = std::all_of(
        remainder.begin(), remainder.end(),
        [](const Fp3& value) { return gf::IsZero(value); });
    if (!out.division_exact) return fail("nonzero_remainder");
    for (size_t degree = quotient_len; degree < quotient.size(); ++degree) {
        if (!gf::IsZero(quotient[degree])) return fail("quotient_degree");
    }
    std::vector<Fp3> committed_quotient(quotient_len, Fp3::Zero());
    for (uint32_t degree = 0;
         degree < quotient_len && degree < quotient.size();
         ++degree) {
        committed_quotient[degree] = quotient[degree];
    }
    CosetShift(committed_quotient);
    out.quotient_built_after_v11_lambda = true;
    out.proximity =
        CompleteWithQuotientV1(precommit, committed_quotient);
    if (!out.proximity.ok) return fail(out.proximity.note);
    std::string verify_why;
    if (!VerifyAirQuotientV1(
            cs, out.proximity.proof, base_column_indices,
            public_fs_seed, &verify_why)) {
        return fail("self_verify:" + verify_why);
    }
    out.ok = true;
    out.note =
        "stage3:v11_air_prove:complete_c_over_zh_after_p2_lambda";
    return out;
}

bool VerifyV1(
    const ProofV1& proof,
    p2::ReceiptV1* transcript_out,
    std::string* why)
{
    const auto fail = [&](const std::string& detail) {
        if (why) *why = "stage3:v11_verify:" + detail;
        return false;
    };
    std::vector<uint32_t> abi_words;
    std::string abi_why;
    if (!abi::EncodeCanonicalV1(
            proof.envelope, abi_words, nullptr, &abi_why) ||
        !abi::DecodeCanonicalV1(abi_words, &abi_why).has_value()) {
        return fail("abi:" + abi_why);
    }
    const auto statement = Statement(proof);
    const auto transcript = p2::DeriveV1(statement);
    if (!TranscriptMatches(proof, transcript, why)) return false;
    const auto& split = proof.envelope.split;
    const auto& batch = split.batch;
    const uint32_t n_lde = batch.n_coeffs * batch.blowup;
    if (split.next_trace_group_rows.size() != batch.queries.size()) {
        return fail("next_count");
    }
    std::vector<Fp3> coefficients = transcript.batching_coefficients;
    Fp3 v1 = Fp3::Zero();
    Fp3 v2 = Fp3::Zero();
    for (uint32_t c = 0; c < batch.column_len.size(); ++c) {
        const uint32_t shift = batch.n_coeffs - batch.column_len[c];
        v1 = Add(
            v1,
            Mul(
                Mul(coefficients[c], PowFp3(batch.z1, shift)),
                batch.evals_z1[c]));
        v2 = Add(
            v2,
            Mul(
                Mul(coefficients[c], PowFp3(batch.z2, shift)),
                batch.evals_z2[c]));
    }
    const Tree terminal =
        BuildFoldTree(std::vector<Fp3>(batch.blowup, batch.final_value));
    if (!DigestEqual(terminal.root, batch.fold_layers.back().root)) {
        return fail("terminal_root");
    }
    const uint32_t transition_step = n_lde / split.trace_rows;
    for (uint32_t q = 0; q < batch.queries.size(); ++q) {
        const auto& query = batch.queries[q];
        if (query.group_rows.size() != batch.groups.size() ||
            query.steps.size() != batch.fold_challenges.size()) {
            return fail("query_shape");
        }
        std::vector<Fp3> row;
        row.reserve(batch.column_len.size());
        for (uint32_t g = 0; g < batch.groups.size(); ++g) {
            const auto& opened = query.group_rows[g];
            if (opened.values.size() != batch.groups[g].column_count ||
                !Fri3AlgVerifyPath(
                    alg_hash::LeafHashRow(opened.values, query.index),
                    query.index, opened.siblings,
                    batch.groups[g].row_commit.root, n_lde)) {
                return fail("current_merkle");
            }
            row.insert(row.end(), opened.values.begin(), opened.values.end());
        }
        if (row.size() != batch.column_len.size()) {
            return fail("current_width");
        }
        const Fp3 x = DomainPoint(n_lde, query.index);
        Fp3 ux = Fp3::Zero();
        for (uint32_t c = 0; c < row.size(); ++c) {
            const uint32_t shift = batch.n_coeffs - batch.column_len[c];
            ux = Add(
                ux,
                Mul(
                    Mul(coefficients[c], PowFp3(x, shift)),
                    row[c]));
        }
        if (Fp3Equal(x, batch.z1) || Fp3Equal(x, batch.z2)) {
            return fail("deep_denominator");
        }
        const Fp3 expected_deep = Add(
            Mul(
                batch.w1,
                Mul(Sub(ux, v1), Inv(Sub(x, batch.z1)))),
            Mul(
                batch.w2,
                Mul(Sub(ux, v2), Inv(Sub(x, batch.z2)))));
        uint32_t index = query.index;
        Fp3 claimed = Fp3::Zero();
        bool have_claimed = false;
        for (uint32_t f = 0; f < batch.fold_challenges.size(); ++f) {
            Fp3 next;
            if (!VerifyFold(
                    query.steps[f], batch.fold_layers[f],
                    batch.fold_challenges[f], index, next)) {
                return fail("fold_path");
            }
            const uint32_t half = batch.fold_layers[f].n_leaves / 2;
            const Fp3 here = index < half
                ? query.steps[f].even
                : query.steps[f].odd;
            if ((f == 0 && !Fp3Equal(here, expected_deep)) ||
                (f != 0 && (!have_claimed || !Fp3Equal(here, claimed)))) {
                return fail("deep_or_fold_link");
            }
            claimed = next;
            have_claimed = true;
            index %= half;
        }
        if (!have_claimed || !Fp3Equal(claimed, batch.final_value)) {
            return fail("final_value");
        }

        const auto& next = split.next_trace_group_rows[q];
        if (next.size() != 2) return fail("next_shape");
        const uint32_t next_index =
            (query.index + transition_step) % n_lde;
        for (uint32_t g = 0; g < 2; ++g) {
            if (next[g].values.size() != batch.groups[g].column_count ||
                !Fri3AlgVerifyPath(
                    alg_hash::LeafHashRow(next[g].values, next_index),
                    next_index, next[g].siblings,
                    batch.groups[g].row_commit.root, n_lde)) {
                return fail("next_merkle");
            }
        }
    }
    if (transcript_out) *transcript_out = transcript;
    if (why) {
        *why =
            "stage3:v11_verify:p2_q192_deep_fri_current_next";
    }
    return true;
}

bool VerifyAirQuotientV1(
    const air_quotient::AirConstraintSystem<Fp3>& cs,
    const ProofV1& proof,
    const std::vector<uint32_t>& expected_base_column_indices,
    const uint256& expected_public_fs_seed,
    std::string* why)
{
    const auto fail = [&](const std::string& detail) {
        if (why) *why = "stage3:v11_air_verify:" + detail;
        return false;
    };
    const auto& envelope = proof.envelope;
    const auto& split = envelope.split;
    const auto& batch = split.batch;
    const uint32_t rows = cs.n_rows;
    const uint32_t width = cs.n_columns;
    if (expected_public_fs_seed.IsNull() ||
        SeedFromWords(envelope.public_fs_seed) != expected_public_fs_seed ||
        !PowerOfTwo(rows) ||
        width < 2 ||
        cs.constraints.empty() ||
        !cs.preprocessed.empty() ||
        !cs.preprocessed_roots.empty() ||
        !cs.preprocessed_row_group_roots.empty() ||
        split.trace_rows != rows ||
        envelope.trace_columns != width ||
        envelope.quotient_len != cs.QuotientLen() ||
        split.base_column_indices != expected_base_column_indices ||
        batch.groups.size() != 3 ||
        batch.column_len.size() != width + 1 ||
        batch.groups[0].column_count != expected_base_column_indices.size() ||
        batch.groups[1].column_count !=
            width - expected_base_column_indices.size() ||
        batch.groups[2].column_count != 1) {
        return fail("statement_shape");
    }
    if (!VerifyV1(proof, nullptr, why)) return false;
    std::vector<uint8_t> is_base(width, 0);
    for (uint32_t column : expected_base_column_indices) {
        if (column >= width || is_base[column]) return fail("base_indices");
        is_base[column] = 1;
    }
    std::vector<uint32_t> dependent;
    for (uint32_t column = 0; column < width; ++column) {
        if (!is_base[column]) dependent.push_back(column);
    }
    const uint32_t n_lde = batch.n_coeffs * batch.blowup;
    const uint32_t transition_step = n_lde / rows;
    const Fp omega_lde = OmegaForSize(n_lde);
    const Fp omega_rows = OmegaForSize(rows);
    const Fp3 first = Fp3::One();
    const Fp3 last = Fp3::FromFp(PowFp(omega_rows, rows - 1));
    const Fp3 coset = Fp3::FromFp(air_quotient::kAirCosetShift);
    std::vector<Fp3> current(width);
    std::vector<Fp3> next(width);
    for (uint32_t q = 0; q < batch.queries.size(); ++q) {
        const auto& opened = batch.queries[q];
        const auto& next_groups = split.next_trace_group_rows[q];
        for (uint32_t i = 0; i < expected_base_column_indices.size(); ++i) {
            current[expected_base_column_indices[i]] =
                opened.group_rows[0].values[i];
            next[expected_base_column_indices[i]] =
                next_groups[0].values[i];
        }
        for (uint32_t i = 0; i < dependent.size(); ++i) {
            current[dependent[i]] = opened.group_rows[1].values[i];
            next[dependent[i]] = next_groups[1].values[i];
        }
        const Fp3 y = Mul(
            coset,
            Fp3::FromFp(PowFp(omega_lde, opened.index)));
        const Fp3 zh = Sub(PowFp3(y, rows), Fp3::One());
        if (gf::IsZero(zh)) return fail("zh_zero");
        Fp3 sum = Fp3::Zero();
        Fp3 power = Fp3::One();
        for (const auto& constraint : cs.constraints) {
            const Fp3 value = constraint.eval(current, next);
            sum = Add(
                sum,
                Mul(
                    power,
                    Mul(
                        Selector(
                            constraint.kind, rows, y, first, last),
                        value)));
            power = Mul(power, split.air_constraint_lambda);
        }
        if (!Fp3Equal(
                sum,
                Mul(opened.group_rows[2].values[0], zh))) {
            return fail("quotient_identity");
        }
        const uint32_t expected_next =
            (opened.index + transition_step) % n_lde;
        (void)expected_next; // VerifyV1 already authenticates this exact index.
    }
    if (why) {
        *why =
            "stage3:v11_air_verify:q192_complete_current_next_identity";
    }
    return true;
}

size_t SerializeV1(
    const ProofV1& proof,
    std::vector<unsigned char>& out)
{
    out.clear();
    std::vector<uint32_t> abi_words;
    if (!abi::EncodeCanonicalV1(proof.envelope, abi_words)) return 0;
    std::vector<unsigned char> nested;
    if (air_quotient::SerializeAirQuotientSplitRapRowsProof(
            proof.envelope.split, nested) == 0 ||
        nested.size() >
            std::numeric_limits<uint32_t>::max()) {
        return 0;
    }
    out.reserve(60 + nested.size());
    Append32(out, kWireMagicV1);
    Append32(out, kWireFormatVersionV1);
    Append32(out, kProtocolVersionV11);
    Append64(out, kProtocolDomainV11);
    for (uint32_t word : proof.envelope.public_fs_seed) {
        Append32(out, word);
    }
    Append32(out, proof.envelope.trace_columns);
    Append32(out, proof.envelope.quotient_len);
    Append32(out, static_cast<uint32_t>(nested.size()));
    out.insert(out.end(), nested.begin(), nested.end());
    if (out.size() > kMaxProofBytesV1) {
        out.clear();
        return 0;
    }
    return out.size();
}

std::optional<ProofV1> DeserializeV1(
    const std::vector<unsigned char>& in,
    std::string* why)
{
    const auto fail = [&](const char* detail) -> std::optional<ProofV1> {
        if (why) *why = std::string{"stage3:v11_decode:"} + detail;
        return std::nullopt;
    };
    if (in.size() > kMaxProofBytesV1 || in.size() < 64) {
        return fail("size");
    }
    const unsigned char* cursor = in.data();
    const unsigned char* end = cursor + in.size();
    uint32_t magic = 0;
    uint32_t wire_version = 0;
    uint32_t protocol_version = 0;
    uint64_t domain = 0;
    if (!Read32(cursor, end, magic) ||
        !Read32(cursor, end, wire_version) ||
        !Read32(cursor, end, protocol_version) ||
        !Read64(cursor, end, domain) ||
        magic != kWireMagicV1 ||
        wire_version != kWireFormatVersionV1 ||
        protocol_version != kProtocolVersionV11 ||
        domain != kProtocolDomainV11) {
        return fail("header");
    }
    ProofV1 out;
    for (uint32_t& word : out.envelope.public_fs_seed) {
        if (!Read32(cursor, end, word)) return fail("seed");
    }
    uint32_t nested_size = 0;
    if (!Read32(cursor, end, out.envelope.trace_columns) ||
        !Read32(cursor, end, out.envelope.quotient_len) ||
        !Read32(cursor, end, nested_size) ||
        size_t(end - cursor) != nested_size) {
        return fail("payload_size_or_trailing");
    }
    std::vector<unsigned char> nested(cursor, end);
    auto split =
        air_quotient::DeserializeAirQuotientSplitRapRowsProof(nested);
    if (!split.has_value()) return fail("nested");
    out.envelope.split = std::move(*split);
    std::vector<uint32_t> abi_words;
    std::string abi_why;
    if (!abi::EncodeCanonicalV1(
            out.envelope, abi_words, nullptr, &abi_why) ||
        !abi::DecodeCanonicalV1(abi_words, &abi_why).has_value()) {
        return fail("abi");
    }
    std::vector<unsigned char> canonical;
    if (SerializeV1(out, canonical) != in.size() || canonical != in) {
        return fail("noncanonical");
    }
    if (why) *why = "stage3:v11_decode:canonical";
    return out;
}

} // namespace matmul::v4::rc::stage3_multirow_v11_backend
