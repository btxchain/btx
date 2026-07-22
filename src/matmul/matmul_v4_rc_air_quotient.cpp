// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_air_quotient.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <span.h>

#include <algorithm>
#include <cassert>
#include <cstring>

// AIR constraint-quotient construction — implementation. See the header for
// the construction map and the per-rule honesty statement (what arithmetizes
// cleanly and what — the tile-tree SHA rule — does not).

namespace matmul::v4::rc::air_quotient {

using gkr_field::Fp;

namespace {

// ---------------------------------------------------------------------------
// Base-field subgroup roots (mirrors the constants in matmul_v4_rc_fri.cpp;
// kept in sync by the round-trip tests — the LDE/Merkle roots computed here
// must agree byte-for-byte with FriBatchColumnRoot).
// ---------------------------------------------------------------------------
constexpr Fp kAirOmega2_32 = 0x185629dcda58878cULL;

Fp AirPowBase(Fp base, uint64_t exp)
{
    Fp result = 1;
    base = gkr_field::Canonical(base);
    while (exp > 0) {
        if (exp & 1u) result = gkr_field::Mul(result, base);
        base = gkr_field::Mul(base, base);
        exp >>= 1;
    }
    return result;
}

/** Primitive n-th root of unity for n = 2^k, k ≤ 32. */
Fp AirOmegaForSize(uint32_t n)
{
    uint32_t logn = 0;
    uint32_t t = n;
    while (t > 1) {
        t >>= 1;
        ++logn;
    }
    return AirPowBase(kAirOmega2_32, 1ULL << (32 - logn));
}

template <typename F>
F AirPow(F base, uint64_t exp)
{
    using T = AirField<F>;
    F result = T::One();
    while (exp > 0) {
        if (exp & 1u) result = T::Mul(result, base);
        base = T::Mul(base, base);
        exp >>= 1;
    }
    return result;
}

template <typename F>
void AirBitReverse(std::vector<F>& a)
{
    const size_t n = a.size();
    size_t j = 0;
    for (size_t i = 1; i < n; ++i) {
        size_t bit = n >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) std::swap(a[i], a[j]);
    }
}

/** Radix-2 NTT over F using base-field roots (mirror of the FRI NTT so the
 *  coefficient/evaluation conventions — natural-order evals at ω^i — agree). */
template <typename F>
void AirNtt(std::vector<F>& a, bool inverse)
{
    using T = AirField<F>;
    const size_t n = a.size();
    if (n <= 1) return;
    AirBitReverse(a);
    Fp omega_n = AirOmegaForSize(static_cast<uint32_t>(n));
    if (inverse) omega_n = gkr_field::Inv(omega_n);
    for (size_t len = 2; len <= n; len <<= 1) {
        const Fp w_len = AirPowBase(omega_n, n / len);
        for (size_t i = 0; i < n; i += len) {
            Fp w = 1;
            for (size_t j = 0; j < len / 2; ++j) {
                const F u = a[i + j];
                const F v = T::Mul(a[i + j + len / 2], T::FromBase(w));
                a[i + j] = T::Add(u, v);
                a[i + j + len / 2] = T::Sub(u, v);
                w = gkr_field::Mul(w, w_len);
            }
        }
    }
    if (inverse) {
        const F inv_n = T::FromBase(gkr_field::Inv(static_cast<Fp>(n)));
        for (auto& x : a) x = T::Mul(x, inv_n);
    }
}

/** values over H (natural order, size N pow2) -> coefficients (deg < N). */
template <typename F>
std::vector<F> AirInterpolate(std::vector<F> values)
{
    AirNtt(values, /*inverse=*/true);
    return values;
}

/** coefficients (≤ M entries) -> evaluations on the size-M subgroup. */
template <typename F>
std::vector<F> AirEvalOnSubgroup(const std::vector<F>& coeffs, uint32_t M)
{
    using T = AirField<F>;
    std::vector<F> padded(M, T::Zero());
    for (size_t i = 0; i < coeffs.size() && i < padded.size(); ++i) padded[i] = coeffs[i];
    AirNtt(padded, /*inverse=*/false);
    return padded;
}

/** Coset shift: c_j := c_j · g^j so evaluations happen at y = g·x. */
template <typename F>
void AirCosetShiftCoeffs(std::vector<F>& coeffs)
{
    using T = AirField<F>;
    Fp gp = 1;
    for (auto& c : coeffs) {
        c = T::Mul(c, T::FromBase(gp));
        gp = gkr_field::Mul(gp, kAirCosetShift);
    }
}

/**
 * Selector polynomial evaluation at y:
 *   kEverywhere: 1
 *   kTransition: y − h_last
 *   kFirstRow:   Z_H(y)/(y − 1)       (a polynomial; at y = h ∈ H the closed
 *   kLastRow:    Z_H(y)/(y − h_last)   form is the derivative N·h^{N−1})
 */
template <typename F>
F AirSelectorEval(AirKind kind, uint32_t N, const F& y, const F& h_first, const F& h_last)
{
    using T = AirField<F>;
    auto zh_over = [&](const F& h) -> F {
        const F den = T::Sub(y, h);
        if (!T::IsZero(den)) {
            const F num = T::Sub(AirPow(y, N), T::One());
            return T::Mul(num, T::Inv(den));
        }
        return T::Mul(T::FromU64(N), AirPow(h, N - 1));
    };
    switch (kind) {
    case AirKind::kEverywhere: return T::One();
    case AirKind::kTransition: return T::Sub(y, h_last);
    case AirKind::kFirstRow: return zh_over(h_first);
    case AirKind::kLastRow: return zh_over(h_last);
    }
    return T::Zero();
}

// ---------------------------------------------------------------------------
// Merkle tree over an LDE evaluation vector, byte-identical to the FRI
// backend's per-column trees (leaf/node hashes come from the backend).
// n_leaves is always a power of two here, so no odd-padding arises.
// ---------------------------------------------------------------------------
struct AirTree {
    std::vector<std::vector<uint256>> levels;
    uint256 root{};
};

template <typename F>
AirTree AirBuildTree(const std::vector<F>& evals)
{
    using B = AirFriBackend<F>;
    AirTree t;
    std::vector<uint256> level(evals.size());
    for (size_t i = 0; i < evals.size(); ++i) {
        level[i] = B::LeafHash(evals[i], static_cast<uint32_t>(i));
    }
    t.levels.push_back(level);
    while (level.size() > 1) {
        std::vector<uint256> next;
        next.reserve(level.size() / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            next.push_back(B::NodeHash(level[i], level[i + 1]));
        }
        t.levels.push_back(next);
        level = std::move(next);
    }
    t.root = t.levels.back()[0];
    return t;
}

std::vector<uint256> AirTreePath(const AirTree& tree, uint32_t index)
{
    std::vector<uint256> siblings;
    uint32_t idx = index;
    for (size_t li = 0; li + 1 < tree.levels.size(); ++li) {
        siblings.push_back(tree.levels[li][idx ^ 1u]);
        idx >>= 1;
    }
    return siblings;
}

void AppendLE32v(std::vector<unsigned char>& buf, uint32_t v)
{
    unsigned char b[4];
    WriteLE32(b, v);
    buf.insert(buf.end(), b, b + 4);
}

uint256 Sha256dOf(const std::vector<unsigned char>& buf)
{
    unsigned char d1[32], d2[32];
    CSHA256().Write(buf.data(), buf.size()).Finalize(d1);
    CSHA256().Write(d1, 32).Finalize(d2);
    return uint256{Span<const unsigned char>{d2, 32}};
}

template <typename F>
F DeriveChallenge(const uint256& fs_seed, const char* label, const std::vector<uint256>& roots,
                  const std::vector<uint32_t>& extra)
{
    const uint256 d = AirChallengeDigest(fs_seed, label, roots, extra);
    return AirField<F>::FromChallenge(d.data());
}

} // namespace

uint256 AirChallengeDigest(const uint256& fs_seed, const char* label,
                           const std::vector<uint256>& roots, const std::vector<uint32_t>& extra)
{
    static constexpr char kTag[] = "BTX_RC_AIRQ_V1";
    std::vector<unsigned char> buf;
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(kTag),
               reinterpret_cast<const unsigned char*>(kTag) + sizeof(kTag) - 1);
    buf.insert(buf.end(), fs_seed.data(), fs_seed.data() + 32);
    const size_t label_len = std::strlen(label);
    AppendLE32v(buf, static_cast<uint32_t>(label_len));
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(label),
               reinterpret_cast<const unsigned char*>(label) + label_len);
    AppendLE32v(buf, static_cast<uint32_t>(roots.size()));
    for (const uint256& r : roots) buf.insert(buf.end(), r.data(), r.data() + 32);
    AppendLE32v(buf, static_cast<uint32_t>(extra.size()));
    for (const uint32_t e : extra) AppendLE32v(buf, e);
    return Sha256dOf(buf);
}

template <typename F>
F AirAcceptPoly(const F& b0, const F& b1, const F& b2, const F& b3)
{
    using T = AirField<F>;
    const F one = T::One();
    // rejected(n) = (1−b2)·((1−b3)·b0 + b3·(1 − b1 + b1·b0)); 1 exactly on the
    // rejected E2M1 codes {1,3,8,9,11}. accept = 1 − rejected (degree 4).
    const F inner = T::Add(T::Mul(T::Sub(one, b3), b0),
                           T::Mul(b3, T::Add(T::Sub(one, b1), T::Mul(b1, b0))));
    const F rejected = T::Mul(T::Sub(one, b2), inner);
    return T::Sub(one, rejected);
}

template <typename F>
uint256 AirCommittedValuesRoot(const std::vector<F>& values, uint32_t n_coeffs)
{
    std::vector<F> cf = AirInterpolate(values);
    AirCosetShiftCoeffs(cf);
    return AirFriBackend<F>::ColumnRoot(cf, n_coeffs);
}

namespace {

/** Barycentric weights over H for an off-subgroup point x: w_j = ω^j/(x − ω^j)
 *  plus the common factor (x^N − 1)/N, so P(x) = zh_over_n · Σ v_j·w_j for any
 *  values vector v over H. Shared across every preprocessed column of a shard
 *  (the weights depend only on x). Returns false iff x ∈ H (never for a coset
 *  point g·z with nonzero extension part; guarded anyway). */
template <typename F>
bool AirBarycentricWeightsOnH(uint32_t N, const F& x, std::vector<F>& weights, F& zh_over_n)
{
    using T = AirField<F>;
    const Fp omega = AirOmegaForSize(N);
    std::vector<F> dens(N);
    Fp wj = 1;
    for (uint32_t j = 0; j < N; ++j) {
        dens[j] = T::Sub(x, T::FromBase(wj));
        if (T::IsZero(dens[j])) return false;
        wj = gkr_field::Mul(wj, omega);
    }
    // Batch inversion (Montgomery trick).
    std::vector<F> prefix(N);
    F run = T::One();
    for (uint32_t j = 0; j < N; ++j) {
        prefix[j] = run;
        run = T::Mul(run, dens[j]);
    }
    F inv_run = T::Inv(run);
    weights.assign(N, T::Zero());
    for (uint32_t j = N; j-- > 0;) {
        const F inv_dj = T::Mul(inv_run, prefix[j]);
        inv_run = T::Mul(inv_run, dens[j]);
        weights[j] = inv_dj;
    }
    wj = 1;
    for (uint32_t j = 0; j < N; ++j) {
        weights[j] = T::Mul(weights[j], T::FromBase(wj));
        wj = gkr_field::Mul(wj, omega);
    }
    const F zh = T::Sub(AirPow(x, N), T::One());
    zh_over_n = T::Mul(zh, T::Inv(T::FromU64(N)));
    return true;
}

} // namespace

// ===========================================================================
// Prover.
// ===========================================================================

template <typename F>
AirQuotientProveResult<F> AirQuotientProve(const AirConstraintSystem<F>& cs,
                                           const std::vector<std::vector<F>>& columns,
                                           const uint256& fs_seed, const AirProveOptions& opt)
{
    using T = AirField<F>;
    using B = AirFriBackend<F>;
    AirQuotientProveResult<F> res;

    const uint32_t N = cs.n_rows;
    if (N < 2 || (N & (N - 1)) != 0) {
        res.note = "n_rows not a power of two";
        return res;
    }
    if (columns.size() != cs.n_columns || cs.n_columns == 0) {
        res.note = "column count mismatch";
        return res;
    }
    for (const auto& c : columns) {
        if (c.size() != N) {
            res.note = "column length mismatch";
            return res;
        }
    }
    const uint64_t dmax = cs.MaxComposedDegreeBound();
    if (dmax + 1 > (1u << 24)) {
        res.note = "composed degree too large";
        return res;
    }
    const uint32_t Lq = cs.QuotientLen();
    const uint32_t Lq_commit = opt.quotient_len_override ? opt.quotient_len_override : Lq;
    const uint32_t n_coeffs = FriNextPow2(std::max(N, Lq_commit));
    const uint32_t W = cs.n_columns;

    // 1. Interpolate the trace columns over H.
    std::vector<std::vector<F>> coeffs(W);
    std::vector<std::vector<F>> shifted(W);
    std::vector<uint256> trace_roots(W);
    for (uint32_t c = 0; c < W; ++c) {
        coeffs[c] = AirInterpolate(columns[c]);
        shifted[c] = coeffs[c];
        AirCosetShiftCoeffs(shifted[c]);
        trace_roots[c] = B::ColumnRoot(shifted[c], n_coeffs);
    }

    // 2. FS λ AFTER the trace commitment roots (commit-then-challenge).
    const F lambda =
        DeriveChallenge<F>(fs_seed, "airq_lambda", trace_roots, {N, Lq_commit, W});

    // 3. Build C(X) = Σ_i λ^i · sel_i(X) · R_i(P(X), P(ω_H X)) by evaluation
    //    on the extended subgroup of size M ≥ deg C + 1, then interpolation.
    const uint32_t M = std::max(N, FriNextPow2(static_cast<uint32_t>(dmax + 1)));
    const uint32_t stepM = M / N;
    std::vector<std::vector<F>> ldeM(W);
    for (uint32_t c = 0; c < W; ++c) ldeM[c] = AirEvalOnSubgroup(coeffs[c], M);

    const Fp omega_M = AirOmegaForSize(M);
    const Fp omega_N = AirOmegaForSize(N);
    const F h_first = T::One();
    const F h_last = T::FromBase(AirPowBase(omega_N, N - 1));

    std::vector<F> cvals(M, T::Zero());
    std::vector<F> cur(W), nxt(W);
    Fp ypow = 1;
    for (uint32_t j = 0; j < M; ++j) {
        const F y = T::FromBase(ypow);
        ypow = gkr_field::Mul(ypow, omega_M);
        const uint32_t jn = (j + stepM) % M;
        for (uint32_t c = 0; c < W; ++c) {
            cur[c] = ldeM[c][j];
            nxt[c] = ldeM[c][jn];
        }
        F acc = T::Zero();
        F lp = T::One();
        for (const auto& con : cs.constraints) {
            const F v = con.eval(cur, nxt);
            if (!T::IsZero(v)) {
                const F sel = AirSelectorEval<F>(con.kind, N, y, h_first, h_last);
                acc = T::Add(acc, T::Mul(lp, T::Mul(sel, v)));
            }
            lp = T::Mul(lp, lambda);
        }
        cvals[j] = acc;
    }
    std::vector<F> ccoeffs = AirInterpolate(std::move(cvals));

    // 4. Divide by Z_H(X) = X^N − 1 (synthetic; exact iff C vanishes on H).
    std::vector<F> rem = std::move(ccoeffs);
    std::vector<F> qc(M > N ? M - N : 1, T::Zero());
    for (uint32_t k = M; k-- > N;) {
        if (T::IsZero(rem[k])) continue;
        qc[k - N] = T::Add(qc[k - N], rem[k]);
        rem[k - N] = T::Add(rem[k - N], rem[k]);
        rem[k] = T::Zero();
    }
    rem.resize(N);
    res.remainder = rem;
    res.division_exact = true;
    for (const F& r : rem) {
        if (!T::IsZero(r)) {
            res.division_exact = false;
            break;
        }
    }
    if (!res.division_exact && !opt.force_commit_on_inexact) {
        res.note = "nonzero remainder: trace violates a constraint on H";
        return res;
    }
    // Declared-degree sanity: coefficients past the declared bound must be 0.
    for (size_t k = Lq; k < qc.size(); ++k) {
        if (!T::IsZero(qc[k])) {
            if (!opt.force_commit_on_inexact) {
                res.note = "quotient exceeds declared degree bound";
                return res;
            }
            qc[k] = T::Zero();
        }
    }
    std::vector<F> q_commit(Lq_commit, T::Zero());
    for (uint32_t k = 0; k < Lq_commit && k < qc.size(); ++k) q_commit[k] = qc[k];
    AirCosetShiftCoeffs(q_commit);

    // 5. ONE batched FRI instance over trace columns + quotient.
    std::vector<std::vector<F>> all_cols = shifted;
    all_cols.push_back(std::move(q_commit));
    typename B::BatchCommitResult cr = B::BatchCommit(all_cols, fs_seed);
    if (!cr.ok) {
        res.note = "batch commit failed: " + cr.note;
        return res;
    }
    for (uint32_t c = 0; c < W; ++c) {
        if (cr.proof.columns[c].root != trace_roots[c]) {
            res.note = "internal: trace root mismatch vs FriBatchColumnRoot";
            return res;
        }
    }

    // 6. Supplemental next-row openings at (query index + n_lde/N) mod n_lde.
    const uint32_t n_lde = cr.proof.n_coeffs * kRCFriBlowup;
    const uint32_t step = n_lde / N;
    std::vector<AirTree> trees(W);
    for (uint32_t c = 0; c < W; ++c) {
        trees[c] = AirBuildTree<F>(cr.column_lde[c]);
        if (trees[c].root != cr.proof.columns[c].root) {
            res.note = "internal: rebuilt tree root mismatch";
            return res;
        }
    }
    res.proof.next_openings.resize(cr.proof.queries.size());
    for (size_t qi = 0; qi < cr.proof.queries.size(); ++qi) {
        const uint32_t idx = (cr.proof.queries[qi].index + step) % n_lde;
        auto& row = res.proof.next_openings[qi];
        row.resize(W);
        for (uint32_t c = 0; c < W; ++c) {
            row[c].index = idx;
            row[c].leaf = cr.column_lde[c][idx];
            row[c].siblings = AirTreePath(trees[c], idx);
        }
    }
    res.proof.batch = std::move(cr.proof);
    res.ok = true;
    res.note = res.division_exact ? "exact division; committed"
                                  : "FORCED commit with nonzero remainder";
    return res;
}

// ===========================================================================
// Verifier.
// ===========================================================================

template <typename F>
bool AirQuotientVerify(const AirConstraintSystem<F>& cs, const AirQuotientProof<F>& proof,
                       const uint256& fs_seed, std::string* why)
{
    using T = AirField<F>;
    using B = AirFriBackend<F>;
    auto fail = [&](const char* w) {
        if (why) *why = w;
        return false;
    };

    const uint32_t N = cs.n_rows;
    const uint32_t W = cs.n_columns;
    if (N < 2 || (N & (N - 1)) != 0 || W == 0) return fail("bad constraint system");
    const auto& batch = proof.batch;

    // Structural degree-bound checks. column_len IS the enforced per-column
    // degree bound (batched-FRI degree-shift RLC); a quotient committed with
    // any other declared length — in particular an over-degree one — is
    // rejected HERE before any crypto work.
    if (batch.columns.size() != W + 1 || batch.column_len.size() != W + 1) {
        return fail("column count mismatch");
    }
    for (uint32_t c = 0; c < W; ++c) {
        if (batch.column_len[c] != N) return fail("trace column degree bound mismatch");
    }
    const uint32_t Lq = cs.QuotientLen();
    if (batch.column_len[W] != Lq) return fail("quotient degree bound mismatch");
    const uint32_t n_coeffs_expect = FriNextPow2(std::max(N, Lq));
    if (batch.n_coeffs != n_coeffs_expect) return fail("n_coeffs mismatch");

    // Proximity + per-column degree enforcement + Merkle binding of the
    // per-query openings (Q = 128 FS query sites, dual-OOD DEEP).
    if (!B::BatchVerify(batch, fs_seed, why)) return false;

    // Preprocessed (public) columns: pin the committed column to the canonical
    // values — a prover-chosen table side is rejected here. Two modes:
    //  • root regen (default): rebuild the LDE Merkle root from the values.
    //  • dual-OOD pin: evaluate the canonical polynomial at g·z1, g·z2
    //    (barycentric over H, shared weights) and require equality with the
    //    DEEP-bound evals_z1/evals_z2 — O(N) field ops, no hashing.
    if (cs.preprocessed_pin_ood && !cs.preprocessed.empty()) {
        if (batch.evals_z1.size() != W + 1 || batch.evals_z2.size() != W + 1) {
            return fail("preprocessed ood eval shape");
        }
        const F g_shift = T::FromBase(kAirCosetShift);
        const F pts[2] = {T::Mul(g_shift, batch.z1), T::Mul(g_shift, batch.z2)};
        const std::vector<F>* evs[2] = {&batch.evals_z1, &batch.evals_z2};
        for (int pi = 0; pi < 2; ++pi) {
            std::vector<F> wts;
            F zh_over_n = T::Zero();
            if (!AirBarycentricWeightsOnH<F>(N, pts[pi], wts, zh_over_n)) {
                return fail("preprocessed ood point degenerate");
            }
            for (const auto& [idx, values] : cs.preprocessed) {
                if (idx >= W || values.size() != N) return fail("preprocessed shape");
                F acc = T::Zero();
                for (uint32_t j = 0; j < N; ++j) {
                    acc = T::Add(acc, T::Mul(values[j], wts[j]));
                }
                if (!T::Eq(T::Mul(zh_over_n, acc), (*evs[pi])[idx])) {
                    return fail("preprocessed ood eval mismatch");
                }
            }
        }
    } else {
        for (const auto& [idx, values] : cs.preprocessed) {
            if (idx >= W || values.size() != N) return fail("preprocessed shape");
            std::vector<F> pc = AirInterpolate(values);
            AirCosetShiftCoeffs(pc);
            if (B::ColumnRoot(pc, batch.n_coeffs) != batch.columns[idx].root) {
                return fail("preprocessed column root mismatch");
            }
        }
    }
    // Preprocessed columns satisfied by ROOT EQUALITY against a supplied root
    // (Stage A slice-opening mode): the committed column must be EXACTLY the
    // one committed under the caller-authenticated root — O(1) per column.
    for (const auto& [idx, root] : cs.preprocessed_roots) {
        if (idx >= W) return fail("preprocessed root index");
        if (batch.columns[idx].root != root) return fail("preprocessed root mismatch");
    }

    // FS λ re-derivation from the committed trace roots.
    std::vector<uint256> trace_roots(W);
    for (uint32_t c = 0; c < W; ++c) trace_roots[c] = batch.columns[c].root;
    const F lambda = DeriveChallenge<F>(fs_seed, "airq_lambda", trace_roots, {N, Lq, W});

    const uint32_t n_lde = batch.n_coeffs * kRCFriBlowup;
    const uint32_t step = n_lde / N;
    if (proof.next_openings.size() != batch.queries.size()) {
        return fail("next-opening count mismatch");
    }

    const Fp omega_lde = AirOmegaForSize(n_lde);
    const Fp omega_N = AirOmegaForSize(N);
    const F h_first = T::One();
    const F h_last = T::FromBase(AirPowBase(omega_N, N - 1));
    const F g = T::FromBase(kAirCosetShift);

    std::vector<F> cur(W), nxt(W);
    for (size_t qi = 0; qi < batch.queries.size(); ++qi) {
        const auto& q = batch.queries[qi];
        if (q.columns.size() != W + 1) return fail("query column count");
        const auto& no = proof.next_openings[qi];
        if (no.size() != W) return fail("next-opening width");
        const uint32_t nidx = (q.index + step) % n_lde;
        for (uint32_t c = 0; c < W; ++c) {
            if (no[c].index != nidx) return fail("next-opening index");
            if (!B::VerifyPath(no[c], batch.columns[c].root, n_lde)) {
                return fail("next-opening merkle");
            }
            cur[c] = q.columns[c].value;
            nxt[c] = no[c].leaf;
        }
        // Actual evaluation point y = g·ω^index (coset — Z_H(y) ≠ 0).
        const F y = T::Mul(g, T::FromBase(AirPowBase(omega_lde, q.index)));
        const F zh = T::Sub(AirPow(y, N), T::One());
        if (T::IsZero(zh)) return fail("Z_H vanishes at query point (coset violated)");

        F csum = T::Zero();
        F lp = T::One();
        for (const auto& con : cs.constraints) {
            const F v = con.eval(cur, nxt);
            if (!T::IsZero(v)) {
                const F sel = AirSelectorEval<F>(con.kind, N, y, h_first, h_last);
                csum = T::Add(csum, T::Mul(lp, T::Mul(sel, v)));
            }
            lp = T::Mul(lp, lambda);
        }
        const F qv = q.columns[W].value;
        if (!T::Eq(csum, T::Mul(qv, zh))) return fail("quotient identity C(y) != Q(y)*Z_H(y)");
    }
    if (why) *why = "AirQuotientVerify ok";
    return true;
}

// ===========================================================================
// Concrete instantiation: Extract-sampler + dequant + LogUp rules of one tile.
// ===========================================================================

template <typename F>
AirConstraintSystem<F> BuildRcSamplerConstraintSystem(uint32_t n_rows, const F& gamma,
                                                      const F& alpha, uint8_t scale_e,
                                                      const gkr_air::TableTM& tm)
{
    using T = AirField<F>;
    AirConstraintSystem<F> cs;
    cs.n_rows = n_rows;
    cs.n_columns = kRcSamplerNumCols;

    auto add = [&](const char* name, AirKind kind, uint32_t deg,
                   std::function<F(const std::vector<F>&, const std::vector<F>&)> ev) {
        AirConstraint<F> c;
        c.name = name;
        c.kind = kind;
        c.alg_degree = deg;
        c.eval = std::move(ev);
        cs.constraints.push_back(std::move(c));
    };
    auto add_bool = [&](const char* name, uint32_t col) {
        add(name, AirKind::kEverywhere, 2,
            [col](const std::vector<F>& r, const std::vector<F>&) {
                return T::Mul(r[col], T::Sub(r[col], T::One()));
            });
    };

    // -- Extract-sampler rule (per-row core; row-scan source: EmitTileConstraints).
    add_bool("act.bool", kColAct);
    add_bool("kb0.bool", kColKb0);
    add_bool("kb1.bool", kColKb1);
    add_bool("kb2.bool", kColKb2);
    add_bool("kb3.bool", kColKb3);
    add_bool("hb0.bool", kColHb0);
    add_bool("hb1.bool", kColHb1);
    add_bool("hb2.bool", kColHb2);
    add_bool("hb3.bool", kColHb3);
    add_bool("mb0.bool", kColMb0);
    add_bool("mb1.bool", kColMb1);
    add_bool("mb2.bool", kColMb2);
    add_bool("mb3.bool", kColMb3);
    add_bool("acc.bool", kColAcc);
    add_bool("vb0.bool", kColVb0);
    add_bool("vb1.bool", kColVb1);
    add_bool("vb2.bool", kColVb2);
    add_bool("vb3.bool", kColVb3);
    add_bool("e0.bool", kColE0);
    add_bool("e1.bool", kColE1);

    auto nibble = [](const std::vector<F>& r, uint32_t b0) {
        F acc = T::Zero();
        for (int i = 0; i < 4; ++i) {
            acc = T::Add(acc, T::Mul(T::FromU64(1ull << i), r[b0 + i]));
        }
        return acc;
    };
    add("kappa.recomp", AirKind::kEverywhere, 1,
        [nibble](const std::vector<F>& r, const std::vector<F>&) {
            return T::Sub(r[kColKappa], nibble(r, kColKb0));
        });
    add("h.recomp", AirKind::kEverywhere, 1,
        [nibble](const std::vector<F>& r, const std::vector<F>&) {
            return T::Sub(r[kColH], nibble(r, kColHb0));
        });
    add("mixed.recomp", AirKind::kEverywhere, 1,
        [nibble](const std::vector<F>& r, const std::vector<F>&) {
            return T::Sub(r[kColMixed], nibble(r, kColMb0));
        });
    // C-E3: mixed = kappa XOR h, per bit (xor = a + b − 2ab).
    add("mixed.xor", AirKind::kEverywhere, 2,
        [](const std::vector<F>& r, const std::vector<F>&) {
            F acc = T::Zero();
            for (int i = 0; i < 4; ++i) {
                const F a = r[kColKb0 + i];
                const F b = r[kColHb0 + i];
                const F x = T::Sub(T::Add(a, b), T::Mul(T::FromU64(2), T::Mul(a, b)));
                acc = T::Add(acc, T::Mul(T::FromU64(1ull << i), x));
            }
            return T::Sub(r[kColMixed], acc);
        });
    // C-E4: degree-4 acceptance selector.
    add("accept.poly", AirKind::kEverywhere, 4,
        [](const std::vector<F>& r, const std::vector<F>&) {
            return T::Sub(r[kColAcc],
                          AirAcceptPoly<F>(r[kColMb0], r[kColMb1], r[kColMb2], r[kColMb3]));
        });
    // C-E5 liveness gated by activity: act·((32 − pos)·inv_live − 1) = 0.
    add("liveness", AirKind::kEverywhere, 3,
        [](const std::vector<F>& r, const std::vector<F>&) {
            const F t32 = T::FromU64(kRCMxBlockLen);
            const F lv = T::Sub(T::Mul(T::Sub(t32, r[kColPos]), r[kColInvLive]), T::One());
            return T::Mul(r[kColAct], lv);
        });
    // Padding rows pin pos = 32: (1 − act)·(pos − 32) = 0.
    add("inactive.pos", AirKind::kEverywhere, 2,
        [](const std::vector<F>& r, const std::vector<F>&) {
            return T::Mul(T::Sub(T::One(), r[kColAct]),
                          T::Sub(r[kColPos], T::FromU64(kRCMxBlockLen)));
        });
    // C-E9: golden mix u·G = q·2^32 + v (exact over F_p: u·G < p).
    add("golden.mix", AirKind::kEverywhere, 1,
        [](const std::vector<F>& r, const std::vector<F>&) {
            const F lhs = T::Mul(r[kColUMix], T::FromU64(0x9E3779B9ull));
            const F rhs = T::Add(T::Mul(T::FromU64(1ull << 32), r[kColGoldQ]), r[kColGoldV]);
            return T::Sub(lhs, rhs);
        });
    // gold_v = v_low28 + 2^28·(top nibble); the 28-bit range of v_low28 (and
    // the 16-bit limb ranges of the row-scan AIR) remain LogUp/T_R16
    // membership obligations, not identities — see the header honesty block.
    add("goldv.decomp", AirKind::kEverywhere, 1,
        [nibble](const std::vector<F>& r, const std::vector<F>&) {
            const F top = nibble(r, kColVb0);
            return T::Sub(r[kColGoldV],
                          T::Add(r[kColVLow28], T::Mul(T::FromU64(1ull << 28), top)));
        });
    add("h.top_nibble", AirKind::kEverywhere, 1,
        [nibble](const std::vector<F>& r, const std::vector<F>&) {
            return T::Sub(r[kColH], nibble(r, kColVb0));
        });
    // Reserved column stays zero.
    add("pad.zero", AirKind::kEverywhere, 1,
        [](const std::vector<F>& r, const std::vector<F>&) { return r[kColPad0]; });

    // -- Dequant / C-E10 rule: out = mu_out·(1 + e0)(1 + 3·e1)  (= mu·2^e).
    add("out.dequant", AirKind::kEverywhere, 3,
        [](const std::vector<F>& r, const std::vector<F>&) {
            const F scale = T::Mul(T::Add(T::One(), r[kColE0]),
                                   T::Add(T::One(), T::Mul(T::FromU64(3), r[kColE1])));
            return T::Sub(r[kColOut], T::Mul(r[kColMuOut], scale));
        });

    // -- LogUp rule (T_M membership of (mixed, acc, mu) with canonical table).
    const F g2 = T::Mul(gamma, gamma);
    add("logup.phi", AirKind::kEverywhere, 2,
        [gamma, g2, alpha](const std::vector<F>& r, const std::vector<F>&) {
            const F w = T::Add(r[kColMixed],
                               T::Add(T::Mul(gamma, r[kColAcc]), T::Mul(g2, r[kColMu])));
            return T::Sub(T::Mul(r[kColPhi], T::Sub(alpha, w)), T::One());
        });
    add("logup.psi", AirKind::kEverywhere, 2,
        [alpha](const std::vector<F>& r, const std::vector<F>&) {
            return T::Sub(T::Mul(r[kColPsi], T::Sub(alpha, r[kColTfp])), r[kColM]);
        });

    // -- Transitions (rows 0..N−2).
    add("pos.trans", AirKind::kTransition, 1,
        [](const std::vector<F>& r, const std::vector<F>& n) {
            return T::Sub(n[kColPos], T::Add(r[kColPos], r[kColAcc]));
        });
    add("act.mono", AirKind::kTransition, 2,
        [](const std::vector<F>& r, const std::vector<F>& n) {
            return T::Mul(n[kColAct], T::Sub(T::One(), r[kColAct]));
        });
    add("e0.const", AirKind::kTransition, 1,
        [](const std::vector<F>& r, const std::vector<F>& n) {
            return T::Sub(n[kColE0], r[kColE0]);
        });
    add("e1.const", AirKind::kTransition, 1,
        [](const std::vector<F>& r, const std::vector<F>& n) {
            return T::Sub(n[kColE1], r[kColE1]);
        });
    add("logup.S.trans", AirKind::kTransition, 1,
        [](const std::vector<F>& r, const std::vector<F>& n) {
            return T::Sub(n[kColS], T::Add(r[kColS], T::Sub(r[kColPhi], r[kColPsi])));
        });

    // -- Boundaries.
    add("pos.first", AirKind::kFirstRow, 1,
        [](const std::vector<F>& r, const std::vector<F>&) { return r[kColPos]; });
    add("act.first", AirKind::kFirstRow, 1,
        [](const std::vector<F>& r, const std::vector<F>&) {
            return T::Sub(r[kColAct], T::One());
        });
    add("logup.S.first", AirKind::kFirstRow, 1,
        [](const std::vector<F>& r, const std::vector<F>&) { return r[kColS]; });
    const uint64_t pub_e0 = scale_e & 1u;
    const uint64_t pub_e1 = (scale_e >> 1) & 1u;
    add("e0.public", AirKind::kFirstRow, 1,
        [pub_e0](const std::vector<F>& r, const std::vector<F>&) {
            return T::Sub(r[kColE0], T::FromU64(pub_e0));
        });
    add("e1.public", AirKind::kFirstRow, 1,
        [pub_e1](const std::vector<F>& r, const std::vector<F>&) {
            return T::Sub(r[kColE1], T::FromU64(pub_e1));
        });
    add("pos.last", AirKind::kLastRow, 1,
        [](const std::vector<F>& r, const std::vector<F>&) {
            return T::Sub(T::Add(r[kColPos], r[kColAcc]), T::FromU64(kRCMxBlockLen));
        });
    // Σφ = Σψ (the LogUp membership identity, telescoped through S).
    add("logup.S.last", AirKind::kLastRow, 1,
        [](const std::vector<F>& r, const std::vector<F>&) {
            return T::Add(r[kColS], T::Sub(r[kColPhi], r[kColPsi]));
        });

    // -- Preprocessed canonical T_M fingerprint column (verifier-regenerated).
    std::vector<F> tvals(n_rows, T::Zero());
    for (uint32_t j = 0; j < n_rows; ++j) {
        const uint32_t n = (j < 16) ? j : 0;  // padding rows duplicate row 0 (m = 0 there)
        tvals[j] = T::Add(T::FromU64(n),
                          T::Add(T::Mul(gamma, T::FromU64(tm.acc[n])),
                                 T::Mul(g2, T::FromSigned(tm.mu[n]))));
    }
    cs.preprocessed.emplace_back(static_cast<uint32_t>(kColTfp), std::move(tvals));
    return cs;
}

template <typename F>
RcSamplerBuild<F> BuildRcSamplerInstance(const gkr_air::TileWitness& w,
                                         const gkr_air::TableTM& tm, const uint256& fs_seed)
{
    using T = AirField<F>;
    using B = AirFriBackend<F>;
    RcSamplerBuild<F> out;

    const uint32_t n_cands = static_cast<uint32_t>(w.cands.size());
    if (n_cands == 0) {
        out.note = "empty tile witness";
        return out;
    }
    const uint32_t N = FriNextPow2(std::max<uint32_t>(n_cands, kRCMxBlockLen + 1));
    out.n_rows = N;

    // ---- Base columns (epoch 1). ----
    std::vector<std::vector<F>> cols(kRcSamplerNumCols, std::vector<F>(N, T::Zero()));
    auto set_bits = [&](uint32_t base_col, uint32_t r, uint32_t v, int nbits) {
        for (int i = 0; i < nbits; ++i) {
            cols[base_col + i][r] = T::FromU64((v >> i) & 1u);
        }
    };
    for (uint32_t r = 0; r < N; ++r) {
        if (r < n_cands) {
            const auto& c = w.cands[r];
            cols[kColAct][r] = T::One();
            cols[kColKappa][r] = T::FromU64(c.kappa);
            set_bits(kColKb0, r, c.kappa, 4);
            cols[kColH][r] = T::FromU64(c.h);
            set_bits(kColHb0, r, c.h, 4);
            cols[kColMixed][r] = T::FromU64(c.mixed);
            set_bits(kColMb0, r, c.mixed, 4);
            cols[kColAcc][r] = T::FromU64(c.acc);
            cols[kColMu][r] = T::FromSigned(c.mu);
            cols[kColPos][r] = T::FromU64(c.pos);
            cols[kColInvLive][r] = T::FromBase(c.inv_live);
            cols[kColUMix][r] = T::FromU64(c.u_mix);
            cols[kColGoldQ][r] = T::FromU64(c.gold_q);
            cols[kColGoldV][r] = T::FromU64(c.gold_v);
            cols[kColVLow28][r] = T::FromU64(c.gold_v & 0x0FFFFFFFu);
            set_bits(kColVb0, r, c.gold_v >> 28, 4);
        } else {
            // Neutral padding: mixed = 1 is a REJECTED E2M1 code, so
            // accept.poly holds with acc = 0 and pos stays at 32.
            cols[kColKappa][r] = T::One();
            cols[kColKb0][r] = T::One();
            cols[kColMixed][r] = T::One();
            cols[kColMb0][r] = T::One();
            cols[kColPos][r] = T::FromU64(kRCMxBlockLen);
        }
        cols[kColE0][r] = T::FromU64(w.scale_e & 1u);
        cols[kColE1][r] = T::FromU64((w.scale_e >> 1) & 1u);
        if (r < kRCMxBlockLen) {
            cols[kColMuOut][r] = T::FromSigned(w.mantissa[r]);
            cols[kColOut][r] = T::FromSigned(w.out[r]);
        }
    }

    // ---- Epoch-1 FS: γ, α from the committed base-column roots. ----
    AirConstraintSystem<F> cs_dummy =
        BuildRcSamplerConstraintSystem<F>(N, T::Zero(), T::Zero(), w.scale_e, tm);
    const uint32_t n_coeffs = FriNextPow2(std::max(N, cs_dummy.QuotientLen()));
    std::vector<uint256> base_roots(kRcSamplerBaseCols);
    for (uint32_t c = 0; c < kRcSamplerBaseCols; ++c) {
        std::vector<F> cf = AirInterpolate(cols[c]);
        AirCosetShiftCoeffs(cf);
        base_roots[c] = B::ColumnRoot(cf, n_coeffs);
    }
    out.gamma = DeriveChallenge<F>(fs_seed, "airq_gamma", base_roots, {N, n_coeffs});
    out.alpha = DeriveChallenge<F>(fs_seed, "airq_alpha", base_roots, {N, n_coeffs});

    // ---- Epoch-2 LogUp columns (φ, t, m, ψ, S). ----
    const F g2 = T::Mul(out.gamma, out.gamma);
    out.cs = BuildRcSamplerConstraintSystem<F>(N, out.gamma, out.alpha, w.scale_e, tm);
    const std::vector<F>& tvals = out.cs.preprocessed.front().second;
    for (uint32_t r = 0; r < N; ++r) cols[kColTfp][r] = tvals[r];

    std::vector<F> wfp(N);
    for (uint32_t r = 0; r < N; ++r) {
        wfp[r] = T::Add(cols[kColMixed][r],
                        T::Add(T::Mul(out.gamma, cols[kColAcc][r]),
                               T::Mul(g2, cols[kColMu][r])));
        const F den = T::Sub(out.alpha, wfp[r]);
        if (T::IsZero(den)) {
            out.note = "alpha collides with a witness key (fail closed)";
            return out;
        }
        cols[kColPhi][r] = T::Inv(den);
    }
    for (uint32_t j = 0; j < 16 && j < N; ++j) {
        uint64_t m = 0;
        for (uint32_t r = 0; r < N; ++r) {
            if (T::Eq(wfp[r], tvals[j])) ++m;
        }
        cols[kColM][j] = T::FromU64(m);
        const F den = T::Sub(out.alpha, tvals[j]);
        if (T::IsZero(den)) {
            out.note = "alpha collides with a table key (fail closed)";
            return out;
        }
        cols[kColPsi][j] = T::Mul(cols[kColM][j], T::Inv(den));
    }
    for (uint32_t r = 1; r < N; ++r) {
        cols[kColS][r] = T::Add(cols[kColS][r - 1],
                                T::Sub(cols[kColPhi][r - 1], cols[kColPsi][r - 1]));
    }
    const F total = T::Add(cols[kColS][N - 1],
                           T::Sub(cols[kColPhi][N - 1], cols[kColPsi][N - 1]));
    if (!T::IsZero(total)) {
        out.note = "LogUp imbalance (witness key outside the canonical table)";
        return out;
    }

    out.columns = std::move(cols);
    out.ok = true;
    return out;
}

template <typename F>
bool RcSamplerAirVerify(const AirQuotientProof<F>& proof, const uint256& fs_seed,
                        uint8_t scale_e, const gkr_air::TableTM& tm, std::string* why)
{
    auto fail = [&](const char* w) {
        if (why) *why = w;
        return false;
    };
    const auto& batch = proof.batch;
    if (batch.columns.size() != kRcSamplerNumCols + 1 ||
        batch.column_len.size() != kRcSamplerNumCols + 1) {
        return fail("sampler column layout mismatch");
    }
    const uint32_t N = batch.column_len[0];
    if (N < 2 || (N & (N - 1)) != 0) return fail("bad row count");
    std::vector<uint256> base_roots(kRcSamplerBaseCols);
    for (uint32_t c = 0; c < kRcSamplerBaseCols; ++c) base_roots[c] = batch.columns[c].root;
    const F gamma =
        DeriveChallenge<F>(fs_seed, "airq_gamma", base_roots, {N, batch.n_coeffs});
    const F alpha =
        DeriveChallenge<F>(fs_seed, "airq_alpha", base_roots, {N, batch.n_coeffs});
    const AirConstraintSystem<F> cs =
        BuildRcSamplerConstraintSystem<F>(N, gamma, alpha, scale_e, tm);
    return AirQuotientVerify<F>(cs, proof, fs_seed, why);
}

// ===========================================================================
// Explicit instantiations (Fp2 today, Fp3 ready).
// ===========================================================================

using gkr_field::Fp2;
using gkr_field::Fp3;

template Fp2 AirAcceptPoly<Fp2>(const Fp2&, const Fp2&, const Fp2&, const Fp2&);
template Fp3 AirAcceptPoly<Fp3>(const Fp3&, const Fp3&, const Fp3&, const Fp3&);

template uint256 AirCommittedValuesRoot<Fp2>(const std::vector<Fp2>&, uint32_t);
template uint256 AirCommittedValuesRoot<Fp3>(const std::vector<Fp3>&, uint32_t);

template AirQuotientProveResult<Fp2> AirQuotientProve<Fp2>(
    const AirConstraintSystem<Fp2>&, const std::vector<std::vector<Fp2>>&, const uint256&,
    const AirProveOptions&);
template AirQuotientProveResult<Fp3> AirQuotientProve<Fp3>(
    const AirConstraintSystem<Fp3>&, const std::vector<std::vector<Fp3>>&, const uint256&,
    const AirProveOptions&);

template bool AirQuotientVerify<Fp2>(const AirConstraintSystem<Fp2>&,
                                     const AirQuotientProof<Fp2>&, const uint256&, std::string*);
template bool AirQuotientVerify<Fp3>(const AirConstraintSystem<Fp3>&,
                                     const AirQuotientProof<Fp3>&, const uint256&, std::string*);

template AirConstraintSystem<Fp2> BuildRcSamplerConstraintSystem<Fp2>(
    uint32_t, const Fp2&, const Fp2&, uint8_t, const gkr_air::TableTM&);
template AirConstraintSystem<Fp3> BuildRcSamplerConstraintSystem<Fp3>(
    uint32_t, const Fp3&, const Fp3&, uint8_t, const gkr_air::TableTM&);

template RcSamplerBuild<Fp2> BuildRcSamplerInstance<Fp2>(const gkr_air::TileWitness&,
                                                         const gkr_air::TableTM&,
                                                         const uint256&);
template RcSamplerBuild<Fp3> BuildRcSamplerInstance<Fp3>(const gkr_air::TileWitness&,
                                                         const gkr_air::TableTM&,
                                                         const uint256&);

template bool RcSamplerAirVerify<Fp2>(const AirQuotientProof<Fp2>&, const uint256&, uint8_t,
                                      const gkr_air::TableTM&, std::string*);
template bool RcSamplerAirVerify<Fp3>(const AirQuotientProof<Fp3>&, const uint256&, uint8_t,
                                      const gkr_air::TableTM&, std::string*);

} // namespace matmul::v4::rc::air_quotient
