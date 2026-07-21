// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_gkr_eval.h>

#include <crypto/sha256.h>

#include <algorithm>
#include <array>
#include <cstring>

// ============================================================================
// EVALUATION ARGUMENT (blueprint §2.4, Theorem 2.2) — Wave-2 implementation.
//
// Aggregated MLE-opening argument (Aurora univariate sumcheck, Lemma 1.1/1.2).
// Every relation of the v7 verifier reduces to "ṽ(r) = c" for a committed
// column v (coefficient basis) and an FS point r. By §1.3 this is the inner
// product ⟨coeffs(P_v), coeffs(q_r)⟩ = c with q_r the eq-kernel.
//
// AGGREGATION. Collect M claims. Draw FS weights μ_1..μ_M (bound to fs_seed and
// EVERY claim). Define, over the order-N=n subgroup D (n = padded column len):
//
//   h(X) := X · Σ_m μ_m · P_{v_m}(X) · q*_{r_m}(X),   q*_r(X)=X^{n-1} q_r(1/X).
//
// On D, X·q*_r(X) = q_r(X^{-1}) (X^n=1), so Σ_{x∈D} h(x) = n·Σ_m μ_m·c_m by
// Lemma 1.1. Lemma 1.2 (deg h < 2n): Σ_{x∈D} h(x) = n·σ  ⇔  ∃ g (deg<n),
// f (deg<n-1) with h(X) = g(X)·(X^n−1) + X·f(X) + σ,   σ := Σ_m μ_m c_m.
//
// The prover commits f, g as two more columns of the SAME batched FRI (their
// z1/z2 evaluations therefore ride the batch's dual-OOD binding for free). The
// verifier recomputes σ from the CLAIMS (never trusts proof.sigma beyond an
// equality check) and checks the identity at BOTH bound OOD points z1, z2:
//
//   z·Σ_m μ_m·C_m(z)·q*_{r_m}(z)  ==  g(z)·(z^n−1) + z·f(z) + σ,   z∈{z1,z2},
//
// where C_m(z), f(z), g(z) are the batch's bound per-column evaluations and
// q*_{r_m}(z) = z^{n-1}·q_{r_m}(z^{-1}) is an O(ν) verifier evaluation.
//
// SOUNDNESS (Theorem 2.2). If some claim is false, σ_true ≠ Σμc, so no (f,g)
// makes the identity a polynomial identity; the residual is a nonzero poly of
// deg < 2n and both random z_s catch it: ε_eval ≤ (2n/|Fp2|)² + (M−1)/|Fp2|,
// times the 2^40 grinding budget ≤ 2^-76 for n ≤ 2^28, M ≤ 2^12 — conditioned
// on a PRIOR successful FriBatchVerify (Theorem 2.1) that binds C_m(z_s).
// ============================================================================

namespace matmul::v4::rc {

using gkr_field::Fp2;

namespace {

void AppendLE32(std::vector<unsigned char>& b, uint32_t v)
{
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<unsigned char>((v >> (8 * i)) & 0xFF));
}

void AppendFp2(std::vector<unsigned char>& b, const Fp2& v)
{
    const auto pair = gkr_field::ToU64Pair(v);
    for (int w = 0; w < 2; ++w)
        for (int i = 0; i < 8; ++i)
            b.push_back(static_cast<unsigned char>((pair[w] >> (8 * i)) & 0xFF));
}

uint256 Sha256dOf(const std::vector<unsigned char>& in)
{
    unsigned char h1[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(in.data(), in.size()).Finalize(h1);
    unsigned char h2[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(h1, sizeof(h1)).Finalize(h2);
    uint256 out;
    std::memcpy(out.data(), h2, 32);
    return out;
}

/** log2 of a power of two. */
uint32_t Log2Pow2(uint64_t n)
{
    uint32_t l = 0;
    while ((uint64_t{1} << l) < n) ++l;
    return l;
}

Fp2 PowFp2(Fp2 base, uint64_t exp)
{
    Fp2 r = Fp2::One();
    while (exp > 0) {
        if (exp & 1u) r = gkr_field::Mul(r, base);
        base = gkr_field::Mul(base, base);
        exp >>= 1;
    }
    return r;
}

/**
 * Common μ-transcript: binds fs_seed and EVERY claim (column_id, point, value)
 * so the aggregation weights cannot be adaptively gamed. Both prover and
 * verifier derive μ_m identically from (claims, fs_seed).
 */
uint256 MuBase(const std::vector<RCGkrOpeningClaim>& claims, const uint256& fs_seed)
{
    std::vector<unsigned char> b;
    b.insert(b.end(), fs_seed.begin(), fs_seed.end());
    const char* tag = "RCGKR_EVALARG_V1";
    b.insert(b.end(), tag, tag + std::strlen(tag));
    AppendLE32(b, static_cast<uint32_t>(claims.size()));
    for (const auto& c : claims) {
        AppendLE32(b, c.column_id);
        AppendLE32(b, static_cast<uint32_t>(c.point.size()));
        for (const Fp2& p : c.point) AppendFp2(b, p);
        AppendFp2(b, c.value);
    }
    return Sha256dOf(b);
}

Fp2 MuChallenge(const uint256& base, uint32_t m)
{
    std::vector<unsigned char> b;
    b.insert(b.end(), base.begin(), base.end());
    const char* tag = "mu";
    b.insert(b.end(), tag, tag + 2);
    AppendLE32(b, m);
    return gkr_field::FromChallengeBytes2(Sha256dOf(b).data());
}

/** q*_r(z) = z^{n-1}·q_r(z^{-1}) — coefficient-reversed eq-kernel, O(ν). */
Fp2 QStarAt(const std::vector<Fp2>& r, const Fp2& z, uint32_t n)
{
    const Fp2 zinv = gkr_field::Inv(z);
    return gkr_field::Mul(PowFp2(z, n - 1), RCGkrEqKernelAt(r, zinv));
}

} // namespace

RCGkrEvalArgumentProveResult EvalArgumentProve(const std::vector<RCGkrOpeningClaim>& claims,
                                               const std::vector<std::vector<Fp2>>& columns,
                                               const uint256& fs_seed)
{
    RCGkrEvalArgumentProveResult res;
    if (claims.empty()) {
        res.note = "no claims";
        return res;
    }
    if (claims.size() > kRCGkrEvalArgMaxClaims) {
        res.note = "too many claims";
        return res;
    }

    // n = padded (pow2) common column length of the batch. f,g are length ≤ n,
    // so they do not grow the batch beyond the epoch-1 max.
    size_t max_len = 0;
    for (const auto& col : columns) max_len = std::max(max_len, col.size());
    if (max_len == 0) {
        res.note = "empty columns";
        return res;
    }
    uint32_t n = 1;
    while (n < max_len) n <<= 1;
    const uint32_t nu = Log2Pow2(n);

    for (const auto& c : claims) {
        if (c.column_id >= columns.size()) {
            res.note = "claim column_id out of range";
            return res;
        }
        if (c.point.size() != nu) {
            res.note = "claim point dimension != log2(n) (caller must zero-extend)";
            return res;
        }
    }
    const uint256 mu_base = MuBase(claims, fs_seed);

    // σ = Σ_m μ_m·c_m and h(X) = X·Σ_m μ_m·P_{v_m}(X)·q*_{r_m}(X) (deg < 2n).
    Fp2 sigma = Fp2::Zero();
    std::vector<Fp2> h(2 * static_cast<size_t>(n), Fp2::Zero());
    for (size_t m = 0; m < claims.size(); ++m) {
        const Fp2 mu = MuChallenge(mu_base, static_cast<uint32_t>(m));
        sigma = gkr_field::Add(sigma, gkr_field::Mul(mu, claims[m].value));

        const std::vector<Fp2>& P = columns[claims[m].column_id];
        const std::vector<Fp2> q = RCGkrEqKernelCoeffs(claims[m].point); // length n
        // q*[j] = q[n-1-j]; h += μ·X·(P * q*).
        for (size_t i = 0; i < P.size(); ++i) {
            if (gkr_field::IsZero(P[i])) continue;
            const Fp2 pw = gkr_field::Mul(mu, P[i]);
            for (uint32_t j = 0; j < n; ++j) {
                const Fp2& qc = q[n - 1 - j];
                if (gkr_field::IsZero(qc)) continue;
                const size_t k = i + j + 1; // +1 for the leading X
                h[k] = gkr_field::Add(h[k], gkr_field::Mul(pw, qc));
            }
        }
    }

    // Lemma 1.2 witnesses. With H(X)=h(X)−σ (σ subtracted from the constant):
    //   g_j = h_{j+n}                 (j = 0..n-1)
    //   f_i = h_{i+1} + h_{i+1+n}     (i = 0..n-2)
    // Consistency H_0+H_n = c0−σ = 0 holds iff every claim is true; the
    // witnesses are well-defined regardless, so a false claim makes the
    // identity fail (by a nonzero constant, caught at both z_s).
    res.g_coeffs.assign(n, Fp2::Zero());
    res.f_coeffs.assign(n > 1 ? n - 1 : 1, Fp2::Zero());
    for (uint32_t j = 0; j < n; ++j) res.g_coeffs[j] = h[static_cast<size_t>(j) + n];
    for (uint32_t i = 0; i + 1 < n; ++i) {
        res.f_coeffs[i] = gkr_field::Add(h[static_cast<size_t>(i) + 1],
                                         h[static_cast<size_t>(i) + 1 + n]);
    }

    res.proof.version = kRCGkrEvalArgVersion;
    res.proof.sigma = sigma;
    // f/g take the next two column ids after the epoch-1 columns (the caller
    // appends f_coeffs then g_coeffs in that order).
    res.proof.f_column = static_cast<uint32_t>(columns.size());
    res.proof.g_column = static_cast<uint32_t>(columns.size() + 1);
    res.ok = true;
    res.note = "ok";
    return res;
}

bool EvalArgumentVerify(const std::vector<RCGkrOpeningClaim>& claims, const FriBatchProof& batch,
                        const RCGkrEvalArgumentProof& proof, const uint256& fs_seed,
                        std::string* why)
{
    auto fail = [&](const char* m) {
        if (why) *why = m;
        return false;
    };
    if (proof.version != kRCGkrEvalArgVersion) return fail("eval:version");
    if (claims.empty()) return fail("eval:no_claims");
    if (claims.size() > kRCGkrEvalArgMaxClaims) return fail("eval:too_many_claims");

    const uint32_t n = batch.n_coeffs;
    if (n == 0 || (n & (n - 1)) != 0) return fail("eval:n_not_pow2");
    const uint32_t nu = Log2Pow2(n);

    // f/g must be real columns of the batch (their z-openings are bound by a
    // PRIOR successful FriBatchVerify — the caller MUST have run it first).
    const uint32_t ncols = static_cast<uint32_t>(batch.columns.size());
    if (proof.f_column >= ncols || proof.g_column >= ncols) return fail("eval:fg_col_range");
    if (batch.evals_z1.size() != ncols || batch.evals_z2.size() != ncols)
        return fail("eval:evals_shape");

    for (const auto& c : claims) {
        if (c.column_id >= ncols) return fail("eval:claim_col_range");
        if (c.point.size() != nu) return fail("eval:claim_point_dim");
    }

    // Recompute μ and σ from the CLAIMS — proof.sigma is never trusted.
    const uint256 mu_base = MuBase(claims, fs_seed);
    Fp2 sigma = Fp2::Zero();
    std::vector<Fp2> mu(claims.size());
    for (size_t m = 0; m < claims.size(); ++m) {
        mu[m] = MuChallenge(mu_base, static_cast<uint32_t>(m));
        sigma = gkr_field::Add(sigma, gkr_field::Mul(mu[m], claims[m].value));
    }
    if (!gkr_field::Eq(sigma, proof.sigma)) return fail("eval:sigma_mismatch");

    // Check the Lemma 1.2 identity at BOTH bound OOD points.
    for (int s = 0; s < 2; ++s) {
        const Fp2 z = (s == 0) ? batch.z1 : batch.z2;
        const std::vector<Fp2>& ev = (s == 0) ? batch.evals_z1 : batch.evals_z2;
        // LHS: h(z) = z·Σ_m μ_m·C_m(z)·q*_{r_m}(z).
        Fp2 lhs = Fp2::Zero();
        for (size_t m = 0; m < claims.size(); ++m) {
            const Fp2 term = gkr_field::Mul(gkr_field::Mul(mu[m], ev[claims[m].column_id]),
                                            QStarAt(claims[m].point, z, n));
            lhs = gkr_field::Add(lhs, term);
        }
        lhs = gkr_field::Mul(z, lhs);
        // RHS: g(z)·(z^n − 1) + z·f(z) + σ.
        const Fp2 zn_minus_1 = gkr_field::Sub(PowFp2(z, n), Fp2::One());
        Fp2 rhs = gkr_field::Mul(ev[proof.g_column], zn_minus_1);
        rhs = gkr_field::Add(rhs, gkr_field::Mul(z, ev[proof.f_column]));
        rhs = gkr_field::Add(rhs, sigma);
        if (!gkr_field::Eq(lhs, rhs)) return fail(s == 0 ? "eval:identity_z1" : "eval:identity_z2");
    }
    return true;
}

} // namespace matmul::v4::rc
