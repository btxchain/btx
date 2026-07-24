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

// ============================================================================
// Fp3 SIBLINGS of the §2.4 aggregated evaluation argument (v7 EPISODE path).
// Structure-for-structure mirror of the Fp2 implementation above over
// K = F_{p^3} (|K| ≈ 2^192), consuming the Fri3Batch* opening primitive. The
// μ-transcript uses a DISTINCT domain tag and 24-byte challenge derivation
// (FromChallengeBytes3) — Fp2 and Fp3 transcripts can never collide.
// ============================================================================

namespace {

using gkr_field::Fp3;

void AppendFp3(std::vector<unsigned char>& b, const Fp3& v)
{
    const auto triple = gkr_field::ToU64Triple(v);
    for (int w = 0; w < 3; ++w)
        for (int i = 0; i < 8; ++i)
            b.push_back(static_cast<unsigned char>((triple[w] >> (8 * i)) & 0xFF));
}

Fp3 PowFp3(Fp3 base, uint64_t exp)
{
    Fp3 r = Fp3::One();
    while (exp > 0) {
        if (exp & 1u) r = gkr_field::Mul(r, base);
        base = gkr_field::Mul(base, base);
        exp >>= 1;
    }
    return r;
}

/** μ-transcript over the Fp3 claims (distinct domain tag from the Fp2 path). */
uint256 MuBase3(const std::vector<RCGkrOpeningClaim3>& claims, const uint256& fs_seed)
{
    std::vector<unsigned char> b;
    b.insert(b.end(), fs_seed.begin(), fs_seed.end());
    const char* tag = "RCGKR_EVALARG3_V1";
    b.insert(b.end(), tag, tag + std::strlen(tag));
    AppendLE32(b, static_cast<uint32_t>(claims.size()));
    for (const auto& c : claims) {
        AppendLE32(b, c.column_id);
        AppendLE32(b, static_cast<uint32_t>(c.point.size()));
        for (const Fp3& p : c.point) AppendFp3(b, p);
        AppendFp3(b, c.value);
    }
    return Sha256dOf(b);
}

Fp3 MuChallenge3(const uint256& base, uint32_t m)
{
    std::vector<unsigned char> b;
    b.insert(b.end(), base.begin(), base.end());
    const char* tag = "mu3";
    b.insert(b.end(), tag, tag + 3);
    AppendLE32(b, m);
    return gkr_field::FromChallengeBytes3(Sha256dOf(b).data());
}

/** q*_r(z) = z^{n-1}·q_r(z^{-1}) — coefficient-reversed eq-kernel, O(ν). */
Fp3 QStarAt3(const std::vector<Fp3>& r, const Fp3& z, uint32_t n)
{
    const Fp3 zinv = gkr_field::Inv(z);
    return gkr_field::Mul(PowFp3(z, n - 1), RCGkrEqKernelAt3(r, zinv));
}

} // namespace

RCGkrEvalArgumentProveResult3 EvalArgumentProve3(const std::vector<RCGkrOpeningClaim3>& claims,
                                                 const std::vector<std::vector<Fp3>>& columns,
                                                 const uint256& fs_seed)
{
    RCGkrEvalArgumentProveResult3 res;
    if (claims.empty()) {
        res.note = "no claims";
        return res;
    }
    if (claims.size() > kRCGkrEvalArgMaxClaims) {
        res.note = "too many claims";
        return res;
    }

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
    const uint256 mu_base = MuBase3(claims, fs_seed);

    // σ = Σ_m μ_m·c_m and h(X) = X·Σ_m μ_m·P_{v_m}(X)·q*_{r_m}(X) (deg < 2n).
    Fp3 sigma = Fp3::Zero();
    std::vector<Fp3> h(2 * static_cast<size_t>(n), Fp3::Zero());
    for (size_t m = 0; m < claims.size(); ++m) {
        const Fp3 mu = MuChallenge3(mu_base, static_cast<uint32_t>(m));
        sigma = gkr_field::Add(sigma, gkr_field::Mul(mu, claims[m].value));

        const std::vector<Fp3>& P = columns[claims[m].column_id];
        const std::vector<Fp3> q = RCGkrEqKernelCoeffs3(claims[m].point); // length n
        // q*[j] = q[n-1-j]; h += μ·X·(P * q*).
        for (size_t i = 0; i < P.size(); ++i) {
            if (gkr_field::IsZero(P[i])) continue;
            const Fp3 pw = gkr_field::Mul(mu, P[i]);
            for (uint32_t j = 0; j < n; ++j) {
                const Fp3& qc = q[n - 1 - j];
                if (gkr_field::IsZero(qc)) continue;
                const size_t k = i + j + 1; // +1 for the leading X
                h[k] = gkr_field::Add(h[k], gkr_field::Mul(pw, qc));
            }
        }
    }

    // Lemma 1.2 witnesses (see the Fp2 body above for the derivation).
    res.g_coeffs.assign(n, Fp3::Zero());
    res.f_coeffs.assign(n > 1 ? n - 1 : 1, Fp3::Zero());
    for (uint32_t j = 0; j < n; ++j) res.g_coeffs[j] = h[static_cast<size_t>(j) + n];
    for (uint32_t i = 0; i + 1 < n; ++i) {
        res.f_coeffs[i] = gkr_field::Add(h[static_cast<size_t>(i) + 1],
                                         h[static_cast<size_t>(i) + 1 + n]);
    }

    res.proof.version = kRCGkrEvalArgVersion;
    res.proof.sigma = sigma;
    res.proof.f_column = static_cast<uint32_t>(columns.size());
    res.proof.g_column = static_cast<uint32_t>(columns.size() + 1);
    res.ok = true;
    res.note = "ok";
    return res;
}

bool EvalArgumentVerify3(const std::vector<RCGkrOpeningClaim3>& claims,
                         const Fri3BatchProof& batch, const RCGkrEvalArgumentProof3& proof,
                         const uint256& fs_seed, std::string* why)
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
    // PRIOR successful Fri3BatchVerify — the caller MUST have run it first).
    const uint32_t ncols = static_cast<uint32_t>(batch.columns.size());
    if (proof.f_column >= ncols || proof.g_column >= ncols) return fail("eval:fg_col_range");
    if (batch.evals_z1.size() != ncols || batch.evals_z2.size() != ncols)
        return fail("eval:evals_shape");

    for (const auto& c : claims) {
        if (c.column_id >= ncols) return fail("eval:claim_col_range");
        if (c.point.size() != nu) return fail("eval:claim_point_dim");
    }

    // Recompute μ and σ from the CLAIMS — proof.sigma is never trusted.
    const uint256 mu_base = MuBase3(claims, fs_seed);
    Fp3 sigma = Fp3::Zero();
    std::vector<Fp3> mu(claims.size());
    for (size_t m = 0; m < claims.size(); ++m) {
        mu[m] = MuChallenge3(mu_base, static_cast<uint32_t>(m));
        sigma = gkr_field::Add(sigma, gkr_field::Mul(mu[m], claims[m].value));
    }
    if (!gkr_field::Eq(sigma, proof.sigma)) return fail("eval:sigma_mismatch");

    // Check the Lemma 1.2 identity at BOTH bound OOD points.
    for (int s = 0; s < 2; ++s) {
        const Fp3 z = (s == 0) ? batch.z1 : batch.z2;
        const std::vector<Fp3>& ev = (s == 0) ? batch.evals_z1 : batch.evals_z2;
        // LHS: h(z) = z·Σ_m μ_m·C_m(z)·q*_{r_m}(z).
        Fp3 lhs = Fp3::Zero();
        for (size_t m = 0; m < claims.size(); ++m) {
            const Fp3 term = gkr_field::Mul(gkr_field::Mul(mu[m], ev[claims[m].column_id]),
                                            QStarAt3(claims[m].point, z, n));
            lhs = gkr_field::Add(lhs, term);
        }
        lhs = gkr_field::Mul(z, lhs);
        // RHS: g(z)·(z^n − 1) + z·f(z) + σ.
        const Fp3 zn_minus_1 = gkr_field::Sub(PowFp3(z, n), Fp3::One());
        Fp3 rhs = gkr_field::Mul(ev[proof.g_column], zn_minus_1);
        rhs = gkr_field::Add(rhs, gkr_field::Mul(z, ev[proof.f_column]));
        rhs = gkr_field::Add(rhs, sigma);
        if (!gkr_field::Eq(lhs, rhs)) return fail(s == 0 ? "eval:identity_z1" : "eval:identity_z2");
    }
    return true;
}

// ============================================================================
// CONSTRUCTION I (header block comment has the full statement + separation
// accounting). Stage 1: γ-batched eq-kernel summation-reduction over
//   F(x) = Σ_m γ^m · u_{c(m)}(x) · eq(z_m, x),   Σ_{x∈{0,1}^ν} F(x) = Σ γ^m y_m,
// a ν-round degree-2 reduction ending at a common point r with residual
// claims ũ_c(r) per distinct column. Stage 2: those residuals are bound to
// the LDE Merkle roots by the §2.4 aggregated opening (EvalArgument*) inside
// the ONE FriBatch instance.
// ============================================================================

namespace {

/** Lean FS transcript (SHA256d over a running byte buffer; same discipline as
 *  the file-local FsTranscript of matmul_v4_rc_gkr.cpp — commit-then-challenge,
 *  every challenge re-absorbed). */
class EqOpenFs
{
public:
    explicit EqOpenFs(const char* domain)
    {
        m_buf.insert(m_buf.end(), reinterpret_cast<const unsigned char*>(domain),
                     reinterpret_cast<const unsigned char*>(domain) + std::strlen(domain));
    }
    void AbsorbU32(uint32_t v) { AppendLE32(m_buf, v); }
    void AbsorbFp2(const Fp2& v) { AppendFp2(m_buf, v); }
    void AbsorbUint256(const uint256& h) { m_buf.insert(m_buf.end(), h.begin(), h.end()); }
    uint256 Challenge(const char* label)
    {
        m_buf.insert(m_buf.end(), reinterpret_cast<const unsigned char*>(label),
                     reinterpret_cast<const unsigned char*>(label) + std::strlen(label));
        const uint256 h = Sha256dOf(m_buf);
        AbsorbUint256(h);
        return h;
    }
    Fp2 ChallengeFp2(const char* label)
    {
        return gkr_field::FromChallengeBytes2(Challenge(label).data());
    }
    [[nodiscard]] uint256 Digest() const { return Sha256dOf(m_buf); }

private:
    std::vector<unsigned char> m_buf;
};

/** Degree-2 Lagrange evaluation from values at {0,1,2}:
 *  g(x) = g0·(1−x)(2−x)/2 + g1·x(2−x) + g2·x(x−1)/2. */
Fp2 EvalDeg2(const Fp2& g0, const Fp2& g1, const Fp2& g2, const Fp2& x)
{
    const Fp2 inv2 = gkr_field::Inv(Fp2::FromFp(2));
    const Fp2 one_minus = gkr_field::Sub(Fp2::One(), x);
    const Fp2 two_minus = gkr_field::Sub(Fp2::FromFp(2), x);
    Fp2 acc = gkr_field::Mul(gkr_field::Mul(g0, gkr_field::Mul(one_minus, two_minus)), inv2);
    acc = gkr_field::Add(acc, gkr_field::Mul(g1, gkr_field::Mul(x, two_minus)));
    acc = gkr_field::Add(
        acc, gkr_field::Mul(gkr_field::Mul(g2, gkr_field::Mul(x, gkr_field::Sub(x, Fp2::One()))),
                            inv2));
    return acc;
}

/** Zero-extend a point to dimension nu (selects the low sub-cube — the
 *  appended eq-factors become (1−0)=1 on the low half, 0 on the high half). */
std::vector<Fp2> PointExtend(const std::vector<Fp2>& p, uint32_t nu)
{
    std::vector<Fp2> q = p;
    while (q.size() < nu) q.push_back(Fp2::Zero());
    return q;
}

/** Distinct-column slots in first-use order over the claims.
 *  slot_of_claim[m] = slot index; slot_column[s] = column_id. */
void BuildSlots(const std::vector<RCGkrOpeningClaim>& claims, std::vector<size_t>& slot_of_claim,
                std::vector<uint32_t>& slot_column)
{
    slot_of_claim.assign(claims.size(), 0);
    slot_column.clear();
    for (size_t m = 0; m < claims.size(); ++m) {
        size_t s = slot_column.size();
        for (size_t t = 0; t < slot_column.size(); ++t) {
            if (slot_column[t] == claims[m].column_id) {
                s = t;
                break;
            }
        }
        if (s == slot_column.size()) slot_column.push_back(claims[m].column_id);
        slot_of_claim[m] = s;
    }
}

/** Structural validation shared by the Stage-1 constructing/checking routines.
 *  column_len[c] = logical length of column c (0 = unknown/skip the cover
 *  check). Returns nullptr on success, else the failure label. */
const char* ValidateOpenClaims(const std::vector<RCGkrOpeningClaim>& claims, uint32_t nu,
                               size_t n_columns, const std::vector<uint32_t>* column_len)
{
    if (claims.empty()) return "eqopen:no_claims";
    if (claims.size() > kRCGkrEvalArgMaxClaims) return "eqopen:too_many_claims";
    for (const auto& c : claims) {
        if (c.column_id >= n_columns) return "eqopen:claim_col_range";
        if (c.point.size() > nu) return "eqopen:point_dim";
        if (column_len != nullptr) {
            const uint64_t cover = uint64_t{1} << std::min<size_t>(c.point.size(), 63);
            if (cover < (*column_len)[c.column_id]) return "eqopen:point_short";
        }
    }
    return nullptr;
}

/** γ-transcript preamble: binds fs_seed + EVERY claim before γ is drawn. */
void AbsorbOpenStatement(EqOpenFs& fs, const std::vector<RCGkrOpeningClaim>& claims,
                         const uint256& fs_seed, uint32_t nu)
{
    fs.AbsorbUint256(fs_seed);
    fs.AbsorbU32(nu);
    fs.AbsorbU32(static_cast<uint32_t>(claims.size()));
    for (const auto& c : claims) {
        fs.AbsorbU32(c.column_id);
        fs.AbsorbU32(static_cast<uint32_t>(c.point.size()));
        for (const Fp2& p : c.point) fs.AbsorbFp2(p);
        fs.AbsorbFp2(c.value);
    }
}

constexpr char kEqOpenDomainTag[] = "BTX_RCGKR_EQOPEN_V1";
constexpr char kConstrIDomainTag[] = "RCGKR_CONSTR_I_V1";

/** Shared Stage-1 core. With repair_invalid=false this is the plain
 *  constructing routine and it REFUSES claims that disagree with the columns
 *  (the summation identity would be violated — nothing to construct). With
 *  repair_invalid=true it emits the STRONGEST internally-consistent transcript
 *  for the (possibly invalid) claims: every round sum is repaired by a
 *  constant shift into g(0) and the chain end is repaired by fabricating one
 *  residual ũ_c(r); all Stage-1 algebra then holds and detection is deferred
 *  to the Stage-2 root binding (test-only path). */
RCGkrEvalOpenProveResult EvalOpenProveCore(const std::vector<RCGkrOpeningClaim>& claims,
                                           const std::vector<std::vector<Fp2>>& columns,
                                           uint32_t nu, const uint256& fs_seed,
                                           bool repair_invalid)
{
    RCGkrEvalOpenProveResult res;
    if (nu > kRCFriMaxColumnLog2) {
        res.note = "eqopen:nu_too_large";
        return res;
    }
    std::vector<uint32_t> lens(columns.size());
    for (size_t i = 0; i < columns.size(); ++i) {
        if (columns[i].empty() || columns[i].size() > (size_t{1} << nu)) {
            res.note = "eqopen:column_len";
            return res;
        }
        lens[i] = static_cast<uint32_t>(columns[i].size());
    }
    if (const char* bad = ValidateOpenClaims(claims, nu, columns.size(), &lens)) {
        res.note = bad;
        return res;
    }

    EqOpenFs fs(kEqOpenDomainTag);
    AbsorbOpenStatement(fs, claims, fs_seed, nu);
    const Fp2 gamma = fs.ChallengeFp2("eqopen_gamma");

    std::vector<size_t> slot_of_claim;
    std::vector<uint32_t> slot_column;
    BuildSlots(claims, slot_of_claim, slot_column);
    const size_t n_slots = slot_column.size();
    const size_t n_full = size_t{1} << nu;

    // Per-slot tables: U_s = zero-padded column; E_s = Σ_{claims m on s} γ^m ·
    // eq-kernel(z_m zero-extended). Claimed total S = Σ_m γ^m·y_m.
    std::vector<std::vector<Fp2>> U(n_slots), E(n_slots);
    for (size_t s = 0; s < n_slots; ++s) {
        U[s].assign(n_full, Fp2::Zero());
        const auto& col = columns[slot_column[s]];
        for (size_t i = 0; i < col.size(); ++i) U[s][i] = col[i];
        E[s].assign(n_full, Fp2::Zero());
    }
    Fp2 gamma_pow = Fp2::One();
    Fp2 claimed_sum = Fp2::Zero();
    for (size_t m = 0; m < claims.size(); ++m) {
        claimed_sum = gkr_field::Add(claimed_sum, gkr_field::Mul(gamma_pow, claims[m].value));
        const std::vector<Fp2> kern = RCGkrEqKernelCoeffs(PointExtend(claims[m].point, nu));
        std::vector<Fp2>& es = E[slot_of_claim[m]];
        for (size_t i = 0; i < n_full; ++i) {
            if (gkr_field::IsZero(kern[i])) continue;
            es[i] = gkr_field::Add(es[i], gkr_field::Mul(gamma_pow, kern[i]));
        }
        gamma_pow = gkr_field::Mul(gamma_pow, gamma);
    }

    // ν degree-2 rounds folding the lowest remaining variable (pairs 2i/2i+1 —
    // little-endian order, matching EqFactor / RCGkrEqKernelCoeffs).
    Fp2 expected = claimed_sum;
    res.proof.version = kRCGkrEvalOpenVersion;
    res.proof.rounds.reserve(nu);
    res.r.clear();
    for (uint32_t round = 0; round < nu; ++round) {
        Fp2 g0 = Fp2::Zero(), g1 = Fp2::Zero(), g2 = Fp2::Zero();
        for (size_t s = 0; s < n_slots; ++s) {
            const std::vector<Fp2>& us = U[s];
            const std::vector<Fp2>& es = E[s];
            for (size_t idx = 0; idx < us.size(); idx += 2) {
                const Fp2 u0 = us[idx], u1 = us[idx + 1];
                const Fp2 e0 = es[idx], e1 = es[idx + 1];
                g0 = gkr_field::Add(g0, gkr_field::Mul(u0, e0));
                g1 = gkr_field::Add(g1, gkr_field::Mul(u1, e1));
                // g(2) from the linear extensions: (2u1−u0)·(2e1−e0).
                const Fp2 u2 = gkr_field::Sub(gkr_field::Mul(u1, Fp2::FromFp(2)), u0);
                const Fp2 e2 = gkr_field::Sub(gkr_field::Mul(e1, Fp2::FromFp(2)), e0);
                g2 = gkr_field::Add(g2, gkr_field::Mul(u2, e2));
            }
        }
        // Round-sum repair: expected − (g(0)+g(1)) is zero for a valid
        // assignment; nonzero deltas are refused (or, test-only, folded into
        // g(0) so the round identity holds by construction).
        const Fp2 delta = gkr_field::Sub(expected, gkr_field::Add(g0, g1));
        if (!gkr_field::IsZero(delta)) {
            if (!repair_invalid) {
                res.note = "claims disagree with columns";
                return res;
            }
            g0 = gkr_field::Add(g0, delta);
        }
        RCGkrEvalSumcheckRound msg{g0, g1, g2};
        fs.AbsorbFp2(msg.g0);
        fs.AbsorbFp2(msg.g1);
        fs.AbsorbFp2(msg.g2);
        const Fp2 r_t = fs.ChallengeFp2("eqopen_r");
        res.r.push_back(r_t);
        expected = EvalDeg2(g0, g1, g2, r_t);
        for (size_t s = 0; s < n_slots; ++s) {
            std::vector<Fp2> nu_tab(U[s].size() / 2), ne_tab(E[s].size() / 2);
            for (size_t i = 0; i < nu_tab.size(); ++i) {
                const Fp2 om = gkr_field::Sub(Fp2::One(), r_t);
                nu_tab[i] = gkr_field::Add(gkr_field::Mul(U[s][2 * i], om),
                                           gkr_field::Mul(U[s][2 * i + 1], r_t));
                ne_tab[i] = gkr_field::Add(gkr_field::Mul(E[s][2 * i], om),
                                           gkr_field::Mul(E[s][2 * i + 1], r_t));
            }
            U[s] = std::move(nu_tab);
            E[s] = std::move(ne_tab);
        }
        res.proof.rounds.push_back(msg);
    }

    // Chain end: residual ũ_c(r) per slot (U tables are fully folded).
    res.proof.column_at_r.resize(n_slots);
    for (size_t s = 0; s < n_slots; ++s) res.proof.column_at_r[s] = U[s][0];

    // Chain-end repair (test-only): solve the final identity for ONE residual
    // so Σ_s ũ_s·E_s(r) equals the (shift-repaired) expected value.
    Fp2 total = Fp2::Zero();
    for (size_t s = 0; s < n_slots; ++s)
        total = gkr_field::Add(total, gkr_field::Mul(res.proof.column_at_r[s], E[s][0]));
    const Fp2 final_delta = gkr_field::Sub(expected, total);
    if (!gkr_field::IsZero(final_delta)) {
        if (!repair_invalid) {
            res.note = "claims disagree with columns";
            return res;
        }
        size_t s_fix = n_slots;
        for (size_t s = 0; s < n_slots; ++s) {
            if (!gkr_field::IsZero(E[s][0])) {
                s_fix = s;
                break;
            }
        }
        if (s_fix == n_slots) {
            res.note = "eqopen:unrepairable (all eq-weights vanish at r)";
            return res;
        }
        res.proof.column_at_r[s_fix] = gkr_field::Add(
            res.proof.column_at_r[s_fix], gkr_field::Div(final_delta, E[s_fix][0]));
    }
    // Bind the residuals into the transcript; the digest seeds Stage 2 (μ).
    for (size_t s = 0; s < n_slots; ++s) {
        fs.AbsorbU32(slot_column[s]);
        fs.AbsorbFp2(res.proof.column_at_r[s]);
    }
    res.bind_digest = fs.Digest();

    res.reduced.clear();
    res.reduced.reserve(n_slots);
    for (size_t s = 0; s < n_slots; ++s) {
        res.reduced.push_back(RCGkrOpeningClaim{slot_column[s], res.r, res.proof.column_at_r[s]});
    }
    res.ok = true;
    res.note = "ok";
    return res;
}

} // namespace

RCGkrEvalOpenProveResult EvalOpenProve(const std::vector<RCGkrOpeningClaim>& claims,
                                       const std::vector<std::vector<Fp2>>& columns, uint32_t nu,
                                       const uint256& fs_seed)
{
    return EvalOpenProveCore(claims, columns, nu, fs_seed, /*repair_invalid=*/false);
}

bool EvalOpenVerify(const std::vector<RCGkrOpeningClaim>& claims, uint32_t nu,
                    const RCGkrEvalOpenProof& proof, const uint256& fs_seed,
                    std::vector<RCGkrOpeningClaim>* out_reduced, uint256* out_bind_digest,
                    std::string* why)
{
    auto fail = [&](const char* m) {
        if (why) *why = m;
        return false;
    };
    if (proof.version != kRCGkrEvalOpenVersion) return fail("eqopen:version");
    if (nu > kRCFriMaxColumnLog2) return fail("eqopen:nu_too_large");
    if (proof.rounds.size() != nu) return fail("eqopen:round_count");
    // Column-range/point-cover checks against real lengths are the caller's
    // duty (BatchedOpeningVerify checks batch.column_len); here only shape.
    if (const char* bad = ValidateOpenClaims(claims, nu, /*n_columns=*/UINT32_MAX, nullptr)) {
        return fail(bad);
    }

    std::vector<size_t> slot_of_claim;
    std::vector<uint32_t> slot_column;
    BuildSlots(claims, slot_of_claim, slot_column);
    if (proof.column_at_r.size() != slot_column.size()) return fail("eqopen:residual_count");

    EqOpenFs fs(kEqOpenDomainTag);
    AbsorbOpenStatement(fs, claims, fs_seed, nu);
    const Fp2 gamma = fs.ChallengeFp2("eqopen_gamma");

    // Claimed total S = Σ_m γ^m·y_m (recomputed — never carried).
    Fp2 gamma_pow = Fp2::One();
    Fp2 expected = Fp2::Zero();
    std::vector<Fp2> gamma_pows(claims.size());
    for (size_t m = 0; m < claims.size(); ++m) {
        gamma_pows[m] = gamma_pow;
        expected = gkr_field::Add(expected, gkr_field::Mul(gamma_pow, claims[m].value));
        gamma_pow = gkr_field::Mul(gamma_pow, gamma);
    }

    // Round-sum chain replay.
    std::vector<Fp2> r;
    r.reserve(nu);
    for (uint32_t round = 0; round < nu; ++round) {
        const RCGkrEvalSumcheckRound& msg = proof.rounds[round];
        if (!gkr_field::Eq(gkr_field::Add(msg.g0, msg.g1), expected)) {
            return fail("eqopen:round_sum");
        }
        fs.AbsorbFp2(msg.g0);
        fs.AbsorbFp2(msg.g1);
        fs.AbsorbFp2(msg.g2);
        const Fp2 r_t = fs.ChallengeFp2("eqopen_r");
        r.push_back(r_t);
        expected = EvalDeg2(msg.g0, msg.g1, msg.g2, r_t);
    }

    // Chain end vs native O(M·ν) eq evaluations of the batched eq-weights.
    std::vector<Fp2> eq_slot(slot_column.size(), Fp2::Zero());
    for (size_t m = 0; m < claims.size(); ++m) {
        const Fp2 w = gkr_field::Mul(gamma_pows[m], RCGkrEqAt(PointExtend(claims[m].point, nu), r));
        eq_slot[slot_of_claim[m]] = gkr_field::Add(eq_slot[slot_of_claim[m]], w);
    }
    Fp2 total = Fp2::Zero();
    for (size_t s = 0; s < slot_column.size(); ++s) {
        total = gkr_field::Add(total, gkr_field::Mul(proof.column_at_r[s], eq_slot[s]));
    }
    if (!gkr_field::Eq(total, expected)) return fail("eqopen:final");

    // Emit reduced claims + the Stage-2 seed.
    for (size_t s = 0; s < slot_column.size(); ++s) {
        fs.AbsorbU32(slot_column[s]);
        fs.AbsorbFp2(proof.column_at_r[s]);
    }
    if (out_bind_digest != nullptr) *out_bind_digest = fs.Digest();
    if (out_reduced != nullptr) {
        out_reduced->clear();
        out_reduced->reserve(slot_column.size());
        for (size_t s = 0; s < slot_column.size(); ++s) {
            out_reduced->push_back(RCGkrOpeningClaim{slot_column[s], r, proof.column_at_r[s]});
        }
    }
    return true;
}

namespace {

/** Shared Construction I assembly (valid path and the test-only
 *  invalid-assignment path differ ONLY in the Stage-1 core flag). */
RCGkrBatchedOpeningProveResult BatchedOpeningProveCore(
    const std::vector<RCGkrOpeningClaim>& claims, const std::vector<std::vector<Fp2>>& columns,
    const uint256& fs_seed, bool repair_invalid)
{
    RCGkrBatchedOpeningProveResult res;
    if (columns.empty()) {
        res.note = "constr1:no_columns";
        return res;
    }
    if (columns.size() + 2 > kRCFriBatchMaxColumns) {
        res.note = "constr1:too_many_columns";
        return res;
    }
    size_t max_len = 0;
    for (const auto& col : columns) {
        if (col.empty()) {
            res.note = "constr1:empty_column";
            return res;
        }
        max_len = std::max(max_len, col.size());
    }
    const uint32_t batch_n = FriNextPow2(static_cast<uint32_t>(max_len));
    const uint32_t nu = Log2Pow2(batch_n);

    // Epoch-1 roots → γ seed (commit-then-challenge: γ depends on every root).
    std::vector<unsigned char> seed_buf;
    seed_buf.insert(seed_buf.end(), fs_seed.begin(), fs_seed.end());
    seed_buf.insert(seed_buf.end(), kConstrIDomainTag,
                    kConstrIDomainTag + std::strlen(kConstrIDomainTag));
    AppendLE32(seed_buf, batch_n);
    AppendLE32(seed_buf, static_cast<uint32_t>(columns.size()));
    for (const auto& col : columns) {
        const uint256 root = FriBatchColumnRoot(col, batch_n);
        seed_buf.insert(seed_buf.end(), root.begin(), root.end());
    }
    const uint256 gamma_seed = Sha256dOf(seed_buf);

    // Stage 1: γ-batched eq-kernel summation-reduction.
    RCGkrEvalOpenProveResult open =
        EvalOpenProveCore(claims, columns, nu, gamma_seed, repair_invalid);
    if (!open.ok) {
        res.note = "constr1:" + open.note;
        return res;
    }
    res.proof.sumcheck = open.proof;

    // Stage 2: aggregated opening of the reduced claims; f/g join the batch.
    const auto ev = EvalArgumentProve(open.reduced, columns, open.bind_digest);
    if (!ev.ok) {
        res.note = "constr1:eval_prove:" + ev.note;
        return res;
    }
    res.proof.eval = ev.proof;
    std::vector<std::vector<Fp2>> all = columns;
    all.push_back(ev.f_coeffs);
    all.push_back(ev.g_coeffs);

    const auto bc = FriBatchCommit(all, fs_seed);
    if (!bc.ok) {
        res.note = "constr1:batch:" + bc.note;
        return res;
    }
    if (bc.proof.n_coeffs != batch_n) {
        res.note = "constr1:batch_n_mismatch";
        return res;
    }
    res.proof.version = kRCGkrConstructionIVersion;
    res.proof.batch = bc.proof;
    res.ok = true;
    res.note = "ok";
    return res;
}

} // namespace

RCGkrBatchedOpeningProveResult BatchedOpeningProve(const std::vector<RCGkrOpeningClaim>& claims,
                                                   const std::vector<std::vector<Fp2>>& columns,
                                                   const uint256& fs_seed)
{
    return BatchedOpeningProveCore(claims, columns, fs_seed, /*repair_invalid=*/false);
}

RCGkrBatchedOpeningProveResult BatchedOpeningProveInvalidAssignmentForTest(
    const std::vector<RCGkrOpeningClaim>& claims, const std::vector<std::vector<Fp2>>& columns,
    const uint256& fs_seed)
{
    return BatchedOpeningProveCore(claims, columns, fs_seed, /*repair_invalid=*/true);
}

bool BatchedOpeningVerify(const std::vector<RCGkrOpeningClaim>& claims,
                          const RCGkrBatchedOpeningProof& proof, const uint256& fs_seed,
                          std::string* why)
{
    auto fail = [&](const std::string& m) {
        if (why) *why = m;
        return false;
    };
    if (proof.version != kRCGkrConstructionIVersion) return fail("constr1:version");

    // Shape: exactly two Stage-2 columns (f,g) after the epoch-1 columns.
    const size_t n_cols = proof.batch.columns.size();
    if (n_cols < 3) return fail("constr1:too_few_columns");
    const uint32_t n_epoch1 = static_cast<uint32_t>(n_cols - 2);
    if (proof.eval.f_column != n_epoch1 || proof.eval.g_column != n_epoch1 + 1) {
        return fail("constr1:fg_columns");
    }
    const uint32_t batch_n = proof.batch.n_coeffs;
    if (batch_n == 0 || (batch_n & (batch_n - 1)) != 0) return fail("constr1:batch_n");
    const uint32_t nu = Log2Pow2(batch_n);
    if (proof.batch.column_len.size() != n_cols) return fail("constr1:column_len_shape");

    // Claims must target epoch-1 columns, and each point must cover the
    // column's logical length (the zero-extension sub-cube identity).
    for (const auto& c : claims) {
        if (c.column_id >= n_epoch1) return fail("constr1:claim_col_range");
        if (c.point.size() > nu) return fail("constr1:claim_point_dim");
        const uint64_t cover = uint64_t{1} << std::min<size_t>(c.point.size(), 63);
        if (cover < proof.batch.column_len[c.column_id]) return fail("constr1:claim_point_short");
    }

    // (1) Bind roots + dual-OOD evaluations FIRST (Theorem 2.1).
    std::string sub;
    if (!FriBatchVerify(proof.batch, fs_seed, &sub)) return fail("constr1:batch:" + sub);

    // (2) Recompute the γ seed from the AUTHENTICATED epoch-1 roots.
    std::vector<unsigned char> seed_buf;
    seed_buf.insert(seed_buf.end(), fs_seed.begin(), fs_seed.end());
    seed_buf.insert(seed_buf.end(), kConstrIDomainTag,
                    kConstrIDomainTag + std::strlen(kConstrIDomainTag));
    AppendLE32(seed_buf, batch_n);
    AppendLE32(seed_buf, n_epoch1);
    for (uint32_t i = 0; i < n_epoch1; ++i) {
        seed_buf.insert(seed_buf.end(), proof.batch.columns[i].root.begin(),
                        proof.batch.columns[i].root.end());
    }
    const uint256 gamma_seed = Sha256dOf(seed_buf);

    // (3) Stage-1 replay → reduced claims + Stage-2 seed.
    std::vector<RCGkrOpeningClaim> reduced;
    uint256 bind_digest;
    if (!EvalOpenVerify(claims, nu, proof.sumcheck, gamma_seed, &reduced, &bind_digest, &sub)) {
        return fail(sub);
    }

    // (4) Stage-2 root binding of the residuals (Theorem 2.2).
    if (!EvalArgumentVerify(reduced, proof.batch, proof.eval, bind_digest, &sub)) {
        return fail(sub);
    }
    return true;
}

} // namespace matmul::v4::rc
