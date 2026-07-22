// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_gkr_coupled.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_extract.h>
#include <matmul/matmul_v4_rc_gkr_air.h>
#include <span.h>

#include <array>
#include <cassert>
#include <chrono>
#include <cstring>
#include <string>
#include <vector>

// ============================================================================
// Relation (5) implementation — see the construction note in the header.
//
// SOLE AUTHORITY: RecomputeCoupledPuzzleReference (immutable int64 reference).
// This file derives its coupled-v7 wires from the exported reference transcript
// so rows_per_lobe, V3 transcript tags, full-bank scheduling, uint64-wrap mix,
// material-exchange rounds, bank_root and barrier_roots all stay byte-identical
// to the path checked by consensus. The int64 reference itself is untouched.
//
// The FS/transcript helpers below intentionally duplicate the (anonymous-
// namespace) episode helpers of matmul_v4_rc_gkr.cpp byte-for-byte so this
// file stays conflict-free with the episode/succinctness work. DerivePowBind
// MUST keep the same tag as the episode path ("BTX_RC_GKR_POW_BIND_V4").
// ============================================================================

namespace matmul::v4::rc {
namespace {

using gkr_field::Add;
using gkr_field::Canonical;
using gkr_field::Eq;
using gkr_field::FromChallengeBytes2;
using gkr_field::FromSigned2;
using gkr_field::Inv;
using gkr_field::Mul;
using gkr_field::Sub;

namespace lt = matmul::v4::lt;

// ---------------------------------------------------------------------------
// Byte / hash helpers (mirror matmul_v4_rc_gkr.cpp anonymous namespace).
// ---------------------------------------------------------------------------

uint256 Sha256dBytes(const unsigned char* data, size_t len)
{
    uint8_t d1[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(data, len).Finalize(d1);
    uint8_t d2[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(d1, sizeof(d1)).Finalize(d2);
    uint256 out;
    std::memcpy(out.data(), d2, 32);
    return out;
}

uint256 DeriveTagged(const uint256& seed, const char* tag)
{
    std::vector<unsigned char> buf;
    const size_t n = std::strlen(tag);
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(tag),
               reinterpret_cast<const unsigned char*>(tag) + n);
    buf.insert(buf.end(), seed.begin(), seed.end());
    return Sha256dBytes(buf.data(), buf.size());
}

/** MUST match the episode path tag (matmul_v4_rc_gkr.cpp DerivePowBind). */
uint256 DerivePowBind(const uint256& claimed_digest)
{
    return DeriveTagged(claimed_digest, "BTX_RC_GKR_POW_BIND_V4");
}

void AppendLE32(std::vector<unsigned char>& buf, uint32_t v)
{
    unsigned char b[4];
    WriteLE32(b, v);
    buf.insert(buf.end(), b, b + 4);
}
void AppendLE64(std::vector<unsigned char>& buf, uint64_t v)
{
    unsigned char b[8];
    WriteLE64(b, v);
    buf.insert(buf.end(), b, b + 8);
}
void AppendFp2(std::vector<unsigned char>& buf, const Fp2& v)
{
    AppendLE64(buf, Canonical(v.c0));
    AppendLE64(buf, Canonical(v.c1));
}
void AppendBytes(std::vector<unsigned char>& buf, const unsigned char* p, size_t n)
{
    buf.insert(buf.end(), p, p + n);
}

class FsTranscript {
public:
    explicit FsTranscript(const char* domain)
    {
        const size_t n = std::strlen(domain);
        m_buf.insert(m_buf.end(), reinterpret_cast<const unsigned char*>(domain),
                     reinterpret_cast<const unsigned char*>(domain) + n);
    }
    void AbsorbBytes(const unsigned char* p, size_t n) { AppendBytes(m_buf, p, n); }
    void AbsorbU32(uint32_t v) { AppendLE32(m_buf, v); }
    void AbsorbFp2(const Fp2& v) { AppendFp2(m_buf, v); }
    void AbsorbUint256(const uint256& h) { AppendBytes(m_buf, h.data(), 32); }
    uint256 Challenge(const char* label)
    {
        AbsorbBytes(reinterpret_cast<const unsigned char*>(label), std::strlen(label));
        const uint256 h = Sha256dBytes(m_buf.data(), m_buf.size());
        AbsorbUint256(h);
        return h;
    }
    Fp2 ChallengeFp2(const char* label) { return FromChallengeBytes2(Challenge(label).data()); }
    [[nodiscard]] uint256 Digest() const { return Sha256dBytes(m_buf.data(), m_buf.size()); }

private:
    std::vector<unsigned char> m_buf;
};

uint32_t Log2Exact(uint32_t n)
{
    assert(n > 0 && (n & (n - 1)) == 0);
    uint32_t l = 0;
    while ((1u << l) < n) ++l;
    return l;
}

Fp2 EvalEqBit(const Fp2& r, uint32_t bit) { return bit ? r : Sub(Fp2::One(), r); }

Fp2 EqFactor(const std::vector<Fp2>& r, uint32_t index)
{
    Fp2 acc = Fp2::One();
    for (size_t i = 0; i < r.size(); ++i) acc = Mul(acc, EvalEqBit(r[i], (index >> i) & 1u));
    return acc;
}

Fp2 EvalDeg2(const Fp2& g0, const Fp2& g1, const Fp2& g2, const Fp2& x)
{
    const Fp2 inv2 = Inv(Fp2::FromFp(2));
    return Add(Add(Mul(Mul(g0, Mul(Sub(Fp2::One(), x), Sub(Fp2::FromFp(2), x))), inv2),
                   Mul(g1, Mul(x, Sub(Fp2::FromFp(2), x)))),
               Mul(Mul(g2, Mul(x, Sub(x, Fp2::One()))), inv2));
}

/** Thaler product sumcheck over the k-dimension (mirror of the episode path). */
std::vector<RCGkrSumcheckRound> ProveProductK(const std::vector<Fp2>& A, uint32_t m,
                                              uint32_t k_dim, const std::vector<Fp2>& B,
                                              uint32_t n, const std::vector<Fp2>& ri,
                                              const std::vector<Fp2>& rj, const Fp2& claim,
                                              FsTranscript& fs, std::vector<Fp2>& out_r,
                                              Fp2& out_final)
{
    const uint32_t k_pad = RCGkrNextPow2(k_dim);
    const std::vector<Fp2> wi = RCGkrEqKernelCoeffs(ri);
    const std::vector<Fp2> wj = RCGkrEqKernelCoeffs(rj);
    std::vector<Fp2> ah(k_pad, Fp2::Zero()), bh(k_pad, Fp2::Zero());
    for (uint32_t t = 0; t < k_dim; ++t) {
        Fp2 sa = Fp2::Zero(), sb = Fp2::Zero();
        for (uint32_t i = 0; i < m; ++i)
            sa = Add(sa, Mul(wi[i], A[static_cast<size_t>(i) * k_dim + t]));
        for (uint32_t j = 0; j < n; ++j)
            sb = Add(sb, Mul(B[static_cast<size_t>(t) * n + j], wj[j]));
        ah[t] = sa;
        bh[t] = sb;
    }
    std::vector<RCGkrSumcheckRound> rounds;
    out_r.clear();
    const uint32_t nu = Log2Exact(k_pad);
    std::vector<Fp2> ca = ah, cb = bh;
    for (uint32_t round = 0; round < nu; ++round) {
        Fp2 g0 = Fp2::Zero(), g1 = Fp2::Zero(), g2 = Fp2::Zero();
        for (size_t idx = 0; idx < ca.size(); idx += 2) {
            const Fp2 a0 = ca[idx], a1 = ca[idx + 1];
            const Fp2 b0 = cb[idx], b1 = cb[idx + 1];
            g0 = Add(g0, Mul(a0, b0));
            g1 = Add(g1, Mul(a1, b1));
            const Fp2 a2 = Sub(Mul(a1, Fp2::FromFp(2)), a0);
            const Fp2 b2 = Sub(Mul(b1, Fp2::FromFp(2)), b0);
            g2 = Add(g2, Mul(a2, b2));
        }
        RCGkrSumcheckRound msg{g0, g1, g2};
        fs.AbsorbFp2(msg.eval0);
        fs.AbsorbFp2(msg.eval1);
        fs.AbsorbFp2(msg.eval2);
        const Fp2 r = fs.ChallengeFp2("prod_sumcheck_r");
        out_r.push_back(r);
        std::vector<Fp2> na(ca.size() / 2), nb(cb.size() / 2);
        for (size_t i = 0; i < na.size(); ++i) {
            na[i] = Add(Mul(ca[2 * i], Sub(Fp2::One(), r)), Mul(ca[2 * i + 1], r));
            nb[i] = Add(Mul(cb[2 * i], Sub(Fp2::One(), r)), Mul(cb[2 * i + 1], r));
        }
        ca = std::move(na);
        cb = std::move(nb);
        rounds.push_back(msg);
    }
    (void)claim;
    out_final = (ca.empty() || cb.empty()) ? Fp2::Zero() : Mul(ca[0], cb[0]);
    return rounds;
}

bool VerifyProductK(const std::vector<RCGkrSumcheckRound>& rounds, const Fp2& claim,
                    FsTranscript& fs, std::vector<Fp2>& out_r, Fp2& out_final)
{
    Fp2 expected = claim;
    out_r.clear();
    for (const auto& m : rounds) {
        if (!Eq(Add(m.eval0, m.eval1), expected)) return false;
        fs.AbsorbFp2(m.eval0);
        fs.AbsorbFp2(m.eval1);
        fs.AbsorbFp2(m.eval2);
        const Fp2 r = fs.ChallengeFp2("prod_sumcheck_r");
        out_r.push_back(r);
        expected = EvalDeg2(m.eval0, m.eval1, m.eval2, r);
    }
    out_final = expected;
    return true;
}

Fp2 MleEval1D2Raw(const Fp2* vals, size_t vals_len, const std::vector<Fp2>& r)
{
    if (r.empty()) return vals_len == 0 ? Fp2::Zero() : vals[0];
    if (r.size() >= 31) return Fp2::Zero();
    const size_t n = size_t{1} << r.size();
    std::vector<Fp2> cur(n, Fp2::Zero());
    const size_t copy_n = std::min(vals_len, n);
    for (size_t i = 0; i < copy_n; ++i) cur[i] = vals[i];
    size_t len = n;
    for (size_t b = 0; b < r.size(); ++b) {
        const Fp2 one_minus = Sub(Fp2::One(), r[b]);
        const Fp2& rb = r[b];
        for (size_t i = 0; i < len / 2; ++i) {
            cur[i] = Add(Mul(cur[2 * i], one_minus), Mul(cur[2 * i + 1], rb));
        }
        len >>= 1;
    }
    return cur[0];
}

Fp2 MleEvalMatrix(const std::vector<Fp2>& mat, uint32_t rows, uint32_t cols,
                  const std::vector<Fp2>& r_row, const std::vector<Fp2>& r_col)
{
    if (rows == 0 || cols == 0 || mat.empty()) return Fp2::Zero();
    std::vector<Fp2> row_evals(rows, Fp2::Zero());
    for (uint32_t i = 0; i < rows; ++i) {
        const size_t off = static_cast<size_t>(i) * cols;
        const size_t end = std::min(off + cols, mat.size());
        if (off >= end) break;
        row_evals[i] = MleEval1D2Raw(mat.data() + off, end - off, r_col);
    }
    return MleEval1D2Raw(row_evals.data(), row_evals.size(), r_row);
}

Fp2 MleEvalI8MatrixSegment(const std::vector<int8_t>& v, size_t off0, uint32_t rows,
                           uint32_t cols, const std::vector<Fp2>& r_row,
                           const std::vector<Fp2>& r_col)
{
    if (rows == 0 || cols == 0 || off0 >= v.size()) return Fp2::Zero();
    std::vector<Fp2> row_evals(rows, Fp2::Zero());
    std::vector<Fp2> row(cols, Fp2::Zero());
    for (uint32_t i = 0; i < rows; ++i) {
        const size_t off = off0 + static_cast<size_t>(i) * cols;
        if (off >= v.size()) break;
        const size_t n = std::min(static_cast<size_t>(cols), v.size() - off);
        for (size_t j = 0; j < n; ++j) row[j] = FromSigned2(v[off + j]);
        for (size_t j = n; j < cols; ++j) row[j] = Fp2::Zero();
        row_evals[i] = MleEval1D2Raw(row.data(), row.size(), r_col);
    }
    return MleEval1D2Raw(row_evals.data(), row_evals.size(), r_row);
}

std::vector<Fp2> ToFp2I8(const std::vector<int8_t>& v)
{
    std::vector<Fp2> o(v.size());
    for (size_t i = 0; i < v.size(); ++i) o[i] = FromSigned2(v[i]);
    return o;
}
std::vector<Fp2> ToFp2I64(const std::vector<int64_t>& v)
{
    std::vector<Fp2> o(v.size());
    for (size_t i = 0; i < v.size(); ++i) o[i] = FromSigned2(v[i]);
    return o;
}

/** Little-endian point layout: low coords first, zero-extended to ν (padding
 *  selects the length-preserving subcube of a zero-padded column, §1.3). */
std::vector<Fp2> PointConcatExtend(const std::vector<Fp2>& low, const std::vector<Fp2>& high,
                                   uint32_t nu)
{
    std::vector<Fp2> p;
    p.reserve(nu);
    p.insert(p.end(), low.begin(), low.end());
    p.insert(p.end(), high.begin(), high.end());
    while (p.size() < nu) p.push_back(Fp2::Zero());
    return p;
}

// ---------------------------------------------------------------------------
// LOCAL MIRRORS of the coupled reference's private stages. Divergence from the
// reference is impossible to exploit: it changes barrier roots → digest, which
// is checked against the exported RecomputeCoupledPuzzleReference.
// ---------------------------------------------------------------------------

void ApplyBalancedPermutationLocal(std::vector<int64_t>& s, const std::vector<uint32_t>& pi)
{
    std::vector<int64_t> tmp(s.size());
    for (uint32_t i = 0; i < static_cast<uint32_t>(s.size()); ++i) tmp[pi[i]] = s[i];
    s = std::move(tmp);
}

std::vector<Fp2> ProofFriendlyPermutationInversePoint(const uint256& sigma, uint32_t barrier,
                                                      const RCCoupParams& params,
                                                      uint32_t transcript_version,
                                                      const std::vector<Fp2>& dst_point)
{
    const auto spec =
        DeriveCoupledProofFriendlyPermutationSpec(sigma, barrier, params, transcript_version);
    if (spec.n == 0 || spec.bits != dst_point.size() ||
        spec.out_to_in_bit.size() != spec.bits || spec.xor_mask_bit.size() != spec.bits) {
        return {};
    }
    std::vector<Fp2> src_point(spec.bits, Fp2::Zero());
    for (uint32_t out_bit = 0; out_bit < spec.bits; ++out_bit) {
        const uint32_t in_bit = spec.out_to_in_bit[out_bit];
        src_point[in_bit] = spec.xor_mask_bit[out_bit] != 0
                                ? Sub(Fp2::One(), dst_point[out_bit])
                                : dst_point[out_bit];
    }
    return src_point;
}

bool SameCoupledParams(const RCCoupParams& a, const RCCoupParams& b)
{
    return a.barriers == b.barriers && a.lobes == b.lobes && a.lobe_width == b.lobe_width &&
           a.bank_pages == b.bank_pages && a.rows_per_lobe == b.rows_per_lobe &&
           a.pages_per_barrier_lobe == b.pages_per_barrier_lobe;
}

/** Proof-only option resolver. Consensus uses ResolveRCCoupOptions(params);
 *  this helper gives standalone proof tests the same V3 domains for the two
 *  canonical V3 shapes without requiring Consensus::Params at this API boundary. */
RCCoupOptions CoupledProofOptionsForParams(const RCCoupParams& p)
{
    if (SameCoupledParams(p, MakeProductionV3RCCoupParams())) return MakeV3RCCoupOptions();
    if (SameCoupledParams(p, MakeMediumV3RCCoupParams())) return MakeMediumV3RCCoupOptions();
    return RCCoupOptions{};
}

// ---------------------------------------------------------------------------
// Coupled trace wires (native reference transcript; the grounding oracle).
// ---------------------------------------------------------------------------

struct CoupledLobeWire {
    uint32_t barrier{0};
    uint32_t lobe{0};
    /** Λ_coup output — the natively scheduled page (never prover data). */
    uint32_t page_id{0};
    std::vector<Fp2> A; // M×W state slice (feed-forward wired)
    std::vector<Fp2> B; // W×W folded bank page sum (page-selection wired)
    std::vector<Fp2> Y; // M×W int64 GEMM block
};

struct CoupledBarrierWire {
    std::vector<CoupledLobeWire> lobes;
    std::vector<int64_t> exchange;  // pre-perm concat (fixed segment offsets)
    std::vector<int64_t> post_perm; // after public π_b
    std::vector<int64_t> post_mix;  // after butterfly mix
    uint256 extract_prf{};
    std::vector<int8_t> state_out;  // Extract output → feed-forward
    uint256 barrier_root{};
};

struct CoupledWires {
    uint256 sigma{};
    uint256 bank_root{};
    std::vector<CoupledBarrierWire> barriers;
    std::vector<uint256> barrier_roots;
    uint256 digest{};
    bool ok{false};
    std::string note;
};

CoupledWires BuildCoupledWires(const CBlockHeader& header, int32_t height,
                               const RCCoupParams& p, const RCCoupOptions& options)
{
    CoupledWires w;
    if (!ValidateRCCoupParams(p)) {
        w.note = "invalid params";
        return w;
    }
    if (options.skip_barrier || options.skip_bank_page) {
        w.note = "proof options include test-only skip hook";
        return w;
    }
    const uint32_t n = p.StateBytes();
    const uint32_t W = p.lobe_width;
    const uint32_t M = p.rows_per_lobe == 0 ? 1 : p.rows_per_lobe;
    const uint32_t lobe_stride = M * W;
    const uint32_t tv = options.transcript_version;
    w.sigma = matmul::v4::DeriveSigma(header);

    RCCoupEpisodeTranscript tx;
    w.digest = RecomputeCoupledPuzzleReference(header, height, p, options, {}, nullptr, &tx);
    if (w.digest.IsNull()) {
        w.note = "reference digest";
        return w;
    }
    w.bank_root = tx.bank_root;
    w.barrier_roots = tx.barrier_roots;
    if (w.bank_root.IsNull() || w.barrier_roots.size() != p.barriers) {
        w.note = "reference transcript roots";
        return w;
    }
    if (AssembleCoupledEpisodeDigest(w.bank_root, w.barrier_roots, tv) != w.digest) {
        w.note = "reference transcript digest";
        return w;
    }
    if (tx.extracts.size() != p.barriers) {
        w.note = "reference extract transcript";
        return w;
    }

    w.barriers.resize(p.barriers);
    size_t gi = 0;
    for (uint32_t b = 0; b < p.barriers; ++b) {
        CoupledBarrierWire& bw = w.barriers[b];
        bw.exchange.assign(n, 0);
        bw.lobes.resize(p.lobes);

        // C3.a per-lobe GEMM vs the scheduled page set. The reference transcript
        // records one M×W · W×W partial per page. Fold the B pages and Y partials:
        // A·ΣB_page = Σ(A·B_page), preserving the full schedule with one sumcheck.
        for (uint32_t ell = 0; ell < p.lobes; ++ell) {
            CoupledLobeWire& lw = bw.lobes[ell];
            lw.barrier = b;
            lw.lobe = ell;
            const auto page_ids = SelectCoupledBankPageIds(
                b, ell, p, w.sigma, options.full_bank_schedule, tv);
            if (page_ids.empty()) {
                w.note = "page schedule";
                return w;
            }
            lw.page_id = page_ids.front(); // representative (schedule head)
            std::vector<int64_t> bsum(static_cast<size_t>(W) * W, 0);
            std::vector<int64_t> yacc(static_cast<size_t>(lobe_stride), 0);
            std::vector<int8_t> a_block;
            for (uint32_t page_id : page_ids) {
                if (gi >= tx.gemms.size()) {
                    w.note = "gemm transcript truncated";
                    return w;
                }
                const RCCoupGemmTranscript& gt = tx.gemms[gi++];
                if (gt.barrier != b || gt.lobe != ell || gt.page_id != page_id ||
                    gt.A.size() != static_cast<size_t>(lobe_stride) ||
                    gt.B.size() != static_cast<size_t>(W) * W ||
                    gt.Y.size() != static_cast<size_t>(lobe_stride)) {
                    w.note = "gemm transcript shape/order";
                    return w;
                }
                if (a_block.empty()) {
                    a_block = gt.A;
                } else if (a_block != gt.A) {
                    w.note = "gemm transcript A mismatch";
                    return w;
                }
                for (size_t idx = 0; idx < bsum.size(); ++idx)
                    bsum[idx] += static_cast<int64_t>(gt.B[idx]);
                for (size_t idx = 0; idx < yacc.size(); ++idx) yacc[idx] += gt.Y[idx];
            }
            // C3.a' material exchange: consensus segment_id = lobe index →
            // FIXED offset ℓ·M·W in the exchange column.
            for (uint32_t i = 0; i < lobe_stride; ++i)
                bw.exchange[static_cast<size_t>(ell) * lobe_stride + i] = yacc[i];
            lw.A = ToFp2I8(a_block);
            lw.B = ToFp2I64(bsum);
            lw.Y = ToFp2I64(yacc);
        }
        if (gi > tx.gemms.size()) {
            w.note = "gemm transcript overflow";
            return w;
        }

        // C3.b public balanced permutation.
        const auto pi = DeriveCoupledBalancedPermutation(w.sigma, b, p, tv);
        if (!IsBalancedPermutation(pi, n)) {
            w.note = "perm not balanced";
            return w;
        }
        bw.post_perm = bw.exchange;
        ApplyBalancedPermutationLocal(bw.post_perm, pi);

        // C3.c/C3.d/C3.e: take post-mix/material-exchange, Extract output and
        // barrier root from the exported reference transcript. This keeps V3
        // uint64-wrap + material-exchange rounds byte-identical without a local
        // shadow implementation.
        const RCCoupExtractTranscript& et = tx.extracts[b];
        if (et.barrier != b || et.extract_in.size() != n || et.extract_out.size() != n ||
            et.barrier_root != w.barrier_roots[b]) {
            w.note = "extract transcript shape/order";
            return w;
        }
        bw.post_mix = et.extract_in;
        bw.extract_prf = et.extract_prf;
        bw.state_out = et.extract_out;
        bw.barrier_root = et.barrier_root;
    }
    if (gi != tx.gemms.size()) {
        w.note = "gemm transcript trailing";
        return w;
    }
    w.ok = true;
    return w;
}

/** Λ_coup flat column list (per barrier: L×(A,B,Y) then e,p,x,s). Both prover
 *  and verifier derive this deterministically from the ground-truth wires. */
std::vector<std::vector<Fp2>> BuildCoupledColumns(const CoupledWires& w)
{
    std::vector<std::vector<Fp2>> cols;
    for (const CoupledBarrierWire& bw : w.barriers) {
        for (const CoupledLobeWire& lw : bw.lobes) {
            cols.push_back(lw.A);
            cols.push_back(lw.B);
            cols.push_back(lw.Y);
        }
        cols.push_back(ToFp2I64(bw.exchange));
        cols.push_back(ToFp2I64(bw.post_perm));
        cols.push_back(ToFp2I64(bw.post_mix));
        cols.push_back(ToFp2I8(bw.state_out));
    }
    return cols;
}

/** Column-id helpers for Λ_coup (must match BuildCoupledColumns order). */
struct CoupColIds {
    uint32_t lobes{0};
    uint32_t a(uint32_t b, uint32_t ell) const { return base(b) + 3 * ell; }
    uint32_t bcol(uint32_t b, uint32_t ell) const { return base(b) + 3 * ell + 1; }
    uint32_t y(uint32_t b, uint32_t ell) const { return base(b) + 3 * ell + 2; }
    uint32_t e(uint32_t b) const { return base(b) + 3 * lobes; }
    uint32_t p(uint32_t b) const { return base(b) + 3 * lobes + 1; }
    uint32_t x(uint32_t b) const { return base(b) + 3 * lobes + 2; }
    uint32_t s(uint32_t b) const { return base(b) + 3 * lobes + 3; }

private:
    uint32_t base(uint32_t b) const { return b * (3 * lobes + 4); }
};

/** Dual-α Extract LogUp over a bounded sample of coupled tiles (§5.5/§7.5).
 *  Tile inputs are the grounded post-mix int64 cells; TraceTile re-runs the
 *  immutable reference sub-primitives. */
gkr_air::LogUpVerifyResult CoupledExtractLogUpSample(const CoupledWires& w, Fp2 gamma,
                                                     Fp2 alpha1, Fp2 alpha2,
                                                     uint32_t max_tiles)
{
    gkr_air::TableTM tm_tab;
    gkr_air::TableTX tx_tab;
    gkr_air::LogUpInstance inst_tm, inst_tx;
    uint32_t used = 0;
    for (const CoupledBarrierWire& bw : w.barriers) {
        if (used >= max_tiles) break;
        const uint32_t n_tiles = static_cast<uint32_t>(bw.post_mix.size() / kRCMxBlockLen);
        for (uint32_t t = 0; t < n_tiles && used < max_tiles; ++t) {
            gkr_air::TilePublic pub;
            pub.prf_key = bw.extract_prf;
            pub.i = 0;
            pub.bj = t;
            std::array<int64_t, kRCMxBlockLen> in{};
            for (uint32_t c = 0; c < kRCMxBlockLen; ++c)
                in[c] = bw.post_mix[static_cast<size_t>(t) * kRCMxBlockLen + c];
            const gkr_air::TileWitness tw = gkr_air::TraceTile(pub, in);
            gkr_air::AppendTileLookupsTmTxOnly(tw, tm_tab, tx_tab, gamma, inst_tm, inst_tx);
            ++used;
        }
    }
    auto build_mult = [](gkr_air::LogUpInstance& in) {
        in.table_mult.assign(in.table.size(), 0);
        for (const Fp2& wt : in.witness)
            for (size_t j = 0; j < in.table.size(); ++j)
                if (gkr_field::Eq(wt, in.table[j])) {
                    in.table_mult[j] += 1;
                    break;
                }
    };
    build_mult(inst_tm);
    build_mult(inst_tx);
    std::vector<gkr_air::LogUpInstance> insts{inst_tm, inst_tx};
    return gkr_air::LogUpDualAlphaVerify(insts, alpha1, alpha2);
}

/** FS seed roots list: bank_root FIRST, then all barrier roots — binds the
 *  §7.6 bank commitment before any challenge (count-prefixed downstream). */
std::vector<uint256> SeedRoots(const uint256& bank_root, const std::vector<uint256>& roots)
{
    std::vector<uint256> out;
    out.reserve(roots.size() + 1);
    out.push_back(bank_root);
    out.insert(out.end(), roots.begin(), roots.end());
    return out;
}

size_t EstimateCoupledProofBytes(const RCGkrCoupledProofV7& proof)
{
    std::vector<unsigned char> tmp;
    size_t bytes = SerializeFriBatchProof(proof.batch, tmp);
    bytes += 4;
    bytes += proof.opening_sumcheck.rounds.size() * 3 * 16;
    bytes += proof.opening_sumcheck.column_at_r.size() * 16;
    bytes += 4 + 32 * 5 + 16 + proof.barrier_roots.size() * 32;
    for (const auto& lc : proof.lobes) bytes += lc.sumcheck.size() * 48 + 5 * 16;
    bytes += (proof.perm_evals.size() + proof.mix_evals.size() + proof.feed_evals.size()) * 16;
    bytes += 16 * 3 + 32 + 8; // eval proof sigma/fg + transcript + logup_bits
    return bytes;
}

} // namespace

RCGkrCoupledV7SuccinctnessStatus
AssessCoupledV7Succinctness(const RCCoupParams& params)
{
    return AssessCoupledV7Succinctness(params, CoupledProofOptionsForParams(params));
}

std::vector<RCGkrCoupledV7RelationStatus>
RCGkrCoupledV7RelationStatuses(const RCCoupParams& params, const RCCoupOptions& options)
{
    std::vector<RCGkrCoupledV7RelationStatus> out;
    if (!ValidateRCCoupParams(params)) return out;

    const bool proof_friendly_perm =
        RCCoupUsesProofFriendlyPermutation(options.transcript_version);

    out.push_back({"bank/page PCS",
                   false,
                   true,
                   false,
                   "coupled:bank_root_forged / coupled:column_not_grounded",
                   "Needed: commit canonical packed page chunks under bank_root and prove "
                   "selected page openings plus MxExpand seed AIR; current verifier "
                   "grounds B roots by reference transcript."});
    out.push_back({"full-schedule GEMM",
                   true,
                   true,
                   true,
                   "coupled:sumcheck / coupled:opening:* / coupled:final_eval",
                   "Current: one Thaler product sumcheck per (barrier,lobe) over "
                   "A · sum(page B) = Y, with all openings aggregated by "
                   "Construction-I batched opening proof. Still native-grounded because "
                   "the verifier rebuilds A/B/Y column roots."});
    out.push_back({"fixed-segment material exchange",
                   true,
                   true,
                   true,
                   "coupled:exchange_segment / coupled:opening:*",
                   "Current: exchange opening at fixed segment bits equals the lobe Y "
                   "claim and is batched into the same opening proof. Still "
                   "native-grounded because exchange column root is rebuilt."});
    out.push_back({"feed-forward copy",
                   true,
                   true,
                   true,
                   "coupled:opening:*",
                   "Current: committed state_out segment from barrier b is opened at the same "
                   "random segment point as A for barrier b+1 and both are forced equal by "
                   "Construction-I batched openings. Still native-grounded because the verifier "
                   "rebuilds both column roots from the reference transcript."});
    out.push_back({"permutation",
                   proof_friendly_perm,
                   true,
                   proof_friendly_perm,
                   proof_friendly_perm ? "coupled:opening:*"
                                       : "coupled:perm_eval_forged",
                   proof_friendly_perm
                       ? "ENC_RC_V4 uses a seeded bit-affine permutation. Verifier checks "
                         "p~(r_dst)=e~(pi^{-1}(r_dst)) through committed openings. "
                         "Native column grounding still remains elsewhere."
                       : "V1-V3 Fisher-Yates pi has no cheap MLE evaluator; verifier "
                         "currently scans StateBytes() cells. Production proof-only needs "
                         "ENC_RC_V4-style bit-affine pi or a separate committed pi table "
                         "proof."});
    out.push_back({"V3 material mix",
                   false,
                   true,
                   false,
                   "coupled:mix_eval_forged / coupled:column_not_grounded",
                   "Needed: AIR for uint64-wrap butterfly/exchange rounds with committed "
                   "range/carry columns; current verifier evaluates post-mix from native "
                   "reference transcript."});
    out.push_back({"Extract all tiles",
                   false,
                   true,
                   false,
                   "coupled:logup:*",
                   "Needed: commit full coupled Extract AIR/composition and LogUp "
                   "multiplicity columns for every StateBytes()/32 tile. Current helper "
                   "checks a bounded native sample."});
    out.push_back({"barrier SHA roots",
                   false,
                   true,
                   false,
                   "coupled:barrier_root_forged / coupled:digest_from_roots",
                   "Needed: SHA/tile-tree AIR binding state_out columns to every "
                   "barrier root; current verifier hashes native state bytes."});
    out.push_back({"digest and target closure",
                   false,
                   true,
                   false,
                   "coupled:digest_not_header_bound / coupled:target",
                   "Needed: proof-bound digest_from_roots and target comparison on the "
                   "proof-carried digest. Current verifier checks digest after native "
                   "reference replay."});
    return out;
}

RCGkrCoupledV7SuccinctnessStatus
AssessCoupledV7Succinctness(const RCCoupParams& params, const RCCoupOptions& options)
{
    RCGkrCoupledV7SuccinctnessStatus st;
    st.params_valid = ValidateRCCoupParams(params);
    if (!st.params_valid) {
        st.blockers.push_back("params_invalid");
        st.summary = "coupled v7 NO-GO: invalid coupled params";
        return st;
    }

    const RCCoupParams prod = MakeProductionV3RCCoupParams();
    st.production_v3_shape =
        params.barriers == prod.barriers && params.lobes == prod.lobes &&
        params.lobe_width == prod.lobe_width && params.bank_pages == prod.bank_pages &&
        params.rows_per_lobe == prod.rows_per_lobe &&
        params.pages_per_barrier_lobe == prod.pages_per_barrier_lobe;

    st.state_bytes = params.StateBytes();
    st.packed_bank_bytes = TotalRCCoupPackedBytes(params);
    st.expanded_bank_bytes = TotalRCCoupExpandedBytes(params);
    st.macs_per_nonce = TotalRCCoupMacs(params);
    st.required_extract_tiles = st.state_bytes / kRCMxBlockLen;
    st.current_extract_logup_tile_cap = 16;
    st.proof_friendly_transcript =
        RCCoupUsesProofFriendlyPermutation(options.transcript_version);

    // These are facts about the construction below, not runtime measurements:
    // VerifyWinnerCoupledV7 still calls RecomputeCoupledPuzzleReference() and
    // BuildCoupledWires(), then rebuilds every committed column root from the
    // native wire image. That is sound by grounding, but non-succinct.
    st.verifier_reruns_reference_digest = true;
    st.verifier_rebuilds_native_wires = true;
    st.verifier_rebuilds_column_roots = true;

    // Landed production-direction pieces. These are not sufficient for
    // proof-only consensus while the verifier still rebuilds the witness roots.
    st.full_schedule_gemm_proof_bound = true;
    st.feed_forward_proof_bound = true;
    st.opening_claims_batched = true;

    // The remaining relations are not yet proved by a block-sized proof object.
    st.bank_pages_proof_bound = false;
    st.permutation_proof_bound = st.proof_friendly_transcript;
    st.mix_proof_bound = false;
    st.extract_all_tiles_proof_bound = false;
    st.barrier_roots_proof_bound = false;
    st.digest_target_proof_bound = false;
    st.under_stage_i_budget = false;

    if (st.verifier_reruns_reference_digest)
        st.blockers.push_back("native_reference_digest_replay");
    if (st.verifier_rebuilds_native_wires)
        st.blockers.push_back("native_wire_regeneration");
    if (st.verifier_rebuilds_column_roots)
        st.blockers.push_back("native_column_root_rebuild");
    if (!st.bank_pages_proof_bound)
        st.blockers.push_back("bank_pages_not_pcs_bound_under_bank_root");
    if (!st.permutation_proof_bound)
        st.blockers.push_back("permutation_requires_proof_friendly_transcript");
    if (!st.mix_proof_bound)
        st.blockers.push_back("mix_not_succinctly_proven");
    if (!st.extract_all_tiles_proof_bound)
        st.blockers.push_back("extract_all_tiles_not_proof_bound");
    if (!st.barrier_roots_proof_bound)
        st.blockers.push_back("barrier_roots_sha_not_in_circuit");
    if (!st.digest_target_proof_bound)
        st.blockers.push_back("digest_target_not_proof_only_bound");
    if (!st.under_stage_i_budget)
        st.blockers.push_back("production_stage_i_budget_unproven");

    st.genuinely_succinct = st.blockers.empty();
    st.summary = st.genuinely_succinct
                     ? "coupled v7 GO: block-sized proof-only verifier"
                     : ("coupled v7 NO-GO: " + std::to_string(st.blockers.size()) +
                        " succinctness blockers; first=" + st.blockers.front());
    return st;
}

bool RCGkrCoupledV7ReadyForProofOnlyConsensus(const RCCoupParams& params, std::string* why)
{
    const RCGkrCoupledV7SuccinctnessStatus st = AssessCoupledV7Succinctness(params);
    if (why) *why = st.summary;
    return st.genuinely_succinct;
}

// ============================================================================
// Prover.
// ============================================================================

RCGkrCoupledProveResultV7 ProveWinnerCoupledV7(const CBlockHeader& header, int32_t height,
                                               const RCCoupParams& params,
                                               const arith_uint256& target,
                                               const uint256& claimed_digest,
                                               const RCCoupOptions& options)
{
    RCGkrCoupledProveResultV7 res;
    RCGkrCoupledProofV7& proof = res.proof;
    const auto t0 = std::chrono::steady_clock::now();

    if (!ValidateRCCoupParams(params)) {
        res.timing.note = "invalid coupled params";
        return res;
    }

    CoupledWires wires = BuildCoupledWires(header, height, params, options);
    if (!wires.ok) {
        res.timing.note = "wires: " + wires.note;
        return res;
    }

    // SOLE AUTHORITY: the immutable int64 coupled reference transcript. Refuse
    // to prove anything else — this is what makes toy/unrelated-work proofs
    // impossible. BuildCoupledWires already exported the reference digest, so
    // do not replay the entire coupled puzzle a second time.
    const uint256 ref_digest = wires.digest;
    if (claimed_digest.IsNull() || claimed_digest != ref_digest) {
        res.timing.note = "coupled_digest_mismatch_refuses_unrelated_work";
        return res;
    }
    if (UintToArith256(ref_digest) > target) {
        res.timing.note = "coupled digest over target";
        return res;
    }

    proof.version = kRCGkrProofVersionV7;
    proof.params = params;
    proof.options = options;
    proof.height = height;
    proof.claimed_digest = claimed_digest;
    proof.pow_bind = DerivePowBind(claimed_digest);
    proof.sigma = wires.sigma;
    proof.bank_root = wires.bank_root;
    proof.barrier_roots = wires.barrier_roots;

    const uint256 base_seed =
        RCGkrFsSeedV7Coupled(header, height, params, options, target, claimed_digest, wires.sigma,
                             SeedRoots(wires.bank_root, wires.barrier_roots));

    // Λ_coup columns + batch dimensioning.
    std::vector<std::vector<Fp2>> columns = BuildCoupledColumns(wires);
    size_t max_len = 0;
    for (const auto& c : columns) max_len = std::max(max_len, c.size());
    const uint32_t batch_n = FriNextPow2(static_cast<uint32_t>(max_len));
    const uint32_t nu = Log2Exact(batch_n);
    const uint32_t W = params.lobe_width;
    const uint32_t M = params.rows_per_lobe == 0 ? 1 : params.rows_per_lobe;
    const uint32_t n_state = params.StateBytes();
    const uint32_t nu_m = Log2Exact(RCGkrNextPow2(M));
    const uint32_t nu_w = Log2Exact(RCGkrNextPow2(W));
    const uint32_t nu_l = Log2Exact(RCGkrNextPow2(params.lobes));
    const uint32_t nu_n = Log2Exact(RCGkrNextPow2(n_state));
    CoupColIds ids{params.lobes};

    FsTranscript fs(kRCGkrDomainTagV7);
    fs.AbsorbBytes(reinterpret_cast<const unsigned char*>("coupled"), 7);
    fs.AbsorbUint256(base_seed);
    std::vector<RCGkrOpeningClaim> claims;
    proof.lobes.resize(RCGkrCoupledExpectedLobeCount(params));

    for (uint32_t b = 0; b < params.barriers; ++b) {
        for (uint32_t ell = 0; ell < params.lobes; ++ell) {
            const size_t li = static_cast<size_t>(b) * params.lobes + ell;
            const CoupledLobeWire& lw = wires.barriers[b].lobes[ell];
            fs.AbsorbU32(static_cast<uint32_t>(li));
            std::vector<Fp2> ri(nu_m);
            std::vector<Fp2> rj(nu_w);
            for (uint32_t t = 0; t < nu_m; ++t) ri[t] = fs.ChallengeFp2("v7c_ri");
            for (uint32_t t = 0; t < nu_w; ++t) rj[t] = fs.ChallengeFp2("v7c_rj");

            // R5.gemm: m = rows_per_lobe (§7.2) — claim c = Ỹ(ri,rj).
            const Fp2 c_claim = MleEvalMatrix(lw.Y, M, W, ri, rj);
            std::vector<Fp2> rk;
            Fp2 gf;
            RCGkrCoupledLobeClaimV7& lc = proof.lobes[li];
            lc.sumcheck = ProveProductK(lw.A, M, W, lw.B, W, ri, rj, c_claim, fs, rk, gf);
            lc.c_claim = c_claim;
            lc.a_eval = MleEvalMatrix(lw.A, M, W, ri, rk);
            lc.b_eval = MleEvalMatrix(lw.B, W, W, rk, rj);
            lc.final_eval = gf; // == a_eval·b_eval for honest wires
            // R5.exchange: fixed segment ℓ ⇒ ẽ_b(rj, ri, bits(ℓ)) = Ỹ(ri,rj).
            lc.exchange_eval = c_claim;

            claims.push_back({ids.y(b, ell), PointConcatExtend(rj, ri, nu), lc.c_claim});
            claims.push_back({ids.a(b, ell), PointConcatExtend(rk, ri, nu), lc.a_eval});
            claims.push_back({ids.bcol(b, ell), PointConcatExtend(rj, rk, nu), lc.b_eval});
            std::vector<Fp2> seg_bits(nu_l);
            for (uint32_t t = 0; t < nu_l; ++t)
                seg_bits[t] = ((ell >> t) & 1u) ? Fp2::One() : Fp2::Zero();
            std::vector<Fp2> exchange_high = ri;
            exchange_high.insert(exchange_high.end(), seg_bits.begin(), seg_bits.end());
            claims.push_back({ids.e(b), PointConcatExtend(rj, exchange_high, nu),
                              lc.exchange_eval});
        }
    }

    // R5.perm / R5.mix bindings (per barrier). V1–V3 use the legacy
    // Fisher–Yates permutation and therefore compute p̃(r) with an O(n) native
    // weight-MLE. V4 switches to the bit-affine permutation: p̃(r_dst) equals
    // ẽ(r_src) with r_src derived in O(log n), and both openings are bound by
    // the eval argument.
    proof.perm_evals.resize(params.barriers);
    proof.mix_evals.resize(params.barriers);
    for (uint32_t b = 0; b < params.barriers; ++b) {
        const CoupledBarrierWire& bw = wires.barriers[b];
        fs.AbsorbBytes(reinterpret_cast<const unsigned char*>("perm"), 4);
        fs.AbsorbU32(b);
        std::vector<Fp2> rp(nu_n), rm(nu_n);
        for (uint32_t t = 0; t < nu_n; ++t) rp[t] = fs.ChallengeFp2("v7c_rp");
        for (uint32_t t = 0; t < nu_n; ++t) rm[t] = fs.ChallengeFp2("v7c_rm");
        Fp2 vp = Fp2::Zero();
        std::vector<Fp2> src_point;
        if (RCCoupUsesProofFriendlyPermutation(options.transcript_version)) {
            src_point = ProofFriendlyPermutationInversePoint(
                wires.sigma, b, params, options.transcript_version, rp);
            if (src_point.empty()) {
                res.timing.note = "proof-friendly permutation point";
                return res;
            }
            vp = RCGkrMleEval1D2(ToFp2I64(bw.exchange), src_point);
            const Fp2 post_eval = RCGkrMleEval1D2(ToFp2I64(bw.post_perm), rp);
            if (!Eq(post_eval, vp)) {
                res.timing.note = "proof-friendly permutation mirror";
                return res;
            }
        } else {
            const auto pi =
                DeriveCoupledBalancedPermutation(wires.sigma, b, params, options.transcript_version);
            for (uint32_t x = 0; x < n_state; ++x)
                vp = Add(vp, Mul(EqFactor(rp, pi[x]), FromSigned2(bw.exchange[x])));
        }
        const Fp2 vm = RCGkrMleEval1D2(ToFp2I64(bw.post_mix), rm);
        proof.perm_evals[b] = vp;
        proof.mix_evals[b] = vm;
        fs.AbsorbFp2(vp);
        fs.AbsorbFp2(vm);
        claims.push_back({ids.p(b), PointConcatExtend(rp, {}, nu), vp});
        if (!src_point.empty())
            claims.push_back({ids.e(b), PointConcatExtend(src_point, {}, nu), vp});
        claims.push_back({ids.x(b), PointConcatExtend(rm, {}, nu), vm});
    }

    // R5.feed-forward: state_out segment of barrier b is the next barrier's A
    // operand for the same lobe. This is a true succinct copy relation: both
    // sides are committed columns opened at the same verifier-chosen segment
    // point and forced equal by Construction I.
    proof.feed_evals.resize(RCGkrCoupledExpectedFeedCount(params));
    for (uint32_t b = 0; b + 1 < params.barriers; ++b) {
        for (uint32_t ell = 0; ell < params.lobes; ++ell) {
            const size_t fi = static_cast<size_t>(b) * params.lobes + ell;
            fs.AbsorbBytes(reinterpret_cast<const unsigned char*>("feed"), 4);
            fs.AbsorbU32(static_cast<uint32_t>(fi));
            std::vector<Fp2> ri(nu_m);
            std::vector<Fp2> rj(nu_w);
            for (uint32_t t = 0; t < nu_m; ++t) ri[t] = fs.ChallengeFp2("v7c_feed_ri");
            for (uint32_t t = 0; t < nu_w; ++t) rj[t] = fs.ChallengeFp2("v7c_feed_rj");

            const Fp2 next_a =
                MleEvalMatrix(wires.barriers[b + 1].lobes[ell].A, M, W, ri, rj);
            const size_t seg_off = static_cast<size_t>(ell) * M * W;
            const Fp2 prev_s =
                MleEvalI8MatrixSegment(wires.barriers[b].state_out, seg_off, M, W, ri, rj);
            if (!Eq(next_a, prev_s)) {
                res.timing.note = "feed-forward transcript mismatch";
                return res;
            }
            proof.feed_evals[fi] = next_a;
            fs.AbsorbFp2(next_a);

            claims.push_back({ids.a(b + 1, ell), PointConcatExtend(rj, ri, nu), next_a});
            std::vector<Fp2> seg_bits(nu_l);
            for (uint32_t t = 0; t < nu_l; ++t)
                seg_bits[t] = ((ell >> t) & 1u) ? Fp2::One() : Fp2::Zero();
            std::vector<Fp2> state_high = ri;
            state_high.insert(state_high.end(), seg_bits.begin(), seg_bits.end());
            claims.push_back({ids.s(b), PointConcatExtend(rj, state_high, nu), next_a});
        }
    }

    // Construction I: γ-batched MLE opening sumcheck + Stage-2 eval argument
    // inside the SAME batched FRI instance. This is the production-direction
    // opening primitive; it avoids a separate per-claim FRI/eval union.
    const auto opening = BatchedOpeningProve(claims, columns, base_seed);
    if (!opening.ok) {
        res.timing.note = "batched opening prove: " + opening.note;
        return res;
    }
    proof.opening_sumcheck = opening.proof.sumcheck;
    proof.eval = opening.proof.eval;
    proof.batch = opening.proof.batch;

    // Dual-α Extract LogUp over coupled tiles (challenges FS-bound).
    fs.AbsorbBytes(reinterpret_cast<const unsigned char*>("logup"), 5);
    const Fp2 gamma = fs.ChallengeFp2("v7c_gamma");
    proof.logup_alpha1 = fs.ChallengeFp2("v7c_alpha1");
    proof.logup_alpha2 = fs.ChallengeFp2("v7c_alpha2");
    const auto lr = CoupledExtractLogUpSample(wires, gamma, proof.logup_alpha1,
                                              proof.logup_alpha2, /*max_tiles=*/16);
    proof.logup_bits = lr.achieved_bits;

    proof.transcript_hash = fs.Digest();
    proof.over_budget = true;
    proof.note = kRCGkrCoupledV7Statement;

    res.timing.prove_s =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    res.timing.proof_bytes = EstimateCoupledProofBytes(proof);
    res.timing.ok = lr.ok;
    res.timing.over_budget = true; // native grounding — SOUND, not succinct
    res.timing.note = lr.ok ? proof.note : ("logup: " + lr.failure);
    return res;
}

// ============================================================================
// Verifier.
// ============================================================================

bool VerifyWinnerCoupledV7(const RCGkrCoupledProofV7& proof, const CBlockHeader& header,
                           int32_t height, const arith_uint256& target, std::string* why)
{
    auto fail = [&](const std::string& m) {
        if (why) *why = m;
        return false;
    };
    if (proof.version != kRCGkrProofVersionV7) return fail("coupled:version");
    const RCCoupParams& params = proof.params;
    const RCCoupOptions& options = proof.options;
    if (!ValidateRCCoupParams(params)) return fail("coupled:params_invalid");
    if (options.skip_barrier || options.skip_bank_page) return fail("coupled:options_test_hook");
    if (proof.height != height) return fail("coupled:height");

    // §6.1 native: pow_bind, header-bound digest, sigma.
    if (proof.pow_bind != DerivePowBind(proof.claimed_digest)) return fail("coupled:pow_bind");
    if (proof.claimed_digest != header.matmul_digest)
        return fail("coupled:digest_not_header_bound");
    if (proof.sigma != matmul::v4::DeriveSigma(header)) return fail("coupled:sigma");

    // SOLE AUTHORITY: native grounding trace (page schedule, π, mix, Extract,
    // roots, bank). This single call exports the immutable int64 reference
    // digest and the wire image; never replay the coupled puzzle twice.
    CoupledWires wires = BuildCoupledWires(header, height, params, options);
    if (!wires.ok) return fail("coupled:wires:" + wires.note);
    const uint256 ref_digest = wires.digest;
    if (proof.claimed_digest != ref_digest) return fail("coupled:digest_mismatch_reference");
    if (UintToArith256(ref_digest) > target) return fail("coupled:target");

    // F10 structural: exactly params.barriers roots (omission is unexpressible).
    // Keep this after the reference digest wall so params/profile relabel
    // attacks reject at the semantic "wrong puzzle" relation, not at whatever
    // array length happens to differ first.
    if (proof.barrier_roots.size() != params.barriers)
        return fail("coupled:barrier_roots_count");

    if (proof.bank_root != wires.bank_root) return fail("coupled:bank_root_forged");
    if (proof.barrier_roots != wires.barrier_roots)
        return fail("coupled:barrier_root_forged"); // F10 forged barrier root
    // Native SHA closure: digest = SHA256d(EPISODE ‖ bank_root ‖ roots…).
    if (AssembleCoupledEpisodeDigest(proof.bank_root, proof.barrier_roots,
                                     options.transcript_version) != proof.claimed_digest)
        return fail("coupled:digest_from_roots");

    // Λ_coup shape (verifier-driven; the proof carries no layout data).
    if (proof.lobes.size() != RCGkrCoupledExpectedLobeCount(params))
        return fail("coupled:lobe_count");
    if (proof.perm_evals.size() != params.barriers || proof.mix_evals.size() != params.barriers)
        return fail("coupled:perm_mix_count");
    if (proof.feed_evals.size() != RCGkrCoupledExpectedFeedCount(params))
        return fail("coupled:feed_count");

    // Rebuild the columns and BIND the commitment to ground truth. This is the
    // page-selection binding (F11): every B column must be the ROOT of the
    // natively scheduled bank page; A columns ground the feed-forward wiring;
    // e/p/x/s ground exchange/perm/mix/Extract (and F-wrap has no freedom).
    std::vector<std::vector<Fp2>> columns = BuildCoupledColumns(wires);
    const uint32_t batch_n = proof.batch.n_coeffs;
    if (batch_n == 0 || (batch_n & (batch_n - 1)) != 0) return fail("coupled:batch_n");
    {
        size_t max_len = 0;
        for (const auto& c : columns) max_len = std::max(max_len, c.size());
        if (batch_n != FriNextPow2(static_cast<uint32_t>(max_len)))
            return fail("coupled:batch_n_mismatch");
    }
    const uint32_t nu = Log2Exact(batch_n);
    if (columns.size() != RCGkrCoupledExpectedColumnCount(params))
        return fail("coupled:layout_column_count");
    if (proof.batch.columns.size() != columns.size() + 2)
        return fail("coupled:batch_col_count");
    for (size_t i = 0; i < columns.size(); ++i)
        if (FriBatchColumnRoot(columns[i], batch_n) != proof.batch.columns[i].root)
            return fail("coupled:column_not_grounded"); // F11 page/segment, F1/F2

    // Thm 2.1: the single batched FRI binds every committed column.
    const uint256 base_seed =
        RCGkrFsSeedV7Coupled(header, height, params, options, target, proof.claimed_digest,
                             proof.sigma, SeedRoots(proof.bank_root, proof.barrier_roots));
    std::string fri_why;
    if (!FriBatchVerify(proof.batch, base_seed, &fri_why))
        return fail("coupled:fri:" + fri_why);

    const uint32_t W = params.lobe_width;
    const uint32_t M = params.rows_per_lobe == 0 ? 1 : params.rows_per_lobe;
    const uint32_t n_state = params.StateBytes();
    const uint32_t nu_m = Log2Exact(RCGkrNextPow2(M));
    const uint32_t nu_w = Log2Exact(RCGkrNextPow2(W));
    const uint32_t nu_l = Log2Exact(RCGkrNextPow2(params.lobes));
    const uint32_t nu_n = Log2Exact(RCGkrNextPow2(n_state));
    CoupColIds ids{params.lobes};

    FsTranscript fs(kRCGkrDomainTagV7);
    fs.AbsorbBytes(reinterpret_cast<const unsigned char*>("coupled"), 7);
    fs.AbsorbUint256(base_seed);
    std::vector<RCGkrOpeningClaim> claims;

    // R5.gemm per (b,ℓ): sumcheck + gf ≡ a·b + fixed-segment exchange opening.
    for (uint32_t b = 0; b < params.barriers; ++b) {
        for (uint32_t ell = 0; ell < params.lobes; ++ell) {
            const size_t li = static_cast<size_t>(b) * params.lobes + ell;
            const RCGkrCoupledLobeClaimV7& lc = proof.lobes[li];
            fs.AbsorbU32(static_cast<uint32_t>(li));
            std::vector<Fp2> ri(nu_m);
            std::vector<Fp2> rj(nu_w);
            for (uint32_t t = 0; t < nu_m; ++t) ri[t] = fs.ChallengeFp2("v7c_ri");
            for (uint32_t t = 0; t < nu_w; ++t) rj[t] = fs.ChallengeFp2("v7c_rj");

            if (lc.sumcheck.size() != nu_w) return fail("coupled:sumcheck_rounds");
            std::vector<Fp2> rk;
            Fp2 gf;
            if (!VerifyProductK(lc.sumcheck, lc.c_claim, fs, rk, gf))
                return fail("coupled:sumcheck"); // forged claim chain
            if (!Eq(lc.final_eval, gf)) return fail("coupled:final_eval_endpoint");
            if (!Eq(lc.final_eval, Mul(lc.a_eval, lc.b_eval)))
                return fail("coupled:final_eval"); // Thm 3.1
            // R5.exchange: the committed exchange column MUST agree with the
            // GEMM output claim at the FIXED segment (segment_id = ℓ).
            if (!Eq(lc.exchange_eval, lc.c_claim)) return fail("coupled:exchange_segment");

            claims.push_back({ids.y(b, ell), PointConcatExtend(rj, ri, nu), lc.c_claim});
            claims.push_back({ids.a(b, ell), PointConcatExtend(rk, ri, nu), lc.a_eval});
            claims.push_back({ids.bcol(b, ell), PointConcatExtend(rj, rk, nu), lc.b_eval});
            std::vector<Fp2> seg_bits(nu_l);
            for (uint32_t t = 0; t < nu_l; ++t)
                seg_bits[t] = ((ell >> t) & 1u) ? Fp2::One() : Fp2::Zero();
            std::vector<Fp2> exchange_high = ri;
            exchange_high.insert(exchange_high.end(), seg_bits.begin(), seg_bits.end());
            claims.push_back({ids.e(b), PointConcatExtend(rj, exchange_high, nu),
                              lc.exchange_eval});
        }
    }

    // R5.perm / R5.mix. V4 proves the permutation relation by two bound MLE
    // openings: p̃(r_dst) == ẽ(π^{-1}(r_dst)), where π is a seeded bit-affine
    // bijection. V1–V3 keep the native Fisher–Yates scan.
    for (uint32_t b = 0; b < params.barriers; ++b) {
        const CoupledBarrierWire& bw = wires.barriers[b];
        fs.AbsorbBytes(reinterpret_cast<const unsigned char*>("perm"), 4);
        fs.AbsorbU32(b);
        std::vector<Fp2> rp(nu_n), rm(nu_n);
        for (uint32_t t = 0; t < nu_n; ++t) rp[t] = fs.ChallengeFp2("v7c_rp");
        for (uint32_t t = 0; t < nu_n; ++t) rm[t] = fs.ChallengeFp2("v7c_rm");
        Fp2 vp = Fp2::Zero();
        std::vector<Fp2> src_point;
        if (RCCoupUsesProofFriendlyPermutation(options.transcript_version)) {
            src_point = ProofFriendlyPermutationInversePoint(
                wires.sigma, b, params, options.transcript_version, rp);
            if (src_point.empty()) return fail("coupled:perm_affine_point");
            vp = proof.perm_evals[b];
        } else {
            const auto pi =
                DeriveCoupledBalancedPermutation(wires.sigma, b, params, options.transcript_version);
            for (uint32_t x = 0; x < n_state; ++x)
                vp = Add(vp, Mul(EqFactor(rp, pi[x]), FromSigned2(bw.exchange[x])));
        }
        const Fp2 vm = RCGkrMleEval1D2(ToFp2I64(bw.post_mix), rm);
        if (!Eq(proof.perm_evals[b], vp)) return fail("coupled:perm_eval_forged"); // F11
        if (!Eq(proof.mix_evals[b], vm)) return fail("coupled:mix_eval_forged");
        fs.AbsorbFp2(vp);
        fs.AbsorbFp2(vm);
        claims.push_back({ids.p(b), PointConcatExtend(rp, {}, nu), vp});
        if (!src_point.empty())
            claims.push_back({ids.e(b), PointConcatExtend(src_point, {}, nu), vp});
        claims.push_back({ids.x(b), PointConcatExtend(rm, {}, nu), vm});
    }

    // R5.feed-forward: proof-bound copy from committed state_out segment to the
    // next barrier's committed A operand. The verifier does not recompute this
    // scalar natively; Construction I binds both openings to committed columns
    // and forces equality at a random point.
    for (uint32_t b = 0; b + 1 < params.barriers; ++b) {
        for (uint32_t ell = 0; ell < params.lobes; ++ell) {
            const size_t fi = static_cast<size_t>(b) * params.lobes + ell;
            fs.AbsorbBytes(reinterpret_cast<const unsigned char*>("feed"), 4);
            fs.AbsorbU32(static_cast<uint32_t>(fi));
            std::vector<Fp2> ri(nu_m);
            std::vector<Fp2> rj(nu_w);
            for (uint32_t t = 0; t < nu_m; ++t) ri[t] = fs.ChallengeFp2("v7c_feed_ri");
            for (uint32_t t = 0; t < nu_w; ++t) rj[t] = fs.ChallengeFp2("v7c_feed_rj");
            const Fp2 feed = proof.feed_evals[fi];
            fs.AbsorbFp2(feed);

            claims.push_back({ids.a(b + 1, ell), PointConcatExtend(rj, ri, nu), feed});
            std::vector<Fp2> seg_bits(nu_l);
            for (uint32_t t = 0; t < nu_l; ++t)
                seg_bits[t] = ((ell >> t) & 1u) ? Fp2::One() : Fp2::Zero();
            std::vector<Fp2> state_high = ri;
            state_high.insert(state_high.end(), seg_bits.begin(), seg_bits.end());
            claims.push_back({ids.s(b), PointConcatExtend(rj, state_high, nu), feed});
        }
    }

    // Construction I: γ-batched MLE opening sumcheck + Stage-2 eval argument
    // bound to the same batched FRI instance.
    RCGkrBatchedOpeningProof opening;
    opening.version = kRCGkrConstructionIVersion;
    opening.sumcheck = proof.opening_sumcheck;
    opening.eval = proof.eval;
    opening.batch = proof.batch;
    std::string open_why;
    if (!BatchedOpeningVerify(claims, opening, base_seed, &open_why))
        return fail("coupled:opening:" + open_why);

    // R5.extract: dual-α LogUp over the grounded coupled tiles (FS-bound α's).
    fs.AbsorbBytes(reinterpret_cast<const unsigned char*>("logup"), 5);
    const Fp2 gamma = fs.ChallengeFp2("v7c_gamma");
    const Fp2 a1 = fs.ChallengeFp2("v7c_alpha1");
    const Fp2 a2 = fs.ChallengeFp2("v7c_alpha2");
    if (!Eq(a1, proof.logup_alpha1) || !Eq(a2, proof.logup_alpha2))
        return fail("coupled:logup_alpha_unbound");
    const auto lr = CoupledExtractLogUpSample(wires, gamma, a1, a2, /*max_tiles=*/16);
    if (!lr.ok) return fail("coupled:logup:" + lr.failure);

    if (fs.Digest() != proof.transcript_hash) return fail("coupled:transcript_hash");
    if (why) *why = "coupled v7 ok (SOUND, over_budget; arbiter OFF)";
    return true;
}

// ============================================================================
// Legacy-format bridge (thin call-site target for ProveWinnerCoupled).
// ============================================================================

RCGkrProveResult ProveWinnerCoupledLegacyBridge(const CBlockHeader& header, int32_t height,
                                                const RCCoupParams& params,
                                                const uint256& resealed_digest)
{
    RCGkrProveResult out;
    out.proof = {};
    out.timing.ok = false;

    if (!ValidateRCCoupParams(params)) {
        out.timing.note = "invalid coupled params";
        out.proof.shrink_note = out.timing.note;
        return out;
    }
    const RCCoupOptions options = CoupledProofOptionsForParams(params);
    // NEVER prove toy/unrelated work: the claimed digest must be the immutable
    // int64 coupled reference digest for exactly this (header, height, params).
    const uint256 ref_digest =
        RecomputeCoupledPuzzleReference(header, height, params, options, {}, nullptr);
    if (resealed_digest.IsNull() || resealed_digest != ref_digest) {
        out.timing.note = "coupled_digest_mismatch_refuses_unrelated_work";
        out.proof.shrink_note = out.timing.note;
        return out;
    }

    // The legacy entry point carries no target; bind the trivially satisfied
    // maximal target (the digest≤target relation is then vacuous, everything
    // else — GEMM/exchange/perm/mix/Extract/roots/bank — is fully proven).
    // The header must commit the digest for the v7 header-binding check;
    // matmul_digest is NOT part of sigma / the template hash, so this does not
    // perturb the coupled reference computation.
    arith_uint256 max_target;
    max_target = ~max_target;
    CBlockHeader bound = header;
    bound.matmul_digest = resealed_digest;
    auto v7 = ProveWinnerCoupledV7(bound, height, params, max_target, resealed_digest, options);
    if (!v7.timing.ok) {
        out.timing.note = "coupled v7 prove failed: " + v7.timing.note;
        out.proof.shrink_note = out.timing.note;
        return out;
    }
    // Self-check: only report ok for a proof the sound verifier accepts.
    std::string why;
    if (!VerifyWinnerCoupledV7(v7.proof, bound, height, max_target, &why)) {
        out.timing.note = "coupled v7 self-verify failed: " + why;
        out.proof.shrink_note = out.timing.note;
        return out;
    }

    out.timing.ok = true;
    out.timing.over_budget = true; // SOUND, not succinct (native grounding)
    out.timing.prove_s = v7.timing.prove_s;
    out.timing.proof_bytes = v7.timing.proof_bytes;
    out.timing.note =
        "coupled v7 proven+verified (RCGkrCoupledProofV7 format; use "
        "ProveWinnerCoupledV7/VerifyWinnerCoupledV7 — the v6 container cannot "
        "carry it). SOUND, over_budget; arbiter OFF.";
    out.proof.shrink_note = out.timing.note;
    return out;
}

} // namespace matmul::v4::rc
