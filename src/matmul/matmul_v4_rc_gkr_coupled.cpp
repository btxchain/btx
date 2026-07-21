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
// This file re-derives the coupled trace with LOCAL mirrors of the reference's
// private stages (mix / barrier-root / bank-commitment / extract-seed); any
// divergence between the mirrors and the reference propagates into the barrier
// roots and therefore the digest, which BOTH prover and verifier check against
// the exported reference entry point — a mirror bug can only cause a false
// REJECT, never a false ACCEPT. The int64 reference itself is untouched.
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

uint256 Sha256Tagged(const char* tag, size_t taglen, const unsigned char* data, size_t len)
{
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(tag), taglen);
    if (len > 0) hasher.Write(data, len);
    uint8_t out[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(out);
    return uint256{Span<const unsigned char>{out, sizeof(out)}};
}

uint256 Sha256TaggedU32(const char* tag, size_t taglen, const uint256& a, uint32_t le32)
{
    unsigned char buf[32 + 4];
    std::memcpy(buf, a.data(), 32);
    WriteLE32(buf + 32, le32);
    return Sha256Tagged(tag, taglen, buf, sizeof(buf));
}

uint256 Sha256TaggedU32U32(const char* tag, size_t taglen, const uint256& a, uint32_t x,
                           uint32_t y)
{
    unsigned char buf[32 + 8];
    std::memcpy(buf, a.data(), 32);
    WriteLE32(buf + 32, x);
    WriteLE32(buf + 36, y);
    return Sha256Tagged(tag, taglen, buf, sizeof(buf));
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
    std::vector<Fp2> wi(RCGkrNextPow2(m), Fp2::Zero()), wj(RCGkrNextPow2(n), Fp2::Zero());
    for (uint32_t i = 0; i < m; ++i) wi[i] = EqFactor(ri, i);
    for (uint32_t j = 0; j < n; ++j) wj[j] = EqFactor(rj, j);
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

Fp2 MleEvalMatrix(const std::vector<Fp2>& mat, uint32_t rows, uint32_t cols,
                  const std::vector<Fp2>& r_row, const std::vector<Fp2>& r_col)
{
    Fp2 acc = Fp2::Zero();
    for (uint32_t i = 0; i < rows; ++i) {
        const Fp2 ei = EqFactor(r_row, i);
        for (uint32_t j = 0; j < cols; ++j) {
            acc = Add(acc,
                      Mul(Mul(mat[static_cast<size_t>(i) * cols + j], ei), EqFactor(r_col, j)));
        }
    }
    return acc;
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

/** SHA256d(base ‖ every epoch-1 column root) — two-epoch eval-arg seed. */
uint256 EvalArgSeed(const uint256& base, const std::vector<FriLayerCommit>& columns,
                    size_t epoch1_count)
{
    std::vector<unsigned char> buf;
    buf.insert(buf.end(), base.begin(), base.end());
    for (size_t i = 0; i < epoch1_count && i < columns.size(); ++i)
        AppendBytes(buf, columns[i].root.data(), 32);
    return Sha256dBytes(buf.data(), buf.size());
}

// ---------------------------------------------------------------------------
// LOCAL MIRRORS of the coupled reference's private stages. Divergence from the
// reference is impossible to exploit: it changes barrier roots → digest, which
// is checked against the exported RecomputeCoupledPuzzleReference.
// ---------------------------------------------------------------------------

/** XOF words from a seed (SHA256 counter mode) — mirror of the reference. */
class ShaXof {
public:
    explicit ShaXof(const uint256& seed) : m_seed(seed) {}
    uint32_t NextU32()
    {
        if (m_pos + 4 > 32) Refill();
        const uint32_t v = ReadLE32(m_block + m_pos);
        m_pos += 4;
        return v;
    }

private:
    void Refill()
    {
        unsigned char buf[32 + 4];
        std::memcpy(buf, m_seed.data(), 32);
        WriteLE32(buf + 32, m_ctr++);
        uint8_t out[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(buf, sizeof(buf)).Finalize(out);
        std::memcpy(m_block, out, 32);
        m_pos = 0;
    }
    uint256 m_seed;
    uint32_t m_ctr{0};
    uint32_t m_pos{32};
    unsigned char m_block[32]{};
};

uint256 BarrierRootLocal(uint32_t barrier, const std::vector<int8_t>& state)
{
    std::vector<unsigned char> buf;
    buf.reserve((sizeof(kRCCoupBarrierTag) - 1) + 4 + state.size());
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(kRCCoupBarrierTag),
               reinterpret_cast<const unsigned char*>(kRCCoupBarrierTag) +
                   sizeof(kRCCoupBarrierTag) - 1);
    unsigned char le[4];
    WriteLE32(le, barrier);
    buf.insert(buf.end(), le, le + 4);
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(state.data()),
               reinterpret_cast<const unsigned char*>(state.data()) + state.size());
    return Sha256dBytes(buf.data(), buf.size());
}

uint256 BankCommitmentLocal(const std::vector<std::vector<int8_t>>& pages, uint32_t bank_pages,
                            uint32_t lobe_width)
{
    CSHA256 outer;
    outer.Write(reinterpret_cast<const unsigned char*>(kRCCoupBankTag),
                sizeof(kRCCoupBankTag) - 1);
    const size_t page_bytes = static_cast<size_t>(lobe_width) * lobe_width;
    for (uint32_t p = 0; p < bank_pages; ++p) {
        if (pages[p].size() != page_bytes) return uint256{};
        outer.Write(reinterpret_cast<const unsigned char*>(pages[p].data()), pages[p].size());
    }
    uint8_t d1[CSHA256::OUTPUT_SIZE];
    outer.Finalize(d1);
    uint8_t d2[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(d1, sizeof(d1)).Finalize(d2);
    return uint256{Span<const unsigned char>{d2, sizeof(d2)}};
}

void MixButterflyAscendingLocal(std::vector<int64_t>& s, uint32_t mask, uint32_t n)
{
    for (uint32_t stage = 0; (uint32_t{1} << stage) < n; ++stage) {
        const uint32_t stride = uint32_t{1} << stage;
        for (uint32_t i = 0; i < n; ++i) {
            const uint32_t j = i ^ stride;
            if (i >= j) continue;
            const uint32_t pi = i ^ mask;
            const uint32_t pj = j ^ mask;
            const int64_t a = s[pi];
            const int64_t b = s[pj];
            s[pi] = a + b;
            s[pj] = a - b;
        }
    }
}

void MixButterflyDescendingLocal(std::vector<int64_t>& s, uint32_t mask, uint32_t n)
{
    assert(n >= 2 && (n & (n - 1)) == 0);
    uint32_t bits = 0;
    for (uint32_t t = n; t > 1; t >>= 1) ++bits;
    auto rotl = [bits, n](uint32_t x, uint32_t r) -> uint32_t {
        r %= bits;
        return ((x << r) | (x >> (bits - r))) & (n - 1);
    };
    for (int stage = static_cast<int>(bits) - 1; stage >= 0; --stage) {
        const uint32_t stride = uint32_t{1} << static_cast<uint32_t>(stage);
        for (uint32_t i = 0; i < n; ++i) {
            const uint32_t j = i ^ stride;
            if (i >= j) continue;
            const uint32_t pi = rotl(i ^ mask, 3);
            const uint32_t pj = rotl(j ^ mask, 3);
            const int64_t a = s[pi];
            const int64_t b = s[pj];
            s[pi] = a + b;
            s[pj] = b - a;
        }
    }
}

void ApplyAllToAllMixLocal(std::vector<int64_t>& s, const uint256& sigma, uint32_t barrier,
                           uint32_t n)
{
    const uint256 mix_seed =
        Sha256TaggedU32(kRCCoupMixTag, sizeof(kRCCoupMixTag) - 1, sigma, barrier);
    ShaXof xof(mix_seed);
    const uint32_t mask = xof.NextU32() & (n - 1);
    const uint32_t pattern = barrier % kRCCoupMixPatterns;
    if (pattern == 0) {
        MixButterflyAscendingLocal(s, mask, n);
    } else {
        MixButterflyDescendingLocal(s, mask, n);
    }
}

void ApplyBalancedPermutationLocal(std::vector<int64_t>& s, const std::vector<uint32_t>& pi)
{
    std::vector<int64_t> tmp(s.size());
    for (uint32_t i = 0; i < static_cast<uint32_t>(s.size()); ++i) tmp[pi[i]] = s[i];
    s = std::move(tmp);
}

void ExtractActiveStateLocal(const uint256& prf_key, const std::vector<int64_t>& raw,
                             std::vector<int8_t>& out)
{
    assert(raw.size() == out.size());
    assert(raw.size() % kRCMxBlockLen == 0);
    const uint32_t n_tiles = static_cast<uint32_t>(raw.size() / kRCMxBlockLen);
    for (uint32_t t = 0; t < n_tiles; ++t) {
        ExtractMXTileInt64(prf_key, /*i=*/0, /*bj=*/t, raw.data() + t * kRCMxBlockLen,
                           out.data() + t * kRCMxBlockLen);
    }
}

uint256 CoupledDigestFromRoots(const uint256& bank_root, const std::vector<uint256>& roots)
{
    std::vector<unsigned char> buf;
    buf.reserve(sizeof(kRCCoupEpisodeTag) - 1 + 32 + roots.size() * 32);
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(kRCCoupEpisodeTag),
               reinterpret_cast<const unsigned char*>(kRCCoupEpisodeTag) +
                   sizeof(kRCCoupEpisodeTag) - 1);
    buf.insert(buf.end(), bank_root.begin(), bank_root.end());
    for (const uint256& root : roots) buf.insert(buf.end(), root.begin(), root.end());
    return Sha256dBytes(buf.data(), buf.size());
}

// ---------------------------------------------------------------------------
// Coupled trace wires (native re-derivation; the grounding oracle).
// ---------------------------------------------------------------------------

struct CoupledLobeWire {
    uint32_t barrier{0};
    uint32_t lobe{0};
    /** Λ_coup output — the natively scheduled page (never prover data). */
    uint32_t page_id{0};
    std::vector<Fp2> A; // 1×W state slice (feed-forward wired)
    std::vector<Fp2> B; // W×W bank page (page-selection wired)
    std::vector<Fp2> Y; // 1×W int64 GEMM row
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
                               const RCCoupParams& p)
{
    CoupledWires w;
    if (!ValidateRCCoupParams(p)) {
        w.note = "invalid params";
        return w;
    }
    const uint32_t n = p.StateBytes();
    const uint32_t W = p.lobe_width;
    w.sigma = matmul::v4::DeriveSigma(header);

    // Bank (template-committed, nonce-independent) + commitment (§7.6).
    const auto pages = DeriveCoupledBankPages(header, height, p);
    w.bank_root = BankCommitmentLocal(pages, p.bank_pages, W);
    if (w.bank_root.IsNull()) {
        w.note = "bank page shape";
        return w;
    }

    // Nonce-fresh lobe activation (C2).
    const auto lobe_seeds = DeriveCoupledLobeSeeds(w.sigma, p);
    std::vector<int8_t> state(n);
    for (uint32_t ell = 0; ell < p.lobes; ++ell) {
        const auto tile = ExpandMxDequantInt8(lobe_seeds[ell], W, W);
        std::memcpy(state.data() + static_cast<size_t>(ell) * W, tile.data(), W);
    }

    w.barriers.resize(p.barriers);
    w.barrier_roots.resize(p.barriers);
    for (uint32_t b = 0; b < p.barriers; ++b) {
        CoupledBarrierWire& bw = w.barriers[b];
        bw.exchange.assign(n, 0);
        bw.lobes.resize(p.lobes);

        // C3.a per-lobe GEMM vs the NATIVELY SCHEDULED page (legacy consensus
        // schedule; §7.1 — a forged page ID is unexpressible because the
        // verifier grounds B against this very schedule).
        for (uint32_t ell = 0; ell < p.lobes; ++ell) {
            CoupledLobeWire& lw = bw.lobes[ell];
            lw.barrier = b;
            lw.lobe = ell;
            const auto page_ids =
                SelectCoupledBankPageIds(b, ell, p, w.sigma, /*full=*/false);
            lw.page_id = page_ids.front();
            const std::vector<int8_t> arow(state.begin() + static_cast<size_t>(ell) * W,
                                           state.begin() + static_cast<size_t>(ell + 1) * W);
            const auto y32 = lt::ExactGemmS8S8(arow, pages[lw.page_id], 1, W, W);
            if (y32.size() != W) {
                w.note = "gemm shape";
                return w;
            }
            std::vector<int64_t> yrow(W);
            for (uint32_t c = 0; c < W; ++c) yrow[c] = static_cast<int64_t>(y32[c]);
            // C3.a' material exchange: consensus segment_id = lobe index →
            // FIXED offset ℓ·W in the exchange column.
            for (uint32_t c = 0; c < W; ++c)
                bw.exchange[static_cast<size_t>(ell) * W + c] = yrow[c];
            lw.A = ToFp2I8(arow);
            lw.B = ToFp2I8(pages[lw.page_id]);
            lw.Y = ToFp2I64(yrow);
        }

        // C3.b public balanced permutation.
        const auto pi = DeriveCoupledBalancedPermutation(w.sigma, b, p);
        if (!IsBalancedPermutation(pi, n)) {
            w.note = "perm not balanced";
            return w;
        }
        bw.post_perm = bw.exchange;
        ApplyBalancedPermutationLocal(bw.post_perm, pi);

        // C3.c butterfly mix (mirror; digest-checked against the reference).
        bw.post_mix = bw.post_perm;
        ApplyAllToAllMixLocal(bw.post_mix, w.sigma, b, n);

        // C3.d Extract.
        const uint256 extract_seed = Sha256TaggedU32U32(
            kRCCoupExtractTag, sizeof(kRCCoupExtractTag) - 1, w.sigma, b, /*unused=*/0);
        bw.extract_prf = lt::DeriveMatExpandPrfKey(extract_seed);
        bw.state_out.assign(n, 0);
        ExtractActiveStateLocal(bw.extract_prf, bw.post_mix, bw.state_out);

        // C3.e barrier root + feed-forward.
        bw.barrier_root = BarrierRootLocal(b, bw.state_out);
        w.barrier_roots[b] = bw.barrier_root;
        state = bw.state_out;
    }

    w.digest = CoupledDigestFromRoots(w.bank_root, w.barrier_roots);
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
    gkr_air::LogUpInstance inst_tm, inst_tx, inst_r16;
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
            gkr_air::AppendTileLookups(tw, tm_tab, tx_tab, gamma, inst_tm, inst_tx, inst_r16);
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
    bytes += 4 + 32 * 5 + 16 + proof.barrier_roots.size() * 32;
    for (const auto& lc : proof.lobes) bytes += lc.sumcheck.size() * 48 + 5 * 16;
    bytes += (proof.perm_evals.size() + proof.mix_evals.size()) * 16;
    bytes += 16 * 3 + 32 + 8; // eval proof sigma/fg + transcript + logup_bits
    return bytes;
}

} // namespace

// ============================================================================
// Prover.
// ============================================================================

RCGkrCoupledProveResultV7 ProveWinnerCoupledV7(const CBlockHeader& header, int32_t height,
                                               const RCCoupParams& params,
                                               const arith_uint256& target,
                                               const uint256& claimed_digest)
{
    RCGkrCoupledProveResultV7 res;
    RCGkrCoupledProofV7& proof = res.proof;
    const auto t0 = std::chrono::steady_clock::now();

    if (!ValidateRCCoupParams(params)) {
        res.timing.note = "invalid coupled params";
        return res;
    }

    // SOLE AUTHORITY: the immutable int64 coupled reference. Refuse to prove
    // anything else — this is what makes toy/unrelated-work proofs impossible.
    const uint256 ref_digest =
        RecomputeCoupledPuzzleReference(header, height, params, {}, {}, nullptr);
    if (claimed_digest.IsNull() || claimed_digest != ref_digest) {
        res.timing.note = "coupled_digest_mismatch_refuses_unrelated_work";
        return res;
    }
    if (UintToArith256(ref_digest) > target) {
        res.timing.note = "coupled digest over target";
        return res;
    }

    CoupledWires wires = BuildCoupledWires(header, height, params);
    if (!wires.ok) {
        res.timing.note = "wires: " + wires.note;
        return res;
    }
    // Mirror-consistency: the re-derived trace MUST reproduce the reference
    // digest byte-for-byte (fail closed on any local-mirror divergence).
    if (wires.digest != ref_digest) {
        res.timing.note = "coupled mirror digest mismatch vs int64 reference";
        return res;
    }

    proof.version = kRCGkrProofVersionV7;
    proof.params = params;
    proof.height = height;
    proof.claimed_digest = claimed_digest;
    proof.pow_bind = DerivePowBind(claimed_digest);
    proof.sigma = wires.sigma;
    proof.bank_root = wires.bank_root;
    proof.barrier_roots = wires.barrier_roots;

    const uint256 base_seed =
        RCGkrFsSeedV7Coupled(header, height, params, target, claimed_digest, wires.sigma,
                             SeedRoots(wires.bank_root, wires.barrier_roots));

    // Λ_coup columns + batch dimensioning.
    std::vector<std::vector<Fp2>> columns = BuildCoupledColumns(wires);
    size_t max_len = 0;
    for (const auto& c : columns) max_len = std::max(max_len, c.size());
    const uint32_t batch_n = FriNextPow2(static_cast<uint32_t>(max_len));
    const uint32_t nu = Log2Exact(batch_n);
    const uint32_t W = params.lobe_width;
    const uint32_t n_state = params.StateBytes();
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
            std::vector<Fp2> rj(nu_w);
            for (uint32_t t = 0; t < nu_w; ++t) rj[t] = fs.ChallengeFp2("v7c_rj");

            // R5.gemm: m = 1 (§7.2) — claim c = Ỹ(rj).
            const Fp2 c_claim = MleEvalMatrix(lw.Y, 1, W, {}, rj);
            std::vector<Fp2> rk;
            Fp2 gf;
            RCGkrCoupledLobeClaimV7& lc = proof.lobes[li];
            lc.sumcheck = ProveProductK(lw.A, 1, W, lw.B, W, {}, rj, c_claim, fs, rk, gf);
            lc.c_claim = c_claim;
            lc.a_eval = MleEvalMatrix(lw.A, 1, W, {}, rk);
            lc.b_eval = MleEvalMatrix(lw.B, W, W, rk, rj);
            lc.final_eval = gf; // == a_eval·b_eval for honest wires
            // R5.exchange: fixed segment ℓ ⇒ ẽ_b(rj, bits(ℓ)) = Ỹ(rj).
            lc.exchange_eval = c_claim;

            claims.push_back({ids.y(b, ell), PointConcatExtend(rj, {}, nu), lc.c_claim});
            claims.push_back({ids.a(b, ell), PointConcatExtend(rk, {}, nu), lc.a_eval});
            claims.push_back({ids.bcol(b, ell), PointConcatExtend(rj, rk, nu), lc.b_eval});
            std::vector<Fp2> seg_bits(nu_l);
            for (uint32_t t = 0; t < nu_l; ++t)
                seg_bits[t] = ((ell >> t) & 1u) ? Fp2::One() : Fp2::Zero();
            claims.push_back(
                {ids.e(b), PointConcatExtend(rj, seg_bits, nu), lc.exchange_eval});
        }
    }

    // R5.perm / R5.mix bindings (per barrier; §7.3 native weight-MLE).
    proof.perm_evals.resize(params.barriers);
    proof.mix_evals.resize(params.barriers);
    for (uint32_t b = 0; b < params.barriers; ++b) {
        const CoupledBarrierWire& bw = wires.barriers[b];
        fs.AbsorbBytes(reinterpret_cast<const unsigned char*>("perm"), 4);
        fs.AbsorbU32(b);
        std::vector<Fp2> rp(nu_n), rm(nu_n);
        for (uint32_t t = 0; t < nu_n; ++t) rp[t] = fs.ChallengeFp2("v7c_rp");
        for (uint32_t t = 0; t < nu_n; ++t) rm[t] = fs.ChallengeFp2("v7c_rm");
        const auto pi = DeriveCoupledBalancedPermutation(wires.sigma, b, params);
        Fp2 vp = Fp2::Zero();
        for (uint32_t x = 0; x < n_state; ++x)
            vp = Add(vp, Mul(EqFactor(rp, pi[x]), FromSigned2(bw.exchange[x])));
        const Fp2 vm = RCGkrMleEval1D2(ToFp2I64(bw.post_mix), rm);
        proof.perm_evals[b] = vp;
        proof.mix_evals[b] = vm;
        fs.AbsorbFp2(vp);
        fs.AbsorbFp2(vm);
        claims.push_back({ids.p(b), PointConcatExtend(rp, {}, nu), vp});
        claims.push_back({ids.x(b), PointConcatExtend(rm, {}, nu), vm});
    }

    // §2.4 eval argument (two-epoch: f,g committed inside the SAME batch).
    std::vector<FriLayerCommit> epoch1_roots(columns.size());
    for (size_t i = 0; i < columns.size(); ++i)
        epoch1_roots[i].root = FriBatchColumnRoot(columns[i], batch_n);
    const uint256 eval_seed = EvalArgSeed(base_seed, epoch1_roots, columns.size());
    const auto ev = EvalArgumentProve(claims, columns, eval_seed);
    if (!ev.ok) {
        res.timing.note = "eval arg prove: " + ev.note;
        return res;
    }
    proof.eval = ev.proof;
    columns.push_back(ev.f_coeffs);
    columns.push_back(ev.g_coeffs);

    const auto bc = FriBatchCommit(columns, base_seed);
    if (!bc.ok) {
        res.timing.note = "batch commit: " + bc.note;
        return res;
    }
    proof.batch = bc.proof;

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
    if (!ValidateRCCoupParams(params)) return fail("coupled:params_invalid");
    if (proof.height != height) return fail("coupled:height");

    // §6.1 native: pow_bind, header-bound digest, sigma.
    if (proof.pow_bind != DerivePowBind(proof.claimed_digest)) return fail("coupled:pow_bind");
    if (proof.claimed_digest != header.matmul_digest)
        return fail("coupled:digest_not_header_bound");
    if (proof.sigma != matmul::v4::DeriveSigma(header)) return fail("coupled:sigma");

    // SOLE AUTHORITY: the immutable int64 coupled reference (F13 dims ride on
    // this too — forged params change the reference digest).
    const uint256 ref_digest =
        RecomputeCoupledPuzzleReference(header, height, params, {}, {}, nullptr);
    if (proof.claimed_digest != ref_digest) return fail("coupled:digest_mismatch_reference");
    if (UintToArith256(ref_digest) > target) return fail("coupled:target");

    // F10 structural: exactly params.barriers roots (omission is unexpressible).
    if (proof.barrier_roots.size() != params.barriers)
        return fail("coupled:barrier_roots_count");

    // Native grounding trace (page schedule, π, mix, Extract, roots, bank).
    CoupledWires wires = BuildCoupledWires(header, height, params);
    if (!wires.ok) return fail("coupled:wires:" + wires.note);
    if (wires.digest != ref_digest) return fail("coupled:mirror_digest");
    if (proof.bank_root != wires.bank_root) return fail("coupled:bank_root_forged");
    if (proof.barrier_roots != wires.barrier_roots)
        return fail("coupled:barrier_root_forged"); // F10 forged barrier root
    // Native SHA closure: digest = SHA256d(EPISODE ‖ bank_root ‖ roots…).
    if (CoupledDigestFromRoots(proof.bank_root, proof.barrier_roots) != proof.claimed_digest)
        return fail("coupled:digest_from_roots");

    // Λ_coup shape (verifier-driven; the proof carries no layout data).
    if (proof.lobes.size() != RCGkrCoupledExpectedLobeCount(params))
        return fail("coupled:lobe_count");
    if (proof.perm_evals.size() != params.barriers || proof.mix_evals.size() != params.barriers)
        return fail("coupled:perm_mix_count");

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
        RCGkrFsSeedV7Coupled(header, height, params, target, proof.claimed_digest,
                             proof.sigma, SeedRoots(proof.bank_root, proof.barrier_roots));
    std::string fri_why;
    if (!FriBatchVerify(proof.batch, base_seed, &fri_why))
        return fail("coupled:fri:" + fri_why);

    const uint32_t W = params.lobe_width;
    const uint32_t n_state = params.StateBytes();
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
            std::vector<Fp2> rj(nu_w);
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

            claims.push_back({ids.y(b, ell), PointConcatExtend(rj, {}, nu), lc.c_claim});
            claims.push_back({ids.a(b, ell), PointConcatExtend(rk, {}, nu), lc.a_eval});
            claims.push_back({ids.bcol(b, ell), PointConcatExtend(rj, rk, nu), lc.b_eval});
            std::vector<Fp2> seg_bits(nu_l);
            for (uint32_t t = 0; t < nu_l; ++t)
                seg_bits[t] = ((ell >> t) & 1u) ? Fp2::One() : Fp2::Zero();
            claims.push_back(
                {ids.e(b), PointConcatExtend(rj, seg_bits, nu), lc.exchange_eval});
        }
    }

    // R5.perm / R5.mix: recompute the native expected values and REJECT any
    // proof-carried mismatch; then bind the committed columns via the eval arg.
    for (uint32_t b = 0; b < params.barriers; ++b) {
        const CoupledBarrierWire& bw = wires.barriers[b];
        fs.AbsorbBytes(reinterpret_cast<const unsigned char*>("perm"), 4);
        fs.AbsorbU32(b);
        std::vector<Fp2> rp(nu_n), rm(nu_n);
        for (uint32_t t = 0; t < nu_n; ++t) rp[t] = fs.ChallengeFp2("v7c_rp");
        for (uint32_t t = 0; t < nu_n; ++t) rm[t] = fs.ChallengeFp2("v7c_rm");
        const auto pi = DeriveCoupledBalancedPermutation(wires.sigma, b, params);
        Fp2 vp = Fp2::Zero();
        for (uint32_t x = 0; x < n_state; ++x)
            vp = Add(vp, Mul(EqFactor(rp, pi[x]), FromSigned2(bw.exchange[x])));
        const Fp2 vm = RCGkrMleEval1D2(ToFp2I64(bw.post_mix), rm);
        if (!Eq(proof.perm_evals[b], vp)) return fail("coupled:perm_eval_forged"); // F11
        if (!Eq(proof.mix_evals[b], vm)) return fail("coupled:mix_eval_forged");
        fs.AbsorbFp2(vp);
        fs.AbsorbFp2(vm);
        claims.push_back({ids.p(b), PointConcatExtend(rp, {}, nu), vp});
        claims.push_back({ids.x(b), PointConcatExtend(rm, {}, nu), vm});
    }

    // Thm 2.2: bind every claimed opening to the committed columns.
    const uint256 eval_seed =
        EvalArgSeed(base_seed, proof.batch.columns,
                    /*epoch1_count=*/RCGkrCoupledExpectedColumnCount(params));
    std::string ev_why;
    if (!EvalArgumentVerify(claims, proof.batch, proof.eval, eval_seed, &ev_why))
        return fail("coupled:eval:" + ev_why); // forged opening values

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
    // NEVER prove toy/unrelated work: the claimed digest must be the immutable
    // int64 coupled reference digest for exactly this (header, height, params).
    const uint256 ref_digest =
        RecomputeCoupledPuzzleReference(header, height, params, {}, {}, nullptr);
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
    auto v7 = ProveWinnerCoupledV7(bound, height, params, max_target, resealed_digest);
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
