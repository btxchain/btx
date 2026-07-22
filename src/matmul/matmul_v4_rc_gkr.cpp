// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_gkr.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <logging.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc_extract.h>
#include <matmul/matmul_v4_rc_gkr_air.h>
#include <matmul/matmul_v4_rc_gkr_coupled.h>
#include <matmul/matmul_v4_rc_gkr_wiring.h>
#include <span.h>
#include <sys/resource.h>

#include <cassert>
#include <atomic>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <list>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <utility>

namespace matmul::v4::rc {
namespace {

using gkr_field::Add;
using gkr_field::Canonical;
using gkr_field::Div;
using gkr_field::Eq;
using gkr_field::FromChallengeBytes2;
using gkr_field::FromSigned2;
using gkr_field::Inv;
using gkr_field::IsZero;
using gkr_field::Mul;
using gkr_field::Sub;

size_t CurrentRssKiB()
{
#if defined(__linux__)
    std::ifstream in("/proc/self/status");
    std::string key;
    while (in >> key) {
        if (key == "VmRSS:") {
            size_t kib = 0;
            in >> kib;
            return kib;
        }
        std::string rest;
        std::getline(in, rest);
    }
#endif
    struct rusage ru {};
    if (getrusage(RUSAGE_SELF, &ru) == 0) {
#if defined(__APPLE__)
        return static_cast<size_t>(ru.ru_maxrss / 1024);
#else
        return static_cast<size_t>(ru.ru_maxrss);
#endif
    }
    return 0;
}

bool ReadLE32Checked(const unsigned char*& p, const unsigned char* end, uint32_t& out)
{
    if (static_cast<size_t>(end - p) < 4) return false;
    out = ReadLE32(p);
    p += 4;
    return true;
}
bool ReadLE64Checked(const unsigned char*& p, const unsigned char* end, uint64_t& out)
{
    if (static_cast<size_t>(end - p) < 8) return false;
    out = ReadLE64(p);
    p += 8;
    return true;
}
bool ReadBytesChecked(const unsigned char*& p, const unsigned char* end, unsigned char* dst,
                      size_t n)
{
    if (static_cast<size_t>(end - p) < n) return false;
    std::memcpy(dst, p, n);
    p += n;
    return true;
}
bool ReadFp2Checked(const unsigned char*& p, const unsigned char* end, Fp2& out)
{
    uint64_t a = 0, b = 0;
    if (!ReadLE64Checked(p, end, a) || !ReadLE64Checked(p, end, b)) return false;
    out = Fp2{a, b};
    return true;
}

std::mutex g_rc_gkr_cache_mu;
/** H1: LRU+TTL proof cache (key → bytes + expiry; list front = most recently used). */
struct RCGkrProofCacheEntry {
    std::vector<unsigned char> bytes;
    std::chrono::steady_clock::time_point expires_at;
    std::list<uint256>::iterator lru_it;
};
std::list<uint256> g_rc_gkr_proof_lru;
std::map<uint256, RCGkrProofCacheEntry> g_rc_gkr_proof_cache;

std::atomic<uint64_t> g_exact_replay_invoke_count{0};

bool RCEpisodeParamsEqual(const RCEpisodeParams& a, const RCEpisodeParams& b)
{
    return a.rounds == b.rounds && a.d_head == b.d_head && a.n_q == b.n_q && a.n_ctx == b.n_ctx &&
           a.L_lyr == b.L_lyr && a.d_model == b.d_model && a.b_seq == b.b_seq &&
           a.T_leaf == b.T_leaf;
}

void RCGkrProofCacheEvictExpiredLocked(const std::chrono::steady_clock::time_point now)
{
    for (auto it = g_rc_gkr_proof_cache.begin(); it != g_rc_gkr_proof_cache.end();) {
        if (it->second.expires_at <= now) {
            g_rc_gkr_proof_lru.erase(it->second.lru_it);
            it = g_rc_gkr_proof_cache.erase(it);
        } else {
            ++it;
        }
    }
}

void RCGkrProofCacheEvictLruLocked()
{
    while (g_rc_gkr_proof_cache.size() > kRCGkrProofCacheMaxEntries) {
        assert(!g_rc_gkr_proof_lru.empty());
        const uint256 oldest = g_rc_gkr_proof_lru.back();
        g_rc_gkr_proof_lru.pop_back();
        g_rc_gkr_proof_cache.erase(oldest);
    }
}

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

std::vector<RCGkrSumcheckRound> ProveProductK(const std::vector<Fp2>& A, uint32_t m, uint32_t k_dim,
                                              const std::vector<Fp2>& B, uint32_t n,
                                              const std::vector<Fp2>& ri, const std::vector<Fp2>& rj,
                                              const Fp2& claim, FsTranscript& fs,
                                              std::vector<Fp2>& out_r, Fp2& out_final,
                                              Fp2& out_a_at_r, Fp2& out_b_at_r)
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
    Fp2 expected = claim;
    const uint32_t nu = Log2Exact(k_pad);
    std::vector<Fp2> ca = ah, cb = bh;
    for (uint32_t round = 0; round < nu; ++round) {
        Fp2 g0 = Fp2::Zero(), g1 = Fp2::Zero(), g2 = Fp2::Zero();
        for (size_t idx = 0; idx < ca.size(); idx += 2) {
            const Fp2 a0 = ca[idx], a1 = ca[idx + 1];
            const Fp2 b0 = cb[idx], b1 = cb[idx + 1];
            g0 = Add(g0, Mul(a0, b0));
            g1 = Add(g1, Mul(a1, b1));
            // g(2) = (2a1-a0)(2b1-b0)
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
        expected = EvalDeg2(g0, g1, g2, r);
        std::vector<Fp2> na(ca.size() / 2), nb(cb.size() / 2);
        for (size_t i = 0; i < na.size(); ++i) {
            na[i] = Add(Mul(ca[2 * i], Sub(Fp2::One(), r)), Mul(ca[2 * i + 1], r));
            nb[i] = Add(Mul(cb[2 * i], Sub(Fp2::One(), r)), Mul(cb[2 * i + 1], r));
        }
        ca = std::move(na);
        cb = std::move(nb);
        rounds.push_back(msg);
        (void)expected;
    }
    out_a_at_r = ca.empty() ? Fp2::Zero() : ca[0];
    out_b_at_r = cb.empty() ? Fp2::Zero() : cb[0];
    out_final = Mul(out_a_at_r, out_b_at_r);
    return rounds;
}

// v7 overload: the sound v7 path does NOT consume prover-supplied a_at_r/b_at_r
// (those v6 free fields are the G1 gap). v7 binds a_eval/b_eval to the committed
// operand columns via the batched-FRI eval argument (§2.4), so the sumcheck only
// needs the fold points and the chain-end gf (=a·b). Discard the two openings.
std::vector<RCGkrSumcheckRound> ProveProductK(const std::vector<Fp2>& A, uint32_t m, uint32_t k_dim,
                                              const std::vector<Fp2>& B, uint32_t n,
                                              const std::vector<Fp2>& ri, const std::vector<Fp2>& rj,
                                              const Fp2& claim, FsTranscript& fs,
                                              std::vector<Fp2>& out_r, Fp2& out_final)
{
    Fp2 discard_a{}, discard_b{};
    return ProveProductK(A, m, k_dim, B, n, ri, rj, claim, fs, out_r, out_final, discard_a,
                         discard_b);
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

/**
 * LogUp key binds the Extract (input, output) pair at (row, block):
 *   prf + scale + pre-Extract int64 block + post-Extract int8 block.
 * M7: Y/acc input MUST be hashed — otherwise extract_out is a free wire
 * relative to the GEMM accumulator (H5 residual lives in that accumulator).
 * Verifier still does NOT recompute Extract(·); relation soundness is via
 * committed lookup_fri keys + (aspirational) fixed-table LogUp.
 */
Fp2 HashLookupKey(uint32_t row, uint32_t block, const uint256& prf, uint8_t scale,
                  const int64_t* in64, const int8_t* out8)
{
    std::vector<unsigned char> buf;
    AppendLE32(buf, row);
    AppendLE32(buf, block);
    AppendBytes(buf, prf.data(), 32);
    buf.push_back(scale);
    for (uint32_t t = 0; t < kRCMxBlockLen; ++t) {
        AppendLE64(buf, static_cast<uint64_t>(in64[t]));
    }
    AppendBytes(buf, reinterpret_cast<const unsigned char*>(out8), kRCMxBlockLen);
    return FromChallengeBytes2(Sha256dBytes(buf.data(), buf.size()).data());
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

void AbsorbEpisode(FsTranscript& fs, const RCEpisodeParams& p)
{
    fs.AbsorbU32(p.rounds);
    fs.AbsorbU32(p.d_head);
    fs.AbsorbU32(p.n_q);
    fs.AbsorbU32(p.n_ctx);
    fs.AbsorbU32(p.L_lyr);
    fs.AbsorbU32(p.d_model);
    fs.AbsorbU32(p.b_seq);
    fs.AbsorbU32(p.T_leaf);
}

void AbsorbCoup(FsTranscript& fs, const RCCoupParams& p, const uint256& bank_root)
{
    // coup_v3: bind V3 shape fields + canonical dc schedule/exchange domain.
    // Verifier absorbs the SAME dc constants (not prover-chosen), so FS challenges
    // depend on the consensus schedule/exchange config.
    fs.AbsorbBytes(reinterpret_cast<const unsigned char*>("coup_v3"), 7);
    fs.AbsorbU32(p.barriers);
    fs.AbsorbU32(p.lobes);
    fs.AbsorbU32(p.lobe_width);
    fs.AbsorbU32(p.bank_pages);
    fs.AbsorbU32(p.rows_per_lobe);
    fs.AbsorbU32(p.pages_per_barrier_lobe);
    fs.AbsorbU32(dc::kRCCoupFullBankScheduleEnabled ? 1u : 0u);
    fs.AbsorbU32(dc::kRCCoupMaterialExchangeEnabled ? 1u : 0u);
    fs.AbsorbU32(dc::kRCCoupExchangeRowsDefault);
    fs.AbsorbUint256(bank_root);
}

uint256 CoupledDigestFromBankAndBarriers(const uint256& bank_root,
                                         const std::vector<uint256>& barrier_roots)
{
    std::vector<unsigned char> buf;
    buf.reserve(sizeof(kRCCoupEpisodeTag) - 1 + 32 + barrier_roots.size() * 32);
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(kRCCoupEpisodeTag),
               reinterpret_cast<const unsigned char*>(kRCCoupEpisodeTag) +
                   sizeof(kRCCoupEpisodeTag) - 1);
    buf.insert(buf.end(), bank_root.begin(), bank_root.end());
    for (const uint256& root : barrier_roots) {
        buf.insert(buf.end(), root.begin(), root.end());
    }
    return Sha256dBytes(buf.data(), buf.size());
}

uint256 DerivePowBind(const uint256& claimed_digest)
{
    return DeriveTagged(claimed_digest, "BTX_RC_GKR_POW_BIND_V4");
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

uint256 DeriveOperandSeedLocal(const uint256& seed_r, const char* tag)
{
    return Sha256Tagged(tag, std::strlen(tag), seed_r.data(), 32);
}

uint256 EpisodeDigestFromRoots(const std::vector<uint256>& round_roots)
{
    std::vector<unsigned char> buf;
    buf.reserve(sizeof(kRCEpisodeTag) - 1 + round_roots.size() * 32);
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(kRCEpisodeTag),
               reinterpret_cast<const unsigned char*>(kRCEpisodeTag) + sizeof(kRCEpisodeTag) - 1);
    for (const uint256& root : round_roots) {
        buf.insert(buf.end(), root.begin(), root.end());
    }
    return Sha256dBytes(buf.data(), buf.size());
}

size_t ExpectedLayerCount(const RCEpisodeParams& p)
{
    return static_cast<size_t>(p.rounds) * (2u + 3u * static_cast<size_t>(p.L_lyr));
}

void AbsorbPowBind(FsTranscript& fs, const uint256& claimed_digest, uint256& out_bind)
{
    out_bind = DerivePowBind(claimed_digest);
    fs.AbsorbBytes(reinterpret_cast<const unsigned char*>("pow_bind"), 8);
    fs.AbsorbUint256(out_bind);
}

bool EnvFlagIsOne(const char* name)
{
    const char* e = std::getenv(name);
    return e != nullptr && e[0] == '1' && e[1] == '\0';
}

bool EnvFlagIsZero(const char* name)
{
    const char* e = std::getenv(name);
    return e != nullptr && e[0] == '0' && e[1] == '\0';
}

Fp2 MleEvalMatrix(const std::vector<Fp2>& mat, uint32_t rows, uint32_t cols,
                  const std::vector<Fp2>& r_row, const std::vector<Fp2>& r_col)
{
    Fp2 acc = Fp2::Zero();
    for (uint32_t i = 0; i < rows; ++i) {
        const Fp2 ei = EqFactor(r_row, i);
        for (uint32_t j = 0; j < cols; ++j) {
            acc = Add(acc, Mul(Mul(mat[static_cast<size_t>(i) * cols + j], ei), EqFactor(r_col, j)));
        }
    }
    return acc;
}

struct LayerWire {
    RCGkrLayerKind kind;
    uint32_t round{0};
    uint32_t layer{0};
    uint32_t m{0}, n{0}, k{0};
    uint32_t page_id{0};
    std::vector<Fp2> A;
    std::vector<Fp2> B;
    std::vector<Fp2> Y; // GEMM product (Fp2) — sumcheck claim target
    /** G5: residual X as Fp2 (Fwd only); empty otherwise. */
    std::vector<Fp2> residual;
    /** Pre-Extract accumulator (int64). Equals Y for non-Fwd; for Fwd includes H5 residual. */
    std::vector<int64_t> extract_in;
    uint256 extract_prf{};
    std::vector<int8_t> extract_out;
    /** When true, skip product sumcheck (Extract-only coupled barrier layer). */
    bool extract_only{false};
    /** Raw int8/int64 witness (carried in the v7 proof for the in-circuit AIRs). */
    std::vector<int8_t> A_i8;
    std::vector<int8_t> B_i8;
    std::vector<int64_t> Y_i64;
};

void ExactInt64Gemm(const std::vector<int8_t>& A, uint32_t m, uint32_t k,
                    const std::vector<int8_t>& B, uint32_t n, std::vector<int64_t>& Y)
{
    Y.assign(static_cast<size_t>(m) * n, 0);
    for (uint32_t i = 0; i < m; ++i) {
        for (uint32_t t = 0; t < k; ++t) {
            const int64_t a = A[static_cast<size_t>(i) * k + t];
            for (uint32_t j = 0; j < n; ++j) {
                Y[static_cast<size_t>(i) * n + j] +=
                    a * static_cast<int64_t>(B[static_cast<size_t>(t) * n + j]);
            }
        }
    }
}

/**
 * Build ALL-PHASE real-episode layer wires for every round and every Phase-1 /
 * Phase-2 GEMM present in the consensus episode (Q·Kᵀ, S·V, Fwd, Bwd, Wgrad).
 * Round seeds match RunEpisode via Sha256TaggedU32 + round_roots.
 */
std::vector<LayerWire> BuildRealEpisodeLayers(const CBlockHeader& header,
                                              const RCEpisodeParams& p,
                                              const std::vector<uint256>& round_roots,
                                              std::vector<uint256>& out_seeds)
{
    assert(ValidateRCEpisodeParams(p));
    assert(round_roots.size() == p.rounds);
    std::vector<LayerWire> out;
    out.reserve(ExpectedLayerCount(p));
    out_seeds.clear();
    out_seeds.reserve(p.rounds);

    const uint256 sigma = matmul::v4::DeriveSigma(header);

    auto push_wire = [&](RCGkrLayerKind kind, uint32_t round, uint32_t layer, uint32_t m,
                         uint32_t n, uint32_t k, std::vector<int8_t> A, std::vector<int8_t> B,
                         std::vector<int64_t> Y_gemm, std::vector<int64_t> extract_in,
                         uint256 prf, std::vector<int8_t> extract) {
        LayerWire w;
        w.kind = kind;
        w.round = round;
        w.layer = layer;
        w.m = m;
        w.n = n;
        w.k = k;
        w.A = ToFp2I8(A);
        w.B = ToFp2I8(B);
        w.Y = ToFp2I64(Y_gemm);
        w.A_i8 = A;
        w.B_i8 = B;
        w.Y_i64 = Y_gemm;
        w.extract_in = std::move(extract_in);
        w.extract_prf = prf;
        w.extract_out = std::move(extract);
        out.push_back(std::move(w));
    };

    for (uint32_t r = 0; r < p.rounds; ++r) {
        uint256 seed_r;
        if (r == 0) {
            seed_r = Sha256TaggedU32(kRCRoundTag, sizeof(kRCRoundTag) - 1, sigma, 0);
        } else {
            seed_r = Sha256TaggedU32(kRCRoundTag, sizeof(kRCRoundTag) - 1, round_roots[r - 1], r);
        }
        out_seeds.push_back(seed_r);

        auto operand = [&](const char* tag) { return DeriveOperandSeedLocal(seed_r, tag); };

        // Phase-1: Q·Kᵀ then Extract S; S·V then Extract Z.
        std::vector<int8_t> S_mat;
        {
            const auto Q = ExpandMxDequantInt8(operand("BTX_RC_Q_V1"), p.n_q, p.d_head);
            const auto K = ExpandMxDequantInt8(operand("BTX_RC_KV_K_V1"), p.n_ctx, p.d_head);
            std::vector<int8_t> Kt(static_cast<size_t>(p.d_head) * p.n_ctx);
            for (uint32_t t = 0; t < p.n_ctx; ++t)
                for (uint32_t d = 0; d < p.d_head; ++d)
                    Kt[static_cast<size_t>(d) * p.n_ctx + t] =
                        K[static_cast<size_t>(t) * p.d_head + d];
            std::vector<int64_t> Y;
            ExactInt64Gemm(Q, p.n_q, p.d_head, Kt, p.n_ctx, Y);
            const uint256 prf_S = lt::DeriveMatExpandPrfKey(operand("BTX_RC_PRF_S_V1"));
            S_mat.assign(Y.size(), 0);
            ExtractMXMatrixInt64(prf_S, Y.data(), p.n_q, p.n_ctx, S_mat.data());
            push_wire(RCGkrLayerKind::GemmPhase1QKt, r, 0, p.n_q, p.n_ctx, p.d_head, Q, Kt, Y, Y,
                      prf_S, S_mat);
        }
        {
            const auto V = ExpandMxDequantInt8(operand("BTX_RC_KV_V_V1"), p.n_ctx, p.d_head);
            std::vector<int64_t> Y;
            ExactInt64Gemm(S_mat, p.n_q, p.n_ctx, V, p.d_head, Y);
            const uint256 prf_Z = lt::DeriveMatExpandPrfKey(operand("BTX_RC_PRF_Z_V1"));
            std::vector<int8_t> Zout(Y.size());
            ExtractMXMatrixInt64(prf_Z, Y.data(), p.n_q, p.d_head, Zout.data());
            push_wire(RCGkrLayerKind::GemmPhase1SV, r, 0, p.n_q, p.d_head, p.n_ctx, S_mat, V, Y, Y,
                      prf_Z, std::move(Zout));
        }

        // Phase-2: all forward layers, then bwd+wgrad from L-1 down to 0.
        std::vector<std::vector<int8_t>> X(p.L_lyr + 1);
        std::vector<std::vector<int8_t>> W(p.L_lyr);
        std::vector<uint256> prf_fwd(p.L_lyr), prf_bwd(p.L_lyr), prf_wg(p.L_lyr);
        X[0] = ExpandMxDequantInt8(operand("BTX_RC_X0_V1"), p.b_seq, p.d_model);
        for (uint32_t l = 0; l < p.L_lyr; ++l) {
            char tag[40];
            std::snprintf(tag, sizeof(tag), "BTX_RC_W_%u_V1", l);
            W[l] = ExpandMxDequantInt8(operand(tag), p.d_model, p.d_model);
            std::snprintf(tag, sizeof(tag), "BTX_RC_PRF_FWD_%u_V1", l);
            prf_fwd[l] = lt::DeriveMatExpandPrfKey(operand(tag));
            std::snprintf(tag, sizeof(tag), "BTX_RC_PRF_BWD_%u_V1", l);
            prf_bwd[l] = lt::DeriveMatExpandPrfKey(operand(tag));
            std::snprintf(tag, sizeof(tag), "BTX_RC_PRF_WG_%u_V1", l);
            prf_wg[l] = lt::DeriveMatExpandPrfKey(operand(tag));
        }

        for (uint32_t l = 0; l < p.L_lyr; ++l) {
            std::vector<int8_t> Wt(static_cast<size_t>(p.d_model) * p.d_model);
            for (uint32_t i = 0; i < p.d_model; ++i)
                for (uint32_t j = 0; j < p.d_model; ++j)
                    Wt[static_cast<size_t>(j) * p.d_model + i] =
                        W[l][static_cast<size_t>(i) * p.d_model + j];
            std::vector<int64_t> Y_gemm;
            ExactInt64Gemm(X[l], p.b_seq, p.d_model, Wt, p.d_model, Y_gemm);
            // H5: residual X[l] is INSIDE the single Extract accumulator (not a second Extract).
            std::vector<int64_t> Y_acc = Y_gemm;
            for (uint32_t i = 0; i < p.b_seq; ++i)
                for (uint32_t j = 0; j < p.d_model; ++j)
                    Y_acc[static_cast<size_t>(i) * p.d_model + j] +=
                        X[l][static_cast<size_t>(i) * p.d_model + j];
            X[l + 1].assign(Y_acc.size(), 0);
            ExtractMXMatrixInt64(prf_fwd[l], Y_acc.data(), p.b_seq, p.d_model, X[l + 1].data());
            // Sumcheck proves Y_gemm = A·B; LogUp binds (Y_acc, extract_out) for H5.
            push_wire(RCGkrLayerKind::GemmPhase2Fwd, r, l, p.b_seq, p.d_model, p.d_model, X[l],
                      Wt, Y_gemm, Y_acc, prf_fwd[l], X[l + 1]);
            out.back().residual = ToFp2I8(X[l]);
        }

        std::vector<std::vector<int8_t>> G(p.L_lyr + 1);
        G[p.L_lyr] = ExpandMxDequantInt8(operand("BTX_RC_GL_V1"), p.b_seq, p.d_model);
        for (int32_t li = static_cast<int32_t>(p.L_lyr) - 1; li >= 0; --li) {
            const uint32_t l = static_cast<uint32_t>(li);
            // Bwd: G[l] = Extract(G[l+1] · W[l]) — ExactGemm(G, W).
            std::vector<int64_t> Y_bwd;
            ExactInt64Gemm(G[l + 1], p.b_seq, p.d_model, W[l], p.d_model, Y_bwd);
            G[l].assign(Y_bwd.size(), 0);
            ExtractMXMatrixInt64(prf_bwd[l], Y_bwd.data(), p.b_seq, p.d_model, G[l].data());
            push_wire(RCGkrLayerKind::GemmPhase2Bwd, r, l, p.b_seq, p.d_model, p.d_model,
                      G[l + 1], W[l], Y_bwd, Y_bwd, prf_bwd[l], G[l]);

            // Wgrad: D = Extract(Gᵀ · X) via ExactInt64Gemm(Gt, X).
            std::vector<int8_t> Gt(static_cast<size_t>(p.d_model) * p.b_seq);
            for (uint32_t t = 0; t < p.b_seq; ++t)
                for (uint32_t row = 0; row < p.d_model; ++row)
                    Gt[static_cast<size_t>(row) * p.b_seq + t] =
                        G[l + 1][static_cast<size_t>(t) * p.d_model + row];
            std::vector<int64_t> Y_wg;
            ExactInt64Gemm(Gt, p.d_model, p.b_seq, X[l], p.d_model, Y_wg);
            std::vector<int8_t> Dout(Y_wg.size());
            ExtractMXMatrixInt64(prf_wg[l], Y_wg.data(), p.d_model, p.d_model, Dout.data());
            push_wire(RCGkrLayerKind::GemmPhase2Wgrad, r, l, p.d_model, p.d_model, p.b_seq, Gt,
                      X[l], Y_wg, Y_wg, prf_wg[l], std::move(Dout));
        }
    }

    return out;
}

void MarkBudget(RCGkrTiming& t, RCGkrProof& p)
{
    t.over_budget = t.prove_s > kRCGkrMediumProveBudgetS || t.verify_s > kRCGkrVerifyBudgetS ||
                    t.proof_bytes > kRCGkrProofBytesBudget;
    p.over_budget = t.over_budget;
    if (t.over_budget) {
        p.shrink_note =
            "over soft budget → shrink-to-VerifyBoundedExactReplay (ε=0 shipping "
            "fallback). ALL-PHASE arithmetization retained (no shrink-to-toy). "
            "NOT inventing production silicon numbers. HBM GKR PARKED.";
        t.used_shrink_fallback = true;
        t.note = p.shrink_note;
    }
}

struct RCGkrProveForgeOpts {
    bool arbitrary_ab_factorization{false};
    bool unrelated_layer_roots{false};
    bool fabricated_identical_lookup{false};
};

RCGkrProveResult ProveFromLayers(const uint256& claimed_digest, const RCEpisodeParams& episode,
                                 const std::vector<LayerWire>& wires,
                                 const std::vector<uint256>& round_seeds,
                                 const std::vector<uint256>& round_roots,
                                 const uint256& episode_sigma, const char* path_note,
                                 bool coupled = false, const RCCoupParams& coup = {},
                                 const uint256& bank_root = {},
                                 const RCGkrProveForgeOpts& forge = {})
{
    RCGkrProveResult out;
    const size_t rss0 = CurrentRssKiB();
    const auto t0 = std::chrono::steady_clock::now();
    RCGkrProof& p = out.proof;
    p.version = kRCGkrProofVersion;
    p.claimed_digest = claimed_digest;
    p.episode = episode;
    p.coupled = coupled;
    p.coup = coup;
    p.bank_root = bank_root;
    p.round_seeds = round_seeds;
    p.round_roots = round_roots;
    p.episode_sigma = episode_sigma;
    p.table_multiplicity = 1;

    FsTranscript fs(kRCGkrDomainTag);
    if (coupled) {
        AbsorbCoup(fs, coup, bank_root);
    } else {
        AbsorbEpisode(fs, episode);
    }
    fs.AbsorbUint256(claimed_digest);
    AbsorbPowBind(fs, claimed_digest, p.pow_bind);
    fs.AbsorbUint256(episode_sigma);
    fs.AbsorbU32(p.table_multiplicity);
    fs.AbsorbBytes(reinterpret_cast<const unsigned char*>("round_seeds"), 11);
    for (const auto& s : round_seeds) fs.AbsorbUint256(s);
    fs.AbsorbBytes(reinterpret_cast<const unsigned char*>("round_roots"), 11);
    for (const auto& rt : round_roots) fs.AbsorbUint256(rt);

    // --- G1/G2/G3: commit A, B, Y, witness keys, Extract-table keys ---
    std::vector<Fp2> a_evals, b_evals, trace_evals, witness_keys, table_keys;
    std::vector<uint256> extract_commits;
    extract_commits.reserve(wires.size());
    for (const auto& w : wires) {
        a_evals.insert(a_evals.end(), w.A.begin(), w.A.end());
        b_evals.insert(b_evals.end(), w.B.begin(), w.B.end());
        trace_evals.insert(trace_evals.end(), w.Y.begin(), w.Y.end());
        std::vector<unsigned char> outbuf;
        outbuf.insert(outbuf.end(), reinterpret_cast<const unsigned char*>(w.extract_out.data()),
                      reinterpret_cast<const unsigned char*>(w.extract_out.data()) +
                          w.extract_out.size());
        extract_commits.push_back(Sha256dBytes(outbuf.empty() ? nullptr : outbuf.data(), outbuf.size()));

        if (w.extract_out.empty() || w.extract_in.empty()) continue;
        assert(w.extract_in.size() == static_cast<size_t>(w.m) * w.n);
        assert(w.extract_out.size() == static_cast<size_t>(w.m) * w.n);
        assert(w.n % kRCMxBlockLen == 0);
        const uint32_t n_blocks = w.n / kRCMxBlockLen;
        for (uint32_t i = 0; i < w.m; ++i) {
            for (uint32_t bj = 0; bj < n_blocks; ++bj) {
                const size_t base =
                    static_cast<size_t>(i) * w.n + static_cast<size_t>(bj) * kRCMxBlockLen;
                const uint8_t scale = lt::DeriveMatExpandMxScale(w.extract_prf, i, bj);
                const Fp2 wkey = HashLookupKey(i, bj, w.extract_prf, scale,
                                              w.extract_in.data() + base,
                                              w.extract_out.data() + base);
                witness_keys.push_back(wkey);
                if (forge.fabricated_identical_lookup) {
                    // G3 vacuity: table := witness (prover-manufactured both sides).
                    table_keys.push_back(wkey);
                } else {
                    int8_t honest_out[kRCMxBlockLen];
                    ExtractMXTileInt64(w.extract_prf, i, bj, w.extract_in.data() + base,
                                       honest_out);
                    table_keys.push_back(HashLookupKey(i, bj, w.extract_prf, scale,
                                                       w.extract_in.data() + base, honest_out));
                }
            }
        }
    }
    // G3 multiplicity=1: every table key must be unique.
    {
        std::vector<Fp2> sorted = table_keys;
        std::sort(sorted.begin(), sorted.end(), [](const Fp2& x, const Fp2& y) {
            if (x.c0 != y.c0) return x.c0 < y.c0;
            return x.c1 < y.c1;
        });
        for (size_t i = 1; i < sorted.size(); ++i) {
            if (Eq(sorted[i], sorted[i - 1])) {
                out.timing.ok = false;
                out.timing.note = "G3 table multiplicity > 1";
                return out;
            }
        }
    }

    auto wire_root = [](const std::vector<Fp2>& v) {
        std::vector<unsigned char> buf;
        for (const auto& x : v) AppendFp2(buf, x);
        return Sha256dBytes(buf.empty() ? nullptr : buf.data(), buf.size());
    };

    const uint256 fri_pre = fs.Challenge("fri_precommit");
    auto a_c = FriCommitAndFold(a_evals.empty() ? std::vector<Fp2>{Fp2::Zero()} : a_evals, fri_pre);
    auto b_c = FriCommitAndFold(b_evals.empty() ? std::vector<Fp2>{Fp2::Zero()} : b_evals, fri_pre);
    auto trace_c = FriCommitAndFold(trace_evals.empty() ? std::vector<Fp2>{Fp2::Zero()} : trace_evals,
                                    fri_pre);
    auto lookup_c = FriCommitAndFold(
        witness_keys.empty() ? std::vector<Fp2>{Fp2::Zero()} : witness_keys, fri_pre);
    auto table_c = FriCommitAndFold(
        table_keys.empty() ? std::vector<Fp2>{Fp2::Zero()} : table_keys, fri_pre);
    p.a_fri = std::move(a_c.proof);
    p.b_fri = std::move(b_c.proof);
    p.trace_fri = std::move(trace_c.proof);
    p.lookup_fri = std::move(lookup_c.proof);
    p.table_fri = std::move(table_c.proof);
    if (p.lookup_fri.layers.empty() || p.table_fri.layers.empty() ||
        p.lookup_fri.layers[0].root != p.table_fri.layers[0].root ||
        (p.lookup_fri.has_deep && p.table_fri.has_deep &&
         !Eq(p.lookup_fri.deep_eval, p.table_fri.deep_eval))) {
        out.timing.ok = false;
        out.timing.note = "G3 Extract table mismatch (witness key != Extract key)";
        return out;
    }
    fs.AbsorbUint256(p.a_fri.layers.empty() ? uint256{} : p.a_fri.layers[0].root);
    fs.AbsorbUint256(p.b_fri.layers.empty() ? uint256{} : p.b_fri.layers[0].root);
    fs.AbsorbUint256(p.trace_fri.layers.empty() ? uint256{} : p.trace_fri.layers[0].root);
    fs.AbsorbUint256(p.lookup_fri.layers.empty() ? uint256{} : p.lookup_fri.layers[0].root);
    fs.AbsorbUint256(p.table_fri.layers.empty() ? uint256{} : p.table_fri.layers[0].root);
    if (p.trace_fri.has_deep) {
        fs.AbsorbFp2(p.trace_fri.deep_z);
        fs.AbsorbFp2(p.trace_fri.deep_eval);
    }
    if (p.lookup_fri.has_deep) {
        fs.AbsorbFp2(p.lookup_fri.deep_z);
        fs.AbsorbFp2(p.lookup_fri.deep_eval);
    }

    uint256 prev_extract_commit{};
    for (size_t wi = 0; wi < wires.size(); ++wi) {
        const auto& w = wires[wi];
        fs.AbsorbUint256(prev_extract_commit);
        fs.AbsorbUint256(extract_commits[wi]);
        fs.AbsorbU32(w.page_id);
        fs.AbsorbU32(/*multiplicity*/ 1);

        const uint32_t nu_i = Log2Exact(RCGkrNextPow2(std::max(w.m, 1u)));
        const uint32_t nu_j = Log2Exact(RCGkrNextPow2(std::max(w.n, 1u)));
        std::vector<Fp2> ri(nu_i), rj(nu_j);
        for (uint32_t t = 0; t < nu_i; ++t) ri[t] = fs.ChallengeFp2("ri");
        for (uint32_t t = 0; t < nu_j; ++t) rj[t] = fs.ChallengeFp2("rj");

        const Fp2 gemm_claim = MleEvalMatrix(w.Y, w.m, w.n, ri, rj);
        Fp2 residual_mle = Fp2::Zero();
        if (!w.residual.empty()) {
            residual_mle = MleEvalMatrix(w.residual, w.m, w.n, ri, rj);
        }
        Fp2 acc_claim = gemm_claim;
        if (!w.extract_in.empty()) {
            acc_claim = MleEvalMatrix(ToFp2I64(w.extract_in), w.m, w.n, ri, rj);
        }
        fs.AbsorbFp2(gemm_claim);
        fs.AbsorbFp2(residual_mle);
        fs.AbsorbFp2(acc_claim);

        RCGkrLayerClaim lc;
        lc.kind = w.kind;
        lc.round = w.round;
        lc.layer = w.layer;
        lc.m = w.m;
        lc.n = w.n;
        lc.k = w.k;
        lc.page_id = w.page_id;
        lc.table_multiplicity = 1;
        lc.claim = gemm_claim;
        lc.residual_mle = residual_mle;
        lc.acc_claim = acc_claim;
        lc.extract_out_commit = extract_commits[wi];
        lc.a_root = wire_root(w.A);
        lc.b_root = wire_root(w.B);
        lc.y_root = wire_root(w.Y);
        if (forge.unrelated_layer_roots) {
            // Independent malicious: roots unrelated to A/B/Y or global FRI commits.
            for (int i = 0; i < 32; ++i) {
                lc.a_root.data()[i] = static_cast<unsigned char>(0xA0 + (i & 0xf));
                lc.b_root.data()[i] = static_cast<unsigned char>(0xB0 + (i & 0xf));
                lc.y_root.data()[i] = static_cast<unsigned char>(0xC0 + (i & 0xf));
            }
        }
        fs.AbsorbUint256(lc.a_root);
        fs.AbsorbUint256(lc.b_root);
        fs.AbsorbUint256(lc.y_root);

        std::vector<Fp2> rk;
        if (w.extract_only || w.k == 0 || w.A.empty() || w.B.empty()) {
            // Extract-only: claim binds Y=extract_in; a_at_r=1, b_at_r=claim.
            lc.a_at_r = Fp2::One();
            lc.b_at_r = gemm_claim;
            lc.final_eval = gemm_claim;
            fs.AbsorbFp2(lc.a_at_r);
            fs.AbsorbFp2(lc.b_at_r);
            fs.AbsorbFp2(lc.final_eval);
        } else {
            lc.sumcheck = ProveProductK(w.A, w.m, w.k, w.B, w.n, ri, rj, gemm_claim, fs, rk,
                                        lc.final_eval, lc.a_at_r, lc.b_at_r);
            if (forge.arbitrary_ab_factorization && !IsZero(lc.final_eval)) {
                // G1 gap: any factorization of final_eval passes without PCS opening.
                lc.a_at_r = Fp2::FromFp(0xC0FFEE);
                lc.b_at_r = Div(lc.final_eval, lc.a_at_r);
            }
            fs.AbsorbFp2(lc.a_at_r);
            fs.AbsorbFp2(lc.b_at_r);
        }
        p.layers.push_back(std::move(lc));
        prev_extract_commit = extract_commits[wi];
    }

    const Fp2 alu = fs.ChallengeFp2("logup_alpha");
    p.logup_alpha = alu;
    std::vector<Fp2> inv, resid;
    inv.reserve(table_keys.size());
    resid.reserve(table_keys.size());
    Fp2 sum_t = Fp2::Zero();
    Fp2 sum_w = Fp2::Zero();
    for (size_t i = 0; i < table_keys.size(); ++i) {
        if (Eq(table_keys[i], alu) || Eq(witness_keys[i], alu)) {
            out.timing.ok = false;
            out.timing.note = "logup collide";
            return out;
        }
        const Fp2 inv_i = Div(Fp2::One(), Sub(alu, table_keys[i]));
        inv.push_back(inv_i);
        resid.push_back(Sub(Mul(inv_i, Sub(alu, table_keys[i])), Fp2::One()));
        sum_t = Add(sum_t, inv_i);
        sum_w = Add(sum_w, Div(Fp2::One(), Sub(alu, witness_keys[i])));
    }
    if (!Eq(sum_w, sum_t)) {
        out.timing.ok = false;
        out.timing.note = "G3 Haböck sum_w != sum_t";
        return out;
    }
    for (const auto& r : resid) {
        if (!IsZero(r)) {
            out.timing.ok = false;
            out.timing.note = "G3 LogUp residual nonzero";
            return out;
        }
    }
    p.lookup_logup_sum = sum_t;
    p.lookup_table_sum = sum_t;
    fs.AbsorbFp2(alu);
    fs.AbsorbFp2(sum_t);

    auto inv_c = FriCommitAndFoldDeepAt(inv.empty() ? std::vector<Fp2>{Fp2::Zero()} : inv, fri_pre,
                                        Fp2::One());
    auto r_c = FriCommitAndFold(resid.empty() ? std::vector<Fp2>{Fp2::Zero()} : resid, fri_pre);
    p.logup_inv_fri = std::move(inv_c.proof);
    p.logup_r_fri = std::move(r_c.proof);
    if (!p.logup_inv_fri.has_deep || !p.logup_inv_fri.deep_z_forced ||
        !Eq(p.logup_inv_fri.deep_z, Fp2::One()) ||
        !Eq(p.logup_inv_fri.deep_eval, sum_t)) {
        out.timing.ok = false;
        out.timing.note = "G3 LogUp I(1) DEEP mismatch";
        return out;
    }
    if (p.logup_r_fri.has_deep && !IsZero(p.logup_r_fri.deep_eval)) {
        out.timing.ok = false;
        out.timing.note = "G3 LogUp R deep nonzero";
        return out;
    }
    if (!IsZero(p.logup_r_fri.final_value)) {
        out.timing.ok = false;
        out.timing.note = "G3 LogUp R final nonzero";
        return out;
    }
    fs.AbsorbUint256(p.logup_inv_fri.layers.empty() ? uint256{} : p.logup_inv_fri.layers[0].root);
    fs.AbsorbUint256(p.logup_r_fri.layers.empty() ? uint256{} : p.logup_r_fri.layers[0].root);
    if (p.logup_inv_fri.has_deep) {
        fs.AbsorbFp2(p.logup_inv_fri.deep_z);
        fs.AbsorbFp2(p.logup_inv_fri.deep_eval);
    }
    p.transcript_hash = fs.Digest();
    p.shrink_note = kRCGkrG1G5ClosedStatement;

    std::vector<unsigned char> ser;
    out.timing.proof_bytes = SerializeRCGkrProof(p, ser);
    out.timing.prove_s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    out.timing.peak_rss_kib = std::max(CurrentRssKiB(), rss0);
    out.timing.ok = a_c.ok && b_c.ok && trace_c.ok && lookup_c.ok && table_c.ok && inv_c.ok && r_c.ok;
    out.timing.note = path_note ? path_note : kRCGkrSoundnessBoundStatement;
    MarkBudget(out.timing, p);
    return out;
}

} // namespace

// ============================================================================
// v7 FOUNDATION substrate: canonical trace layout Λ(params) + FS binding.
// ============================================================================

RCGkrLayout RCGkrTraceLayout(const RCEpisodeParams& p)
{
    assert(ValidateRCEpisodeParams(p));
    RCGkrLayout out;
    out.params = p;

    // Register one tensor = ceil(cells/κ) chunk columns; return (first, n_chunks).
    auto add_tensor = [&](RCGkrTensor tensor, uint32_t round, uint32_t layer, uint32_t rows,
                          uint32_t cols, bool int64_cells) -> RCGkrOperandRef {
        const uint64_t cells = static_cast<uint64_t>(rows) * cols;
        const uint32_t n_chunks = static_cast<uint32_t>(
            (cells + kRCGkrColumnMaxCoeffs - 1) >> kRCGkrColumnMaxLog2);
        const uint32_t first = static_cast<uint32_t>(out.columns.size());
        for (uint32_t c = 0; c < n_chunks; ++c) {
            RCGkrColumnInfo ci;
            ci.id = first + c;
            ci.tensor = tensor;
            ci.round = round;
            ci.layer = layer;
            ci.rows = rows;
            ci.cols = cols;
            ci.chunk = c;
            ci.n_chunks = n_chunks;
            ci.chunk_offset = static_cast<uint64_t>(c) << kRCGkrColumnMaxLog2;
            ci.len = std::min<uint64_t>(kRCGkrColumnMaxCoeffs, cells - ci.chunk_offset);
            ci.int64_cells = int64_cells;
            out.columns.push_back(ci);
        }
        if (int64_cells) {
            out.trace_cells += cells;
        } else {
            out.operand_cells += cells;
        }
        out.total_cells += cells;
        return RCGkrOperandRef{first, n_chunks, /*transpose=*/false};
    };
    auto transposed = [](RCGkrOperandRef ref) {
        ref.transpose = true;
        return ref;
    };
    auto add_layer = [&](RCGkrLayerKind kind, uint32_t round, uint32_t layer, uint32_t m,
                         uint32_t n, uint32_t k, const RCGkrOperandRef& a,
                         const RCGkrOperandRef& b, RCGkrTensor y_tensor,
                         RCGkrTensor out_tensor, uint32_t out_rows, uint32_t out_cols,
                         int32_t residual_first) {
        RCGkrLayerSpec ls;
        ls.kind = kind;
        ls.round = round;
        ls.layer = layer;
        ls.m = m;
        ls.n = n;
        ls.k = k;
        ls.a = a;
        ls.b = b;
        const RCGkrOperandRef y = add_tensor(y_tensor, round, layer, m, n, /*int64=*/true);
        ls.y_first_column = y.first_column;
        ls.y_chunks = y.n_chunks;
        const RCGkrOperandRef o =
            add_tensor(out_tensor, round, layer, out_rows, out_cols, /*int64=*/false);
        ls.out_first_column = o.first_column;
        ls.out_chunks = o.n_chunks;
        ls.residual_first_column = residual_first;
        out.layers.push_back(ls);
        return o;
    };

    out.columns.reserve(static_cast<size_t>(p.rounds) * (8u + 5u * p.L_lyr));
    out.layers.reserve(RCGkrExpectedLayerCount(p));

    for (uint32_t r = 0; r < p.rounds; ++r) {
        // Phase 1. QKt: A = Q, B = Kᵀ (free transpose of the single K column).
        const auto q_ref = add_tensor(RCGkrTensor::Q, r, 0, p.n_q, p.d_head, false);
        const auto k_ref = add_tensor(RCGkrTensor::K, r, 0, p.n_ctx, p.d_head, false);
        const auto s_ref =
            add_layer(RCGkrLayerKind::GemmPhase1QKt, r, 0, p.n_q, p.n_ctx, p.d_head, q_ref,
                      transposed(k_ref), RCGkrTensor::YQKt, RCGkrTensor::S, p.n_q, p.n_ctx, -1);
        // SV: A = S (= extract_out of QKt, SAME column — wiring is definitional).
        const auto v_ref = add_tensor(RCGkrTensor::V, r, 0, p.n_ctx, p.d_head, false);
        (void)add_layer(RCGkrLayerKind::GemmPhase1SV, r, 0, p.n_q, p.d_head, p.n_ctx, s_ref,
                        v_ref, RCGkrTensor::YSV, RCGkrTensor::Z, p.n_q, p.d_head, -1);

        // Phase 2 forward. X(r,0) expanded; W(r,l) committed once and shared
        // between Fwd (transposed) and Bwd (plain).
        std::vector<RCGkrOperandRef> x_refs(p.L_lyr + 1);
        std::vector<RCGkrOperandRef> w_refs(p.L_lyr);
        x_refs[0] = add_tensor(RCGkrTensor::X, r, 0, p.b_seq, p.d_model, false);
        for (uint32_t l = 0; l < p.L_lyr; ++l) {
            w_refs[l] = add_tensor(RCGkrTensor::W, r, l, p.d_model, p.d_model, false);
            x_refs[l + 1] = add_layer(
                RCGkrLayerKind::GemmPhase2Fwd, r, l, p.b_seq, p.d_model, p.d_model, x_refs[l],
                transposed(w_refs[l]), RCGkrTensor::YFwd, RCGkrTensor::X, p.b_seq, p.d_model,
                static_cast<int32_t>(x_refs[l].first_column));
        }

        // Phase 2 backward: G(r,L) expanded; G(r,l+1) shared between Bwd (plain
        // A) and Wgrad (transposed A).
        std::vector<RCGkrOperandRef> g_refs(p.L_lyr + 1);
        g_refs[p.L_lyr] = add_tensor(RCGkrTensor::G, r, p.L_lyr, p.b_seq, p.d_model, false);
        for (int32_t li = static_cast<int32_t>(p.L_lyr) - 1; li >= 0; --li) {
            const uint32_t l = static_cast<uint32_t>(li);
            g_refs[l] = add_layer(RCGkrLayerKind::GemmPhase2Bwd, r, l, p.b_seq, p.d_model,
                                  p.d_model, g_refs[l + 1], w_refs[l], RCGkrTensor::YBwd,
                                  RCGkrTensor::G, p.b_seq, p.d_model, -1);
            (void)add_layer(RCGkrLayerKind::GemmPhase2Wgrad, r, l, p.d_model, p.d_model,
                            p.b_seq, transposed(g_refs[l + 1]), x_refs[l], RCGkrTensor::YWgrad,
                            RCGkrTensor::D, p.d_model, p.d_model, -1);
        }
    }
    assert(out.layers.size() == RCGkrExpectedLayerCount(p));
    return out;
}

uint256 RCGkrFsSeedV7(const CBlockHeader& header, int32_t height, const RCEpisodeParams& params,
                      const arith_uint256& target, const uint256& claimed_digest,
                      const uint256& episode_sigma, const std::vector<uint256>& round_roots)
{
    std::vector<unsigned char> buf;
    // Domain + versions FIRST (blueprint item 7): proof version, domain tag,
    // transcript/FS profile version — all bound before any challenge.
    AppendBytes(buf, reinterpret_cast<const unsigned char*>(kRCGkrDomainTagV7),
                sizeof(kRCGkrDomainTagV7) - 1);
    AppendLE32(buf, kRCGkrProofVersionV7);
    AppendLE32(buf, kRCGkrFsProfileVersionV7);
    // Full header/template binding: EVERY wire field plus the header hash.
    AppendBytes(buf, reinterpret_cast<const unsigned char*>("hdr"), 3);
    AppendLE32(buf, static_cast<uint32_t>(header.nVersion));
    AppendBytes(buf, header.hashPrevBlock.data(), 32);
    AppendBytes(buf, header.hashMerkleRoot.data(), 32);
    AppendLE32(buf, header.nTime);
    AppendLE32(buf, header.nBits);
    AppendLE64(buf, header.nNonce64);
    AppendBytes(buf, header.matmul_digest.data(), 32);
    AppendLE32(buf, header.matmul_dim);
    AppendBytes(buf, header.seed_a.data(), 32);
    AppendBytes(buf, header.seed_b.data(), 32);
    const uint256 hh = header.GetHash();
    AppendBytes(buf, hh.data(), 32);
    // Height.
    AppendBytes(buf, reinterpret_cast<const unsigned char*>("hgt"), 3);
    AppendLE32(buf, static_cast<uint32_t>(height));
    // Exact episode params (all 8 fields — F13-style dims binding).
    AppendBytes(buf, reinterpret_cast<const unsigned char*>("eps"), 3);
    AppendLE32(buf, params.rounds);
    AppendLE32(buf, params.d_head);
    AppendLE32(buf, params.n_q);
    AppendLE32(buf, params.n_ctx);
    AppendLE32(buf, params.L_lyr);
    AppendLE32(buf, params.d_model);
    AppendLE32(buf, params.b_seq);
    AppendLE32(buf, params.T_leaf);
    // Target AND nBits (nBits already in the header block above; target is the
    // expanded work bound actually enforced).
    AppendBytes(buf, reinterpret_cast<const unsigned char*>("tgt"), 3);
    const uint256 tgt = ArithToUint256(target);
    AppendBytes(buf, tgt.data(), 32);
    // Claimed digest + nonce-bound pow_bind + nonce-bound sigma.
    AppendBytes(buf, reinterpret_cast<const unsigned char*>("dig"), 3);
    AppendBytes(buf, claimed_digest.data(), 32);
    const uint256 bind = DerivePowBind(claimed_digest);
    AppendBytes(buf, bind.data(), 32);
    AppendBytes(buf, reinterpret_cast<const unsigned char*>("sig"), 3);
    AppendBytes(buf, episode_sigma.data(), 32);
    // All round roots (count-prefixed).
    AppendBytes(buf, reinterpret_cast<const unsigned char*>("rts"), 3);
    AppendLE32(buf, static_cast<uint32_t>(round_roots.size()));
    for (const auto& rt : round_roots) AppendBytes(buf, rt.data(), 32);
    return Sha256dBytes(buf.data(), buf.size());
}

uint256 RCGkrFsSeedV7Coupled(const CBlockHeader& header, int32_t height,
                             const RCCoupParams& params, const arith_uint256& target,
                             const uint256& claimed_digest, const uint256& sigma,
                             const std::vector<uint256>& barrier_roots)
{
    std::vector<unsigned char> buf;
    AppendBytes(buf, reinterpret_cast<const unsigned char*>(kRCGkrDomainTagV7),
                sizeof(kRCGkrDomainTagV7) - 1);
    // Distinct sub-domain: coupled transcripts can never collide with episode.
    AppendBytes(buf, reinterpret_cast<const unsigned char*>("coupled"), 7);
    AppendLE32(buf, kRCGkrProofVersionV7);
    AppendLE32(buf, kRCGkrFsProfileVersionV7);
    AppendBytes(buf, reinterpret_cast<const unsigned char*>("hdr"), 3);
    AppendLE32(buf, static_cast<uint32_t>(header.nVersion));
    AppendBytes(buf, header.hashPrevBlock.data(), 32);
    AppendBytes(buf, header.hashMerkleRoot.data(), 32);
    AppendLE32(buf, header.nTime);
    AppendLE32(buf, header.nBits);
    AppendLE64(buf, header.nNonce64);
    AppendBytes(buf, header.matmul_digest.data(), 32);
    AppendLE32(buf, header.matmul_dim);
    AppendBytes(buf, header.seed_a.data(), 32);
    AppendBytes(buf, header.seed_b.data(), 32);
    const uint256 hh = header.GetHash();
    AppendBytes(buf, hh.data(), 32);
    AppendBytes(buf, reinterpret_cast<const unsigned char*>("hgt"), 3);
    AppendLE32(buf, static_cast<uint32_t>(height));
    // Exact coupled params.
    AppendBytes(buf, reinterpret_cast<const unsigned char*>("cps"), 3);
    AppendLE32(buf, params.barriers);
    AppendLE32(buf, params.lobes);
    AppendLE32(buf, params.lobe_width);
    AppendLE32(buf, params.bank_pages);
    AppendBytes(buf, reinterpret_cast<const unsigned char*>("tgt"), 3);
    const uint256 tgt = ArithToUint256(target);
    AppendBytes(buf, tgt.data(), 32);
    AppendBytes(buf, reinterpret_cast<const unsigned char*>("dig"), 3);
    AppendBytes(buf, claimed_digest.data(), 32);
    const uint256 bind = DerivePowBind(claimed_digest);
    AppendBytes(buf, bind.data(), 32);
    AppendBytes(buf, reinterpret_cast<const unsigned char*>("sig"), 3);
    AppendBytes(buf, sigma.data(), 32);
    AppendBytes(buf, reinterpret_cast<const unsigned char*>("rts"), 3);
    AppendLE32(buf, static_cast<uint32_t>(barrier_roots.size()));
    for (const auto& rt : barrier_roots) AppendBytes(buf, rt.data(), 32);
    return Sha256dBytes(buf.data(), buf.size());
}

size_t RCGkrExpectedLayerCount(const RCEpisodeParams& p)
{
    return static_cast<size_t>(p.rounds) * (2u + 3u * static_cast<size_t>(p.L_lyr));
}

size_t RCGkrExpectedCoupledLayerCount(const RCCoupParams& p, bool full_bank_schedule)
{
    // Legacy: 1 page per (barrier, lobe). Full schedule: pages_per_barrier_lobe
    // (SelectCoupledBankPageIds returns that many ids; may wrap bank_pages).
    const size_t pages_per =
        full_bank_schedule
            ? std::max<size_t>(1, static_cast<size_t>(p.pages_per_barrier_lobe == 0
                                                          ? dc::kRCCoupPagesPerBarrierLobe
                                                          : p.pages_per_barrier_lobe))
            : 1u;
    return static_cast<size_t>(p.barriers) *
           (static_cast<size_t>(p.lobes) * pages_per + 1u /*Extract*/);
}

// ============================================================================
// v7 layout-driven prover / verifier (blueprint §10). Composes the batched FRI
// + per-layer Thaler sumcheck + §2.4 eval argument + dual-α Extract LogUp +
// §6.3 tile-tree round-root binding. SOUND but not succinct (grounding is
// native re-derivation against the immutable int64 reference; the in-circuit
// ChaCha/SHA/tile-tree AIRs of §5.7/§6.2/§6.3 are the parked succinctness gap).
// Arbiter OFF; nMatMulRCHeight=INT32_MAX; ExactReplay remains sole authority.
// ============================================================================
namespace {

// Little-endian log2 point layout: index = high·2^|low| + low, so the LOW
// coordinate parts occupy the least-significant bits (matches EqFactor /
// MleEvalMatrix). Concatenate low-first, then zero-extend to `nu` (the padded
// batch dimension) — appending 0-coordinates selects the length-preserving
// sub-cube of a zero-padded column (§1.3), so ṽ_padded(point,0…0)=ṽ_logical.
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

// SHA256d(base ‖ every epoch-1 column root) — the eval-argument transcript seed
// (two-epoch discipline: binds all epoch-1 commitments before μ is drawn).
uint256 EvalArgSeed(const uint256& base, const std::vector<FriLayerCommit>& columns,
                    size_t epoch1_count)
{
    std::vector<unsigned char> buf;
    buf.insert(buf.end(), base.begin(), base.end());
    for (size_t i = 0; i < epoch1_count && i < columns.size(); ++i)
        AppendBytes(buf, columns[i].root.data(), 32);
    return Sha256dBytes(buf.data(), buf.size());
}

// Build the flat column list (per layer: A, B, Y, extract_out), matching both
// prover and verifier deterministically from the ground-truth wires.
std::vector<std::vector<Fp2>> BuildV7Columns(const std::vector<LayerWire>& wires)
{
    std::vector<std::vector<Fp2>> cols;
    cols.reserve(wires.size() * 4);
    for (const LayerWire& w : wires) {
        cols.push_back(w.A);
        cols.push_back(w.B);
        cols.push_back(w.Y);
        cols.push_back(ToFp2I8(w.extract_out));
    }
    return cols;
}

// Dual-α Extract LogUp over a bounded sample of real episode tiles (§5.5/§5.6).
// Demonstrates the R3 aggregate on the actual tile lookups and reports the
// Thm-5.2 achieved bits. (Full per-tile coverage + the r16 range instance are
// exercised by matmul_v4_rc_gkr_air_tests; the byte-exactness binding of every
// tile to the immutable reference is enforced separately.)
gkr_air::LogUpVerifyResult ExtractLogUpSample(const std::vector<LayerWire>& wires, Fp2 gamma,
                                              Fp2 alpha1, Fp2 alpha2, uint32_t max_tiles)
{
    gkr_air::TableTM tm_tab;
    gkr_air::TableTX tx_tab;
    gkr_air::LogUpInstance inst_tm, inst_tx;
    uint32_t used = 0;
    for (const LayerWire& w : wires) {
        if (used >= max_tiles) break;
        const uint32_t n_blocks = w.n / kRCMxBlockLen;
        for (uint32_t i = 0; i < w.m && used < max_tiles; ++i) {
            for (uint32_t bj = 0; bj < n_blocks && used < max_tiles; ++bj) {
                gkr_air::TilePublic pub;
                pub.prf_key = w.extract_prf;
                pub.i = i;
                pub.bj = bj;
                std::array<int64_t, kRCMxBlockLen> in{};
                const size_t off = static_cast<size_t>(i) * w.n + bj * kRCMxBlockLen;
                for (uint32_t t = 0; t < kRCMxBlockLen; ++t) in[t] = w.extract_in[off + t];
                const gkr_air::TileWitness tw = gkr_air::TraceTile(pub, in);
                gkr_air::AppendTileLookupsTmTxOnly(tw, tm_tab, tx_tab, gamma, inst_tm, inst_tx);
                ++used;
            }
        }
    }
    // Manual multiplicities for the small tables (avoids the 2^16 r16 blowup;
    // r16 range membership is checked structurally in CheckTileConstraints).
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

// ============================================================================
// SUCCINCT in-circuit grounding (§5.4/§5.7/§6.3). The verifier grounds the
// committed columns WITHOUT running the int64 reference: leaf operands bound to
// seeds by MxExpandAir, chained operands bound to prior extract_out (Λ wiring),
// extract_out bound to extract_in by the Extract sampler AIR over ALL tiles,
// and round_roots bound to the extract stream by the tile-tree AIR. Only PUBLIC
// seeds / prf keys are derived natively (§4.2/§6.1) — never a GEMM or Extract.
// ============================================================================

// Per-operand provenance in the Λ wiring graph.
struct TensorRef {
    bool is_leaf{false};
    uint256 seed;                 // leaf expansion seed
    uint32_t erows{0}, ecols{0};  // untransposed leaf/extract dims
    size_t src_idx{0};            // chained: producing layer index
    bool transpose{false};        // operand = transpose(tensor)
};

struct LayerProv {
    RCGkrLayerKind kind{};
    uint32_t round{0}, layer{0}, m{0}, n{0}, k{0};
    TensorRef a, b;
    uint256 extract_prf{};
    bool fwd_residual{false};     // extract_in = Y + A (H5 residual) when true
};

// Reproduce ONLY the Λ wiring structure of BuildRealEpisodeLayers (public seeds
// + prf + operand provenance). Runs no GEMM and no Extract — cheap and native.
std::vector<LayerProv> RCGkrEpisodeWiring(const CBlockHeader& header, const RCEpisodeParams& p,
                                          const std::vector<uint256>& round_roots)
{
    std::vector<LayerProv> out;
    out.reserve(ExpectedLayerCount(p));
    const uint256 sigma = matmul::v4::DeriveSigma(header);

    for (uint32_t r = 0; r < p.rounds; ++r) {
        const uint256 seed_r =
            (r == 0) ? Sha256TaggedU32(kRCRoundTag, sizeof(kRCRoundTag) - 1, sigma, 0)
                     : Sha256TaggedU32(kRCRoundTag, sizeof(kRCRoundTag) - 1, round_roots[r - 1], r);
        auto operand = [&](const char* tag) { return DeriveOperandSeedLocal(seed_r, tag); };
        const size_t base = out.size();
        const size_t qkt_idx = base + 0;
        std::vector<size_t> fwd_idx(p.L_lyr), bwd_idx(p.L_lyr);
        for (uint32_t l = 0; l < p.L_lyr; ++l) fwd_idx[l] = base + 2 + l;
        for (uint32_t l = 0; l < p.L_lyr; ++l)
            bwd_idx[l] = base + 2 + p.L_lyr + 2 * static_cast<size_t>(p.L_lyr - 1 - l);
        // wg_idx[l] = bwd_idx[l] + 1 (Bwd then Wgrad per iteration).

        auto leaf = [&](const uint256& s, uint32_t er, uint32_t ec, bool tr) {
            TensorRef t; t.is_leaf = true; t.seed = s; t.erows = er; t.ecols = ec; t.transpose = tr;
            return t;
        };
        auto chain = [&](size_t src, uint32_t er, uint32_t ec, bool tr) {
            TensorRef t; t.is_leaf = false; t.src_idx = src; t.erows = er; t.ecols = ec;
            t.transpose = tr; return t;
        };
        // Named tensors resolving to leaf-or-chain.
        auto X_tensor = [&](uint32_t l, bool tr) {
            return (l == 0) ? leaf(operand("BTX_RC_X0_V1"), p.b_seq, p.d_model, tr)
                            : chain(fwd_idx[l - 1], p.b_seq, p.d_model, tr);
        };
        auto G_tensor = [&](uint32_t l, bool tr) { // G[l]
            return (l == p.L_lyr) ? leaf(operand("BTX_RC_GL_V1"), p.b_seq, p.d_model, tr)
                                  : chain(bwd_idx[l], p.b_seq, p.d_model, tr);
        };
        auto W_seed = [&](uint32_t l) {
            char tag[40];
            std::snprintf(tag, sizeof(tag), "BTX_RC_W_%u_V1", l);
            return operand(tag);
        };
        auto prf_tag = [&](const char* fmt, uint32_t l) {
            char tag[40];
            std::snprintf(tag, sizeof(tag), fmt, l);
            return lt::DeriveMatExpandPrfKey(operand(tag));
        };

        // QKt.
        {
            LayerProv lp;
            lp.kind = RCGkrLayerKind::GemmPhase1QKt;
            lp.round = r; lp.layer = 0; lp.m = p.n_q; lp.n = p.n_ctx; lp.k = p.d_head;
            lp.a = leaf(operand("BTX_RC_Q_V1"), p.n_q, p.d_head, false);
            lp.b = leaf(operand("BTX_RC_KV_K_V1"), p.n_ctx, p.d_head, true); // Kᵀ
            lp.extract_prf = lt::DeriveMatExpandPrfKey(operand("BTX_RC_PRF_S_V1"));
            out.push_back(lp);
        }
        // SV.
        {
            LayerProv lp;
            lp.kind = RCGkrLayerKind::GemmPhase1SV;
            lp.round = r; lp.layer = 0; lp.m = p.n_q; lp.n = p.d_head; lp.k = p.n_ctx;
            lp.a = chain(qkt_idx, p.n_q, p.n_ctx, false); // S = extract_out(QKt)
            lp.b = leaf(operand("BTX_RC_KV_V_V1"), p.n_ctx, p.d_head, false);
            lp.extract_prf = lt::DeriveMatExpandPrfKey(operand("BTX_RC_PRF_Z_V1"));
            out.push_back(lp);
        }
        // Fwd layers.
        for (uint32_t l = 0; l < p.L_lyr; ++l) {
            LayerProv lp;
            lp.kind = RCGkrLayerKind::GemmPhase2Fwd;
            lp.round = r; lp.layer = l; lp.m = p.b_seq; lp.n = p.d_model; lp.k = p.d_model;
            lp.a = X_tensor(l, false);
            lp.b = leaf(W_seed(l), p.d_model, p.d_model, true); // Wᵀ
            lp.extract_prf = prf_tag("BTX_RC_PRF_FWD_%u_V1", l);
            lp.fwd_residual = true;
            out.push_back(lp);
        }
        // Bwd + Wgrad (l = L-1 .. 0).
        for (int32_t li = static_cast<int32_t>(p.L_lyr) - 1; li >= 0; --li) {
            const uint32_t l = static_cast<uint32_t>(li);
            {
                LayerProv lp;
                lp.kind = RCGkrLayerKind::GemmPhase2Bwd;
                lp.round = r; lp.layer = l; lp.m = p.b_seq; lp.n = p.d_model; lp.k = p.d_model;
                lp.a = G_tensor(l + 1, false);
                lp.b = leaf(W_seed(l), p.d_model, p.d_model, false);
                lp.extract_prf = prf_tag("BTX_RC_PRF_BWD_%u_V1", l);
                out.push_back(lp);
            }
            {
                LayerProv lp;
                lp.kind = RCGkrLayerKind::GemmPhase2Wgrad;
                lp.round = r; lp.layer = l; lp.m = p.d_model; lp.n = p.d_model; lp.k = p.b_seq;
                lp.a = G_tensor(l + 1, true); // Gᵀ
                lp.b = X_tensor(l, false);
                lp.extract_prf = prf_tag("BTX_RC_PRF_WG_%u_V1", l);
                out.push_back(lp);
            }
        }
    }
    return out;
}

std::vector<int8_t> TransposeI8(const std::vector<int8_t>& src, uint32_t rows, uint32_t cols)
{
    std::vector<int8_t> out(static_cast<size_t>(rows) * cols);
    for (uint32_t i = 0; i < rows; ++i)
        for (uint32_t j = 0; j < cols; ++j)
            out[static_cast<size_t>(j) * rows + i] = src[static_cast<size_t>(i) * cols + j];
    return out;
}

std::vector<std::vector<Fp2>> BuildV7ColumnsFromWitness(
    const std::vector<RCGkrV7WireWitness>& wires)
{
    std::vector<std::vector<Fp2>> cols;
    cols.reserve(wires.size() * 4);
    for (const auto& w : wires) {
        cols.push_back(ToFp2I8(w.A));
        cols.push_back(ToFp2I8(w.B));
        cols.push_back(ToFp2I64(w.Y));
        cols.push_back(ToFp2I8(w.extract_out));
    }
    return cols;
}

// Round stream in the frozen V1 layout (Z ‖ per-layer X_{l+1} ‖ G_l ‖ D_l).
std::vector<int8_t> ReconstructRoundStreamFromWitness(
    const std::vector<RCGkrV7WireWitness>& wires, uint32_t round, const RCEpisodeParams& p)
{
    const size_t lpr = 2u + 3u * static_cast<size_t>(p.L_lyr);
    const size_t base = static_cast<size_t>(round) * lpr;
    const std::vector<int8_t>* z = nullptr;
    std::vector<const std::vector<int8_t>*> fwd(p.L_lyr, nullptr), bwd(p.L_lyr, nullptr),
        wg(p.L_lyr, nullptr);
    for (size_t li = 0; li < lpr; ++li) {
        const RCGkrV7WireWitness& w = wires[base + li];
        switch (w.kind) {
        case RCGkrLayerKind::GemmPhase1SV: z = &w.extract_out; break;
        case RCGkrLayerKind::GemmPhase2Fwd: fwd[w.layer] = &w.extract_out; break;
        case RCGkrLayerKind::GemmPhase2Bwd: bwd[w.layer] = &w.extract_out; break;
        case RCGkrLayerKind::GemmPhase2Wgrad: wg[w.layer] = &w.extract_out; break;
        default: break;
        }
    }
    std::vector<int8_t> stream;
    if (z) stream.insert(stream.end(), z->begin(), z->end());
    for (uint32_t l = 0; l < p.L_lyr; ++l) {
        if (fwd[l]) stream.insert(stream.end(), fwd[l]->begin(), fwd[l]->end());
        if (bwd[l]) stream.insert(stream.end(), bwd[l]->begin(), bwd[l]->end());
        if (wg[l]) stream.insert(stream.end(), wg[l]->begin(), wg[l]->end());
    }
    return stream;
}

struct GroundResult {
    bool ok{false};
    std::string failure;
    uint64_t n_tiles{0};
    uint64_t n_mxexpand_sha{0};
    uint64_t n_tiletree_sha{0};
};

// Bind one committed operand (dims crows×ccols) to its Λ provenance.
bool BindOperand(const TensorRef& ref, const std::vector<int8_t>& committed, uint32_t crows,
                 uint32_t ccols, const std::vector<RCGkrV7WireWitness>& wires,
                 const gkr_air::TableTM& tm, Fp2 gamma, gkr_air::LogUpInstance& inst_tm,
                 uint64_t& n_sha, std::string& why)
{
    if (ref.is_leaf) {
        // Un-transpose the committed column into the untransposed expansion E.
        std::vector<int8_t> cand;
        if (ref.transpose) {
            // committed = Eᵀ (ecols×erows); recover E (erows×ecols).
            cand = TransposeI8(committed, crows, ccols);
        } else {
            cand = committed;
        }
        if (cand.size() != static_cast<size_t>(ref.erows) * ref.ecols) {
            why = "mxexpand:leaf_dims"; return false;
        }
        const gkr_air::MxExpandVerifyResult mr =
            gkr_air::VerifyMxExpandColumn(ref.seed, ref.erows, ref.ecols, cand, tm, gamma, inst_tm);
        n_sha += mr.n_mantissa_blocks + mr.n_scale_blocks;
        if (!mr.ok) { why = mr.failure; return false; }
        return true;
    }
    // Chained: operand equals (transpose of) the source layer's extract_out.
    const std::vector<int8_t>& src = wires[ref.src_idx].extract_out;
    if (src.size() != static_cast<size_t>(ref.erows) * ref.ecols) {
        why = "wiring:chain_src_dims"; return false;
    }
    const std::vector<int8_t> expected =
        ref.transpose ? TransposeI8(src, ref.erows, ref.ecols) : src;
    if (expected != committed) { why = "wiring:chain_mismatch"; return false; }
    (void)crows; (void)ccols;
    return true;
}

GroundResult GroundEpisodeInCircuit(const std::vector<RCGkrV7WireWitness>& wires,
                                    const std::vector<LayerProv>& prov, const RCEpisodeParams& p,
                                    const std::vector<uint256>& round_roots, Fp2 gamma,
                                    gkr_air::LogUpInstance& inst_tm, gkr_air::LogUpInstance& inst_tx)
{
    GroundResult res;
    gkr_air::TableTM tm;
    gkr_air::TableTX tx;

    for (size_t li = 0; li < wires.size(); ++li) {
        const RCGkrV7WireWitness& w = wires[li];
        const LayerProv& lp = prov[li];
        if (lp.kind != w.kind || lp.m != w.m || lp.n != w.n || lp.k != w.k) {
            res.failure = "wiring:layer_mismatch"; return res;
        }
        std::string why;
        // §5.7 operand grounding.
        if (!BindOperand(lp.a, w.A, w.m, w.k, wires, tm, gamma, inst_tm, res.n_mxexpand_sha, why)) {
            res.failure = "A:" + why; return res;
        }
        if (!BindOperand(lp.b, w.B, w.k, w.n, wires, tm, gamma, inst_tm, res.n_mxexpand_sha, why)) {
            res.failure = "B:" + why; return res;
        }
        // extract_in binding: = Y (+ A residual for Fwd). Y is sumcheck-bound.
        if (w.extract_in.size() != static_cast<size_t>(w.m) * w.n ||
            w.Y.size() != static_cast<size_t>(w.m) * w.n) {
            res.failure = "extract_in:size"; return res;
        }
        for (size_t idx = 0; idx < w.extract_in.size(); ++idx) {
            int64_t expect = w.Y[idx];
            if (lp.fwd_residual) expect += static_cast<int64_t>(w.A[idx]);
            if (w.extract_in[idx] != expect) { res.failure = "extract_in:binding"; return res; }
        }
        // Extract sampler AIR over ALL tiles + dual-α LogUp feed.
        const uint32_t n_blocks = w.n / kRCMxBlockLen;
        for (uint32_t i = 0; i < w.m; ++i) {
            for (uint32_t bj = 0; bj < n_blocks; ++bj) {
                gkr_air::TilePublic pub;
                pub.prf_key = lp.extract_prf;
                pub.i = i;
                pub.bj = bj;
                std::array<int64_t, kRCMxBlockLen> in{};
                const size_t off = static_cast<size_t>(i) * w.n + bj * kRCMxBlockLen;
                for (uint32_t t = 0; t < kRCMxBlockLen; ++t) in[t] = w.extract_in[off + t];
                const gkr_air::TileWitness tw = gkr_air::TraceTile(pub, in);
                const gkr_air::TileCheckResult cr = gkr_air::CheckTileConstraints(tw, tm, tx);
                if (!cr.ok) { res.failure = "extract_air:" + cr.failure; return res; }
                for (uint32_t t = 0; t < kRCMxBlockLen; ++t) {
                    if (tw.out[t] != w.extract_out[off + t]) {
                        res.failure = "extract_air:out_binding"; return res;
                    }
                }
                gkr_air::AppendTileLookupsTmTxOnly(tw, tm, tx, gamma, inst_tm, inst_tx);
                ++res.n_tiles;
            }
        }
    }

    // §6.3 tile-tree AIR: round_roots bound to the extract stream in-circuit.
    for (uint32_t r = 0; r < p.rounds; ++r) {
        const std::vector<int8_t> stream = ReconstructRoundStreamFromWitness(wires, r, p);
        const gkr_air::TileTreeCheckResult tr =
            gkr_air::CheckTileTreeInCircuit(stream, p.T_leaf, round_roots[r]);
        res.n_tiletree_sha += tr.n_compressions;
        if (!tr.ok) { res.failure = tr.failure; return res; }
    }

    res.ok = true;
    return res;
}

// Shared v7 prover core: composes the batched FRI + per-layer sumcheck + eval
// argument + dual-α LogUp over the SUPPLIED wires/roots/seeds/digest. Both the
// honest prover (ProveWinnerEpisodeV7) and the internally-consistent-forgery
// helper (ProveMaliciousEpisodeV7ForTest) call this with identical FS ordering,
// so a forgery differs from an honest proof ONLY in the witness it commits — it
// still passes every trivial/algebraic gate and only fails the deep in-circuit
// grounding AIRs (§5.4/§5.7/§6.3) inside VerifyWinnerProofV7.
RCGkrProveResultV7 ProveV7Core(const CBlockHeader& header, const RCEpisodeParams& params,
                               int32_t height, const arith_uint256& target,
                               const uint256& claimed_digest, const uint256& sigma,
                               const std::vector<uint256>& roots,
                               const std::vector<uint256>& seeds,
                               const std::vector<LayerWire>& wires, const char* note)
{
    RCGkrProveResultV7 res;
    RCGkrProofV7& proof = res.proof;
    const auto t0 = std::chrono::steady_clock::now();

    proof.version = kRCGkrProofVersionV7;
    proof.episode = params;
    proof.height = height;
    proof.claimed_digest = claimed_digest;
    proof.pow_bind = DerivePowBind(claimed_digest);
    proof.episode_sigma = sigma;
    proof.round_seeds = seeds;
    proof.round_roots = roots;

    // Carry the committed witness columns for the in-circuit AIRs (§5.4/§5.7/§6.3).
    proof.wires.resize(wires.size());
    for (size_t li = 0; li < wires.size(); ++li) {
        const LayerWire& w = wires[li];
        RCGkrV7WireWitness& ww = proof.wires[li];
        ww.kind = w.kind;
        ww.round = w.round;
        ww.layer = w.layer;
        ww.m = w.m;
        ww.n = w.n;
        ww.k = w.k;
        ww.A = w.A_i8;
        ww.B = w.B_i8;
        ww.Y = w.Y_i64;
        ww.extract_in = w.extract_in;
        ww.extract_out = w.extract_out;
    }

    const uint256 base_seed =
        RCGkrFsSeedV7(header, height, params, target, claimed_digest, sigma, roots);

    // Epoch-1 columns and the batch degree (all toy tensors are single-chunk).
    std::vector<std::vector<Fp2>> columns = BuildV7Columns(wires);
    size_t max_len = 0;
    for (const auto& c : columns) max_len = std::max(max_len, c.size());
    const uint32_t batch_n = FriNextPow2(static_cast<uint32_t>(max_len));
    const uint32_t nu = Log2Exact(batch_n);

    // Per-layer Thaler product sumcheck + collect opening claims.
    FsTranscript fs(kRCGkrDomainTagV7);
    fs.AbsorbUint256(base_seed);
    std::vector<RCGkrOpeningClaim> claims;
    proof.layers.resize(wires.size());
    for (size_t li = 0; li < wires.size(); ++li) {
        const LayerWire& w = wires[li];
        fs.AbsorbU32(static_cast<uint32_t>(li));
        const uint32_t nu_i = Log2Exact(RCGkrNextPow2(w.m));
        const uint32_t nu_j = Log2Exact(RCGkrNextPow2(w.n));
        std::vector<Fp2> ri(nu_i), rj(nu_j);
        for (uint32_t b = 0; b < nu_i; ++b) ri[b] = fs.ChallengeFp2("v7_ri");
        for (uint32_t b = 0; b < nu_j; ++b) rj[b] = fs.ChallengeFp2("v7_rj");

        const Fp2 c_claim = MleEvalMatrix(w.Y, w.m, w.n, ri, rj);
        std::vector<Fp2> rk;
        Fp2 gf;
        RCGkrLayerClaimV7& lc = proof.layers[li];
        lc.sumcheck = ProveProductK(w.A, w.m, w.k, w.B, w.n, ri, rj, c_claim, fs, rk, gf);
        lc.c_claim = c_claim;
        lc.a_eval = MleEvalMatrix(w.A, w.m, w.k, ri, rk);
        lc.b_eval = MleEvalMatrix(w.B, w.k, w.n, rk, rj);
        lc.final_eval = gf; // == a_eval·b_eval for A·B==Y wires (honest OR forged)

        const uint32_t a_col = static_cast<uint32_t>(4 * li);
        const uint32_t b_col = a_col + 1;
        const uint32_t y_col = a_col + 2;
        claims.push_back({y_col, PointConcatExtend(rj, ri, nu), c_claim});
        claims.push_back({a_col, PointConcatExtend(rk, ri, nu), lc.a_eval});
        claims.push_back({b_col, PointConcatExtend(rj, rk, nu), lc.b_eval});
    }

    // §2.4 eval argument: f,g committed inside the SAME batched FRI.
    std::vector<FriLayerCommit> epoch1_roots(columns.size());
    for (size_t i = 0; i < columns.size(); ++i)
        epoch1_roots[i].root = FriBatchColumnRoot(columns[i], batch_n);
    const uint256 eval_seed = EvalArgSeed(base_seed, epoch1_roots, columns.size());
    const auto ev = EvalArgumentProve(claims, columns, eval_seed);
    if (!ev.ok) {
        res.timing.ok = false;
        res.timing.note = "eval arg prove: " + ev.note;
        return res;
    }
    proof.eval = ev.proof;
    columns.push_back(ev.f_coeffs);
    columns.push_back(ev.g_coeffs);

    const auto bc = FriBatchCommit(columns, base_seed);
    if (!bc.ok) {
        res.timing.ok = false;
        res.timing.note = "batch commit: " + bc.note;
        return res;
    }
    proof.batch = bc.proof;

    // Dual-α Extract LogUp (FS-bound challenges).
    fs.AbsorbBytes(reinterpret_cast<const unsigned char*>("logup"), 5);
    const Fp2 gamma = fs.ChallengeFp2("v7_gamma");
    proof.logup_alpha1 = fs.ChallengeFp2("v7_alpha1");
    proof.logup_alpha2 = fs.ChallengeFp2("v7_alpha2");
    const auto lr = ExtractLogUpSample(wires, gamma, proof.logup_alpha1, proof.logup_alpha2,
                                       /*max_tiles=*/16);
    proof.logup_bits = lr.achieved_bits;

    proof.transcript_hash = fs.Digest();
    proof.note = note;

    const auto t1 = std::chrono::steady_clock::now();
    res.timing.prove_s = std::chrono::duration<double>(t1 - t0).count();
    res.timing.ok = true;
    res.timing.over_budget = res.timing.prove_s > kRCGkrMediumProveBudgetS;
    proof.over_budget = false; // verify is succinct: in-circuit AIRs, no reference re-run
    res.timing.note = proof.note;
    return res;
}

} // namespace

RCGkrProveResultV7 ProveWinnerEpisodeV7(const CBlockHeader& header, const RCEpisodeParams& params,
                                        int32_t height, const arith_uint256& target,
                                        const uint256& claimed_digest)
{
    if (!ValidateRCEpisodeParams(params)) {
        RCGkrProveResultV7 res;
        res.timing.ok = false;
        res.timing.note = "invalid params";
        return res;
    }

    // Ground truth: run the immutable int64 reference for round roots + digest.
    std::vector<RCRoundTranscript> transcripts;
    const uint256 true_digest =
        RecomputeResidentCurriculumReference(header, params, height, {}, &transcripts);
    (void)true_digest;
    std::vector<uint256> roots(params.rounds);
    for (uint32_t r = 0; r < params.rounds; ++r) roots[r] = transcripts[r].round_root;
    const uint256 sigma = matmul::v4::DeriveSigma(header);
    std::vector<uint256> seeds;
    const std::vector<LayerWire> wires = BuildRealEpisodeLayers(header, params, roots, seeds);

    return ProveV7Core(
        header, params, height, target, claimed_digest, sigma, roots, seeds, wires,
        "v7 SUCCINCT: batched FRI + sumcheck + eval-arg + in-circuit Extract/MxExpand/"
        "tile-tree AIRs over committed columns (no int64-reference re-derivation)");
}

namespace {

// Rebuild a LayerWire's Fp2 mirrors from its int8/int64 witness after a forge.
void ResyncV7WireFp2(LayerWire& w)
{
    w.A = ToFp2I8(w.A_i8);
    w.B = ToFp2I8(w.B_i8);
    w.Y = ToFp2I64(w.Y_i64);
}

bool IsForgeableGemm(const LayerWire& w)
{
    return !w.extract_only && w.k > 0 && !w.A_i8.empty() && !w.B_i8.empty() && !w.Y_i64.empty();
}

} // namespace

// Test/audit-only INTERNALLY-CONSISTENT v7 forgery constructor. Unlike the v6
// ProveIndepMalicious*ForTest (which target the PARKED v6 verifier) and unlike a
// bit-flip of an honest proof (which dies at a trivial consistency gate), this
// runs the FULL honest v7 prover machinery (ProveV7Core: columns → sumcheck →
// eval-arg → batched FRI → LogUp → transcript) over a FABRICATED witness. The
// resulting RCGkrProofV7 is internally consistent: it passes pow_bind, the
// header/digest/sigma binding, digest_from_roots, the round-seed chain, the Λ
// layout, column_not_grounded, FriBatchVerify, the per-layer sumcheck,
// final_eval endpoint/product, the eval argument, and the FS-bound LogUp α's.
// It can therefore only be rejected by the DEEP security mechanism — the
// in-circuit MxExpand / Extract-sampler / tile-tree grounding AIRs. Reaching
// that mechanism for the committed-witness kinds REQUIRES running the honest
// prover here (doing the work): the attacker cannot forge these cheaply.
RCGkrProveResultV7 ProveMaliciousEpisodeV7ForTest(const CBlockHeader& header,
                                                  const RCEpisodeParams& params, int32_t height,
                                                  const arith_uint256& target,
                                                  const uint256& claimed_digest,
                                                  RCGkrIndepMaliciousKind kind)
{
    if (!ValidateRCEpisodeParams(params)) {
        RCGkrProveResultV7 res;
        res.timing.ok = false;
        res.timing.note = "invalid params";
        return res;
    }

    std::vector<RCRoundTranscript> transcripts;
    (void)RecomputeResidentCurriculumReference(header, params, height, {}, &transcripts);
    std::vector<uint256> roots(params.rounds);
    for (uint32_t r = 0; r < params.rounds; ++r) roots[r] = transcripts[r].round_root;
    const uint256 sigma = matmul::v4::DeriveSigma(header);
    std::vector<uint256> seeds;
    std::vector<LayerWire> wires = BuildRealEpisodeLayers(header, params, roots, seeds);
    uint256 digest = claimed_digest; // == EpisodeDigestFromRoots(real roots)

    switch (kind) {
    case RCGkrIndepMaliciousKind::ArbitraryAbFactorization: {
        // Present an ALTERNATE exact factorization of the SAME product Y at ONE
        // GEMM layer: swap columns (c0,c1) of A and rows (c0,c1) of B. A·B is
        // unchanged (the k-sum is reordered), so the GEMM sumcheck, c_claim,
        // final_eval and the eval argument all stay consistent, AND Y / extract
        // / round_roots / tile-tree are byte-identical to the honest episode. The
        // ONLY thing that changed is the committed operand factorization — which
        // is NOT the Λ MxExpand expansion. Must die at the operand grounding AIR.
        bool done = false;
        for (auto& w : wires) {
            if (!IsForgeableGemm(w) || w.k < 2) continue;
            for (uint32_t c1 = 1; c1 < w.k && !done; ++c1) {
                // Try to find a column pair (0,c1) that actually differs.
                bool differs = false;
                for (uint32_t i = 0; i < w.m; ++i)
                    if (w.A_i8[static_cast<size_t>(i) * w.k + 0] !=
                        w.A_i8[static_cast<size_t>(i) * w.k + c1]) { differs = true; break; }
                if (!differs) continue;
                for (uint32_t i = 0; i < w.m; ++i)
                    std::swap(w.A_i8[static_cast<size_t>(i) * w.k + 0],
                              w.A_i8[static_cast<size_t>(i) * w.k + c1]);
                for (uint32_t j = 0; j < w.n; ++j)
                    std::swap(w.B_i8[static_cast<size_t>(0) * w.n + j],
                              w.B_i8[static_cast<size_t>(c1) * w.n + j]);
                ResyncV7WireFp2(w);
                done = true;
            }
            if (done) break;
        }
        break;
    }
    case RCGkrIndepMaliciousKind::FabricatedTraceWires: {
        // Self-consistent GEMM wires (constant fills) UNBOUND to the episode PRF
        // expansion: Y = A·B is recomputed so the sumcheck is valid, but the
        // operands are not the Λ leaf expansion. Must die at operand grounding.
        for (auto& w : wires) {
            if (!IsForgeableGemm(w)) continue;
            w.A_i8.assign(static_cast<size_t>(w.m) * w.k, 3);
            w.B_i8.assign(static_cast<size_t>(w.k) * w.n, 5);
            ExactInt64Gemm(w.A_i8, w.m, w.k, w.B_i8, w.n, w.Y_i64);
            w.extract_in = w.Y_i64; // sizes preserved; grounding fails earlier at A
            ResyncV7WireFp2(w);
        }
        break;
    }
    case RCGkrIndepMaliciousKind::IdenticalFabricatedLookup: {
        // Operands + Y are the REAL episode (so operand grounding + extract_in
        // binding pass), but extract_out is a prover-chosen constant witness. The
        // verifier-defined Extract sampler AIR recomputes TraceTile(extract_in)
        // and must reject the fabricated output → extract_air:out_binding.
        for (auto& w : wires) {
            if (w.extract_out.empty()) continue;
            w.extract_out.assign(w.extract_out.size(), 7);
        }
        break;
    }
    case RCGkrIndepMaliciousKind::FabricatedExtractIO: {
        // Fabricate the (non-committed) pre-Extract accumulator extract_in. It is
        // NOT a committed column, so every algebraic gate still passes; the
        // §5.7 binding extract_in == Y (+ Fwd residual) is the mechanism that
        // rejects → extract_in:binding.
        for (auto& w : wires) {
            if (w.extract_in.empty()) continue;
            w.extract_in[0] += 123456; // unbind from the sumcheck-proven Y
            break;
        }
        break;
    }
    case RCGkrIndepMaliciousKind::UnrelatedLayerRoots: {
        // Prover-chosen round_roots UNRELATED to the committed extract stream.
        // Forge the LAST round root (no operand seed depends on roots[last]), then
        // re-seal claimed_digest = EpisodeDigestFromRoots(forged) and re-chain the
        // round seeds so digest_from_roots + the seed chain still pass. Operands
        // still ground (round-0 seeds derive from sigma); the §6.3 tile-tree AIR
        // that binds round_roots to the extract stream is the mechanism → dies at
        // the tile-tree grounding.
        const uint32_t last = params.rounds - 1;
        roots[last] = Sha256TaggedU32(kRCRoundTag, sizeof(kRCRoundTag) - 1, roots[last], 0xBADBAD);
        digest = EpisodeDigestFromRoots(roots);
        for (uint32_t r = 0; r < params.rounds; ++r) {
            seeds[r] = (r == 0)
                           ? Sha256TaggedU32(kRCRoundTag, sizeof(kRCRoundTag) - 1, sigma, 0)
                           : Sha256TaggedU32(kRCRoundTag, sizeof(kRCRoundTag) - 1, roots[r - 1], r);
        }
        break;
    }
    case RCGkrIndepMaliciousKind::UnrelatedBankPages:
    case RCGkrIndepMaliciousKind::OmittedPages:
    case RCGkrIndepMaliciousKind::DuplicatedPages:
    case RCGkrIndepMaliciousKind::WrongM:
    case RCGkrIndepMaliciousKind::WrongExchangeTranscript:
    case RCGkrIndepMaliciousKind::CrossVersionReplay:
        // Coupled-only kinds: the episode API has no bank pages / page schedule /
        // rows_per_lobe / exchange transcript / coupled version, so they are not
        // constructible here. Fall through to the fabricated-trace behaviour so the
        // helper is total (any coupled kind mis-routed to the episode constructor
        // still yields a rejected proof, exercised via the coupled constructor).
        for (auto& w : wires) {
            if (!IsForgeableGemm(w)) continue;
            w.A_i8.assign(static_cast<size_t>(w.m) * w.k, 1);
            w.B_i8.assign(static_cast<size_t>(w.k) * w.n, -1);
            ExactInt64Gemm(w.A_i8, w.m, w.k, w.B_i8, w.n, w.Y_i64);
            w.extract_in = w.Y_i64;
            ResyncV7WireFp2(w);
        }
        break;
    }

    // The FS seed binds header.matmul_digest (RCGkrFsSeedV7). Prove under a header
    // that commits the (possibly re-sealed) digest so the verifier — which the
    // test calls with header.matmul_digest == proof.claimed_digest — recomputes
    // the identical base_seed. matmul_digest is NOT part of sigma/roots, so this
    // does not perturb the episode wiring or the round roots.
    CBlockHeader hdr = header;
    hdr.matmul_digest = digest;
    auto res = ProveV7Core(hdr, params, height, target, digest, sigma, roots, seeds, wires,
                           RCGkrIndepMaliciousGapNote(kind));
    if (res.timing.ok) res.timing.note = RCGkrIndepMaliciousGapNote(kind);
    return res;
}

// ============================================================================
// G1–G5 IN-CIRCUIT RELATIONS — the four constructions wired over the committed
// columns. Runs STANDALONE from the proof (re-derives the sumcheck points and
// its own challenges), so an internally-consistent forgery is caught by the
// construction identities and not only by the native §5 re-derivation. Every
// identity below vanishes for the honest witness; each failing class of forgery
// is named at its "v7:g<N>:" relation. Arbiter stays OFF; ExactReplay decides.
// ============================================================================
namespace {

inline constexpr char kRCGkrRelDomainTagV7[] = "BTX_RC_GKR_RELV7";

RCGkrRelationsResult CheckWinnerProofRelationsV7Impl(const RCGkrProofV7& proof,
                                                    const CBlockHeader& header, int32_t height,
                                                    const arith_uint256& target,
                                                    bool assume_grounded)
{
    RCGkrRelationsResult r;
    auto fail = [&](RCGkrRelation rel, const std::string& detail) {
        r.ok = false;
        r.first_failing = rel;
        const int n = static_cast<int>(rel);
        r.failure = "v7:g" + std::to_string(n) + ":" + detail;
        return r;
    };

    // Shape gates (mirror VerifyWinnerProofV7 so the module is self-standing).
    if (proof.round_roots.size() != proof.episode.rounds) return fail(RCGkrRelation::G2, "roots_size");
    const std::vector<uint256>& roots = proof.round_roots;
    const uint32_t batch_n = proof.batch.n_coeffs;
    if (batch_n == 0 || (batch_n & (batch_n - 1)) != 0) return fail(RCGkrRelation::G1, "batch_n");

    const std::vector<LayerProv> prov = RCGkrEpisodeWiring(header, proof.episode, roots);
    if (prov.size() != proof.wires.size()) return fail(RCGkrRelation::G1, "wiring_count");

    const uint256 base_seed = RCGkrFsSeedV7(header, height, proof.episode, target,
                                            proof.claimed_digest, proof.episode_sigma, roots);

    // Module-local challenges (independent of the main transcript; soundness only
    // needs uniform-random draws — the FS-binding of the shipped α's is a
    // separate gate in VerifyWinnerProofV7). eta: G3 composition; gamma: G3
    // fingerprint; alpha1/alpha2: G3 dual-α membership.
    FsTranscript rel_fs(kRCGkrRelDomainTagV7);
    rel_fs.AbsorbUint256(base_seed);
    const Fp2 eta = rel_fs.ChallengeFp2("g3_eta");
    const Fp2 gamma = rel_fs.ChallengeFp2("g3_gamma");
    const Fp2 alpha1 = rel_fs.ChallengeFp2("g3_alpha1");
    const Fp2 alpha2 = rel_fs.ChallengeFp2("g3_alpha2");

    gkr_air::TableTM tm_tab;
    gkr_air::TableTX tx_tab;
    // G3 membership instances — populated ONLY by AppendTileLookups so their table
    // sides are exactly the canonical fixed reference vectors (Construction III).
    gkr_air::LogUpInstance inst_tm, inst_tx;
    // G1 operand grounding uses VerifyMxExpandColumn only for its in-circuit bool;
    // its LogUp feed goes to a throwaway so it never perturbs the G3 instances.
    gkr_air::LogUpInstance g1_mx_scratch;

    // ---- Per-layer sumcheck-point relations: G1 (operands), G2 (claim), G5. ----
    FsTranscript fs(kRCGkrDomainTagV7);
    fs.AbsorbUint256(base_seed);
    for (size_t li = 0; li < proof.wires.size(); ++li) {
        const RCGkrV7WireWitness& w = proof.wires[li];
        const RCGkrLayerClaimV7& lc = proof.layers[li];
        const LayerProv& lp = prov[li];
        fs.AbsorbU32(static_cast<uint32_t>(li));
        const uint32_t nu_i = Log2Exact(RCGkrNextPow2(std::max(w.m, 1u)));
        const uint32_t nu_j = Log2Exact(RCGkrNextPow2(std::max(w.n, 1u)));
        std::vector<Fp2> ri(nu_i), rj(nu_j);
        for (uint32_t b = 0; b < nu_i; ++b) ri[b] = fs.ChallengeFp2("v7_ri");
        for (uint32_t b = 0; b < nu_j; ++b) rj[b] = fs.ChallengeFp2("v7_rj");
        std::vector<Fp2> rk;
        Fp2 gf;
        if (!VerifyProductK(lc.sumcheck, lc.c_claim, fs, rk, gf))
            return fail(RCGkrRelation::G1, "sumcheck_endpoint"); // cannot re-derive the point

        // -- G1: bind a_at_r/b_at_r to the committed A/B columns (Construction I
        //    matrix-opening claim points) + the final-eval binding (Thm 3.1). --
        const std::vector<Fp2> a_col = ToFp2I8(w.A);
        const std::vector<Fp2> b_col = ToFp2I8(w.B);
        const Fp2 a_at_r = MleEvalMatrix(a_col, w.m, w.k, ri, rk);
        const Fp2 b_at_r = MleEvalMatrix(b_col, w.k, w.n, rk, rj);
        if (!Eq(a_at_r, lc.a_eval)) return fail(RCGkrRelation::G1, "a_open");
        if (!Eq(b_at_r, lc.b_eval)) return fail(RCGkrRelation::G1, "b_open");
        if (!RCGkrCheckFinalEvalBinding(gf, a_at_r, b_at_r))
            return fail(RCGkrRelation::G1, "final_eval");

        // -- G1 (operand→PRF): each LEAF operand column bound to its Λ MxExpand
        //    expansion (an alternate factorization / fabricated leaf is not the
        //    PRF expansion). Chained operands are G4.
        //
        // VerifyWinnerProofV7 already ran GroundEpisodeInCircuit immediately
        // before this relation pass. In that verified-grounded path, re-running
        // leaf MxExpand here only duplicates SHA/AIR work and cannot add a new
        // accept/reject condition. Keep the full work in the standalone relation
        // checker used by tests/audits.
        if (!assume_grounded) {
            uint64_t n_sha = 0;
            std::string why;
            if (lp.a.is_leaf &&
                !BindOperand(lp.a, w.A, w.m, w.k, proof.wires, tm_tab, gamma, g1_mx_scratch, n_sha,
                             why))
                return fail(RCGkrRelation::G1, "A_mxexpand:" + why);
            if (lp.b.is_leaf &&
                !BindOperand(lp.b, w.B, w.k, w.n, proof.wires, tm_tab, gamma, g1_mx_scratch, n_sha,
                             why))
                return fail(RCGkrRelation::G1, "B_mxexpand:" + why);
        }

        // -- G2: layer claim c_ℓ bound to the committed Y trace-column segment
        //    (Construction I segment point; single segment ⇒ index 0). --
        const std::vector<Fp2> y_col = ToFp2I64(w.Y);
        const Fp2 c_at_r = MleEvalMatrix(y_col, w.m, w.n, ri, rj);
        if (!Eq(c_at_r, lc.c_claim)) return fail(RCGkrRelation::G2, "claim_segment");

        // -- G5: residual accumulator binding acc = claim + X̃(pt) (Fwd), or
        //    extract_in == Y for the non-residual layers (Construction I residual
        //    binder). Only where the committed accumulator exists. --
        if (w.extract_in.size() == static_cast<size_t>(w.m) * w.n) {
            const Fp2 acc_at_r = MleEvalMatrix(ToFp2I64(w.extract_in), w.m, w.n, ri, rj);
            if (lp.fwd_residual) {
                // X̃ is the SAME committed operand A used as the Fwd input (k == n).
                const Fp2 x_at_r = MleEvalMatrix(a_col, w.m, w.n, ri, rj);
                if (!RCGkrCheckResidualAcc(acc_at_r, c_at_r, x_at_r))
                    return fail(RCGkrRelation::G5, "residual_acc");
            } else if (!Eq(acc_at_r, c_at_r)) {
                return fail(RCGkrRelation::G5, "extract_in_eq_claim");
            }
        }

        // -- G3 (per tile): Construction II Extract composition polynomial ==0 and
        //    the verifier-defined sampler out-binding, plus feed Construction III
        //    membership witnesses. --
        if (!assume_grounded && w.n % kRCMxBlockLen == 0 &&
            w.extract_out.size() == static_cast<size_t>(w.m) * w.n &&
            w.extract_in.size() == static_cast<size_t>(w.m) * w.n) {
            const uint32_t n_blocks = w.n / kRCMxBlockLen;
            for (uint32_t i = 0; i < w.m; ++i) {
                for (uint32_t bj = 0; bj < n_blocks; ++bj) {
                    gkr_air::TilePublic pub;
                    pub.prf_key = lp.extract_prf;
                    pub.i = i;
                    pub.bj = bj;
                    std::array<int64_t, kRCMxBlockLen> in{};
                    const size_t off = static_cast<size_t>(i) * w.n + bj * kRCMxBlockLen;
                    for (uint32_t t = 0; t < kRCMxBlockLen; ++t) in[t] = w.extract_in[off + t];
                    const gkr_air::TileWitness tw = gkr_air::TraceTile(pub, in);
                    // Construction II: composition polynomial over the committed cells.
                    const gkr_air::RCAirConstraintSet cs = gkr_air::EmitTileConstraints(tw);
                    const gkr_air::CompositionResult comp = gkr_air::ComposeConstraints(cs, eta);
                    if (!comp.ok)
                        return fail(RCGkrRelation::G3, "composition:" + comp.first_bad_families);
                    // Sampler out-binding: the AIR-produced output must equal the
                    // committed extract_out (a prover-chosen output is rejected here).
                    for (uint32_t t = 0; t < kRCMxBlockLen; ++t) {
                        if (tw.out[t] != w.extract_out[off + t])
                            return fail(RCGkrRelation::G3, "extract_out_binding");
                    }
                    gkr_air::AppendTileLookupsTmTxOnly(tw, tm_tab, tx_tab, gamma, inst_tm,
                                                       inst_tx);
                    ++r.n_tiles;
                }
            }
        }
    }

    // -- G3 (aggregate): Construction III fixed-reference-vector membership. The
    //    table sides are REGENERATED from consensus constants (never prover
    //    data), closing the Theorem-5.1 clone-table vacuity; witnesses are the
    //    fingerprints emitted above. T_R16 range is carried structurally by the
    //    composition (matches the shipped sample path), so membership runs over
    //    {T_M, T_X}. --
    if (!assume_grounded) {
        auto finalize = [](gkr_air::LogUpInstance& in) {
            in.table_mult.assign(in.table.size(), 0);
            for (const Fp2& wt : in.witness)
                for (size_t j = 0; j < in.table.size(); ++j)
                    if (gkr_field::Eq(wt, in.table[j])) { in.table_mult[j] += 1; break; }
        };
        finalize(inst_tm);
        finalize(inst_tx);
        {
            std::vector<gkr_air::LogUpInstance> insts{inst_tm, inst_tx};
            const gkr_air::LookupBindResult lr =
                gkr_air::VerifyLookupAgainstPreprocessed(insts, gamma, alpha1, alpha2);
            if (!lr.ok) return fail(RCGkrRelation::G3, "membership:" + lr.failure);
        }
    }

    // -- G4: extract_out(L) == input(L+1) copy/permutation wiring (Construction
    //    IV), over the TRUE Λ provenance. Direct copies use the equality identity
    //    (Schwartz–Zippel MLE); transposed copies use the DUAL-challenge grand
    //    product (the single-challenge form is never constructed here). --
    auto bind_chain = [&](const TensorRef& ref, const std::vector<int8_t>& committed,
                          uint32_t crows, uint32_t ccols, uint32_t idx, std::string& why) -> bool {
        (void)crows;
        (void)ccols; // dims come from ref.erows/ecols; kept for call-site symmetry
        if (ref.is_leaf) return true; // leaf operands are G1 (MxExpand), not wiring
        if (ref.src_idx >= proof.wires.size()) { why = "chain_src_oob"; return false; }
        const std::vector<int8_t>& src = proof.wires[ref.src_idx].extract_out;
        if (src.size() != static_cast<size_t>(ref.erows) * ref.ecols) { why = "chain_src_dims"; return false; }
        ++r.n_chain_wirings;
        if (!ref.transpose) {
            // Direct copy: committed == src.
            const WiringEqualityConstraint c = WiringEqualityFromInt8(src, committed);
            const WiringVerifyResult vr = VerifyWiringEquality(c, base_seed, idx);
            if (!vr.ok) { why = "equality:" + vr.reason; return false; }
            return true;
        }
        // Transposed copy: committed == Transpose(src). DUAL grand product with
        // the materialized transpose permutation (mandatory — single-challenge is
        // 60 bits at κ, below target).
        const std::vector<Fp2> u = ToFp2I8(src);
        const std::vector<Fp2> v = ToFp2I8(committed);
        const std::vector<uint64_t> pi = MakeTransposePermutation(ref.erows, ref.ecols);
        if (v.size() != u.size() || pi.size() != u.size()) { why = "transpose_shape"; return false; }
        const WiringPermutationDual d = BuildWiringPermutationDual(u, v, pi, base_seed, idx);
        const WiringVerifyResult vr = VerifyWiringPermutationDual(d);
        if (!vr.ok) { why = "permutation_dual:" + vr.reason; return false; }
        return true;
    };
    if (!assume_grounded) {
        for (size_t li = 0; li < proof.wires.size(); ++li) {
            const RCGkrV7WireWitness& w = proof.wires[li];
            const LayerProv& lp = prov[li];
            std::string why;
            if (!bind_chain(lp.a, w.A, w.m, w.k, static_cast<uint32_t>(4 * li + 0), why))
                return fail(RCGkrRelation::G4, "A:" + why);
            if (!bind_chain(lp.b, w.B, w.k, w.n, static_cast<uint32_t>(4 * li + 1), why))
                return fail(RCGkrRelation::G4, "B:" + why);
        }
    }

    // -- G4 (§6.3 companion): the round_roots must be the tile-tree commitment of
    //    the reconstructed extract stream (a Construction-IV-style binding of the
    //    per-round stream to its public root). Catches prover-chosen roots. --
    if (!assume_grounded) {
        for (uint32_t rr = 0; rr < proof.episode.rounds; ++rr) {
            const std::vector<int8_t> stream =
                ReconstructRoundStreamFromWitness(proof.wires, rr, proof.episode);
            const gkr_air::TileTreeCheckResult tr =
                gkr_air::CheckTileTreeInCircuit(stream, proof.episode.T_leaf, roots[rr]);
            if (!tr.ok) return fail(RCGkrRelation::G4, "tiletree:" + tr.failure);
        }
    }

    r.ok = true;
    return r;
}

} // namespace

RCGkrRelationsResult CheckWinnerProofRelationsV7(const RCGkrProofV7& proof,
                                                 const CBlockHeader& header, int32_t height,
                                                 const arith_uint256& target)
{
    // Structural pre-gates that the impl assumes (kept out of the identity core).
    RCGkrRelationsResult r;
    if (proof.version != kRCGkrProofVersionV7) {
        r.failure = "v7:g1:version";
        return r;
    }
    if (!ValidateRCEpisodeParams(proof.episode)) {
        r.failure = "v7:g1:params_invalid";
        return r;
    }
    const RCGkrLayout layout = RCGkrTraceLayout(proof.episode);
    if (proof.wires.size() != layout.layers.size() ||
        proof.layers.size() != layout.layers.size()) {
        r.failure = "v7:g2:layer_count";
        return r;
    }
    for (size_t li = 0; li < layout.layers.size(); ++li) {
        const auto& w = proof.wires[li];
        if (w.A.size() != static_cast<size_t>(w.m) * w.k ||
            w.B.size() != static_cast<size_t>(w.k) * w.n ||
            w.Y.size() != static_cast<size_t>(w.m) * w.n) {
            r.failure = "v7:g1:wire_shape";
            return r;
        }
    }
    return CheckWinnerProofRelationsV7Impl(proof, header, height, target,
                                          /*assume_grounded=*/false);
}

RCGkrRelationsResult CheckWinnerProofRelationsV7AfterGrounding(const RCGkrProofV7& proof,
                                                               const CBlockHeader& header,
                                                               int32_t height,
                                                               const arith_uint256& target)
{
    return CheckWinnerProofRelationsV7Impl(proof, header, height, target,
                                          /*assume_grounded=*/true);
}

bool VerifyWinnerRelationsV7ForTest(const RCGkrProofV7& proof, const CBlockHeader& header,
                                    int32_t height, const arith_uint256& target, std::string* why)
{
    const RCGkrRelationsResult r = CheckWinnerProofRelationsV7(proof, header, height, target);
    if (why) *why = r.ok ? std::string("v7 g1-g5 relations ok") : r.failure;
    return r.ok;
}

// COMPOSED separation bound: −log2(Σ 2^-term) over the four constructions + the
// batched-FRI backend + SHA256d, PARAMETRIC in the FRI proximity bits.
RCGkrComposedBound RCGkrComposedSeparation(double fri_proximity_bits)
{
    RCGkrComposedBound b;
    b.construction_i_bits = static_cast<double>(RCGkrConstructionISeparationBits()); // 74
    b.construction_ii_bits = kRCGkrCompositionSepBits;                                // 80
    b.construction_iii_bits = kRCGkrLookupSepBits;                                    // 128
    b.construction_iv_bits =
        std::min(kRCGkrWiringEqualitySepBits, kRCGkrWiringPermutationDualSepBits);    // 83.19
    b.wiring_single_bits = kRCGkrWiringPermutationSingleSepBits;                      // 60
    b.fri_proximity_bits = fri_proximity_bits;
    b.sha_bits = kRCGkrShaSepBits;                                                    // 88

    // ε_total = Σ 2^-term ; composed = −log2(ε_total) via a stable log-sum-exp.
    // Construction I (its FS-side sub-bound, 74) is ABSORBED into the whole-
    // protocol FS subtotal (kRCGkrFsSubtotalSepBits = 72; the eval opening
    // rides the same sumcheck rows), so it is reported but not summed twice.
    const double terms[] = {kRCGkrFsSubtotalSepBits, b.construction_ii_bits,
                            b.construction_iii_bits, b.construction_iv_bits,
                            b.fri_proximity_bits,    b.sha_bits};
    double lo = terms[0];
    for (double t : terms) lo = std::min(lo, t);
    double sum = 0.0;
    for (double t : terms) sum += std::pow(2.0, -(t - lo));
    b.composed_bits = lo - std::log2(sum);

    b.margin_bits = b.composed_bits - static_cast<double>(kRCFriTargetSoundnessBits);
    b.clears_target = b.composed_bits >= static_cast<double>(kRCFriTargetSoundnessBits);
    // FRI-dominated iff the (parametric) FRI proximity term is the smallest.
    // At Q=128 / Fp2 it is NOT: the FS subtotal (72) sits below the FRI floor
    // (76.80), so the composed bound is FS-dominated at ≈ 71.9.
    b.fri_dominated = (lo == b.fri_proximity_bits);
    // INADEQUATE for consensus authority if the margin over 64 is < 2 bits.
    // At Q=128 / Fp2 the margin is ≈ 7.9 bits ⇒ adequate (it was ≈ 1.8 at
    // Q=116/Fp2 — inadequate). Arbiter stays hard-disabled regardless.
    b.inadequate_margin = b.margin_bits < kRCGkrAdequateMarginBits;
    b.any_term_below_target = false;
    for (double t : terms)
        if (t < static_cast<double>(kRCFriTargetSoundnessBits)) b.any_term_below_target = true;
    return b;
}

double RCGkrComposedSeparationBits(double fri_proximity_bits)
{
    return RCGkrComposedSeparation(fri_proximity_bits).composed_bits;
}

double RCGkrComposedSeparationBits()
{
    // SHIPPED: sound v5 fold, Q=128, Fp2 challenges. Raising Q to 128 lifted
    // the FRI floor (65.85 → 76.80, field-independent) ABOVE the Fp2 FS
    // subtotal (72), so the composed bound is now FS-dominated at ≈ 71.9 bits
    // (ε_total ≤ 2^-71.9), clearing the 2^-64 target by ≈ 7.9 bits (adequate).
    // Reaching the 74-bit bar (≈ 76.8) needs the DEFERRED Fp3 challenge
    // cutover (INTEGRATION_REPORT.md); see the header note. (Historical
    // Q=116/Fp2: ≈ 65.8, inadequate.)
    return RCGkrComposedSeparationBits(kRCGkrFriProximityBitsV5);
}

bool VerifyWinnerProofV7(const RCGkrProofV7& proof, const CBlockHeader& header, int32_t height,
                         const arith_uint256& target, std::string* why, RCGkrTiming* out_timing)
{
    const auto t0 = std::chrono::steady_clock::now();
    auto fail = [&](const std::string& m) {
        if (why) *why = m;
        if (out_timing) {
            out_timing->ok = false;
            out_timing->verify_s =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            out_timing->note = m;
        }
        return false;
    };
    if (proof.version != kRCGkrProofVersionV7) return fail("v7:version");
    if (!ValidateRCEpisodeParams(proof.episode)) return fail("v7:params_invalid");
    if (proof.height != height) return fail("v7:height");

    // §6.1 native: pow_bind, claimed digest bound to the header, target check.
    if (proof.pow_bind != DerivePowBind(proof.claimed_digest)) return fail("v7:pow_bind");
    if (proof.claimed_digest != header.matmul_digest) return fail("v7:digest_not_header_bound");
    if (proof.episode_sigma != matmul::v4::DeriveSigma(header)) return fail("v7:sigma");

    // SUCCINCT: the digest/target are read from the PUBLIC round_roots — no int64
    // reference re-run. round_roots are grounded below by the in-circuit tile-tree
    // AIR over the committed extract columns (§6.3 / F0), not by comparison to a
    // fresh reference computation.
    const std::vector<uint256>& roots = proof.round_roots;
    if (roots.size() != proof.episode.rounds) return fail("v7:round_roots_size");
    const uint256 digest = EpisodeDigestFromRoots(roots);
    if (digest != proof.claimed_digest) return fail("v7:digest_from_roots"); // F15
    if (UintToArith256(digest) > target) return fail("v7:target");           // F14

    // Native round-seed chain (public; §6.1) — cheap, no episode work.
    const uint256 sigma = proof.episode_sigma;
    for (uint32_t r = 0; r < proof.episode.rounds; ++r) {
        const uint256 expect =
            (r == 0) ? Sha256TaggedU32(kRCRoundTag, sizeof(kRCRoundTag) - 1, sigma, 0)
                     : Sha256TaggedU32(kRCRoundTag, sizeof(kRCRoundTag) - 1, roots[r - 1], r);
        if (r >= proof.round_seeds.size() || expect != proof.round_seeds[r])
            return fail("v7:round_seeds");
    }

    // R4: the verifier drives Λ(params); layer count and dims are Λ outputs.
    const RCGkrLayout layout = RCGkrTraceLayout(proof.episode);
    if (proof.wires.size() != layout.layers.size()) return fail("v7:layout_count");
    if (proof.layers.size() != layout.layers.size()) return fail("v7:layer_count"); // F8/F9
    for (size_t li = 0; li < layout.layers.size(); ++li) {
        const auto& ls = layout.layers[li];
        const auto& w = proof.wires[li];
        if (!(ls.kind == w.kind && ls.round == w.round && ls.layer == w.layer && ls.m == w.m &&
              ls.n == w.n && ls.k == w.k))
            return fail("v7:layout_layer_mismatch"); // F13 dims / F8 order
        // Committed-column shapes must match the layout (anti-smuggling).
        if (w.A.size() != static_cast<size_t>(w.m) * w.k ||
            w.B.size() != static_cast<size_t>(w.k) * w.n ||
            w.Y.size() != static_cast<size_t>(w.m) * w.n ||
            w.extract_in.size() != static_cast<size_t>(w.m) * w.n ||
            w.extract_out.size() != static_cast<size_t>(w.m) * w.n)
            return fail("v7:wire_shape");
    }

    // BIND the carried witness columns to the batched-FRI commitment (F1/F2/F6):
    // a tampered column fails the root check; a *consistent* forged column fails
    // the in-circuit AIR that constrains it (below).
    std::vector<std::vector<Fp2>> columns = BuildV7ColumnsFromWitness(proof.wires);
    const uint32_t batch_n = proof.batch.n_coeffs;
    if (batch_n == 0 || (batch_n & (batch_n - 1)) != 0) return fail("v7:batch_n");
    const uint32_t nu = Log2Exact(batch_n);
    if (proof.batch.columns.size() != columns.size() + 2) return fail("v7:batch_col_count");
    for (size_t i = 0; i < columns.size(); ++i)
        if (FriBatchColumnRoot(columns[i], batch_n) != proof.batch.columns[i].root)
            return fail("v7:column_not_grounded"); // F1/F2/F6 operand/trace/extract forgery

    // Thm 2.1: batched FRI binds every committed column to a low-degree poly.
    const uint256 base_seed = RCGkrFsSeedV7(header, height, proof.episode, target,
                                            proof.claimed_digest, proof.episode_sigma, roots);
    std::string fri_why;
    if (!FriBatchVerify(proof.batch, base_seed, &fri_why)) return fail("v7:fri:" + fri_why);

    // Per-layer sumcheck (R1) + collect opening claims (R2), Λ-driven order.
    FsTranscript fs(kRCGkrDomainTagV7);
    fs.AbsorbUint256(base_seed);
    std::vector<RCGkrOpeningClaim> claims;
    for (size_t li = 0; li < proof.wires.size(); ++li) {
        const RCGkrV7WireWitness& w = proof.wires[li];
        const RCGkrLayerClaimV7& lc = proof.layers[li];
        fs.AbsorbU32(static_cast<uint32_t>(li));
        const uint32_t nu_i = Log2Exact(RCGkrNextPow2(w.m));
        const uint32_t nu_j = Log2Exact(RCGkrNextPow2(w.n));
        std::vector<Fp2> ri(nu_i), rj(nu_j);
        for (uint32_t b = 0; b < nu_i; ++b) ri[b] = fs.ChallengeFp2("v7_ri");
        for (uint32_t b = 0; b < nu_j; ++b) rj[b] = fs.ChallengeFp2("v7_rj");

        std::vector<Fp2> rk;
        Fp2 gf;
        if (!VerifyProductK(lc.sumcheck, lc.c_claim, fs, rk, gf))
            return fail("v7:sumcheck"); // F5 forged claim
        // R1 (Thm 3.1): the carried final_eval must equal BOTH the sumcheck
        // chain-end AND the product of the two bound openings — it is no longer
        // a free proof field (v6's F4 hole).
        if (!Eq(lc.final_eval, gf)) return fail("v7:final_eval_endpoint"); // F4
        if (!Eq(lc.final_eval, Mul(lc.a_eval, lc.b_eval))) return fail("v7:final_eval"); // F4

        const uint32_t a_col = static_cast<uint32_t>(4 * li);
        const uint32_t b_col = a_col + 1;
        const uint32_t y_col = a_col + 2;
        claims.push_back({y_col, PointConcatExtend(rj, ri, nu), lc.c_claim});
        claims.push_back({a_col, PointConcatExtend(rk, ri, nu), lc.a_eval});
        claims.push_back({b_col, PointConcatExtend(rj, rk, nu), lc.b_eval});
    }

    // Thm 2.2: the eval argument binds c_claim / a_eval / b_eval to the committed
    // columns. A forged opening value (F3) fails the Lemma-1.2 identity at z1/z2.
    const uint256 eval_seed =
        EvalArgSeed(base_seed, proof.batch.columns, /*epoch1_count=*/4 * proof.wires.size());
    std::string ev_why;
    if (!EvalArgumentVerify(claims, proof.batch, proof.eval, eval_seed, &ev_why))
        return fail("v7:eval:" + ev_why); // F3

    // R3/§5.7/§6.3: dual-α challenges (FS-bound), then the in-circuit grounding.
    fs.AbsorbBytes(reinterpret_cast<const unsigned char*>("logup"), 5);
    const Fp2 gamma = fs.ChallengeFp2("v7_gamma");
    const Fp2 a1 = fs.ChallengeFp2("v7_alpha1");
    const Fp2 a2 = fs.ChallengeFp2("v7_alpha2");
    if (!Eq(a1, proof.logup_alpha1) || !Eq(a2, proof.logup_alpha2))
        return fail("v7:logup_alpha_unbound");

    // §5.4/§5.7/§6.3 IN-CIRCUIT grounding over the committed columns (THE
    // soundness mechanism — no int64-reference re-derivation): leaf operands →
    // MxExpandAir, extract_out → Extract sampler AIR over ALL tiles, round_roots
    // → tile-tree AIR. Public seeds/prf are Λ-derived natively.
    const std::vector<LayerProv> prov = RCGkrEpisodeWiring(header, proof.episode, roots);
    if (prov.size() != proof.wires.size()) return fail("v7:wiring_count");
    gkr_air::LogUpInstance inst_tm, inst_tx;
    const GroundResult gr = GroundEpisodeInCircuit(proof.wires, prov, proof.episode, roots, gamma,
                                                   inst_tm, inst_tx);
    if (!gr.ok) return fail("v7:ground:" + gr.failure); // F0/F6/F7 in-circuit

    // Dual-α LogUp aggregate over ALL committed tiles + MxExpand mantissa rows.
    // T_M/T_X carry the membership soundness (§5.5/§5.6); the 16-bit range (T_R16)
    // is enforced structurally by the sampler AIR (avoids the 2^16-row mult scan),
    // matching the shipped sample path.
    auto finalize_small = [](gkr_air::LogUpInstance& in) {
        in.table_mult.assign(in.table.size(), 0);
        for (const Fp2& wt : in.witness)
            for (size_t j = 0; j < in.table.size(); ++j)
                if (gkr_field::Eq(wt, in.table[j])) { in.table_mult[j] += 1; break; }
    };
    finalize_small(inst_tm);
    finalize_small(inst_tx);
    std::vector<gkr_air::LogUpInstance> insts{inst_tm, inst_tx};
    const gkr_air::LogUpVerifyResult lr = gkr_air::LogUpDualAlphaVerify(insts, a1, a2);
    if (!lr.ok) return fail("v7:logup:" + lr.failure); // F6/F7 (mechanism)

    // G1–G5 IN-CIRCUIT RELATIONS (defense-in-depth; the four constructions).
    // Runs AFTER the native §5 grounding, so it never changes which relation an
    // already-rejected forgery first fails (the red-team asserts the ground/logup
    // relation), while binding every winner-proof relation by a construction
    // identity. Honest proofs satisfy all of G1–G5. Behind the OFF arbiter.
    const RCGkrRelationsResult rel =
        CheckWinnerProofRelationsV7AfterGrounding(proof, header, height, target);
    if (!rel.ok) return fail(rel.failure); // v7:g1..g5 in-circuit relation

    if (fs.Digest() != proof.transcript_hash) return fail("v7:transcript_hash");

    const double verify_s =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    const bool over_budget = verify_s > kRCGkrVerifyBudgetS;
    if (out_timing) {
        out_timing->ok = true;
        out_timing->verify_s = verify_s;
        out_timing->over_budget = over_budget;
        out_timing->note = "v7 SUCCINCT ok (in-circuit AIRs; no reference re-run)";
    }
    if (why) {
        *why = "v7 SUCCINCT ok: tiles=" + std::to_string(gr.n_tiles) +
               " mxexpand_sha=" + std::to_string(gr.n_mxexpand_sha) +
               " tiletree_sha=" + std::to_string(gr.n_tiletree_sha) +
               " logup_bits=" + std::to_string(lr.achieved_bits) +
               " verify_s=" + std::to_string(verify_s) +
               " over_budget=" + (over_budget ? "1" : "0");
    }
    return true;
}

bool EnvRCWinnerGkrEnabled() { return EnvFlagIsOne("BTX_RC_WINNER_GKR"); }
bool EnvRCVerifyGkrEnabled() { return EnvFlagIsOne("BTX_RC_VERIFY_GKR"); }
bool EnvRCGkrShadowEnabled() { return !EnvFlagIsZero("BTX_RC_GKR_SHADOW"); }
bool EnvRCGkrArbiterEnabled()
{
    // A3/F3: compile-time hard-disable — no env var can grant proof-only
    // consensus authority while formal soundness is not ready. Prove/verify/
    // shadow and v7 grounding paths remain independent of this gate.
    if (!kRCGkrFormalSoundnessReady) return false;
    return EnvFlagIsOne("BTX_RC_GKR_ARBITER");
}

DistSynthShape RCGkrShapeForEpisode(const RCEpisodeParams& params)
{
    if (params.n_ctx >= 256 || params.b_seq >= 256 || params.d_model >= 64) {
        return DistSynthShape{64, 64, 256, 64};
    }
    return DistSynthShape{32, 32, 128, 32};
}

DistSynthShape RCGkrShapeForCoupled(const RCCoupParams& params)
{
    const bool medium = params.barriers > kRCCoupRounds || params.lobes > kRCCoupLobes;
    return medium ? DistSynthShape{64, 64, 256, 64} : DistSynthShape{32, 32, 128, 32};
}

void RCGkrProofCachePut(const uint256& block_hash, std::vector<unsigned char> proof_bytes)
{
    std::lock_guard<std::mutex> lock(g_rc_gkr_cache_mu);
    const auto now = std::chrono::steady_clock::now();
    RCGkrProofCacheEvictExpiredLocked(now);
    const auto expires =
        now + std::chrono::seconds(kRCGkrProofCacheTtlSeconds);

    auto it = g_rc_gkr_proof_cache.find(block_hash);
    if (it != g_rc_gkr_proof_cache.end()) {
        g_rc_gkr_proof_lru.erase(it->second.lru_it);
        g_rc_gkr_proof_lru.push_front(block_hash);
        it->second.bytes = std::move(proof_bytes);
        it->second.expires_at = expires;
        it->second.lru_it = g_rc_gkr_proof_lru.begin();
    } else {
        g_rc_gkr_proof_lru.push_front(block_hash);
        RCGkrProofCacheEntry entry;
        entry.bytes = std::move(proof_bytes);
        entry.expires_at = expires;
        entry.lru_it = g_rc_gkr_proof_lru.begin();
        g_rc_gkr_proof_cache.emplace(block_hash, std::move(entry));
    }
    RCGkrProofCacheEvictLruLocked();
}

bool RCGkrProofCacheGet(const uint256& block_hash, std::vector<unsigned char>& out_proof_bytes)
{
    std::lock_guard<std::mutex> lock(g_rc_gkr_cache_mu);
    const auto now = std::chrono::steady_clock::now();
    auto it = g_rc_gkr_proof_cache.find(block_hash);
    if (it == g_rc_gkr_proof_cache.end()) return false;
    if (it->second.expires_at <= now) {
        g_rc_gkr_proof_lru.erase(it->second.lru_it);
        g_rc_gkr_proof_cache.erase(it);
        return false;
    }
    // Touch LRU (most-recently used → front).
    g_rc_gkr_proof_lru.erase(it->second.lru_it);
    g_rc_gkr_proof_lru.push_front(block_hash);
    it->second.lru_it = g_rc_gkr_proof_lru.begin();
    out_proof_bytes = it->second.bytes;
    return true;
}

void RCGkrProofCacheClear()
{
    std::lock_guard<std::mutex> lock(g_rc_gkr_cache_mu);
    g_rc_gkr_proof_cache.clear();
    g_rc_gkr_proof_lru.clear();
}

size_t RCGkrProofCacheSizeForTest()
{
    std::lock_guard<std::mutex> lock(g_rc_gkr_cache_mu);
    RCGkrProofCacheEvictExpiredLocked(std::chrono::steady_clock::now());
    return g_rc_gkr_proof_cache.size();
}

uint64_t ExactReplayInvocationCountForTest()
{
    return g_exact_replay_invoke_count.load(std::memory_order_relaxed);
}

void ResetExactReplayInvocationCountForTest()
{
    g_exact_replay_invoke_count.store(0, std::memory_order_relaxed);
}

uint32_t RCGkrNextPow2(uint32_t n)
{
    if (n <= 1) return 1;
    --n;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    return n + 1;
}

Fp RCGkrMleEval1D(const std::vector<Fp>& evals_pow2, const std::vector<Fp>& r)
{
    Fp acc = 0;
    for (size_t i = 0; i < evals_pow2.size(); ++i) {
        Fp eq = 1;
        for (size_t b = 0; b < r.size(); ++b) {
            const Fp bit = ((i >> b) & 1u) ? r[b] : gkr_field::Sub(1, r[b]);
            eq = gkr_field::Mul(eq, bit);
        }
        acc = gkr_field::Add(acc, gkr_field::Mul(evals_pow2[i], eq));
    }
    return acc;
}

Fp2 RCGkrMleEval1D2(const std::vector<Fp2>& evals_pow2, const std::vector<Fp2>& r)
{
    Fp2 acc = Fp2::Zero();
    for (size_t i = 0; i < evals_pow2.size(); ++i) {
        acc = Add(acc, Mul(evals_pow2[i], EqFactor(r, static_cast<uint32_t>(i))));
    }
    return acc;
}

RCGkrProveResult ProveWinnerFromSegments(const uint256& claimed_digest, const DistSynthShape& shape,
                                         const std::vector<std::vector<int64_t>>& segs,
                                         const uint256& extract_seed, const std::vector<int8_t>* A,
                                         const std::vector<int8_t>* B)
{
    // DEPRECATED synth helper — still emits succinct FRI+LogUp (no per-tile ship).
    const auto Y = SumSegmentPartials(segs);
    const auto extracted = ExtractOnce(extract_seed, Y, shape.m, shape.n);
    LayerWire w;
    w.kind = RCGkrLayerKind::SynthGemmDeprecated;
    w.m = shape.m;
    w.n = shape.n;
    w.k = shape.k;
    if (A && B) {
        w.A = ToFp2I8(*A);
        w.B = ToFp2I8(*B);
    } else {
        w.A.assign(static_cast<size_t>(shape.m) * shape.k, Fp2::Zero());
        w.B.assign(static_cast<size_t>(shape.k) * shape.n, Fp2::Zero());
    }
    w.Y = ToFp2I64(Y);
    w.extract_in = Y;
    w.extract_prf = lt::DeriveMatExpandPrfKey(extract_seed);
    w.extract_out = extracted;
    RCEpisodeParams ep = MakeToyRCEpisodeParams();
    ep.n_q = shape.m;
    ep.n_ctx = shape.n;
    ep.d_head = shape.k >= 32 ? 32 : shape.k;
    auto r = ProveFromLayers(claimed_digest, ep, {w}, /*round_seeds=*/{}, /*round_roots=*/{},
                             /*episode_sigma=*/uint256{},
                             "DEPRECATED ProveWinnerFromSegments synth→succinct");
    r.proof.shape = shape;
    return r;
}

RCGkrProveResult ProveWinnerSynth(const uint256& seed, const DistSynthShape& shape,
                                  const uint256& claimed_digest)
{
    std::vector<int8_t> A, B;
    ExpandSynthOperands(seed, shape, A, B);
    auto parts = SimulateDevices(A, B, shape, 1);
    const uint256 extract_seed = DeriveTagged(seed, "BTX_RC_DIST_EXTRACT_V1");
    return ProveWinnerFromSegments(claimed_digest, shape, parts.segs, extract_seed, &A, &B);
}

RCGkrProveResult ProveWinnerEpisode(const CBlockHeader& header, const RCEpisodeParams& params,
                                    int32_t height, const uint256& resealed_digest)
{
    // M2: ALWAYS arithmetize the actual params — no shrink-to-toy.
    std::vector<RCRoundTranscript> transcripts;
    const uint256 dig =
        RecomputeResidentCurriculumReference(header, params, height, {}, &transcripts);
    (void)dig;
    std::vector<uint256> roots(params.rounds);
    for (uint32_t r = 0; r < params.rounds; ++r) {
        roots[r] = transcripts[r].round_root;
    }
    std::vector<uint256> seeds;
    const auto wires = BuildRealEpisodeLayers(header, params, roots, seeds);
    const uint256 sigma = matmul::v4::DeriveSigma(header);
    return ProveFromLayers(resealed_digest, params, wires, seeds, roots, sigma,
                           "ProveWinnerEpisode: ALL-PHASE GEMM+Extract LogUp+FRI (no shrink-to-toy)");
}

RCGkrProveResult ProveWinnerCoupled(const CBlockHeader& header, int32_t height,
                                    const RCCoupParams& params, const uint256& resealed_digest)
{
    // Wave 3B (retire-v6 decision): the sound coupled-R5 arithmetization lives in
    // matmul_v4_rc_gkr_coupled.cpp (ProveWinnerCoupledV7/VerifyWinnerCoupledV7).
    // The v6 RCGkrProof container is NOT sound for coupled (bank pages are unbound —
    // the UnrelatedBankPages construction is ACCEPTED), so this legacy entry no
    // longer emits a v6 coupled proof. It grounds against the immutable int64
    // coupled reference for exactly this (header, height, params) — via
    // RecomputeCoupledPuzzleReference, which honors the V3 rows_per_lobe shape —
    // delegates real proving to the sound v7 path, self-verifies, and reports
    // SOUND + over_budget so callers route to ExactReplay/V7. It never proves
    // toy/unrelated work. Shadow/arbiter stay OFF; heights INT32_MAX.
    return ProveWinnerCoupledLegacyBridge(header, height, params, resealed_digest);
}

const char* RCGkrIndepMaliciousGapNote(RCGkrIndepMaliciousKind kind)
{
    switch (kind) {
    case RCGkrIndepMaliciousKind::ArbitraryAbFactorization:
        return "OPEN-GKR-G1: a_at_r/b_at_r unbound to a_fri/b_fri PCS openings at sumcheck point";
    case RCGkrIndepMaliciousKind::UnrelatedLayerRoots:
        return "OPEN-GKR-G1G2: layer a_root/b_root/y_root unbound to global FRI commitments";
    case RCGkrIndepMaliciousKind::FabricatedTraceWires:
        return "OPEN-GKR-G2: claim/Y unbound to episode PRF expansion; trace_fri only self-consistent";
    case RCGkrIndepMaliciousKind::IdenticalFabricatedLookup:
        return "OPEN-GKR-G3: prover manufactures identical witness/table (Theorem 5.1 vacuity)";
    case RCGkrIndepMaliciousKind::FabricatedExtractIO:
        return "OPEN-GKR-G3G4: fabricated Extract I/O + recomputed prover fields accepted";
    case RCGkrIndepMaliciousKind::UnrelatedBankPages:
        return "OPEN-GKR-BANK: lobe B matrix unbound to bank_root page openings";
    case RCGkrIndepMaliciousKind::OmittedPages:
        return "coupled:omitted_page (layout rejects missing scheduled page GEMM)";
    case RCGkrIndepMaliciousKind::DuplicatedPages:
        return "coupled:duplicated_layer (layout rejects extra page GEMM)";
    case RCGkrIndepMaliciousKind::WrongM:
        return "coupled:wrong_m (layer.m must equal coup.rows_per_lobe)";
    case RCGkrIndepMaliciousKind::WrongExchangeTranscript:
        return "OPEN-GKR-XCHG: mix/exchange domain not re-derived in VerifyWinnerProof scaffold";
    case RCGkrIndepMaliciousKind::CrossVersionReplay:
        return "v7:version (proof.version must equal kRCGkrProofVersion)";
    }
    return "OPEN-GKR";
}

namespace {

void FabricateConsistentGemm(LayerWire& w, int8_t a_fill, int8_t b_fill)
{
    if (w.extract_only || w.k == 0) return;
    std::vector<int8_t> A(static_cast<size_t>(w.m) * w.k, a_fill);
    std::vector<int8_t> B(static_cast<size_t>(w.k) * w.n, b_fill);
    std::vector<int64_t> Y;
    ExactInt64Gemm(A, w.m, w.k, B, w.n, Y);
    w.A = ToFp2I8(A);
    w.B = ToFp2I8(B);
    w.Y = ToFp2I64(Y);
    w.residual.clear(); // keep G5: acc=claim when residual empty
    if (!w.extract_in.empty()) {
        w.extract_in = Y;
        w.extract_out.assign(Y.size(), 0);
        if (w.n % kRCMxBlockLen == 0 && !w.extract_prf.IsNull()) {
            ExtractMXMatrixInt64(w.extract_prf, Y.data(), w.m, w.n, w.extract_out.data());
        }
    }
}

void FabricateExtractOut(LayerWire& w, int8_t fill)
{
    if (w.extract_in.empty()) return;
    w.extract_out.assign(w.extract_in.size(), fill);
}

} // namespace

RCGkrProveResult ProveIndepMaliciousEpisodeForTest(const CBlockHeader& header,
                                                   const RCEpisodeParams& params, int32_t height,
                                                   const uint256& claimed_digest,
                                                   RCGkrIndepMaliciousKind kind)
{
    std::vector<RCRoundTranscript> transcripts;
    (void)RecomputeResidentCurriculumReference(header, params, height, {}, &transcripts);
    std::vector<uint256> roots(params.rounds);
    for (uint32_t r = 0; r < params.rounds; ++r) roots[r] = transcripts[r].round_root;
    std::vector<uint256> seeds;
    auto wires = BuildRealEpisodeLayers(header, params, roots, seeds);
    const uint256 sigma = matmul::v4::DeriveSigma(header);

    RCGkrProveForgeOpts forge;
    switch (kind) {
    case RCGkrIndepMaliciousKind::ArbitraryAbFactorization:
        forge.arbitrary_ab_factorization = true;
        break;
    case RCGkrIndepMaliciousKind::UnrelatedLayerRoots:
        forge.unrelated_layer_roots = true;
        break;
    case RCGkrIndepMaliciousKind::FabricatedTraceWires:
        for (auto& w : wires) FabricateConsistentGemm(w, /*a_fill=*/3, /*b_fill=*/5);
        break;
    case RCGkrIndepMaliciousKind::IdenticalFabricatedLookup:
        for (auto& w : wires) FabricateExtractOut(w, /*fill=*/7);
        forge.fabricated_identical_lookup = true;
        break;
    case RCGkrIndepMaliciousKind::FabricatedExtractIO:
        for (auto& w : wires) {
            FabricateExtractOut(w, /*fill=*/-9);
        }
        forge.fabricated_identical_lookup = true;
        break;
    case RCGkrIndepMaliciousKind::UnrelatedBankPages:
        // Episode-only API; treat as fabricated trace.
        for (auto& w : wires) FabricateConsistentGemm(w, /*a_fill=*/1, /*b_fill=*/-1);
        break;
    case RCGkrIndepMaliciousKind::OmittedPages:
    case RCGkrIndepMaliciousKind::DuplicatedPages:
    case RCGkrIndepMaliciousKind::WrongM:
    case RCGkrIndepMaliciousKind::WrongExchangeTranscript:
    case RCGkrIndepMaliciousKind::CrossVersionReplay:
        // Coupled-oriented kinds: episode path falls back to fabricated wires.
        for (auto& w : wires) FabricateConsistentGemm(w, /*a_fill=*/1, /*b_fill=*/-1);
        break;
    }

    auto out = ProveFromLayers(claimed_digest, params, wires, seeds, roots, sigma,
                               RCGkrIndepMaliciousGapNote(kind), /*coupled=*/false, {}, {}, forge);
    if (out.timing.ok) {
        out.timing.note = RCGkrIndepMaliciousGapNote(kind);
        out.proof.shrink_note = out.timing.note;
    }
    return out;
}

RCGkrProveResult ProveIndepMaliciousCoupledForTest(const CBlockHeader& header, int32_t height,
                                                   const RCCoupParams& params,
                                                   const uint256& claimed_digest,
                                                   RCGkrIndepMaliciousKind kind)
{
    RCCoupEpisodeTranscript tx;
    (void)RecomputeCoupledPuzzleReference(header, height, params, {}, {}, nullptr, &tx);

    std::vector<LayerWire> wires;
    wires.reserve(tx.gemms.size() + tx.extracts.size());
    const uint32_t M = params.rows_per_lobe == 0 ? 1 : params.rows_per_lobe;
    size_t gi = 0;
    for (uint32_t b = 0; b < params.barriers; ++b) {
        while (gi < tx.gemms.size() && tx.gemms[gi].barrier == b) {
            const auto& g = tx.gemms[gi++];
            LayerWire w;
            w.kind = RCGkrLayerKind::CoupLobeGemm;
            w.round = g.barrier;
            w.layer = g.lobe;
            w.page_id = g.page_id;
            w.m = M;
            w.n = params.lobe_width;
            w.k = params.lobe_width;
            w.A = ToFp2I8(g.A);
            w.B = ToFp2I8(g.B);
            w.Y = ToFp2I64(g.Y);
            w.extract_in.clear();
            w.extract_out.clear();
            w.extract_only = false;
            wires.push_back(std::move(w));
        }
        const RCCoupExtractTranscript* et = nullptr;
        for (const auto& e : tx.extracts) {
            if (e.barrier == b) {
                et = &e;
                break;
            }
        }
        if (!et) {
            RCGkrProveResult fail;
            fail.timing.ok = false;
            fail.timing.note = "coupled:extract_transcript_missing";
            return fail;
        }
        LayerWire w;
        w.kind = RCGkrLayerKind::CoupBarrierExtract;
        w.round = b;
        w.layer = 0;
        w.page_id = 0;
        w.m = 1;
        w.n = params.StateBytes();
        w.k = 0;
        w.Y = ToFp2I64(et->extract_in);
        w.extract_in = et->extract_in;
        w.extract_out = et->extract_out;
        w.extract_prf = et->extract_prf;
        w.extract_only = true;
        wires.push_back(std::move(w));
    }

    RCGkrProveForgeOpts forge;
    switch (kind) {
    case RCGkrIndepMaliciousKind::ArbitraryAbFactorization:
        forge.arbitrary_ab_factorization = true;
        break;
    case RCGkrIndepMaliciousKind::UnrelatedLayerRoots:
        forge.unrelated_layer_roots = true;
        break;
    case RCGkrIndepMaliciousKind::FabricatedTraceWires:
    case RCGkrIndepMaliciousKind::UnrelatedBankPages:
        for (auto& w : wires) {
            if (w.kind == RCGkrLayerKind::CoupLobeGemm) {
                FabricateConsistentGemm(w, /*a_fill=*/2, /*b_fill=*/9);
            }
        }
        break;
    case RCGkrIndepMaliciousKind::IdenticalFabricatedLookup:
    case RCGkrIndepMaliciousKind::FabricatedExtractIO:
        for (auto& w : wires) {
            if (w.kind == RCGkrLayerKind::CoupBarrierExtract) {
                FabricateExtractOut(w, /*fill=*/11);
            }
        }
        forge.fabricated_identical_lookup = true;
        break;
    case RCGkrIndepMaliciousKind::OmittedPages:
        // Drop one scheduled lobe-GEMM page (first GEMM) — layout must reject.
        for (size_t i = 0; i < wires.size(); ++i) {
            if (wires[i].kind == RCGkrLayerKind::CoupLobeGemm) {
                wires.erase(wires.begin() + static_cast<std::ptrdiff_t>(i));
                break;
            }
        }
        break;
    case RCGkrIndepMaliciousKind::DuplicatedPages:
        // Duplicate the first lobe-GEMM page — layout must reject.
        for (size_t i = 0; i < wires.size(); ++i) {
            if (wires[i].kind == RCGkrLayerKind::CoupLobeGemm) {
                wires.insert(wires.begin() + static_cast<std::ptrdiff_t>(i), wires[i]);
                break;
            }
        }
        break;
    case RCGkrIndepMaliciousKind::WrongM:
        for (auto& w : wires) {
            if (w.kind == RCGkrLayerKind::CoupLobeGemm) {
                w.m = M + 1;
                // Keep A/Y shapes consistent with the forged m so sumcheck can run;
                // layout check must still reject before algebra if dims≠coup.
                FabricateConsistentGemm(w, /*a_fill=*/4, /*b_fill=*/3);
            }
        }
        break;
    case RCGkrIndepMaliciousKind::WrongExchangeTranscript:
        // Scaffold cannot re-derive mix/exchange — fabricate Extract I/O as a stand-in
        // witness divergence under an honest barrier-root commitment (OPEN gap).
        for (auto& w : wires) {
            if (w.kind == RCGkrLayerKind::CoupBarrierExtract) {
                FabricateExtractOut(w, /*fill=*/13);
            }
        }
        forge.fabricated_identical_lookup = true;
        break;
    case RCGkrIndepMaliciousKind::CrossVersionReplay:
        break; // handled after ProveFromLayers
    }

    std::vector<uint256> seeds(params.barriers);
    const uint256 sigma = matmul::v4::DeriveSigma(header);
    for (uint32_t b = 0; b < params.barriers; ++b) {
        seeds[b] = Sha256TaggedU32(kRCCoupBarrierTag, sizeof(kRCCoupBarrierTag) - 1, sigma, b);
    }
    RCEpisodeParams empty_ep{};
    auto out =
        ProveFromLayers(claimed_digest, empty_ep, wires, seeds, tx.barrier_roots, sigma,
                        RCGkrIndepMaliciousGapNote(kind), /*coupled=*/true, params, tx.bank_root,
                        forge);
    if (kind == RCGkrIndepMaliciousKind::CrossVersionReplay && out.timing.ok) {
        out.proof.version = kRCGkrProofVersion - 1; // replay older format bytes
    }
    if (out.timing.ok || kind == RCGkrIndepMaliciousKind::OmittedPages ||
        kind == RCGkrIndepMaliciousKind::DuplicatedPages ||
        kind == RCGkrIndepMaliciousKind::WrongM ||
        kind == RCGkrIndepMaliciousKind::CrossVersionReplay) {
        // Layout-breaking kinds may still produce a proof object; surface the relation id.
        out.timing.note = RCGkrIndepMaliciousGapNote(kind);
        out.proof.shrink_note = out.timing.note;
    }
    return out;
}

bool VerifyWinnerProof(const RCGkrProof& proof, RCGkrTiming* out_timing)
{
    const size_t rss0 = CurrentRssKiB();
    const auto t0 = std::chrono::steady_clock::now();
    auto fail = [&](const char* why) {
        if (out_timing) {
            out_timing->verify_s =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            out_timing->peak_rss_kib = std::max(CurrentRssKiB(), rss0);
            out_timing->ok = false;
            out_timing->note = why ? why : "VerifyWinnerProof failed";
            std::vector<unsigned char> ser;
            out_timing->proof_bytes = SerializeRCGkrProof(proof, ser);
            out_timing->over_budget =
                out_timing->verify_s > kRCGkrVerifyBudgetS ||
                out_timing->proof_bytes > kRCGkrProofBytesBudget || proof.over_budget;
            if (out_timing->over_budget) out_timing->used_shrink_fallback = true;
        }
        return false;
    };

    if (proof.version != kRCGkrProofVersion) return fail("v7:version");
    if (proof.layers.empty()) return fail("v7:no_layers");
    if (proof.layers.size() > kRCGkrMaxLayersHard) return fail("v7:max_layers");
    // Reject oversized proofs before FRI work (canonical size via serialize).
    {
        std::vector<unsigned char> ser;
        const size_t nbytes = SerializeRCGkrProof(proof, ser);
        if (nbytes == 0 || nbytes > kRCGkrMaxProofBytesHard) return fail("v7:max_proof_size");
    }
    for (const auto& lc : proof.layers) {
        if (lc.sumcheck.size() > kRCGkrMaxSumcheckRoundsHard) return fail("v7:max_sumcheck_rounds");
    }
    if (proof.round_seeds.size() > kRCGkrMaxRoundSeedsHard ||
        proof.round_roots.size() > kRCGkrMaxRoundSeedsHard) {
        return fail("v7:max_round_seeds");
    }
    if (proof.pow_bind != DerivePowBind(proof.claimed_digest)) return fail("v7:pow_bind");
    if (proof.table_multiplicity != 1) return fail("v7:logup:table_multiplicity");

    // Round-seed / tile-tree / barrier consistency (skip DEPRECATED synth empty roots).
    if (!proof.round_roots.empty() || !proof.round_seeds.empty()) {
        if (proof.coupled) {
            if (!ValidateRCCoupParams(proof.coup)) return fail("coupled:coup_params");
            if (proof.round_roots.size() != proof.coup.barriers) {
                return fail("coupled:barrier_roots_size");
            }
            if (proof.round_seeds.size() != proof.coup.barriers) {
                return fail("coupled:barrier_seeds_size");
            }
            if (CoupledDigestFromBankAndBarriers(proof.bank_root, proof.round_roots) !=
                proof.claimed_digest) {
                return fail("coupled:digest_from_bank_barriers");
            }
            for (uint32_t b = 0; b < proof.coup.barriers; ++b) {
                const uint256 expect =
                    Sha256TaggedU32(kRCCoupBarrierTag, sizeof(kRCCoupBarrierTag) - 1,
                                    proof.episode_sigma, b);
                if (expect != proof.round_seeds[b]) return fail("coupled:barrier_seed");
            }
            // Canonical sequencing: per barrier, lobe GEMMs then Extract; no repeats/omissions.
            // The page schedule MUST match the config RecomputeCoupledPuzzleReference (and the
            // coupled trace constructor that grounds against it) uses. Fleet commit 1ea2a63
            // flipped the coupled reference default to the full-bank schedule
            // (dc::kRCCoupFullBankScheduleEnabled=true) but left this verify-side page selection
            // pinned to the legacy single-page schedule, so the reference-derived coupled proof
            // (barriers·lobes·pages_per GEMM layers) no longer matched the verifier's expected
            // barriers·lobes single-page sequence. Ground against the SAME canonical schedule.
            // (expect_m below carries the V3 rows_per_lobe generalization; =1 for production.
            //  This sequencer still runs for the malicious coupled constructors used by the
            //  gap tests; the honest v6 coupled prover is retired — see ProveWinnerCoupled.)
            size_t idx = 0;
            const uint32_t expect_m =
                proof.coup.rows_per_lobe == 0 ? 1 : proof.coup.rows_per_lobe;
            for (uint32_t b = 0; b < proof.coup.barriers; ++b) {
                for (uint32_t ell = 0; ell < proof.coup.lobes; ++ell) {
                    const auto expect_pages =
                        SelectCoupledBankPageIds(b, ell, proof.coup, proof.episode_sigma,
                                                 dc::kRCCoupFullBankScheduleEnabled);
                    for (uint32_t page_id : expect_pages) {
                        if (idx >= proof.layers.size()) return fail("coupled:omitted_page");
                        const auto& lc = proof.layers[idx++];
                        if (lc.kind != RCGkrLayerKind::CoupLobeGemm) {
                            return fail("coupled:layer_order");
                        }
                        if (lc.round != b || lc.layer != ell) return fail("coupled:layer_order");
                        if (lc.page_id != page_id) return fail("coupled:page_id");
                        if (lc.m != expect_m) return fail("coupled:wrong_m");
                        if (lc.n != proof.coup.lobe_width || lc.k != proof.coup.lobe_width) {
                            return fail("coupled:layer_dims");
                        }
                        if (lc.table_multiplicity != 1) {
                            return fail("v7:logup:layer_multiplicity");
                        }
                    }
                }
                if (idx >= proof.layers.size()) return fail("coupled:omitted_barrier");
                const auto& ex = proof.layers[idx++];
                if (ex.kind != RCGkrLayerKind::CoupBarrierExtract) {
                    return fail("coupled:layer_order");
                }
                if (ex.round != b) return fail("coupled:layer_order");
                if (ex.m != 1 || ex.n != proof.coup.StateBytes() || ex.k != 0) {
                    return fail("coupled:layer_dims");
                }
            }
            if (idx != proof.layers.size()) return fail("coupled:duplicated_layer");
        } else {
            if (proof.round_roots.size() != proof.episode.rounds) return fail("round_roots size");
            if (proof.round_seeds.size() != proof.episode.rounds) return fail("round_seeds size");
            if (EpisodeDigestFromRoots(proof.round_roots) != proof.claimed_digest) {
                return fail("episode digest vs round_roots");
            }
            for (uint32_t r = 0; r < proof.episode.rounds; ++r) {
                uint256 expect;
                if (r == 0) {
                    expect = Sha256TaggedU32(kRCRoundTag, sizeof(kRCRoundTag) - 1,
                                             proof.episode_sigma, 0);
                } else {
                    expect = Sha256TaggedU32(kRCRoundTag, sizeof(kRCRoundTag) - 1,
                                             proof.round_roots[r - 1], r);
                }
                if (expect != proof.round_seeds[r]) return fail("round_seed chain");
            }
            if (proof.layers.size() != ExpectedLayerCount(proof.episode)) {
                return fail("layer count");
            }
            // Canonical (round, kind) order: QKt, SV, then L×(Fwd), then L×(Bwd,Wgrad) descending.
            size_t idx = 0;
            bool saw_qkt = false, saw_sv = false, saw_fwd = false, saw_bwd = false, saw_wg = false;
            for (uint32_t r = 0; r < proof.episode.rounds; ++r) {
                auto need = [&](RCGkrLayerKind kind, uint32_t layer, uint32_t m, uint32_t n,
                                uint32_t k) -> bool {
                    if (idx >= proof.layers.size()) return false;
                    const auto& lc = proof.layers[idx++];
                    if (lc.kind != kind || lc.round != r || lc.layer != layer) return false;
                    if (lc.m != m || lc.n != n || lc.k != k) return false;
                    if (lc.table_multiplicity != 1) return false;
                    return true;
                };
                const auto& ep = proof.episode;
                if (!need(RCGkrLayerKind::GemmPhase1QKt, 0, ep.n_q, ep.n_ctx, ep.d_head))
                    return fail("layer order");
                saw_qkt = true;
                if (!need(RCGkrLayerKind::GemmPhase1SV, 0, ep.n_q, ep.d_head, ep.n_ctx))
                    return fail("layer order");
                saw_sv = true;
                for (uint32_t l = 0; l < ep.L_lyr; ++l) {
                    if (!need(RCGkrLayerKind::GemmPhase2Fwd, l, ep.b_seq, ep.d_model, ep.d_model))
                        return fail("layer order");
                    saw_fwd = true;
                }
                for (int32_t li = static_cast<int32_t>(ep.L_lyr) - 1; li >= 0; --li) {
                    const uint32_t l = static_cast<uint32_t>(li);
                    if (!need(RCGkrLayerKind::GemmPhase2Bwd, l, ep.b_seq, ep.d_model, ep.d_model))
                        return fail("layer order");
                    saw_bwd = true;
                    if (!need(RCGkrLayerKind::GemmPhase2Wgrad, l, ep.d_model, ep.d_model, ep.b_seq))
                        return fail("layer order");
                    saw_wg = true;
                }
            }
            if (idx != proof.layers.size()) return fail("repeated layer");
            if (!(saw_qkt && saw_sv && saw_fwd && saw_bwd && saw_wg)) {
                return fail("missing ALL-PHASE layer kind");
            }
        }
        if (proof.trace_fri.layers.empty() || proof.lookup_fri.layers.empty() ||
            proof.table_fri.layers.empty() || proof.logup_inv_fri.layers.empty() ||
            proof.logup_r_fri.layers.empty() || proof.a_fri.layers.empty() ||
            proof.b_fri.layers.empty()) {
            return fail("missing FRI");
        }
    }

    FsTranscript fs(kRCGkrDomainTag);
    if (proof.coupled) {
        AbsorbCoup(fs, proof.coup, proof.bank_root);
    } else {
        AbsorbEpisode(fs, proof.episode);
    }
    fs.AbsorbUint256(proof.claimed_digest);
    uint256 bind{};
    AbsorbPowBind(fs, proof.claimed_digest, bind);
    if (bind != proof.pow_bind) return fail("pow_bind fs");
    fs.AbsorbUint256(proof.episode_sigma);
    fs.AbsorbU32(proof.table_multiplicity);
    fs.AbsorbBytes(reinterpret_cast<const unsigned char*>("round_seeds"), 11);
    for (const auto& s : proof.round_seeds) fs.AbsorbUint256(s);
    fs.AbsorbBytes(reinterpret_cast<const unsigned char*>("round_roots"), 11);
    for (const auto& rt : proof.round_roots) fs.AbsorbUint256(rt);

    // G1/G2: FRI commits absorbed before per-layer challenges (commit-then-challenge).
    const uint256 fri_pre = fs.Challenge("fri_precommit");
    (void)fri_pre;
    std::string fri_why;
    if (!FriVerify(proof.a_fri, fri_pre, &fri_why)) return fail(fri_why.c_str());
    if (!FriVerify(proof.b_fri, fri_pre, &fri_why)) return fail(fri_why.c_str());
    if (!FriVerify(proof.trace_fri, fri_pre, &fri_why)) return fail(fri_why.c_str());
    if (!FriVerify(proof.lookup_fri, fri_pre, &fri_why)) return fail(fri_why.c_str());
    if (!FriVerify(proof.table_fri, fri_pre, &fri_why)) return fail(fri_why.c_str());
    // G3: witness key commitment must match Extract-table commitment.
    if (proof.lookup_fri.layers.empty() || proof.table_fri.layers.empty() ||
        proof.lookup_fri.layers[0].root != proof.table_fri.layers[0].root) {
        return fail("G3 witness/table root");
    }
    if (proof.lookup_fri.has_deep && proof.table_fri.has_deep &&
        !Eq(proof.lookup_fri.deep_eval, proof.table_fri.deep_eval)) {
        return fail("G3 witness/table DEEP");
    }
    fs.AbsorbUint256(proof.a_fri.layers.empty() ? uint256{} : proof.a_fri.layers[0].root);
    fs.AbsorbUint256(proof.b_fri.layers.empty() ? uint256{} : proof.b_fri.layers[0].root);
    fs.AbsorbUint256(proof.trace_fri.layers.empty() ? uint256{} : proof.trace_fri.layers[0].root);
    fs.AbsorbUint256(proof.lookup_fri.layers.empty() ? uint256{} : proof.lookup_fri.layers[0].root);
    fs.AbsorbUint256(proof.table_fri.layers.empty() ? uint256{} : proof.table_fri.layers[0].root);
    if (proof.trace_fri.has_deep) {
        fs.AbsorbFp2(proof.trace_fri.deep_z);
        fs.AbsorbFp2(proof.trace_fri.deep_eval);
    }
    if (proof.lookup_fri.has_deep) {
        fs.AbsorbFp2(proof.lookup_fri.deep_z);
        fs.AbsorbFp2(proof.lookup_fri.deep_eval);
    }

    uint256 prev_extract_commit{};
    for (const auto& lc : proof.layers) {
        const uint32_t nu_i = Log2Exact(RCGkrNextPow2(std::max(lc.m, 1u)));
        const uint32_t nu_j = Log2Exact(RCGkrNextPow2(std::max(lc.n, 1u)));
        const bool extract_only =
            lc.kind == RCGkrLayerKind::CoupBarrierExtract || lc.k == 0 || lc.sumcheck.empty();
        const uint32_t nu_k = extract_only ? 0 : Log2Exact(RCGkrNextPow2(lc.k));
        if (!extract_only && lc.sumcheck.size() != nu_k) return fail("sumcheck round count");

        // G4 cross-layer extract_out commit chain.
        fs.AbsorbUint256(prev_extract_commit);
        fs.AbsorbUint256(lc.extract_out_commit);
        fs.AbsorbU32(lc.page_id);
        fs.AbsorbU32(lc.table_multiplicity);
        if (lc.table_multiplicity != 1) return fail("G3 layer multiplicity");

        std::vector<Fp2> ri(nu_i), rj(nu_j);
        for (uint32_t t = 0; t < nu_i; ++t) ri[t] = fs.ChallengeFp2("ri");
        for (uint32_t t = 0; t < nu_j; ++t) rj[t] = fs.ChallengeFp2("rj");
        fs.AbsorbFp2(lc.claim);
        fs.AbsorbFp2(lc.residual_mle);
        fs.AbsorbFp2(lc.acc_claim);
        // G5: acc = gemm + residual (Fwd); non-Fwd residual must be 0.
        if (!Eq(lc.acc_claim, Add(lc.claim, lc.residual_mle))) return fail("H5 residual");
        if (lc.kind != RCGkrLayerKind::GemmPhase2Fwd && !IsZero(lc.residual_mle)) {
            return fail("residual on non-Fwd");
        }
        fs.AbsorbUint256(lc.a_root);
        fs.AbsorbUint256(lc.b_root);
        fs.AbsorbUint256(lc.y_root);
        if (extract_only) {
            fs.AbsorbFp2(lc.a_at_r);
            fs.AbsorbFp2(lc.b_at_r);
            fs.AbsorbFp2(lc.final_eval);
            if (!Eq(lc.a_at_r, Fp2::One()) || !Eq(lc.b_at_r, lc.claim) ||
                !Eq(lc.final_eval, lc.claim)) {
                return fail("extract-only final");
            }
            if (!Eq(lc.final_eval, Mul(lc.a_at_r, lc.b_at_r))) return fail("G1 a*b!=final");
        } else {
            std::vector<Fp2> rk;
            Fp2 gf;
            if (!VerifyProductK(lc.sumcheck, lc.claim, fs, rk, gf)) return fail("gemm sumcheck");
            if (!Eq(gf, lc.final_eval)) return fail("gemm final");
            if (rk.size() != nu_k) return fail("sumcheck rk size");
            fs.AbsorbFp2(lc.a_at_r);
            fs.AbsorbFp2(lc.b_at_r);
            // G1: A/B openings at sumcheck point bound to final_eval.
            if (!Eq(lc.final_eval, Mul(lc.a_at_r, lc.b_at_r))) return fail("G1 a*b!=final");
        }
        prev_extract_commit = lc.extract_out_commit;
    }

    const Fp2 alu = fs.ChallengeFp2("logup_alpha");
    if (!Eq(alu, proof.logup_alpha)) return fail("logup_alpha");
    if (!Eq(proof.lookup_logup_sum, proof.lookup_table_sum)) return fail("G3 sum_w/sum_t");
    fs.AbsorbFp2(alu);
    fs.AbsorbFp2(proof.lookup_logup_sum);

    if (!FriVerify(proof.logup_inv_fri, fri_pre, &fri_why)) return fail(fri_why.c_str());
    if (!FriVerify(proof.logup_r_fri, fri_pre, &fri_why)) return fail(fri_why.c_str());
    if (!proof.logup_inv_fri.has_deep || !proof.logup_inv_fri.deep_z_forced ||
        !Eq(proof.logup_inv_fri.deep_z, Fp2::One()) ||
        !Eq(proof.logup_inv_fri.deep_eval, proof.lookup_logup_sum)) {
        return fail("G3 I(1) DEEP");
    }
    if (!IsZero(proof.logup_r_fri.final_value)) return fail("G3 R final");
    if (proof.logup_r_fri.has_deep && !IsZero(proof.logup_r_fri.deep_eval)) {
        return fail("G3 R deep");
    }
    // Spot-check R openings are zero at every FRI query leaf (v5 half-domain:
    // pair i with i+N/2 — leaf at index is even if index < N/2, else odd).
    for (const auto& q : proof.logup_r_fri.queries) {
        if (q.steps.empty()) return fail("G3 R empty step");
        if (proof.logup_r_fri.layers.empty()) return fail("G3 R empty layers");
        const auto& st = q.steps[0];
        const uint32_t half = proof.logup_r_fri.layers[0].n_leaves / 2;
        const Fp2 leaf = (q.index < half) ? st.even : st.odd;
        if (!IsZero(leaf) || !IsZero(st.even) || !IsZero(st.odd)) return fail("G3 R leaf");
    }
    fs.AbsorbUint256(proof.logup_inv_fri.layers.empty() ? uint256{}
                                                         : proof.logup_inv_fri.layers[0].root);
    fs.AbsorbUint256(proof.logup_r_fri.layers.empty() ? uint256{}
                                                       : proof.logup_r_fri.layers[0].root);
    if (proof.logup_inv_fri.has_deep) {
        fs.AbsorbFp2(proof.logup_inv_fri.deep_z);
        fs.AbsorbFp2(proof.logup_inv_fri.deep_eval);
    }
    if (fs.Digest() != proof.transcript_hash) return fail("transcript");

    // Succinct path: do NOT re-expand operands / re-run episode / recompute Extract.
    if (out_timing) {
        out_timing->verify_s =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        std::vector<unsigned char> ser;
        out_timing->proof_bytes = SerializeRCGkrProof(proof, ser);
        out_timing->peak_rss_kib = std::max(CurrentRssKiB(), rss0);
        out_timing->ok = true;
        out_timing->note = "VerifyWinnerProof succinct ok (no episode re-run)";
        out_timing->over_budget =
            out_timing->verify_s > kRCGkrVerifyBudgetS ||
            out_timing->proof_bytes > kRCGkrProofBytesBudget || proof.over_budget;
        if (out_timing->over_budget) {
            out_timing->used_shrink_fallback = true;
            out_timing->note =
                "verify/proof over budget → shrink-to-VerifyBoundedExactReplay";
        }
    }
    return true;
}

bool VerifyWinnerProofPublic(const RCGkrProof& proof, const uint256& seed,
                             const DistSynthShape& shape, RCGkrTiming* out_timing)
{
    (void)seed;
    (void)shape;
    // v3 succinct proofs verify without re-running synth work.
    return VerifyWinnerProof(proof, out_timing);
}

size_t SerializeRCGkrProof(const RCGkrProof& proof, std::vector<unsigned char>& out)
{
    out.clear();
    AppendLE32(out, kRCGkrProofMagic);
    AppendLE32(out, proof.version);
    AppendBytes(out, proof.claimed_digest.data(), 32);
    AppendBytes(out, proof.pow_bind.data(), 32);
    AppendLE32(out, proof.episode.rounds);
    AppendLE32(out, proof.episode.d_head);
    AppendLE32(out, proof.episode.n_q);
    AppendLE32(out, proof.episode.n_ctx);
    AppendLE32(out, proof.episode.L_lyr);
    AppendLE32(out, proof.episode.d_model);
    AppendLE32(out, proof.episode.b_seq);
    AppendLE32(out, proof.episode.T_leaf);
    out.push_back(proof.coupled ? 1 : 0);
    AppendLE32(out, proof.coup.barriers);
    AppendLE32(out, proof.coup.lobes);
    AppendLE32(out, proof.coup.lobe_width);
    AppendLE32(out, proof.coup.bank_pages);
    AppendLE32(out, proof.coup.rows_per_lobe);
    AppendLE32(out, proof.coup.pages_per_barrier_lobe);
    AppendBytes(out, proof.bank_root.data(), 32);
    AppendLE32(out, proof.table_multiplicity);
    AppendLE32(out, static_cast<uint32_t>(proof.round_seeds.size()));
    for (const auto& s : proof.round_seeds) AppendBytes(out, s.data(), 32);
    AppendLE32(out, static_cast<uint32_t>(proof.round_roots.size()));
    for (const auto& rt : proof.round_roots) AppendBytes(out, rt.data(), 32);
    AppendBytes(out, proof.episode_sigma.data(), 32);
    AppendLE32(out, static_cast<uint32_t>(proof.layers.size()));
    for (const auto& lc : proof.layers) {
        AppendLE32(out, static_cast<uint32_t>(lc.kind));
        AppendLE32(out, lc.round);
        AppendLE32(out, lc.layer);
        AppendLE32(out, lc.m);
        AppendLE32(out, lc.n);
        AppendLE32(out, lc.k);
        AppendFp2(out, lc.claim);
        AppendFp2(out, lc.residual_mle);
        AppendFp2(out, lc.acc_claim);
        AppendBytes(out, lc.extract_out_commit.data(), 32);
        AppendBytes(out, lc.a_root.data(), 32);
        AppendBytes(out, lc.b_root.data(), 32);
        AppendBytes(out, lc.y_root.data(), 32);
        AppendFp2(out, lc.a_at_r);
        AppendFp2(out, lc.b_at_r);
        AppendLE32(out, lc.page_id);
        AppendLE32(out, lc.table_multiplicity);
        AppendLE32(out, static_cast<uint32_t>(lc.sumcheck.size()));
        for (const auto& r : lc.sumcheck) {
            AppendFp2(out, r.eval0);
            AppendFp2(out, r.eval1);
            AppendFp2(out, r.eval2);
        }
        AppendFp2(out, lc.final_eval);
    }
    AppendFp2(out, proof.lookup_logup_sum);
    AppendFp2(out, proof.lookup_table_sum);
    AppendFp2(out, proof.logup_alpha);
    std::vector<unsigned char> fri_a, fri_b, fri_t, fri_l, fri_tab, fri_inv, fri_r;
    (void)SerializeFriProof(proof.a_fri, fri_a);
    (void)SerializeFriProof(proof.b_fri, fri_b);
    (void)SerializeFriProof(proof.trace_fri, fri_t);
    (void)SerializeFriProof(proof.lookup_fri, fri_l);
    (void)SerializeFriProof(proof.table_fri, fri_tab);
    (void)SerializeFriProof(proof.logup_inv_fri, fri_inv);
    (void)SerializeFriProof(proof.logup_r_fri, fri_r);
    AppendLE32(out, static_cast<uint32_t>(fri_a.size()));
    AppendBytes(out, fri_a.data(), fri_a.size());
    AppendLE32(out, static_cast<uint32_t>(fri_b.size()));
    AppendBytes(out, fri_b.data(), fri_b.size());
    AppendLE32(out, static_cast<uint32_t>(fri_t.size()));
    AppendBytes(out, fri_t.data(), fri_t.size());
    AppendLE32(out, static_cast<uint32_t>(fri_l.size()));
    AppendBytes(out, fri_l.data(), fri_l.size());
    AppendLE32(out, static_cast<uint32_t>(fri_tab.size()));
    AppendBytes(out, fri_tab.data(), fri_tab.size());
    AppendLE32(out, static_cast<uint32_t>(fri_inv.size()));
    AppendBytes(out, fri_inv.data(), fri_inv.size());
    AppendLE32(out, static_cast<uint32_t>(fri_r.size()));
    AppendBytes(out, fri_r.data(), fri_r.size());
    AppendBytes(out, proof.transcript_hash.data(), 32);
    out.push_back(proof.over_budget ? 1 : 0);
    AppendLE32(out, static_cast<uint32_t>(proof.shrink_note.size()));
    AppendBytes(out, reinterpret_cast<const unsigned char*>(proof.shrink_note.data()),
                proof.shrink_note.size());
    return out.size();
}

std::optional<RCGkrProof> DeserializeRCGkrProof(const std::vector<unsigned char>& in)
{
    if (in.size() > kRCGkrMaxProofBytesHard) return std::nullopt;
    const unsigned char* p = in.data();
    const unsigned char* end = in.data() + in.size();
    uint32_t magic = 0, version = 0;
    if (!ReadLE32Checked(p, end, magic) || magic != kRCGkrProofMagic) return std::nullopt;
    if (!ReadLE32Checked(p, end, version) || version != kRCGkrProofVersion) return std::nullopt;

    RCGkrProof proof;
    proof.version = version;
    if (!ReadBytesChecked(p, end, proof.claimed_digest.data(), 32)) return std::nullopt;
    if (!ReadBytesChecked(p, end, proof.pow_bind.data(), 32)) return std::nullopt;
    if (!ReadLE32Checked(p, end, proof.episode.rounds)) return std::nullopt;
    if (!ReadLE32Checked(p, end, proof.episode.d_head)) return std::nullopt;
    if (!ReadLE32Checked(p, end, proof.episode.n_q)) return std::nullopt;
    if (!ReadLE32Checked(p, end, proof.episode.n_ctx)) return std::nullopt;
    if (!ReadLE32Checked(p, end, proof.episode.L_lyr)) return std::nullopt;
    if (!ReadLE32Checked(p, end, proof.episode.d_model)) return std::nullopt;
    if (!ReadLE32Checked(p, end, proof.episode.b_seq)) return std::nullopt;
    if (!ReadLE32Checked(p, end, proof.episode.T_leaf)) return std::nullopt;
    if (p >= end) return std::nullopt;
    proof.coupled = (*p++ != 0);
    if (!ReadLE32Checked(p, end, proof.coup.barriers)) return std::nullopt;
    if (!ReadLE32Checked(p, end, proof.coup.lobes)) return std::nullopt;
    if (!ReadLE32Checked(p, end, proof.coup.lobe_width)) return std::nullopt;
    if (!ReadLE32Checked(p, end, proof.coup.bank_pages)) return std::nullopt;
    if (!ReadLE32Checked(p, end, proof.coup.rows_per_lobe)) return std::nullopt;
    if (!ReadLE32Checked(p, end, proof.coup.pages_per_barrier_lobe)) return std::nullopt;
    if (!ReadBytesChecked(p, end, proof.bank_root.data(), 32)) return std::nullopt;
    if (!ReadLE32Checked(p, end, proof.table_multiplicity)) return std::nullopt;

    uint32_t n_seeds = 0, n_roots = 0;
    if (!ReadLE32Checked(p, end, n_seeds) || n_seeds > kRCGkrMaxRoundSeedsHard) return std::nullopt;
    proof.round_seeds.resize(n_seeds);
    for (auto& s : proof.round_seeds) {
        if (!ReadBytesChecked(p, end, s.data(), 32)) return std::nullopt;
    }
    if (!ReadLE32Checked(p, end, n_roots) || n_roots > kRCGkrMaxRoundSeedsHard) return std::nullopt;
    proof.round_roots.resize(n_roots);
    for (auto& rt : proof.round_roots) {
        if (!ReadBytesChecked(p, end, rt.data(), 32)) return std::nullopt;
    }
    if (!ReadBytesChecked(p, end, proof.episode_sigma.data(), 32)) return std::nullopt;

    uint32_t n_layers = 0;
    if (!ReadLE32Checked(p, end, n_layers) || n_layers == 0 || n_layers > kRCGkrMaxLayersHard)
        return std::nullopt;
    proof.layers.resize(n_layers);
    for (auto& lc : proof.layers) {
        uint32_t kind = 0;
        if (!ReadLE32Checked(p, end, kind)) return std::nullopt;
        lc.kind = static_cast<RCGkrLayerKind>(kind);
        if (!ReadLE32Checked(p, end, lc.round) || !ReadLE32Checked(p, end, lc.layer))
            return std::nullopt;
        if (!ReadLE32Checked(p, end, lc.m) || !ReadLE32Checked(p, end, lc.n) ||
            !ReadLE32Checked(p, end, lc.k))
            return std::nullopt;
        if (!ReadFp2Checked(p, end, lc.claim)) return std::nullopt;
        if (!ReadFp2Checked(p, end, lc.residual_mle)) return std::nullopt;
        if (!ReadFp2Checked(p, end, lc.acc_claim)) return std::nullopt;
        if (!ReadBytesChecked(p, end, lc.extract_out_commit.data(), 32)) return std::nullopt;
        if (!ReadBytesChecked(p, end, lc.a_root.data(), 32)) return std::nullopt;
        if (!ReadBytesChecked(p, end, lc.b_root.data(), 32)) return std::nullopt;
        if (!ReadBytesChecked(p, end, lc.y_root.data(), 32)) return std::nullopt;
        if (!ReadFp2Checked(p, end, lc.a_at_r)) return std::nullopt;
        if (!ReadFp2Checked(p, end, lc.b_at_r)) return std::nullopt;
        if (!ReadLE32Checked(p, end, lc.page_id)) return std::nullopt;
        if (!ReadLE32Checked(p, end, lc.table_multiplicity)) return std::nullopt;
        uint32_t sc_n = 0;
        if (!ReadLE32Checked(p, end, sc_n) || sc_n > kRCGkrMaxSumcheckRoundsHard)
            return std::nullopt;
        lc.sumcheck.resize(sc_n);
        for (auto& r : lc.sumcheck) {
            if (!ReadFp2Checked(p, end, r.eval0) || !ReadFp2Checked(p, end, r.eval1) ||
                !ReadFp2Checked(p, end, r.eval2))
                return std::nullopt;
        }
        if (!ReadFp2Checked(p, end, lc.final_eval)) return std::nullopt;
    }
    if (!ReadFp2Checked(p, end, proof.lookup_logup_sum)) return std::nullopt;
    if (!ReadFp2Checked(p, end, proof.lookup_table_sum)) return std::nullopt;
    if (!ReadFp2Checked(p, end, proof.logup_alpha)) return std::nullopt;
    auto read_fri = [&](FriProof& dest) -> bool {
        uint32_t n = 0;
        if (!ReadLE32Checked(p, end, n) || n > kRCFriMaxProofBytesHard) return false;
        std::vector<unsigned char> buf(n);
        if (!ReadBytesChecked(p, end, buf.data(), n)) return false;
        auto parsed = DeserializeFriProof(buf);
        if (!parsed) return false;
        dest = std::move(*parsed);
        return true;
    };
    if (!read_fri(proof.a_fri) || !read_fri(proof.b_fri) || !read_fri(proof.trace_fri) ||
        !read_fri(proof.lookup_fri) || !read_fri(proof.table_fri) ||
        !read_fri(proof.logup_inv_fri) || !read_fri(proof.logup_r_fri))
        return std::nullopt;
    if (!ReadBytesChecked(p, end, proof.transcript_hash.data(), 32)) return std::nullopt;
    if (p >= end) return std::nullopt;
    proof.over_budget = (*p++ != 0);
    uint32_t note_n = 0;
    if (!ReadLE32Checked(p, end, note_n) || note_n > (1u << 16)) return std::nullopt;
    if (static_cast<size_t>(end - p) < note_n) return std::nullopt;
    proof.shrink_note.assign(reinterpret_cast<const char*>(p), note_n);
    p += note_n;
    if (p != end) return std::nullopt;
    return proof;
}

WinnerGkrSolveReport SolveRCEpisodeProveWinner(CBlockHeader header, const RCEpisodeParams& params,
                                               int32_t height, const arith_uint256& target,
                                               uint64_t max_tries, bool do_prove)
{
    WinnerGkrSolveReport rep;
    const auto t0 = std::chrono::steady_clock::now();
    for (uint64_t i = 0; i < max_tries; ++i) {
        header.nNonce64 = i;
        header.nNonce = static_cast<uint32_t>(i);
        const uint256 dig = MineRCEpisode(header, params, height);
        ++rep.nonces_tried;
        if (UintToArith256(dig) > target) continue;
        const auto tm = std::chrono::steady_clock::now();
        rep.mine_s = std::chrono::duration<double>(tm - t0).count();
        const uint256 reseal = RecomputeResidentCurriculumReference(header, params, height);
        rep.reseal_s = std::chrono::duration<double>(std::chrono::steady_clock::now() - tm).count();
        if (reseal != dig) {
            rep.note = "reseal mismatch";
            return rep;
        }
        rep.digest = reseal;
        rep.nonce = i;
        rep.ok = true;
        if (do_prove) {
            auto pr = ProveWinnerEpisode(header, params, height, reseal);
            rep.prove_s = pr.timing.prove_s;
            rep.proof = std::move(pr.proof);
            rep.proof_bytes = pr.timing.proof_bytes;
            rep.peak_rss_kib = pr.timing.peak_rss_kib;
            rep.hbm_parked = pr.timing.over_budget;
            rep.used_shrink_fallback = pr.timing.used_shrink_fallback;
            RCGkrTiming vt;
            rep.proved = VerifyWinnerProof(rep.proof, &vt);
            rep.verify_s = vt.verify_s;
            rep.ok = rep.proved;
            if (rep.hbm_parked) {
                rep.note = "problems arise: prove over budget; HBM GKR PARKED; ExactReplay fallback";
            } else {
                rep.note = rep.proved ? "winner proved (real-episode succinct)" : "prove/verify failed";
            }
        } else {
            rep.note = "winner; prove skipped";
        }
        return rep;
    }
    rep.mine_s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    rep.note = "no winner in max_tries";
    return rep;
}

WinnerGkrSolveReport SolveCoupledProveWinner(CBlockHeader header, int32_t height,
                                             const RCCoupParams& params,
                                             const arith_uint256& target, uint64_t max_tries,
                                             bool do_prove)
{
    WinnerGkrSolveReport rep;
    const auto t0 = std::chrono::steady_clock::now();
    for (uint64_t i = 0; i < max_tries; ++i) {
        header.nNonce64 = i;
        header.nNonce = static_cast<uint32_t>(i);
        const uint256 dig = MineCoupledPuzzle(header, height, params);
        ++rep.nonces_tried;
        if (UintToArith256(dig) > target) continue;
        const auto tm = std::chrono::steady_clock::now();
        rep.mine_s = std::chrono::duration<double>(tm - t0).count();
        const uint256 reseal = RecomputeCoupledPuzzleReference(header, height, params);
        rep.reseal_s = std::chrono::duration<double>(std::chrono::steady_clock::now() - tm).count();
        if (reseal != dig) {
            rep.note = "coupled reseal mismatch";
            return rep;
        }
        rep.digest = reseal;
        rep.nonce = i;
        rep.ok = true;
        if (do_prove) {
            auto pr = ProveWinnerCoupled(header, height, params, reseal);
            rep.prove_s = pr.timing.prove_s;
            rep.proof = std::move(pr.proof);
            rep.proof_bytes = pr.timing.proof_bytes;
            rep.peak_rss_kib = pr.timing.peak_rss_kib;
            rep.hbm_parked = pr.timing.over_budget;
            if (!pr.timing.ok) {
                rep.proved = false;
                rep.ok = true; // mining/reseal succeeded; prove failed/refused
                rep.note = pr.timing.note.empty() ? "coupled prove failed" : pr.timing.note;
            } else {
                // Wave 3B: the coupled proof is v7-format and self-verified by
                // the bridge (VerifyWinnerCoupledV7); the v6 container carries
                // no layers, so VerifyWinnerProof does not apply here.
                rep.proved = true;
                rep.ok = true;
                rep.note = "coupled winner proved (v7 coupled R5; sound, over_budget)";
            }
        } else {
            rep.note = "coupled winner; prove skipped";
        }
        return rep;
    }
    rep.mine_s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    rep.note = "no coupled winner in max_tries";
    return rep;
}

ExactReplayVerifyResult VerifyBoundedExactReplay(const CBlockHeader& header,
                                                 const RCEpisodeParams& params, int32_t height,
                                                 const arith_uint256* target)
{
    g_exact_replay_invoke_count.fetch_add(1, std::memory_order_relaxed);
    ExactReplayVerifyResult out;
    const size_t rss0 = CurrentRssKiB();
    const auto t0 = std::chrono::steady_clock::now();
    out.digest = RecomputeResidentCurriculumReference(header, params, height);
    out.verify_s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    out.rss_kib = std::max(CurrentRssKiB(), rss0);
    out.proof_bytes = 0;
    if (out.digest.IsNull()) {
        out.ok = false;
        out.note = "ExactReplay: null digest";
        return out;
    }
    // F4: mirror coupled path — null committed digest is an unconditional REJECT
    // (coupled: digest.IsNull() || digest != header.matmul_digest).
    if (header.matmul_digest.IsNull() || out.digest != header.matmul_digest) {
        out.ok = false;
        out.note = header.matmul_digest.IsNull() ? "ExactReplay: null header.matmul_digest"
                                                 : "ExactReplay: digest mismatch vs header.matmul_digest";
        return out;
    }
    if (target && UintToArith256(out.digest) > *target) {
        out.ok = false;
        out.note = "ExactReplay: digest over target";
        return out;
    }
    out.ok = true;
    out.note = "VerifyBoundedExactReplay eps=0 (DISPUTE/fallback path)";
    return out;
}

RCProdVerifyResult VerifyRCWinnerOrExactReplay(const CBlockHeader& header,
                                               const RCEpisodeParams& params, int32_t height,
                                               const arith_uint256* target,
                                               const std::vector<unsigned char>* optional_gkr_proof)
{
    RCProdVerifyResult out;
    const bool have_proof =
        optional_gkr_proof != nullptr && !optional_gkr_proof->empty();
    const bool want_gkr = (EnvRCVerifyGkrEnabled() || EnvRCGkrArbiterEnabled()) && have_proof;

    if (want_gkr) {
        auto parsed = DeserializeRCGkrProof(*optional_gkr_proof);
        if (!parsed) {
            out.replay = VerifyBoundedExactReplay(header, params, height, target);
            out.path = RCProdVerifyPath::GkrFallbackExactReplay;
            out.ok = out.replay.ok;
            out.gkr.ok = false;
            out.gkr.note = "malformed proof -> ExactReplay fallback";
            out.note = out.gkr.note;
            return out;
        }
        if (header.matmul_digest.IsNull() || parsed->claimed_digest != header.matmul_digest) {
            out.replay = VerifyBoundedExactReplay(header, params, height, target);
            out.path = RCProdVerifyPath::GkrFallbackExactReplay;
            out.ok = out.replay.ok;
            out.gkr.ok = false;
            out.gkr.note = header.matmul_digest.IsNull()
                               ? "null header.matmul_digest -> ExactReplay fallback"
                               : "wrong digest in proof -> ExactReplay fallback";
            out.note = out.gkr.note;
            return out;
        }
        const bool gkr_ok = VerifyWinnerProof(*parsed, &out.gkr);
        if (gkr_ok && EnvRCGkrArbiterEnabled()) {
            // F3: bind sigma / episode dims / PoW target before accepting WinnerGkr.
            // Failures reject (no ExactReplay fallback). Soft over_budget still
            // falls through to ExactReplay after these bindings pass.
            const uint256 sigma = matmul::v4::DeriveSigma(header);
            if (parsed->episode_sigma != sigma) {
                out.path = RCProdVerifyPath::WinnerGkr;
                out.ok = false;
                out.note = "WinnerGkr arbiter reject: episode_sigma != DeriveSigma(header)";
                return out;
            }
            if (!RCEpisodeParamsEqual(parsed->episode, params)) {
                out.path = RCProdVerifyPath::WinnerGkr;
                out.ok = false;
                out.note = "WinnerGkr arbiter reject: episode dims != ResolveRCEpisodeParams";
                return out;
            }
            if (target && UintToArith256(parsed->claimed_digest) > *target) {
                out.path = RCProdVerifyPath::WinnerGkr;
                out.ok = false;
                out.note = "WinnerGkr arbiter reject: claimed_digest > target";
                return out;
            }
            if (!out.gkr.over_budget) {
                out.path = RCProdVerifyPath::WinnerGkr;
                out.ok = true;
                out.note = "WinnerGkr arbiter ok (ExactReplay reserved for DISPUTE)";
                return out;
            }
        }
        out.replay = VerifyBoundedExactReplay(header, params, height, target);
        out.path = RCProdVerifyPath::GkrFallbackExactReplay;
        out.ok = out.replay.ok;
        out.note = (!gkr_ok) ? "GKR verify failed -> ExactReplay fallback"
                             : (out.gkr.over_budget ? "GKR over budget -> ExactReplay fallback"
                                                    : "GKR shadow/arbiter-off -> ExactReplay decides");
        return out;
    }

    out.replay = VerifyBoundedExactReplay(header, params, height, target);
    out.path = RCProdVerifyPath::ExactReplay;
    out.ok = out.replay.ok;
    out.note = "ExactReplay (GKR disabled or no proof)";
    return out;
}

void RCGkrShadowObserve(const CBlockHeader& header, const RCEpisodeParams& params, int32_t height,
                        const arith_uint256* target,
                        const std::vector<unsigned char>* optional_gkr_proof,
                        const ExactReplayVerifyResult* prior_replay)
{
    if (!EnvRCGkrShadowEnabled()) return;
    std::vector<unsigned char> cached;
    const std::vector<unsigned char>* proof = optional_gkr_proof;
    if ((proof == nullptr || proof->empty()) && RCGkrProofCacheGet(header.GetHash(), cached)) {
        proof = &cached;
    }
    if (proof == nullptr || proof->empty()) return;

    auto parsed = DeserializeRCGkrProof(*proof);
    if (!parsed) {
        LogWarning("RC GKR shadow: malformed proof for block %s (ExactReplay still decides)\n",
                   header.GetHash().ToString().c_str());
        return;
    }
    RCGkrTiming vt;
    const bool gkr_ok = VerifyWinnerProof(*parsed, &vt);
    // H2: reuse prior ExactReplay when the caller already computed it.
    ExactReplayVerifyResult replay_local;
    const ExactReplayVerifyResult* replay = prior_replay;
    if (replay == nullptr) {
        replay_local = VerifyBoundedExactReplay(header, params, height, target);
        replay = &replay_local;
    }
    if (!gkr_ok || (replay->ok && parsed->claimed_digest != replay->digest)) {
        LogWarning("RC GKR shadow mismatch: gkr_ok=%d replay_ok=%d proof_bytes=%zu "
                   "verify_s=%.6f (ExactReplay remains consensus arbiter; never rejects)\n",
                   gkr_ok ? 1 : 0, replay->ok ? 1 : 0, vt.proof_bytes, vt.verify_s);
    } else {
        LogDebug(BCLog::VALIDATION,
                 "RC GKR shadow ok: proof_bytes=%zu verify_s=%.6f over_budget=%d\n",
                 vt.proof_bytes, vt.verify_s, vt.over_budget ? 1 : 0);
    }
    (void)target;
}

std::string RunWinnerGkrBakeoffSection(const uint256& synth_seed, const DistSynthShape& shape)
{
    const auto ep = RunSyntheticDistributed(synth_seed, shape, 1, DistReduceOrder::TreeLeftToRight);
    const auto pr = ProveWinnerSynth(synth_seed, shape, ep.digest);
    RCGkrTiming vt;
    const bool ok = VerifyWinnerProof(pr.proof, &vt);
    std::ostringstream os;
    os << "  \"winner_gkr\": {\n"
       << "    \"direction\": \"DECIDED winner-only GKR/sumcheck+FRI\",\n"
       << "    \"soundness_bound\": \"<=2^-64 after PoW grinding (Fp2 aspirational)\",\n"
       << "    \"prove_s\": " << pr.timing.prove_s << ",\n"
       << "    \"verify_s\": " << vt.verify_s << ",\n"
       << "    \"proof_bytes\": " << pr.timing.proof_bytes << ",\n"
       << "    \"peak_rss_kib\": " << pr.timing.peak_rss_kib << ",\n"
       << "    \"over_budget\": " << (pr.timing.over_budget ? "true" : "false") << ",\n"
       << "    \"ok\": " << (ok ? "true" : "false") << "\n"
       << "  }";
    return os.str();
}

std::string MeasureWinnerGkrToyMedium(const uint256& seed)
{
    (void)seed;
    // M9: CI proves toy only. Ladder (b_seq=256) / medium (b_seq=8192) require
    // BTX_RC_GKR_MEASURE_LADDER=1 / BTX_RC_GKR_MEASURE_MEDIUM=1 (off-CI).
    const bool measure_medium = EnvFlagIsOne("BTX_RC_GKR_MEASURE_MEDIUM");
    const bool measure_ladder = EnvFlagIsOne("BTX_RC_GKR_MEASURE_LADDER");
    CBlockHeader header;
    header.nVersion = 0x20000004;
    header.nTime = 1'770'000'000;
    header.nBits = 0x207fffff;
    header.nNonce64 = 42;
    header.nNonce = 42;
    for (int i = 0; i < 32; ++i) {
        header.hashPrevBlock.data()[i] = static_cast<unsigned char>(0x51);
        header.hashMerkleRoot.data()[i] = static_cast<unsigned char>(0xa3);
        header.seed_a.data()[i] = static_cast<unsigned char>(0x11);
        header.seed_b.data()[i] = static_cast<unsigned char>(0x22);
    }

    auto one = [&](const RCEpisodeParams& params, const char* label, bool do_prove) {
        if (!do_prove) {
            std::ostringstream os;
            os << "  \"" << label << "\": {\n"
               << "    \"n_ctx\": " << params.n_ctx << ", \"b_seq\": " << params.b_seq << ",\n"
               << "    \"skipped\": true,\n"
               << "    \"note\": \"set BTX_RC_GKR_MEASURE_LADDER=1 / "
                  "BTX_RC_GKR_MEASURE_MEDIUM=1 for off-CI ALL-PHASE prove; "
                  "shipping = ExactReplay when over_budget\",\n"
               << "    \"ok\": false\n"
               << "  }";
            return os.str();
        }
        const uint256 dig = RecomputeResidentCurriculumReference(header, params, 0);
        const auto pr = ProveWinnerEpisode(header, params, 0, dig);
        RCGkrTiming vt;
        const bool ok = VerifyWinnerProof(pr.proof, &vt);
        std::ostringstream os;
        os << "  \"" << label << "\": {\n"
           << "    \"n_ctx\": " << params.n_ctx << ", \"b_seq\": " << params.b_seq << ",\n"
           << "    \"prove_s\": " << pr.timing.prove_s << ",\n"
           << "    \"verify_s\": " << vt.verify_s << ",\n"
           << "    \"proof_bytes\": " << pr.timing.proof_bytes << ",\n"
           << "    \"peak_rss_kib\": " << std::max(pr.timing.peak_rss_kib, vt.peak_rss_kib) << ",\n"
           << "    \"over_budget\": " << (pr.timing.over_budget ? "true" : "false") << ",\n"
           << "    \"shrink_fallback\": " << (pr.timing.used_shrink_fallback ? "true" : "false")
           << ",\n"
           << "    \"hbm_park\": " << (pr.timing.over_budget ? "\"PARKED\"" : "\"candidate\"")
           << ",\n"
           << "    \"ok\": " << (ok ? "true" : "false") << "\n"
           << "  }";
        return os.str();
    };
    std::ostringstream os;
    os << "{\n"
       << "  \"soundness\": \"" << kRCGkrSoundnessBoundStatement << "\",\n"
       << "  \"reality_guardrail\": \"" << kRCGkrRealityGuardrail << "\",\n"
       << "  \"shadow\": \"" << kRCGkrShadowStatement << "\",\n"
       << "  \"m9_note\": \"prove cost ~linear in ALL-PHASE trace words (Y + LogUp keys); "
          "do NOT invent silicon rates; consensus-dim HBM vs shrink needs datacenter GPU\",\n"
       << one(MakeToyRCEpisodeParams(), "toy", /*do_prove=*/true) << ",\n"
       << one(MakeCostLadderRCEpisodeParams(), "ladder_b256",
              /*do_prove=*/measure_ladder) << ",\n"
       << one(MakeMediumRCEpisodeParams(), "medium", /*do_prove=*/measure_medium) << "\n"
       << "}\n";
    return os.str();
}

std::string MeasureWinnerGkrCurveCsv(const CBlockHeader& header)
{
    const bool measure_medium = EnvFlagIsOne("BTX_RC_GKR_MEASURE_MEDIUM");
    const bool measure_ladder = EnvFlagIsOne("BTX_RC_GKR_MEASURE_LADDER");
    std::ostringstream os;
    os << "label,n_ctx,b_seq,prove_s,verify_s,proof_bytes,peak_rss_kib,over_budget,ok\n";
    auto emit = [&](const char* label, const RCEpisodeParams& params, bool do_prove) {
        if (!do_prove) {
            os << label << "," << params.n_ctx << "," << params.b_seq << ",,,0,0,1,0\n";
            return;
        }
        const uint256 dig = RecomputeResidentCurriculumReference(header, params, 0);
        const auto pr = ProveWinnerEpisode(header, params, 0, dig);
        RCGkrTiming vt;
        const bool ok = VerifyWinnerProof(pr.proof, &vt);
        os << label << "," << params.n_ctx << "," << params.b_seq << "," << pr.timing.prove_s << ","
           << vt.verify_s << "," << pr.timing.proof_bytes << ","
           << std::max(pr.timing.peak_rss_kib, vt.peak_rss_kib) << ","
           << (pr.timing.over_budget ? 1 : 0) << "," << (ok ? 1 : 0) << "\n";
    };
    emit("toy", MakeToyRCEpisodeParams(), true);
    emit("ladder_b256", MakeCostLadderRCEpisodeParams(), measure_ladder);
    emit("medium", MakeMediumRCEpisodeParams(), measure_medium);
    return os.str();
}

} // namespace matmul::v4::rc
