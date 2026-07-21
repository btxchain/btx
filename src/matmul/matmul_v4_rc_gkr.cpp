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
#include <span.h>
#include <sys/resource.h>

#include <cassert>
#include <atomic>
#include <chrono>
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
                                              std::vector<Fp2>& out_r, Fp2& out_final)
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
    std::vector<Fp2> A;
    std::vector<Fp2> B;
    std::vector<Fp2> Y; // GEMM product (Fp2) — sumcheck claim target
    /** G5: residual X as Fp2 (Fwd only); empty otherwise. */
    std::vector<Fp2> residual;
    /** Pre-Extract accumulator (int64). Equals Y for non-Fwd; for Fwd includes H5 residual. */
    std::vector<int64_t> extract_in;
    uint256 extract_prf{};
    std::vector<int8_t> extract_out;
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

RCGkrProveResult ProveFromLayers(const uint256& claimed_digest, const RCEpisodeParams& episode,
                                 const std::vector<LayerWire>& wires,
                                 const std::vector<uint256>& round_seeds,
                                 const std::vector<uint256>& round_roots,
                                 const uint256& episode_sigma, const char* path_note)
{
    RCGkrProveResult out;
    const size_t rss0 = CurrentRssKiB();
    const auto t0 = std::chrono::steady_clock::now();
    RCGkrProof& p = out.proof;
    p.version = kRCGkrProofVersion;
    p.claimed_digest = claimed_digest;
    p.episode = episode;
    p.round_seeds = round_seeds;
    p.round_roots = round_roots;
    p.episode_sigma = episode_sigma;

    FsTranscript fs(kRCGkrDomainTag);
    AbsorbEpisode(fs, episode);
    fs.AbsorbUint256(claimed_digest);
    AbsorbPowBind(fs, claimed_digest, p.pow_bind);
    fs.AbsorbUint256(episode_sigma);
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
        extract_commits.push_back(Sha256dBytes(outbuf.data(), outbuf.size()));

        const uint32_t n_blocks = w.n / kRCMxBlockLen;
        assert(w.extract_in.size() == static_cast<size_t>(w.m) * w.n);
        assert(w.extract_out.size() == static_cast<size_t>(w.m) * w.n);
        for (uint32_t i = 0; i < w.m; ++i) {
            for (uint32_t bj = 0; bj < n_blocks; ++bj) {
                const size_t base =
                    static_cast<size_t>(i) * w.n + static_cast<size_t>(bj) * kRCMxBlockLen;
                const uint8_t scale = lt::DeriveMatExpandMxScale(w.extract_prf, i, bj);
                // Witness key binds claimed (in, out).
                witness_keys.push_back(HashLookupKey(i, bj, w.extract_prf, scale,
                                                     w.extract_in.data() + base,
                                                     w.extract_out.data() + base));
                // Virtual Extract table key: out MUST be ExtractMX(in).
                int8_t honest_out[kRCMxBlockLen];
                ExtractMXTileInt64(w.extract_prf, i, bj, w.extract_in.data() + base, honest_out);
                table_keys.push_back(HashLookupKey(i, bj, w.extract_prf, scale,
                                                   w.extract_in.data() + base, honest_out));
            }
        }
    }

    auto wire_root = [](const std::vector<Fp2>& v) {
        std::vector<unsigned char> buf;
        for (const auto& x : v) AppendFp2(buf, x);
        return Sha256dBytes(buf.empty() ? nullptr : buf.data(), buf.size());
    };

    // FRI commits (DEEP enabled) bind polynomials before sumcheck challenges.
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
    // G3: witness keys must equal Extract-table keys (out = Extract(in)).
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
        // G4: absorb prior extract_out commit (cross-layer link).
        fs.AbsorbUint256(prev_extract_commit);
        fs.AbsorbUint256(extract_commits[wi]);

        const uint32_t nu_i = Log2Exact(RCGkrNextPow2(w.m));
        const uint32_t nu_j = Log2Exact(RCGkrNextPow2(w.n));
        std::vector<Fp2> ri(nu_i), rj(nu_j);
        for (uint32_t t = 0; t < nu_i; ++t) ri[t] = fs.ChallengeFp2("ri");
        for (uint32_t t = 0; t < nu_j; ++t) rj[t] = fs.ChallengeFp2("rj");

        const Fp2 gemm_claim = MleEvalMatrix(w.Y, w.m, w.n, ri, rj);
        Fp2 residual_mle = Fp2::Zero();
        if (!w.residual.empty()) {
            residual_mle = MleEvalMatrix(w.residual, w.m, w.n, ri, rj);
        }
        const Fp2 acc_claim = MleEvalMatrix(ToFp2I64(w.extract_in), w.m, w.n, ri, rj);
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
        lc.claim = gemm_claim;
        lc.residual_mle = residual_mle;
        lc.acc_claim = acc_claim;
        lc.extract_out_commit = extract_commits[wi];
        lc.a_root = wire_root(w.A);
        lc.b_root = wire_root(w.B);
        fs.AbsorbUint256(lc.a_root);
        fs.AbsorbUint256(lc.b_root);
        std::vector<Fp2> rk;
        lc.sumcheck =
            ProveProductK(w.A, w.m, w.k, w.B, w.n, ri, rj, gemm_claim, fs, rk, lc.final_eval);
        p.layers.push_back(std::move(lc));
        prev_extract_commit = extract_commits[wi];
    }

    // G3 Haböck LogUp (2022/1530): α, inv_i=1/(α−t_i), S=Σ inv_i = I(1), R≡0.
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
    // R must be identically zero (Extract-honest + correct inverses).
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
    // I(1) = S via forced DEEP.
    if (!p.logup_inv_fri.has_deep || !p.logup_inv_fri.deep_z_forced ||
        !Eq(p.logup_inv_fri.deep_z, Fp2::One()) ||
        !Eq(p.logup_inv_fri.deep_eval, sum_t)) {
        out.timing.ok = false;
        out.timing.note = "G3 LogUp I(1) DEEP mismatch";
        return out;
    }
    // R≡0: deep_eval and final must be zero.
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

size_t RCGkrExpectedLayerCount(const RCEpisodeParams& p)
{
    return static_cast<size_t>(p.rounds) * (2u + 3u * static_cast<size_t>(p.L_lyr));
}

bool EnvRCWinnerGkrEnabled() { return EnvFlagIsOne("BTX_RC_WINNER_GKR"); }
bool EnvRCVerifyGkrEnabled() { return EnvFlagIsOne("BTX_RC_VERIFY_GKR"); }
bool EnvRCGkrShadowEnabled() { return !EnvFlagIsZero("BTX_RC_GKR_SHADOW"); }
bool EnvRCGkrArbiterEnabled() { return EnvFlagIsOne("BTX_RC_GKR_ARBITER"); }

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
    (void)header;
    (void)height;
    (void)params;
    (void)resealed_digest;
    // Assessment Wave A #3: previously discarded params and proved
    // MakeToyRCEpisodeParams() — a valid-looking proof of unrelated work.
    // Fail closed until real coupled-product arithmetization lands.
    // Shadow/arbiter stay OFF; heights INT32_MAX; ExactReplay decides.
    RCGkrProveResult out;
    out.proof = {};
    out.proof.shrink_note = kRCGkrCoupledArithStatement;
    out.timing.ok = false;
    out.timing.note = "coupled_arithmetization_unwired";
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

    if (proof.version != kRCGkrProofVersion) return fail("bad version");
    if (proof.layers.empty()) return fail("no layers");
    if (proof.pow_bind != DerivePowBind(proof.claimed_digest)) return fail("pow_bind");

    // Round-seed / tile-tree consistency (skip for DEPRECATED synth path with empty roots).
    if (!proof.round_roots.empty() || !proof.round_seeds.empty()) {
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
        bool saw_qkt = false, saw_sv = false, saw_fwd = false, saw_bwd = false, saw_wg = false;
        for (const auto& lc : proof.layers) {
            // M7: layer dims must match public episode params (no free m/n/k).
            const auto& ep = proof.episode;
            bool dims_ok = false;
            switch (lc.kind) {
            case RCGkrLayerKind::GemmPhase1QKt:
                saw_qkt = true;
                dims_ok = lc.m == ep.n_q && lc.n == ep.n_ctx && lc.k == ep.d_head;
                break;
            case RCGkrLayerKind::GemmPhase1SV:
                saw_sv = true;
                dims_ok = lc.m == ep.n_q && lc.n == ep.d_head && lc.k == ep.n_ctx;
                break;
            case RCGkrLayerKind::GemmPhase2Fwd:
                saw_fwd = true;
                dims_ok = lc.m == ep.b_seq && lc.n == ep.d_model && lc.k == ep.d_model;
                break;
            case RCGkrLayerKind::GemmPhase2Bwd:
                saw_bwd = true;
                dims_ok = lc.m == ep.b_seq && lc.n == ep.d_model && lc.k == ep.d_model;
                break;
            case RCGkrLayerKind::GemmPhase2Wgrad:
                saw_wg = true;
                dims_ok = lc.m == ep.d_model && lc.n == ep.d_model && lc.k == ep.b_seq;
                break;
            default:
                return fail("unexpected layer kind");
            }
            if (!dims_ok) return fail("layer dims vs episode");
            if (lc.layer >= ep.L_lyr && (lc.kind == RCGkrLayerKind::GemmPhase2Fwd ||
                                         lc.kind == RCGkrLayerKind::GemmPhase2Bwd ||
                                         lc.kind == RCGkrLayerKind::GemmPhase2Wgrad)) {
                return fail("layer index");
            }
            if (lc.round >= ep.rounds) return fail("round index");
        }
        if (!(saw_qkt && saw_sv && saw_fwd && saw_bwd && saw_wg)) {
            return fail("missing ALL-PHASE layer kind");
        }
        if (proof.trace_fri.layers.empty() || proof.lookup_fri.layers.empty() ||
            proof.table_fri.layers.empty() || proof.logup_inv_fri.layers.empty() ||
            proof.logup_r_fri.layers.empty() || proof.a_fri.layers.empty() ||
            proof.b_fri.layers.empty()) {
            return fail("missing FRI");
        }
    }

    FsTranscript fs(kRCGkrDomainTag);
    AbsorbEpisode(fs, proof.episode);
    fs.AbsorbUint256(proof.claimed_digest);
    uint256 bind{};
    AbsorbPowBind(fs, proof.claimed_digest, bind);
    if (bind != proof.pow_bind) return fail("pow_bind fs");
    fs.AbsorbUint256(proof.episode_sigma);
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
        const uint32_t nu_i = Log2Exact(RCGkrNextPow2(lc.m));
        const uint32_t nu_j = Log2Exact(RCGkrNextPow2(lc.n));
        const uint32_t nu_k = Log2Exact(RCGkrNextPow2(lc.k));
        if (lc.sumcheck.size() != nu_k) return fail("sumcheck round count");

        // G4 cross-layer extract_out commit chain.
        fs.AbsorbUint256(prev_extract_commit);
        fs.AbsorbUint256(lc.extract_out_commit);

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
        std::vector<Fp2> rk;
        Fp2 gf;
        if (!VerifyProductK(lc.sumcheck, lc.claim, fs, rk, gf)) return fail("gemm sumcheck");
        if (!Eq(gf, lc.final_eval)) return fail("gemm final");
        if (rk.size() != nu_k) return fail("sumcheck rk size");
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
    // Spot-check R openings are zero at every FRI query leaf.
    for (const auto& q : proof.logup_r_fri.queries) {
        if (q.steps.empty()) return fail("G3 R empty step");
        const auto& st = q.steps[0];
        const Fp2 leaf = (q.index & 1u) ? st.odd : st.even;
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

    uint32_t n_seeds = 0, n_roots = 0;
    if (!ReadLE32Checked(p, end, n_seeds) || n_seeds > 64) return std::nullopt;
    proof.round_seeds.resize(n_seeds);
    for (auto& s : proof.round_seeds) {
        if (!ReadBytesChecked(p, end, s.data(), 32)) return std::nullopt;
    }
    if (!ReadLE32Checked(p, end, n_roots) || n_roots > 64) return std::nullopt;
    proof.round_roots.resize(n_roots);
    for (auto& rt : proof.round_roots) {
        if (!ReadBytesChecked(p, end, rt.data(), 32)) return std::nullopt;
    }
    if (!ReadBytesChecked(p, end, proof.episode_sigma.data(), 32)) return std::nullopt;

    uint32_t n_layers = 0;
    if (!ReadLE32Checked(p, end, n_layers) || n_layers == 0 || n_layers > 1024) return std::nullopt;
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
        uint32_t sc_n = 0;
        if (!ReadLE32Checked(p, end, sc_n) || sc_n > 256) return std::nullopt;
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
        if (!ReadLE32Checked(p, end, n) || n > (8u << 20)) return false;
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
                rep.ok = true; // mining/reseal succeeded; prove is unsupported
                rep.note = pr.timing.note.empty() ? "coupled_arithmetization_unwired" : pr.timing.note;
            } else {
                RCGkrTiming vt;
                rep.proved = VerifyWinnerProof(rep.proof, &vt);
                rep.verify_s = vt.verify_s;
                rep.ok = rep.proved;
                rep.note = rep.proved ? "coupled winner proved" : "coupled prove/verify failed";
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
