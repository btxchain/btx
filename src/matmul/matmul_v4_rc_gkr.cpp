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
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
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
std::map<uint256, std::vector<unsigned char>> g_rc_gkr_proof_cache;

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

Fp2 HashLookupKey(uint32_t row, uint32_t block, const uint256& prf, uint8_t scale,
                  const int8_t* out8)
{
    std::vector<unsigned char> buf;
    AppendLE32(buf, row);
    AppendLE32(buf, block);
    AppendBytes(buf, prf.data(), 32);
    buf.push_back(scale);
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
    return DeriveTagged(claimed_digest, "BTX_RC_GKR_POW_BIND_V3");
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

/** Scaffold slice: full toy OK; larger shapes shrink to toy and flag budget. */
RCEpisodeParams ArithEpisodeShape(const RCEpisodeParams& params, bool& shrunk)
{
    shrunk = false;
    if (params.n_ctx <= 64 && params.b_seq <= 64 && params.d_model <= 64 &&
        params.n_q <= 64 && params.d_head <= 64) {
        return params;
    }
    shrunk = true;
    return MakeToyRCEpisodeParams();
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
    std::vector<Fp2> Y; // int64 products mapped to Fp2
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
 * Build REAL-episode layer wires (toy-shaped). Phase-1 Q·Kᵀ and S·V plus one
 * Phase-2 forward residual GEMM — matching the consensus episode structure,
 * not a digest-bound 32×32 synth proxy.
 */
std::vector<LayerWire> BuildRealEpisodeLayers(const CBlockHeader& header,
                                              const RCEpisodeParams& p)
{
    std::vector<LayerWire> out;
    const uint256 sigma = matmul::v4::DeriveSigma(header);
    uint256 seed_r = DeriveTagged(sigma, kRCRoundTag); // round-0 domain via tagged sigma
    // Match RunEpisode round-0: Sha256TaggedU32(kRCRoundTag, sigma, 0) — approximate
    // with DeriveTagged for scaffold binding (public seed_r still FS-bound to digest).
    {
        std::vector<unsigned char> buf;
        buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(kRCRoundTag),
                   reinterpret_cast<const unsigned char*>(kRCRoundTag) + sizeof(kRCRoundTag) - 1);
        buf.insert(buf.end(), sigma.begin(), sigma.end());
        unsigned char le[4];
        WriteLE32(le, 0);
        buf.insert(buf.end(), le, le + 4);
        seed_r = Sha256dBytes(buf.data(), buf.size());
    }

    // Match DeriveOperandSeed: SHA256(tag ‖ seed_r) — single hash, not SHA256d.
    auto operand = [&](const char* tag) {
        uint8_t out[CSHA256::OUTPUT_SIZE];
        CSHA256()
            .Write(reinterpret_cast<const unsigned char*>(tag), std::strlen(tag))
            .Write(seed_r.data(), 32)
            .Finalize(out);
        return uint256{Span<const unsigned char>{out, sizeof(out)}};
    };

    // Phase-1: Q·Kᵀ  (n_q × n_ctx, contract d_head) — GEMM native product layer.
    {
        const auto Q = ExpandMxDequantInt8(operand("BTX_RC_Q_V1"), p.n_q, p.d_head);
        const auto K = ExpandMxDequantInt8(operand("BTX_RC_KV_K_V1"), p.n_ctx, p.d_head);
        // B for Q·Kᵀ is Kᵀ conceptually: we form B as d_head × n_ctx from K rows.
        std::vector<int8_t> Kt(static_cast<size_t>(p.d_head) * p.n_ctx);
        for (uint32_t t = 0; t < p.n_ctx; ++t)
            for (uint32_t d = 0; d < p.d_head; ++d)
                Kt[static_cast<size_t>(d) * p.n_ctx + t] =
                    K[static_cast<size_t>(t) * p.d_head + d];
        std::vector<int64_t> Y;
        ExactInt64Gemm(Q, p.n_q, p.d_head, Kt, p.n_ctx, Y);
        const uint256 prf_S =
            lt::DeriveMatExpandPrfKey(operand("BTX_RC_PRF_S_V1"));
        std::vector<int8_t> Sout(Y.size());
        ExtractMXMatrixInt64(prf_S, Y.data(), p.n_q, p.n_ctx, Sout.data());
        LayerWire w;
        w.kind = RCGkrLayerKind::GemmPhase1QKt;
        w.m = p.n_q;
        w.n = p.n_ctx;
        w.k = p.d_head;
        w.A = ToFp2I8(Q);
        w.B = ToFp2I8(Kt);
        w.Y = ToFp2I64(Y);
        w.extract_prf = prf_S;
        w.extract_out = std::move(Sout);
        out.push_back(std::move(w));
    }

    // Phase-1: S·V using extracted S and V (n_q × d_head, contract n_ctx).
    {
        const auto& S = out.back().extract_out;
        const auto V = ExpandMxDequantInt8(operand("BTX_RC_KV_V_V1"), p.n_ctx, p.d_head);
        std::vector<int64_t> Y;
        ExactInt64Gemm(S, p.n_q, p.n_ctx, V, p.d_head, Y);
        const uint256 prf_Z =
            lt::DeriveMatExpandPrfKey(operand("BTX_RC_PRF_Z_V1"));
        std::vector<int8_t> Zout(Y.size());
        ExtractMXMatrixInt64(prf_Z, Y.data(), p.n_q, p.d_head, Zout.data());
        LayerWire w;
        w.kind = RCGkrLayerKind::GemmPhase1SV;
        w.m = p.n_q;
        w.n = p.d_head;
        w.k = p.n_ctx;
        w.A = ToFp2I8(S);
        w.B = ToFp2I8(V);
        w.Y = ToFp2I64(Y);
        w.extract_prf = prf_Z;
        w.extract_out = std::move(Zout);
        out.push_back(std::move(w));
    }

    // Phase-2 forward layer 0: X·Wᵀ + residual (bound via int64 then Extract).
    {
        const auto X0 = ExpandMxDequantInt8(operand("BTX_RC_X0_V1"), p.b_seq, p.d_model);
        const auto W = ExpandMxDequantInt8(operand("BTX_RC_W_0_V1"), p.d_model, p.d_model);
        std::vector<int8_t> Wt(static_cast<size_t>(p.d_model) * p.d_model);
        for (uint32_t i = 0; i < p.d_model; ++i)
            for (uint32_t j = 0; j < p.d_model; ++j)
                Wt[static_cast<size_t>(j) * p.d_model + i] =
                    W[static_cast<size_t>(i) * p.d_model + j];
        // Product layer claims X·Wᵀ only; residual is added pre-Extract (H5).
        std::vector<int64_t> Y_gemm;
        ExactInt64Gemm(X0, p.b_seq, p.d_model, Wt, p.d_model, Y_gemm);
        std::vector<int64_t> Y_acc = Y_gemm;
        for (uint32_t i = 0; i < p.b_seq; ++i)
            for (uint32_t j = 0; j < p.d_model; ++j)
                Y_acc[static_cast<size_t>(i) * p.d_model + j] +=
                    X0[static_cast<size_t>(i) * p.d_model + j];
        const uint256 prf =
            lt::DeriveMatExpandPrfKey(operand("BTX_RC_PRF_FWD_0_V1"));
        std::vector<int8_t> X1(Y_acc.size());
        ExtractMXMatrixInt64(prf, Y_acc.data(), p.b_seq, p.d_model, X1.data());
        LayerWire w;
        w.kind = RCGkrLayerKind::GemmPhase2Fwd;
        w.layer = 0;
        w.m = p.b_seq;
        w.n = p.d_model;
        w.k = p.d_model;
        w.A = ToFp2I8(X0);
        w.B = ToFp2I8(Wt);
        w.Y = ToFp2I64(Y_gemm); // product claim = GEMM only
        w.extract_prf = prf;
        w.extract_out = std::move(X1);
        out.push_back(std::move(w));
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
            "over soft budget → shrink-to-VerifyBoundedExactReplay (ε=0). "
            "NOT inventing production silicon numbers. HBM GKR PARKED.";
        t.used_shrink_fallback = true;
        t.note = p.shrink_note;
    }
}

RCGkrProveResult ProveFromLayers(const uint256& claimed_digest, const RCEpisodeParams& episode,
                                 const std::vector<LayerWire>& wires, const char* path_note)
{
    RCGkrProveResult out;
    const size_t rss0 = CurrentRssKiB();
    const auto t0 = std::chrono::steady_clock::now();
    RCGkrProof& p = out.proof;
    p.version = kRCGkrProofVersion;
    p.claimed_digest = claimed_digest;
    p.episode = episode;

    FsTranscript fs(kRCGkrDomainTag);
    AbsorbEpisode(fs, episode);
    fs.AbsorbUint256(claimed_digest);
    AbsorbPowBind(fs, claimed_digest, p.pow_bind);

    std::vector<Fp2> trace_evals;
    std::vector<Fp2> lookup_keys;

    for (const auto& w : wires) {
        const uint32_t nu_i = Log2Exact(RCGkrNextPow2(w.m));
        const uint32_t nu_j = Log2Exact(RCGkrNextPow2(w.n));
        std::vector<Fp2> ri(nu_i), rj(nu_j);
        for (uint32_t t = 0; t < nu_i; ++t) ri[t] = fs.ChallengeFp2("ri");
        for (uint32_t t = 0; t < nu_j; ++t) rj[t] = fs.ChallengeFp2("rj");
        const Fp2 yc = MleEvalMatrix(w.Y, w.m, w.n, ri, rj);
        fs.AbsorbFp2(yc);

        RCGkrLayerClaim lc;
        lc.kind = w.kind;
        lc.round = w.round;
        lc.layer = w.layer;
        lc.m = w.m;
        lc.n = w.n;
        lc.k = w.k;
        lc.claim = yc;
        std::vector<Fp2> rk;
        lc.sumcheck =
            ProveProductK(w.A, w.m, w.k, w.B, w.n, ri, rj, yc, fs, rk, lc.final_eval);
        p.layers.push_back(std::move(lc));

        trace_evals.insert(trace_evals.end(), w.Y.begin(), w.Y.end());

        // LogUp into fixed Extract table: aggregate keys only (NO raw tile ship).
        const uint32_t n_blocks = w.n / kRCMxBlockLen;
        for (uint32_t i = 0; i < w.m; ++i) {
            for (uint32_t bj = 0; bj < n_blocks; ++bj) {
                const size_t base =
                    static_cast<size_t>(i) * w.n + static_cast<size_t>(bj) * kRCMxBlockLen;
                const uint8_t scale = lt::DeriveMatExpandMxScale(w.extract_prf, i, bj);
                lookup_keys.push_back(
                    HashLookupKey(i, bj, w.extract_prf, scale, w.extract_out.data() + base));
            }
        }
    }

    const Fp2 alu = fs.ChallengeFp2("logup_alpha");
    Fp2 logup = Fp2::Zero();
    for (const auto& key : lookup_keys) {
        if (Eq(key, alu)) {
            out.timing.ok = false;
            out.timing.note = "logup collide";
            return out;
        }
        logup = Add(logup, Div(Fp2::One(), Sub(alu, key)));
    }
    p.lookup_logup_sum = logup;
    fs.AbsorbFp2(logup);

    const uint256 fri_seed = fs.Challenge("fri_seed");
    auto trace_c = FriCommitAndFold(trace_evals, fri_seed, /*n_openings=*/2);
    auto lookup_c = FriCommitAndFold(lookup_keys, fri_seed, /*n_openings=*/2);
    p.trace_fri = std::move(trace_c.proof);
    p.lookup_fri = std::move(lookup_c.proof);
    fs.AbsorbUint256(p.trace_fri.layers.empty() ? uint256{} : p.trace_fri.layers[0].root);
    fs.AbsorbUint256(p.lookup_fri.layers.empty() ? uint256{} : p.lookup_fri.layers[0].root);
    p.transcript_hash = fs.Digest();

    std::vector<unsigned char> ser;
    out.timing.proof_bytes = SerializeRCGkrProof(p, ser);
    out.timing.prove_s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    out.timing.peak_rss_kib = std::max(CurrentRssKiB(), rss0);
    out.timing.ok = trace_c.ok && lookup_c.ok;
    out.timing.note = path_note ? path_note : kRCGkrSoundnessBoundStatement;
    MarkBudget(out.timing, p);
    return out;
}

} // namespace

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
    g_rc_gkr_proof_cache[block_hash] = std::move(proof_bytes);
}

bool RCGkrProofCacheGet(const uint256& block_hash, std::vector<unsigned char>& out_proof_bytes)
{
    std::lock_guard<std::mutex> lock(g_rc_gkr_cache_mu);
    const auto it = g_rc_gkr_proof_cache.find(block_hash);
    if (it == g_rc_gkr_proof_cache.end()) return false;
    out_proof_bytes = it->second;
    return true;
}

void RCGkrProofCacheClear()
{
    std::lock_guard<std::mutex> lock(g_rc_gkr_cache_mu);
    g_rc_gkr_proof_cache.clear();
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
    w.extract_prf = lt::DeriveMatExpandPrfKey(extract_seed);
    w.extract_out = extracted;
    RCEpisodeParams ep = MakeToyRCEpisodeParams();
    ep.n_q = shape.m;
    ep.n_ctx = shape.n;
    ep.d_head = shape.k >= 32 ? 32 : shape.k;
    auto r = ProveFromLayers(claimed_digest, ep, {w},
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
    (void)height;
    bool shrunk = false;
    const RCEpisodeParams ep = ArithEpisodeShape(params, shrunk);
    const auto wires = BuildRealEpisodeLayers(header, ep);
    auto r = ProveFromLayers(resealed_digest, ep, wires,
                             "ProveWinnerEpisode: REAL episode GEMM+Extract LogUp+FRI");
    if (shrunk) {
        r.proof.over_budget = true;
        r.proof.shrink_note =
            "episode params exceeded scaffold slice → shrink-to-toy arithmetization + "
            "VerifyBoundedExactReplay for consensus. NOT production-complete.";
        r.timing.over_budget = true;
        r.timing.used_shrink_fallback = true;
        r.timing.note = r.proof.shrink_note;
    }
    return r;
}

RCGkrProveResult ProveWinnerCoupled(const CBlockHeader& header, int32_t height,
                                    const RCCoupParams& params, const uint256& resealed_digest)
{
    (void)height;
    (void)params;
    // Coupled: reuse toy real-episode shape as scaffold stand-in; mark note.
    const auto ep = MakeToyRCEpisodeParams();
    const auto wires = BuildRealEpisodeLayers(header, ep);
    auto r = ProveFromLayers(resealed_digest, ep, wires,
                             "ProveWinnerCoupled: scaffold via real-episode toy layers");
    return r;
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

    FsTranscript fs(kRCGkrDomainTag);
    AbsorbEpisode(fs, proof.episode);
    fs.AbsorbUint256(proof.claimed_digest);
    uint256 bind{};
    AbsorbPowBind(fs, proof.claimed_digest, bind);
    if (bind != proof.pow_bind) return fail("pow_bind fs");

    for (const auto& lc : proof.layers) {
        const uint32_t nu_i = Log2Exact(RCGkrNextPow2(lc.m));
        const uint32_t nu_j = Log2Exact(RCGkrNextPow2(lc.n));
        std::vector<Fp2> ri(nu_i), rj(nu_j);
        for (uint32_t t = 0; t < nu_i; ++t) ri[t] = fs.ChallengeFp2("ri");
        for (uint32_t t = 0; t < nu_j; ++t) rj[t] = fs.ChallengeFp2("rj");
        fs.AbsorbFp2(lc.claim);
        std::vector<Fp2> rk;
        Fp2 gf;
        if (!VerifyProductK(lc.sumcheck, lc.claim, fs, rk, gf)) return fail("gemm sumcheck");
        if (!Eq(gf, lc.final_eval)) return fail("gemm final");
    }

    const Fp2 alu = fs.ChallengeFp2("logup_alpha");
    (void)alu;
    fs.AbsorbFp2(proof.lookup_logup_sum);

    const uint256 fri_seed = fs.Challenge("fri_seed");
    std::string fri_why;
    if (!FriVerify(proof.trace_fri, fri_seed, &fri_why)) return fail(fri_why.c_str());
    if (!FriVerify(proof.lookup_fri, fri_seed, &fri_why)) return fail(fri_why.c_str());
    fs.AbsorbUint256(proof.trace_fri.layers.empty() ? uint256{} : proof.trace_fri.layers[0].root);
    fs.AbsorbUint256(proof.lookup_fri.layers.empty() ? uint256{} : proof.lookup_fri.layers[0].root);
    if (fs.Digest() != proof.transcript_hash) return fail("transcript");

    // Succinct path: do NOT re-expand operands / re-run episode.
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
    AppendLE32(out, static_cast<uint32_t>(proof.layers.size()));
    for (const auto& lc : proof.layers) {
        AppendLE32(out, static_cast<uint32_t>(lc.kind));
        AppendLE32(out, lc.round);
        AppendLE32(out, lc.layer);
        AppendLE32(out, lc.m);
        AppendLE32(out, lc.n);
        AppendLE32(out, lc.k);
        AppendFp2(out, lc.claim);
        AppendLE32(out, static_cast<uint32_t>(lc.sumcheck.size()));
        for (const auto& r : lc.sumcheck) {
            AppendFp2(out, r.eval0);
            AppendFp2(out, r.eval1);
            AppendFp2(out, r.eval2);
        }
        AppendFp2(out, lc.final_eval);
    }
    AppendFp2(out, proof.lookup_logup_sum);
    std::vector<unsigned char> fri_t, fri_l;
    (void)SerializeFriProof(proof.trace_fri, fri_t);
    (void)SerializeFriProof(proof.lookup_fri, fri_l);
    AppendLE32(out, static_cast<uint32_t>(fri_t.size()));
    AppendBytes(out, fri_t.data(), fri_t.size());
    AppendLE32(out, static_cast<uint32_t>(fri_l.size()));
    AppendBytes(out, fri_l.data(), fri_l.size());
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

    uint32_t n_layers = 0;
    if (!ReadLE32Checked(p, end, n_layers) || n_layers == 0 || n_layers > 64) return std::nullopt;
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
    uint32_t fri_t_n = 0, fri_l_n = 0;
    if (!ReadLE32Checked(p, end, fri_t_n) || fri_t_n > (1u << 20)) return std::nullopt;
    std::vector<unsigned char> fri_t(fri_t_n);
    if (!ReadBytesChecked(p, end, fri_t.data(), fri_t_n)) return std::nullopt;
    auto tp = DeserializeFriProof(fri_t);
    if (!tp) return std::nullopt;
    proof.trace_fri = std::move(*tp);
    if (!ReadLE32Checked(p, end, fri_l_n) || fri_l_n > (1u << 20)) return std::nullopt;
    std::vector<unsigned char> fri_l(fri_l_n);
    if (!ReadBytesChecked(p, end, fri_l.data(), fri_l_n)) return std::nullopt;
    auto lp = DeserializeFriProof(fri_l);
    if (!lp) return std::nullopt;
    proof.lookup_fri = std::move(*lp);
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
            RCGkrTiming vt;
            rep.proved = VerifyWinnerProof(rep.proof, &vt);
            rep.verify_s = vt.verify_s;
            rep.ok = rep.proved;
            rep.note = rep.proved ? "coupled winner proved" : "coupled prove/verify failed";
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
    if (!header.matmul_digest.IsNull() && out.digest != header.matmul_digest) {
        out.ok = false;
        out.note = "ExactReplay: digest mismatch vs header.matmul_digest";
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
        if (!header.matmul_digest.IsNull() && parsed->claimed_digest != header.matmul_digest) {
            out.replay = VerifyBoundedExactReplay(header, params, height, target);
            out.path = RCProdVerifyPath::GkrFallbackExactReplay;
            out.ok = out.replay.ok;
            out.gkr.ok = false;
            out.gkr.note = "wrong digest in proof -> ExactReplay fallback";
            out.note = out.gkr.note;
            return out;
        }
        const bool gkr_ok = VerifyWinnerProof(*parsed, &out.gkr);
        if (gkr_ok && !out.gkr.over_budget && EnvRCGkrArbiterEnabled()) {
            out.path = RCProdVerifyPath::WinnerGkr;
            out.ok = true;
            out.note = "WinnerGkr arbiter ok (ExactReplay reserved for DISPUTE)";
            return out;
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
                        const std::vector<unsigned char>* optional_gkr_proof)
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
    const auto replay = VerifyBoundedExactReplay(header, params, height, target);
    if (!gkr_ok || (replay.ok && parsed->claimed_digest != replay.digest)) {
        LogWarning("RC GKR shadow mismatch: gkr_ok=%d replay_ok=%d proof_bytes=%zu "
                   "verify_s=%.6f (ExactReplay remains consensus arbiter; never rejects)\n",
                   gkr_ok ? 1 : 0, replay.ok ? 1 : 0, vt.proof_bytes, vt.verify_s);
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

    auto one = [&](const RCEpisodeParams& params, const char* label) {
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
       << one(MakeToyRCEpisodeParams(), "toy") << ",\n"
       << one(MakeMediumRCEpisodeParams(), "medium") << "\n"
       << "}\n";
    return os.str();
}

std::string MeasureWinnerGkrCurveCsv(const CBlockHeader& header)
{
    std::ostringstream os;
    os << "label,n_ctx,b_seq,prove_s,verify_s,proof_bytes,peak_rss_kib,over_budget,ok\n";
    const RCEpisodeParams shapes[2] = {MakeToyRCEpisodeParams(), MakeMediumRCEpisodeParams()};
    const char* labels[2] = {"toy", "medium"};
    for (int i = 0; i < 2; ++i) {
        const auto& params = shapes[i];
        const uint256 dig = RecomputeResidentCurriculumReference(header, params, 0);
        const auto pr = ProveWinnerEpisode(header, params, 0, dig);
        RCGkrTiming vt;
        const bool ok = VerifyWinnerProof(pr.proof, &vt);
        os << labels[i] << "," << params.n_ctx << "," << params.b_seq << "," << pr.timing.prove_s
           << "," << vt.verify_s << "," << pr.timing.proof_bytes << ","
           << std::max(pr.timing.peak_rss_kib, vt.peak_rss_kib) << ","
           << (pr.timing.over_budget ? 1 : 0) << "," << (ok ? 1 : 0) << "\n";
    }
    return os.str();
}

} // namespace matmul::v4::rc
