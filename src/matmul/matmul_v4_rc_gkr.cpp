// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_gkr.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc_extract.h>

#include <cassert>
#include <chrono>
#include <cstring>
#include <sstream>
#include <utility>

namespace matmul::v4::rc {
namespace {

using gkr_field::Add;
using gkr_field::Div;
using gkr_field::FromChallengeBytes;
using gkr_field::FromSigned;
using gkr_field::Inv;
using gkr_field::Mul;
using gkr_field::Sub;

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
    void AbsorbFp(Fp v) { AppendLE64(m_buf, v); }
    void AbsorbUint256(const uint256& h) { AppendBytes(m_buf, h.data(), 32); }
    void AbsorbI64(int64_t v) { AppendLE64(m_buf, static_cast<uint64_t>(v)); }
    uint256 Challenge(const char* label)
    {
        AbsorbBytes(reinterpret_cast<const unsigned char*>(label), std::strlen(label));
        const uint256 h = Sha256dBytes(m_buf.data(), m_buf.size());
        AbsorbUint256(h);
        return h;
    }
    Fp ChallengeFp(const char* label) { return FromChallengeBytes(Challenge(label).data()); }
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

Fp EvalEqBit(Fp r, uint32_t bit) { return bit ? r : Sub(1, r); }

Fp EqFactor(const std::vector<Fp>& r, uint32_t index)
{
    Fp acc = 1;
    for (size_t i = 0; i < r.size(); ++i) acc = Mul(acc, EvalEqBit(r[i], (index >> i) & 1u));
    return acc;
}

Fp EvalDeg1(Fp a, Fp b, Fp x) { return Add(Mul(a, Sub(1, x)), Mul(b, x)); }
Fp EvalDeg2(Fp g0, Fp g1, Fp g2, Fp x)
{
    const Fp inv2 = Inv(2);
    return Add(Add(Mul(Mul(g0, Mul(Sub(1, x), Sub(2, x))), inv2), Mul(g1, Mul(x, Sub(2, x)))),
               Mul(Mul(g2, Mul(x, Sub(x, 1))), inv2));
}

Fp MleEvalMatrix(const std::vector<Fp>& mat, uint32_t rows, uint32_t cols,
                 const std::vector<Fp>& r_row, const std::vector<Fp>& r_col)
{
    Fp acc = 0;
    for (uint32_t i = 0; i < rows; ++i) {
        const Fp ei = EqFactor(r_row, i);
        for (uint32_t j = 0; j < cols; ++j) {
            acc = Add(acc, Mul(Mul(mat[static_cast<size_t>(i) * cols + j], ei), EqFactor(r_col, j)));
        }
    }
    return acc;
}

std::vector<RCGkrSumcheckRound> ProveSumcheck1D(const std::vector<Fp>& f, Fp claim, FsTranscript& fs,
                                                std::vector<Fp>& out_r, Fp& out_final)
{
    std::vector<Fp> cur = f;
    std::vector<RCGkrSumcheckRound> rounds;
    out_r.clear();
    Fp expected = claim;
    const uint32_t nu = Log2Exact(static_cast<uint32_t>(f.size()));
    for (uint32_t round = 0; round < nu; ++round) {
        Fp g0 = 0, g1 = 0;
        for (size_t idx = 0; idx < cur.size(); ++idx) {
            if ((idx & 1u) == 0) g0 = Add(g0, cur[idx]);
            else g1 = Add(g1, cur[idx]);
        }
        assert(Add(g0, g1) == expected);
        rounds.push_back({g0, g1, 0});
        fs.AbsorbFp(g0);
        fs.AbsorbFp(g1);
        const Fp r = fs.ChallengeFp("sumcheck_r");
        out_r.push_back(r);
        expected = EvalDeg1(g0, g1, r);
        std::vector<Fp> nxt(cur.size() / 2);
        for (size_t i = 0; i < nxt.size(); ++i) {
            nxt[i] = Add(Mul(Sub(1, r), cur[2 * i]), Mul(r, cur[2 * i + 1]));
        }
        cur = std::move(nxt);
    }
    out_final = expected;
    return rounds;
}

bool VerifySumcheck1D(const std::vector<RCGkrSumcheckRound>& rounds, Fp claim, FsTranscript& fs,
                      std::vector<Fp>& out_r, Fp& out_final)
{
    Fp expected = claim;
    out_r.clear();
    for (const auto& m : rounds) {
        if (Add(m.eval0, m.eval1) != expected) return false;
        fs.AbsorbFp(m.eval0);
        fs.AbsorbFp(m.eval1);
        const Fp r = fs.ChallengeFp("sumcheck_r");
        out_r.push_back(r);
        expected = EvalDeg1(m.eval0, m.eval1, r);
    }
    out_final = expected;
    return true;
}

std::vector<RCGkrSumcheckRound> ProveProductK(const std::vector<Fp>& A, uint32_t m, uint32_t k_dim,
                                              const std::vector<Fp>& B, uint32_t n,
                                              const std::vector<Fp>& r_i, const std::vector<Fp>& r_j,
                                              Fp claim, FsTranscript& fs, std::vector<Fp>& out_r,
                                              Fp& out_final)
{
    const uint32_t k_pad = RCGkrNextPow2(k_dim);
    std::vector<Fp> wi(RCGkrNextPow2(m), 0), wj(RCGkrNextPow2(n), 0);
    for (uint32_t i = 0; i < m; ++i) wi[i] = EqFactor(r_i, i);
    for (uint32_t j = 0; j < n; ++j) wj[j] = EqFactor(r_j, j);
    std::vector<Fp> a(k_pad, 0), b(k_pad, 0);
    for (uint32_t t = 0; t < k_dim; ++t) {
        Fp sa = 0, sb = 0;
        for (uint32_t i = 0; i < m; ++i) sa = Add(sa, Mul(wi[i], A[static_cast<size_t>(i) * k_dim + t]));
        for (uint32_t j = 0; j < n; ++j) sb = Add(sb, Mul(B[static_cast<size_t>(t) * n + j], wj[j]));
        a[t] = sa;
        b[t] = sb;
    }
    std::vector<RCGkrSumcheckRound> rounds;
    out_r.clear();
    Fp expected = claim;
    const uint32_t nu = Log2Exact(k_pad);
    for (uint32_t round = 0; round < nu; ++round) {
        auto eg = [&](Fp X) {
            Fp s = 0;
            for (size_t i = 0; i < a.size() / 2; ++i) {
                const Fp av = Add(Mul(Sub(1, X), a[2 * i]), Mul(X, a[2 * i + 1]));
                const Fp bv = Add(Mul(Sub(1, X), b[2 * i]), Mul(X, b[2 * i + 1]));
                s = Add(s, Mul(av, bv));
            }
            return s;
        };
        const Fp g0 = eg(0), g1 = eg(1), g2 = eg(2);
        assert(Add(g0, g1) == expected);
        rounds.push_back({g0, g1, g2});
        fs.AbsorbFp(g0);
        fs.AbsorbFp(g1);
        fs.AbsorbFp(g2);
        const Fp r = fs.ChallengeFp("prod_sumcheck_r");
        out_r.push_back(r);
        expected = EvalDeg2(g0, g1, g2, r);
        std::vector<Fp> an(a.size() / 2), bn(b.size() / 2);
        for (size_t i = 0; i < an.size(); ++i) {
            an[i] = Add(Mul(Sub(1, r), a[2 * i]), Mul(r, a[2 * i + 1]));
            bn[i] = Add(Mul(Sub(1, r), b[2 * i]), Mul(r, b[2 * i + 1]));
        }
        a = std::move(an);
        b = std::move(bn);
    }
    out_final = expected;
    return rounds;
}

bool VerifyProductK(const std::vector<RCGkrSumcheckRound>& rounds, Fp claim, FsTranscript& fs,
                    std::vector<Fp>& out_r, Fp& out_final)
{
    Fp expected = claim;
    out_r.clear();
    for (const auto& m : rounds) {
        if (Add(m.eval0, m.eval1) != expected) return false;
        fs.AbsorbFp(m.eval0);
        fs.AbsorbFp(m.eval1);
        fs.AbsorbFp(m.eval2);
        const Fp r = fs.ChallengeFp("prod_sumcheck_r");
        out_r.push_back(r);
        expected = EvalDeg2(m.eval0, m.eval1, m.eval2, r);
    }
    out_final = expected;
    return true;
}

Fp HashTile(const RCGkrLookupOpening& o)
{
    std::vector<unsigned char> buf;
    AppendLE32(buf, o.row);
    AppendLE32(buf, o.block);
    for (int64_t v : o.raw64) AppendLE64(buf, static_cast<uint64_t>(v));
    AppendBytes(buf, reinterpret_cast<const unsigned char*>(o.out8.data()), o.out8.size());
    buf.push_back(o.scale);
    AppendLE64(buf, o.multiplicity);
    return FromChallengeBytes(Sha256dBytes(buf.data(), buf.size()).data());
}

std::vector<Fp> ToFpI64(const std::vector<int64_t>& v)
{
    std::vector<Fp> o(v.size());
    for (size_t i = 0; i < v.size(); ++i) o[i] = FromSigned(v[i]);
    return o;
}
std::vector<Fp> ToFpI8(const std::vector<int8_t>& v)
{
    std::vector<Fp> o(v.size());
    for (size_t i = 0; i < v.size(); ++i) o[i] = FromSigned(v[i]);
    return o;
}

void AbsorbShape(FsTranscript& fs, const DistSynthShape& s)
{
    fs.AbsorbU32(s.m);
    fs.AbsorbU32(s.n);
    fs.AbsorbU32(s.k);
    fs.AbsorbU32(s.seg_len);
}

uint256 MixSeed(const uint256& d, const char* tag) { return DeriveTagged(d, tag); }

} // namespace

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
        acc = Add(acc, Mul(evals_pow2[i], EqFactor(r, static_cast<uint32_t>(i))));
    }
    return acc;
}

RCGkrProveResult ProveWinnerFromSegments(const uint256& claimed_digest, const DistSynthShape& shape,
                                         const std::vector<std::vector<int64_t>>& segs,
                                         const uint256& extract_seed, const std::vector<int8_t>* A,
                                         const std::vector<int8_t>* B)
{
    RCGkrProveResult out;
    const auto t0 = std::chrono::steady_clock::now();
    const auto Y = SumSegmentPartials(segs);
    const auto extracted = ExtractOnce(extract_seed, Y, shape.m, shape.n);

    RCGkrProof& p = out.proof;
    p.version = kRCGkrProofVersion;
    p.claimed_digest = claimed_digest;
    p.shape = shape;
    p.claimed_Y = Y;
    p.claimed_extract = extracted;

    FsTranscript fs(kRCGkrDomainTag);
    AbsorbShape(fs, shape);
    fs.AbsorbUint256(claimed_digest);
    for (int64_t v : Y) fs.AbsorbI64(v);
    fs.AbsorbBytes(reinterpret_cast<const unsigned char*>(extracted.data()), extracted.size());

    if (A && B && A->size() == static_cast<size_t>(shape.m) * shape.k &&
        B->size() == static_cast<size_t>(shape.k) * shape.n) {
        const auto Af = ToFpI8(*A), Bf = ToFpI8(*B), Yf = ToFpI64(Y);
        const uint32_t nu_i = Log2Exact(RCGkrNextPow2(shape.m));
        const uint32_t nu_j = Log2Exact(RCGkrNextPow2(shape.n));
        std::vector<Fp> ri(nu_i), rj(nu_j);
        for (uint32_t t = 0; t < nu_i; ++t) ri[t] = fs.ChallengeFp("ri");
        for (uint32_t t = 0; t < nu_j; ++t) rj[t] = fs.ChallengeFp("rj");
        const Fp yc = MleEvalMatrix(Yf, shape.m, shape.n, ri, rj);
        fs.AbsorbFp(yc);
        std::vector<Fp> rk;
        p.gemm_sumcheck =
            ProveProductK(Af, shape.m, shape.k, Bf, shape.n, ri, rj, yc, fs, rk, p.gemm_final_eval);
    }

    const size_t elems = Y.size();
    std::vector<Fp> alpha(elems);
    for (size_t e = 0; e < elems; ++e) alpha[e] = fs.ChallengeFp("seg_alpha");
    Fp wY = 0;
    for (size_t e = 0; e < elems; ++e) wY = Add(wY, Mul(alpha[e], FromSigned(Y[e])));
    fs.AbsorbFp(wY);

    const uint32_t n_segs = static_cast<uint32_t>(segs.size());
    std::vector<Fp> f(RCGkrNextPow2(std::max(n_segs, 1u)), 0);
    for (uint32_t s = 0; s < n_segs; ++s) {
        Fp v = 0;
        for (size_t e = 0; e < elems; ++e) v = Add(v, Mul(alpha[e], FromSigned(segs[s][e])));
        f[s] = v;
    }
    std::vector<Fp> rseg;
    p.sumcheck = ProveSumcheck1D(f, wY, fs, rseg, p.final_eval);

    const uint256 prf = lt::DeriveMatExpandPrfKey(extract_seed);
    const uint32_t n_blocks = shape.n / kRCMxBlockLen;
    const Fp alu = fs.ChallengeFp("logup_alpha");
    Fp logup = 0;
    for (uint32_t i = 0; i < shape.m; ++i) {
        for (uint32_t bj = 0; bj < n_blocks; ++bj) {
            RCGkrLookupOpening o;
            o.row = i;
            o.block = bj;
            o.raw64.resize(kRCMxBlockLen);
            o.out8.resize(kRCMxBlockLen);
            const size_t base = static_cast<size_t>(i) * shape.n + static_cast<size_t>(bj) * kRCMxBlockLen;
            for (uint32_t t = 0; t < kRCMxBlockLen; ++t) {
                o.raw64[t] = Y[base + t];
                o.out8[t] = extracted[base + t];
            }
            o.scale = lt::DeriveMatExpandMxScale(prf, i, bj);
            o.multiplicity = 1;
            int8_t chk[kRCMxBlockLen];
            ExtractMXTileInt64(prf, i, bj, o.raw64.data(), chk);
            for (uint32_t t = 0; t < kRCMxBlockLen; ++t) assert(chk[t] == o.out8[t]);
            logup = Add(logup, Div(1, Sub(alu, HashTile(o))));
            p.lookups.push_back(std::move(o));
        }
    }
    p.lookup_logup_sum = logup;
    fs.AbsorbFp(logup);
    p.transcript_hash = fs.Digest();

    std::vector<unsigned char> ser;
    out.timing.proof_bytes = SerializeRCGkrProof(p, ser);
    out.timing.prove_s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    out.timing.ok = true;
    out.timing.note = kRCGkrSoundnessStatement;
    return out;
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
    (void)header;
    (void)params;
    (void)height;
    const uint256 seed = MixSeed(resealed_digest, "BTX_RC_GKR_EPISODE_SEED_V1");
    DistSynthShape shape{32, 32, 128, 32};
    auto r = ProveWinnerSynth(seed, shape, resealed_digest);
    r.timing.note = "ProveWinnerEpisode digest-bound synth GKR";
    return r;
}

RCGkrProveResult ProveWinnerCoupled(const CBlockHeader& header, int32_t height,
                                    const RCCoupParams& params, const uint256& resealed_digest)
{
    (void)header;
    (void)height;
    const bool medium = params.barriers > kRCCoupRounds || params.lobes > kRCCoupLobes;
    const uint256 seed = MixSeed(resealed_digest, "BTX_RC_GKR_COUPLED_SEED_V1");
    DistSynthShape shape = medium ? DistSynthShape{64, 64, 256, 64} : DistSynthShape{32, 32, 128, 32};
    auto r = ProveWinnerSynth(seed, shape, resealed_digest);
    r.timing.note = "ProveWinnerCoupled digest-bound synth GKR";
    return r;
}

bool VerifyWinnerProof(const RCGkrProof& proof, const DistSynthShape& shape,
                       const std::vector<std::vector<int64_t>>& segs, const uint256& extract_seed,
                       RCGkrTiming* out_timing)
{
    const auto t0 = std::chrono::steady_clock::now();
    auto fail = [&]() {
        if (out_timing) {
            out_timing->verify_s =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            out_timing->ok = false;
        }
        return false;
    };

    if (proof.version != kRCGkrProofVersion) return fail();
    if (proof.shape.m != shape.m || proof.shape.n != shape.n || proof.shape.k != shape.k ||
        proof.shape.seg_len != shape.seg_len)
        return fail();
    if (segs.size() != DistNumSegs(shape.k, shape.seg_len)) return fail();
    if (proof.claimed_Y != SumSegmentPartials(segs)) return fail();
    if (proof.claimed_extract.size() != proof.claimed_Y.size()) return fail();

    FsTranscript fs(kRCGkrDomainTag);
    AbsorbShape(fs, shape);
    fs.AbsorbUint256(proof.claimed_digest);
    for (int64_t v : proof.claimed_Y) fs.AbsorbI64(v);
    fs.AbsorbBytes(reinterpret_cast<const unsigned char*>(proof.claimed_extract.data()),
                   proof.claimed_extract.size());

    if (!proof.gemm_sumcheck.empty()) {
        const uint32_t nu_i = Log2Exact(RCGkrNextPow2(shape.m));
        const uint32_t nu_j = Log2Exact(RCGkrNextPow2(shape.n));
        std::vector<Fp> ri(nu_i), rj(nu_j);
        for (uint32_t t = 0; t < nu_i; ++t) ri[t] = fs.ChallengeFp("ri");
        for (uint32_t t = 0; t < nu_j; ++t) rj[t] = fs.ChallengeFp("rj");
        const Fp yc = MleEvalMatrix(ToFpI64(proof.claimed_Y), shape.m, shape.n, ri, rj);
        fs.AbsorbFp(yc);
        std::vector<Fp> rk;
        Fp gf = 0;
        if (!VerifyProductK(proof.gemm_sumcheck, yc, fs, rk, gf)) return fail();
        if (gf != proof.gemm_final_eval) return fail();
    }

    const size_t elems = proof.claimed_Y.size();
    std::vector<Fp> alpha(elems);
    for (size_t e = 0; e < elems; ++e) alpha[e] = fs.ChallengeFp("seg_alpha");
    Fp wY = 0;
    for (size_t e = 0; e < elems; ++e) wY = Add(wY, Mul(alpha[e], FromSigned(proof.claimed_Y[e])));
    fs.AbsorbFp(wY);
    std::vector<Fp> rseg;
    Fp sf = 0;
    if (!VerifySumcheck1D(proof.sumcheck, wY, fs, rseg, sf)) return fail();
    if (sf != proof.final_eval) return fail();

    {
        const uint32_t n_segs = static_cast<uint32_t>(segs.size());
        std::vector<Fp> f(RCGkrNextPow2(std::max(n_segs, 1u)), 0);
        for (uint32_t s = 0; s < n_segs; ++s) {
            Fp v = 0;
            for (size_t e = 0; e < elems; ++e) v = Add(v, Mul(alpha[e], FromSigned(segs[s][e])));
            f[s] = v;
        }
        if (RCGkrMleEval1D(f, rseg) != sf) return fail();
    }

    const uint256 prf = lt::DeriveMatExpandPrfKey(extract_seed);
    const uint32_t n_blocks = shape.n / kRCMxBlockLen;
    if (proof.lookups.size() != static_cast<size_t>(shape.m) * n_blocks) return fail();
    const Fp alu = fs.ChallengeFp("logup_alpha");
    Fp logup = 0;
    for (const auto& o : proof.lookups) {
        if (o.raw64.size() != kRCMxBlockLen || o.out8.size() != kRCMxBlockLen) return fail();
        const size_t base =
            static_cast<size_t>(o.row) * shape.n + static_cast<size_t>(o.block) * kRCMxBlockLen;
        for (uint32_t t = 0; t < kRCMxBlockLen; ++t) {
            if (o.raw64[t] != proof.claimed_Y[base + t]) return fail();
            if (o.out8[t] != proof.claimed_extract[base + t]) return fail();
        }
        if (o.scale != lt::DeriveMatExpandMxScale(prf, o.row, o.block)) return fail();
        int8_t chk[kRCMxBlockLen];
        ExtractMXTileInt64(prf, o.row, o.block, o.raw64.data(), chk);
        for (uint32_t t = 0; t < kRCMxBlockLen; ++t)
            if (chk[t] != o.out8[t]) return fail();
        const Fp z = HashTile(o);
        if (z == alu) return fail();
        logup = Add(logup, Div(1, Sub(alu, z)));
    }
    if (logup != proof.lookup_logup_sum) return fail();
    fs.AbsorbFp(logup);
    if (fs.Digest() != proof.transcript_hash) return fail();

    if (out_timing) {
        out_timing->verify_s =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        std::vector<unsigned char> ser;
        out_timing->proof_bytes = SerializeRCGkrProof(proof, ser);
        out_timing->ok = true;
        out_timing->note = "VerifyWinnerProof ok";
    }
    return true;
}

bool VerifyWinnerProofPublic(const RCGkrProof& proof, const uint256& seed,
                             const DistSynthShape& shape, RCGkrTiming* out_timing)
{
    std::vector<int8_t> A, B;
    ExpandSynthOperands(seed, shape, A, B);
    auto parts = SimulateDevices(A, B, shape, 1);
    const uint256 extract_seed = DeriveTagged(seed, "BTX_RC_DIST_EXTRACT_V1");

    // Optional: bind GEMM final oracle with A,B when gemm rounds present.
    if (!proof.gemm_sumcheck.empty()) {
        FsTranscript fs(kRCGkrDomainTag);
        AbsorbShape(fs, proof.shape);
        fs.AbsorbUint256(proof.claimed_digest);
        for (int64_t v : proof.claimed_Y) fs.AbsorbI64(v);
        fs.AbsorbBytes(reinterpret_cast<const unsigned char*>(proof.claimed_extract.data()),
                       proof.claimed_extract.size());
        const auto Af = ToFpI8(A), Bf = ToFpI8(B), Yf = ToFpI64(proof.claimed_Y);
        const uint32_t nu_i = Log2Exact(RCGkrNextPow2(shape.m));
        const uint32_t nu_j = Log2Exact(RCGkrNextPow2(shape.n));
        std::vector<Fp> ri(nu_i), rj(nu_j);
        for (uint32_t t = 0; t < nu_i; ++t) ri[t] = fs.ChallengeFp("ri");
        for (uint32_t t = 0; t < nu_j; ++t) rj[t] = fs.ChallengeFp("rj");
        const Fp yc = MleEvalMatrix(Yf, shape.m, shape.n, ri, rj);
        fs.AbsorbFp(yc);
        std::vector<Fp> rk;
        Fp gf = 0;
        if (!VerifyProductK(proof.gemm_sumcheck, yc, fs, rk, gf) || gf != proof.gemm_final_eval) {
            if (out_timing) out_timing->ok = false;
            return false;
        }
        const uint32_t k_pad = RCGkrNextPow2(shape.k);
        std::vector<Fp> wi(RCGkrNextPow2(shape.m), 0), wj(RCGkrNextPow2(shape.n), 0);
        for (uint32_t i = 0; i < shape.m; ++i) wi[i] = EqFactor(ri, i);
        for (uint32_t j = 0; j < shape.n; ++j) wj[j] = EqFactor(rj, j);
        std::vector<Fp> ah(k_pad, 0), bh(k_pad, 0);
        for (uint32_t t = 0; t < shape.k; ++t) {
            Fp sa = 0, sb = 0;
            for (uint32_t i = 0; i < shape.m; ++i)
                sa = Add(sa, Mul(wi[i], Af[static_cast<size_t>(i) * shape.k + t]));
            for (uint32_t j = 0; j < shape.n; ++j)
                sb = Add(sb, Mul(Bf[static_cast<size_t>(t) * shape.n + j], wj[j]));
            ah[t] = sa;
            bh[t] = sb;
        }
        if (Mul(RCGkrMleEval1D(ah, rk), RCGkrMleEval1D(bh, rk)) != gf) {
            if (out_timing) out_timing->ok = false;
            return false;
        }
    }

    return VerifyWinnerProof(proof, shape, parts.segs, extract_seed, out_timing);
}

size_t SerializeRCGkrProof(const RCGkrProof& proof, std::vector<unsigned char>& out)
{
    out.clear();
    AppendLE32(out, proof.version);
    AppendBytes(out, proof.claimed_digest.data(), 32);
    AppendLE32(out, proof.shape.m);
    AppendLE32(out, proof.shape.n);
    AppendLE32(out, proof.shape.k);
    AppendLE32(out, proof.shape.seg_len);
    AppendLE32(out, static_cast<uint32_t>(proof.claimed_Y.size()));
    for (int64_t v : proof.claimed_Y) AppendLE64(out, static_cast<uint64_t>(v));
    AppendLE32(out, static_cast<uint32_t>(proof.claimed_extract.size()));
    AppendBytes(out, reinterpret_cast<const unsigned char*>(proof.claimed_extract.data()),
                proof.claimed_extract.size());
    AppendLE32(out, static_cast<uint32_t>(proof.sumcheck.size()));
    for (const auto& r : proof.sumcheck) {
        AppendLE64(out, r.eval0);
        AppendLE64(out, r.eval1);
        AppendLE64(out, r.eval2);
    }
    AppendLE32(out, static_cast<uint32_t>(proof.gemm_sumcheck.size()));
    for (const auto& r : proof.gemm_sumcheck) {
        AppendLE64(out, r.eval0);
        AppendLE64(out, r.eval1);
        AppendLE64(out, r.eval2);
    }
    AppendLE64(out, proof.final_eval);
    AppendLE64(out, proof.gemm_final_eval);
    AppendLE64(out, proof.lookup_logup_sum);
    AppendLE32(out, static_cast<uint32_t>(proof.lookups.size()));
    for (const auto& o : proof.lookups) {
        AppendLE32(out, o.row);
        AppendLE32(out, o.block);
        for (int64_t v : o.raw64) AppendLE64(out, static_cast<uint64_t>(v));
        AppendBytes(out, reinterpret_cast<const unsigned char*>(o.out8.data()), o.out8.size());
        out.push_back(o.scale);
        AppendLE64(out, o.multiplicity);
    }
    AppendBytes(out, proof.transcript_hash.data(), 32);
    return out.size();
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
            RCGkrTiming vt;
            const uint256 seed = MixSeed(reseal, "BTX_RC_GKR_EPISODE_SEED_V1");
            DistSynthShape shape{32, 32, 128, 32};
            rep.proved = VerifyWinnerProofPublic(rep.proof, seed, shape, &vt);
            rep.verify_s = vt.verify_s;
            rep.ok = rep.proved;
            rep.note = rep.proved ? "winner proved" : "prove/verify failed";
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
            RCGkrTiming vt;
            const bool medium = params.barriers > kRCCoupRounds || params.lobes > kRCCoupLobes;
            const uint256 seed = MixSeed(reseal, "BTX_RC_GKR_COUPLED_SEED_V1");
            DistSynthShape shape =
                medium ? DistSynthShape{64, 64, 256, 64} : DistSynthShape{32, 32, 128, 32};
            rep.proved = VerifyWinnerProofPublic(rep.proof, seed, shape, &vt);
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

std::string RunWinnerGkrBakeoffSection(const uint256& synth_seed, const DistSynthShape& shape)
{
    const auto ep = RunSyntheticDistributed(synth_seed, shape, 1, DistReduceOrder::TreeLeftToRight);
    const auto pr = ProveWinnerSynth(synth_seed, shape, ep.digest);
    RCGkrTiming vt;
    const bool ok = VerifyWinnerProofPublic(pr.proof, synth_seed, shape, &vt);
    std::ostringstream os;
    os << "  \"winner_gkr\": {\n"
       << "    \"direction\": \"DECIDED winner-only GKR/sumcheck\",\n"
       << "    \"soundness\": \"computational_not_eps0\",\n"
       << "    \"prove_s\": " << pr.timing.prove_s << ",\n"
       << "    \"verify_s\": " << vt.verify_s << ",\n"
       << "    \"proof_bytes\": " << pr.timing.proof_bytes << ",\n"
       << "    \"ok\": " << (ok ? "true" : "false") << "\n"
       << "  }";
    return os.str();
}

} // namespace matmul::v4::rc
