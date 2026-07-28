// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_air_quotient.h>

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_alg_hash.h>
#include <matmul/matmul_v4_rc_stage3_safe_v12.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <span.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <future>
#include <limits>
#include <type_traits>

#if defined(_OPENMP)
#include <omp.h>
#endif

// AIR constraint-quotient construction — implementation. See the header for
// the construction map and the per-rule honesty statement (what arithmetizes
// cleanly and what — the tile-tree SHA rule — does not).

namespace matmul::v4::rc::air_quotient {

using gkr_field::Fp;

namespace {

// Prover thread count: BTX_PROVE_THREADS if set (>0), else all cores.
// Every parallelized phase writes only to distinct output indices, so the
// thread count and OpenMP schedule never change the produced bytes — the
// multi-threaded proof is byte-identical to the single-threaded one.
inline int BtxProveThreads()
{
#if defined(_OPENMP)
    static const int t = [] {
        if (const char* e = std::getenv("BTX_PROVE_THREADS")) {
            const int v = std::atoi(e);
            if (v > 0) return v;
        }
        return omp_get_max_threads();
    }();
    return t;
#else
    return 1;
#endif
}

// Optional per-phase wall-clock instrumentation, gated by BTX_PROVE_TIMING.
// Prints nothing (and costs nothing but a clock read) when the env is unset, so
// it never affects the produced proof.
struct BtxPhaseTimer {
    const bool on;
    std::chrono::steady_clock::time_point last;
    std::chrono::steady_clock::time_point start;
    BtxPhaseTimer()
        : on(std::getenv("BTX_PROVE_TIMING") != nullptr),
          last(std::chrono::steady_clock::now()),
          start(last) {}
    void mark(const char* name)
    {
        const auto now = std::chrono::steady_clock::now();
        if (on) {
            const double ms =
                std::chrono::duration<double, std::milli>(now - last).count();
            std::fprintf(stderr, "[BTX_TIMING] %-24s %12.1f ms  (threads=%d)\n",
                         name, ms, BtxProveThreads());
            std::fflush(stderr);
        }
        last = now;
    }
    void total(const char* name)
    {
        if (!on) return;
        const auto now = std::chrono::steady_clock::now();
        const double ms =
            std::chrono::duration<double, std::milli>(now - start).count();
        std::fprintf(stderr, "[BTX_TIMING] %-24s %12.1f ms  TOTAL\n", name, ms);
        std::fflush(stderr);
    }
};

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

template <typename F>
F AirMulBase(const F& value, Fp scalar)
{
    if constexpr (std::is_same_v<F, gkr_field::Fp3>) {
        return gkr_field::MulBase(value, scalar);
    } else {
        return AirField<F>::Mul(
            value, AirField<F>::FromBase(scalar));
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
                const F v =
                    AirMulBase(a[i + j + len / 2], w);
                a[i + j] = T::Add(u, v);
                a[i + j + len / 2] = T::Sub(u, v);
                w = gkr_field::Mul(w, w_len);
            }
        }
    }
    if (inverse) {
        const Fp inv_n =
            gkr_field::Inv(static_cast<Fp>(n));
        for (auto& x : a) {
            x = AirMulBase(x, inv_n);
        }
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

/**
 * COSET SLICE of AirEvalOnSubgroup, written into `out` (which is reused
 * across calls so the composition slab never reallocates).
 *
 *   out[t] = P(twist · ω_N^t),  t ∈ [0, N),  P = Σ_i coeffs[i] X^i
 *
 * IDENTITY THIS RELIES ON.  Let M = stepM · N and twist = ω_M^s.  Then
 * ω_M^{s + stepM·t} = ω_M^s · ω_M^{stepM·t} = twist · ω_N^t, so
 *
 *   AirEvalOnCosetInto(coeffs, N, ω_M^s, out)  =>
 *       out[t] == AirEvalOnSubgroup(coeffs, M)[s + stepM·t]
 *
 * for every t — the s-th coset of H_N inside the size-M subgroup, in natural
 * t order.  Ranging s over [0, stepM) therefore covers the M-domain exactly
 * once, at W x N residency instead of W x M.
 *
 * P(twist·ω_N^t) = Σ_i coeffs[i]·twist^i·ω_N^{t·i} and ω_N^{t·i} depends only
 * on i mod N, so the twisted coefficients fold onto i mod N and one size-N
 * NTT finishes the job.  (Here coeffs.size() == N, so the fold is a no-op;
 * it is written out so the helper is correct for any coefficient count.)
 *
 * Exactness: Goldilocks Add/Sub/Mul return canonical residues in [0, p), so
 * this schedule and AirEvalOnSubgroup produce BIT-IDENTICAL vectors, not
 * merely equal-up-to-representation ones.  Cross-checked against the exact
 * AirNtt recurrence at (N,M) = (4,32), (8,8), (16,128) and the real-shape
 * (256, 2048) before this was written.
 */
template <typename F>
void AirEvalOnCosetInto(const std::vector<F>& coeffs, uint32_t N, Fp twist,
                        std::vector<F>& out)
{
    using T = AirField<F>;
    out.assign(N, T::Zero());
    Fp tw = 1;
    for (size_t i = 0; i < coeffs.size(); ++i) {
        const size_t slot = i % N;
        const F term = AirMulBase(coeffs[i], tw);
        out[slot] = (i < N) ? term : T::Add(out[slot], term);
        tw = gkr_field::Mul(tw, twist);
    }
    AirNtt(out, /*inverse=*/false);
}

/** Coset shift: c_j := c_j · g^j so evaluations happen at y = g·x. */
template <typename F>
void AirCosetShiftCoeffs(std::vector<F>& coeffs)
{
    Fp gp = 1;
    for (auto& c : coeffs) {
        c = AirMulBase(c, gp);
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

template <typename B, typename F>
AirTree AirBuildTree(const std::vector<F>& evals)
{
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

// ---------------------------------------------------------------------------
// ROW tree over the first n_cols columns of an LDE column set, matching the
// row-wise backend's layout (leaf i = B::RowLeafHash of the row, node =
// B::NodeHash; field-native B::Digest nodes). n_leaves = n_lde is a power of
// two, so no odd-padding arises (same as the backend's own tree builder).
// Used only for row-wise backends: to rebuild the batch's full-row tree for
// the next-row openings and the trace-only tree behind R_T.
// ---------------------------------------------------------------------------
template <typename B, typename F>
struct AirRowTree {
    std::vector<std::vector<typename B::Digest>> levels;
};

template <typename B, typename F>
AirRowTree<B, F> AirBuildRowTree(const std::vector<std::vector<F>>& col_lde, uint32_t n_cols)
{
    AirRowTree<B, F> t;
    const size_t n_leaves = col_lde.empty() ? 0 : col_lde[0].size();
    std::vector<typename B::Digest> level(n_leaves);
    // Row-tree leaf hashing (supplemental-opening Merkle paths): one leaf per
    // LDE row hashing n_cols values. Independent leaf writes; the per-row scratch
    // is allocated once per thread. This is one of the dominant node-scale phases
    // (n_leaves = n_lde, n_cols up to ~16k). Parallel => byte-identical.
    const int64_t nlv = static_cast<int64_t>(n_leaves);
#if defined(_OPENMP)
#pragma omp parallel num_threads(BtxProveThreads())
#endif
    {
        std::vector<F> row(n_cols);
#if defined(_OPENMP)
#pragma omp for schedule(static)
#endif
        for (int64_t i = 0; i < nlv; ++i) {
            for (uint32_t c = 0; c < n_cols; ++c) row[c] = col_lde[c][i];
            level[i] = B::RowLeafHash(row, static_cast<uint32_t>(i));
        }
    }
    t.levels.push_back(level);
    while (level.size() > 1) {
        const size_t half = level.size() / 2;
        std::vector<typename B::Digest> next(half);
        const int64_t nh = static_cast<int64_t>(half);
        // Per-level Merkle compress: distinct parent writes, byte-identical.
#if defined(_OPENMP)
#pragma omp parallel for schedule(static) num_threads(BtxProveThreads())
#endif
        for (int64_t i = 0; i < nh; ++i) {
            next[i] = B::NodeHash(level[2 * i], level[2 * i + 1]);
        }
        t.levels.push_back(next);
        level = std::move(next);
    }
    return t;
}

template <typename B, typename F>
std::vector<typename B::Digest> AirRowTreePath(const AirRowTree<B, F>& tree, uint32_t index)
{
    std::vector<typename B::Digest> siblings;
    uint32_t idx = index;
    for (size_t li = 0; li + 1 < tree.levels.size(); ++li) {
        siblings.push_back(tree.levels[li][idx ^ 1u]);
        idx >>= 1;
    }
    return siblings;
}

/** Placeholder giving the per-column verifier instantiation a valid (unused)
 *  type for the row-wise R_T digest slot (see AirQuotientVerify). */
struct AirRowWiseNullState {
    using Digest = std::nullptr_t;
};

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
    // Default SHA path — used by callers that are not Backend-templated
    // (Split-RAP two-epoch helpers). Prove/Verify use DeriveChallengeForBackend.
    const uint256 d = AirChallengeDigest(fs_seed, label, roots, extra);
    return AirField<F>::FromChallenge(d.data());
}

template <typename F, typename Backend>
F DeriveChallengeForBackend(const uint256& fs_seed, const char* label,
                            const std::vector<uint256>& roots,
                            const std::vector<uint32_t>& extra)
{
    const uint256 d =
        AirChallengeDigestForBackend<Backend>(fs_seed, label, roots, extra);
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

// ===========================================================================
// PR-89: Poseidon2 route (NOT ACTIVATED — nothing below is reachable from any
// producer or verifier; see the header for why AirChallengeDigest above is
// deliberately left byte-identical).
// ===========================================================================

namespace {

/** Absorb a u32 as ONE lane.  Safe precisely because every u32 is < 2^32 < p,
 *  so FromU64's reduction is the identity here and the map is injective. */
void P2PushU32(std::vector<Fp>& lanes, uint32_t v)
{
    lanes.push_back(gkr_field::FromU64(static_cast<uint64_t>(v)));
}

/** Absorb a byte string length-prefixed, packed 4 bytes per lane, LE.  The
 *  explicit length makes the section prefix-free, so a shorter string can
 *  never be a prefix of a longer one's lane image (the zero padding of the
 *  final partial lane is not ambiguous once the length is pinned). */
void P2PushBytes(std::vector<Fp>& lanes, const unsigned char* p, size_t len)
{
    P2PushU32(lanes, static_cast<uint32_t>(len));
    for (size_t i = 0; i < len; i += 4) {
        uint32_t w = 0;
        for (size_t j = 0; j < 4 && i + j < len; ++j) {
            w |= static_cast<uint32_t>(p[i + j]) << (8 * j);
        }
        P2PushU32(lanes, w);
    }
}

/** Absorb a uint256 as EIGHT 32-bit lanes (LE).
 *
 *  NOT four u64 lanes.  gkr_field::FromU64(x) = x mod p, p = 2^64 - 2^32 + 1,
 *  so x and x + p are the same lane for every x < 2^32 - 1.  Four-u64
 *  absorption would let two DIFFERENT roots collide onto one challenge; eight
 *  32-bit lanes cannot, because each lane is < 2^32 < p. */
void P2PushU256(std::vector<Fp>& lanes, const uint256& v)
{
    const unsigned char* b = v.data();
    for (int i = 0; i < 8; ++i) {
        uint32_t w = 0;
        for (int j = 0; j < 4; ++j) {
            w |= static_cast<uint32_t>(b[4 * i + j]) << (8 * j);
        }
        P2PushU32(lanes, w);
    }
}

} // namespace

std::vector<Fp> AirChallengeP2Lanes(const uint256& fs_seed, const char* label,
                                    const std::vector<uint256>& roots,
                                    const std::vector<uint32_t>& extra)
{
    std::vector<Fp> lanes;
    // Domain tag, length-prefixed: separates this route from the SHA256d one
    // and from every other Poseidon2 sponge in the tree.
    P2PushBytes(lanes, reinterpret_cast<const unsigned char*>(kAirChallengeP2DomainTag),
                sizeof(kAirChallengeP2DomainTag) - 1);
    // Route version, so a future re-layout cannot replay against this one.
    P2PushU32(lanes, kAirChallengeP2RouteVersion);
    P2PushU256(lanes, fs_seed);
    P2PushBytes(lanes, reinterpret_cast<const unsigned char*>(label), std::strlen(label));
    P2PushU32(lanes, static_cast<uint32_t>(roots.size()));
    for (const uint256& r : roots) P2PushU256(lanes, r);
    P2PushU32(lanes, static_cast<uint32_t>(extra.size()));
    for (const uint32_t e : extra) P2PushU32(lanes, e);
    return lanes;
}

uint32_t AirChallengeP2Permutations(size_t n_lanes)
{
    // SpongeHashFp's 10*-padding ALWAYS appends a 1 lane, then zero-pads to a
    // rate multiple (a whole extra block when n_lanes is already a multiple).
    const size_t padded = ((n_lanes + 1) + alg_hash::kAlgHashRate - 1) /
                          alg_hash::kAlgHashRate * alg_hash::kAlgHashRate;
    return static_cast<uint32_t>(padded / alg_hash::kAlgHashRate);
}

uint256 AirChallengeDigestP2(const uint256& fs_seed, const char* label,
                             const std::vector<uint256>& roots,
                             const std::vector<uint32_t>& extra)
{
    const alg_hash::Digest d =
        alg_hash::SpongeHashFp(AirChallengeP2Lanes(fs_seed, label, roots, extra));
    // Pack the four canonical lanes LE.  Each is < p, so this is injective and
    // the resulting uint256 limbs are canonical by construction.
    unsigned char out[32];
    for (int i = 0; i < 4; ++i) {
        WriteLE64(out + 8 * i, static_cast<uint64_t>(d[i]));
    }
    return uint256{Span<const unsigned char>{out, 32}};
}

uint256 AirChallengeDigestSelected(bool use_p2, const uint256& fs_seed, const char* label,
                                   const std::vector<uint256>& roots,
                                   const std::vector<uint32_t>& extra)
{
    return use_p2 ? AirChallengeDigestP2(fs_seed, label, roots, extra)
                  : AirChallengeDigest(fs_seed, label, roots, extra);
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

template <typename F, typename Backend>
uint256 AirCommittedValuesRoot(const std::vector<F>& values, uint32_t n_coeffs)
{
    std::vector<F> cf = AirInterpolate(values);
    AirCosetShiftCoeffs(cf);
    return Backend::ColumnRoot(cf, n_coeffs);
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

AirFp3ExternalColumnStore::AirFp3ExternalColumnStore(
    AirExternalStoreBackend backend,
    uint32_t columns,
    uint32_t rows)
    : backend_(backend),
      columns_(columns),
      rows_(rows)
{
    if (columns_ == 0 || rows_ == 0) return;
    if (backend_ == AirExternalStoreBackend::kMemory) {
        memory_.assign(
            columns_,
            std::vector<gkr_field::Fp3>(
                rows_, gkr_field::Fp3::Zero()));
        return;
    }
    file_ = std::tmpfile();
}

AirFp3ExternalColumnStore::~AirFp3ExternalColumnStore()
{
    if (file_ != nullptr) {
        std::fclose(static_cast<std::FILE*>(file_));
    }
}

bool AirFp3ExternalColumnStore::IsOpen() const
{
    if (backend_ == AirExternalStoreBackend::kMemory) {
        return memory_.size() == columns_;
    }
    return file_ != nullptr;
}

bool AirFp3ExternalColumnStore::Write(
    uint32_t column,
    uint32_t offset,
    const std::vector<gkr_field::Fp3>& values,
    std::string* why)
{
    auto fail =
        [&](const char* reason) {
            if (why) *why = reason;
            return false;
        };
    if (!IsOpen() || column >= columns_ ||
        offset > rows_ ||
        values.size() > rows_ - offset) {
        return fail("external store write bounds");
    }
    peak_live_cells_ = std::max<uint64_t>(
        peak_live_cells_, values.size());
    if (backend_ == AirExternalStoreBackend::kMemory) {
        std::copy(
            values.begin(), values.end(),
            memory_[column].begin() + offset);
        return true;
    }
    constexpr uint64_t CELL_BYTES = 24;
    const uint64_t cell =
        uint64_t{column} * rows_ + offset;
    if (cell >
        static_cast<uint64_t>(
            std::numeric_limits<long>::max()) /
            CELL_BYTES) {
        return fail("external store file offset");
    }
    std::FILE* file = static_cast<std::FILE*>(file_);
    if (std::fseek(
            file, static_cast<long>(cell * CELL_BYTES),
            SEEK_SET) != 0) {
        return fail("external store seek write");
    }
    std::array<unsigned char, CELL_BYTES> bytes{};
    for (const auto& value : values) {
        WriteLE64(
            bytes.data(),
            gkr_field::Canonical(value.c0));
        WriteLE64(
            bytes.data() + 8,
            gkr_field::Canonical(value.c1));
        WriteLE64(
            bytes.data() + 16,
            gkr_field::Canonical(value.c2));
        if (std::fwrite(
                bytes.data(), 1, bytes.size(), file) !=
            bytes.size()) {
            return fail("external store file write");
        }
    }
    return std::fflush(file) == 0 ||
        fail("external store flush");
}

bool AirFp3ExternalColumnStore::Read(
    uint32_t column,
    uint32_t offset,
    uint32_t count,
    std::vector<gkr_field::Fp3>& out,
    std::string* why)
{
    auto fail =
        [&](const char* reason) {
            if (why) *why = reason;
            return false;
        };
    if (!IsOpen() || column >= columns_ ||
        offset > rows_ || count > rows_ - offset) {
        return fail("external store read bounds");
    }
    peak_live_cells_ = std::max<uint64_t>(
        peak_live_cells_, count);
    if (backend_ == AirExternalStoreBackend::kMemory) {
        out.assign(
            memory_[column].begin() + offset,
            memory_[column].begin() + offset + count);
        return true;
    }
    constexpr uint64_t CELL_BYTES = 24;
    const uint64_t cell =
        uint64_t{column} * rows_ + offset;
    if (cell >
        static_cast<uint64_t>(
            std::numeric_limits<long>::max()) /
            CELL_BYTES) {
        return fail("external store file offset");
    }
    std::FILE* file = static_cast<std::FILE*>(file_);
    if (std::fseek(
            file, static_cast<long>(cell * CELL_BYTES),
            SEEK_SET) != 0) {
        return fail("external store seek read");
    }
    out.assign(count, gkr_field::Fp3::Zero());
    std::array<unsigned char, CELL_BYTES> bytes{};
    for (uint32_t item = 0; item < count; ++item) {
        if (std::fread(
                bytes.data(), 1, bytes.size(), file) !=
            bytes.size()) {
            return fail("external store file read");
        }
        const uint64_t c0 = ReadLE64(bytes.data());
        const uint64_t c1 = ReadLE64(bytes.data() + 8);
        const uint64_t c2 = ReadLE64(bytes.data() + 16);
        if (c0 >= gkr_field::kP ||
            c1 >= gkr_field::kP ||
            c2 >= gkr_field::kP) {
            return fail("external store noncanonical field");
        }
        out[item] = gkr_field::Fp3{c0, c1, c2};
    }
    return true;
}

uint64_t AirFp3ExternalColumnStore::PeakLiveCells() const
{
    return peak_live_cells_;
}

uint64_t AirFp3ExternalColumnStore::ResidentCells() const
{
    if (backend_ == AirExternalStoreBackend::kMemory) {
        return uint64_t{columns_} * rows_;
    }
    return 0;
}

AirQuotientSpillAudit
AuditAirQuotientSpillFp3(
    const AirConstraintSystem<gkr_field::Fp3>& cs,
    const std::vector<std::vector<gkr_field::Fp3>>& columns,
    const uint256& fs_seed,
    uint32_t tile_rows,
    AirExternalStoreBackend backend)
{
    using F = gkr_field::Fp3;
    using T = AirField<F>;
    AirQuotientSpillAudit spill;
    spill.backend = backend;
    AirQuotientRowTileAudit& out = spill.quotient;
    out.trace_rows = cs.n_rows;
    out.trace_columns = cs.n_columns;
    out.tile_rows = tile_rows;
    const uint32_t N = cs.n_rows;
    const uint32_t W = cs.n_columns;
    if (N < 2 || (N & (N - 1)) != 0 ||
        W == 0 || columns.size() != W ||
        tile_rows == 0) {
        out.note = "row-tile audit: invalid shape";
        spill.note = out.note;
        return spill;
    }
    for (const auto& column : columns) {
        if (column.size() != N) {
            out.note = "row-tile audit: column length";
            spill.note = out.note;
            return spill;
        }
    }
    const uint64_t dmax = cs.MaxComposedDegreeBound();
    if (dmax + 1 > (1u << 24)) {
        out.note = "row-tile audit: degree";
        spill.note = out.note;
        return spill;
    }
    const uint32_t Lq = cs.QuotientLen();
    const uint32_t n_coeffs =
        FriNextPow2(std::max(N, Lq));
    const uint32_t M =
        std::max(
            N, FriNextPow2(
                   static_cast<uint32_t>(dmax + 1)));
    out.composition_rows = M;

    std::vector<std::vector<F>> coeffs(W);
    std::vector<std::vector<F>> shifted(W);
    std::vector<std::vector<F>> lde(W);
    for (uint32_t column = 0; column < W; ++column) {
        coeffs[column] =
            AirInterpolate(columns[column]);
        shifted[column] = coeffs[column];
        AirCosetShiftCoeffs(shifted[column]);
        lde[column] =
            AirEvalOnSubgroup(coeffs[column], M);
    }
    AirFp3ExternalColumnStore store(backend, W, M);
    if (!store.IsOpen()) {
        out.note = "row-tile audit: external store open";
        spill.note = out.note;
        return spill;
    }
    std::string store_why;
    spill.all_lde_columns_spilled = true;
    spill.byte_canonical_roundtrip = true;
    for (uint32_t column = 0; column < W; ++column) {
        if (!store.Write(
                column, 0, lde[column], &store_why)) {
            spill.all_lde_columns_spilled = false;
            out.note = store_why;
            spill.note = out.note;
            return spill;
        }
        std::vector<F> roundtrip;
        if (!store.Read(
                column, 0, M, roundtrip, &store_why) ||
            roundtrip.size() != lde[column].size()) {
            spill.byte_canonical_roundtrip = false;
            out.note = store_why;
            spill.note = out.note;
            return spill;
        }
        for (uint32_t row = 0;
             spill.byte_canonical_roundtrip &&
             row < M; ++row) {
            spill.byte_canonical_roundtrip =
                T::Eq(roundtrip[row], lde[column][row]);
        }
    }
    const uint256 trace_root =
        AirFriBackendAlg<F>::RowRoot(
            shifted, n_coeffs);
    const F lambda =
        DeriveChallengeForBackend<F, AirFriBackendAlg<F>>(
            fs_seed, "airq_lambda", {trace_root},
            {N, Lq, W});
    const Fp omega_M = AirOmegaForSize(M);
    const Fp omega_N = AirOmegaForSize(N);
    const F h_first = T::One();
    const F h_last =
        T::FromBase(AirPowBase(omega_N, N - 1));
    const uint32_t step = M / N;

    auto evaluate_row =
        [&](uint32_t row,
            std::vector<F>& current,
            std::vector<F>& next) {
            const uint32_t next_row =
                (row + step) % M;
            for (uint32_t column = 0;
                 column < W; ++column) {
                current[column] = lde[column][row];
                next[column] = lde[column][next_row];
            }
            Fp y_base = AirPowBase(omega_M, row);
            const F y = T::FromBase(y_base);
            F acc = T::Zero();
            F power = T::One();
            for (const auto& constraint :
                 cs.constraints) {
                const F value =
                    constraint.eval(current, next);
                if (!T::IsZero(value)) {
                    const F selector =
                        AirSelectorEval<F>(
                            constraint.kind, N, y,
                            h_first, h_last);
                    acc = T::Add(
                        acc, T::Mul(
                                 power,
                                 T::Mul(selector, value)));
                }
                power = T::Mul(power, lambda);
            }
            return acc;
        };
    bool store_ok = true;
    auto evaluate_spilled_row =
        [&](uint32_t row,
            std::vector<F>& current,
            std::vector<F>& next) {
            const uint32_t next_row =
                (row + step) % M;
            std::vector<F> cell;
            for (uint32_t column = 0;
                 column < W; ++column) {
                if (!store.Read(
                        column, row, 1, cell,
                        &store_why)) {
                    store_ok = false;
                    return T::Zero();
                }
                current[column] = cell[0];
                if (!store.Read(
                        column, next_row, 1, cell,
                        &store_why)) {
                    store_ok = false;
                    return T::Zero();
                }
                next[column] = cell[0];
            }
            const F y = T::FromBase(
                AirPowBase(omega_M, row));
            F acc = T::Zero();
            F power = T::One();
            for (const auto& constraint :
                 cs.constraints) {
                const F value =
                    constraint.eval(current, next);
                if (!T::IsZero(value)) {
                    const F selector =
                        AirSelectorEval<F>(
                            constraint.kind, N, y,
                            h_first, h_last);
                    acc = T::Add(
                        acc, T::Mul(
                                 power,
                                 T::Mul(selector, value)));
                }
                power = T::Mul(power, lambda);
            }
            return acc;
        };

    std::vector<F> dense(M, T::Zero());
    std::vector<F> tiled(M, T::Zero());
    std::vector<F> current(W), next(W);
    for (uint32_t row = 0; row < M; ++row) {
        dense[row] =
            evaluate_row(row, current, next);
    }
    for (uint32_t begin = 0; begin < M;
         begin += tile_rows) {
        const uint32_t end =
            std::min<uint32_t>(M, begin + tile_rows);
        ++out.tiles_visited;
        for (uint32_t row = begin; row < end; ++row) {
            tiled[row] =
                evaluate_spilled_row(
                    row, current, next);
        }
    }
    spill.all_tiles_reloaded = store_ok;
    out.callback_schedule_executed =
        out.tiles_visited != 0;
    out.composition_values_identical =
        dense.size() == tiled.size();
    for (uint32_t row = 0;
         out.composition_values_identical &&
         row < M; ++row) {
        out.composition_values_identical =
            T::Eq(dense[row], tiled[row]);
    }

    std::vector<F> dense_coeffs =
        AirInterpolate(std::move(dense));
    std::vector<F> tiled_coeffs =
        AirInterpolate(std::move(tiled));
    auto divide =
        [N, M](std::vector<F> values) {
            std::vector<F> quotient(
                M > N ? M - N : 1, T::Zero());
            for (uint32_t degree = M;
                 degree-- > N;) {
                if (T::IsZero(values[degree])) continue;
                quotient[degree - N] =
                    T::Add(
                        quotient[degree - N],
                        values[degree]);
                values[degree - N] =
                    T::Add(
                        values[degree - N],
                        values[degree]);
                values[degree] = T::Zero();
            }
            return quotient;
        };
    const std::vector<F> dense_quotient =
        divide(std::move(dense_coeffs));
    const std::vector<F> tiled_quotient =
        divide(std::move(tiled_coeffs));
    out.quotient_coefficients_identical =
        dense_quotient.size() ==
            tiled_quotient.size();
    for (size_t index = 0;
         out.quotient_coefficients_identical &&
         index < dense_quotient.size(); ++index) {
        out.quotient_coefficients_identical =
            T::Eq(
                dense_quotient[index],
                tiled_quotient[index]);
    }
    out.valid =
        spill.all_lde_columns_spilled &&
        spill.all_tiles_reloaded &&
        spill.byte_canonical_roundtrip &&
        out.callback_schedule_executed &&
        out.composition_values_identical &&
        out.quotient_coefficients_identical;
    out.note =
        out.valid
            ? "row-tile quotient callback is algebraically identical"
            : "row-tile quotient callback mismatch";
    spill.store_peak_live_cells =
        store.PeakLiveCells();
    spill.store_resident_cells =
        store.ResidentCells();
    spill.valid = out.valid;
    spill.note = out.note;
    return spill;
}

AirQuotientRowTileAudit
AuditAirQuotientRowTilesFp3(
    const AirConstraintSystem<gkr_field::Fp3>& cs,
    const std::vector<std::vector<gkr_field::Fp3>>& columns,
    const uint256& fs_seed,
    uint32_t tile_rows)
{
    return AuditAirQuotientSpillFp3(
               cs, columns, fs_seed, tile_rows,
               AirExternalStoreBackend::kMemory)
        .quotient;
}

// ===========================================================================
// Composition-site memory guard (see the header for why this site is separate
// from the commit-site guard).
// ===========================================================================

uint64_t AirQuotientCompositionPeakBytes(uint64_t columns, uint32_t n_rows,
                                         uint32_t composition_rows,
                                         uint64_t elem_bytes, bool coset_blocked,
                                         uint32_t threads)
{
    // Coefficient matrix: held for the whole composition because every coset
    // re-reads it (the dense route consumes it column-by-column instead, but
    // its slab is the whole M-domain matrix, so it is strictly worse).
    const uint64_t coeff_matrix = columns * n_rows * elem_bytes;
    const uint64_t slab_rows =
        coset_blocked ? static_cast<uint64_t>(n_rows)
                      : static_cast<uint64_t>(composition_rows);
    const uint64_t slab = columns * slab_rows * elem_bytes;
    const uint64_t cvals =
        static_cast<uint64_t>(composition_rows) * elem_bytes;
    // Per-thread cur/nxt row frames.
    const uint64_t frames =
        uint64_t{2} * columns * elem_bytes * (threads == 0 ? 1 : threads);
    return coeff_matrix + slab + cvals + frames;
}

bool AirQuotientCompositionFitsMemoryBudget(uint64_t columns, uint32_t n_rows,
                                            uint32_t composition_rows,
                                            uint64_t elem_bytes,
                                            bool coset_blocked, uint32_t threads,
                                            uint64_t* projected, std::string* why)
{
    static const uint64_t ceiling = [] {
        if (const char* e =
                std::getenv("BTX_AIRQ_COMPOSITION_PEAK_BYTES")) {
            const long long v = std::atoll(e);
            if (v > 0) return static_cast<uint64_t>(v);
        }
        return kRCAirQuotientCompositionPeakByteCeiling;
    }();
    const uint64_t peak = AirQuotientCompositionPeakBytes(
        columns, n_rows, composition_rows, elem_bytes, coset_blocked, threads);
    if (projected != nullptr) *projected = peak;
    if (peak <= ceiling) return true;
    if (why != nullptr) {
        // Fail CLOSED and say exactly why. A shape can sit far under
        // kRCFri3AlgBatchMaxColumns and under the commit-site ceiling and
        // still be unallocatable HERE, because this site scales with M, not
        // with n_lde.
        *why = "projected composition residency " + std::to_string(peak) +
               " B exceeds ceiling " + std::to_string(ceiling) +
               " B (columns=" + std::to_string(columns) +
               " n_rows=" + std::to_string(n_rows) +
               " composition_rows=" + std::to_string(composition_rows) +
               " coset_blocked=" + (coset_blocked ? "1" : "0") +
               " threads=" + std::to_string(threads) +
               ") — this is a MEMORY guard on the COMPOSITION matrix, a "
               "different site from Fri3AlgCommitFitsMemoryBudget and not the "
               "column cap (kRCFri3AlgBatchMaxColumns=" +
               std::to_string(kRCFri3AlgBatchMaxColumns) + ")";
    }
    return false;
}

// ===========================================================================
// Prover.
// ===========================================================================

template <typename F, typename Backend>
AirQuotientProveResult<F, Backend> AirQuotientProve(const AirConstraintSystem<F>& cs,
                                                    const std::vector<std::vector<F>>& columns,
                                                    const uint256& fs_seed,
                                                    const AirProveOptions& opt)
{
    using T = AirField<F>;
    using B = Backend;
    AirQuotientProveResult<F, Backend> res;
    BtxPhaseTimer __phase;

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

    // 1. Interpolate the trace columns over H, then commit the trace for the
    //    FS batching challenge (commit-then-challenge). Per-column backends:
    //    one root per column, byte-identical to the roots the batched FRI
    //    itself recomputes (checked below). ROW-WISE backends: ONE trace-only
    //    row root R_T over the W shifted columns — the quotient depends on λ,
    //    so it cannot ride the tree that seeds λ; R_T ships in the proof
    //    (trace_commit) and is bound to the batch by per-query cross-openings
    //    built in step 6.
    std::vector<std::vector<F>> coeffs(W);
    std::vector<std::vector<F>> shifted(W);
    std::vector<uint256> trace_roots;
    std::shared_ptr<Fri3AlgRowTreeCache>
        streamed_trace_row_cache;
    // Per-column trace NTT (interpolate + coset shift): each column is an
    // independent transform writing distinct coeffs[c]/shifted[c].
#if defined(_OPENMP)
#pragma omp parallel for schedule(static) num_threads(BtxProveThreads())
#endif
    for (uint32_t c = 0; c < W; ++c) {
        coeffs[c] = AirInterpolate(columns[c]);
        shifted[c] = coeffs[c];
        AirCosetShiftCoeffs(shifted[c]);
    }
    // PROVER FOOTPRINT DECISION (memory only; proof bytes are identical
    // either way). The dense route materializes the full (W+1) x n_lde Fp3
    // extension — ~35 GiB at the MEASURED real-role arity-4 parent shape
    // (W = 384,984, n_lde = 4096), which OOM-kills the prover. When that
    // exceeds the residency budget the backend commits in streaming
    // column-blocks instead, so peak memory stops depending on W.
    //
    // ONE decision, taken on the WIDEST column set the prove will handle
    // (trace + quotient = W+1), and reused for both the trace row root and
    // the batch commit, so the two halves can never disagree about whether a
    // dense column_lde exists.
    [[maybe_unused]] bool stream_rows = false;
    if constexpr (AirBackendStreamsRowOpenings<Backend>) {
        stream_rows = B::StreamRows(
            static_cast<uint64_t>(W) + 1,
            n_coeffs * kRCFriBlowup);
    }
    if constexpr (AirBackendIsRowWise<Backend>) {
        if (!opt.checked_trace_root_hints.empty()) {
            res.note =
                "checked trace-root hints unsupported by row-wise backend";
            return res;
        }
        if constexpr (
            AirBackendStreamsRowOpenings<Backend>) {
          if (!stream_rows) {
            trace_roots.push_back(
                B::RowRoot(shifted, n_coeffs));
          } else {
            std::string cache_why;
            const uint256 root =
                B::RowRootCached(
                    shifted, n_coeffs,
                    streamed_trace_row_cache,
                    &cache_why);
            if (root.IsNull() ||
                !streamed_trace_row_cache) {
                res.note =
                    "streamed trace row cache: " +
                    cache_why;
                return res;
            }
            trace_roots.push_back(root);
          }
        } else {
            trace_roots.push_back(
                B::RowRoot(shifted, n_coeffs));
        }
    } else {
        if (!opt.checked_trace_root_hints.empty() &&
            opt.checked_trace_root_hints.size() != W) {
            res.note = "checked trace-root hint count mismatch";
            return res;
        }
        trace_roots.resize(W);
        for (uint32_t c = 0; c < W; ++c) {
            const uint256 hinted =
                opt.checked_trace_root_hints.empty()
                ? uint256{}
                : opt.checked_trace_root_hints[c];
            trace_roots[c] = hinted.IsNull()
                ? B::ColumnRoot(shifted[c], n_coeffs)
                : hinted;
        }
    }

    __phase.mark("trace_ntt+roots");
    // 2. FS λ AFTER the trace commitment roots (commit-then-challenge).
    // Backend-gated: row-wise algebraic path may select Poseidon2 when
    // kAirChallengeP2Activated; SHA per-column backends stay on SHA256d.
    const F lambda =
        DeriveChallengeForBackend<F, Backend>(
            fs_seed, "airq_lambda", trace_roots, {N, Lq_commit, W});

    // 3. Build C(X) = Σ_i λ^i · sel_i(X) · R_i(P(X), P(ω_H X)) by evaluation
    //    on the extended subgroup of size M ≥ deg C + 1, then interpolation.
    const uint32_t M = std::max(N, FriNextPow2(static_cast<uint32_t>(dmax + 1)));
    const uint32_t stepM = M / N;
    // COMPOSITION-SITE FOOTPRINT DECISION (memory only; the two schedules
    // produce bit-identical proofs — see AirEvalOnCosetInto).
    //
    // DEFAULT: coset-blocked. The composition loop reads only rows j and
    // jn = (j + stepM) mod M, and those are always congruent mod stepM, so
    // the O(W x M) matrix is built and consumed one W x N coset slab at a
    // time — a factor of stepM = M/N less resident (8x at the MEASURED real
    // parent shape, 17.6 GiB -> 2.2 GiB for the slab).
    //
    // BTX_AIRQ_DENSE_COMPOSITION restores the old whole-matrix schedule. It
    // exists ONLY as the bit-identity control for the coset route and is not
    // a budget decision: route selection here is an explicit env switch, NOT
    // a footprint threshold, so a dense control can never silently take the
    // blocked route the way a budget-driven selector could. The route taken
    // is reported in AIRQ_SHAPE (composition=) so a comparison can be proved
    // non-vacuous instead of assumed to be.
    const bool dense_composition =
        std::getenv("BTX_AIRQ_DENSE_COMPOSITION") != nullptr;
    const uint32_t prove_threads =
        static_cast<uint32_t>(BtxProveThreads());
    const uint64_t composition_peak = AirQuotientCompositionPeakBytes(
        W, N, M, sizeof(F), !dense_composition, prove_threads);
    // Shape + projected residency, printed BEFORE the big allocations so an
    // out-of-memory prove is still diagnosable. The composition matrix below
    // is O(W x M) and is a SEPARATE materialization from the commit's column
    // LDE — streaming the commit does not shrink it. ldeM_bytes is the DENSE
    // figure (what the site would cost unblocked); composition_peak_bytes is
    // what this run will actually hold.
    if (std::getenv("BTX_AIRQ_REPORT_BYTES") != nullptr) {
        const uint64_t elem = sizeof(F);
        std::fprintf(
            stderr,
            "AIRQ_SHAPE W=%u N=%u M=%u Lq_commit=%u n_coeffs=%u n_lde=%u "
            "stream_rows=%d ldeM_bytes=%llu dense_col_lde_bytes=%llu "
            "trace_bytes=%llu composition=%s stepM=%u "
            "composition_slab_bytes=%llu composition_peak_bytes=%llu\n",
            W, N, M, Lq_commit, n_coeffs, n_coeffs * kRCFriBlowup,
            static_cast<int>(stream_rows),
            static_cast<unsigned long long>(uint64_t{W} * M * elem),
            static_cast<unsigned long long>(
                (uint64_t{W} + 1) * n_coeffs * kRCFriBlowup * elem),
            static_cast<unsigned long long>(uint64_t{W} * N * elem),
            dense_composition ? "dense" : "coset", stepM,
            static_cast<unsigned long long>(
                uint64_t{W} * (dense_composition ? M : N) * elem),
            static_cast<unsigned long long>(composition_peak));
        std::fflush(stderr);
    }
    // FAIL CLOSED BEFORE ALLOCATING. kRCFri3AlgBatchMaxColumns (2^20) does not
    // bound this site at all and neither does the commit-site ceiling: the
    // MEASURED real shape sits under both and still wants 17.6 GiB here.
    {
        std::string composition_why;
        if (!AirQuotientCompositionFitsMemoryBudget(
                W, N, M, sizeof(F), !dense_composition, prove_threads,
                nullptr, &composition_why)) {
            res.note = composition_why;
            return res;
        }
    }
    // `coeffs` is dead once the composition sum is finished (only the
    // env-gated AIRQ_DUMP still reads it); the dense route can release it
    // column-by-column as it is consumed, the coset route must hold it until
    // the last coset. Either way it is another O(W x N) matrix — 2.4 GiB at
    // real-role parent width.
    const bool keep_coeffs_for_dump =
        std::getenv("AIRQ_DUMP") != nullptr;

    const Fp omega_M = AirOmegaForSize(M);
    const Fp omega_N = AirOmegaForSize(N);
    const F h_first = T::One();
    const F h_last = T::FromBase(AirPowBase(omega_N, N - 1));

    // ONE copy of the per-row composition arithmetic, used by BOTH schedules,
    // so the coset route and its dense control cannot drift in operation
    // order. The per-row acc reduction over constraints stays in-thread, so
    // the Fp3 operation order is identical to the single-threaded loop →
    // byte-identical output.
    const auto compose_row =
        [&](const std::vector<F>& cur, const std::vector<F>& nxt,
            const F& y) -> F {
        F acc = T::Zero();
        F lp = T::One();
        for (const auto& con : cs.constraints) {
            const F v = con.eval(cur, nxt);
            if (!T::IsZero(v)) {
                const F sel =
                    AirSelectorEval<F>(con.kind, N, y, h_first, h_last);
                acc = T::Add(acc, T::Mul(lp, T::Mul(sel, v)));
            }
            lp = T::Mul(lp, lambda);
        }
        return acc;
    };

    std::vector<F> cvals(M, T::Zero());
    if (!dense_composition) {
        // DOMINANT PHASE, coset-blocked. Coset s holds the W x N slab
        //     slab[c][t] = P_c(ω_M^s · ω_N^t) = ldeM[c][s + stepM·t].
        // Row j = s + stepM·t and its successor jn = j + stepM (mod M)
        // correspond to t and (t+1) mod N inside the SAME slab, which is the
        // structural reason this site can be blocked at all. Each t writes a
        // distinct cvals[j].
        std::vector<std::vector<F>> slab(W);
        for (uint32_t s = 0; s < stepM; ++s) {
            const Fp twist = AirPowBase(omega_M, s);
            // Per-column coset NTT (size N): independent, distinct slab[c].
            // slab[c] is reused across cosets, so this reallocates only on
            // the first pass.
#if defined(_OPENMP)
#pragma omp parallel for schedule(static) num_threads(BtxProveThreads())
#endif
            for (uint32_t c = 0; c < W; ++c) {
                AirEvalOnCosetInto<F>(coeffs[c], N, twist, slab[c]);
            }
            // cur/nxt are allocated ONCE PER THREAD PER COSET (not per row).
#if defined(_OPENMP)
#pragma omp parallel num_threads(BtxProveThreads())
#endif
            {
                std::vector<F> cur(W), nxt(W);
#if defined(_OPENMP)
#pragma omp for schedule(static)
#endif
                for (uint32_t t = 0; t < N; ++t) {
                    const uint32_t tn = (t + 1u == N) ? 0u : t + 1u;
                    const uint32_t j = s + stepM * t;
                    const F y = T::FromBase(AirPowBase(omega_M, j));
                    for (uint32_t c = 0; c < W; ++c) {
                        cur[c] = slab[c][t];
                        nxt[c] = slab[c][tn];
                    }
                    cvals[j] = compose_row(cur, nxt, y);
                }
            }
        }
        // The slab is dead the moment the last coset is summed. Release it
        // here so it never coexists with the batch commit's working set.
        slab.clear();
        slab.shrink_to_fit();
        if (!keep_coeffs_for_dump) {
            for (uint32_t c = 0; c < W; ++c) {
                std::vector<F>().swap(coeffs[c]);
            }
        }
    } else {
        // DENSE CONTROL (BTX_AIRQ_DENSE_COMPOSITION): whole O(W x M) matrix.
        // Kept only so the coset route can be proved bit-identical against
        // it on real workloads. Do not use at real width — 17.6 GiB.
        std::vector<std::vector<F>> ldeM(W);
        // Per-column extended-domain NTT (size M): independent, distinct
        // ldeM[c].
#if defined(_OPENMP)
#pragma omp parallel for schedule(static) num_threads(BtxProveThreads())
#endif
        for (uint32_t c = 0; c < W; ++c) {
            ldeM[c] = AirEvalOnSubgroup(coeffs[c], M);
            if (!keep_coeffs_for_dump) {
                std::vector<F>().swap(coeffs[c]);
            }
        }
        // The running power ypow = omega_M^j is replaced by
        // AirPowBase(omega_M, j) (same field element, no cross-iteration
        // dependency) so the loop parallelizes.
#if defined(_OPENMP)
#pragma omp parallel num_threads(BtxProveThreads())
#endif
        {
            std::vector<F> cur(W), nxt(W);
#if defined(_OPENMP)
#pragma omp for schedule(static)
#endif
            for (uint32_t j = 0; j < M; ++j) {
                const F y = T::FromBase(AirPowBase(omega_M, j));
                const uint32_t jn = (j + stepM) % M;
                for (uint32_t c = 0; c < W; ++c) {
                    cur[c] = ldeM[c][j];
                    nxt[c] = ldeM[c][jn];
                }
                cvals[j] = compose_row(cur, nxt, y);
            }
        }
        ldeM.clear();
        ldeM.shrink_to_fit();
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
    if constexpr (std::is_same_v<F, gkr_field::Fp3>) {
      if (const char* dp = std::getenv("AIRQ_DUMP")) {
        std::FILE* f = std::fopen(dp, "w");
        std::fprintf(f, "%u %u %u %u %u\n", N, M, Lq_commit, W, stepM);
        std::fprintf(f, "%llu %llu %llu\n",(unsigned long long)gkr_field::Canonical(lambda.c0),(unsigned long long)gkr_field::Canonical(lambda.c1),(unsigned long long)gkr_field::Canonical(lambda.c2));
        for (uint32_t c=0;c<W;++c) for (uint32_t j=0;j<N;++j) std::fprintf(f,"%llu %llu %llu\n",(unsigned long long)gkr_field::Canonical(coeffs[c][j].c0),(unsigned long long)gkr_field::Canonical(coeffs[c][j].c1),(unsigned long long)gkr_field::Canonical(coeffs[c][j].c2));
        for (uint32_t k=0;k<Lq_commit;++k){ gkr_field::Fp3 v=(k<q_commit.size())?q_commit[k]:gkr_field::Fp3::Zero(); std::fprintf(f,"%llu %llu %llu\n",(unsigned long long)gkr_field::Canonical(v.c0),(unsigned long long)gkr_field::Canonical(v.c1),(unsigned long long)gkr_field::Canonical(v.c2)); }
        std::fclose(f);
      }
    }

    __phase.mark("composition(M rows)");
    // 5. ONE batched FRI instance over trace columns + quotient.
    std::vector<std::vector<F>> all_cols = shifted;
    all_cols.push_back(std::move(q_commit));
    const uint32_t n_lde =
        n_coeffs * kRCFriBlowup;
    const uint32_t step = n_lde / N;
    typename B::BatchCommitResult cr;
    if constexpr (
        AirBackendStreamsColumnOpenings<Backend>) {
        cr = B::BatchCommitWithStep(
            all_cols, fs_seed, step);
    } else if constexpr (
        AirBackendStreamsRowOpenings<Backend>) {
        // Same footprint decision as the trace row root above.
        cr = B::BatchCommitStreamed(
            all_cols, fs_seed, stream_rows);
    } else {
        cr = B::BatchCommit(all_cols, fs_seed);
    }
    if (!cr.ok) {
        res.note = "batch commit failed: " + cr.note;
        return res;
    }
    __phase.mark("lde+leafcommit+fri");
    if constexpr (!AirBackendIsRowWise<Backend>) {
        for (uint32_t c = 0; c < W; ++c) {
            if (cr.proof.columns[c].root != trace_roots[c]) {
                res.note = "internal: trace root mismatch vs FriBatchColumnRoot";
                return res;
            }
        }
    }

    // 6. Supplemental next-row openings at (query index + n_lde/N) mod n_lde.
    res.proof.next_openings.resize(cr.proof.queries.size());
    if constexpr (AirBackendIsRowWise<Backend>) {
        res.proof.trace_commit = trace_roots[0];
        // Dense supplemental openings: rebuild both row trees from the
        // materialized column_lde. Only reachable when the footprint decision
        // above kept the dense route (cr.column_lde is populated).
        [[maybe_unused]] const auto emit_dense_row_supplemental =
            [&]() -> bool {
            // Full-row tree (must reproduce the batch's row_commit) and the
            // trace-only tree behind R_T (must reproduce trace_roots[0]).
            const AirRowTree<B, F> full =
                AirBuildRowTree<B, F>(
                    cr.column_lde, W + 1);
            const AirRowTree<B, F> trace =
                AirBuildRowTree<B, F>(
                    cr.column_lde, W);
            if (B::PackDigest(full.levels.back()[0]) !=
                B::PackDigest(
                    cr.proof.row_commit.root)) {
                res.note =
                    "internal: rebuilt row tree root mismatch";
                return false;
            }
            if (B::PackDigest(trace.levels.back()[0]) !=
                trace_roots[0]) {
                res.note =
                    "internal: trace row root mismatch vs RowRoot";
                return false;
            }
            for (size_t qi = 0;
                 qi < cr.proof.queries.size(); ++qi) {
                const uint32_t src =
                    cr.proof.queries[qi].index;
                const uint32_t idx =
                    (src + step) % n_lde;
                auto& row =
                    res.proof.next_openings[qi];
                row.resize(2);
                // [0] next-row opening: the full W+1 row against batch root.
                row[0].index = idx;
                row[0].values.resize(W + 1);
                for (uint32_t c = 0; c <= W; ++c) {
                    row[0].values[c] =
                        cr.column_lde[c][idx];
                }
                row[0].siblings =
                    AirRowTreePath(full, idx);
                // [1] trace-binding path reuses current query values.
                row[1].index = src;
                row[1].siblings =
                    AirRowTreePath(trace, src);
            }
            return true;
        };
        if constexpr (
            AirBackendStreamsRowOpenings<Backend>) {
          if (!stream_rows) {
            if (!emit_dense_row_supplemental()) return res;
          } else {
            const auto trace_digest =
                B::UnpackDigest(trace_roots[0]);
            if (!trace_digest) {
                res.note =
                    "internal: streamed trace root not canonical";
                return res;
            }
            std::vector<uint32_t> current_indices;
            std::vector<uint32_t> next_indices;
            current_indices.reserve(
                cr.proof.queries.size());
            next_indices.reserve(
                cr.proof.queries.size());
            for (const auto& query : cr.proof.queries) {
                current_indices.push_back(query.index);
                next_indices.push_back(
                    (query.index + step) % n_lde);
            }
            std::vector<typename B::MerklePath>
                streamed_next;
            std::vector<typename B::MerklePath>
                streamed_trace;
            std::string stream_why;
            if (!B::OpenRowsCached(
                    all_cols, n_coeffs, next_indices,
                    cr.proof.row_commit.root,
                    cr.row_tree_cache,
                    streamed_next, &stream_why) ||
                !B::OpenRowsCached(
                    shifted, n_coeffs, current_indices,
                    *trace_digest,
                    streamed_trace_row_cache,
                    streamed_trace, &stream_why) ||
                streamed_next.size() !=
                    cr.proof.queries.size() ||
                streamed_trace.size() !=
                    cr.proof.queries.size()) {
                res.note =
                    "streamed supplemental row openings: " +
                    stream_why;
                return res;
            }
            for (size_t qi = 0;
                 qi < cr.proof.queries.size(); ++qi) {
                auto& row = res.proof.next_openings[qi];
                row.resize(2);
                row[0] = std::move(streamed_next[qi]);
                row[1] = std::move(streamed_trace[qi]);
                // The verifier reuses batch-query values when checking R_T.
                row[1].values.clear();
            }
          }
        } else {
            if (!emit_dense_row_supplemental()) return res;
        }
    } else {
        if constexpr (AirBackendStreamsColumnOpenings<Backend>) {
            if (cr.supplemental_openings.size() !=
                cr.proof.queries.size()) {
                res.note =
                    "streamed supplemental column opening count";
                return res;
            }
            for (size_t qi = 0;
                 qi < cr.proof.queries.size(); ++qi) {
                auto& streamed =
                    cr.supplemental_openings[qi];
                if (streamed.size() != W + 1) {
                    res.note =
                        "streamed supplemental column opening width";
                    return res;
                }
                // The quotient column is not part of the next-row trace.
                streamed.resize(W);
                res.proof.next_openings[qi] =
                    std::move(streamed);
            }
        } else {
            std::vector<AirTree> trees(W);
            for (uint32_t c = 0; c < W; ++c) {
                trees[c] = AirBuildTree<B, F>(cr.column_lde[c]);
                if (trees[c].root != cr.proof.columns[c].root) {
                    res.note = "internal: rebuilt tree root mismatch";
                    return res;
                }
            }
            for (size_t qi = 0; qi < cr.proof.queries.size(); ++qi) {
                const uint32_t idx =
                    (cr.proof.queries[qi].index + step) % n_lde;
                auto& row = res.proof.next_openings[qi];
                row.resize(W);
                for (uint32_t c = 0; c < W; ++c) {
                    row[c].index = idx;
                    row[c].leaf = cr.column_lde[c][idx];
                    row[c].siblings = AirTreePath(trees[c], idx);
                }
            }
        }
    }
    // MEASURED artifact size (env-gated diagnostic; no effect on the proof).
    // The batch half is a real serialization (cr.proof_bytes is the byte count
    // SerializeFri3AlgBatchProof actually produced); the supplemental half is
    // counted from the real containers with the codec's element widths
    // (Fp3 = 3x8 B, digest = 4x8 B), mirroring EstimateAlgAirProofBytes.
    // This exists because no real-child-width parent proof had ever been
    // serialized — every figure at that width was estimator output.
    if constexpr (AirBackendIsRowWise<Backend> &&
                  std::is_same_v<F, gkr_field::Fp3> &&
                  std::is_same_v<typename B::BatchProof,
                                 Fri3AlgBatchProof>) {
        if (std::getenv("BTX_AIRQ_REPORT_BYTES") != nullptr) {
            uint64_t values = 0;
            uint64_t siblings = 0;
            uint64_t frame = 0;
            for (const auto& paths : res.proof.next_openings) {
                frame += 4;
                for (const auto& path : paths) {
                    frame += 8;
                    values += path.values.size();
                    siblings += path.siblings.size();
                }
            }
            const uint64_t supplemental =
                frame + values * 3 * sizeof(uint64_t) +
                siblings * 4 * sizeof(uint64_t);
            const uint64_t total =
                static_cast<uint64_t>(cr.proof_bytes) + 32 + 4 +
                supplemental;
            std::fprintf(
                stderr,
                "AIRQ_PROOF_BYTES W=%u n_coeffs=%u n_lde=%u queries=%zu "
                "streamed=%d batch_bytes=%llu trace_commit_bytes=32 "
                "next_openings_bytes=%llu next_openings_values=%llu "
                "next_openings_siblings=%llu total_bytes=%llu\n",
                W, n_coeffs, n_lde, cr.proof.queries.size(),
                static_cast<int>(stream_rows),
                static_cast<unsigned long long>(cr.proof_bytes),
                static_cast<unsigned long long>(supplemental),
                static_cast<unsigned long long>(values),
                static_cast<unsigned long long>(siblings),
                static_cast<unsigned long long>(total));
            std::fflush(stderr);
        }
        // BIT-IDENTICAL GATE: fingerprint the WHOLE emitted artifact (batch
        // proof bytes + trace commitment + every supplemental opening) so a
        // dense run and a streamed run of the same real workload can be
        // compared prove-for-prove, not just at the final assertion. Env-gated;
        // it re-serializes the batch, so never enable it at real-child width.
        if (std::getenv("BTX_AIRQ_PROOF_SHA") != nullptr) {
            std::vector<unsigned char> ser;
            const size_t serialized_size =
                SerializeFri3AlgBatchProof(cr.proof, ser);
            if (serialized_size == 0 ||
                serialized_size != ser.size()) {
                res.note =
                    "failed to serialize batch proof for fingerprint";
                return res;
            }
            CSHA256 h;
            h.Write(ser.data(), ser.size());
            h.Write(res.proof.trace_commit.data(), 32);
            const auto absorb_u64 = [&h](uint64_t v) {
                unsigned char b[8];
                for (int i = 0; i < 8; ++i) {
                    b[i] = static_cast<unsigned char>(
                        (v >> (8 * i)) & 0xFF);
                }
                h.Write(b, 8);
            };
            for (const auto& paths : res.proof.next_openings) {
                for (const auto& path : paths) {
                    absorb_u64(path.index);
                    absorb_u64(path.values.size());
                    for (const auto& v : path.values) {
                        absorb_u64(gkr_field::Canonical(v.c0));
                        absorb_u64(gkr_field::Canonical(v.c1));
                        absorb_u64(gkr_field::Canonical(v.c2));
                    }
                    absorb_u64(path.siblings.size());
                    for (const auto& s : path.siblings) {
                        for (uint32_t k = 0; k < 4; ++k) {
                            absorb_u64(
                                gkr_field::Canonical(s[k]));
                        }
                    }
                }
            }
            uint8_t digest[CSHA256::OUTPUT_SIZE];
            h.Finalize(digest);
            std::string hex;
            hex.reserve(64);
            static const char* kHex = "0123456789abcdef";
            for (unsigned char b : digest) {
                hex.push_back(kHex[b >> 4]);
                hex.push_back(kHex[b & 0xF]);
            }
            std::fprintf(stderr,
                         "AIRQ_PROOF_SHA W=%u n_coeffs=%u batch_bytes=%zu "
                         "sha256=%s\n",
                         W, n_coeffs, ser.size(), hex.c_str());
            std::fflush(stderr);
        }
    }
    res.proof.batch = std::move(cr.proof);
    res.ok = true;
    res.note = res.division_exact ? "exact division; committed"
                                  : "FORCED commit with nonzero remainder";
    __phase.mark("supplemental_openings");
    __phase.total("AirQuotientProve");

    // Optional proof-byte dump for the multi-thread determinism harness: writes
    // the canonically serialized batch proof to $BTX_PROOF_OUT and prints its
    // SHA256 + length. Alg (Fp3 recursion) backend only; gated by env, so it
    // never runs on the consensus path.
    if constexpr (std::is_same_v<F, gkr_field::Fp3> &&
                  std::is_same_v<Backend,
                                 AirFriBackendAlg<gkr_field::Fp3>>) {
        if (const char* po = std::getenv("BTX_PROOF_OUT")) {
            std::vector<unsigned char> ser;
            const size_t serialized_size =
                SerializeFri3AlgBatchProof(res.proof.batch, ser);
            if (serialized_size == 0 ||
                serialized_size != ser.size()) {
                res.ok = false;
                res.note =
                    "failed to serialize batch proof for output";
                return res;
            }
            if (std::FILE* f = std::fopen(po, "wb")) {
                std::fwrite(ser.data(), 1, ser.size(), f);
                std::fclose(f);
            }
            unsigned char h[32];
            CSHA256().Write(ser.data(), ser.size()).Finalize(h);
            std::fprintf(stderr,
                         "[BTX_PROOF] threads=%d bytes=%zu sha256=",
                         BtxProveThreads(), ser.size());
            for (unsigned char b : h) std::fprintf(stderr, "%02x", b);
            std::fprintf(stderr, "\n");
            std::fflush(stderr);
        }
    }
    return res;
}

// ===========================================================================
// Verifier.
// ===========================================================================

template <typename F, typename Backend>
bool AirQuotientVerify(const AirConstraintSystem<F>& cs,
                       const AirQuotientProof<F, Backend>& proof, const uint256& fs_seed,
                       std::string* why, uint32_t verify_threads)
{
    using T = AirField<F>;
    using B = Backend;
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
    // rejected HERE before any crypto work. (Row-wise backends carry no
    // per-column commitments — only column_len — so only that is checked.)
    if constexpr (AirBackendIsRowWise<Backend>) {
        if (batch.column_len.size() != W + 1) return fail("column count mismatch");
    } else {
        if (batch.columns.size() != W + 1 || batch.column_len.size() != W + 1) {
            return fail("column count mismatch");
        }
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
    } else if constexpr (AirBackendIsRowWise<Backend>) {
        // No per-column roots exist to regenerate in the row-wise layout;
        // value-pinned preprocessed columns must use the OOD-pin mode.
        if (!cs.preprocessed.empty()) {
            return fail("preprocessed root regen unsupported on row-wise backend "
                        "(set preprocessed_pin_ood)");
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
    // Per-column layouts only — a row-wise batch has no per-column roots.
    if constexpr (AirBackendIsRowWise<Backend>) {
        if (!cs.preprocessed_roots.empty()) {
            return fail("preprocessed root equality unsupported on row-wise backend");
        }
    } else {
        for (const auto& [idx, root] : cs.preprocessed_roots) {
            if (idx >= W) return fail("preprocessed root index");
            if (batch.columns[idx].root != root) return fail("preprocessed root mismatch");
        }
    }
    if (!cs.preprocessed_row_group_roots.empty()) {
        return fail(
            "preprocessed row-group roots require Split-RAP");
    }

    // FS λ re-derivation from the committed trace roots: the batch's own
    // per-column roots (per-column layout) or the trace-only row root R_T
    // shipped in the proof (row-wise layout — bound to the batch by the
    // per-query cross-openings verified in the query loop below).
    std::vector<uint256> trace_roots;
    [[maybe_unused]] typename std::conditional_t<AirBackendIsRowWise<Backend>, Backend,
                                                 AirRowWiseNullState>::Digest rt_digest{};
    if constexpr (AirBackendIsRowWise<Backend>) {
        const auto rt = B::UnpackDigest(proof.trace_commit);
        if (!rt) return fail("trace commitment not canonical");
        rt_digest = *rt;
        trace_roots.push_back(proof.trace_commit);
    } else {
        trace_roots.resize(W);
        for (uint32_t c = 0; c < W; ++c) trace_roots[c] = batch.columns[c].root;
    }
    const F lambda = DeriveChallengeForBackend<F, Backend>(
        fs_seed, "airq_lambda", trace_roots, {N, Lq, W});

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

    // One query's worth of the loop body below, factored out so the
    // sequential and (row-wise-only) threaded paths run IDENTICAL logic.
    // nullptr = accepted; otherwise a literal from the same fail() vocabulary
    // as the rest of this function. `cur`/`nxt` are function-local (not
    // shared scratch), which is what makes concurrent calls with distinct
    // `qi` data-race-free: every element of both is written before it is
    // read, on every call, for every backend branch below.
    auto verify_one_query = [&](size_t qi) -> const char* {
        std::vector<F> cur(W), nxt(W);
        const auto& q = batch.queries[qi];
        const auto& no = proof.next_openings[qi];
        const uint32_t nidx = (q.index + step) % n_lde;
        F qv = T::Zero();
        if constexpr (AirBackendIsRowWise<Backend>) {
            if (q.row.values.size() != W + 1) return "query row width";
            if (no.size() != 2) return "next-opening width";
            // [0] next-row opening: the FULL row (leaf recomputation needs
            // every column value) against the batch's single row_commit.
            if (no[0].index != nidx) return "next-opening index";
            if (no[0].values.size() != W + 1) return "next-opening row width";
            if (!B::VerifyRowPath(B::RowLeafHash(no[0].values, nidx), nidx, no[0].siblings,
                                  batch.row_commit.root, n_lde)) {
                return "next-opening merkle";
            }
            // [1] trace-binding opening: the λ-seeding trace commitment R_T
            // must agree with the batch's own (already Merkle-verified) trace
            // row values at this FS query index — same α = 17/32 per-query
            // soundness as the FRI itself.
            if (no[1].index != q.index) return "trace-binding index";
            if (!no[1].values.empty()) return "trace-binding values not empty";
            const std::vector<F> trow(q.row.values.begin(), q.row.values.begin() + W);
            if (!B::VerifyRowPath(B::RowLeafHash(trow, q.index), q.index, no[1].siblings,
                                  rt_digest, n_lde)) {
                return "trace-binding merkle";
            }
            for (uint32_t c = 0; c < W; ++c) {
                cur[c] = q.row.values[c];
                nxt[c] = no[0].values[c];
            }
            qv = q.row.values[W];
        } else {
            if (q.columns.size() != W + 1) return "query column count";
            if (no.size() != W) return "next-opening width";
            for (uint32_t c = 0; c < W; ++c) {
                if (no[c].index != nidx) return "next-opening index";
                if (!B::VerifyPath(no[c], batch.columns[c].root, n_lde)) {
                    return "next-opening merkle";
                }
                cur[c] = q.columns[c].value;
                nxt[c] = no[c].leaf;
            }
            qv = q.columns[W].value;
        }
        // Actual evaluation point y = g·ω^index (coset — Z_H(y) ≠ 0).
        const F y = T::Mul(g, T::FromBase(AirPowBase(omega_lde, q.index)));
        const F zh = T::Sub(AirPow(y, N), T::One());
        if (T::IsZero(zh)) return "Z_H vanishes at query point (coset violated)";
        // All constraints at this query share the same selector point.  The
        // old loop called AirSelectorEval once per constraint, which repeated
        // y^N and an Fp3 inversion for every first/last-row constraint.  Pin
        // the four selector values once instead.  The coset check above makes
        // both denominators non-zero, so this is algebraically identical to
        // AirSelectorEval's non-domain branch.
        const std::array<F, 4> selectors{
            T::One(),
            T::Sub(y, h_last),
            T::Mul(
                zh,
                T::Inv(T::Sub(y, h_first))),
            T::Mul(
                zh,
                T::Inv(T::Sub(y, h_last)))};

        F csum = T::Zero();
        F lp = T::One();
        for (const auto& con : cs.constraints) {
            const F v = con.eval(cur, nxt);
            if (!T::IsZero(v)) {
                const F& sel = selectors[
                    static_cast<uint8_t>(
                        con.kind)];
                csum = T::Add(csum, T::Mul(lp, T::Mul(sel, v)));
            }
            lp = T::Mul(lp, lambda);
        }
        if (!T::Eq(csum, T::Mul(qv, zh))) return "quotient identity C(y) != Q(y)*Z_H(y)";
        return nullptr;
    };

    const size_t n_queries = batch.queries.size();
    bool used_parallel = false;
#if defined(_OPENMP)
    if constexpr (AirBackendIsRowWise<Backend>) {
        if (verify_threads > 1 && n_queries > 1) {
            used_parallel = true;
            const char* first_error = nullptr;
            const int threads = static_cast<int>(
                std::min<size_t>(verify_threads, n_queries));
            #pragma omp parallel for num_threads(threads) schedule(static)
            for (long qi = 0; qi < static_cast<long>(n_queries); ++qi) {
                const char* e = verify_one_query(static_cast<size_t>(qi));
                if (e != nullptr) {
                    #pragma omp critical(air_quotient_verify_first_error)
                    {
                        if (first_error == nullptr) first_error = e;
                    }
                }
            }
            if (first_error != nullptr) return fail(first_error);
        }
    }
#endif
#if !defined(_OPENMP)
    if constexpr (AirBackendIsRowWise<Backend>) {
        if (verify_threads > 1 && n_queries > 1) {
            used_parallel = true;
            using QueryChunkResult =
                std::pair<size_t, const char*>;
            const uint32_t workers =
                std::min<uint32_t>(
                    {verify_threads,
                     static_cast<uint32_t>(
                         n_queries),
                     UINT32_C(16)});
            const size_t chunk =
                (n_queries + workers - 1) /
                workers;
            std::vector<
                std::future<QueryChunkResult>>
                jobs;
            jobs.reserve(workers);
            for (uint32_t worker = 0;
                 worker < workers; ++worker) {
                const size_t begin =
                    worker * chunk;
                const size_t end =
                    std::min(
                        n_queries,
                        begin + chunk);
                if (begin >= end) break;
                jobs.push_back(
                    std::async(
                        std::launch::async,
                        [&, begin, end]() {
                            for (size_t qi = begin;
                                 qi < end; ++qi) {
                                if (const char* error =
                                        verify_one_query(
                                            qi)) {
                                    return QueryChunkResult{
                                        qi, error};
                                }
                            }
                            return QueryChunkResult{
                                std::numeric_limits<
                                    size_t>::max(),
                                nullptr};
                        }));
            }
            QueryChunkResult first_error{
                std::numeric_limits<
                    size_t>::max(),
                nullptr};
            for (auto& job : jobs) {
                const QueryChunkResult result =
                    job.get();
                if (result.first <
                    first_error.first) {
                    first_error = result;
                }
            }
            if (first_error.second != nullptr) {
                return fail(first_error.second);
            }
        }
    }
#endif
    if (!used_parallel) {
        for (size_t qi = 0; qi < n_queries; ++qi) {
            if (const char* e = verify_one_query(qi)) return fail(e);
        }
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
    // f = tbl_a + γ·tbl_b + γ²·tbl_c : binds the COMMITTED fingerprint column
    // kColTfp to the CHALLENGE-INDEPENDENT preprocessed table columns. γ is a
    // verifier challenge coefficient (as in logup.phi/psi), NOT baked into a
    // preprocessed column — this is what makes the fingerprint challenge-
    // independent bytecode and catches a grinding/clone tamper by ALGEBRA
    // (the quotient stops dividing) rather than only by preprocessed-root
    // regeneration. Linear in the columns (γ, γ² are fixed post-FS constants).
    add("logup.tfp.bind", AirKind::kEverywhere, 1,
        [gamma, g2](const std::vector<F>& r, const std::vector<F>&) {
            return T::Sub(r[kColTfp],
                          T::Add(r[kColTblA],
                                 T::Add(T::Mul(gamma, r[kColTblB]),
                                        T::Mul(g2, r[kColTblC]))));
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

    // -- Preprocessed canonical T_M table columns (verifier-regenerated,
    //    CHALLENGE-INDEPENDENT): tbl_a = n, tbl_b = acc[n], tbl_c = mu[n]. The
    //    γ-fingerprint is NOT preprocessed anymore; it is the committed column
    //    kColTfp, forced to tbl_a + γ·tbl_b + γ²·tbl_c by logup.tfp.bind above.
    std::vector<F> tbl_a(n_rows, T::Zero());
    std::vector<F> tbl_b(n_rows, T::Zero());
    std::vector<F> tbl_c(n_rows, T::Zero());
    for (uint32_t j = 0; j < n_rows; ++j) {
        const uint32_t n = (j < 16) ? j : 0;  // padding rows duplicate row 0 (m = 0 there)
        tbl_a[j] = T::FromU64(n);
        tbl_b[j] = T::FromU64(tm.acc[n]);
        tbl_c[j] = T::FromSigned(tm.mu[n]);
    }
    cs.preprocessed.emplace_back(static_cast<uint32_t>(kColTblA), std::move(tbl_a));
    cs.preprocessed.emplace_back(static_cast<uint32_t>(kColTblB), std::move(tbl_b));
    cs.preprocessed.emplace_back(static_cast<uint32_t>(kColTblC), std::move(tbl_c));
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
    // Fill the challenge-independent preprocessed table columns and the
    // committed fingerprint f = kColTfp bound to them by logup.tfp.bind. tvals
    // (= the canonical table fingerprints) still drives ψ/m below, bit-for-bit
    // identical to the prior preprocessed t_fp values.
    std::vector<F> tvals(N, T::Zero());
    for (uint32_t r = 0; r < N; ++r) {
        const uint32_t n = (r < 16) ? r : 0;  // padding rows duplicate row 0
        cols[kColTblA][r] = T::FromU64(n);
        cols[kColTblB][r] = T::FromU64(tm.acc[n]);
        cols[kColTblC][r] = T::FromSigned(tm.mu[n]);
        tvals[r] = T::Add(cols[kColTblA][r],
                          T::Add(T::Mul(out.gamma, cols[kColTblB][r]),
                                 T::Mul(g2, cols[kColTblC][r])));
        cols[kColTfp][r] = tvals[r];
    }

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
// Explicit instantiations (Fp2 today, Fp3 ready; Fp3 additionally over the
// row-wise algebraic-hash backend for the recursion path — the RcSampler
// concrete instantiation stays on the default backend, see the header).
// ===========================================================================

using gkr_field::Fp2;
using gkr_field::Fp3;
using StreamingColumnsB3 =
    AirFriBackendFp3StreamingColumns;
using AlgB3 = AirFriBackendAlg<Fp3>;
using AlgDualB3 = AirFriBackendAlgDual<Fp3>;
using AlgDualStreamingAuditB3 =
    AirFriBackendAlgDualStreamingAudit;

AirQuotientRowsProveResult AirQuotientProveRows(
    const AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns,
    const uint256& fs_seed,
    const AirProveOptions& opt)
{
    return AirQuotientProve<
        Fp3, AirFriBackendAlgStreamingRows>(
        cs, columns, fs_seed, opt);
}

bool AirQuotientVerifyRows(
    const AirConstraintSystem<Fp3>& cs,
    const AirQuotientRowsProof& proof,
    const uint256& fs_seed,
    std::string* why)
{
    return AirQuotientVerify<
        Fp3, AirFriBackendAlgStreamingRows>(
        cs, proof, fs_seed, why);
}

namespace {

bool BuildTwoEpochBaseColumns(
    const AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns,
    const std::vector<uint32_t>& indices,
    std::vector<std::vector<Fp3>>& shifted,
    uint32_t& n_coeffs,
    std::string* why)
{
    const auto fail = [&](const char* detail) {
        shifted.clear();
        n_coeffs = 0;
        if (why != nullptr) {
            *why =
                std::string{"two_epoch_base:"} + detail;
        }
        return false;
    };
    if (cs.n_rows < 2 ||
        (cs.n_rows & (cs.n_rows - 1)) != 0 ||
        cs.n_columns == 0 ||
        columns.size() != cs.n_columns ||
        indices.empty()) {
        return fail("shape");
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) {
            return fail("trace_column_length");
        }
    }
    uint32_t previous = 0;
    for (size_t position = 0;
         position < indices.size(); ++position) {
        const uint32_t column = indices[position];
        if (column >= cs.n_columns ||
            (position != 0 && column <= previous)) {
            return fail("base_column_indices");
        }
        previous = column;
    }
    const uint64_t dmax = cs.MaxComposedDegreeBound();
    if (dmax + 1 > (uint64_t{1} << 24)) {
        return fail("composed_degree");
    }
    n_coeffs = FriNextPow2(
        std::max(cs.n_rows, cs.QuotientLen()));
    shifted.clear();
    shifted.reserve(indices.size());
    for (uint32_t column : indices) {
        std::vector<Fp3> coefficients =
            AirInterpolate(columns[column]);
        AirCosetShiftCoeffs(coefficients);
        shifted.push_back(std::move(coefficients));
    }
    return true;
}

uint256 TwoEpochFinalSeed(
    const uint256& public_fs_seed,
    const uint256& base_root,
    uint32_t trace_rows,
    uint32_t n_coeffs,
    const std::vector<uint32_t>& indices)
{
    if (public_fs_seed.IsNull() || base_root.IsNull()) {
        return {};
    }
    std::vector<uint32_t> extra;
    extra.reserve(3 + indices.size());
    extra.push_back(trace_rows);
    extra.push_back(n_coeffs);
    extra.push_back(
        static_cast<uint32_t>(indices.size()));
    extra.insert(extra.end(), indices.begin(), indices.end());
    return AirChallengeDigest(
        public_fs_seed,
        "airq_two_epoch_r1",
        {base_root}, extra);
}

bool BuildSplitRapTraceGroups(
    const AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns,
    const std::vector<uint32_t>& base_indices,
    std::vector<std::vector<Fp3>>& r0,
    std::vector<std::vector<Fp3>>& rdep,
    std::vector<uint32_t>& dependent_indices,
    uint32_t& n_coeffs,
    std::string* why)
{
    if (!BuildTwoEpochBaseColumns(
            cs, columns, base_indices,
            r0, n_coeffs, why)) {
        return false;
    }
    std::vector<uint8_t> is_base(
        cs.n_columns, 0);
    for (uint32_t column : base_indices) {
        is_base[column] = 1;
    }
    dependent_indices.clear();
    rdep.clear();
    dependent_indices.reserve(
        cs.n_columns - base_indices.size());
    rdep.reserve(
        cs.n_columns - base_indices.size());
    for (uint32_t column = 0;
         column < cs.n_columns; ++column) {
        if (is_base[column]) continue;
        dependent_indices.push_back(column);
        std::vector<Fp3> coefficients =
            AirInterpolate(columns[column]);
        AirCosetShiftCoeffs(coefficients);
        rdep.push_back(std::move(coefficients));
    }
    if (rdep.empty()) {
        if (why != nullptr) {
            *why = "split_rap:no_dependent_columns";
        }
        return false;
    }
    return true;
}

bool DeriveSplitRapUniformFp3(
    const uint256& public_fs_seed,
    const char* label,
    const std::vector<uint256>& ordered_roots,
    const std::vector<uint32_t>& extra,
    Fp3& out)
{
    if (public_fs_seed.IsNull()) return false;
    std::array<uint64_t,
               kRCFri3AlgDualUniformWords> words{};
    for (uint32_t block = 0;
         block < kRCFri3AlgDualUniformHashBlocks;
         ++block) {
        std::vector<uint32_t> block_extra = extra;
        block_extra.push_back(block);
        const uint256 digest =
            AirChallengeDigest(
                public_fs_seed, label,
                ordered_roots, block_extra);
        for (uint32_t word = 0; word < 4;
             ++word) {
            words[4 * block + word] =
                ReadLE64(
                    digest.data() + 8 * word);
        }
    }
    const auto selected =
        Fri3AlgSelectUniformFp3Words(words);
    if (!selected.has_value()) return false;
    out = *selected;
    return true;
}

bool DeriveSplitRapSafeDigestV2(
    const uint256& public_fs_seed,
    const char* label,
    const std::vector<uint256>& ordered_roots,
    const std::vector<uint32_t>& extra,
    alg_hash_typed::RoleV12 role,
    alg_hash::Digest& out)
{
    namespace safe =
        safe_v12;
    if (public_fs_seed.IsNull() ||
        label == nullptr ||
        !alg_hash_typed::IsKnownRoleV12(role)) {
        return false;
    }
    static constexpr char kDomain[] =
        "BTX_RC_AIRQ_SPLIT_RAP_SAFE_V2";
    const std::vector<uint8_t> application_domain(
        reinterpret_cast<const uint8_t*>(kDomain),
        reinterpret_cast<const uint8_t*>(kDomain) +
            sizeof(kDomain) - 1);
    // AirChallengeP2Lanes is used only as an injective field-lane encoder
    // here. SAFECore supplies the typed capacity, IO-pattern tag and security
    // reduction; no untyped P2 digest is evaluated or consumed.
    const std::vector<Fp> message =
        AirChallengeP2Lanes(
            public_fs_seed, label,
            ordered_roots, extra);
    return safe::SafeCoreDigestV12(
        role, application_domain,
        message, out, nullptr, nullptr);
}

bool DeriveSplitRapSafeFp3V2(
    const uint256& public_fs_seed,
    const char* label,
    const std::vector<uint256>& ordered_roots,
    const std::vector<uint32_t>& extra,
    Fp3& out)
{
    alg_hash::Digest digest{};
    if (!DeriveSplitRapSafeDigestV2(
            public_fs_seed, label,
            ordered_roots, extra,
            alg_hash_typed::RoleV12::
                TranscriptAirLambda,
            digest)) {
        return false;
    }
    out = Fp3{
        gkr_field::Canonical(digest[0]),
        gkr_field::Canonical(digest[1]),
        gkr_field::Canonical(digest[2])};
    return true;
}

uint256 SplitRapSafeDigestToUint256(
    const alg_hash::Digest& digest)
{
    unsigned char encoded[32];
    for (uint32_t lane = 0; lane < 4;
         ++lane) {
        WriteLE64(
            encoded + 8 * lane,
            static_cast<uint64_t>(
                gkr_field::Canonical(
                    digest[lane])));
    }
    return uint256{
        Span<const unsigned char>{
            encoded, sizeof(encoded)}};
}

uint256 SplitRapFinalFriSeedSafeV2(
    const uint256& public_fs_seed,
    const std::vector<uint256>& ordered_roots,
    uint32_t trace_rows,
    uint32_t trace_columns,
    uint32_t quotient_len,
    uint32_t n_coeffs,
    const std::vector<uint32_t>& base_indices)
{
    std::vector<uint32_t> extra;
    extra.reserve(5 + base_indices.size());
    extra.push_back(trace_rows);
    extra.push_back(trace_columns);
    extra.push_back(quotient_len);
    extra.push_back(n_coeffs);
    extra.push_back(
        static_cast<uint32_t>(
            base_indices.size()));
    extra.insert(
        extra.end(),
        base_indices.begin(),
        base_indices.end());
    alg_hash::Digest digest{};
    if (!DeriveSplitRapSafeDigestV2(
            public_fs_seed,
            "airq_split_rap_fri_seed_safe_v2",
            ordered_roots, extra,
            alg_hash_typed::RoleV12::
                TranscriptFriSeed,
            digest)) {
        return {};
    }
    return SplitRapSafeDigestToUint256(
        digest);
}

uint256 SplitRapFinalFriSeed(
    const uint256& public_fs_seed,
    const std::vector<uint256>& ordered_roots,
    uint32_t trace_rows,
    uint32_t trace_columns,
    uint32_t quotient_len,
    uint32_t n_coeffs,
    const std::vector<uint32_t>& base_indices)
{
    std::vector<uint32_t> extra;
    extra.reserve(5 + base_indices.size());
    extra.push_back(trace_rows);
    extra.push_back(trace_columns);
    extra.push_back(quotient_len);
    extra.push_back(n_coeffs);
    extra.push_back(
        static_cast<uint32_t>(
            base_indices.size()));
    extra.insert(
        extra.end(),
        base_indices.begin(),
        base_indices.end());
    return AirChallengeDigest(
        public_fs_seed,
        "airq_split_rap_fri_seed_v1",
        ordered_roots, extra);
}

} // namespace

uint256 AirQuotientTwoEpochBaseRowCommitment(
    const AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns,
    const std::vector<uint32_t>& base_column_indices,
    std::string* why)
{
    const auto session =
        AirQuotientBuildTwoEpochBaseRowSession(
            cs, columns, base_column_indices);
    if (!session.valid && why != nullptr) {
        *why = session.note;
    }
    return session.valid
        ? session.base_row_commitment
        : uint256{};
}

AirQuotientTwoEpochBaseRowSession
AirQuotientBuildTwoEpochBaseRowSession(
    const AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns,
    const std::vector<uint32_t>& base_column_indices)
{
    AirQuotientTwoEpochBaseRowSession out;
    std::vector<std::vector<Fp3>> shifted;
    std::string why;
    if (!BuildTwoEpochBaseColumns(
            cs, columns, base_column_indices,
            shifted, out.n_coeffs, &why)) {
        out.note = why;
        return out;
    }
    auto cache =
        std::make_shared<Fri3AlgRowTreeCache>();
    if (!Fri3AlgBuildRowTreeCacheStreaming(
            shifted, out.n_coeffs,
            *cache, &why) ||
        !cache->valid) {
        out.note =
            "two_epoch_base_session:" + why;
        return out;
    }
    out.trace_rows = cs.n_rows;
    out.base_column_indices =
        base_column_indices;
    out.base_row_commitment =
        Fri3AlgDigestToUint256(cache->root);
    out.row_tree_cache = std::move(cache);
    out.valid =
        !out.base_row_commitment.IsNull();
    out.note = out.valid
        ? "two_epoch_base_session:retained"
        : "two_epoch_base_session:null_root";
    return out;
}

AirQuotientTwoEpochRowsProveResult
AirQuotientProveRowsTwoEpoch(
    const AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns,
    const std::vector<uint32_t>& base_column_indices,
    const uint256& public_fs_seed,
    const AirProveOptions& opt,
    const AirQuotientTwoEpochBaseRowSession*
        retained_r0)
{
    AirQuotientTwoEpochRowsProveResult out;
    auto fail = [&](const std::string& detail) {
        out.receipt = {};
        out.note = "two_epoch_prove:" + detail;
        return out;
    };
    if (public_fs_seed.IsNull()) {
        return fail("public_seed");
    }
    std::vector<std::vector<Fp3>> shifted;
    uint32_t n_coeffs = 0;
    std::string why;
    if (!BuildTwoEpochBaseColumns(
            cs, columns, base_column_indices,
            shifted, n_coeffs, &why)) {
        return fail(why);
    }
    std::shared_ptr<Fri3AlgRowTreeCache> cache;
    uint256 base_root;
    if (retained_r0 != nullptr) {
        if (!retained_r0->valid ||
            retained_r0->trace_rows != cs.n_rows ||
            retained_r0->n_coeffs != n_coeffs ||
            retained_r0->base_column_indices !=
                base_column_indices ||
            retained_r0->base_row_commitment.IsNull() ||
            !retained_r0->row_tree_cache ||
            !retained_r0->row_tree_cache->valid) {
            return fail("retained_r0_shape");
        }
        cache = retained_r0->row_tree_cache;
        base_root =
            retained_r0->base_row_commitment;
    } else {
        cache =
            std::make_shared<Fri3AlgRowTreeCache>();
        if (!Fri3AlgBuildRowTreeCacheStreaming(
                shifted, n_coeffs, *cache, &why) ||
            !cache->valid) {
            return fail("base_commit:" + why);
        }
        base_root =
            Fri3AlgDigestToUint256(cache->root);
    }
    const uint256 final_seed =
        TwoEpochFinalSeed(
            public_fs_seed, base_root,
            cs.n_rows, n_coeffs,
            base_column_indices);
    if (base_root.IsNull() || final_seed.IsNull()) {
        return fail("seed");
    }
    const auto proved =
        AirQuotientProveRows(
            cs, columns, final_seed, opt);
    if (!proved.ok || !proved.division_exact) {
        return fail("r1:" + proved.note);
    }
    std::vector<uint32_t> query_indices;
    query_indices.reserve(
        proved.proof.batch.queries.size());
    for (const auto& query :
         proved.proof.batch.queries) {
        query_indices.push_back(query.index);
    }
    std::vector<Fri3AlgRowOpening> opened;
    if (!Fri3AlgOpenRowsStreamingSharedCached(
            shifted, n_coeffs, query_indices,
            cache->root, *cache, opened, &why) ||
        opened.size() != query_indices.size()) {
        return fail("r0_open:" + why);
    }

    auto& receipt = out.receipt;
    receipt.trace_rows = cs.n_rows;
    receipt.n_coeffs = n_coeffs;
    receipt.base_column_indices =
        base_column_indices;
    receipt.base_row_commitment = base_root;
    receipt.base_openings.resize(opened.size());
    for (size_t query = 0;
         query < opened.size(); ++query) {
        receipt.base_openings[query].index =
            query_indices[query];
        receipt.base_openings[query].values =
            std::move(opened[query].values);
        receipt.base_openings[query].siblings =
            std::move(opened[query].siblings);
    }
    receipt.quotient = proved.proof;
    receipt.base_commitment_bound_in_fs = true;
    receipt.same_query_cross_openings = true;
    // Deliberately false: sampled cross-openings do not prove global oracle
    // equality. A sparse difference in R0 can alter the challenge while
    // avoiding all sampled sites. Retain this diagnostic receipt only until
    // the ordered multi-root R0/Rdep/Rq FRI backend replaces it.
    receipt.low_degree_proximity_accounted = false;
    receipt.valid = false;
    receipt.note =
        "two_epoch_rows:global_oracle_equality_unproved;"
        "multi_root_fri_required";
    out.ok = false;
    out.note = receipt.note;
    return out;
}

bool AirQuotientVerifyRowsTwoEpoch(
    const AirConstraintSystem<Fp3>& cs,
    const AirQuotientTwoEpochRowsReceipt& receipt,
    const uint256& public_fs_seed,
    std::string* why)
{
    const auto fail = [&](const std::string& detail) {
        if (why != nullptr) {
            *why = "two_epoch_verify:" + detail;
        }
        return false;
    };
    (void)cs;
    (void)receipt;
    (void)public_fs_seed;
    // Fail before parsing attacker-controlled proof material. The sampled
    // cross-opening construction cannot establish global R0/R1 equality,
    // regardless of attacker-controlled receipt flags.
    return fail(
        "global_oracle_equality_unproved;"
        "multi_root_fri_required");
}

AirQuotientSplitRapRowsProveResult
AirQuotientProveRowsSplitRapConfigured(
    const AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns,
    const std::vector<uint32_t>& base_column_indices,
    const uint256& public_fs_seed,
    const AirProveOptions& opt,
    const AirQuotientTwoEpochBaseRowSession*
        retained_r0,
    bool use_safe_v2)
{
    using T = AirField<Fp3>;
    AirQuotientSplitRapRowsProveResult out;
    const auto fail = [&](const std::string& detail) {
        out.ok = false;
        out.note = "split_rap_prove:" + detail;
        return out;
    };
    if (public_fs_seed.IsNull()) {
        return fail("public_seed");
    }
    if (opt.quotient_len_override != 0) {
        return fail(
            "quotient_len_override_unsupported");
    }

    std::vector<std::vector<Fp3>> r0;
    std::vector<std::vector<Fp3>> rdep;
    std::vector<uint32_t> dependent_indices;
    uint32_t n_coeffs = 0;
    std::string why;
    if (!BuildSplitRapTraceGroups(
            cs, columns, base_column_indices,
            r0, rdep, dependent_indices,
            n_coeffs, &why)) {
        return fail(why);
    }
    const uint32_t N = cs.n_rows;
    const uint32_t W = cs.n_columns;
    const uint32_t Lq = cs.QuotientLen();

    std::shared_ptr<Fri3AlgRowTreeCache>
        r0_cache;
    uint256 r0_root;
    if (retained_r0 != nullptr) {
        if (!retained_r0->valid ||
            retained_r0->trace_rows != N ||
            retained_r0->n_coeffs != n_coeffs ||
            retained_r0->base_column_indices !=
                base_column_indices ||
            retained_r0->base_row_commitment.IsNull() ||
            !retained_r0->row_tree_cache ||
            !retained_r0->row_tree_cache->valid ||
            Fri3AlgDigestToUint256(
                retained_r0->row_tree_cache->root) !=
                retained_r0
                    ->base_row_commitment) {
            return fail("retained_r0");
        }
        r0_cache = retained_r0->row_tree_cache;
        r0_root =
            retained_r0->base_row_commitment;
    } else {
        r0_cache =
            std::make_shared<
                Fri3AlgRowTreeCache>();
        if (!Fri3AlgBuildRowTreeCacheStreaming(
                r0, n_coeffs, *r0_cache,
                &why)) {
            return fail("r0_commit:" + why);
        }
        r0_root =
            Fri3AlgDigestToUint256(
                r0_cache->root);
    }

    auto rdep_cache =
        std::make_shared<
            Fri3AlgRowTreeCache>();
    if (!Fri3AlgBuildRowTreeCacheStreaming(
            rdep, n_coeffs, *rdep_cache,
            &why)) {
        return fail("rdep_commit:" + why);
    }
    const uint256 rdep_root =
        Fri3AlgDigestToUint256(
            rdep_cache->root);
    std::array<bool, 2> seen_group_pin{
        false, false};
    for (const auto& pin :
         cs.preprocessed_row_group_roots) {
        const uint32_t role =
            static_cast<uint32_t>(pin.role);
        if (pin.version != 1 ||
            role >= seen_group_pin.size() ||
            seen_group_pin[role] ||
            pin.root.IsNull() ||
            !Fri3AlgDigestFromUint256(pin.root)
                 .has_value()) {
            return fail(
                "preprocessed_row_group_pin_shape");
        }
        seen_group_pin[role] = true;
        const auto& expected_columns =
            pin.role ==
                AirPreprocessedRowGroupRole::kR0
            ? base_column_indices
            : dependent_indices;
        const uint256& actual_root =
            pin.role ==
                AirPreprocessedRowGroupRole::kR0
            ? r0_root
            : rdep_root;
        if (pin.ordered_columns !=
                expected_columns ||
            pin.root != actual_root) {
            return fail(
                "preprocessed_row_group_pin_mismatch");
        }
    }
    std::vector<uint32_t> lambda_extra{
        N, W, Lq, n_coeffs,
        static_cast<uint32_t>(
            base_column_indices.size())};
    lambda_extra.insert(
        lambda_extra.end(),
        base_column_indices.begin(),
        base_column_indices.end());
    Fp3 air_lambda;
    const bool lambda_ok =
        use_safe_v2
        ? DeriveSplitRapSafeFp3V2(
              public_fs_seed,
              "airq_split_rap_constraint_safe_v2",
              {r0_root, rdep_root},
              lambda_extra, air_lambda)
        : DeriveSplitRapUniformFp3(
              public_fs_seed,
              "airq_split_rap_constraint_v1",
              {r0_root, rdep_root},
              lambda_extra, air_lambda);
    if (!lambda_ok) {
        return fail("air_lambda");
    }

    const uint64_t dmax =
        cs.MaxComposedDegreeBound();
    if (dmax + 1 >
        (uint64_t{1} << 24)) {
        return fail("composed_degree");
    }
    const uint32_t M =
        std::max(
            N,
            FriNextPow2(
                static_cast<uint32_t>(
                    dmax + 1)));
    const uint32_t step_m = M / N;
    std::vector<std::vector<Fp3>> lde_m(W);
    for (uint32_t column = 0;
         column < W; ++column) {
        lde_m[column] =
            AirEvalOnSubgroup(
                AirInterpolate(
                    columns[column]),
                M);
    }
    const Fp omega_m =
        AirOmegaForSize(M);
    const Fp omega_n =
        AirOmegaForSize(N);
    const Fp3 h_first = T::One();
    const Fp3 h_last =
        T::FromBase(
            AirPowBase(omega_n, N - 1));
    std::vector<Fp3> composition(
        M, T::Zero());
    std::vector<Fp3> current(W);
    std::vector<Fp3> next(W);
    Fp y_base = 1;
    for (uint32_t row = 0;
         row < M; ++row) {
        const Fp3 y =
            T::FromBase(y_base);
        y_base =
            gkr_field::Mul(
                y_base, omega_m);
        const uint32_t next_row =
            (row + step_m) % M;
        for (uint32_t column = 0;
             column < W; ++column) {
            current[column] =
                lde_m[column][row];
            next[column] =
                lde_m[column][next_row];
        }
        Fp3 sum = T::Zero();
        Fp3 power = T::One();
        for (const auto& constraint :
             cs.constraints) {
            const Fp3 value =
                constraint.eval(
                    current, next);
            if (!T::IsZero(value)) {
                const Fp3 selector =
                    AirSelectorEval<Fp3>(
                        constraint.kind, N, y,
                        h_first, h_last);
                sum = T::Add(
                    sum,
                    T::Mul(
                        power,
                        T::Mul(
                            selector, value)));
            }
            power =
                T::Mul(power, air_lambda);
        }
        composition[row] = sum;
    }
    std::vector<Fp3> remainder =
        AirInterpolate(
            std::move(composition));
    std::vector<Fp3> quotient(
        M > N ? M - N : 1,
        T::Zero());
    for (uint32_t degree = M;
         degree-- > N;) {
        if (T::IsZero(
                remainder[degree])) {
            continue;
        }
        quotient[degree - N] =
            T::Add(
                quotient[degree - N],
                remainder[degree]);
        remainder[degree - N] =
            T::Add(
                remainder[degree - N],
                remainder[degree]);
        remainder[degree] = T::Zero();
    }
    remainder.resize(N);
    out.remainder = remainder;
    out.division_exact =
        std::all_of(
            remainder.begin(),
            remainder.end(),
            [](const Fp3& value) {
                return AirField<Fp3>::
                    IsZero(value);
            });
    if (!out.division_exact &&
        !opt.force_commit_on_inexact) {
        return fail("nonzero_remainder");
    }
    for (size_t degree = Lq;
         degree < quotient.size();
         ++degree) {
        if (!T::IsZero(
                quotient[degree])) {
            if (!opt.force_commit_on_inexact) {
                return fail(
                    "quotient_degree");
            }
            quotient[degree] = T::Zero();
        }
    }
    std::vector<Fp3> q_commit(
        Lq, T::Zero());
    for (uint32_t degree = 0;
         degree < Lq &&
         degree < quotient.size();
         ++degree) {
        q_commit[degree] =
            quotient[degree];
    }
    AirCosetShiftCoeffs(q_commit);

    auto rq_cache =
        std::make_shared<
            Fri3AlgRowTreeCache>();
    const std::vector<
        std::vector<Fp3>> rq{
            q_commit};
    if (!Fri3AlgBuildRowTreeCacheStreaming(
            rq, n_coeffs, *rq_cache,
            &why)) {
        return fail("rq_commit:" + why);
    }
    const uint256 rq_root =
        Fri3AlgDigestToUint256(
            rq_cache->root);
    const std::vector<uint256>
        ordered_roots{
            r0_root, rdep_root, rq_root};
    const uint256 fri_seed =
        use_safe_v2
        ? SplitRapFinalFriSeedSafeV2(
              public_fs_seed, ordered_roots,
              N, W, Lq, n_coeffs,
              base_column_indices)
        : SplitRapFinalFriSeed(
              public_fs_seed, ordered_roots,
              N, W, Lq, n_coeffs,
              base_column_indices);
    if (fri_seed.IsNull()) {
        return fail("fri_seed");
    }
    const std::vector<
        std::vector<
            std::vector<Fp3>>> groups{
                r0, rdep, rq};
    const std::vector<
        Fri3AlgMultiRowGroupRole> roles{
            Fri3AlgMultiRowGroupRole::
                MainTrace,
            Fri3AlgMultiRowGroupRole::
                AuxiliaryTrace,
            Fri3AlgMultiRowGroupRole::
                Quotient};
    std::vector<
        std::shared_ptr<
            Fri3AlgRowTreeCache>> caches{
                r0_cache, rdep_cache,
                rq_cache};
    auto committed =
        use_safe_v2
        ? Fri3AlgMultiRowSafeQ192K2V13BatchCommitStreaming(
              groups, roles, fri_seed, 0,
              caches)
        : Fri3AlgMultiRowBatchCommitStreaming(
              groups, roles, fri_seed, 0,
              caches);
    if (!committed.ok ||
        committed.proof.n_coeffs !=
            n_coeffs ||
        committed.proof.groups.size() !=
            3 ||
        Fri3AlgDigestToUint256(
            committed.proof.groups[0]
                .row_commit.root) != r0_root ||
        Fri3AlgDigestToUint256(
            committed.proof.groups[1]
                .row_commit.root) !=
            rdep_root ||
        Fri3AlgDigestToUint256(
            committed.proof.groups[2]
                .row_commit.root) != rq_root) {
        return fail(
            "multi_row:" +
            committed.note);
    }

    const uint32_t n_lde =
        n_coeffs * kRCFriBlowup;
    const uint32_t step =
        n_lde / N;
    std::vector<uint32_t> next_indices;
    next_indices.reserve(
        committed.proof.queries.size());
    for (const auto& query :
         committed.proof.queries) {
        next_indices.push_back(
            (query.index + step) %
            n_lde);
    }
    std::array<
        std::vector<
            Fri3AlgRowOpening>, 2>
        next_groups;
    if (!Fri3AlgOpenRowsStreamingSharedCached(
            r0, n_coeffs, next_indices,
            r0_cache->root, *r0_cache,
            next_groups[0], &why) ||
        !Fri3AlgOpenRowsStreamingSharedCached(
            rdep, n_coeffs, next_indices,
            rdep_cache->root,
            *rdep_cache,
            next_groups[1], &why)) {
        return fail(
            "next_rows:" + why);
    }

    out.proof.version =
        use_safe_v2
        ? kAirQuotientSplitRapRowsSafeProofVersionV2
        : kAirQuotientSplitRapRowsProofVersionV1;
    out.proof.trace_rows = N;
    out.proof.base_column_indices =
        base_column_indices;
    out.proof.air_constraint_lambda =
        air_lambda;
    out.proof.batch =
        std::move(committed.proof);
    out.proof.next_trace_group_rows.resize(
        next_indices.size(),
        std::vector<Fri3AlgRowOpening>(2));
    for (size_t query = 0;
         query < next_indices.size();
         ++query) {
        out.proof.next_trace_group_rows[
            query][0] =
            std::move(
                next_groups[0][query]);
        out.proof.next_trace_group_rows[
            query][1] =
            std::move(
                next_groups[1][query]);
    }
    out.group_row_tree_caches =
        std::move(
            committed
                .group_row_tree_caches);
    out.ok = true;
    out.note = out.division_exact
        ? use_safe_v2
              ? "split_rap_prove:"
                "exact_safe_multi_row_v13"
              : "split_rap_prove:"
                "exact_multi_row_v2"
        : "split_rap_prove:"
          "forced_inexact";
    return out;
}

AirQuotientSplitRapRowsProveResult
AirQuotientProveRowsSplitRap(
    const AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns,
    const std::vector<uint32_t>& base_column_indices,
    const uint256& public_fs_seed,
    const AirProveOptions& opt,
    const AirQuotientTwoEpochBaseRowSession*
        retained_r0)
{
    return AirQuotientProveRowsSplitRapConfigured(
        cs, columns, base_column_indices,
        public_fs_seed, opt, retained_r0,
        false);
}

AirQuotientSplitRapRowsProveResult
AirQuotientProveRowsSplitRapSafeV2(
    const AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns,
    const std::vector<uint32_t>& base_column_indices,
    const uint256& public_fs_seed,
    const AirProveOptions& opt,
    const AirQuotientTwoEpochBaseRowSession*
        retained_r0)
{
    return AirQuotientProveRowsSplitRapConfigured(
        cs, columns, base_column_indices,
        public_fs_seed, opt, retained_r0,
        true);
}

bool AirQuotientVerifyRowsSplitRapConfigured(
    const AirConstraintSystem<Fp3>& cs,
    const AirQuotientSplitRapRowsProof& proof,
    const std::vector<uint32_t>& expected_base_column_indices,
    const uint256& public_fs_seed,
    bool use_safe_v2,
    std::string* why)
{
    using T = AirField<Fp3>;
    const auto fail =
        [&](const std::string& detail) {
            if (why != nullptr) {
                *why =
                    "split_rap_verify:" +
                    detail;
            }
            return false;
        };
    const uint32_t N = cs.n_rows;
    const uint32_t W = cs.n_columns;
    if (proof.version !=
            (use_safe_v2
                 ? kAirQuotientSplitRapRowsSafeProofVersionV2
                 : kAirQuotientSplitRapRowsProofVersionV1) ||
        public_fs_seed.IsNull() ||
        N < 2 ||
        (N & (N - 1)) != 0 ||
        W < 2 ||
        proof.trace_rows != N ||
        proof.base_column_indices !=
            expected_base_column_indices ||
        proof.base_column_indices.empty() ||
        proof.base_column_indices.size() >=
            W) {
        return fail("shape");
    }
    std::vector<uint8_t> is_base(W, 0);
    uint32_t previous = 0;
    for (size_t position = 0;
         position <
             proof.base_column_indices.size();
         ++position) {
        const uint32_t column =
            proof.base_column_indices[position];
        if (column >= W ||
            (position != 0 &&
             column <= previous)) {
            return fail("base_indices");
        }
        previous = column;
        is_base[column] = 1;
    }
    std::vector<uint32_t>
        dependent_indices;
    for (uint32_t column = 0;
         column < W; ++column) {
        if (!is_base[column]) {
            dependent_indices.push_back(
                column);
        }
    }
    const auto& batch = proof.batch;
    const uint32_t Lq = cs.QuotientLen();
    const uint32_t n_coeffs =
        FriNextPow2(
            std::max(N, Lq));
    if (batch.groups.size() != 3 ||
        batch.groups[0].role !=
            Fri3AlgMultiRowGroupRole::
                MainTrace ||
        batch.groups[1].role !=
            Fri3AlgMultiRowGroupRole::
                AuxiliaryTrace ||
        batch.groups[2].role !=
            Fri3AlgMultiRowGroupRole::
                Quotient ||
        batch.groups[0].first_column != 0 ||
        batch.groups[0].column_count !=
            proof.base_column_indices.size() ||
        batch.groups[1].first_column !=
            batch.groups[0].column_count ||
        batch.groups[1].column_count !=
            dependent_indices.size() ||
        batch.groups[2].first_column != W ||
        batch.groups[2].column_count != 1 ||
        batch.column_len.size() != W + 1 ||
        batch.n_coeffs != n_coeffs) {
        return fail("group_schedule");
    }
    for (uint32_t column = 0;
         column < W; ++column) {
        if (batch.column_len[column] != N) {
            return fail(
                "trace_degree");
        }
    }
    if (batch.column_len[W] != Lq) {
        return fail(
            "quotient_degree");
    }
    const uint256 r0_root =
        Fri3AlgDigestToUint256(
            batch.groups[0]
                .row_commit.root);
    const uint256 rdep_root =
        Fri3AlgDigestToUint256(
            batch.groups[1]
                .row_commit.root);
    const uint256 rq_root =
        Fri3AlgDigestToUint256(
            batch.groups[2]
                .row_commit.root);
    std::vector<uint32_t> lambda_extra{
        N, W, Lq, n_coeffs,
        static_cast<uint32_t>(
            proof.base_column_indices
                .size())};
    lambda_extra.insert(
        lambda_extra.end(),
        proof.base_column_indices.begin(),
        proof.base_column_indices.end());
    Fp3 air_lambda;
    const bool lambda_ok =
        use_safe_v2
        ? DeriveSplitRapSafeFp3V2(
              public_fs_seed,
              "airq_split_rap_constraint_safe_v2",
              {r0_root, rdep_root},
              lambda_extra, air_lambda)
        : DeriveSplitRapUniformFp3(
              public_fs_seed,
              "airq_split_rap_constraint_v1",
              {r0_root, rdep_root},
              lambda_extra, air_lambda);
    if (!lambda_ok ||
        !T::Eq(
            air_lambda,
            proof.air_constraint_lambda)) {
        return fail("air_lambda");
    }
    const uint256 fri_seed =
        use_safe_v2
        ? SplitRapFinalFriSeedSafeV2(
              public_fs_seed,
              {r0_root, rdep_root, rq_root},
              N, W, Lq, n_coeffs,
              proof.base_column_indices)
        : SplitRapFinalFriSeed(
              public_fs_seed,
              {r0_root, rdep_root, rq_root},
              N, W, Lq, n_coeffs,
              proof.base_column_indices);
    std::string fri_why;
    const bool fri_ok =
        !fri_seed.IsNull() &&
        (use_safe_v2
             ? Fri3AlgMultiRowSafeQ192K2V13BatchVerify(
                   batch, fri_seed, &fri_why)
             : Fri3AlgMultiRowBatchVerify(
                   batch, fri_seed, &fri_why));
    if (!fri_ok) {
        return fail(
            "multi_row:" + fri_why);
    }

    std::vector<uint32_t> flat_index(
        W, W);
    for (uint32_t position = 0;
         position <
             proof.base_column_indices.size();
         ++position) {
        flat_index[
            proof.base_column_indices[
                position]] = position;
    }
    const uint32_t dep_base =
        static_cast<uint32_t>(
            proof.base_column_indices.size());
    for (uint32_t position = 0;
         position <
             dependent_indices.size();
         ++position) {
        flat_index[
            dependent_indices[position]] =
            dep_base + position;
    }
    if (!cs.preprocessed_roots.empty()) {
        return fail(
            "preprocessed_roots_unsupported");
    }
    std::array<bool, 2> seen_group_pin{
        false, false};
    for (const auto& pin :
         cs.preprocessed_row_group_roots) {
        const uint32_t role =
            static_cast<uint32_t>(pin.role);
        if (pin.version != 1 ||
            role >= seen_group_pin.size() ||
            seen_group_pin[role] ||
            pin.root.IsNull() ||
            !Fri3AlgDigestFromUint256(pin.root)
                 .has_value()) {
            return fail(
                "preprocessed_row_group_pin_shape");
        }
        seen_group_pin[role] = true;
        const auto& expected_columns =
            pin.role ==
                AirPreprocessedRowGroupRole::kR0
            ? proof.base_column_indices
            : dependent_indices;
        const uint256& actual_root =
            pin.role ==
                AirPreprocessedRowGroupRole::kR0
            ? r0_root
            : rdep_root;
        if (pin.ordered_columns !=
                expected_columns ||
            pin.root != actual_root) {
            return fail(
                "preprocessed_row_group_pin_mismatch");
        }
    }
    if (!cs.preprocessed.empty() &&
        !cs.preprocessed_pin_ood) {
        return fail(
            "preprocessed_requires_ood_pin");
    }
    if (cs.preprocessed_pin_ood) {
        const Fp3 shift =
            T::FromBase(kAirCosetShift);
        const std::array<Fp3, 2> points{
            T::Mul(shift, batch.z1),
            T::Mul(shift, batch.z2)};
        const std::array<
            const std::vector<Fp3>*, 2>
            evals{
                &batch.evals_z1,
                &batch.evals_z2};
        for (uint32_t point = 0;
             point < 2; ++point) {
            std::vector<Fp3> weights;
            Fp3 zh_over_n = T::Zero();
            if (!AirBarycentricWeightsOnH<Fp3>(
                    N, points[point],
                    weights, zh_over_n)) {
                return fail(
                    "preprocessed_ood_point");
            }
            for (const auto& [column, values] :
                 cs.preprocessed) {
                if (column >= W ||
                    values.size() != N ||
                    flat_index[column] >= W) {
                    return fail(
                        "preprocessed_shape");
                }
                Fp3 value = T::Zero();
                for (uint32_t row = 0;
                     row < N; ++row) {
                    value = T::Add(
                        value,
                        T::Mul(
                            values[row],
                            weights[row]));
                }
                if (!T::Eq(
                        T::Mul(
                            zh_over_n, value),
                        (*evals[point])[
                            flat_index[column]])) {
                    return fail(
                        "preprocessed_ood");
                }
            }
        }
    }

    const uint32_t n_lde =
        n_coeffs * kRCFriBlowup;
    const uint32_t step =
        n_lde / N;
    if (proof.next_trace_group_rows.size() !=
            batch.queries.size()) {
        return fail("next_count");
    }
    const Fp omega_lde =
        AirOmegaForSize(n_lde);
    const Fp omega_n =
        AirOmegaForSize(N);
    const Fp3 h_first = T::One();
    const Fp3 h_last =
        T::FromBase(
            AirPowBase(omega_n, N - 1));
    const Fp3 coset =
        T::FromBase(kAirCosetShift);
    std::vector<Fp3> current(W);
    std::vector<Fp3> next(W);
    for (size_t query = 0;
         query < batch.queries.size();
         ++query) {
        const auto& opened =
            batch.queries[query];
        const auto& next_groups =
            proof.next_trace_group_rows[
                query];
        if (opened.group_rows.size() != 3 ||
            next_groups.size() != 2 ||
            opened.group_rows[0]
                    .values.size() !=
                proof.base_column_indices
                    .size() ||
            opened.group_rows[1]
                    .values.size() !=
                dependent_indices.size() ||
            opened.group_rows[2]
                    .values.size() != 1 ||
            next_groups[0].values.size() !=
                proof.base_column_indices
                    .size() ||
            next_groups[1].values.size() !=
                dependent_indices.size()) {
            return fail("query_width");
        }
        const uint32_t next_index =
            (opened.index + step) %
            n_lde;
        for (uint32_t group = 0;
             group < 2; ++group) {
            if (!Fri3AlgVerifyPath(
                    alg_hash::LeafHashRow(
                        next_groups[group]
                            .values,
                        next_index),
                    next_index,
                    next_groups[group]
                        .siblings,
                    batch.groups[group]
                        .row_commit.root,
                    n_lde)) {
                return fail("next_merkle");
            }
        }
        for (uint32_t position = 0;
             position <
                 proof.base_column_indices
                     .size();
             ++position) {
            const uint32_t column =
                proof.base_column_indices[
                    position];
            current[column] =
                opened.group_rows[0]
                    .values[position];
            next[column] =
                next_groups[0]
                    .values[position];
        }
        for (uint32_t position = 0;
             position <
                 dependent_indices.size();
             ++position) {
            const uint32_t column =
                dependent_indices[position];
            current[column] =
                opened.group_rows[1]
                    .values[position];
            next[column] =
                next_groups[1]
                    .values[position];
        }
        const Fp3 y =
            T::Mul(
                coset,
                T::FromBase(
                    AirPowBase(
                        omega_lde,
                        opened.index)));
        const Fp3 zh =
            T::Sub(
                AirPow(y, N),
                T::One());
        if (T::IsZero(zh)) {
            return fail("zh_zero");
        }
        Fp3 sum = T::Zero();
        Fp3 power = T::One();
        for (const auto& constraint :
             cs.constraints) {
            const Fp3 value =
                constraint.eval(
                    current, next);
            if (!T::IsZero(value)) {
                const Fp3 selector =
                    AirSelectorEval<Fp3>(
                        constraint.kind, N, y,
                        h_first, h_last);
                sum = T::Add(
                    sum,
                    T::Mul(
                        power,
                        T::Mul(
                            selector, value)));
            }
            power =
                T::Mul(power, air_lambda);
        }
        const Fp3 quotient_value =
            opened.group_rows[2]
                .values[0];
        if (!T::Eq(
                sum,
                T::Mul(
                    quotient_value, zh))) {
            return fail(
                "quotient_identity");
        }
    }
    if (why != nullptr) {
        *why =
            "split_rap_verify:"
            "complete_current_next_identity";
    }
    return true;
}

bool AirQuotientVerifyRowsSplitRap(
    const AirConstraintSystem<Fp3>& cs,
    const AirQuotientSplitRapRowsProof& proof,
    const std::vector<uint32_t>& expected_base_column_indices,
    const uint256& public_fs_seed,
    std::string* why)
{
    return AirQuotientVerifyRowsSplitRapConfigured(
        cs, proof, expected_base_column_indices,
        public_fs_seed, false, why);
}

bool AirQuotientVerifyRowsSplitRapSafeV2(
    const AirConstraintSystem<Fp3>& cs,
    const AirQuotientSplitRapRowsProof& proof,
    const std::vector<uint32_t>& expected_base_column_indices,
    const uint256& public_fs_seed,
    std::string* why)
{
    return AirQuotientVerifyRowsSplitRapConfigured(
        cs, proof, expected_base_column_indices,
        public_fs_seed, true, why);
}

bool AirQuotientVerifyRowsSplitRapSafeV2Replay(
    const AirConstraintSystem<Fp3>& cs,
    const AirQuotientSplitRapRowsProof& proof,
    const std::vector<uint32_t>& expected_base_column_indices,
    const uint256& public_fs_seed,
    AirQuotientSplitRapSafeReplayV2& out,
    std::string* why)
{
    out = {};
    std::string verify_why;
    if (!AirQuotientVerifyRowsSplitRapSafeV2(
            cs, proof,
            expected_base_column_indices,
            public_fs_seed, &verify_why)) {
        if (why != nullptr) {
            *why =
                "split_rap_safe_replay:verify:" +
                verify_why;
        }
        return false;
    }
    const uint32_t N = cs.n_rows;
    const uint32_t W = cs.n_columns;
    const uint32_t Lq = cs.QuotientLen();
    const uint32_t n_coeffs =
        proof.batch.n_coeffs;
    const uint256 r0_root =
        Fri3AlgDigestToUint256(
            proof.batch.groups[0]
                .row_commit.root);
    const uint256 rdep_root =
        Fri3AlgDigestToUint256(
            proof.batch.groups[1]
                .row_commit.root);
    const uint256 rq_root =
        Fri3AlgDigestToUint256(
            proof.batch.groups[2]
                .row_commit.root);
    std::vector<uint32_t> lambda_extra{
        N, W, Lq, n_coeffs,
        static_cast<uint32_t>(
            proof.base_column_indices
                .size())};
    lambda_extra.insert(
        lambda_extra.end(),
        proof.base_column_indices.begin(),
        proof.base_column_indices.end());
    out.air_lambda_message =
        AirChallengeP2Lanes(
            public_fs_seed,
            "airq_split_rap_constraint_safe_v2",
            {r0_root, rdep_root},
            lambda_extra);
    if (!DeriveSplitRapSafeDigestV2(
            public_fs_seed,
            "airq_split_rap_constraint_safe_v2",
            {r0_root, rdep_root},
            lambda_extra,
            alg_hash_typed::RoleV12::
                TranscriptAirLambda,
            out.air_lambda_digest)) {
        out = {};
        if (why != nullptr) {
            *why =
                "split_rap_safe_replay:air_lambda";
        }
        return false;
    }
    out.air_lambda = Fp3{
        gkr_field::Canonical(
            out.air_lambda_digest[0]),
        gkr_field::Canonical(
            out.air_lambda_digest[1]),
        gkr_field::Canonical(
            out.air_lambda_digest[2])};
    if (!gkr_field::Eq(
            out.air_lambda,
            proof.air_constraint_lambda)) {
        out = {};
        if (why != nullptr) {
            *why =
                "split_rap_safe_replay:air_lambda_mismatch";
        }
        return false;
    }

    std::vector<uint32_t> fri_extra{
        N, W, Lq, n_coeffs,
        static_cast<uint32_t>(
            proof.base_column_indices
                .size())};
    fri_extra.insert(
        fri_extra.end(),
        proof.base_column_indices.begin(),
        proof.base_column_indices.end());
    out.fri_seed_message =
        AirChallengeP2Lanes(
            public_fs_seed,
            "airq_split_rap_fri_seed_safe_v2",
            {r0_root, rdep_root, rq_root},
            fri_extra);
    if (!DeriveSplitRapSafeDigestV2(
            public_fs_seed,
            "airq_split_rap_fri_seed_safe_v2",
            {r0_root, rdep_root, rq_root},
            fri_extra,
            alg_hash_typed::RoleV12::
                TranscriptFriSeed,
            out.fri_seed_digest)) {
        out = {};
        if (why != nullptr) {
            *why =
                "split_rap_safe_replay:fri_seed";
        }
        return false;
    }
    out.fri_seed =
        SplitRapSafeDigestToUint256(
            out.fri_seed_digest);
    if (out.fri_seed.IsNull()) {
        out = {};
        if (why != nullptr) {
            *why =
                "split_rap_safe_replay:null_fri_seed";
        }
        return false;
    }
    out.native_verified = true;
    if (why != nullptr) {
        *why =
            "split_rap_safe_replay:verified";
    }
    return true;
}

namespace {

void AppendLE64v(
    std::vector<unsigned char>& out,
    uint64_t value)
{
    unsigned char bytes[8];
    WriteLE64(bytes, value);
    out.insert(out.end(), bytes, bytes + 8);
}

void AppendCanonicalFp3v(
    std::vector<unsigned char>& out,
    const Fp3& value)
{
    AppendLE64v(
        out, gkr_field::Canonical(value.c0));
    AppendLE64v(
        out, gkr_field::Canonical(value.c1));
    AppendLE64v(
        out, gkr_field::Canonical(value.c2));
}

void AppendCanonicalAlgDigestv(
    std::vector<unsigned char>& out,
    const Fri3AlgDigest& digest)
{
    for (Fp limb : digest) {
        AppendLE64v(
            out, gkr_field::Canonical(limb));
    }
}

bool ReadLE32vChecked(
    const unsigned char*& p,
    const unsigned char* end,
    uint32_t& out)
{
    if (static_cast<size_t>(end - p) < 4) {
        return false;
    }
    out = ReadLE32(p);
    p += 4;
    return true;
}

bool ReadLE64vChecked(
    const unsigned char*& p,
    const unsigned char* end,
    uint64_t& out)
{
    if (static_cast<size_t>(end - p) < 8) {
        return false;
    }
    out = ReadLE64(p);
    p += 8;
    return true;
}

bool ReadCanonicalFp3v(
    const unsigned char*& p,
    const unsigned char* end,
    Fp3& out)
{
    uint64_t c0 = 0;
    uint64_t c1 = 0;
    uint64_t c2 = 0;
    if (!ReadLE64vChecked(p, end, c0) ||
        !ReadLE64vChecked(p, end, c1) ||
        !ReadLE64vChecked(p, end, c2) ||
        c0 >= gkr_field::kP ||
        c1 >= gkr_field::kP ||
        c2 >= gkr_field::kP) {
        return false;
    }
    out = Fp3{c0, c1, c2};
    return true;
}

bool ReadCanonicalAlgDigestv(
    const unsigned char*& p,
    const unsigned char* end,
    Fri3AlgDigest& out)
{
    for (Fp& limb : out) {
        uint64_t value = 0;
        if (!ReadLE64vChecked(
                p, end, value) ||
            value >= gkr_field::kP) {
            return false;
        }
        limb = value;
    }
    return true;
}

bool AirWireBytes(
    const unsigned char* p,
    const unsigned char* end,
    uint32_t count,
    size_t item_bytes)
{
    return item_bytes == 0 ||
        count <=
            static_cast<size_t>(end - p) /
                item_bytes;
}

uint32_t AirLog2Exact(uint32_t value)
{
    uint32_t log = 0;
    while (value > 1) {
        value >>= 1;
        ++log;
    }
    return log;
}

bool SplitRapCodecShape(
    const AirQuotientSplitRapRowsProof& proof,
    size_t batch_bytes,
    size_t* encoded_size)
{
    const bool v1 =
        proof.version ==
        kAirQuotientSplitRapRowsProofVersionV1;
    const bool safe_v2 =
        proof.version ==
        kAirQuotientSplitRapRowsSafeProofVersionV2;
    if ((!v1 && !safe_v2) ||
        (v1 &&
         proof.batch.version !=
             kRCFri3AlgMultiRowBatchProofVersion) ||
        (safe_v2 &&
         proof.batch.version !=
             kRCFri3AlgMultiRowSafeQ192K2ProofVersionV13) ||
        proof.trace_rows < 2 ||
        (proof.trace_rows &
         (proof.trace_rows - 1)) != 0 ||
        batch_bytes == 0 ||
        batch_bytes >
            kRCFri3AlgMultiRowMaxProofBytesHard ||
        proof.batch.groups.size() != 3 ||
        proof.batch.column_len.size() < 3 ||
        proof.base_column_indices.empty()) {
        return false;
    }
    const uint32_t width =
        static_cast<uint32_t>(
            proof.batch.column_len.size() - 1);
    if (proof.base_column_indices.size() >=
            width ||
        proof.base_column_indices.size() !=
            proof.batch.groups[0]
                .column_count ||
        proof.batch.groups[0].first_column != 0 ||
        proof.batch.groups[1].first_column !=
            proof.base_column_indices.size() ||
        proof.batch.groups[1].column_count !=
            width -
                proof.base_column_indices.size() ||
        proof.batch.groups[2].first_column !=
            width ||
        proof.batch.groups[2].column_count !=
            1) {
        return false;
    }
    uint32_t previous = 0;
    for (uint32_t position = 0;
         position <
             proof.base_column_indices.size();
         ++position) {
        const uint32_t index =
            proof.base_column_indices[position];
        if (index >= width ||
            (position != 0 &&
             index <= previous)) {
            return false;
        }
        previous = index;
    }
    for (uint32_t column = 0;
         column < width; ++column) {
        if (proof.batch.column_len[column] !=
            proof.trace_rows) {
            return false;
        }
    }
    const uint32_t quotient_len =
        proof.batch.column_len[width];
    if (quotient_len == 0 ||
        FriNextPow2(
            std::max(
                proof.trace_rows,
                quotient_len)) !=
            proof.batch.n_coeffs ||
        proof.next_trace_group_rows.size() !=
            proof.batch.queries.size() ||
        proof.next_trace_group_rows.size() !=
            kRCFri3AlgNumQueries) {
        return false;
    }
    const uint32_t row_depth =
        AirLog2Exact(
            proof.batch.n_coeffs *
            kRCFriBlowup);
    for (const auto& next :
         proof.next_trace_group_rows) {
        if (next.size() != 2) {
            return false;
        }
        for (uint32_t group = 0;
             group < 2; ++group) {
            if (next[group].values.size() !=
                    proof.batch.groups[group]
                        .column_count ||
                next[group].siblings.size() !=
                    row_depth) {
                return false;
            }
        }
    }

    unsigned __int128 bytes =
        4 + 4 + 4 + 4 +
        static_cast<unsigned __int128>(
            proof.base_column_indices.size()) *
            4 +
        24 + 4 + batch_bytes + 4;
    for (const auto& next :
         proof.next_trace_group_rows) {
        bytes += 4;
        for (const auto& row : next) {
            bytes +=
                4 +
                static_cast<unsigned __int128>(
                    row.values.size()) *
                    24 +
                4 +
                static_cast<unsigned __int128>(
                    row.siblings.size()) *
                    32;
        }
    }
    if (bytes >
            kAirQuotientSplitRapRowsMaxProofBytesHard ||
        bytes >
            std::numeric_limits<size_t>::max()) {
        return false;
    }
    if (encoded_size != nullptr) {
        *encoded_size =
            static_cast<size_t>(bytes);
    }
    return true;
}

} // namespace

size_t SerializeAirQuotientSplitRapRowsProof(
    const AirQuotientSplitRapRowsProof& proof,
    std::vector<unsigned char>& out)
{
    out.clear();
    std::vector<unsigned char> batch;
    const size_t batch_bytes =
        SerializeFri3AlgMultiRowBatchProof(
            proof.batch, batch);
    size_t exact_size = 0;
    if (!SplitRapCodecShape(
            proof, batch_bytes, &exact_size)) {
        return 0;
    }
    out.reserve(exact_size);
    AppendLE32v(
        out,
        kAirQuotientSplitRapRowsProofMagic);
    AppendLE32v(out, proof.version);
    AppendLE32v(out, proof.trace_rows);
    AppendLE32v(
        out,
        static_cast<uint32_t>(
            proof.base_column_indices.size()));
    for (uint32_t index :
         proof.base_column_indices) {
        AppendLE32v(out, index);
    }
    AppendCanonicalFp3v(
        out, proof.air_constraint_lambda);
    AppendLE32v(
        out,
        static_cast<uint32_t>(
            batch_bytes));
    out.insert(
        out.end(),
        batch.begin(), batch.end());
    AppendLE32v(
        out,
        static_cast<uint32_t>(
            proof.next_trace_group_rows
                .size()));
    for (const auto& next :
         proof.next_trace_group_rows) {
        AppendLE32v(
            out,
            static_cast<uint32_t>(
                next.size()));
        for (const auto& row : next) {
            AppendLE32v(
                out,
                static_cast<uint32_t>(
                    row.values.size()));
            for (const auto& value :
                 row.values) {
                AppendCanonicalFp3v(
                    out, value);
            }
            AppendLE32v(
                out,
                static_cast<uint32_t>(
                    row.siblings.size()));
            for (const auto& sibling :
                 row.siblings) {
                AppendCanonicalAlgDigestv(
                    out, sibling);
            }
        }
    }
    if (out.size() != exact_size) {
        out.clear();
        return 0;
    }
    return out.size();
}

std::optional<AirQuotientSplitRapRowsProof>
DeserializeAirQuotientSplitRapRowsProof(
    const std::vector<unsigned char>& in)
{
    if (in.empty() ||
        in.size() >
            kAirQuotientSplitRapRowsMaxProofBytesHard) {
        return std::nullopt;
    }
    const unsigned char* p = in.data();
    const unsigned char* end =
        in.data() + in.size();
    uint32_t magic = 0;
    uint32_t version = 0;
    AirQuotientSplitRapRowsProof proof;
    if (!ReadLE32vChecked(p, end, magic) ||
        magic !=
            kAirQuotientSplitRapRowsProofMagic ||
        !ReadLE32vChecked(p, end, version) ||
        (version !=
             kAirQuotientSplitRapRowsProofVersionV1 &&
         version !=
             kAirQuotientSplitRapRowsSafeProofVersionV2) ||
        !ReadLE32vChecked(
            p, end, proof.trace_rows) ||
        proof.trace_rows < 2 ||
        (proof.trace_rows &
         (proof.trace_rows - 1)) != 0) {
        return std::nullopt;
    }
    proof.version =
        static_cast<uint16_t>(version);
    uint32_t base_count = 0;
    if (!ReadLE32vChecked(
            p, end, base_count) ||
        base_count == 0 ||
        base_count >=
            kRCFri3AlgBatchMaxColumns ||
        !AirWireBytes(
            p, end, base_count, 4)) {
        return std::nullopt;
    }
    proof.base_column_indices.resize(
        base_count);
    uint32_t previous = 0;
    for (uint32_t position = 0;
         position < base_count;
         ++position) {
        uint32_t& index =
            proof.base_column_indices[position];
        if (!ReadLE32vChecked(
                p, end, index) ||
            (position != 0 &&
             index <= previous)) {
            return std::nullopt;
        }
        previous = index;
    }
    if (!ReadCanonicalFp3v(
            p, end,
            proof.air_constraint_lambda)) {
        return std::nullopt;
    }
    uint32_t batch_bytes = 0;
    if (!ReadLE32vChecked(
            p, end, batch_bytes) ||
        batch_bytes == 0 ||
        batch_bytes >
            kRCFri3AlgMultiRowMaxProofBytesHard ||
        !AirWireBytes(
            p, end, batch_bytes, 1)) {
        return std::nullopt;
    }
    std::vector<unsigned char> batch_wire(
        p, p + batch_bytes);
    p += batch_bytes;
    auto batch =
        DeserializeFri3AlgMultiRowBatchProof(
            batch_wire);
    if (!batch.has_value()) {
        return std::nullopt;
    }
    proof.batch = std::move(*batch);
    if (proof.batch.groups.size() != 3 ||
        proof.batch.column_len.size() < 3) {
        return std::nullopt;
    }
    const uint32_t width =
        static_cast<uint32_t>(
            proof.batch.column_len.size() - 1);
    if (base_count >= width ||
        base_count !=
            proof.batch.groups[0]
                .column_count ||
        proof.batch.groups[1].column_count !=
            width - base_count ||
        proof.batch.groups[2].first_column !=
            width ||
        proof.batch.groups[2].column_count !=
            1 ||
        proof.base_column_indices.back() >=
            width) {
        return std::nullopt;
    }
    for (uint32_t column = 0;
         column < width; ++column) {
        if (proof.batch.column_len[column] !=
            proof.trace_rows) {
            return std::nullopt;
        }
    }
    const uint32_t quotient_len =
        proof.batch.column_len[width];
    if (quotient_len == 0 ||
        FriNextPow2(
            std::max(
                proof.trace_rows,
                quotient_len)) !=
            proof.batch.n_coeffs) {
        return std::nullopt;
    }
    uint32_t query_count = 0;
    if (!ReadLE32vChecked(
            p, end, query_count) ||
        query_count !=
            kRCFri3AlgNumQueries ||
        query_count !=
            proof.batch.queries.size() ||
        !AirWireBytes(
            p, end, query_count,
            4 + 2 * (4 + 4))) {
        return std::nullopt;
    }
    proof.next_trace_group_rows.resize(
        query_count);
    const uint32_t row_depth =
        AirLog2Exact(
            proof.batch.n_coeffs *
            kRCFriBlowup);
    for (auto& next :
         proof.next_trace_group_rows) {
        uint32_t group_count = 0;
        if (!ReadLE32vChecked(
                p, end, group_count) ||
            group_count != 2) {
            return std::nullopt;
        }
        next.resize(group_count);
        for (uint32_t group = 0;
             group < group_count;
             ++group) {
            auto& row = next[group];
            uint32_t value_count = 0;
            if (!ReadLE32vChecked(
                    p, end, value_count) ||
                value_count !=
                    proof.batch.groups[group]
                        .column_count ||
                !AirWireBytes(
                    p, end, value_count,
                    24)) {
                return std::nullopt;
            }
            row.values.resize(value_count);
            for (auto& value : row.values) {
                if (!ReadCanonicalFp3v(
                        p, end, value)) {
                    return std::nullopt;
                }
            }
            uint32_t sibling_count = 0;
            if (!ReadLE32vChecked(
                    p, end,
                    sibling_count) ||
                sibling_count != row_depth ||
                !AirWireBytes(
                    p, end,
                    sibling_count, 32)) {
                return std::nullopt;
            }
            row.siblings.resize(
                sibling_count);
            for (auto& sibling :
                 row.siblings) {
                if (!ReadCanonicalAlgDigestv(
                        p, end, sibling)) {
                    return std::nullopt;
                }
            }
        }
    }
    if (p != end) return std::nullopt;
    size_t expected_size = 0;
    if (!SplitRapCodecShape(
            proof, batch_bytes,
            &expected_size) ||
        expected_size != in.size()) {
        return std::nullopt;
    }
    std::vector<unsigned char> canonical;
    if (SerializeAirQuotientSplitRapRowsProof(
            proof, canonical) !=
            in.size() ||
        canonical != in) {
        return std::nullopt;
    }
    return proof;
}

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
                                     const AirQuotientProof<Fp2>&, const uint256&, std::string*,
                                     uint32_t);
template bool AirQuotientVerify<Fp3>(const AirConstraintSystem<Fp3>&,
                                     const AirQuotientProof<Fp3>&, const uint256&, std::string*,
                                     uint32_t);

template AirQuotientProveResult<Fp3, StreamingColumnsB3>
AirQuotientProve<Fp3, StreamingColumnsB3>(
    const AirConstraintSystem<Fp3>&,
    const std::vector<std::vector<Fp3>>&,
    const uint256&,
    const AirProveOptions&);
template bool AirQuotientVerify<Fp3, StreamingColumnsB3>(
    const AirConstraintSystem<Fp3>&,
    const AirQuotientProof<Fp3, StreamingColumnsB3>&,
    const uint256&,
    std::string*,
    uint32_t);

template uint256 AirCommittedValuesRoot<Fp3, AlgB3>(const std::vector<Fp3>&, uint32_t);
template AirQuotientProveResult<Fp3, AlgB3> AirQuotientProve<Fp3, AlgB3>(
    const AirConstraintSystem<Fp3>&, const std::vector<std::vector<Fp3>>&, const uint256&,
    const AirProveOptions&);
template bool AirQuotientVerify<Fp3, AlgB3>(const AirConstraintSystem<Fp3>&,
                                            const AirQuotientProof<Fp3, AlgB3>&, const uint256&,
                                            std::string*, uint32_t);

template AirQuotientProveResult<
    Fp3, AirFriBackendAlgStreamingRows>
AirQuotientProve<Fp3, AirFriBackendAlgStreamingRows>(
    const AirConstraintSystem<Fp3>&,
    const std::vector<std::vector<Fp3>>&,
    const uint256&,
    const AirProveOptions&);
template bool
AirQuotientVerify<Fp3, AirFriBackendAlgStreamingRows>(
    const AirConstraintSystem<Fp3>&,
    const AirQuotientProof<
        Fp3, AirFriBackendAlgStreamingRows>&,
    const uint256&,
    std::string*,
    uint32_t);

template uint256 AirCommittedValuesRoot<Fp3, AlgDualB3>(const std::vector<Fp3>&, uint32_t);
template AirQuotientProveResult<Fp3, AlgDualB3> AirQuotientProve<Fp3, AlgDualB3>(
    const AirConstraintSystem<Fp3>&, const std::vector<std::vector<Fp3>>&, const uint256&,
    const AirProveOptions&);
template bool AirQuotientVerify<Fp3, AlgDualB3>(
    const AirConstraintSystem<Fp3>&, const AirQuotientProof<Fp3, AlgDualB3>&,
    const uint256&, std::string*, uint32_t);

template AirQuotientProveResult<
    Fp3, AlgDualStreamingAuditB3>
AirQuotientProve<Fp3, AlgDualStreamingAuditB3>(
    const AirConstraintSystem<Fp3>&,
    const std::vector<std::vector<Fp3>>&,
    const uint256&, const AirProveOptions&);
template bool AirQuotientVerify<
    Fp3, AlgDualStreamingAuditB3>(
    const AirConstraintSystem<Fp3>&,
    const AirQuotientProof<
        Fp3, AlgDualStreamingAuditB3>&,
    const uint256&, std::string*, uint32_t);

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
