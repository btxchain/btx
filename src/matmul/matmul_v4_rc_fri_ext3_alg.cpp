// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_fri_ext3_alg.h>

#include <matmul/matmul_v4_rc_fri_ext3.h> // Sha256dBytes (FS transcript only)
#include <matmul/matmul_v4_rc_rowleaf_gpu.h> // PR-89 GPU splice #1 (row-leaf sponge)
#include <matmul/matmul_v4_rc_air_quotient.h> // PR-89 Construction 2 predicate AIR
#include <crypto/sha256.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <future>
#include <limits>
#include <mutex>
#include <string>
#include <thread>

#if defined(_OPENMP)
#include <omp.h>
#endif

// Algebraic-hash twin of the BATCHED half of matmul_v4_rc_fri_ext3.cpp —
// see the header for the approach note (spec §2.1 option (b): parallel file,
// SHA256d consensus path byte-for-byte untouched). Everything below the hash
// surface (NTT/LDE, degree-shift RLC, dual-OOD DEEP, v5 half-domain fold,
// terminal B-constant layer, FS replay) is transcribed VERBATIM from that
// file's anonymous namespace; the swapped surface is exactly:
//   Fri3LeafHash   → alg_hash::LeafHash        (fold-layer leaves)
//   (per-col leaf) → alg_hash::LeafHashRow     (row-wise commitment, §2.3)
//   Fri3NodeHash   → alg_hash::Compress        (2→1 over Fp^4 digests)
//   Digest         → std::array<Fp,4>          (uint256 only at FS/ser edges)
// plus the row-wise Merkle layout (ONE tree, ONE path per query) and the
// path-local Stage-3 Q=192 query count.

namespace matmul::v4::rc {

// PR-89 Construction 2 predicate AIR (field-native grind).
namespace aq = air_quotient;
namespace gf = gkr_field;

namespace {

using gkr_field::Add;
using gkr_field::Canonical;
using gkr_field::Eq;
using gkr_field::Fp;
using gkr_field::FromChallengeBytes3;
using gkr_field::Inv;
using gkr_field::kP;
using gkr_field::Mul;
using gkr_field::Sub;

// Prover thread count: BTX_PROVE_THREADS if set (>0), else all cores.
// Parallelized phases here (per-leaf hashing, per-column LDE, per-level
// compress) write only distinct output indices, so thread count / schedule
// never alter the produced digests — output is byte-identical to serial.
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

// Per-phase wall-clock instrumentation for the FRI commit, gated by
// BTX_PROVE_TIMING (unset => no output, no effect on the proof).
struct BtxFriTimer {
    const bool on;
    std::chrono::steady_clock::time_point last;
    BtxFriTimer()
        : on(std::getenv("BTX_PROVE_TIMING") != nullptr),
          last(std::chrono::steady_clock::now()) {}
    void mark(const char* name)
    {
        const auto now = std::chrono::steady_clock::now();
        if (on) {
            const double ms =
                std::chrono::duration<double, std::milli>(now - last).count();
            std::fprintf(stderr, "[BTX_TIMING]   fri:%-18s %12.1f ms\n",
                         name, ms);
            std::fflush(stderr);
        }
        last = now;
    }
};

/** Goldilocks 2^32-th root of unity: 7^((p-1)/2^32). */
constexpr Fp kOmega2_32 = 0x185629dcda58878cULL;

void AppendLE32(std::vector<unsigned char>& buf, uint32_t v)
{
    for (int i = 0; i < 4; ++i) {
        buf.push_back(static_cast<unsigned char>((v >> (8 * i)) & 0xFF));
    }
}
void AppendLE64(std::vector<unsigned char>& buf, uint64_t v)
{
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<unsigned char>((v >> (8 * i)) & 0xFF));
    }
}
void AppendFp3(std::vector<unsigned char>& buf, const Fp3& v)
{
    AppendLE64(buf, Canonical(v.c0));
    AppendLE64(buf, Canonical(v.c1));
    AppendLE64(buf, Canonical(v.c2));
}
void AppendBytes(std::vector<unsigned char>& buf, const unsigned char* p, size_t n)
{
    buf.insert(buf.end(), p, p + n);
}
/** Serialize a digest as 4 canonical LE64 limbs (the header's packing). */
void AppendAlgDigest(std::vector<unsigned char>& buf, const Fri3AlgDigest& d)
{
    for (uint32_t k = 0; k < alg_hash::kAlgHashDigestLen; ++k) AppendLE64(buf, Canonical(d[k]));
}

bool ReadLE32Checked(const unsigned char*& p, const unsigned char* end, uint32_t& out)
{
    if (static_cast<size_t>(end - p) < 4) return false;
    out = 0;
    for (int i = 0; i < 4; ++i) out |= static_cast<uint32_t>(p[i]) << (8 * i);
    p += 4;
    return true;
}
bool ReadLE64Checked(const unsigned char*& p, const unsigned char* end, uint64_t& out)
{
    if (static_cast<size_t>(end - p) < 8) return false;
    out = 0;
    for (int i = 0; i < 8; ++i) out |= static_cast<uint64_t>(p[i]) << (8 * i);
    p += 8;
    return true;
}
bool ReadUint256Checked(const unsigned char*& p, const unsigned char* end,
                        uint256& out)
{
    if (static_cast<size_t>(end - p) < 32) return false;
    std::memcpy(out.data(), p, 32);
    p += 32;
    return true;
}
bool ReadFp3Checked(const unsigned char*& p, const unsigned char* end, Fp3& out,
                    bool require_canonical)
{
    uint64_t a = 0, b = 0, c = 0;
    if (!ReadLE64Checked(p, end, a) || !ReadLE64Checked(p, end, b) ||
        !ReadLE64Checked(p, end, c))
        return false;
    // V5 requires a byte-unique wire representation. V3's historical parser
    // semantics are retained by its configured wrapper below.
    if (require_canonical && (a >= kP || b >= kP || c >= kP)) return false;
    out = Fp3{a, b, c};
    return true;
}
/** Deserialize a digest; REJECTS non-canonical limbs (limb ≥ p). */
bool ReadAlgDigestChecked(const unsigned char*& p, const unsigned char* end, Fri3AlgDigest& out)
{
    for (uint32_t k = 0; k < alg_hash::kAlgHashDigestLen; ++k) {
        uint64_t limb = 0;
        if (!ReadLE64Checked(p, end, limb) || limb >= kP) return false;
        out[k] = limb;
    }
    return true;
}

/** Digest equality on canonical limb values. */
bool AlgDigestEq(const Fri3AlgDigest& a, const Fri3AlgDigest& b)
{
    for (uint32_t k = 0; k < alg_hash::kAlgHashDigestLen; ++k) {
        if (Canonical(a[k]) != Canonical(b[k])) return false;
    }
    return true;
}

Fp PowFp(Fp base, uint64_t exp)
{
    Fp result = 1;
    base = Canonical(base);
    while (exp > 0) {
        if (exp & 1u) result = Mul(result, base);
        base = Mul(base, base);
        exp >>= 1;
    }
    return result;
}

/** Primitive n-th root of unity in Goldilocks for n = 2^k, k ≤ 32. */
Fp OmegaForSize(uint32_t n)
{
    // omega_n = kOmega2_32 ^{2^{32} / n}
    uint32_t logn = 0;
    uint32_t t = n;
    while (t > 1) {
        t >>= 1;
        ++logn;
    }
    return PowFp(kOmega2_32, 1ULL << (32 - logn));
}

void BitReverse(std::vector<Fp3>& a)
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

/** In-place radix-2 NTT over Fp3 using base-field roots embedded as (ω, 0, 0). */
void NttFp3(std::vector<Fp3>& a, bool inverse)
{
    const size_t n = a.size();
    if (n <= 1) return;
    BitReverse(a);
    Fp omega_n = OmegaForSize(static_cast<uint32_t>(n));
    if (inverse) omega_n = Inv(omega_n);

    for (size_t len = 2; len <= n; len <<= 1) {
        const Fp w_len = PowFp(omega_n, n / len);
        for (size_t i = 0; i < n; i += len) {
            Fp w = 1;
            for (size_t j = 0; j < len / 2; ++j) {
                const Fp3 u = a[i + j];
                const Fp3 v = Mul(a[i + j + len / 2], Fp3::FromFp(w));
                a[i + j] = Add(u, v);
                a[i + j + len / 2] = Sub(u, v);
                w = Mul(w, w_len);
            }
        }
    }
    if (inverse) {
        const Fp inv_n = Inv(static_cast<Fp>(n));
        const Fp3 inv = Fp3::FromFp(inv_n);
        for (auto& x : a) x = Mul(x, inv);
    }
}

/** LDE: coeffs (deg < n) → evaluations on size-(blowup*n) subgroup. */
std::vector<Fp3> LdeFromCoeffs(const std::vector<Fp3>& coeffs, uint32_t blowup)
{
    const uint32_t n = static_cast<uint32_t>(coeffs.size());
    const uint32_t N = n * blowup;
    std::vector<Fp3> padded(N, Fp3::Zero());
    for (size_t i = 0; i < coeffs.size(); ++i) padded[i] = coeffs[i];
    NttFp3(padded, /*inverse=*/false);
    return padded;
}

// ===========================================================================
// STREAMING COLUMN-BLOCK COMMIT (bounded prover residency)
//
// The dense prover materializes the WHOLE low-degree extension, W x n_lde Fp3.
// At the MEASURED arity-4 real-role parent shape (W = 384,984 columns,
// n_rows = 256 => n_lde = 4096) that single array is
//   384984 * 4096 * 24 B ~= 35 GiB,
// which OOM-kills the prover well before any soundness parameter is stressed.
// Width is NOT the problem here: the column cap is 2^20 and query-proximity
// soundness is W-independent. Only the FOOTPRINT is.
//
// The streaming form walks the column set in blocks of K, materializes only
// those K column LDEs, and absorbs the block into the resident per-row sponge
// state (StreamingRowHasher). Peak residency becomes O(K * n_lde) instead of
// O(W * n_lde) — 6 MiB at K=64/n_lde=4096 instead of 35 GiB.
//
// BIT-IDENTICAL BY CONSTRUCTION, not by luck:
//   * Column absorption order is unchanged. Block b covers columns
//     [b*K, (b+1)*K); within a block the columns are absorbed in ascending
//     index order; within a column the lanes are c0, c1, c2. That is exactly
//     the sequence the monolithic LeafHashRow absorbs.
//   * Each column LDE is an independent transform of that column's own
//     coefficients, so blocking cannot perturb a value.
//   * The Merkle tree is built from the same leaf digests in the same order.
// Consequently the row root, every opening, and the serialized proof bytes are
// byte-for-byte equal to the dense path. (Cross-checked against the dense
// prover in the alg unit tests and, independently, against a CUDA streaming
// implementation of the same absorb order on real prove data.)
// ===========================================================================

/** Peak column-LDE staging budget for the streaming commit, in bytes.
 *  K is reduced below the nominal block size whenever K * n_lde * 24 would
 *  exceed this, so a large LDE domain cannot reintroduce a huge allocation. */
inline uint64_t Fri3AlgStreamBlockByteBudget()
{
    static const uint64_t b = [] {
        if (const char* e = std::getenv("BTX_FRI_STREAM_BYTES")) {
            const long long v = std::atoll(e);
            if (v > 0) return static_cast<uint64_t>(v);
        }
        return kRCFri3AlgStreamBlockByteBudget;
    }();
    return b;
}

/** Nominal columns-per-block K (env-tunable; never changes proof bytes). */
inline uint32_t Fri3AlgStreamColumnBlockNominal()
{
    static const uint32_t k = [] {
        if (const char* e = std::getenv("BTX_FRI_STREAM_COLS")) {
            const long v = std::atol(e);
            if (v > 0 && v <= 65536) {
                return static_cast<uint32_t>(v);
            }
        }
        return kRCFri3AlgStreamColumnBlock;
    }();
    return k;
}

/** Effective K for an LDE domain of n_lde rows: at least 1, at most the
 *  nominal K, and small enough to respect the staging byte budget. */
inline uint32_t Fri3AlgStreamColumnBlockFor(uint32_t n_lde)
{
    const uint32_t nominal = Fri3AlgStreamColumnBlockNominal();
    if (n_lde == 0) return nominal;
    const uint64_t per_column =
        static_cast<uint64_t>(n_lde) * sizeof(Fp3);
    const uint64_t allowed =
        Fri3AlgStreamBlockByteBudget() / std::max<uint64_t>(per_column, 1);
    if (allowed <= 1) return 1;
    return static_cast<uint32_t>(
        std::min<uint64_t>(nominal, allowed));
}

/**
 * Materialize the LDEs of columns [c0, c0 + kc) into block[0..kc).
 *
 * `block` is reused across iterations, so the caller's peak staging cost is
 * kc * n_lde * sizeof(Fp3) regardless of W. The per-column transforms are
 * independent and write distinct block entries, so the OpenMP schedule cannot
 * change a single output limb — identical to the dense per-column LDE loop.
 */
void BuildColumnLdeBlock(
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t c0, uint32_t kc, uint32_t n_coeffs,
    std::vector<std::vector<Fp3>>& block)
{
    if (block.size() < kc) block.resize(kc);
    const int64_t count = static_cast<int64_t>(kc);
#if defined(_OPENMP)
#pragma omp parallel for schedule(static) num_threads(BtxProveThreads())
#endif
    for (int64_t t = 0; t < count; ++t) {
        const std::vector<Fp3>& src =
            columns[c0 + static_cast<uint32_t>(t)];
        std::vector<Fp3> padded(n_coeffs, Fp3::Zero());
        std::copy(src.begin(), src.end(), padded.begin());
        block[static_cast<size_t>(t)] =
            LdeFromCoeffs(padded, kRCFriBlowup);
    }
}

/** Field-native Merkle tree; public only as a prover-local checked cache. */
using AlgMerkleTree = Fri3AlgRowTreeCache;

Fri3AlgDigest AlgHashCompressForLane(const Fri3AlgDigest& left,
                                    const Fri3AlgDigest& right,
                                    int32_t lane)
{
    if (lane < 0) return alg_hash::Compress(left, right);
    alg_hash::State state{};
    for (uint32_t i = 0; i < alg_hash::kAlgHashDigestLen; ++i) {
        state[i] = Canonical(left[i]);
        state[alg_hash::kAlgHashDigestLen + i] =
            Canonical(right[i]);
    }
    state[8] = alg_hash::GetAlgHashConstants().node_domain;
    state[9] = gkr_field::FromU64(static_cast<uint64_t>(lane) + 1);
    alg_hash::Permute(state);
    return {state[0], state[1], state[2], state[3]};
}

Fri3AlgDigest AlgHashLeafForLane(const Fp3& value, uint32_t index,
                                int32_t lane)
{
    if (lane < 0) return alg_hash::LeafHash(value, index);
    alg_hash::State state{};
    state[0] = Canonical(value.c0);
    state[1] = Canonical(value.c1);
    state[2] = Canonical(value.c2);
    state[3] = gkr_field::FromU64(index);
    state[4] = alg_hash::GetAlgHashConstants().leaf_domain;
    state[5] = gkr_field::FromU64(static_cast<uint64_t>(lane) + 1);
    alg_hash::Permute(state);
    return {state[0], state[1], state[2], state[3]};
}

Fri3AlgDigest AlgHashRowLeafForLane(const std::vector<Fp3>& row,
                                   uint32_t index, int32_t lane)
{
    if (lane < 0) return alg_hash::LeafHashRow(row, index);
    std::vector<Fp> values;
    values.reserve(3 * row.size() + 4);
    values.push_back(alg_hash::GetAlgHashConstants().leaf_domain);
    values.push_back(gkr_field::FromU64(0x524f57)); // "ROW"
    values.push_back(gkr_field::FromU64(static_cast<uint64_t>(lane) + 1));
    for (const Fp3& value : row) {
        values.push_back(Canonical(value.c0));
        values.push_back(Canonical(value.c1));
        values.push_back(Canonical(value.c2));
    }
    values.push_back(gkr_field::FromU64(index));
    return alg_hash::SpongeHashFp(values);
}

/** Build from precomputed leaf digests (row tree: LeafHashRow; fold layers:
 *  LeafHash). Odd-pad by duplicating the last node — same shape as the SHA
 *  BuildMerkleTree, though LDE sizes here are always powers of two. */
AlgMerkleTree BuildAlgMerkleTreeFromLeaves(
    std::vector<Fri3AlgDigest> leaves, int32_t lane = -1)
{
    AlgMerkleTree t;
    if (leaves.empty()) return t; // root = all-zero digest (callers reject empty)
    t.levels.push_back(std::move(leaves));
    std::vector<Fri3AlgDigest> level = t.levels[0];
    while (level.size() > 1) {
        if (level.size() % 2 == 1) level.push_back(level.back());
        const size_t half = level.size() / 2;
        // Per-level Merkle compress: each parent next[i] is an independent
        // 2->1 hash of a distinct pair. Indexed writes → byte-identical.
        std::vector<Fri3AlgDigest> next(half);
        const int64_t nh = static_cast<int64_t>(half);
#if defined(_OPENMP)
#pragma omp parallel for schedule(static) num_threads(BtxProveThreads())
#endif
        for (int64_t i = 0; i < nh; ++i) {
            next[i] = AlgHashCompressForLane(
                level[2 * i], level[2 * i + 1], lane);
        }
        t.levels.push_back(next);
        level = std::move(next);
    }
    t.root = t.levels.back()[0];
    return t;
}

/** Fold-layer tree: leaf i = alg_hash::LeafHash(evals[i], i). */
AlgMerkleTree BuildAlgMerkleTree(const std::vector<Fp3>& evals,
                                 int32_t lane = -1)
{
    std::vector<Fri3AlgDigest> leaves(evals.size());
    for (size_t i = 0; i < evals.size(); ++i) {
        leaves[i] = AlgHashLeafForLane(
            evals[i], static_cast<uint32_t>(i), lane);
    }
    return BuildAlgMerkleTreeFromLeaves(std::move(leaves), lane);
}

std::vector<Fri3AlgDigest> PathFromAlgTree(const AlgMerkleTree& tree, uint32_t index)
{
    std::vector<Fri3AlgDigest> siblings;
    if (tree.levels.empty()) return siblings;
    uint32_t idx = index;
    for (size_t li = 0; li + 1 < tree.levels.size(); ++li) {
        auto level = tree.levels[li];
        // Match BuildAlgMerkleTreeFromLeaves's odd-pad (pad is only in the
        // next-level build; reconstruct padded width for sibling lookup).
        if (level.size() % 2 == 1) level.push_back(level.back());
        const uint32_t sib = idx ^ 1u;
        siblings.push_back(level[sib]);
        idx >>= 1;
    }
    return siblings;
}

/**
 * Commit-then-challenge FS state — SHA256d transcript, UNCHANGED from the
 * SHA batch path except for the domain tag (spec §2.2: FS is not
 * arithmetized; only the Merkle commitment is field-native). Field-native
 * roots enter the byte transcript through the canonical LE-limb packing.
 */
struct Fri3AlgFs {
    std::vector<unsigned char> buf;
    CSHA256 prefix_sha256;
    size_t prefix_bytes{0};

    Fri3AlgFs(const uint256& fs_seed, uint64_t pow_grind_nonce, uint32_t blowup,
              uint32_t n_coeffs, const char* domain_tag)
    {
        const size_t domain_len = std::strlen(domain_tag);
        AppendBytes(buf, reinterpret_cast<const unsigned char*>(domain_tag), domain_len);
        AppendBytes(buf, fs_seed.data(), 32);
        AppendLE64(buf, pow_grind_nonce);
        AppendLE32(buf, blowup);
        AppendLE32(buf, n_coeffs);
    }

    void AbsorbAlgRoot(const Fri3AlgDigest& root)
    {
        const uint256 packed = Fri3AlgDigestToUint256(root);
        AppendBytes(buf, packed.data(), 32);
    }
    void AbsorbFp3(const Fp3& v) { AppendFp3(buf, v); }

    uint256 ChallengeDigest(
        const unsigned char* suffix, size_t suffix_len)
    {
        // Preserve both the SHA chaining words and partial-block buffer.  The
        // resulting digest is byte-identical to SHA256d(buf || suffix), while
        // the immutable prefix compression work is paid only once.
        if (prefix_bytes < buf.size()) {
            prefix_sha256.Write(
                buf.data() + prefix_bytes,
                buf.size() - prefix_bytes);
            prefix_bytes = buf.size();
        }
        CSHA256 first = prefix_sha256;
        first.Write(suffix, suffix_len);
        uint256 digest;
        first.Finalize(digest.begin());
        CSHA256()
            .Write(digest.begin(), digest.size())
            .Finalize(digest.begin());
        return digest;
    }

    Fp3 ChallengeFp3(const char* label, uint32_t idx)
    {
        std::vector<unsigned char> suffix;
        const size_t n = std::strlen(label);
        suffix.insert(
            suffix.end(),
            reinterpret_cast<const unsigned char*>(label),
            reinterpret_cast<const unsigned char*>(label) + n);
        AppendLE32(suffix, idx);
        // 24 of the 32 SHA256d bytes feed the Fp3 draw (~2^192 challenge space).
        const uint256 digest =
            ChallengeDigest(suffix.data(), suffix.size());
        return FromChallengeBytes3(digest.data());
    }

    bool ChallengeFp3Uniform(
        const char* draw_domain_tag,
        const char* label, uint32_t idx, Fp3& out)
    {
        // Fixed two-hash schedule: eight independent u64 words, then select
        // the first three canonical words (<p). Conditioned on success, the
        // selected limbs are independent uniform Fp elements. Failure needs
        // at least six rejected words.  Its exact probability is the
        // binomial tail sum_{j=6}^8 C(8,j) r^j (1-r)^(8-j), where
        // r=(2^32-1)/2^64; the global ledger charges this full tail.
        std::array<uint64_t, kRCFri3AlgDualUniformWords> words{};
        for (uint32_t block = 0; block < kRCFri3AlgDualUniformHashBlocks; ++block) {
            std::vector<unsigned char> suffix;
            AppendBytes(
                suffix,
                reinterpret_cast<const unsigned char*>(
                    draw_domain_tag),
                std::strlen(draw_domain_tag));
            const size_t n = std::strlen(label);
            suffix.insert(
                suffix.end(),
                reinterpret_cast<const unsigned char*>(label),
                reinterpret_cast<const unsigned char*>(label) + n);
            AppendLE32(suffix, idx);
            AppendLE32(suffix, block);
            const uint256 digest =
                ChallengeDigest(suffix.data(), suffix.size());
            for (uint32_t word = 0; word < 4; ++word) {
                uint64_t value = 0;
                for (uint32_t byte = 0; byte < 8; ++byte) {
                    value |= static_cast<uint64_t>(digest.data()[8 * word + byte])
                             << (8 * byte);
                }
                words[4 * block + word] = value;
            }
        }
        auto selected = Fri3AlgSelectUniformFp3Words(words);
        if (!selected.has_value()) return false;
        out = *selected;
        return true;
    }

    bool ChallengeIndexUniform(
        const char* draw_domain_tag,
        const char* label, uint32_t idx,
        uint32_t modulus, uint32_t& out)
    {
        if (modulus == 0 || (modulus & (modulus - 1)) != 0) return false;
        std::vector<unsigned char> suffix;
        AppendBytes(
            suffix,
            reinterpret_cast<const unsigned char*>(
                draw_domain_tag),
            std::strlen(draw_domain_tag));
        const size_t n = std::strlen(label);
        suffix.insert(
            suffix.end(),
            reinterpret_cast<const unsigned char*>(label),
            reinterpret_cast<const unsigned char*>(label) + n);
        AppendLE32(suffix, idx);
        const uint256 digest =
            ChallengeDigest(suffix.data(), suffix.size());
        uint32_t raw = 0;
        for (uint32_t byte = 0; byte < 4; ++byte) {
            raw |= static_cast<uint32_t>(digest.data()[byte]) << (8 * byte);
        }
        // A mask is exactly uniform for a power-of-two modulus.
        out = raw & (modulus - 1);
        return true;
    }
};

struct Fri3AlgProtocolConfig {
    uint32_t proof_version;
    const char* domain_tag;
    const char* uniform_draw_domain_tag;
    const char* index_draw_domain_tag;
    uint32_t query_count;
    // Zero preserves the V3 baseline's deterministic unbounded rejection
    // sampler. V5 dual lanes use a fixed nonzero attempt bound so recursive
    // replay has a statically bounded schedule.
    uint32_t ood_candidates;
    bool uniform_challenges;
    // false: legacy one-power batching [1,lambda,...].
    // true: one independently sampled uniform Fp3 coefficient per column.
    bool independent_batching_coefficients;
    // -1 is the legacy unprefixed AlgHash; V5 lanes use 0/1 in every
    // row/fold leaf and internal node input.
    int32_t alg_hash_lane;
    bool require_q192_proximity_guard;
    // PR-89 g4 TRANSCRIPT HALF. false: the shipped byte layout, in which the
    // W column lengths and both full OOD evaluation vectors are absorbed
    // VERBATIM, so every challenge preimage is >= 52*W bytes. true: absorb a
    // domain-tagged Poseidon2 commitment over exactly the same data instead,
    // making every challenge preimage O(log n) and W-INDEPENDENT.
    //
    // This member is declared AFTER require_q192_proximity_guard and carries a
    // default member initializer on purpose: every existing constexpr config
    // above initializes exactly ten members positionally, so they all keep the
    // shipped `false` without being edited. Adding it earlier would silently
    // re-point their positional initializers.
    bool short_transcript_commitments{false};
    // PR-89 Construction 1 (Pi_JQ): when joint_query is set, the "fra3_query"
    // index draw is REPLACED by the joint squeeze derivation
    //   index_{l,j} = LE32(SHA256d(sigma_Q || "fra3_joint_query" || l || j))
    //                 & (n_lde-1)
    // instead of consuming this lane's post-terminal-fold transcript. The
    // deciding squeeze sigma_Q binds BOTH lanes' terminal transcripts, so a
    // per-lane last-round regrind cannot independently retarget one lane.
    bool joint_query{false};
    const uint256* joint_query_sigma{nullptr};
    uint32_t joint_query_lane{0};
};

constexpr Fri3AlgProtocolConfig kFri3AlgQ192V3Config{
    kRCFri3AlgBatchProofVersion,
    kRCFri3AlgBatchDomainTag,
    kRCFri3AlgDualUniformDrawDomainTag,
    kRCFri3AlgDualIndexDrawDomainTag,
    kRCFri3AlgNumQueries,
    0,
    false,
    // PR-89 blocker #6 (H1): independent-coefficient batching for the single
    // Q192 recursion. Removes the ~14-bit Lemma-5.10 batching loss; the
    // recursion recovers the W independent coeffs via
    // Fri3AlgReplayBatchCoefficients (see air_recurse ExtractChildPublicInputs).
    //
    // Held FALSE. The single-lane replay + air_recurse threading (steps 1-2)
    // are complete and EXECUTABLE: under `true`, air_recurse (20/20),
    // fri_ext3_alg (28/28, 1933 assertions) and soundness_scenarios (12/12) all
    // pass with the independent draw. But recursive_fixedpoint's NormalizedDeep64
    // parent codec (BuildNormalizedDeepSitesV1 / deep64.lambda_*_recurrence AIR /
    // NormalizedDeep64 port witness) still hard-wires geometric lambda_power and
    // feeds only the scalar lambda into its input-table; flipping to `true` adds
    // 7 fold_bus_violations there (step 3 not done — an event-table + AIR
    // rearchitecture). recursive_fixedpoint is additionally red at BASELINE for
    // reasons orthogonal to batching (instruction_count 31!=32 @1180,
    // capability_audit @1482), so the suite cannot gate green in this scope.
    // Leaving `true` would leave the tree more broken than baseline; keep FALSE
    // until step 3 lands. Do NOT claim the ~78.5 union floor as executable
    // without a passing recursive_fixedpoint under the independent draw.
    false,
    -1,
    true,
};

// PR-89 g4 TRANSCRIPT HALF. Identical to kFri3AlgQ192V3Config in EVERY
// soundness-bearing parameter — Q = 192, the same proximity guard, the same
// legacy (non-uniform) draws, the same one-power batching, the same
// unprefixed AlgHash lane — so an A/B between the two isolates the transcript
// layout and nothing else. Only the version, the domain tag and
// short_transcript_commitments differ.
constexpr Fri3AlgProtocolConfig kFri3AlgQ192ShortFsV7Config{
    kRCFri3AlgShortFsLaneProofVersion,
    kRCFri3AlgShortFsDomainTag,
    kRCFri3AlgDualUniformDrawDomainTag,
    kRCFri3AlgDualIndexDrawDomainTag,
    kRCFri3AlgNumQueries,
    0,
    false,
    false,
    -1,
    true,
    true,
};

// PR-89 g4 ACTIVATION.  The ONE selector every Q192 producer and consumer in
// this file reads.  Held as a constexpr object rather than a reference so the
// version/tag/short-transcript members cannot drift apart from
// kRCFri3AlgActiveBatchProofVersion.
constexpr Fri3AlgProtocolConfig kFri3AlgQ192ActiveConfig =
    kRCFri3AlgShortFsActivatedV1 ? kFri3AlgQ192ShortFsV7Config
                                 : kFri3AlgQ192V3Config;
static_assert(kFri3AlgQ192ActiveConfig.proof_version ==
                  kRCFri3AlgActiveBatchProofVersion,
              "the active config and the active version constant must agree");
static_assert(kFri3AlgQ192ActiveConfig.short_transcript_commitments ==
                  kRCFri3AlgActiveShortTranscript,
              "the active config and the active layout flag must agree");
static_assert(kFri3AlgQ192ActiveConfig.query_count == kRCFri3AlgNumQueries,
              "activation must not move Q");
static_assert(kFri3AlgQ192ActiveConfig.require_q192_proximity_guard,
              "activation must not drop the Q192 proximity guard");
static_assert(kFri3AlgQ192ActiveConfig.uniform_challenges ==
                  kFri3AlgQ192V3Config.uniform_challenges &&
                  kFri3AlgQ192ActiveConfig.independent_batching_coefficients ==
                      kFri3AlgQ192V3Config.independent_batching_coefficients &&
                  kFri3AlgQ192ActiveConfig.alg_hash_lane ==
                      kFri3AlgQ192V3Config.alg_hash_lane &&
                  kFri3AlgQ192ActiveConfig.ood_candidates ==
                      kFri3AlgQ192V3Config.ood_candidates,
              "activation moves the TRANSCRIPT LAYOUT and nothing else: every "
              "other soundness-bearing parameter must equal the V3 lane's");

constexpr Fri3AlgProtocolConfig kFri3AlgDualLane0Config{
    kRCFri3AlgDualLaneProofVersion,
    kRCFri3AlgDualLane0DomainTag,
    kRCFri3AlgDualUniformDrawDomainTag,
    kRCFri3AlgDualIndexDrawDomainTag,
    kRCFri3AlgDualQueriesPerLane,
    kRCFri3AlgDualOodCandidates,
    true,
    true,
    0,
    false,
};

constexpr Fri3AlgProtocolConfig kFri3AlgDualLane1Config{
    kRCFri3AlgDualLaneProofVersion,
    kRCFri3AlgDualLane1DomainTag,
    kRCFri3AlgDualUniformDrawDomainTag,
    kRCFri3AlgDualIndexDrawDomainTag,
    kRCFri3AlgDualQueriesPerLane,
    kRCFri3AlgDualOodCandidates,
    true,
    true,
    1,
    false,
};

constexpr Fri3AlgProtocolConfig
    kFri3AlgDualQ136Lane0Config{
        kRCFri3AlgDualQ136LaneProofVersion,
        kRCFri3AlgDualQ136Lane0DomainTag,
        kRCFri3AlgDualQ136UniformDrawDomainTag,
        kRCFri3AlgDualQ136IndexDrawDomainTag,
        kRCFri3AlgDualQ136QueriesPerLane,
        kRCFri3AlgDualOodCandidates,
        true,
        true,
        0,
        false,
    };

constexpr Fri3AlgProtocolConfig
    kFri3AlgDualQ136Lane1Config{
        kRCFri3AlgDualQ136LaneProofVersion,
        kRCFri3AlgDualQ136Lane1DomainTag,
        kRCFri3AlgDualQ136UniformDrawDomainTag,
        kRCFri3AlgDualQ136IndexDrawDomainTag,
        kRCFri3AlgDualQ136QueriesPerLane,
        kRCFri3AlgDualOodCandidates,
        true,
        true,
        1,
        false,
    };

const Fri3AlgProtocolConfig& DualLaneConfig(uint32_t lane)
{
    return lane == 0 ? kFri3AlgDualLane0Config : kFri3AlgDualLane1Config;
}

struct Fri3AlgDualProtocolSuite {
    uint32_t envelope_magic;
    uint32_t envelope_version;
    uint32_t lane_version;
    uint32_t queries_per_lane;
    const char* envelope_domain_tag;
    const char* lane0_domain_tag;
    const char* lane1_domain_tag;
    const char* master_binding_domain_tag;
    const char* child_binding_domain_tag;
    size_t max_proof_bytes;
    const Fri3AlgProtocolConfig* lane0_config;
    const Fri3AlgProtocolConfig* lane1_config;
    const char* name;
};

constexpr Fri3AlgDualProtocolSuite
    kFri3AlgDualQ128V5Suite{
        kRCFri3AlgDualProofMagic,
        kRCFri3AlgDualProofVersion,
        kRCFri3AlgDualLaneProofVersion,
        kRCFri3AlgDualQueriesPerLane,
        kRCFri3AlgDualDomainTag,
        kRCFri3AlgDualLane0DomainTag,
        kRCFri3AlgDualLane1DomainTag,
        kRCFri3AlgDualMasterBindingDomainTag,
        kRCFri3AlgDualChildBindingDomainTag,
        kRCFri3AlgDualMaxProofBytesHard,
        &kFri3AlgDualLane0Config,
        &kFri3AlgDualLane1Config,
        "V5 dual-Q128",
    };

constexpr Fri3AlgDualProtocolSuite
    kFri3AlgDualQ136V6Suite{
        kRCFri3AlgDualQ136ProofMagic,
        kRCFri3AlgDualQ136ProofVersion,
        kRCFri3AlgDualQ136LaneProofVersion,
        kRCFri3AlgDualQ136QueriesPerLane,
        kRCFri3AlgDualQ136DomainTag,
        kRCFri3AlgDualQ136Lane0DomainTag,
        kRCFri3AlgDualQ136Lane1DomainTag,
        kRCFri3AlgDualQ136MasterBindingDomainTag,
        kRCFri3AlgDualQ136ChildBindingDomainTag,
        kRCFri3AlgDualQ136MaxProofBytesHard,
        &kFri3AlgDualQ136Lane0Config,
        &kFri3AlgDualQ136Lane1Config,
        "V6 dual-Q136",
    };

const Fri3AlgProtocolConfig& DualLaneConfig(
    uint32_t lane,
    const Fri3AlgDualProtocolSuite& suite)
{
    return lane == 0
        ? *suite.lane0_config
        : *suite.lane1_config;
}

bool KnownDualCommitmentScenario(
    Fri3AlgDualCommitmentScenario scenario)
{
    return scenario ==
               Fri3AlgDualCommitmentScenario::
                   FullyDuplicatedLaneCommitments ||
           scenario ==
               Fri3AlgDualCommitmentScenario::
                   SharedMasterDerivedChildren;
}

Fri3AlgProtocolConfig DualLaneConfigForScenario(
    uint32_t lane, Fri3AlgDualCommitmentScenario scenario,
    const Fri3AlgDualProtocolSuite& suite =
        kFri3AlgDualQ128V5Suite)
{
    Fri3AlgProtocolConfig config =
        DualLaneConfig(lane, suite);
    if (scenario ==
        Fri3AlgDualCommitmentScenario::SharedMasterDerivedChildren) {
        config.alg_hash_lane = -1;
    }
    return config;
}

bool ProtocolChallengeFp3(Fri3AlgFs& fs, const Fri3AlgProtocolConfig& config,
                          const char* label, uint32_t idx, Fp3& out)
{
    if (config.uniform_challenges) {
        return fs.ChallengeFp3Uniform(
            config.uniform_draw_domain_tag,
            label, idx, out);
    }
    out = fs.ChallengeFp3(label, idx);
    return true;
}

// PR-89 Construction 1 (Pi_JQ): derive one joint query index from the deciding
// squeeze sigma_Q. n_lde MUST be a power of two so the mask is exact/unbiased.
uint32_t Fri3AlgJointQIndexInternal(const uint256& sigma_q, uint32_t lane,
                                    uint32_t j, uint32_t n_lde)
{
    std::vector<unsigned char> buf;
    AppendBytes(buf, sigma_q.data(), 32);
    static constexpr char kTag[] = "fra3_joint_query";
    AppendBytes(buf, reinterpret_cast<const unsigned char*>(kTag),
                sizeof(kTag) - 1);
    AppendLE32(buf, lane);
    AppendLE32(buf, j);
    const uint256 d = Sha256dBytes(buf.data(), buf.size());
    uint32_t le32 = 0;
    for (uint32_t b = 0; b < 4; ++b)
        le32 |= static_cast<uint32_t>(d.data()[b]) << (8 * b);
    return le32 & (n_lde - 1);
}

bool ProtocolChallengeIndex(Fri3AlgFs& fs, const Fri3AlgProtocolConfig& config,
                            const char* label, uint32_t idx, uint32_t modulus,
                            uint32_t& out)
{
    if (config.joint_query && config.joint_query_sigma != nullptr &&
        modulus != 0 && (modulus & (modulus - 1)) == 0) {
        // Terminal-round joint squeeze REPLACES the per-lane index draw. The
        // lane transcript is intentionally NOT consumed here: the deciding
        // squeeze already bound both lanes' terminal states.
        out = Fri3AlgJointQIndexInternal(
            *config.joint_query_sigma, config.joint_query_lane, idx, modulus);
        return true;
    }
    if (config.uniform_challenges)
        return fs.ChallengeIndexUniform(
            config.index_draw_domain_tag,
            label, idx, modulus, out);
    if (modulus == 0) return false;
    const Fp3 ch = fs.ChallengeFp3(label, idx);
    // V3 baseline behavior, deliberately preserved.
    const unsigned __int128 wide =
        (static_cast<unsigned __int128>(Canonical(ch.c1)) << 64) |
        Canonical(ch.c0);
    out = static_cast<uint32_t>(wide % modulus);
    return true;
}

bool ProtocolBatchCoefficients(Fri3AlgFs& fs,
                               const Fri3AlgProtocolConfig& config,
                               uint32_t width,
                               std::vector<Fp3>& coefficients,
                               Fp3& encoded_first_or_lambda)
{
    if (width == 0 || width > kRCFri3AlgBatchMaxColumns) return false;
    coefficients.resize(width);
    if (config.independent_batching_coefficients) {
        // Draw every coordinate from the same pre-batching transcript state
        // under a distinct index, then absorb the complete vector. This is
        // independent-coordinate batching, not the legacy
        // [1,lambda,...,lambda^(W-1)] construction.
        for (uint32_t i = 0; i < width; ++i) {
            if (!ProtocolChallengeFp3(
                    fs, config, "fra3_batch_coeff", i, coefficients[i])) {
                return false;
            }
        }
        for (const Fp3& coefficient : coefficients) {
            fs.AbsorbFp3(coefficient);
        }
        encoded_first_or_lambda = coefficients[0];
        return true;
    }

    Fp3 lambda{};
    if (!ProtocolChallengeFp3(fs, config, "fra3_lambda", 0, lambda)) {
        return false;
    }
    fs.AbsorbFp3(lambda);
    encoded_first_or_lambda = lambda;
    coefficients[0] = Fp3::One();
    for (uint32_t i = 1; i < width; ++i) {
        coefficients[i] = Mul(coefficients[i - 1], lambda);
    }
    return true;
}

/** log2(n) for n = 2^k ≥ 1. */
uint32_t Fri3AlgLog2Exact(uint32_t n)
{
    uint32_t log = 0;
    while (n > 1) {
        n >>= 1;
        ++log;
    }
    return log;
}

Fp3 DomainPoint(uint32_t n0, uint32_t index)
{
    return Fp3::FromFp(PowFp(OmegaForSize(n0), index));
}

/** Extension part (c1, c2) nonzero? Guarantees z off the base-field line. */
bool Fri3AlgHasExtCoord(const Fp3& z)
{
    return Canonical(z.c1) != 0 || Canonical(z.c2) != 0;
}

/** z ∈ D (size-n_lde LDE subgroup on the c1=c2=0 base-field line)? */
bool Fri3AlgPointInDomain(const Fp3& z, uint32_t n_lde)
{
    if (Fri3AlgHasExtCoord(z)) return false;
    return Canonical(PowFp(z.c0, n_lde)) == 1;
}

/**
 * v5 half-domain fold: pair i with i+N/2.
 *   even = (f(x)+f(-x))/2, odd = (f(x)-f(-x))/(2x), next = even + β·odd
 * Returns false if x=0 (fail closed; should not occur on subgroup points).
 */
bool HalfDomainFoldLayer(const std::vector<Fp3>& cur, const Fp3& beta, std::vector<Fp3>& next)
{
    const uint32_t N = static_cast<uint32_t>(cur.size());
    if (N < 2 || (N % 2) != 0) return false;
    const uint32_t half = N / 2;
    next.resize(half);
    const Fp3 inv2 = Inv(Fp3::FromFp(2));
    for (uint32_t i = 0; i < half; ++i) {
        const Fp3 f_x = cur[i];
        const Fp3 f_neg = cur[i + half];
        const Fp3 x = DomainPoint(N, i);
        if (gkr_field::IsZero(x)) return false;
        const Fp3 even = Mul(Add(f_x, f_neg), inv2);
        const Fp3 odd = Mul(Sub(f_x, f_neg), Mul(inv2, Inv(x)));
        next[i] = Add(even, Mul(beta, odd));
    }
    return true;
}

/** Algebraic fold of one opened pair (same formula as HalfDomainFoldLayer). */
bool HalfDomainFoldPair(const Fp3& f_x, const Fp3& f_neg, const Fp3& x, const Fp3& beta,
                        Fp3& out_folded)
{
    if (gkr_field::IsZero(x)) return false;
    const Fp3 inv2 = Inv(Fp3::FromFp(2));
    const Fp3 even = Mul(Add(f_x, f_neg), inv2);
    const Fp3 odd = Mul(Sub(f_x, f_neg), Mul(inv2, Inv(x)));
    out_folded = Add(even, Mul(beta, odd));
    return true;
}

/** Merkle root of blowup identical constant leaves (terminal v5 layer). */
Fri3AlgDigest AlgMerkleRootConstantLayer(const Fp3& value,
                                         uint32_t n_leaves,
                                         int32_t lane = -1)
{
    std::vector<Fp3> consts(n_leaves, value);
    return BuildAlgMerkleTree(consts, lane).root;
}

Fri3AlgFoldStep OpenFoldStep(const std::vector<Fp3>& evals, const AlgMerkleTree& tree,
                             uint32_t idx)
{
    Fri3AlgFoldStep step;
    const uint32_t n = static_cast<uint32_t>(evals.size());
    const uint32_t half = n / 2;
    const uint32_t i = idx % half;
    step.even_index = i;
    step.odd_index = i + half;
    step.even = evals[i];
    step.odd = evals[i + half];
    step.even_siblings = PathFromAlgTree(tree, i);
    step.odd_siblings = PathFromAlgTree(tree, i + half);
    return step;
}

bool VerifyAlgPathForLane(const Fri3AlgDigest& leaf_digest, uint32_t index,
                          const std::vector<Fri3AlgDigest>& siblings,
                          const Fri3AlgDigest& root, uint32_t n_leaves,
                          int32_t lane)
{
    if (n_leaves == 0 || index >= n_leaves) return false;
    Fri3AlgDigest cur = leaf_digest;
    uint32_t idx = index;
    uint32_t width = n_leaves;
    size_t si = 0;
    while (width > 1) {
        if (width % 2 == 1) ++width;
        if (si >= siblings.size()) return false;
        const Fri3AlgDigest& sib = siblings[si++];
        cur = (idx & 1u) == 0
            ? AlgHashCompressForLane(cur, sib, lane)
            : AlgHashCompressForLane(sib, cur, lane);
        idx >>= 1;
        width /= 2;
    }
    return AlgDigestEq(cur, root) && si == siblings.size();
}

bool VerifyFoldStep(const Fri3AlgFoldStep& step, const Fri3AlgDigest& root,
                    uint32_t n_leaves, const Fp3& beta, uint32_t idx,
                    Fp3& out_folded, std::string* why,
                    int32_t lane = -1)
{
    auto fail = [&](const char* w) {
        if (why) *why = w;
        return false;
    };
    if (n_leaves < 2 || (n_leaves % 2) != 0) return fail("fold layer size");
    const uint32_t half = n_leaves / 2;
    const uint32_t i = idx % half;
    if (step.even_index != i) return fail("fold even_index");
    if (step.odd_index != i + half) return fail("fold odd_index");
    if (step.odd_index >= n_leaves) return fail("fold pair OOB");

    if (!VerifyAlgPathForLane(
            AlgHashLeafForLane(step.even, i, lane), i,
            step.even_siblings, root, n_leaves, lane)) {
        return fail("fold even merkle");
    }
    if (!VerifyAlgPathForLane(
            AlgHashLeafForLane(step.odd, step.odd_index, lane),
            step.odd_index, step.odd_siblings, root, n_leaves, lane)) {
        return fail("fold odd merkle");
    }

    const Fp3 x = DomainPoint(n_leaves, i);
    if (!HalfDomainFoldPair(step.even, step.odd, x, beta, out_folded)) {
        return fail("fold x=0");
    }
    return true;
}

Fp3 PowFp3(Fp3 base, uint64_t exp)
{
    Fp3 result = Fp3::One();
    while (exp > 0) {
        if (exp & 1u) result = Mul(result, base);
        base = Mul(base, base);
        exp >>= 1;
    }
    return result;
}

Fp3 EvalPolyCoeffs(const std::vector<Fp3>& coeffs, const Fp3& z)
{
    Fp3 acc = Fp3::Zero();
    for (size_t i = coeffs.size(); i-- > 0;) {
        acc = Add(Mul(acc, z), coeffs[i]);
    }
    return acc;
}

/** Quotient coeffs of (P(X) − v) / (X − z). Requires P(z)=v. */
std::vector<Fp3> SyntheticQuotient(const std::vector<Fp3>& coeffs, const Fp3& z, const Fp3& v)
{
    if (coeffs.size() <= 1) return {};
    std::vector<Fp3> num = coeffs;
    num[0] = Sub(num[0], v);
    const size_t n = num.size();
    std::vector<Fp3> q(n - 1, Fp3::Zero());
    q[n - 2] = num[n - 1];
    for (size_t k = n - 1; k-- > 1;) {
        q[k - 1] = Add(num[k], Mul(z, q[k]));
    }
    return q;
}

/** Row leaf digests over the common LDE domain: leaf i = LeafHashRow of ALL
 *  W column values at row i, in column order (spec §2.3). */
std::vector<Fri3AlgDigest> RowLeafDigestsCpu(const std::vector<std::vector<Fp3>>& column_lde,
                                             uint32_t n_lde,
                                             int32_t lane)
{
    const uint32_t W = static_cast<uint32_t>(column_lde.size());
    std::vector<Fri3AlgDigest> leaves(n_lde);
    // LEAF-COMMIT: per-leaf Poseidon2 row hash, independent over the n_lde
    // leaves. leaves[i] is a distinct write; the W-wide row scratch is
    // allocated once per thread (not per leaf) to stay allocation-free.
#if defined(_OPENMP)
#pragma omp parallel num_threads(BtxProveThreads())
#endif
    {
        std::vector<Fp3> row(W);
#if defined(_OPENMP)
#pragma omp for schedule(static)
#endif
        for (uint32_t i = 0; i < n_lde; ++i) {
            for (uint32_t c = 0; c < W; ++c) row[c] = column_lde[c][i];
            leaves[i] = AlgHashRowLeafForLane(row, i, lane);
        }
    }
    return leaves;
}

// ---------------------------------------------------------------------------
// PR-89 GPU splice #1: CUDA row-leaf sponge (BTX_GPU_ROWLEAF=1).
//
// Policy (no silent fallback):
//  * env unset            -> CPU path, byte-identical to before this splice.
//  * BTX_GPU_ROWLEAF=1    -> eligible calls (untagged lane, B256 binding) run
//                            on the GPU; ANY GPU failure aborts the process.
//                            Ineligible calls fall through to CPU with a
//                            mandatory stderr notice (never silent).
//  * BTX_GPU_ROWLEAF_AUDIT=1 (with =1 above) -> every GPU call ALSO runs the
//                            CPU reference on the SAME real in-prove data and
//                            aborts on the first digest mismatch. This is the
//                            real-structured-data parity gate demanded by the
//                            lazy-vs-canonical false-positive lesson.
enum class RowLeafGpuMode { kOff,
                            kOn,
                            kAudit };

RowLeafGpuMode RowLeafGpuModeActive()
{
    static const RowLeafGpuMode mode = [] {
        const char* env = std::getenv("BTX_GPU_ROWLEAF");
        if (env == nullptr || env[0] == '\0' || std::strcmp(env, "0") == 0) {
            return RowLeafGpuMode::kOff;
        }
        if (std::getenv("BTX_GPU_ROWLEAF_AUDIT") != nullptr) {
            return RowLeafGpuMode::kAudit;
        }
        return RowLeafGpuMode::kOn;
    }();
    return mode;
}

bool RowLeafDigestsGpu(const std::vector<std::vector<Fp3>>& column_lde,
                       uint32_t n_lde,
                       std::vector<Fri3AlgDigest>& out,
                       std::string& why)
{
    const uint32_t W = static_cast<uint32_t>(column_lde.size());
    if (W == 0 || n_lde == 0) {
        why = "empty input";
        return false;
    }
    if (BtxGpuRowLeafAvailable() == 0) {
        why = "no CUDA device (or non-CUDA build)";
        return false;
    }
    static std::once_flag consts_once;
    static int consts_rc = -1;
    std::call_once(consts_once, [] {
        const auto& c = alg_hash::GetAlgHashConstants();
        // std::array storage is contiguous: rc_ext flattens to [8][12] u64.
        consts_rc = BtxGpuRowLeafSetConstants(
            c.rc_ext.front().data(), c.rc_int.data(), c.mu.data());
    });
    if (consts_rc != 0) {
        why = "constant upload failed";
        return false;
    }
    void* ctx = nullptr;
    if (BtxGpuRowLeafBegin(n_lde, &ctx) != 0) {
        why = "Begin failed";
        return false;
    }
    // Stream K-column, lane-major blocks: blk[(3*lc+t)*n_lde + i] =
    // column_lde[c0+lc][i] limb t. Host staging is capped near 100 MiB.
    uint32_t cols_per_block = static_cast<uint32_t>(
        std::max<uint64_t>(1, (uint64_t{1} << 22) / n_lde));
    if (cols_per_block > W) cols_per_block = W;
    std::vector<uint64_t> blk(
        static_cast<size_t>(3) * cols_per_block * n_lde);
    for (uint32_t c0 = 0; c0 < W; c0 += cols_per_block) {
        const uint32_t kc = std::min(cols_per_block, W - c0);
        const int64_t kc64 = kc;
#if defined(_OPENMP)
#pragma omp parallel for schedule(static) num_threads(BtxProveThreads())
#endif
        for (int64_t lc = 0; lc < kc64; ++lc) {
            const std::vector<Fp3>& col = column_lde[c0 + lc];
            uint64_t* b0 = blk.data() + static_cast<size_t>(3 * lc) * n_lde;
            uint64_t* b1 = b0 + n_lde;
            uint64_t* b2 = b1 + n_lde;
            for (uint32_t i = 0; i < n_lde; ++i) {
                b0[i] = col[i].c0;
                b1[i] = col[i].c1;
                b2[i] = col[i].c2;
            }
        }
        if (BtxGpuRowLeafAbsorb(ctx, blk.data(), 3 * kc,
                                uint64_t{3} * c0) != 0) {
            BtxGpuRowLeafRelease(ctx);
            why = "Absorb failed";
            return false;
        }
    }
    out.assign(n_lde, Fri3AlgDigest{});
    static_assert(sizeof(Fri3AlgDigest) == 4 * sizeof(uint64_t),
                  "Fri3AlgDigest must be 4 contiguous u64 limbs");
    if (BtxGpuRowLeafFinalize(ctx, uint64_t{3} * W,
                              reinterpret_cast<uint64_t*>(out.data())) != 0) {
        why = "Finalize failed";
        return false;
    }
    return true;
}

std::vector<Fri3AlgDigest> RowLeafDigests(const std::vector<std::vector<Fp3>>& column_lde,
                                          uint32_t n_lde,
                                          int32_t lane = -1)
{
    const RowLeafGpuMode gpu_mode = RowLeafGpuModeActive();
    if (gpu_mode == RowLeafGpuMode::kOff) {
        return RowLeafDigestsCpu(column_lde, n_lde, lane);
    }
    if (lane != -1 ||
        alg_hash::ActiveBindingMode() != alg_hash::BindingMode::B256) {
        // Non-silent CPU fallthrough: the GPU sponge implements only the
        // untagged B256 row leaf (the shipped Q192 consensus path).
        std::fprintf(stderr,
                     "[BTX_GPU_ROWLEAF] ineligible call (lane=%d, mode=%s) "
                     "-> CPU reference path\n",
                     static_cast<int>(lane),
                     alg_hash::ActiveBindingMode() ==
                             alg_hash::BindingMode::B256 ?
                         "B256" :
                         "B384");
        return RowLeafDigestsCpu(column_lde, n_lde, lane);
    }
    std::vector<Fri3AlgDigest> gpu_leaves;
    std::string why;
    const auto t0 = std::chrono::steady_clock::now();
    if (!RowLeafDigestsGpu(column_lde, n_lde, gpu_leaves, why)) {
        std::fprintf(stderr,
                     "[BTX_GPU_ROWLEAF] FATAL: GPU row-leaf commit failed "
                     "(%s); BTX_GPU_ROWLEAF forbids a silent CPU fallback\n",
                     why.c_str());
        std::abort();
    }
    const double gpu_ms =
        std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - t0)
            .count();
    std::fprintf(stderr,
                 "[BTX_GPU_ROWLEAF] GPU leaf-commit W=%u n_lde=%u %.1f ms%s\n",
                 static_cast<uint32_t>(column_lde.size()), n_lde, gpu_ms,
                 gpu_mode == RowLeafGpuMode::kAudit ? " (audit)" : "");
    if (gpu_mode == RowLeafGpuMode::kAudit) {
        const std::vector<Fri3AlgDigest> cpu_leaves =
            RowLeafDigestsCpu(column_lde, n_lde, lane);
        size_t mismatches = 0;
        size_t first_bad = 0;
        for (size_t i = 0; i < cpu_leaves.size(); ++i) {
            if (cpu_leaves[i] != gpu_leaves[i]) {
                if (mismatches == 0) first_bad = i;
                ++mismatches;
            }
        }
        if (mismatches != 0 || cpu_leaves.size() != gpu_leaves.size()) {
            std::fprintf(stderr,
                         "[BTX_GPU_ROWLEAF] AUDIT FAIL W=%u n_lde=%u "
                         "mismatches=%zu first_bad=%zu — GPU/CPU digest "
                         "divergence on real prove data\n",
                         static_cast<uint32_t>(column_lde.size()), n_lde,
                         mismatches, first_bad);
            std::abort();
        }
        std::fprintf(stderr,
                     "[BTX_GPU_ROWLEAF] AUDIT PASS W=%u n_lde=%u leaves=%zu "
                     "(bit-identical CPU vs GPU on real prove data)\n",
                     static_cast<uint32_t>(column_lde.size()), n_lde,
                     gpu_leaves.size());
    }
    return gpu_leaves;
}

/** Batch FS preamble: domain-separated from every SHA-path transcript; the
 *  SINGLE row root replaces the per-column root list of the SHA batch. */
Fri3AlgFs Fri3AlgBatchFsInit(const uint256& fs_seed, uint64_t pow_grind_nonce, uint32_t n_coeffs,
                             const Fri3AlgLayerCommit& row_commit,
                             const std::vector<uint32_t>& column_len,
                             const Fri3AlgProtocolConfig& config)
{
    Fri3AlgFs fs(fs_seed, pow_grind_nonce, kRCFriBlowup, n_coeffs, config.domain_tag);
    AppendLE32(fs.buf, config.proof_version);
    AppendLE32(fs.buf, static_cast<uint32_t>(column_len.size()));
    if (config.short_transcript_commitments) {
        // PR-89 g4 TRANSCRIPT HALF, term (i). The 4*W-byte column_len loop is
        // the term that precedes EVERY challenge, including fra3_lambda, the
        // very first one. Replaced by a single 32-byte Poseidon2 commitment
        // over exactly the same data (plus n_coeffs and W, which the loop left
        // implicit). W itself stays in the clear above: it is one word, the
        // verifier needs it before it can even size its vectors, and it is
        // re-bound inside the commitment anyway.
        fs.AbsorbAlgRoot(Fri3AlgShapeCommit(n_coeffs, column_len));
    } else {
        for (const uint32_t len : column_len) AppendLE32(fs.buf, len);
    }
    fs.AbsorbAlgRoot(row_commit.root);
    return fs;
}

/** Dual-OOD sampling: FS challenges rejected until (c1,c2)!=(0,0) (⇒ ∉ D) and
 *  distinct. The rejection counter is deterministic, so prover and verifier agree.
 *  V5 lanes use a bounded number of attempts for finite recursive replay. */
bool Fri3AlgBatchSampleZ(Fri3AlgFs& fs, uint32_t& ctr, const Fp3* distinct_from,
                         const Fri3AlgProtocolConfig& config, Fp3& out)
{
    if (!config.uniform_challenges) {
        // V3 baseline behavior, deliberately preserved.
        while (true) {
            const Fp3 z = fs.ChallengeFp3("fra3_z", ctr++);
            if (!Fri3AlgHasExtCoord(z)) continue;
            if (distinct_from != nullptr && Eq(z, *distinct_from)) continue;
            out = z;
            return true;
        }
    }

    // V5 fixed schedule: materialize both uniformly sampled candidates, then
    // select the first valid OOD point. Both prover and verifier execute the
    // same number of RO calls regardless of which candidate is selected.
    std::array<Fp3, kRCFri3AlgDualOodCandidates> candidate{};
    for (Fp3& z : candidate) {
        if (!ProtocolChallengeFp3(fs, config, "fra3_z", ctr++, z)) return false;
    }
    for (const Fp3& z : candidate) {
        if (!Fri3AlgHasExtCoord(z)) continue;
        if (distinct_from != nullptr && Eq(z, *distinct_from)) continue;
        out = z;
        return true;
    }
    return false;
}

uint256 RowTreeCacheBinding(
    const Fri3AlgDigest& root,
    uint32_t n_coeffs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.empty()) return {};
    static constexpr char CACHE_DOMAIN[] =
        "BTX_RC_FRI3_ALG_ROW_TREE_CACHE_V1";
    // The encoded pre-image is 24 bytes per coefficient over the WHOLE column
    // set — ~2.4 GiB at the real-role parent width, and it used to be built as
    // one contiguous vector (with reallocation doubling on top). Feed the SAME
    // byte sequence to the hash one column at a time instead: the digest is
    // unchanged (SHA256d is defined on the byte stream, not on the buffering),
    // and the staging cost drops to one column.
    CSHA256 inner;
    inner.Write(
        reinterpret_cast<const unsigned char*>(CACHE_DOMAIN),
        sizeof(CACHE_DOMAIN) - 1);
    std::vector<unsigned char> encoded;
    AppendLE32(
        encoded, static_cast<uint32_t>(columns.size()));
    AppendLE32(encoded, n_coeffs);
    AppendAlgDigest(encoded, root);
    inner.Write(encoded.data(), encoded.size());
    for (const auto& column : columns) {
        if (column.empty() ||
            column.size() >
                std::numeric_limits<uint32_t>::max()) {
            return {};
        }
        encoded.clear();
        encoded.reserve(4 + 24 * column.size());
        AppendLE32(
            encoded,
            static_cast<uint32_t>(column.size()));
        for (const Fp3& coefficient : column) {
            AppendFp3(encoded, coefficient);
        }
        inner.Write(encoded.data(), encoded.size());
    }
    // This is a prover-local integrity binding, not a protocol commitment.
    // Pin the canonical coefficient limbs as well as shape/order so a cache
    // cannot be reused with an altered same-shaped coefficient matrix.
    uint8_t d1[CSHA256::OUTPUT_SIZE];
    inner.Finalize(d1);
    uint8_t d2[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(d1, sizeof(d1)).Finalize(d2);
    uint256 out;
    std::memcpy(out.data(), d2, sizeof(d2));
    return out;
}

} // namespace

Fri3AlgStreamingFsAudit
AuditFri3AlgStreamingFs(const uint256& fs_seed)
{
    Fri3AlgStreamingFsAudit out;
    out.legacy_fp3_match = true;
    out.uniform_fp3_match = true;
    out.uniform_index_match = true;

    Fri3AlgLayerCommit row;
    row.root = {1, 2, 3, 4};
    row.n_leaves = 32;
    Fri3AlgFs fs =
        Fri3AlgBatchFsInit(
            fs_seed, 7, 2, row, {2, 1},
            kFri3AlgDualLane0Config);

    const auto legacy_digest =
        [&](const std::vector<unsigned char>& suffix) {
            std::vector<unsigned char> preimage = fs.buf;
            preimage.insert(
                preimage.end(), suffix.begin(), suffix.end());
            return Sha256dBytes(
                preimage.data(), preimage.size());
        };
    const auto plain_suffix =
        [](const char* label, uint32_t index) {
            std::vector<unsigned char> suffix;
            const auto* begin =
                reinterpret_cast<const unsigned char*>(label);
            suffix.insert(
                suffix.end(), begin,
                begin + std::strlen(label));
            AppendLE32(suffix, index);
            return suffix;
        };
    const auto uniform_suffix =
        [](const char* label, uint32_t index,
           uint32_t block) {
            std::vector<unsigned char> suffix;
            AppendBytes(
                suffix,
                reinterpret_cast<const unsigned char*>(
                    kRCFri3AlgDualUniformDrawDomainTag),
                sizeof(kRCFri3AlgDualUniformDrawDomainTag) - 1);
            const auto* begin =
                reinterpret_cast<const unsigned char*>(label);
            suffix.insert(
                suffix.end(), begin,
                begin + std::strlen(label));
            AppendLE32(suffix, index);
            AppendLE32(suffix, block);
            return suffix;
        };

    const std::array<const char*, 6> legacy_labels{
        "fra3_lambda", "fra3_z", "fra3_w",
        "fra3_fold", "fra3_query", "airq_lambda"};
    for (uint32_t index = 0;
         index < legacy_labels.size(); ++index) {
        const auto suffix =
            plain_suffix(legacy_labels[index], index);
        const uint256 optimized =
            fs.ChallengeDigest(
                suffix.data(), suffix.size());
        out.legacy_fp3_match &=
            optimized == legacy_digest(suffix);
        ++out.legacy_fp3_vectors;
        fs.AbsorbFp3(
            Fp3{11 + index, 21 + index, 31 + index});
    }

    const std::array<const char*, 4> uniform_labels{
        "fra3_batch_coeff", "fra3_z",
        "fra3_w", "fra3_fold"};
    for (uint32_t index = 0;
         index < uniform_labels.size(); ++index) {
        for (uint32_t block = 0;
             block < kRCFri3AlgDualUniformHashBlocks;
             ++block) {
            const auto suffix =
                uniform_suffix(
                    uniform_labels[index], index, block);
            const uint256 optimized =
                fs.ChallengeDigest(
                    suffix.data(), suffix.size());
            out.uniform_fp3_match &=
                optimized == legacy_digest(suffix);
            ++out.uniform_fp3_vectors;
        }
        fs.AbsorbFp3(
            Fp3{41 + index, 51 + index, 61 + index});
    }

    {
        std::vector<unsigned char> suffix;
        AppendBytes(
            suffix,
            reinterpret_cast<const unsigned char*>(
                kRCFri3AlgDualIndexDrawDomainTag),
            sizeof(kRCFri3AlgDualIndexDrawDomainTag) - 1);
        constexpr char label[] = "fra3_query";
        AppendBytes(
            suffix,
            reinterpret_cast<const unsigned char*>(label),
            sizeof(label) - 1);
        AppendLE32(suffix, 127);
        const uint256 optimized =
            fs.ChallengeDigest(
                suffix.data(), suffix.size());
        out.uniform_index_match =
            optimized == legacy_digest(suffix);
        ++out.uniform_index_vectors;
    }

    out.all_match =
        out.legacy_fp3_match &&
        out.uniform_fp3_match &&
        out.uniform_index_match;
    out.note =
        out.all_match
            ? "Fri3Alg streaming FS byte-equivalent"
            : "Fri3Alg streaming FS mismatch";
    return out;
}

Fri3AlgStreamingProverPlan
AssessFri3AlgStreamingProverPlan(
    uint32_t batch_columns, uint32_t n_coeffs,
    uint32_t query_openings)
{
    Fri3AlgStreamingProverPlan out;
    out.batch_columns = batch_columns;
    out.n_coeffs = n_coeffs;
    out.query_openings = query_openings;
    out.column_lde_passes = 2;
    if (batch_columns == 0 ||
        batch_columns > kRCFri3AlgBatchMaxColumns ||
        n_coeffs == 0 ||
        (n_coeffs & (n_coeffs - 1)) != 0 ||
        query_openings == 0 ||
        static_cast<uint64_t>(n_coeffs) *
                kRCFriBlowup >
            (uint64_t{1} << kRCFriMaxLdeLog2)) {
        out.note = "streaming prover plan: invalid shape";
        return out;
    }
    out.n_lde = n_coeffs * kRCFriBlowup;
    const auto checked =
        [](unsigned __int128 value) {
            return value >
                           std::numeric_limits<uint64_t>::max()
                       ? std::numeric_limits<uint64_t>::max()
                       : static_cast<uint64_t>(value);
        };
    constexpr uint64_t FP3_BYTES = 3 * sizeof(uint64_t);
    constexpr uint64_t DIGEST_BYTES =
        alg_hash::kAlgHashDigestLen * sizeof(uint64_t);
    out.materialized_column_lde_bytes =
        checked(
            static_cast<unsigned __int128>(batch_columns) *
            out.n_lde * FP3_BYTES);
    out.row_sponge_bytes =
        alg_hash::StreamingRowHasher::
            WorkingSetBytesForRows(out.n_lde);
    out.row_merkle_bytes =
        checked(
            (static_cast<unsigned __int128>(2) *
                 out.n_lde -
             1) *
            DIGEST_BYTES);
    out.one_column_recompute_bytes =
        checked(
            (static_cast<unsigned __int128>(out.n_lde) +
             n_coeffs) *
            FP3_BYTES);
    out.composition_coeff_bytes =
        checked(
            static_cast<unsigned __int128>(n_coeffs) *
            FP3_BYTES);
    out.retained_query_value_bytes =
        checked(
            static_cast<unsigned __int128>(batch_columns) *
            query_openings * FP3_BYTES);
    // Fold one layer at a time; after query indices are known, recompute the
    // layers once to emit paths instead of retaining every layer/tree.
    out.fold_recompute_peak_bytes =
        checked(
            static_cast<unsigned __int128>(out.n_lde) *
                FP3_BYTES +
            (static_cast<unsigned __int128>(2) *
                 out.n_lde -
             1) *
                DIGEST_BYTES +
            out.retained_query_value_bytes);
    const uint64_t pass1_sponge =
        checked(
            static_cast<unsigned __int128>(
                out.row_sponge_bytes) +
            out.one_column_recompute_bytes +
            out.composition_coeff_bytes);
    const uint64_t pass1_tree =
        checked(
            static_cast<unsigned __int128>(
                out.row_merkle_bytes) +
            out.composition_coeff_bytes);
    const uint64_t pass2 =
        checked(
            static_cast<unsigned __int128>(
                out.one_column_recompute_bytes) +
            out.retained_query_value_bytes);
    out.streaming_peak_bytes =
        std::max(
            {pass1_sponge, pass1_tree, pass2,
             out.fold_recompute_peak_bytes});
    if (out.streaming_peak_bytes != 0 &&
        out.materialized_column_lde_bytes !=
            std::numeric_limits<uint64_t>::max()) {
        out.materialization_reduction_ratio =
            static_cast<double>(
                out.materialized_column_lde_bytes) /
            static_cast<double>(out.streaming_peak_bytes);
    }
    out.shape_valid = true;
    out.under_four_gib =
        out.streaming_peak_bytes <=
        (uint64_t{4} << 30);
    out.executable_row_hash_primitive = true;
    // Column-wise NTT/U accumulation, queried-value spill/reload and fold
    // recomputation are not yet composed into Fri3AlgDualBatchCommit.
    out.complete_streaming_prover = false;
    out.note =
        out.under_four_gib
            ? "streaming prover plan: memory target met; composition open"
            : "streaming prover plan: memory target exceeded";
    return out;
}

std::optional<Fp3> Fri3AlgDecodeUniformFp3Candidate(
    const std::array<unsigned char, 24>& candidate)
{
    std::array<uint64_t, 3> limb{};
    for (uint32_t coordinate = 0; coordinate < limb.size(); ++coordinate) {
        for (uint32_t byte = 0; byte < 8; ++byte) {
            limb[coordinate] |=
                static_cast<uint64_t>(candidate[8 * coordinate + byte])
                << (8 * byte);
        }
        if (limb[coordinate] >= kP) return std::nullopt;
    }
    return Fp3{limb[0], limb[1], limb[2]};
}

std::optional<Fp3> Fri3AlgSelectUniformFp3Words(
    const std::array<uint64_t, kRCFri3AlgDualUniformWords>& words)
{
    std::array<Fp, 3> limb{};
    uint32_t accepted = 0;
    for (const uint64_t word : words) {
        if (word < kP && accepted < limb.size()) limb[accepted++] = word;
    }
    if (accepted != limb.size()) return std::nullopt;
    return Fp3{limb[0], limb[1], limb[2]};
}

uint256 Fri3AlgDigestToUint256(const Fri3AlgDigest& d)
{
    uint256 out;
    for (uint32_t k = 0; k < alg_hash::kAlgHashDigestLen; ++k) {
        const uint64_t limb = Canonical(d[k]);
        for (int b = 0; b < 8; ++b) {
            out.data()[8 * k + b] = static_cast<unsigned char>((limb >> (8 * b)) & 0xFF);
        }
    }
    return out;
}

std::optional<Fri3AlgDigest> Fri3AlgDigestFromUint256(const uint256& u)
{
    Fri3AlgDigest d{};
    for (uint32_t k = 0; k < alg_hash::kAlgHashDigestLen; ++k) {
        uint64_t limb = 0;
        for (int b = 0; b < 8; ++b) {
            limb |= static_cast<uint64_t>(u.data()[8 * k + b]) << (8 * b);
        }
        if (limb >= kP) return std::nullopt; // non-canonical encoding rejected
        d[k] = limb;
    }
    return d;
}

bool Fri3AlgVerifyPath(const Fri3AlgDigest& leaf_digest, uint32_t index,
                       const std::vector<Fri3AlgDigest>& siblings, const Fri3AlgDigest& root,
                       uint32_t n_leaves)
{
    return VerifyAlgPathForLane(
        leaf_digest, index, siblings, root, n_leaves, -1);
}

Fri3AlgDigest Fri3AlgBatchRowRoot(const std::vector<std::vector<Fp3>>& columns, uint32_t n_coeffs)
{
    if (columns.empty() || columns.size() > kRCFri3AlgBatchMaxColumns || n_coeffs == 0 ||
        (n_coeffs & (n_coeffs - 1)) != 0 ||
        static_cast<uint64_t>(n_coeffs) * kRCFriBlowup > (uint64_t{1} << kRCFriMaxLdeLog2)) {
        return Fri3AlgDigest{};
    }
    const uint32_t n_lde = n_coeffs * kRCFriBlowup;
    for (size_t i = 0; i < columns.size(); ++i) {
        if (columns[i].empty() || columns[i].size() > n_coeffs) return Fri3AlgDigest{};
    }
    // Byte-based admission (see Fri3AlgCommitFitsMemoryBudget): this DENSE row
    // root materializes the whole W x n_lde extension. Refuse a shape that
    // cannot fit rather than letting the allocator take the process down.
    if (!Fri3AlgCommitFitsMemoryBudget(
            columns.size(), n_lde, /*streaming=*/false, nullptr, nullptr)) {
        return Fri3AlgDigest{};
    }
    // LDE-NTT (trace commitment root): forward coset-LDE per column, independent
    // transforms writing distinct column_lde[i]. This is the DOMINANT node-scale
    // phase (W up to ~16k columns), parallelized over columns. Bit-identical.
    const int64_t ncols = static_cast<int64_t>(columns.size());
    std::vector<std::vector<Fp3>> column_lde(columns.size());
#if defined(_OPENMP)
#pragma omp parallel for schedule(static) num_threads(BtxProveThreads())
#endif
    for (int64_t i = 0; i < ncols; ++i) {
        std::vector<Fp3> padded(n_coeffs, Fp3::Zero());
        for (size_t j = 0; j < columns[i].size(); ++j) padded[j] = columns[i][j];
        column_lde[i] = LdeFromCoeffs(padded, kRCFriBlowup);
    }
    return BuildAlgMerkleTreeFromLeaves(RowLeafDigests(column_lde, n_lde)).root;
}

Fri3AlgDigest Fri3AlgBatchRowRootStreaming(
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t n_coeffs)
{
    if (columns.empty() ||
        columns.size() > kRCFri3AlgBatchMaxColumns ||
        n_coeffs == 0 ||
        (n_coeffs & (n_coeffs - 1)) != 0 ||
        uint64_t{n_coeffs} * kRCFriBlowup >
            (uint64_t{1} << kRCFriMaxLdeLog2)) {
        return {};
    }
    const uint32_t n_lde = n_coeffs * kRCFriBlowup;
    for (const auto& column : columns) {
        if (column.empty() ||
            column.size() > n_coeffs) {
            return {};
        }
    }
    // Column-BLOCK streaming: only K column LDEs are resident at a time.
    // Absorption order (ascending column, then c0/c1/c2) is unchanged, so the
    // root equals Fri3AlgBatchRowRoot's limb for limb.
    alg_hash::StreamingRowHasher row_hasher(n_lde);
    {
        const uint32_t W =
            static_cast<uint32_t>(columns.size());
        const uint32_t K =
            Fri3AlgStreamColumnBlockFor(n_lde);
        std::vector<std::vector<Fp3>> block;
        for (uint32_t c0 = 0; c0 < W; c0 += K) {
            const uint32_t kc = std::min(K, W - c0);
            BuildColumnLdeBlock(
                columns, c0, kc, n_coeffs, block);
            if (!row_hasher.AbsorbColumnBlock(block, kc)) {
                return {};
            }
        }
    }
    std::vector<Fri3AlgDigest> leaves;
    if (!row_hasher.Finalize(leaves)) return {};
    return BuildAlgMerkleTreeFromLeaves(
               std::move(leaves))
        .root;
}

Fri3AlgBatchCommitResult Fri3AlgBatchCommitConfigured(
    const std::vector<std::vector<Fp3>>& columns, const uint256& fs_seed,
    uint64_t pow_grind_nonce, const Fri3AlgProtocolConfig& config,
    bool stream_column_lde = false,
    const AlgMerkleTree* reused_row_tree = nullptr,
    AlgMerkleTree* built_row_tree_out = nullptr,
    uint256* terminal_fold_transcript_out = nullptr,
    // PR-89 g4 measurement hook. When non-null, records fs.buf.size() at the
    // instant BEFORE each Fiat-Shamir challenge is drawn -- i.e. the exact
    // preimage length the parent's in-AIR replay of that challenge must hash.
    // Read off the PRODUCTION transcript; nothing here is re-derived.
    std::vector<Fri3AlgTranscriptChallengeCostV1>* fs_prefix_trace_out = nullptr)
{
    const auto trace_prefix = [&](const char* label,
                                  const std::vector<unsigned char>& buf) {
        if (fs_prefix_trace_out == nullptr) return;
        Fri3AlgTranscriptChallengeCostV1 e;
        e.label = label;
        e.prefix_bytes = buf.size();
        fs_prefix_trace_out->push_back(std::move(e));
    };
    Fri3AlgBatchCommitResult out;
    if (columns.empty() || columns.size() > kRCFri3AlgBatchMaxColumns) {
        out.note = "bad column count";
        return out;
    }
    uint32_t max_len = 0;
    for (const auto& c : columns) {
        if (c.empty()) {
            out.note = "empty column";
            return out;
        }
        if (c.size() > (uint64_t{1} << kRCFriMaxColumnLog2)) {
            out.note = "column exceeds kappa=2^28 (2-adicity wall — split the tensor)";
            return out;
        }
        max_len = std::max<uint32_t>(max_len, static_cast<uint32_t>(c.size()));
    }
    const uint32_t n = FriNextPow2(max_len);
    if (static_cast<uint64_t>(n) * kRCFriBlowup > (uint64_t{1} << kRCFriMaxLdeLog2)) {
        // CPU soft guard (matches the SHA batch path). The PROTOCOL cap is
        // κ=2^28 / LDE 2^32.
        out.note = "LDE domain too large (CPU guard)";
        return out;
    }
    const uint32_t n_lde = n * kRCFriBlowup;
    const uint32_t W = static_cast<uint32_t>(columns.size());
    // FAIL CLOSED ON PROJECTED BYTES, before a single column LDE is allocated.
    // The column cap does not bound memory: the MEASURED real-role parent is
    // under it and would still need 302.7 GiB densely. Reject cleanly instead
    // of being OOM-killed.
    {
        uint64_t projected = 0;
        std::string budget_why;
        if (!Fri3AlgCommitFitsMemoryBudget(
                W, n_lde, stream_column_lde, &projected, &budget_why)) {
            out.note = "commit memory budget: " + budget_why;
            return out;
        }
    }
    BtxFriTimer __fri;

    Fri3AlgBatchProof& p = out.proof;
    p.version = config.proof_version;
    p.pow_grind_nonce = pow_grind_nonce;
    p.blowup = kRCFriBlowup;
    p.n_coeffs = n;
    p.column_len.resize(W);
    if (!stream_column_lde) out.column_lde.resize(W);
    // LDE-NTT: forward coset-LDE per column, independent transforms writing
    // distinct out.column_lde[i]. padded scratch is loop-local (thread-private).
#if defined(_OPENMP)
#pragma omp parallel for schedule(static) num_threads(BtxProveThreads())
#endif
    for (uint32_t i = 0; i < W; ++i) {
        p.column_len[i] = static_cast<uint32_t>(columns[i].size());
        if (!stream_column_lde) {
            std::vector<Fp3> padded(n, Fp3::Zero());
            for (size_t j = 0; j < columns[i].size(); ++j) {
                padded[j] = columns[i][j];
            }
            out.column_lde[i] =
                LdeFromCoeffs(padded, kRCFriBlowup);
        }
    }
    __fri.mark("lde_ntt(cols)");
    // ROW-WISE commitment (§2.3): ONE tree; leaf i = LeafHashRow of the whole
    // W-value row at LDE index i — one opening path per query instead of W.
    AlgMerkleTree row_tree;
    const AlgMerkleTree* row_tree_view = &row_tree;
    if (reused_row_tree != nullptr) {
        if (reused_row_tree->levels.empty() ||
            reused_row_tree->levels.front().size() != n_lde ||
            reused_row_tree->levels.back().size() != 1) {
            out.note = "reused row tree has wrong shape";
            return out;
        }
        row_tree_view = reused_row_tree;
    } else if (stream_column_lde) {
        // The selected shared-master construction has the canonical untagged
        // row tree.  A lane-tagged streaming sponge is intentionally not
        // inferred here: the duplicated-tree scenario must keep using the
        // materialized prover until that primitive exists.
        if (config.alg_hash_lane != -1) {
            out.note =
                "streaming row prover requires shared untagged commitment";
            return out;
        }
        std::vector<Fri3AlgDigest> leaves;
        {
            alg_hash::StreamingRowHasher row_hasher(n_lde);
            // Column-BLOCK pass 1: K column LDEs resident at a time.
            const uint32_t K =
                Fri3AlgStreamColumnBlockFor(n_lde);
            std::vector<std::vector<Fp3>> block;
            for (uint32_t c0 = 0; c0 < W; c0 += K) {
                const uint32_t kc = std::min(K, W - c0);
                BuildColumnLdeBlock(
                    columns, c0, kc, n, block);
                std::string stream_why;
                if (!row_hasher.AbsorbColumnBlock(
                        block, kc, &stream_why)) {
                    out.note =
                        "streaming row absorb: " + stream_why;
                    return out;
                }
            }
            std::string stream_why;
            if (!row_hasher.Finalize(leaves, &stream_why)) {
                out.note =
                    "streaming row finalize: " + stream_why;
                return out;
            }
        }
        row_tree =
            BuildAlgMerkleTreeFromLeaves(std::move(leaves));
    } else {
        row_tree = BuildAlgMerkleTreeFromLeaves(
            RowLeafDigests(
                out.column_lde, n_lde, config.alg_hash_lane),
            config.alg_hash_lane);
    }
    p.row_commit.root = row_tree_view->root;
    p.row_commit.n_leaves = n_lde;
    __fri.mark("rowleaf+merkle");

    // FS: the row root absorbed BEFORE any challenge (commit-then-challenge).
    Fri3AlgFs fs =
        Fri3AlgBatchFsInit(fs_seed, pow_grind_nonce, n, p.row_commit, p.column_len, config);

    // Column-composition coefficients. V3 keeps its one-power vector; V5
    // samples every coordinate independently. The existing `lambda` wire is
    // retained in the codec and carries either the legacy lambda or, in V5,
    // coefficient[0], so transcript tampering remains directly observable.
    std::vector<Fp3> batch_coefficients;
    trace_prefix("fra3_lambda", fs.buf);
    if (!ProtocolBatchCoefficients(
            fs, config, W, batch_coefficients, p.lambda)) {
        out.note = "uniform batching-coefficient sampling exhausted";
        return out;
    }

    // Dual OOD: two independent points; single-z caps the bindable degree.
    uint32_t zctr = 0;
    trace_prefix("fra3_z", fs.buf);
    trace_prefix("fra3_z", fs.buf);
    if (!Fri3AlgBatchSampleZ(fs, zctr, nullptr, config, p.z1) ||
        !Fri3AlgBatchSampleZ(fs, zctr, &p.z1, config, p.z2)) {
        out.note = "bounded OOD sampling exhausted";
        return out;
    }
    fs.AbsorbFp3(p.z1);
    fs.AbsorbFp3(p.z2);

    // Claimed per-column evaluations at both OOD points (the opening primitive).
    p.evals_z1.resize(W);
    p.evals_z2.resize(W);
    for (uint32_t i = 0; i < W; ++i) {
        p.evals_z1[i] = EvalPolyCoeffs(columns[i], p.z1);
        p.evals_z2[i] = EvalPolyCoeffs(columns[i], p.z2);
        if (!config.short_transcript_commitments) {
            fs.AbsorbFp3(p.evals_z1[i]);
            fs.AbsorbFp3(p.evals_z2[i]);
        }
    }
    if (config.short_transcript_commitments) {
        // PR-89 g4 TRANSCRIPT HALF, term (ii). 48*W bytes -> 32. Every
        // post-claim challenge (w1, w2, every fold beta, every query index)
        // still depends on the WHOLE 2W-cell claim vector, now through a
        // collision-resistant commitment instead of verbatim absorption.
        fs.AbsorbAlgRoot(
            Fri3AlgOodEvalCommit(p.z1, p.z2, p.evals_z1, p.evals_z2));
    }
    trace_prefix("fra3_w", fs.buf);
    trace_prefix("fra3_w", fs.buf);
    if (!ProtocolChallengeFp3(fs, config, "fra3_w", 0, p.w1) ||
        !ProtocolChallengeFp3(fs, config, "fra3_w", 1, p.w2)) {
        out.note = "uniform DEEP-weight sampling exhausted";
        return out;
    }
    fs.AbsorbFp3(p.w1);
    fs.AbsorbFp3(p.w2);

    // U = Σ λ^{i−1}·X^{n−len_i}·P_i (degree-shift = maximal-degree enforcement).
    std::vector<Fp3> U(n, Fp3::Zero());
    for (uint32_t i = 0; i < W; ++i) {
        const uint32_t shift = n - p.column_len[i];
        for (size_t j = 0; j < columns[i].size(); ++j) {
            U[shift + j] =
                Add(U[shift + j], Mul(batch_coefficients[i], columns[i][j]));
        }
    }
    // v_s = U(z_s) recomputed from the per-column claims (exactly equal for an
    // honest prover; the verifier recomputes the same way — that binds claims).
    Fp3 v1 = Fp3::Zero(), v2 = Fp3::Zero();
    for (uint32_t i = 0; i < W; ++i) {
        const uint32_t shift = n - p.column_len[i];
        v1 = Add(v1, Mul(Mul(batch_coefficients[i], PowFp3(p.z1, shift)),
                         p.evals_z1[i]));
        v2 = Add(v2, Mul(Mul(batch_coefficients[i], PowFp3(p.z2, shift)),
                         p.evals_z2[i]));
    }

    // DEEP composition G = w1·(U−v1)/(X−z1) + w2·(U−v2)/(X−z2), deg G < n−1.
    std::vector<Fp3> q1 = SyntheticQuotient(U, p.z1, v1);
    std::vector<Fp3> q2 = SyntheticQuotient(U, p.z2, v2);
    q1.resize(n, Fp3::Zero());
    q2.resize(n, Fp3::Zero());
    std::vector<Fp3> G(n);
    for (uint32_t j = 0; j < n; ++j) {
        G[j] = Add(Mul(p.w1, q1[j]), Mul(p.w2, q2[j]));
    }

    // Fold-commit phase on G — v5 half-domain fold × log2(n), terminal B-constant.
    const uint32_t n_folds = Fri3AlgLog2Exact(n);
    std::vector<Fp3> cur = LdeFromCoeffs(G, kRCFriBlowup);
    std::vector<AlgMerkleTree> g_trees;
    std::vector<std::vector<Fp3>> g_layers;
    for (uint32_t fold = 0;; ++fold) {
        AlgMerkleTree tree =
            BuildAlgMerkleTree(cur, config.alg_hash_lane);
        Fri3AlgLayerCommit lc;
        lc.n_leaves = static_cast<uint32_t>(cur.size());
        lc.root = tree.root;
        p.fold_layers.push_back(lc);
        g_layers.push_back(cur);
        g_trees.push_back(std::move(tree));
        fs.AbsorbAlgRoot(lc.root);
        if (fold == n_folds) {
            if (cur.size() != kRCFriBlowup) {
                out.note = "terminal layer size != blowup";
                return out;
            }
            p.final_value = cur[0];
            for (size_t i = 1; i < cur.size(); ++i) {
                if (!Eq(cur[i], p.final_value)) {
                    out.note = "terminal layer not constant";
                    return out;
                }
            }
            break;
        }
        Fp3 beta{};
        trace_prefix("fra3_fold", fs.buf);
        if (!ProtocolChallengeFp3(
                fs, config, "fra3_fold",
                static_cast<uint32_t>(p.fold_challenges.size()), beta)) {
            out.note = "uniform fold sampling exhausted";
            return out;
        }
        p.fold_challenges.push_back(beta);
        std::vector<Fp3> next;
        if (!HalfDomainFoldLayer(cur, beta, next)) {
            out.note = "half-domain fold failed (x=0)";
            return out;
        }
        cur = std::move(next);
    }

    __fri.mark("fold_layers");
    // PR-89 Construction 1 (Pi_JQ): T_l = SHA256d(lane-l FS buffer) captured at
    // the terminal fold layer, BEFORE the query loop. The dual driver squeezes
    // sigma_Q from both lanes' T_l and re-enters with config.joint_query set.
    if (terminal_fold_transcript_out != nullptr) {
        *terminal_fold_transcript_out =
            Sha256dBytes(fs.buf.data(), fs.buf.size());
    }

    // Queries: the configured Q. The SAME index opens the ROW
    // (one path carrying all W values) AND G's fold path.
    p.queries.reserve(config.query_count);
    for (uint32_t qi = 0; qi < config.query_count; ++qi) {
        Fri3AlgBatchQuery q;
        trace_prefix("fra3_query", fs.buf);
        if (!ProtocolChallengeIndex(
                fs, config, "fra3_query", qi, n_lde, q.index)) {
            out.note = "uniform query-index sampling failed";
            return out;
        }
        q.row.values.resize(W);
        if (!stream_column_lde) {
            for (uint32_t i = 0; i < W; ++i) {
                q.row.values[i] =
                    out.column_lde[i][q.index];
            }
        }
        q.row.siblings =
            PathFromAlgTree(*row_tree_view, q.index);
        uint32_t idx = q.index;
        q.steps.reserve(n_folds);
        for (uint32_t L = 0; L < n_folds; ++L) {
            q.steps.push_back(OpenFoldStep(g_layers[L], g_trees[L], idx));
            const uint32_t half = p.fold_layers[L].n_leaves / 2;
            idx = idx % half;
        }
        p.queries.push_back(std::move(q));
    }
    if (stream_column_lde) {
        // Query indices are transcript-derived only after every fold root is
        // committed. Recompute the column LDEs one BLOCK of K at a time and
        // retain only the selected values. This is the second pass; no
        // W×N_LDE matrix ever exists.
        const uint32_t K = Fri3AlgStreamColumnBlockFor(n_lde);
        std::vector<std::vector<Fp3>> block;
        for (uint32_t c0 = 0; c0 < W; c0 += K) {
            const uint32_t kc = std::min(K, W - c0);
            BuildColumnLdeBlock(columns, c0, kc, n, block);
            for (uint32_t t = 0; t < kc; ++t) {
                const std::vector<Fp3>& one_column = block[t];
                for (Fri3AlgBatchQuery& q : p.queries) {
                    q.row.values[c0 + t] =
                        one_column[q.index];
                }
            }
        }
    }

    __fri.mark("query_openings");
    std::vector<unsigned char> ser;
    out.proof_bytes = SerializeFri3AlgBatchProof(p, ser);
    if (built_row_tree_out != nullptr &&
        reused_row_tree == nullptr) {
        *built_row_tree_out = std::move(row_tree);
    }
    out.ok = true;
    if (stream_column_lde) {
        out.note =
            "two-pass column-streaming row commitment and query reconstruction";
    } else {
        out.note = config.query_count == kRCFri3AlgNumQueries
            ? kRCFri3AlgBatchSoundnessStatement
            : "experimental domain-separated Q128 independent-batching algebraic-FRI lane";
    }
    return out;
}

uint64_t Fri3AlgDenseLdeBytes(uint64_t columns, uint32_t n_lde)
{
    return columns * static_cast<uint64_t>(n_lde) *
           static_cast<uint64_t>(sizeof(Fp3));
}

bool Fri3AlgShouldStreamColumns(uint64_t columns, uint32_t n_lde)
{
    static const uint64_t budget = [] {
        if (const char* e =
                std::getenv("BTX_FRI_DENSE_LDE_BYTES")) {
            // 0 is meaningful: "never materialize densely".
            return static_cast<uint64_t>(
                std::max<long long>(0, std::atoll(e)));
        }
        return kRCFri3AlgDenseLdeByteBudget;
    }();
    return Fri3AlgDenseLdeBytes(columns, n_lde) > budget;
}

uint64_t Fri3AlgProjectedCommitPeakBytes(uint64_t columns, uint32_t n_lde,
                                         bool streaming)
{
    const uint64_t lde = streaming
        ? Fri3AlgDenseLdeBytes(
              Fri3AlgStreamColumnBlockFor(n_lde), n_lde)
        : Fri3AlgDenseLdeBytes(columns, n_lde);
    // Row-leaf digests + the Merkle levels above them (~2x the leaf level),
    // plus the streaming sponge state when that path is active.
    const uint64_t leaves =
        static_cast<uint64_t>(n_lde) * sizeof(Fri3AlgDigest) * 2;
    const uint64_t sponge =
        streaming
            ? alg_hash::StreamingRowHasher::WorkingSetBytesForRows(n_lde)
            : 0;
    return lde + leaves + sponge;
}

bool Fri3AlgCommitFitsMemoryBudget(uint64_t columns, uint32_t n_lde,
                                   bool streaming, uint64_t* projected,
                                   std::string* why)
{
    static const uint64_t ceiling = [] {
        if (const char* e =
                std::getenv("BTX_FRI_COMMIT_PEAK_BYTES")) {
            const long long v = std::atoll(e);
            if (v > 0) return static_cast<uint64_t>(v);
        }
        return kRCFri3AlgCommitPeakByteCeiling;
    }();
    const uint64_t peak =
        Fri3AlgProjectedCommitPeakBytes(columns, n_lde, streaming);
    if (projected != nullptr) *projected = peak;
    if (peak <= ceiling) return true;
    if (why != nullptr) {
        // Fail CLOSED and say exactly why: a shape can sit far under the
        // column cap and still be unallocatable.
        *why = "projected commit residency " +
               std::to_string(peak) +
               " B exceeds ceiling " + std::to_string(ceiling) +
               " B (columns=" + std::to_string(columns) +
               " n_lde=" + std::to_string(n_lde) +
               " streaming=" + (streaming ? "1" : "0") +
               ") — this is a MEMORY guard, not the column cap "
               "(kRCFri3AlgBatchMaxColumns=" +
               std::to_string(kRCFri3AlgBatchMaxColumns) + ")";
    }
    return false;
}

Fri3AlgBatchCommitResult Fri3AlgBatchCommit(const std::vector<std::vector<Fp3>>& columns,
                                            const uint256& fs_seed, uint64_t pow_grind_nonce)
{
    return Fri3AlgBatchCommitConfigured(columns, fs_seed, pow_grind_nonce,
                                        kFri3AlgQ192ActiveConfig);
}

Fri3AlgBatchCommitResult Fri3AlgBatchCommitStreamingShared(
    const std::vector<std::vector<Fp3>>& columns,
    const uint256& fs_seed,
    uint64_t pow_grind_nonce)
{
    return Fri3AlgBatchCommitConfigured(
        columns, fs_seed, pow_grind_nonce,
        kFri3AlgQ192ActiveConfig,
        /*stream_column_lde=*/true);
}

namespace {

void FinalizeRowTreeCache(
    Fri3AlgRowTreeCache& cache,
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t n_coeffs)
{
    cache.version = 1;
    cache.columns =
        static_cast<uint32_t>(columns.size());
    cache.n_coeffs = n_coeffs;
    cache.n_lde = n_coeffs * kRCFriBlowup;
    cache.column_len.clear();
    cache.column_len.reserve(columns.size());
    for (const auto& column : columns) {
        cache.column_len.push_back(
            static_cast<uint32_t>(column.size()));
    }
    cache.coefficient_commitment =
        RowTreeCacheBinding(
            cache.root, n_coeffs, columns);
    cache.valid =
        !cache.levels.empty() &&
        cache.levels.back().size() == 1 &&
        cache.levels.back()[0] == cache.root &&
        !cache.coefficient_commitment.IsNull();
}

bool ValidateRowTreeCache(
    const Fri3AlgRowTreeCache& cache,
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t n_coeffs,
    const Fri3AlgDigest& expected_root,
    std::string* why)
{
    const auto fail = [&](const char* detail) {
        if (why != nullptr) *why = detail;
        return false;
    };
    if (!cache.valid || cache.version != 1 ||
        columns.empty() ||
        cache.columns != columns.size() ||
        cache.n_coeffs != n_coeffs ||
        cache.n_lde != n_coeffs * kRCFriBlowup ||
        cache.column_len.size() != columns.size() ||
        cache.root != expected_root ||
        cache.levels.empty() ||
        cache.levels.front().size() != cache.n_lde ||
        cache.levels.back().size() != 1 ||
        cache.levels.back()[0] != cache.root) {
        return fail("cache shape/root");
    }
    size_t expected_width = cache.n_lde;
    for (const auto& level : cache.levels) {
        if (level.size() != expected_width) {
            return fail("cache level");
        }
        expected_width = (expected_width + 1) / 2;
    }
    if (expected_width != 1) {
        return fail("cache depth");
    }
    for (size_t column = 0;
         column < columns.size(); ++column) {
        if (columns[column].empty() ||
            columns[column].size() > n_coeffs ||
            cache.column_len[column] !=
                columns[column].size()) {
            return fail("cache column");
        }
    }
    if (cache.coefficient_commitment !=
        RowTreeCacheBinding(
            expected_root, n_coeffs, columns)) {
        return fail("cache binding");
    }
    return true;
}

} // namespace

Fri3AlgBatchCommitResult
Fri3AlgBatchCommitStreamingSharedCached(
    const std::vector<std::vector<Fp3>>& columns,
    const uint256& fs_seed,
    uint64_t pow_grind_nonce)
{
    AlgMerkleTree built;
    Fri3AlgBatchCommitResult out =
        Fri3AlgBatchCommitConfigured(
            columns, fs_seed, pow_grind_nonce,
            kFri3AlgQ192ActiveConfig,
            /*stream_column_lde=*/true,
            /*reused_row_tree=*/nullptr,
            &built);
    if (!out.ok) return out;
    FinalizeRowTreeCache(
        built, columns, out.proof.n_coeffs);
    if (!built.valid ||
        built.root != out.proof.row_commit.root) {
        out.ok = false;
        out.note = "streaming row cache finalize failed";
        return out;
    }
    out.row_tree_cache =
        std::make_shared<Fri3AlgRowTreeCache>(
            std::move(built));
    out.note += "; checked row tree retained";
    return out;
}

bool Fri3AlgBuildRowTreeCacheStreaming(
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t n_coeffs,
    Fri3AlgRowTreeCache& out,
    std::string* why)
{
    const auto fail =
        [&](const std::string& detail) {
            out = {};
            if (why != nullptr) {
                *why =
                    "Fri3AlgBuildRowTreeCacheStreaming: " +
                    detail;
            }
            return false;
        };
    out = {};
    if (columns.empty() ||
        columns.size() > kRCFri3AlgBatchMaxColumns ||
        n_coeffs == 0 ||
        (n_coeffs & (n_coeffs - 1)) != 0 ||
        uint64_t{n_coeffs} * kRCFriBlowup >
            (uint64_t{1} << kRCFriMaxLdeLog2)) {
        return fail("shape");
    }
    const uint32_t n_lde = n_coeffs * kRCFriBlowup;
    for (const auto& column : columns) {
        if (column.empty() ||
            column.size() > n_coeffs) {
            return fail("column length");
        }
    }
    std::vector<Fri3AlgDigest> leaves;
    alg_hash::StreamingRowHasher row_hasher(n_lde);
    {
        // Column-BLOCK streaming: peak staging is K * n_lde Fp3, not W * n_lde.
        const uint32_t W =
            static_cast<uint32_t>(columns.size());
        const uint32_t K =
            Fri3AlgStreamColumnBlockFor(n_lde);
        std::vector<std::vector<Fp3>> block;
        for (uint32_t c0 = 0; c0 < W; c0 += K) {
            const uint32_t kc = std::min(K, W - c0);
            BuildColumnLdeBlock(
                columns, c0, kc, n_coeffs, block);
            std::string block_why;
            if (!row_hasher.AbsorbColumnBlock(
                    block, kc, &block_why)) {
                return fail(
                    "row absorb: " + block_why);
            }
        }
    }
    std::string stream_why;
    if (!row_hasher.Finalize(leaves, &stream_why)) {
        return fail("row finalize: " + stream_why);
    }
    out =
        BuildAlgMerkleTreeFromLeaves(std::move(leaves));
    FinalizeRowTreeCache(out, columns, n_coeffs);
    if (!out.valid) {
        return fail("cache finalize");
    }
    return true;
}

bool Fri3AlgOpenRowsStreamingSharedCached(
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t n_coeffs,
    const std::vector<uint32_t>& indices,
    const Fri3AlgDigest& expected_root,
    const Fri3AlgRowTreeCache& cache,
    std::vector<Fri3AlgRowOpening>& out,
    std::string* why)
{
    const auto fail =
        [&](const std::string& detail) {
            out.clear();
            if (why != nullptr) {
                *why =
                    "Fri3AlgOpenRowsStreamingSharedCached: " +
                    detail;
            }
            return false;
        };
    out.clear();
    std::string cache_why;
    if (!ValidateRowTreeCache(
            cache, columns, n_coeffs,
            expected_root, &cache_why)) {
        return fail(cache_why);
    }
    const uint32_t n_lde = n_coeffs * kRCFriBlowup;
    for (uint32_t index : indices) {
        if (index >= n_lde) return fail("index");
    }
    out.resize(indices.size());
    for (size_t opening = 0;
         opening < indices.size(); ++opening) {
        out[opening].values.resize(columns.size());
        out[opening].siblings =
            PathFromAlgTree(cache, indices[opening]);
    }
    {
        // Column-BLOCK opening pass: recompute K column LDEs at a time and
        // keep only the queried rows. Values land in ascending column order,
        // exactly as the dense path writes them.
        const uint32_t W =
            static_cast<uint32_t>(columns.size());
        const uint32_t K =
            Fri3AlgStreamColumnBlockFor(n_lde);
        std::vector<std::vector<Fp3>> block;
        for (uint32_t c0 = 0; c0 < W; c0 += K) {
            const uint32_t kc = std::min(K, W - c0);
            BuildColumnLdeBlock(
                columns, c0, kc, n_coeffs, block);
            for (uint32_t t = 0; t < kc; ++t) {
                const std::vector<Fp3>& one_column = block[t];
                for (size_t opening = 0;
                     opening < indices.size(); ++opening) {
                    out[opening].values[c0 + t] =
                        one_column[indices[opening]];
                }
            }
        }
    }
    // A retained cache is an untrusted prover hint. Its root/coefficient
    // binding does not by itself authenticate every cached internal level.
    // Verify each emitted opening against the expected root before allowing
    // an `ok=true` proof result, so corrupted cache levels fail here instead
    // of merely producing a verifier-invalid proof.
    for (size_t opening = 0;
         opening < indices.size(); ++opening) {
        if (!VerifyAlgPathForLane(
                AlgHashRowLeafForLane(
                    out[opening].values,
                    indices[opening], -1),
                indices[opening],
                out[opening].siblings,
                expected_root, n_lde, -1)) {
            return fail(
                "cached opening path/root");
        }
    }
    return true;
}

bool Fri3AlgOpenRowsStreamingShared(
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t n_coeffs,
    const std::vector<uint32_t>& indices,
    const Fri3AlgDigest& expected_root,
    std::vector<Fri3AlgRowOpening>& out,
    std::string* why)
{
    Fri3AlgRowTreeCache cache;
    if (!Fri3AlgBuildRowTreeCacheStreaming(
            columns, n_coeffs, cache, why)) {
        return false;
    }
    return Fri3AlgOpenRowsStreamingSharedCached(
        columns, n_coeffs, indices,
        expected_root, cache, out, why);
}

bool Fri3AlgBatchVerifyConfigured(const Fri3AlgBatchProof& proof, const uint256& fs_seed,
                                  const Fri3AlgProtocolConfig& config, std::string* why,
                                  uint256* terminal_fold_transcript_out = nullptr,
                                  bool terminal_fold_only = false)
{
    auto fail = [&](const char* w) {
        if (why) *why = w ? w : "Fri3AlgBatchVerify failed";
        return false;
    };
    if (proof.version != config.proof_version) return fail("bad batch version");
    if (proof.blowup != kRCFriBlowup) return fail("bad blowup");
    const uint32_t n = proof.n_coeffs;
    if (n == 0 || (n & (n - 1)) != 0) return fail("n_coeffs not pow2");
    if (n > (uint64_t{1} << kRCFriMaxColumnLog2)) return fail("n_coeffs exceeds kappa");
    if (static_cast<uint64_t>(n) * kRCFriBlowup > (uint64_t{1} << kRCFriMaxLdeLog2))
        return fail("LDE guard");
    const uint32_t n_lde = n * kRCFriBlowup;
    const uint32_t W = static_cast<uint32_t>(proof.column_len.size());
    if (W == 0 || W > kRCFri3AlgBatchMaxColumns) return fail("bad column count");
    if (proof.row_commit.n_leaves != n_lde) return fail("row n_leaves");
    uint32_t max_len = 0;
    for (uint32_t i = 0; i < W; ++i) {
        if (proof.column_len[i] == 0 || proof.column_len[i] > n) return fail("column len");
        max_len = std::max(max_len, proof.column_len[i]);
    }
    if (FriNextPow2(max_len) != n) return fail("n_coeffs not canonical");
    if (proof.evals_z1.size() != W || proof.evals_z2.size() != W) return fail("eval count");
    if (proof.fold_layers.empty()) return fail("no fold layers");
    if (proof.fold_layers[0].n_leaves != n_lde) return fail("fold LDE size");
    const uint32_t n_folds_expect = Fri3AlgLog2Exact(n);
    if (proof.fold_challenges.size() != n_folds_expect) return fail("fold count");
    if (proof.fold_challenges.size() + 1 != proof.fold_layers.size())
        return fail("fold layer/challenge count");
    // Terminal MUST be the blowup-sized constant layer (singleton rejected).
    if (proof.fold_layers.back().n_leaves != proof.blowup) return fail("final layer not blowup");
    for (size_t i = 0; i + 1 < proof.fold_layers.size(); ++i) {
        if (proof.fold_layers[i].n_leaves < 2 || (proof.fold_layers[i].n_leaves % 2) != 0)
            return fail("fold layer parity");
        if (proof.fold_layers[i].n_leaves / 2 != proof.fold_layers[i + 1].n_leaves)
            return fail("fold layer size");
    }
    // Path-local numeric parameters (statically asserted in the header;
    // re-checked here fail-closed).
    if (proof.queries.size() != config.query_count) return fail("query count");
    if (proof.queries.size() > kRCFri3AlgMaxQueriesHard) return fail("query count hard");
    if (config.require_q192_proximity_guard && !Fri3AlgClaimedBitsMeetTarget())
        return fail("soundness params");

    // FS replay: every challenge recomputed from the transcript and compared.
    Fri3AlgFs fs = Fri3AlgBatchFsInit(fs_seed, proof.pow_grind_nonce, n, proof.row_commit,
                                      proof.column_len, config);
    std::vector<Fp3> batch_coefficients;
    Fp3 encoded_first_or_lambda{};
    if (!ProtocolBatchCoefficients(
            fs, config, W, batch_coefficients, encoded_first_or_lambda)) {
        return fail("uniform batching-coefficient sampling exhausted");
    }
    if (!Eq(encoded_first_or_lambda, proof.lambda))
        return fail("batch coefficient mismatch");
    {
        uint32_t zctr = 0;
        Fp3 z1{};
        if (!Fri3AlgBatchSampleZ(fs, zctr, nullptr, config, z1))
            return fail("bounded z1 sampling exhausted");
        if (!Eq(z1, proof.z1)) return fail("z1 mismatch");
        Fp3 z2{};
        if (!Fri3AlgBatchSampleZ(fs, zctr, &z1, config, z2))
            return fail("bounded z2 sampling exhausted");
        if (!Eq(z2, proof.z2)) return fail("z2 mismatch");
        fs.AbsorbFp3(z1);
        fs.AbsorbFp3(z2);
    }
    if (!Fri3AlgHasExtCoord(proof.z1) || !Fri3AlgHasExtCoord(proof.z2) ||
        Fri3AlgPointInDomain(proof.z1, n_lde) || Fri3AlgPointInDomain(proof.z2, n_lde) ||
        Eq(proof.z1, proof.z2)) {
        return fail("OOD points invalid");
    }
    if (config.short_transcript_commitments) {
        // Mirror of the prover's term (ii). The verifier RECOMPUTES the
        // commitment from the claimed evaluation vectors it was shipped, so a
        // single altered cell moves the commitment, moves w1/w2, and is caught
        // by the `Eq(w1, proof.w1)` check below — the same rejection the
        // verbatim absorption produced.
        fs.AbsorbAlgRoot(Fri3AlgOodEvalCommit(
            proof.z1, proof.z2, proof.evals_z1, proof.evals_z2));
    } else {
        for (uint32_t i = 0; i < W; ++i) {
            fs.AbsorbFp3(proof.evals_z1[i]);
            fs.AbsorbFp3(proof.evals_z2[i]);
        }
    }
    {
        Fp3 w1{};
        Fp3 w2{};
        if (!ProtocolChallengeFp3(fs, config, "fra3_w", 0, w1) ||
            !ProtocolChallengeFp3(fs, config, "fra3_w", 1, w2)) {
            return fail("uniform DEEP-weight sampling exhausted");
        }
        if (!Eq(w1, proof.w1) || !Eq(w2, proof.w2)) return fail("deep weights mismatch");
        fs.AbsorbFp3(w1);
        fs.AbsorbFp3(w2);
    }
    for (size_t i = 0; i < proof.fold_layers.size(); ++i) {
        fs.AbsorbAlgRoot(proof.fold_layers[i].root);
        if (i + 1 < proof.fold_layers.size()) {
            Fp3 beta{};
            if (!ProtocolChallengeFp3(
                    fs, config, "fra3_fold", static_cast<uint32_t>(i), beta)) {
                return fail("uniform fold sampling exhausted");
            }
            if (!Eq(beta, proof.fold_challenges[i])) return fail("fold challenge mismatch");
        }
    }
    if (!AlgDigestEq(AlgMerkleRootConstantLayer(
                         proof.final_value, proof.blowup,
                         config.alg_hash_lane),
                     proof.fold_layers.back().root)) {
        return fail("final constant layer root");
    }

    // PR-89 Construction 1 (Pi_JQ): capture T_l at the terminal fold, matching
    // the prover's capture point, so the dual verifier can recompute sigma_Q.
    if (terminal_fold_transcript_out != nullptr) {
        *terminal_fold_transcript_out =
            Sha256dBytes(fs.buf.data(), fs.buf.size());
    }
    if (terminal_fold_only) return true;

    // v_s = U(z_s) from the per-column claims — the DEEP identity below binds
    // every claimed (C_i(z1), C_i(z2)) to the committed words.
    Fp3 v1 = Fp3::Zero(), v2 = Fp3::Zero();
    for (uint32_t i = 0; i < W; ++i) {
        const uint32_t shift = n - proof.column_len[i];
        v1 = Add(v1, Mul(Mul(batch_coefficients[i], PowFp3(proof.z1, shift)),
                         proof.evals_z1[i]));
        v2 = Add(v2, Mul(Mul(batch_coefficients[i], PowFp3(proof.z2, shift)),
                         proof.evals_z2[i]));
    }

    const uint32_t n_folds = static_cast<uint32_t>(proof.fold_challenges.size());
    std::vector<uint32_t> expected_query_indices(
        config.query_count);
    for (uint32_t qi = 0; qi < config.query_count; ++qi) {
        const Fri3AlgBatchQuery& q = proof.queries[qi];
        if (!ProtocolChallengeIndex(
                fs, config, "fra3_query", qi, n_lde,
                expected_query_indices[qi])) {
            return fail("uniform query-index sampling failed");
        }
        if (q.index != expected_query_indices[qi])
            return fail("query index");
        if (q.row.values.size() != W) return fail("query row width");
        if (q.steps.size() != n_folds) return fail("query steps");
    }

    const auto verify_query =
        [&](uint32_t qi) -> std::string {
        const Fri3AlgBatchQuery& q = proof.queries[qi];
        // ONE row opening: recompute leaf i = LeafHashRow(row, i) from the
        // opened values, then ONE path into row_commit (§2.3).
        if (!VerifyAlgPathForLane(
                AlgHashRowLeafForLane(
                    q.row.values, q.index, config.alg_hash_lane),
                q.index, q.row.siblings, proof.row_commit.root, n_lde,
                config.alg_hash_lane)) {
            return "row merkle";
        }
        const Fp3 x = DomainPoint(n_lde, q.index);
        Fp3 U_x = Fp3::Zero();
        for (uint32_t i = 0; i < W; ++i) {
            const uint32_t shift = n - proof.column_len[i];
            U_x = Add(
                U_x,
                Mul(Mul(batch_coefficients[i], PowFp3(x, shift)),
                    q.row.values[i]));
        }

        // Dual-OOD DEEP identity at the query site.
        const Fp3 g_expect =
            Add(Mul(proof.w1, Mul(Sub(U_x, v1), Inv(Sub(x, proof.z1)))),
                Mul(proof.w2, Mul(Sub(U_x, v2), Inv(Sub(x, proof.z2)))));

        if (n_folds == 0) {
            // Constant G codeword bound by terminal root; must match DEEP identity.
            if (!Eq(g_expect, proof.final_value))
                return "deep identity";
            return {};
        }

        uint32_t idx = q.index;
        Fp3 claimed{};
        bool have_claimed = false;
        for (uint32_t L = 0; L < n_folds; ++L) {
            const Fri3AlgFoldStep& step = q.steps[L];
            Fp3 folded{};
            std::string step_why;
            if (!VerifyFoldStep(step, proof.fold_layers[L].root, proof.fold_layers[L].n_leaves,
                                proof.fold_challenges[L], idx, folded,
                                &step_why, config.alg_hash_lane)) {
                return step_why;
            }
            const uint32_t half = proof.fold_layers[L].n_leaves / 2;
            const Fp3 leaf_here = (idx < half) ? step.even : step.odd;
            if (L == 0) {
                if (!Eq(leaf_here, g_expect))
                    return "deep identity";
            } else if (have_claimed && !Eq(leaf_here, claimed)) {
                return "fold path consistency";
            }
            claimed = folded;
            have_claimed = true;
            idx = idx % half;
        }
        if (!Eq(claimed, proof.final_value))
            return "final fold value";
        return {};
    };

    uint32_t workers = 1;
    if (config.query_count >= 32) {
        workers = std::max<uint32_t>(
            1, std::thread::hardware_concurrency());
        // Both V5 lanes are already independent outer jobs. Divide the
        // machine between them before chunking the inner query sites.
        if (config.proof_version ==
            kRCFri3AlgDualLaneProofVersion) {
            workers = std::max<uint32_t>(1, workers / 2);
        }
        workers =
            std::min<uint32_t>(
                {workers, config.query_count, 16});
    }
    if (workers == 1) {
        for (uint32_t qi = 0;
            qi < config.query_count; ++qi) {
            const std::string error = verify_query(qi);
            if (!error.empty()) return fail(error.c_str());
        }
    } else {
        using QueryChunkResult =
            std::pair<uint32_t, std::string>;
        std::vector<std::future<QueryChunkResult>> jobs;
        jobs.reserve(workers);
        const uint32_t chunk =
            (config.query_count + workers - 1) / workers;
        for (uint32_t worker = 0;
             worker < workers; ++worker) {
            const uint32_t begin = worker * chunk;
            const uint32_t end =
                std::min<uint32_t>(
                    config.query_count, begin + chunk);
            if (begin >= end) break;
            jobs.push_back(std::async(
                std::launch::async,
                [&, begin, end]() -> QueryChunkResult {
                    for (uint32_t qi = begin; qi < end; ++qi) {
                        std::string error = verify_query(qi);
                        if (!error.empty()) {
                            return {
                                qi, std::move(error)};
                        }
                    }
                    return {
                        std::numeric_limits<uint32_t>::max(),
                        {}};
                }));
        }
        QueryChunkResult first_error{
            std::numeric_limits<uint32_t>::max(), {}};
        for (auto& job : jobs) {
            QueryChunkResult result = job.get();
            if (result.first < first_error.first) {
                first_error = std::move(result);
            }
        }
        if (first_error.first !=
            std::numeric_limits<uint32_t>::max()) {
            return fail(first_error.second.c_str());
        }
    }

    if (why) *why = "Fri3AlgBatchVerify ok";
    return true;
}

bool Fri3AlgBatchVerify(const Fri3AlgBatchProof& proof, const uint256& fs_seed, std::string* why)
{
    return Fri3AlgBatchVerifyConfigured(proof, fs_seed, kFri3AlgQ192ActiveConfig,
                                        why);
}

Fri3AlgBatchCommitResult Fri3AlgLegacyV3BatchCommit(
    const std::vector<std::vector<Fp3>>& columns, const uint256& fs_seed,
    uint64_t pow_grind_nonce)
{
    return Fri3AlgBatchCommitConfigured(columns, fs_seed, pow_grind_nonce,
                                        kFri3AlgQ192V3Config);
}

bool Fri3AlgLegacyV3BatchVerify(const Fri3AlgBatchProof& proof,
                                const uint256& fs_seed, std::string* why)
{
    return Fri3AlgBatchVerifyConfigured(proof, fs_seed, kFri3AlgQ192V3Config,
                                        why);
}

Fri3AlgBatchCommitResult Fri3AlgShortFsBatchCommit(
    const std::vector<std::vector<Fp3>>& columns, const uint256& fs_seed,
    uint64_t pow_grind_nonce)
{
    return Fri3AlgBatchCommitConfigured(columns, fs_seed, pow_grind_nonce,
                                        kFri3AlgQ192ShortFsV7Config);
}

bool Fri3AlgShortFsBatchVerify(const Fri3AlgBatchProof& proof,
                              const uint256& fs_seed, std::string* why)
{
    // Version check inside Fri3AlgBatchVerifyConfigured is what keeps the two
    // layouts from ever being confused: a V3 proof fed here, or a V7 proof fed
    // to Fri3AlgBatchVerify, fails at "bad batch version" before any FS work.
    return Fri3AlgBatchVerifyConfigured(proof, fs_seed,
                                        kFri3AlgQ192ShortFsV7Config, why);
}

bool Fri3AlgQ192IndependentBatching()
{
    return kFri3AlgQ192ActiveConfig.independent_batching_coefficients;
}

bool Fri3AlgReplayBatchCoefficients(const Fri3AlgBatchProof& proof,
                                    const uint256& fs_seed,
                                    std::vector<Fp3>& out_coefficients)
{
    out_coefficients.clear();
    if (proof.version != kFri3AlgQ192ActiveConfig.proof_version) return false;
    const uint32_t n = proof.n_coeffs;
    if (n == 0 || (n & (n - 1)) != 0) return false;
    const uint32_t W = static_cast<uint32_t>(proof.column_len.size());
    if (W == 0 || W > kRCFri3AlgBatchMaxColumns) return false;
    for (uint32_t i = 0; i < W; ++i) {
        if (proof.column_len[i] == 0 || proof.column_len[i] > n) return false;
    }
    if (proof.row_commit.n_leaves != n * kRCFriBlowup) return false;
    // Exactly the FS state the honest prover/verifier reach before drawing the
    // batching coefficients (see Fri3AlgBatchVerifyConfigured): init the sponge
    // from the seed, PoW nonce, common length, row commitment and per-column
    // lengths, then replay ProtocolBatchCoefficients under the Q192 config.
    Fri3AlgFs fs = Fri3AlgBatchFsInit(fs_seed, proof.pow_grind_nonce, n,
                                      proof.row_commit, proof.column_len,
                                      kFri3AlgQ192ActiveConfig);
    Fp3 encoded_first_or_lambda{};
    if (!ProtocolBatchCoefficients(fs, kFri3AlgQ192ActiveConfig, W,
                                   out_coefficients,
                                   encoded_first_or_lambda)) {
        out_coefficients.clear();
        return false;
    }
    // The scalar the codec DOES persist must bind the replayed transcript.
    if (!Eq(encoded_first_or_lambda, proof.lambda)) {
        out_coefficients.clear();
        return false;
    }
    return true;
}

namespace {

constexpr char kFri3AlgMultiRowDomainTag[] =
    "BTX_RC_FRI3ALG_MULTI_ROW_RAP_V2";

constexpr Fri3AlgProtocolConfig
    kFri3AlgMultiRowQ192Config{
        kRCFri3AlgMultiRowBatchProofVersion,
        kFri3AlgMultiRowDomainTag,
        kRCFri3AlgDualUniformDrawDomainTag,
        kRCFri3AlgDualIndexDrawDomainTag,
        kRCFri3AlgNumQueries,
        kRCFri3AlgDualOodCandidates,
        true,
        true,
        -1,
        true,
    };

bool CanonicalMultiRowRoles(
    const std::vector<Fri3AlgMultiRowGroupRole>& roles)
{
    return roles ==
        std::vector<Fri3AlgMultiRowGroupRole>{
            Fri3AlgMultiRowGroupRole::MainTrace,
            Fri3AlgMultiRowGroupRole::AuxiliaryTrace,
            Fri3AlgMultiRowGroupRole::Quotient};
}

Fri3AlgFs Fri3AlgMultiRowFsInit(
    const uint256& fs_seed,
    uint64_t pow_grind_nonce,
    uint32_t n_coeffs,
    const std::vector<Fri3AlgMultiRowGroupCommit>& groups,
    const std::vector<uint32_t>& column_len)
{
    Fri3AlgFs fs(
        fs_seed, pow_grind_nonce, kRCFriBlowup,
        n_coeffs, kFri3AlgMultiRowDomainTag);
    AppendLE32(
        fs.buf, kRCFri3AlgMultiRowBatchProofVersion);
    AppendLE32(
        fs.buf, static_cast<uint32_t>(groups.size()));
    for (const auto& group : groups) {
        AppendLE32(
            fs.buf,
            static_cast<uint32_t>(group.role));
        AppendLE32(fs.buf, group.first_column);
        AppendLE32(fs.buf, group.column_count);
        AppendLE32(
            fs.buf, group.row_commit.n_leaves);
        fs.AbsorbAlgRoot(group.row_commit.root);
    }
    AppendLE32(
        fs.buf,
        static_cast<uint32_t>(column_len.size()));
    for (uint32_t length : column_len) {
        AppendLE32(fs.buf, length);
    }
    return fs;
}

} // namespace

Fri3AlgMultiRowBatchCommitResult
Fri3AlgMultiRowBatchCommitStreaming(
    const std::vector<std::vector<std::vector<Fp3>>>& groups,
    const std::vector<Fri3AlgMultiRowGroupRole>& roles,
    const uint256& fs_seed,
    uint64_t pow_grind_nonce,
    const std::vector<
        std::shared_ptr<Fri3AlgRowTreeCache>>& retained)
{
    Fri3AlgMultiRowBatchCommitResult out;
    const auto fail = [&](const std::string& detail) {
        out.note =
            "multi_row_commit:" + detail;
        return out;
    };
    if (!CanonicalMultiRowRoles(roles) ||
        groups.size() != roles.size() ||
        (!retained.empty() &&
         retained.size() != groups.size()) ||
        fs_seed.IsNull()) {
        return fail("shape_or_roles");
    }
    uint32_t max_len = 0;
    uint32_t width = 0;
    for (const auto& group : groups) {
        if (group.empty()) return fail("empty_group");
        if (width >
            kRCFri3AlgBatchMaxColumns - group.size()) {
            return fail("width");
        }
        width += static_cast<uint32_t>(group.size());
        for (const auto& column : group) {
            if (column.empty() ||
                column.size() >
                    (uint64_t{1} <<
                     kRCFriMaxColumnLog2)) {
                return fail("column_length");
            }
            max_len = std::max<uint32_t>(
                max_len,
                static_cast<uint32_t>(
                    column.size()));
        }
    }
    const uint32_t n = FriNextPow2(max_len);
    if (n < 2 ||
        uint64_t{n} * kRCFriBlowup >
            (uint64_t{1} << kRCFriMaxLdeLog2)) {
        return fail("domain");
    }
    const uint32_t n_lde =
        n * kRCFriBlowup;
    auto& proof = out.proof;
    proof.pow_grind_nonce = pow_grind_nonce;
    proof.n_coeffs = n;
    proof.groups.resize(groups.size());
    proof.column_len.reserve(width);
    out.group_row_tree_caches.resize(
        groups.size());
    uint32_t first = 0;
    for (uint32_t group = 0;
         group < groups.size(); ++group) {
        std::shared_ptr<Fri3AlgRowTreeCache> cache =
            retained.empty()
            ? nullptr
            : retained[group];
        std::string cache_why;
        if (cache) {
            if (!cache->valid ||
                cache->columns != groups[group].size() ||
                cache->n_coeffs != n ||
                !ValidateRowTreeCache(
                    *cache, groups[group], n,
                    cache->root, &cache_why)) {
                return fail(
                    "retained_cache:" + cache_why);
            }
        } else {
            cache =
                std::make_shared<
                    Fri3AlgRowTreeCache>();
            if (!Fri3AlgBuildRowTreeCacheStreaming(
                    groups[group], n, *cache,
                    &cache_why)) {
                return fail(
                    "group_root:" + cache_why);
            }
        }
        out.group_row_tree_caches[group] = cache;
        auto& commitment = proof.groups[group];
        commitment.role = roles[group];
        commitment.first_column = first;
        commitment.column_count =
            static_cast<uint32_t>(
                groups[group].size());
        commitment.row_commit.root =
            cache->root;
        commitment.row_commit.n_leaves =
            n_lde;
        for (const auto& column : groups[group]) {
            proof.column_len.push_back(
                static_cast<uint32_t>(
                    column.size()));
        }
        first += commitment.column_count;
    }

    Fri3AlgFs fs =
        Fri3AlgMultiRowFsInit(
            fs_seed, pow_grind_nonce, n,
            proof.groups, proof.column_len);
    uint32_t z_counter = 0;
    if (!Fri3AlgBatchSampleZ(
            fs, z_counter, nullptr,
            kFri3AlgMultiRowQ192Config,
            proof.z1) ||
        !Fri3AlgBatchSampleZ(
            fs, z_counter, &proof.z1,
            kFri3AlgMultiRowQ192Config,
            proof.z2)) {
        return fail("ood");
    }
    fs.AbsorbFp3(proof.z1);
    fs.AbsorbFp3(proof.z2);
    proof.evals_z1.resize(width);
    proof.evals_z2.resize(width);
    uint32_t flattened = 0;
    for (const auto& group : groups) {
        for (const auto& column : group) {
            proof.evals_z1[flattened] =
                EvalPolyCoeffs(column, proof.z1);
            proof.evals_z2[flattened] =
                EvalPolyCoeffs(column, proof.z2);
            fs.AbsorbFp3(
                proof.evals_z1[flattened]);
            fs.AbsorbFp3(
                proof.evals_z2[flattened]);
            ++flattened;
        }
    }
    // V2: all per-column claims are fixed before the random batching vector.
    // With the reverse order only aggregate v(z1),v(z2) was bound: after
    // seeing the coefficients, a prover could add a nonzero kernel vector to
    // individual claims while preserving both aggregates. The post-claim
    // vector reduces any such fixed nonzero delta to a field-size event.
    std::vector<Fp3> coefficients;
    if (!ProtocolBatchCoefficients(
            fs, kFri3AlgMultiRowQ192Config,
            width, coefficients, proof.lambda)) {
        return fail("batch_coefficients");
    }
    if (!ProtocolChallengeFp3(
            fs, kFri3AlgMultiRowQ192Config,
            "fra3_w", 0, proof.w1) ||
        !ProtocolChallengeFp3(
            fs, kFri3AlgMultiRowQ192Config,
            "fra3_w", 1, proof.w2)) {
        return fail("deep_weights");
    }
    fs.AbsorbFp3(proof.w1);
    fs.AbsorbFp3(proof.w2);

    std::vector<Fp3> combined(
        n, Fp3::Zero());
    flattened = 0;
    for (const auto& group : groups) {
        for (const auto& column : group) {
            const uint32_t shift =
                n - proof.column_len[flattened];
            for (uint32_t coefficient = 0;
                 coefficient < column.size();
                 ++coefficient) {
                combined[shift + coefficient] =
                    Add(
                        combined[
                            shift + coefficient],
                        Mul(
                            coefficients[flattened],
                            column[coefficient]));
            }
            ++flattened;
        }
    }
    Fp3 v1 = Fp3::Zero();
    Fp3 v2 = Fp3::Zero();
    for (uint32_t column = 0;
         column < width; ++column) {
        const uint32_t shift =
            n - proof.column_len[column];
        v1 = Add(
            v1,
            Mul(
                Mul(
                    coefficients[column],
                    PowFp3(proof.z1, shift)),
                proof.evals_z1[column]));
        v2 = Add(
            v2,
            Mul(
                Mul(
                    coefficients[column],
                    PowFp3(proof.z2, shift)),
                proof.evals_z2[column]));
    }
    std::vector<Fp3> q1 =
        SyntheticQuotient(
            combined, proof.z1, v1);
    std::vector<Fp3> q2 =
        SyntheticQuotient(
            combined, proof.z2, v2);
    q1.resize(n, Fp3::Zero());
    q2.resize(n, Fp3::Zero());
    std::vector<Fp3> folded(n);
    for (uint32_t coefficient = 0;
         coefficient < n; ++coefficient) {
        folded[coefficient] =
            Add(
                Mul(proof.w1, q1[coefficient]),
                Mul(proof.w2, q2[coefficient]));
    }

    const uint32_t fold_count =
        Fri3AlgLog2Exact(n);
    std::vector<Fp3> current =
        LdeFromCoeffs(folded, kRCFriBlowup);
    std::vector<AlgMerkleTree> fold_trees;
    std::vector<std::vector<Fp3>> fold_values;
    for (uint32_t fold = 0;; ++fold) {
        AlgMerkleTree tree =
            BuildAlgMerkleTree(current);
        Fri3AlgLayerCommit layer;
        layer.root = tree.root;
        layer.n_leaves =
            static_cast<uint32_t>(current.size());
        proof.fold_layers.push_back(layer);
        fold_values.push_back(current);
        fold_trees.push_back(std::move(tree));
        fs.AbsorbAlgRoot(
            proof.fold_layers.back().root);
        if (fold == fold_count) {
            if (current.size() != kRCFriBlowup) {
                return fail("terminal_size");
            }
            proof.final_value = current[0];
            for (const auto& value : current) {
                if (!Eq(value, proof.final_value)) {
                    return fail("terminal_constant");
                }
            }
            break;
        }
        Fp3 beta;
        if (!ProtocolChallengeFp3(
                fs, kFri3AlgMultiRowQ192Config,
                "fra3_fold", fold, beta)) {
            return fail("fold_challenge");
        }
        proof.fold_challenges.push_back(beta);
        std::vector<Fp3> next;
        if (!HalfDomainFoldLayer(
                current, beta, next)) {
            return fail("fold");
        }
        current = std::move(next);
    }

    proof.queries.resize(
        kFri3AlgMultiRowQ192Config.query_count);
    std::vector<uint32_t> query_indices(
        proof.queries.size());
    for (uint32_t query = 0;
         query < proof.queries.size(); ++query) {
        auto& opened = proof.queries[query];
        if (!ProtocolChallengeIndex(
                fs, kFri3AlgMultiRowQ192Config,
                "fra3_query", query, n_lde,
                opened.index)) {
            return fail("query_index");
        }
        query_indices[query] = opened.index;
        opened.group_rows.resize(groups.size());
        uint32_t index = opened.index;
        for (uint32_t fold = 0;
             fold < fold_count; ++fold) {
            opened.steps.push_back(
                OpenFoldStep(
                    fold_values[fold],
                    fold_trees[fold], index));
            index %= proof.fold_layers[fold]
                         .n_leaves /
                     2;
        }
    }
    for (uint32_t group = 0;
         group < groups.size(); ++group) {
        std::vector<Fri3AlgRowOpening> rows;
        std::string opening_why;
        if (!Fri3AlgOpenRowsStreamingSharedCached(
                groups[group], n, query_indices,
                proof.groups[group].row_commit.root,
                *out.group_row_tree_caches[group],
                rows, &opening_why) ||
            rows.size() != proof.queries.size()) {
            return fail(
                "group_open:" + opening_why);
        }
        for (uint32_t query = 0;
             query < rows.size(); ++query) {
            proof.queries[query]
                .group_rows[group] =
                std::move(rows[query]);
        }
    }
    out.ok = true;
    out.note =
        "multi_row_commit:ordered_roots_one_rlc_deep_fri";
    return out;
}

bool Fri3AlgMultiRowBatchVerify(
    const Fri3AlgMultiRowBatchProof& proof,
    const uint256& fs_seed,
    std::string* why)
{
    const auto fail = [&](const std::string& detail) {
        if (why != nullptr) {
            *why =
                "multi_row_verify:" + detail;
        }
        return false;
    };
    if (proof.version !=
            kRCFri3AlgMultiRowBatchProofVersion ||
        proof.blowup != kRCFriBlowup ||
        proof.n_coeffs < 2 ||
        (proof.n_coeffs &
         (proof.n_coeffs - 1)) != 0 ||
        uint64_t{proof.n_coeffs} *
                kRCFriBlowup >
            (uint64_t{1} <<
             kRCFriMaxLdeLog2) ||
        proof.groups.size() != 3 ||
        proof.column_len.empty() ||
        proof.column_len.size() >
            kRCFri3AlgBatchMaxColumns ||
        proof.evals_z1.size() !=
            proof.column_len.size() ||
        proof.evals_z2.size() !=
            proof.column_len.size() ||
        fs_seed.IsNull()) {
        return fail("shape");
    }
    std::vector<Fri3AlgMultiRowGroupRole> roles;
    uint32_t first = 0;
    const uint32_t n_lde =
        proof.n_coeffs * kRCFriBlowup;
    for (const auto& group : proof.groups) {
        roles.push_back(group.role);
        const uint32_t remaining =
            static_cast<uint32_t>(
                proof.column_len.size()) -
            first;
        if (group.first_column != first ||
            group.column_count == 0 ||
            first > proof.column_len.size() ||
            group.column_count > remaining ||
            group.row_commit.n_leaves != n_lde) {
            return fail("group_metadata");
        }
        first += group.column_count;
    }
    if (!CanonicalMultiRowRoles(roles) ||
        first != proof.column_len.size()) {
        return fail("group_order_or_range");
    }
    uint32_t max_len = 0;
    for (uint32_t length : proof.column_len) {
        if (length == 0 ||
            length > proof.n_coeffs) {
            return fail("column_length");
        }
        max_len = std::max(max_len, length);
    }
    if (FriNextPow2(max_len) !=
            proof.n_coeffs ||
        proof.fold_layers.empty() ||
        proof.fold_challenges.size() !=
            Fri3AlgLog2Exact(
                proof.n_coeffs) ||
        proof.fold_layers.size() !=
            proof.fold_challenges.size() + 1 ||
        proof.queries.size() !=
            kFri3AlgMultiRowQ192Config.query_count ||
        !Fri3AlgClaimedBitsMeetTarget()) {
        return fail("fri_shape");
    }
    Fri3AlgFs fs =
        Fri3AlgMultiRowFsInit(
            fs_seed, proof.pow_grind_nonce,
            proof.n_coeffs, proof.groups,
            proof.column_len);
    uint32_t z_counter = 0;
    Fp3 z1;
    Fp3 z2;
    if (!Fri3AlgBatchSampleZ(
            fs, z_counter, nullptr,
            kFri3AlgMultiRowQ192Config, z1) ||
        !Fri3AlgBatchSampleZ(
            fs, z_counter, &z1,
            kFri3AlgMultiRowQ192Config, z2) ||
        !Eq(z1, proof.z1) ||
        !Eq(z2, proof.z2) ||
        !Fri3AlgHasExtCoord(z1) ||
        !Fri3AlgHasExtCoord(z2) ||
        Fri3AlgPointInDomain(z1, n_lde) ||
        Fri3AlgPointInDomain(z2, n_lde) ||
        Eq(z1, z2)) {
        return fail("ood");
    }
    fs.AbsorbFp3(z1);
    fs.AbsorbFp3(z2);
    for (uint32_t column = 0;
         column < proof.column_len.size();
         ++column) {
        fs.AbsorbFp3(proof.evals_z1[column]);
        fs.AbsorbFp3(proof.evals_z2[column]);
    }
    std::vector<Fp3> coefficients;
    Fp3 encoded;
    if (!ProtocolBatchCoefficients(
            fs, kFri3AlgMultiRowQ192Config,
            static_cast<uint32_t>(
                proof.column_len.size()),
            coefficients, encoded) ||
        !Eq(encoded, proof.lambda)) {
        return fail("batch_coefficients");
    }
    Fp3 w1;
    Fp3 w2;
    if (!ProtocolChallengeFp3(
            fs, kFri3AlgMultiRowQ192Config,
            "fra3_w", 0, w1) ||
        !ProtocolChallengeFp3(
            fs, kFri3AlgMultiRowQ192Config,
            "fra3_w", 1, w2) ||
        !Eq(w1, proof.w1) ||
        !Eq(w2, proof.w2)) {
        return fail("deep_weights");
    }
    fs.AbsorbFp3(w1);
    fs.AbsorbFp3(w2);
    for (uint32_t fold = 0;
         fold < proof.fold_layers.size();
         ++fold) {
        const auto& layer =
            proof.fold_layers[fold];
        const uint32_t expected_size =
            n_lde >> fold;
        if (layer.n_leaves != expected_size) {
            return fail("fold_size");
        }
        fs.AbsorbAlgRoot(layer.root);
        if (fold <
            proof.fold_challenges.size()) {
            Fp3 beta;
            if (!ProtocolChallengeFp3(
                    fs,
                    kFri3AlgMultiRowQ192Config,
                    "fra3_fold", fold, beta) ||
                !Eq(
                    beta,
                    proof.fold_challenges[
                        fold])) {
                return fail("fold_challenge");
            }
        }
    }
    if (proof.fold_layers.back().n_leaves !=
            proof.blowup ||
        !AlgDigestEq(
            AlgMerkleRootConstantLayer(
                proof.final_value,
                proof.blowup),
            proof.fold_layers.back().root)) {
        return fail("terminal");
    }
    Fp3 v1 = Fp3::Zero();
    Fp3 v2 = Fp3::Zero();
    for (uint32_t column = 0;
         column < proof.column_len.size();
         ++column) {
        const uint32_t shift =
            proof.n_coeffs -
            proof.column_len[column];
        v1 = Add(
            v1,
            Mul(
                Mul(
                    coefficients[column],
                    PowFp3(proof.z1, shift)),
                proof.evals_z1[column]));
        v2 = Add(
            v2,
            Mul(
                Mul(
                    coefficients[column],
                    PowFp3(proof.z2, shift)),
                proof.evals_z2[column]));
    }
    for (uint32_t query = 0;
         query < proof.queries.size(); ++query) {
        uint32_t expected_index = 0;
        if (!ProtocolChallengeIndex(
                fs, kFri3AlgMultiRowQ192Config,
                "fra3_query", query, n_lde,
                expected_index)) {
            return fail("query_sampling");
        }
        const auto& opened =
            proof.queries[query];
        if (opened.index != expected_index ||
            opened.group_rows.size() !=
                proof.groups.size() ||
            opened.steps.size() !=
                proof.fold_challenges.size()) {
            return fail("query_shape");
        }
        std::vector<Fp3> row;
        row.reserve(proof.column_len.size());
        for (uint32_t group = 0;
             group < proof.groups.size();
             ++group) {
            const auto& group_row =
                opened.group_rows[group];
            if (group_row.values.size() !=
                    proof.groups[group]
                        .column_count ||
                !VerifyAlgPathForLane(
                    AlgHashRowLeafForLane(
                        group_row.values,
                        opened.index, -1),
                    opened.index,
                    group_row.siblings,
                    proof.groups[group]
                        .row_commit.root,
                    n_lde, -1)) {
                return fail("group_row");
            }
            row.insert(
                row.end(),
                group_row.values.begin(),
                group_row.values.end());
        }
        const Fp3 x =
            DomainPoint(n_lde, opened.index);
        Fp3 ux = Fp3::Zero();
        for (uint32_t column = 0;
             column < row.size(); ++column) {
            const uint32_t shift =
                proof.n_coeffs -
                proof.column_len[column];
            ux = Add(
                ux,
                Mul(
                    Mul(
                        coefficients[column],
                        PowFp3(x, shift)),
                    row[column]));
        }
        const Fp3 expected_g =
            Add(
                Mul(
                    proof.w1,
                    Mul(
                        Sub(ux, v1),
                        Inv(Sub(x, proof.z1)))),
                Mul(
                    proof.w2,
                    Mul(
                        Sub(ux, v2),
                        Inv(Sub(x, proof.z2)))));
        uint32_t index = opened.index;
        Fp3 claimed;
        bool have_claimed = false;
        for (uint32_t fold = 0;
             fold <
                 proof.fold_challenges.size();
             ++fold) {
            Fp3 next;
            std::string fold_why;
            if (!VerifyFoldStep(
                    opened.steps[fold],
                    proof.fold_layers[fold].root,
                    proof.fold_layers[fold]
                        .n_leaves,
                    proof.fold_challenges[fold],
                    index, next, &fold_why)) {
                return fail(
                    "fold_path:" + fold_why);
            }
            const uint32_t half =
                proof.fold_layers[fold]
                    .n_leaves /
                2;
            const Fp3 here =
                index < half
                ? opened.steps[fold].even
                : opened.steps[fold].odd;
            if ((fold == 0 &&
                 !Eq(here, expected_g)) ||
                (fold != 0 && have_claimed &&
                 !Eq(here, claimed))) {
                return fail("deep_or_fold");
            }
            claimed = next;
            have_claimed = true;
            index %= half;
        }
        if (!have_claimed ||
            !Eq(claimed, proof.final_value)) {
            return fail("final_value");
        }
    }
    if (why != nullptr) {
        *why =
            "multi_row_verify:"
            "ordered_roots_one_rlc_deep_fri";
    }
    return true;
}

namespace {

bool MultiRowCodecShape(
    const Fri3AlgMultiRowBatchProof& proof,
    size_t* encoded_size)
{
    if (proof.version !=
            kRCFri3AlgMultiRowBatchProofVersion ||
        proof.blowup != kRCFriBlowup ||
        proof.n_coeffs < 2 ||
        (proof.n_coeffs &
         (proof.n_coeffs - 1)) != 0 ||
        uint64_t{proof.n_coeffs} *
                kRCFriBlowup >
            (uint64_t{1} <<
             kRCFriMaxLdeLog2) ||
        proof.groups.size() != 3 ||
        proof.column_len.empty() ||
        proof.column_len.size() >
            kRCFri3AlgBatchMaxColumns ||
        proof.evals_z1.size() !=
            proof.column_len.size() ||
        proof.evals_z2.size() !=
            proof.column_len.size()) {
        return false;
    }
    const uint32_t n_lde =
        proof.n_coeffs * kRCFriBlowup;
    const uint32_t row_depth =
        Fri3AlgLog2Exact(n_lde);
    const uint32_t folds =
        Fri3AlgLog2Exact(
            proof.n_coeffs);
    const std::array<
        Fri3AlgMultiRowGroupRole, 3>
        roles{
            Fri3AlgMultiRowGroupRole::
                MainTrace,
            Fri3AlgMultiRowGroupRole::
                AuxiliaryTrace,
            Fri3AlgMultiRowGroupRole::
                Quotient};
    uint32_t first = 0;
    for (uint32_t group = 0;
         group < proof.groups.size();
         ++group) {
        const auto& commitment =
            proof.groups[group];
        if (commitment.role != roles[group] ||
            commitment.first_column != first ||
            commitment.column_count == 0 ||
            commitment.column_count >
                proof.column_len.size() -
                    first ||
            commitment.row_commit.n_leaves !=
                n_lde) {
            return false;
        }
        first += commitment.column_count;
    }
    if (first != proof.column_len.size()) {
        return false;
    }
    uint32_t max_len = 0;
    for (uint32_t length : proof.column_len) {
        if (length == 0 ||
            length > proof.n_coeffs) {
            return false;
        }
        max_len = std::max(max_len, length);
    }
    if (FriNextPow2(max_len) !=
            proof.n_coeffs ||
        proof.fold_layers.size() !=
            size_t{folds} + 1 ||
        proof.fold_challenges.size() !=
            folds ||
        proof.queries.size() !=
            kRCFri3AlgNumQueries) {
        return false;
    }
    for (uint32_t fold = 0;
         fold < proof.fold_layers.size();
         ++fold) {
        if (proof.fold_layers[fold]
                .n_leaves !=
            (n_lde >> fold)) {
            return false;
        }
    }
    for (const auto& query : proof.queries) {
        if (query.index >= n_lde ||
            query.group_rows.size() != 3 ||
            query.steps.size() != folds) {
            return false;
        }
        for (uint32_t group = 0;
             group < 3; ++group) {
            if (query.group_rows[group]
                    .values.size() !=
                    proof.groups[group]
                        .column_count ||
                query.group_rows[group]
                    .siblings.size() !=
                    row_depth) {
                return false;
            }
        }
        uint32_t index = query.index;
        for (uint32_t fold = 0;
             fold < folds; ++fold) {
            const auto& step =
                query.steps[fold];
            const uint32_t layer_size =
                n_lde >> fold;
            const uint32_t half =
                layer_size / 2;
            const uint32_t even_index =
                index % half;
            const uint32_t path_depth =
                row_depth - fold;
            if (step.even_index !=
                    even_index ||
                step.odd_index !=
                    even_index + half ||
                step.even_siblings.size() !=
                    path_depth ||
                step.odd_siblings.size() !=
                    path_depth) {
                return false;
            }
            index %= half;
        }
    }

    // Exact size arithmetic is performed before reserve/append. This both
    // prevents wraparound and ensures serialization never temporarily grows
    // beyond the decoder's consensus-facing cap.
    unsigned __int128 bytes = 0;
    const auto add =
        [&](unsigned __int128 amount) {
            bytes += amount;
            return bytes <=
                kRCFri3AlgMultiRowMaxProofBytesHard;
        };
    if (!add(4 + 4 + 8 + 4 + 4 + 4) ||
        !add(
            static_cast<unsigned __int128>(
                proof.groups.size()) *
            (4 + 4 + 4 + 32 + 4)) ||
        !add(
            4 +
            static_cast<unsigned __int128>(
                proof.column_len.size()) *
                4) ||
        !add(3 * 24) ||
        !add(
            4 +
            static_cast<unsigned __int128>(
                proof.evals_z1.size()) *
                24) ||
        !add(
            4 +
            static_cast<unsigned __int128>(
                proof.evals_z2.size()) *
                24) ||
        !add(2 * 24) ||
        !add(
            4 +
            static_cast<unsigned __int128>(
                proof.fold_layers.size()) *
                (32 + 4)) ||
        !add(24) ||
        !add(
            4 +
            static_cast<unsigned __int128>(
                proof.fold_challenges.size()) *
                24) ||
        !add(4)) {
        return false;
    }
    for (const auto& query : proof.queries) {
        if (!add(4 + 4)) return false;
        for (const auto& row :
             query.group_rows) {
            if (!add(
                    4 +
                    static_cast<unsigned __int128>(
                        row.values.size()) *
                        24 +
                    4 +
                    static_cast<unsigned __int128>(
                        row.siblings.size()) *
                        32)) {
                return false;
            }
        }
        if (!add(4)) return false;
        for (const auto& step :
             query.steps) {
            if (!add(
                    4 + 4 + 24 + 24 + 4 +
                    static_cast<unsigned __int128>(
                        step.even_siblings
                            .size()) *
                        32 +
                    4 +
                    static_cast<unsigned __int128>(
                        step.odd_siblings
                            .size()) *
                        32)) {
                return false;
            }
        }
    }
    if (bytes >
        std::numeric_limits<size_t>::max()) {
        return false;
    }
    if (encoded_size != nullptr) {
        *encoded_size =
            static_cast<size_t>(bytes);
    }
    return true;
}

bool HasWireBytes(
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

} // namespace

size_t SerializeFri3AlgMultiRowBatchProof(
    const Fri3AlgMultiRowBatchProof& proof,
    std::vector<unsigned char>& out)
{
    out.clear();
    size_t exact_size = 0;
    if (!MultiRowCodecShape(
            proof, &exact_size)) {
        return 0;
    }
    out.reserve(exact_size);
    AppendLE32(
        out,
        kRCFri3AlgMultiRowBatchProofMagic);
    AppendLE32(out, proof.version);
    AppendLE64(out, proof.pow_grind_nonce);
    AppendLE32(out, proof.blowup);
    AppendLE32(out, proof.n_coeffs);
    AppendLE32(
        out,
        static_cast<uint32_t>(
            proof.groups.size()));
    for (const auto& group : proof.groups) {
        AppendLE32(
            out,
            static_cast<uint32_t>(
                group.role));
        AppendLE32(out, group.first_column);
        AppendLE32(out, group.column_count);
        AppendAlgDigest(
            out, group.row_commit.root);
        AppendLE32(
            out,
            group.row_commit.n_leaves);
    }
    AppendLE32(
        out,
        static_cast<uint32_t>(
            proof.column_len.size()));
    for (uint32_t length :
         proof.column_len) {
        AppendLE32(out, length);
    }
    AppendFp3(out, proof.lambda);
    AppendFp3(out, proof.z1);
    AppendFp3(out, proof.z2);
    AppendLE32(
        out,
        static_cast<uint32_t>(
            proof.evals_z1.size()));
    for (const auto& value :
         proof.evals_z1) {
        AppendFp3(out, value);
    }
    AppendLE32(
        out,
        static_cast<uint32_t>(
            proof.evals_z2.size()));
    for (const auto& value :
         proof.evals_z2) {
        AppendFp3(out, value);
    }
    AppendFp3(out, proof.w1);
    AppendFp3(out, proof.w2);
    AppendLE32(
        out,
        static_cast<uint32_t>(
            proof.fold_layers.size()));
    for (const auto& layer :
         proof.fold_layers) {
        AppendAlgDigest(out, layer.root);
        AppendLE32(out, layer.n_leaves);
    }
    AppendFp3(out, proof.final_value);
    AppendLE32(
        out,
        static_cast<uint32_t>(
            proof.fold_challenges.size()));
    for (const auto& challenge :
         proof.fold_challenges) {
        AppendFp3(out, challenge);
    }
    AppendLE32(
        out,
        static_cast<uint32_t>(
            proof.queries.size()));
    for (const auto& query :
         proof.queries) {
        AppendLE32(out, query.index);
        AppendLE32(
            out,
            static_cast<uint32_t>(
                query.group_rows.size()));
        for (const auto& row :
             query.group_rows) {
            AppendLE32(
                out,
                static_cast<uint32_t>(
                    row.values.size()));
            for (const auto& value :
                 row.values) {
                AppendFp3(out, value);
            }
            AppendLE32(
                out,
                static_cast<uint32_t>(
                    row.siblings.size()));
            for (const auto& sibling :
                 row.siblings) {
                AppendAlgDigest(out, sibling);
            }
        }
        AppendLE32(
            out,
            static_cast<uint32_t>(
                query.steps.size()));
        for (const auto& step :
             query.steps) {
            AppendLE32(out, step.even_index);
            AppendLE32(out, step.odd_index);
            AppendFp3(out, step.even);
            AppendFp3(out, step.odd);
            AppendLE32(
                out,
                static_cast<uint32_t>(
                    step.even_siblings.size()));
            for (const auto& sibling :
                 step.even_siblings) {
                AppendAlgDigest(out, sibling);
            }
            AppendLE32(
                out,
                static_cast<uint32_t>(
                    step.odd_siblings.size()));
            for (const auto& sibling :
                 step.odd_siblings) {
                AppendAlgDigest(out, sibling);
            }
        }
    }
    if (out.size() != exact_size) {
        out.clear();
        return 0;
    }
    return out.size();
}

std::optional<Fri3AlgMultiRowBatchProof>
DeserializeFri3AlgMultiRowBatchProof(
    const std::vector<unsigned char>& in)
{
    if (in.empty() ||
        in.size() >
            kRCFri3AlgMultiRowMaxProofBytesHard) {
        return std::nullopt;
    }
    const unsigned char* p = in.data();
    const unsigned char* end =
        in.data() + in.size();
    uint32_t magic = 0;
    uint32_t version = 0;
    Fri3AlgMultiRowBatchProof proof;
    if (!ReadLE32Checked(p, end, magic) ||
        magic !=
            kRCFri3AlgMultiRowBatchProofMagic ||
        !ReadLE32Checked(p, end, version) ||
        version !=
            kRCFri3AlgMultiRowBatchProofVersion) {
        return std::nullopt;
    }
    proof.version = version;
    if (!ReadLE64Checked(
            p, end,
            proof.pow_grind_nonce) ||
        !ReadLE32Checked(
            p, end, proof.blowup) ||
        proof.blowup != kRCFriBlowup ||
        !ReadLE32Checked(
            p, end, proof.n_coeffs) ||
        proof.n_coeffs < 2 ||
        (proof.n_coeffs &
         (proof.n_coeffs - 1)) != 0 ||
        uint64_t{proof.n_coeffs} *
                kRCFriBlowup >
            (uint64_t{1} <<
             kRCFriMaxLdeLog2)) {
        return std::nullopt;
    }
    const uint32_t n_lde =
        proof.n_coeffs * kRCFriBlowup;
    const uint32_t row_depth =
        Fri3AlgLog2Exact(n_lde);
    const uint32_t folds =
        Fri3AlgLog2Exact(
            proof.n_coeffs);
    uint32_t group_count = 0;
    if (!ReadLE32Checked(
            p, end, group_count) ||
        group_count != 3 ||
        !HasWireBytes(
            p, end, group_count,
            4 + 4 + 4 + 32 + 4)) {
        return std::nullopt;
    }
    proof.groups.resize(group_count);
    const std::array<
        Fri3AlgMultiRowGroupRole, 3>
        roles{
            Fri3AlgMultiRowGroupRole::
                MainTrace,
            Fri3AlgMultiRowGroupRole::
                AuxiliaryTrace,
            Fri3AlgMultiRowGroupRole::
                Quotient};
    uint32_t first = 0;
    for (uint32_t group = 0;
         group < group_count; ++group) {
        uint32_t role = 0;
        auto& commitment =
            proof.groups[group];
        if (!ReadLE32Checked(p, end, role) ||
            role !=
                static_cast<uint32_t>(
                    roles[group]) ||
            !ReadLE32Checked(
                p, end,
                commitment.first_column) ||
            commitment.first_column != first ||
            !ReadLE32Checked(
                p, end,
                commitment.column_count) ||
            commitment.column_count == 0 ||
            commitment.column_count >
                kRCFri3AlgBatchMaxColumns -
                    first ||
            !ReadAlgDigestChecked(
                p, end,
                commitment.row_commit.root) ||
            !ReadLE32Checked(
                p, end,
                commitment.row_commit
                    .n_leaves) ||
            commitment.row_commit.n_leaves !=
                n_lde) {
            return std::nullopt;
        }
        commitment.role = roles[group];
        first += commitment.column_count;
    }
    uint32_t columns = 0;
    if (!ReadLE32Checked(
            p, end, columns) ||
        columns == 0 ||
        columns > kRCFri3AlgBatchMaxColumns ||
        columns != first ||
        !HasWireBytes(p, end, columns, 4)) {
        return std::nullopt;
    }
    proof.column_len.resize(columns);
    uint32_t max_len = 0;
    for (uint32_t& length :
         proof.column_len) {
        if (!ReadLE32Checked(
                p, end, length) ||
            length == 0 ||
            length > proof.n_coeffs) {
            return std::nullopt;
        }
        max_len = std::max(max_len, length);
    }
    if (FriNextPow2(max_len) !=
        proof.n_coeffs) {
        return std::nullopt;
    }
    if (!ReadFp3Checked(
            p, end, proof.lambda, true) ||
        !ReadFp3Checked(
            p, end, proof.z1, true) ||
        !ReadFp3Checked(
            p, end, proof.z2, true)) {
        return std::nullopt;
    }
    uint32_t evaluations = 0;
    if (!ReadLE32Checked(
            p, end, evaluations) ||
        evaluations != columns ||
        !HasWireBytes(
            p, end, evaluations, 24)) {
        return std::nullopt;
    }
    proof.evals_z1.resize(evaluations);
    for (auto& value : proof.evals_z1) {
        if (!ReadFp3Checked(
                p, end, value, true)) {
            return std::nullopt;
        }
    }
    if (!ReadLE32Checked(
            p, end, evaluations) ||
        evaluations != columns ||
        !HasWireBytes(
            p, end, evaluations, 24)) {
        return std::nullopt;
    }
    proof.evals_z2.resize(evaluations);
    for (auto& value : proof.evals_z2) {
        if (!ReadFp3Checked(
                p, end, value, true)) {
            return std::nullopt;
        }
    }
    if (!ReadFp3Checked(
            p, end, proof.w1, true) ||
        !ReadFp3Checked(
            p, end, proof.w2, true)) {
        return std::nullopt;
    }
    uint32_t layer_count = 0;
    if (!ReadLE32Checked(
            p, end, layer_count) ||
        layer_count != folds + 1 ||
        !HasWireBytes(
            p, end, layer_count,
            32 + 4)) {
        return std::nullopt;
    }
    proof.fold_layers.resize(layer_count);
    for (uint32_t fold = 0;
         fold < layer_count; ++fold) {
        auto& layer =
            proof.fold_layers[fold];
        if (!ReadAlgDigestChecked(
                p, end, layer.root) ||
            !ReadLE32Checked(
                p, end, layer.n_leaves) ||
            layer.n_leaves !=
                (n_lde >> fold)) {
            return std::nullopt;
        }
    }
    if (!ReadFp3Checked(
            p, end, proof.final_value,
            true)) {
        return std::nullopt;
    }
    uint32_t challenge_count = 0;
    if (!ReadLE32Checked(
            p, end, challenge_count) ||
        challenge_count != folds ||
        !HasWireBytes(
            p, end, challenge_count, 24)) {
        return std::nullopt;
    }
    proof.fold_challenges.resize(
        challenge_count);
    for (auto& challenge :
         proof.fold_challenges) {
        if (!ReadFp3Checked(
                p, end, challenge, true)) {
            return std::nullopt;
        }
    }
    uint32_t query_count = 0;
    if (!ReadLE32Checked(
            p, end, query_count) ||
        query_count !=
            kRCFri3AlgNumQueries ||
        !HasWireBytes(
            p, end, query_count,
            4 + 4 + 3 * (4 + 4) + 4)) {
        return std::nullopt;
    }
    proof.queries.resize(query_count);
    for (auto& query : proof.queries) {
        uint32_t opened_groups = 0;
        if (!ReadLE32Checked(
                p, end, query.index) ||
            query.index >= n_lde ||
            !ReadLE32Checked(
                p, end, opened_groups) ||
            opened_groups != group_count) {
            return std::nullopt;
        }
        query.group_rows.resize(
            opened_groups);
        for (uint32_t group = 0;
             group < opened_groups;
             ++group) {
            auto& row =
                query.group_rows[group];
            uint32_t value_count = 0;
            if (!ReadLE32Checked(
                    p, end, value_count) ||
                value_count !=
                    proof.groups[group]
                        .column_count ||
                !HasWireBytes(
                    p, end, value_count,
                    24)) {
                return std::nullopt;
            }
            row.values.resize(value_count);
            for (auto& value : row.values) {
                if (!ReadFp3Checked(
                        p, end, value,
                        true)) {
                    return std::nullopt;
                }
            }
            uint32_t sibling_count = 0;
            if (!ReadLE32Checked(
                    p, end,
                    sibling_count) ||
                sibling_count != row_depth ||
                !HasWireBytes(
                    p, end,
                    sibling_count, 32)) {
                return std::nullopt;
            }
            row.siblings.resize(
                sibling_count);
            for (auto& sibling :
                 row.siblings) {
                if (!ReadAlgDigestChecked(
                        p, end, sibling)) {
                    return std::nullopt;
                }
            }
        }
        uint32_t step_count = 0;
        if (!ReadLE32Checked(
                p, end, step_count) ||
            step_count != folds) {
            return std::nullopt;
        }
        query.steps.resize(step_count);
        uint32_t index = query.index;
        for (uint32_t fold = 0;
             fold < step_count; ++fold) {
            auto& step =
                query.steps[fold];
            const uint32_t layer_size =
                n_lde >> fold;
            const uint32_t half =
                layer_size / 2;
            const uint32_t even_index =
                index % half;
            if (!ReadLE32Checked(
                    p, end,
                    step.even_index) ||
                step.even_index !=
                    even_index ||
                !ReadLE32Checked(
                    p, end,
                    step.odd_index) ||
                step.odd_index !=
                    even_index + half ||
                !ReadFp3Checked(
                    p, end, step.even,
                    true) ||
                !ReadFp3Checked(
                    p, end, step.odd,
                    true)) {
                return std::nullopt;
            }
            const uint32_t path_depth =
                row_depth - fold;
            uint32_t sibling_count = 0;
            if (!ReadLE32Checked(
                    p, end,
                    sibling_count) ||
                sibling_count !=
                    path_depth ||
                !HasWireBytes(
                    p, end,
                    sibling_count, 32)) {
                return std::nullopt;
            }
            step.even_siblings.resize(
                sibling_count);
            for (auto& sibling :
                 step.even_siblings) {
                if (!ReadAlgDigestChecked(
                        p, end, sibling)) {
                    return std::nullopt;
                }
            }
            if (!ReadLE32Checked(
                    p, end,
                    sibling_count) ||
                sibling_count !=
                    path_depth ||
                !HasWireBytes(
                    p, end,
                    sibling_count, 32)) {
                return std::nullopt;
            }
            step.odd_siblings.resize(
                sibling_count);
            for (auto& sibling :
                 step.odd_siblings) {
                if (!ReadAlgDigestChecked(
                        p, end, sibling)) {
                    return std::nullopt;
                }
            }
            index %= half;
        }
    }
    if (p != end) return std::nullopt;
    size_t expected_size = 0;
    if (!MultiRowCodecShape(
            proof, &expected_size) ||
        expected_size != in.size()) {
        return std::nullopt;
    }
    std::vector<unsigned char> canonical;
    if (SerializeFri3AlgMultiRowBatchProof(
            proof, canonical) !=
            in.size() ||
        canonical != in) {
        return std::nullopt;
    }
    return proof;
}

Fri3AlgMultiRowPostClaimBindingAudit
AuditFri3AlgMultiRowPostClaimBinding(
    const std::vector<std::vector<std::vector<Fp3>>>& groups,
    const std::vector<Fri3AlgMultiRowGroupRole>& roles,
    const uint256& fs_seed,
    uint64_t pow_grind_nonce)
{
    Fri3AlgMultiRowPostClaimBindingAudit out;
    const auto committed =
        Fri3AlgMultiRowBatchCommitStreaming(
            groups, roles, fs_seed,
            pow_grind_nonce);
    if (!committed.ok) {
        out.note =
            "multi_row_post_claim_audit:commit:" +
            committed.note;
        return out;
    }
    const auto& proof = committed.proof;
    const uint32_t width =
        static_cast<uint32_t>(
            proof.column_len.size());
    if (width < 2) {
        out.note =
            "multi_row_post_claim_audit:width";
        return out;
    }

    // Replay the vulnerable ordering against the same committed group roots:
    // coefficients first, then OOD points and individual claims.
    Fri3AlgFs legacy_fs =
        Fri3AlgMultiRowFsInit(
            fs_seed, pow_grind_nonce,
            proof.n_coeffs, proof.groups,
            proof.column_len);
    std::vector<Fp3> legacy_coefficients;
    Fp3 legacy_encoded;
    if (!ProtocolBatchCoefficients(
            legacy_fs,
            kFri3AlgMultiRowQ192Config,
            width, legacy_coefficients,
            legacy_encoded)) {
        out.note =
            "multi_row_post_claim_audit:"
            "legacy_coefficients";
        return out;
    }
    uint32_t legacy_z_counter = 0;
    Fp3 legacy_z1;
    Fp3 legacy_z2;
    if (!Fri3AlgBatchSampleZ(
            legacy_fs, legacy_z_counter,
            nullptr,
            kFri3AlgMultiRowQ192Config,
            legacy_z1) ||
        !Fri3AlgBatchSampleZ(
            legacy_fs, legacy_z_counter,
            &legacy_z1,
            kFri3AlgMultiRowQ192Config,
            legacy_z2)) {
        out.note =
            "multi_row_post_claim_audit:"
            "legacy_ood";
        return out;
    }

    std::vector<Fp3> legacy_evals_z1(width);
    std::vector<Fp3> legacy_evals_z2(width);
    uint32_t flattened = 0;
    for (const auto& group : groups) {
        for (const auto& column : group) {
            legacy_evals_z1[flattened] =
                EvalPolyCoeffs(
                    column, legacy_z1);
            legacy_evals_z2[flattened] =
                EvalPolyCoeffs(
                    column, legacy_z2);
            ++flattened;
        }
    }
    if (flattened != width) {
        out.note =
            "multi_row_post_claim_audit:"
            "flattened_width";
        return out;
    }

    const auto aggregate =
        [&](const std::vector<Fp3>& evals,
            const Fp3& z) {
            Fp3 value = Fp3::Zero();
            for (uint32_t column = 0;
                 column < width; ++column) {
                const uint32_t shift =
                    proof.n_coeffs -
                    proof.column_len[column];
                value = Add(
                    value,
                    Mul(
                        Mul(
                            legacy_coefficients[column],
                            PowFp3(z, shift)),
                        evals[column]));
            }
            return value;
        };
    const auto add_kernel_delta =
        [&](std::vector<Fp3>& evals,
            const Fp3& z) {
            uint32_t first = width;
            uint32_t second = width;
            Fp3 first_weight;
            Fp3 second_weight;
            for (uint32_t column = 0;
                 column < width; ++column) {
                const uint32_t shift =
                    proof.n_coeffs -
                    proof.column_len[column];
                const Fp3 weight =
                    Mul(
                        legacy_coefficients[column],
                        PowFp3(z, shift));
                if (Eq(weight, Fp3::Zero())) {
                    continue;
                }
                if (first == width) {
                    first = column;
                    first_weight = weight;
                } else {
                    second = column;
                    second_weight = weight;
                    break;
                }
            }
            if (second == width) return false;
            const Fp3 first_delta =
                Fp3::One();
            const Fp3 second_delta =
                Sub(
                    Fp3::Zero(),
                    Mul(
                        first_weight,
                        Inv(second_weight)));
            evals[first] =
                Add(evals[first], first_delta);
            evals[second] =
                Add(evals[second], second_delta);
            return
                !Eq(first_delta, Fp3::Zero()) ||
                !Eq(second_delta, Fp3::Zero());
        };

    const Fp3 honest_legacy_v1 =
        aggregate(legacy_evals_z1, legacy_z1);
    const Fp3 honest_legacy_v2 =
        aggregate(legacy_evals_z2, legacy_z2);
    auto forged_legacy_z1 = legacy_evals_z1;
    auto forged_legacy_z2 = legacy_evals_z2;
    out.legacy_nonzero_kernel_constructed =
        add_kernel_delta(
            forged_legacy_z1, legacy_z1) &&
        add_kernel_delta(
            forged_legacy_z2, legacy_z2);
    out.legacy_aggregate_z1_preserved =
        out.legacy_nonzero_kernel_constructed &&
        Eq(
            honest_legacy_v1,
            aggregate(
                forged_legacy_z1, legacy_z1));
    out.legacy_aggregate_z2_preserved =
        out.legacy_nonzero_kernel_constructed &&
        Eq(
            honest_legacy_v2,
            aggregate(
                forged_legacy_z2, legacy_z2));

    // Apply the same explicit nonzero deltas to a V2 proof. V2 absorbs the
    // altered claims before it draws the batching vector.
    auto forged = proof;
    for (uint32_t column = 0;
         column < width; ++column) {
        forged.evals_z1[column] =
            Add(
                forged.evals_z1[column],
                Sub(
                    forged_legacy_z1[column],
                    legacy_evals_z1[column]));
        forged.evals_z2[column] =
            Add(
                forged.evals_z2[column],
                Sub(
                    forged_legacy_z2[column],
                    legacy_evals_z2[column]));
    }
    Fri3AlgFs fixed_fs =
        Fri3AlgMultiRowFsInit(
            fs_seed, pow_grind_nonce,
            forged.n_coeffs, forged.groups,
            forged.column_len);
    uint32_t fixed_z_counter = 0;
    Fp3 fixed_z1;
    Fp3 fixed_z2;
    if (!Fri3AlgBatchSampleZ(
            fixed_fs, fixed_z_counter, nullptr,
            kFri3AlgMultiRowQ192Config,
            fixed_z1) ||
        !Fri3AlgBatchSampleZ(
            fixed_fs, fixed_z_counter, &fixed_z1,
            kFri3AlgMultiRowQ192Config,
            fixed_z2) ||
        !Eq(fixed_z1, forged.z1) ||
        !Eq(fixed_z2, forged.z2)) {
        out.note =
            "multi_row_post_claim_audit:"
            "fixed_ood";
        return out;
    }
    fixed_fs.AbsorbFp3(fixed_z1);
    fixed_fs.AbsorbFp3(fixed_z2);
    for (uint32_t column = 0;
         column < width; ++column) {
        fixed_fs.AbsorbFp3(
            forged.evals_z1[column]);
        fixed_fs.AbsorbFp3(
            forged.evals_z2[column]);
    }
    std::vector<Fp3> fixed_coefficients;
    Fp3 fixed_encoded;
    if (!ProtocolBatchCoefficients(
            fixed_fs,
            kFri3AlgMultiRowQ192Config,
            width, fixed_coefficients,
            fixed_encoded)) {
        out.note =
            "multi_row_post_claim_audit:"
            "fixed_coefficients";
        return out;
    }
    out.fixed_batch_challenge_changed =
        !Eq(fixed_encoded, proof.lambda);
    std::string verify_why;
    out.fixed_verifier_rejected =
        !Fri3AlgMultiRowBatchVerify(
            forged, fs_seed, &verify_why);
    out.valid =
        out.legacy_nonzero_kernel_constructed &&
        out.legacy_aggregate_z1_preserved &&
        out.legacy_aggregate_z2_preserved &&
        out.fixed_batch_challenge_changed &&
        out.fixed_verifier_rejected;
    out.note = out.valid
        ? "multi_row_post_claim_audit:"
          "legacy_kernel_closed_by_v2"
        : "multi_row_post_claim_audit:"
          "regression_failed";
    return out;
}

bool Fri3AlgForgeFlippedEvalMustFail(const Fri3AlgBatchCommitResult& honest,
                                     const uint256& fs_seed, uint32_t flip_col,
                                     uint32_t flip_index, std::string* why)
{
    if (!honest.ok || honest.column_lde.empty()) {
        if (why) *why = "no honest proof";
        return false; // forge helper itself failed — not a verify-pass
    }
    Fri3AlgBatchProof forged = honest.proof;
    const uint32_t W = static_cast<uint32_t>(honest.column_lde.size());
    const uint32_t n_lde = forged.row_commit.n_leaves;
    const uint32_t c = flip_col % W;
    const uint32_t idx = flip_index % n_lde;
    // Flip one LDE eval conceptually: recompute ONLY the row root from the
    // tampered value while retaining the honest openings.
    std::vector<std::vector<Fp3>> tampered = honest.column_lde;
    tampered[c][idx].c0 ^= 1;
    forged.row_commit.root = BuildAlgMerkleTreeFromLeaves(RowLeafDigests(tampered, n_lde)).root;
    // Old queries/openings → inconsistent with the new root (and the FS replay,
    // since the row root seeds every challenge).
    std::string local;
    const bool ok = Fri3AlgBatchVerify(forged, fs_seed, &local);
    if (why) *why = ok ? "FORGE PASSED (bug)" : local;
    return !ok; // true iff verify correctly rejected
}

size_t SerializeFri3AlgBatchProof(const Fri3AlgBatchProof& proof, std::vector<unsigned char>& out)
{
    out.clear();
    AppendLE32(out, kRCFri3AlgBatchProofMagic);
    AppendLE32(out, proof.version);
    AppendLE64(out, proof.pow_grind_nonce);
    AppendLE32(out, proof.blowup);
    AppendLE32(out, proof.n_coeffs);
    AppendAlgDigest(out, proof.row_commit.root);
    AppendLE32(out, proof.row_commit.n_leaves);
    AppendLE32(out, static_cast<uint32_t>(proof.column_len.size()));
    for (const uint32_t len : proof.column_len) AppendLE32(out, len);
    AppendFp3(out, proof.lambda);
    AppendFp3(out, proof.z1);
    AppendFp3(out, proof.z2);
    AppendLE32(out, static_cast<uint32_t>(proof.evals_z1.size()));
    for (const auto& e : proof.evals_z1) AppendFp3(out, e);
    AppendLE32(out, static_cast<uint32_t>(proof.evals_z2.size()));
    for (const auto& e : proof.evals_z2) AppendFp3(out, e);
    AppendFp3(out, proof.w1);
    AppendFp3(out, proof.w2);
    AppendLE32(out, static_cast<uint32_t>(proof.fold_layers.size()));
    for (const auto& lc : proof.fold_layers) {
        AppendAlgDigest(out, lc.root);
        AppendLE32(out, lc.n_leaves);
    }
    AppendFp3(out, proof.final_value);
    AppendLE32(out, static_cast<uint32_t>(proof.fold_challenges.size()));
    for (const auto& c : proof.fold_challenges) AppendFp3(out, c);
    AppendLE32(out, static_cast<uint32_t>(proof.queries.size()));
    for (const auto& q : proof.queries) {
        AppendLE32(out, q.index);
        AppendLE32(out, static_cast<uint32_t>(q.row.values.size()));
        for (const auto& v : q.row.values) AppendFp3(out, v);
        AppendLE32(out, static_cast<uint32_t>(q.row.siblings.size()));
        for (const auto& s : q.row.siblings) AppendAlgDigest(out, s);
        AppendLE32(out, static_cast<uint32_t>(q.steps.size()));
        for (const auto& st : q.steps) {
            AppendLE32(out, st.even_index);
            AppendLE32(out, st.odd_index);
            AppendFp3(out, st.even);
            AppendFp3(out, st.odd);
            AppendLE32(out, static_cast<uint32_t>(st.even_siblings.size()));
            for (const auto& s : st.even_siblings) AppendAlgDigest(out, s);
            AppendLE32(out, static_cast<uint32_t>(st.odd_siblings.size()));
            for (const auto& s : st.odd_siblings) AppendAlgDigest(out, s);
        }
    }
    return out.size();
}

std::optional<Fri3AlgBatchProof> DeserializeFri3AlgBatchProofConfigured(
    const std::vector<unsigned char>& in, uint32_t expected_version,
    uint32_t max_queries, bool require_canonical_fp3)
{
    if (in.size() > kRCFriMaxProofBytesHard) return std::nullopt;
    const unsigned char* p = in.data();
    const unsigned char* end = in.data() + in.size();
    uint32_t magic = 0, version = 0;
    if (!ReadLE32Checked(p, end, magic) || magic != kRCFri3AlgBatchProofMagic) return std::nullopt;
    if (!ReadLE32Checked(p, end, version) || version != expected_version)
        return std::nullopt;
    Fri3AlgBatchProof proof;
    proof.version = version;
    if (!ReadLE64Checked(p, end, proof.pow_grind_nonce)) return std::nullopt;
    if (!ReadLE32Checked(p, end, proof.blowup)) return std::nullopt;
    if (!ReadLE32Checked(p, end, proof.n_coeffs)) return std::nullopt;
    if (!ReadAlgDigestChecked(p, end, proof.row_commit.root)) return std::nullopt;
    if (!ReadLE32Checked(p, end, proof.row_commit.n_leaves)) return std::nullopt;
    uint32_t n_cols = 0;
    if (!ReadLE32Checked(p, end, n_cols) || n_cols == 0 || n_cols > kRCFri3AlgBatchMaxColumns)
        return std::nullopt;
    proof.column_len.resize(n_cols);
    for (auto& len : proof.column_len) {
        if (!ReadLE32Checked(p, end, len)) return std::nullopt;
    }
    if (!ReadFp3Checked(p, end, proof.lambda, require_canonical_fp3)) return std::nullopt;
    if (!ReadFp3Checked(p, end, proof.z1, require_canonical_fp3)) return std::nullopt;
    if (!ReadFp3Checked(p, end, proof.z2, require_canonical_fp3)) return std::nullopt;
    uint32_t n_e1 = 0, n_e2 = 0;
    if (!ReadLE32Checked(p, end, n_e1) || n_e1 != n_cols) return std::nullopt;
    proof.evals_z1.resize(n_e1);
    for (auto& e : proof.evals_z1) {
        if (!ReadFp3Checked(p, end, e, require_canonical_fp3)) return std::nullopt;
    }
    if (!ReadLE32Checked(p, end, n_e2) || n_e2 != n_cols) return std::nullopt;
    proof.evals_z2.resize(n_e2);
    for (auto& e : proof.evals_z2) {
        if (!ReadFp3Checked(p, end, e, require_canonical_fp3)) return std::nullopt;
    }
    if (!ReadFp3Checked(p, end, proof.w1, require_canonical_fp3)) return std::nullopt;
    if (!ReadFp3Checked(p, end, proof.w2, require_canonical_fp3)) return std::nullopt;
    uint32_t n_layers = 0;
    if (!ReadLE32Checked(p, end, n_layers) || n_layers == 0 || n_layers > 64) return std::nullopt;
    proof.fold_layers.resize(n_layers);
    for (auto& lc : proof.fold_layers) {
        if (!ReadAlgDigestChecked(p, end, lc.root)) return std::nullopt;
        if (!ReadLE32Checked(p, end, lc.n_leaves)) return std::nullopt;
    }
    if (!ReadFp3Checked(p, end, proof.final_value, require_canonical_fp3))
        return std::nullopt;
    uint32_t n_ch = 0;
    if (!ReadLE32Checked(p, end, n_ch) || n_ch > 64) return std::nullopt;
    proof.fold_challenges.resize(n_ch);
    for (auto& c : proof.fold_challenges) {
        if (!ReadFp3Checked(p, end, c, require_canonical_fp3)) return std::nullopt;
    }
    uint32_t n_q = 0;
    if (!ReadLE32Checked(p, end, n_q) || n_q > max_queries ||
        n_q > kRCFri3AlgMaxQueriesHard) {
        return std::nullopt;
    }
    proof.queries.resize(n_q);
    for (auto& q : proof.queries) {
        if (!ReadLE32Checked(p, end, q.index)) return std::nullopt;
        uint32_t n_rv = 0;
        if (!ReadLE32Checked(p, end, n_rv) || n_rv != n_cols) return std::nullopt;
        q.row.values.resize(n_rv);
        for (auto& v : q.row.values) {
            if (!ReadFp3Checked(p, end, v, require_canonical_fp3)) return std::nullopt;
        }
        uint32_t n_rs = 0;
        if (!ReadLE32Checked(p, end, n_rs) || n_rs > 64) return std::nullopt;
        q.row.siblings.resize(n_rs);
        for (auto& s : q.row.siblings) {
            if (!ReadAlgDigestChecked(p, end, s)) return std::nullopt;
        }
        uint32_t n_steps = 0;
        if (!ReadLE32Checked(p, end, n_steps) || n_steps > 64) return std::nullopt;
        q.steps.resize(n_steps);
        for (auto& st : q.steps) {
            if (!ReadLE32Checked(p, end, st.even_index)) return std::nullopt;
            if (!ReadLE32Checked(p, end, st.odd_index)) return std::nullopt;
            if (!ReadFp3Checked(p, end, st.even, require_canonical_fp3))
                return std::nullopt;
            if (!ReadFp3Checked(p, end, st.odd, require_canonical_fp3))
                return std::nullopt;
            uint32_t n_es = 0, n_os = 0;
            if (!ReadLE32Checked(p, end, n_es) || n_es > 64) return std::nullopt;
            st.even_siblings.resize(n_es);
            for (auto& s : st.even_siblings) {
                if (!ReadAlgDigestChecked(p, end, s)) return std::nullopt;
            }
            if (!ReadLE32Checked(p, end, n_os) || n_os > 64) return std::nullopt;
            st.odd_siblings.resize(n_os);
            for (auto& s : st.odd_siblings) {
                if (!ReadAlgDigestChecked(p, end, s)) return std::nullopt;
            }
        }
    }
    if (p != end) return std::nullopt;
    return proof;
}

std::optional<Fri3AlgBatchProof> DeserializeFri3AlgBatchProof(
    const std::vector<unsigned char>& in)
{
    return DeserializeFri3AlgBatchProofConfigured(
        in, kRCFri3AlgActiveBatchProofVersion, kRCFri3AlgMaxQueriesHard,
        /*require_canonical_fp3=*/false);
}

namespace {

uint256 Fri3AlgDualLaneSeed(const uint256& fs_seed, uint64_t pow_grind_nonce,
                            uint32_t lane,
                            const Fri3AlgDualProtocolSuite& suite =
                                kFri3AlgDualQ128V5Suite)
{
    std::vector<unsigned char> buf;
    AppendBytes(
        buf,
        reinterpret_cast<const unsigned char*>(
            suite.envelope_domain_tag),
        std::strlen(suite.envelope_domain_tag));
    AppendLE32(buf, suite.envelope_version);
    static constexpr char kLaneLabel[] = "lane";
    AppendBytes(buf, reinterpret_cast<const unsigned char*>(kLaneLabel),
                sizeof(kLaneLabel) - 1);
    AppendLE32(buf, lane);
    AppendBytes(buf, fs_seed.data(), 32);
    AppendLE64(buf, pow_grind_nonce);
    return Sha256dBytes(buf.data(), buf.size());
}

bool Fri3AlgDualSameStatement(const Fri3AlgBatchProof& a,
                              const Fri3AlgBatchProof& b)
{
    return a.pow_grind_nonce == b.pow_grind_nonce &&
           a.blowup == b.blowup &&
           a.n_coeffs == b.n_coeffs &&
           a.row_commit.n_leaves == b.row_commit.n_leaves &&
           a.column_len == b.column_len;
}

uint256 Fri3AlgDualMasterBinding(const uint256& fs_seed,
                                const Fri3AlgBatchProof& lane0,
                                const Fri3AlgBatchProof& lane1,
                                const Fri3AlgDualProtocolSuite& suite =
                                    kFri3AlgDualQ128V5Suite)
{
    std::vector<unsigned char> buf;
    AppendBytes(
        buf,
        reinterpret_cast<const unsigned char*>(
            suite.master_binding_domain_tag),
        std::strlen(suite.master_binding_domain_tag));
    AppendLE32(buf, suite.envelope_version);
    AppendBytes(buf, fs_seed.data(), 32);
    AppendLE64(buf, lane0.pow_grind_nonce);
    AppendLE32(buf, lane0.blowup);
    AppendLE32(buf, lane0.n_coeffs);
    AppendLE32(buf, lane0.row_commit.n_leaves);
    AppendLE32(buf, static_cast<uint32_t>(lane0.column_len.size()));
    for (const uint32_t len : lane0.column_len) AppendLE32(buf, len);
    AppendAlgDigest(buf, lane0.row_commit.root);
    AppendAlgDigest(buf, lane1.row_commit.root);
    return Sha256dBytes(buf.data(), buf.size());
}

uint256 Fri3AlgDualChildBinding(const uint256& master, uint32_t lane,
                               const Fri3AlgDigest& row_root,
                               const Fri3AlgDualProtocolSuite& suite =
                                   kFri3AlgDualQ128V5Suite)
{
    std::vector<unsigned char> buf;
    AppendBytes(
        buf,
        reinterpret_cast<const unsigned char*>(
            suite.child_binding_domain_tag),
        std::strlen(suite.child_binding_domain_tag));
    AppendLE32(buf, suite.envelope_version);
    AppendLE32(buf, suite.lane_version);
    AppendLE32(buf, lane);
    const char* lane_domain =
        lane == 0 ? suite.lane0_domain_tag
                  : suite.lane1_domain_tag;
    AppendBytes(
        buf, reinterpret_cast<const unsigned char*>(lane_domain),
        std::strlen(lane_domain));
    AppendBytes(buf, master.data(), 32);
    AppendAlgDigest(buf, row_root);
    return Sha256dBytes(buf.data(), buf.size());
}

bool Fri3AlgDualBindingsMatch(const Fri3AlgDualBatchProof& proof,
                              const uint256& fs_seed,
                              const Fri3AlgDualProtocolSuite& suite =
                                  kFri3AlgDualQ128V5Suite)
{
    const uint256 master =
        Fri3AlgDualMasterBinding(
            fs_seed, proof.lane[0], proof.lane[1],
            suite);
    if (master != proof.master_statement_binding) return false;
    for (uint32_t lane = 0; lane < kRCFri3AlgDualNumLanes; ++lane) {
        if (Fri3AlgDualChildBinding(
                master, lane,
                proof.lane[lane].row_commit.root,
                suite) !=
            proof.lane_child_binding[lane]) {
            return false;
        }
    }
    return true;
}

} // namespace

namespace {

Fri3AlgDualBatchCommitResult Fri3AlgDualBatchCommitForScenarioImpl(
    const std::vector<std::vector<Fp3>>& columns, const uint256& fs_seed,
    Fri3AlgDualCommitmentScenario scenario, uint64_t pow_grind_nonce,
    bool stream_column_lde,
    const Fri3AlgDualProtocolSuite& suite =
        kFri3AlgDualQ128V5Suite)
{
    Fri3AlgDualBatchCommitResult out;
    out.proof.version = suite.envelope_version;
    if (!KnownDualCommitmentScenario(scenario)) {
        out.note = "dual prover: unknown commitment scenario";
        return out;
    }
    AlgMerkleTree shared_streaming_row_tree;
    for (uint32_t lane = 0; lane < kRCFri3AlgDualNumLanes; ++lane) {
        const uint256 lane_seed =
            Fri3AlgDualLaneSeed(
                fs_seed, pow_grind_nonce, lane,
                suite);
        const Fri3AlgProtocolConfig config =
            DualLaneConfigForScenario(
                lane, scenario, suite);
        const AlgMerkleTree* reused_row_tree =
            stream_column_lde && lane > 0
                ? &shared_streaming_row_tree
                : nullptr;
        AlgMerkleTree* built_row_tree =
            stream_column_lde && lane == 0
                ? &shared_streaming_row_tree
                : nullptr;
        Fri3AlgBatchCommitResult lane_result =
            Fri3AlgBatchCommitConfigured(columns, lane_seed, pow_grind_nonce,
                                         config, stream_column_lde,
                                         reused_row_tree, built_row_tree);
        if (!lane_result.ok) {
            out.note = "dual lane " + std::to_string(lane) + ": " + lane_result.note;
            return out;
        }
        if (lane == 0) out.column_lde = std::move(lane_result.column_lde);
        out.proof.lane[lane] = std::move(lane_result.proof);
    }
    if (!Fri3AlgDualSameStatement(out.proof.lane[0], out.proof.lane[1])) {
        out.note = "dual prover produced different lane statements";
        return out;
    }
    if (scenario ==
            Fri3AlgDualCommitmentScenario::SharedMasterDerivedChildren &&
        !AlgDigestEq(out.proof.lane[0].row_commit.root,
                     out.proof.lane[1].row_commit.root)) {
        out.note = "dual prover produced different shared row commitments";
        return out;
    }
    out.proof.master_statement_binding =
        Fri3AlgDualMasterBinding(
            fs_seed, out.proof.lane[0],
            out.proof.lane[1], suite);
    for (uint32_t lane = 0; lane < kRCFri3AlgDualNumLanes; ++lane) {
        out.proof.lane_child_binding[lane] =
            Fri3AlgDualChildBinding(
                out.proof.master_statement_binding, lane,
                out.proof.lane[lane].row_commit.root,
                suite);
    }
    std::vector<unsigned char> encoded;
    out.proof_bytes =
        suite.envelope_version ==
                kRCFri3AlgDualProofVersion
            ? SerializeFri3AlgDualBatchProof(
                  out.proof, encoded)
            : SerializeFri3AlgDualQ136BatchProof(
                  out.proof, encoded);
    if (out.proof_bytes == 0 ||
        out.proof_bytes > suite.max_proof_bytes) {
        out.note = "dual proof exceeds codec bound";
        return out;
    }
    out.ok = true;
    if (stream_column_lde) {
        out.note =
            std::string("experimental ") +
            suite.name +
            " shared-master proof with two-pass "
            "column-streaming row commitment; binding hybrid pending";
    } else {
        out.note = scenario ==
                Fri3AlgDualCommitmentScenario::SharedMasterDerivedChildren
            ? std::string("experimental ") + suite.name +
              " independent batching with shared AlgHash master; "
              "binding hybrid pending"
            : std::string("experimental ") + suite.name +
              " independent batching with fully lane-prefixed AlgHash "
              "trees; NIROP reduction pending";
    }
    return out;
}

} // namespace

Fri3AlgDualBatchCommitResult Fri3AlgDualBatchCommitForScenario(
    const std::vector<std::vector<Fp3>>& columns, const uint256& fs_seed,
    Fri3AlgDualCommitmentScenario scenario, uint64_t pow_grind_nonce)
{
    return Fri3AlgDualBatchCommitForScenarioImpl(
        columns, fs_seed, scenario, pow_grind_nonce,
        /*stream_column_lde=*/false,
        kFri3AlgDualQ128V5Suite);
}

Fri3AlgDualBatchCommitResult Fri3AlgDualBatchCommitStreamingShared(
    const std::vector<std::vector<Fp3>>& columns, const uint256& fs_seed,
    uint64_t pow_grind_nonce)
{
    return Fri3AlgDualBatchCommitForScenarioImpl(
        columns, fs_seed,
        Fri3AlgDualCommitmentScenario::SharedMasterDerivedChildren,
        pow_grind_nonce, /*stream_column_lde=*/true,
        kFri3AlgDualQ128V5Suite);
}

Fri3AlgDualBatchCommitResult
Fri3AlgDualQ136BatchCommit(
    const std::vector<std::vector<Fp3>>& columns,
    const uint256& fs_seed,
    uint64_t pow_grind_nonce)
{
    return Fri3AlgDualQ136BatchCommitForScenario(
        columns, fs_seed,
        Fri3AlgDualCommitmentScenario::
            SharedMasterDerivedChildren,
        pow_grind_nonce);
}

Fri3AlgDualBatchCommitResult
Fri3AlgDualQ136BatchCommitForScenario(
    const std::vector<std::vector<Fp3>>& columns,
    const uint256& fs_seed,
    Fri3AlgDualCommitmentScenario scenario,
    uint64_t pow_grind_nonce)
{
    return Fri3AlgDualBatchCommitForScenarioImpl(
        columns, fs_seed, scenario,
        pow_grind_nonce,
        /*stream_column_lde=*/false,
        kFri3AlgDualQ136V6Suite);
}

Fri3AlgDualBatchCommitResult
Fri3AlgDualQ136BatchCommitStreamingShared(
    const std::vector<std::vector<Fp3>>& columns,
    const uint256& fs_seed,
    uint64_t pow_grind_nonce)
{
    return Fri3AlgDualBatchCommitForScenarioImpl(
        columns, fs_seed,
        Fri3AlgDualCommitmentScenario::
            SharedMasterDerivedChildren,
        pow_grind_nonce,
        /*stream_column_lde=*/true,
        kFri3AlgDualQ136V6Suite);
}

Fri3AlgDualBatchCommitResult Fri3AlgDualBatchCommit(
    const std::vector<std::vector<Fp3>>& columns, const uint256& fs_seed,
    uint64_t pow_grind_nonce)
{
    return Fri3AlgDualBatchCommitForScenario(
        columns, fs_seed,
        Fri3AlgDualCommitmentScenario::SharedMasterDerivedChildren,
        pow_grind_nonce);
}

Fri3AlgFoldSpillReplayAudit
AuditFri3AlgDualFoldSpillReplay(
    const std::vector<std::vector<Fp3>>& columns,
    const uint256& fs_seed,
    const Fri3AlgFoldLayerWriteCallback& write_layer,
    const Fri3AlgFoldLayerReadCallback& read_layer,
    uint64_t pow_grind_nonce)
{
    Fri3AlgFoldSpillReplayAudit out;
    if (!write_layer || !read_layer) {
        out.note = "fold spill audit: callbacks missing";
        return out;
    }
    const Fri3AlgDualBatchCommitResult dense =
        Fri3AlgDualBatchCommit(
            columns, fs_seed, pow_grind_nonce);
    if (!dense.ok) {
        out.note =
            "fold spill audit dense: " + dense.note;
        return out;
    }
    const Fri3AlgDualTranscriptWitness transcript =
        BuildFri3AlgDualTranscriptWitness(
            dense.proof, fs_seed);
    if (!transcript.valid) {
        out.note =
            "fold spill audit transcript: " +
            transcript.note;
        return out;
    }
    Fri3AlgDualBatchProof replayed = dense.proof;
    out.lanes = kRCFri3AlgDualNumLanes;
    out.fold_values_roundtrip = true;
    out.layer_roots_identical = true;
    out.query_paths_identical = true;
    std::string callback_why;

    auto same_step =
        [](const Fri3AlgFoldStep& a,
           const Fri3AlgFoldStep& b) {
            return
                a.even_index == b.even_index &&
                a.odd_index == b.odd_index &&
                Eq(a.even, b.even) &&
                Eq(a.odd, b.odd) &&
                a.even_siblings ==
                    b.even_siblings &&
                a.odd_siblings ==
                    b.odd_siblings;
        };

    for (uint32_t lane = 0;
         lane < kRCFri3AlgDualNumLanes; ++lane) {
        const Fri3AlgBatchProof& proof =
            dense.proof.lane[lane];
        if (proof.column_len.size() != columns.size() ||
            transcript.lane[lane].
                    batch_coefficients.size() !=
                columns.size()) {
            out.note =
                "fold spill audit: column shape";
            return out;
        }
        const uint32_t n = proof.n_coeffs;
        std::vector<Fp3> U(n, Fp3::Zero());
        for (uint32_t column = 0;
             column < columns.size(); ++column) {
            if (columns[column].size() !=
                proof.column_len[column] ||
                columns[column].size() > n) {
                out.note =
                    "fold spill audit: column length";
                return out;
            }
            const uint32_t shift =
                n - proof.column_len[column];
            const Fp3 coefficient =
                transcript.lane[lane].
                    batch_coefficients[column];
            for (uint32_t item = 0;
                 item < columns[column].size();
                 ++item) {
                U[shift + item] =
                    Add(
                        U[shift + item],
                        Mul(
                            coefficient,
                            columns[column][item]));
            }
        }
        Fp3 v1 = Fp3::Zero();
        Fp3 v2 = Fp3::Zero();
        for (uint32_t column = 0;
             column < columns.size(); ++column) {
            const uint32_t shift =
                n - proof.column_len[column];
            const Fp3 coefficient =
                transcript.lane[lane].
                    batch_coefficients[column];
            v1 = Add(
                v1, Mul(
                        Mul(
                            coefficient,
                            PowFp3(proof.z1, shift)),
                        proof.evals_z1[column]));
            v2 = Add(
                v2, Mul(
                        Mul(
                            coefficient,
                            PowFp3(proof.z2, shift)),
                        proof.evals_z2[column]));
        }
        std::vector<Fp3> q1 =
            SyntheticQuotient(U, proof.z1, v1);
        std::vector<Fp3> q2 =
            SyntheticQuotient(U, proof.z2, v2);
        q1.resize(n, Fp3::Zero());
        q2.resize(n, Fp3::Zero());
        std::vector<Fp3> G(n);
        for (uint32_t item = 0; item < n; ++item) {
            G[item] = Add(
                Mul(proof.w1, q1[item]),
                Mul(proof.w2, q2[item]));
        }
        std::vector<Fp3> current =
            LdeFromCoeffs(G, kRCFriBlowup);
        std::vector<uint32_t> query_indices;
        query_indices.reserve(proof.queries.size());
        for (const auto& query : proof.queries) {
            query_indices.push_back(query.index);
        }
        const uint32_t n_folds =
            Fri3AlgLog2Exact(n);
        for (uint32_t layer = 0;
             layer <= n_folds; ++layer) {
            if (!write_layer(
                    lane, layer, current,
                    &callback_why)) {
                out.note =
                    "fold spill audit write: " +
                    callback_why;
                return out;
            }
            std::vector<Fp3> loaded;
            if (!read_layer(
                    lane, layer,
                    static_cast<uint32_t>(
                        current.size()),
                    loaded, &callback_why)) {
                out.note =
                    "fold spill audit read: " +
                    callback_why;
                return out;
            }
            ++out.layers_spilled;
            out.evaluations_spilled +=
                loaded.size();
            if (loaded.size() != current.size()) {
                out.fold_values_roundtrip = false;
                out.note =
                    "fold spill audit: loaded size";
                return out;
            }
            for (uint32_t item = 0;
                 item < loaded.size(); ++item) {
                if (!Eq(loaded[item], current[item])) {
                    out.fold_values_roundtrip = false;
                    out.note =
                        "fold spill audit: loaded value";
                    return out;
                }
            }
            const AlgMerkleTree tree =
                BuildAlgMerkleTree(loaded);
            if (layer >= proof.fold_layers.size() ||
                !AlgDigestEq(
                    tree.root,
                    proof.fold_layers[layer].root) ||
                loaded.size() !=
                    proof.fold_layers[layer].
                        n_leaves) {
                out.layer_roots_identical = false;
                out.note =
                    "fold spill audit: layer root";
                return out;
            }
            replayed.lane[lane].
                fold_layers[layer].root =
                    tree.root;
            if (layer == n_folds) break;
            for (uint32_t query = 0;
                 query < proof.queries.size();
                 ++query) {
                const Fri3AlgFoldStep step =
                    OpenFoldStep(
                        loaded, tree,
                        query_indices[query]);
                if (layer >=
                        proof.queries[query].
                            steps.size() ||
                    !same_step(
                        step,
                        proof.queries[query].
                            steps[layer])) {
                    out.query_paths_identical = false;
                    out.note =
                        "fold spill audit: query path";
                    return out;
                }
                replayed.lane[lane].
                    queries[query].steps[layer] =
                        step;
                ++out.paths_replayed;
                query_indices[query] %=
                    loaded.size() / 2;
            }
            std::vector<Fp3> next;
            if (!HalfDomainFoldLayer(
                    loaded,
                    proof.fold_challenges[layer],
                    next)) {
                out.note =
                    "fold spill audit: fold";
                return out;
            }
            current = std::move(next);
        }
    }

    std::vector<unsigned char> dense_bytes;
    std::vector<unsigned char> replayed_bytes;
    const size_t dense_size =
        SerializeFri3AlgDualBatchProof(
            dense.proof, dense_bytes);
    const size_t replayed_size =
        SerializeFri3AlgDualBatchProof(
            replayed, replayed_bytes);
    out.dense_proof_bytes_identical =
        dense_size != 0 &&
        dense_size == replayed_size &&
        dense_bytes == replayed_bytes;

    const Fri3AlgDualBatchCommitResult streamed =
        Fri3AlgDualBatchCommitStreamingShared(
            columns, fs_seed, pow_grind_nonce);
    if (!streamed.ok) {
        out.note =
            "fold spill audit streaming: " +
            streamed.note;
        return out;
    }
    std::vector<unsigned char> streamed_bytes;
    const size_t streamed_size =
        SerializeFri3AlgDualBatchProof(
            streamed.proof, streamed_bytes);
    out.streaming_proof_bytes_identical =
        streamed_size == dense_size &&
        streamed_bytes == dense_bytes;
    std::string verify_why;
    out.replayed_proof_verified =
        Fri3AlgDualBatchVerify(
            replayed, fs_seed, &verify_why);
    out.executable_bounded_audit = true;
    out.valid =
        out.fold_values_roundtrip &&
        out.layer_roots_identical &&
        out.query_paths_identical &&
        out.dense_proof_bytes_identical &&
        out.streaming_proof_bytes_identical &&
        out.replayed_proof_verified;
    out.note =
        out.valid
            ? "bounded fold spill/path replay is byte-identical"
            : "bounded fold spill/path replay mismatch: " +
                  verify_why;
    return out;
}

namespace {

template <typename Fn>
void FixtureParallelFor(uint32_t count, Fn&& fn)
{
    if (count < 1024) {
        for (uint32_t i = 0; i < count; ++i) fn(i);
        return;
    }
    const uint32_t workers = std::min<uint32_t>(
        {std::max<uint32_t>(1, std::thread::hardware_concurrency()),
         count, 16});
    const uint32_t chunk = (count + workers - 1) / workers;
    std::vector<std::future<void>> jobs;
    jobs.reserve(workers);
    for (uint32_t worker = 0; worker < workers; ++worker) {
        const uint32_t begin = worker * chunk;
        const uint32_t end = std::min<uint32_t>(count, begin + chunk);
        if (begin >= end) break;
        jobs.push_back(std::async(
            std::launch::async,
            [begin, end, &fn]() {
                for (uint32_t i = begin; i < end; ++i) fn(i);
            }));
    }
    for (auto& job : jobs) job.get();
}

template <typename LeafFn>
AlgMerkleTree BuildFixtureMerkleTree(
    uint32_t n_leaves, LeafFn&& leaf_fn, uint64_t& nodes_built)
{
    AlgMerkleTree tree;
    if (n_leaves == 0 || (n_leaves & (n_leaves - 1)) != 0) {
        return tree;
    }
    tree.levels.emplace_back(n_leaves);
    FixtureParallelFor(
        n_leaves,
        [&](uint32_t index) {
            tree.levels[0][index] = leaf_fn(index);
        });
    nodes_built += n_leaves;
    uint32_t width = n_leaves;
    while (width > 1) {
        const uint32_t next_width = width / 2;
        std::vector<Fri3AlgDigest> next(next_width);
        const auto& current = tree.levels.back();
        FixtureParallelFor(
            next_width,
            [&](uint32_t index) {
                next[index] = alg_hash::Compress(
                    current[2 * index], current[2 * index + 1]);
            });
        nodes_built += next_width;
        tree.levels.push_back(std::move(next));
        width = next_width;
    }
    tree.root = tree.levels.back()[0];
    return tree;
}

/**
 * Zero row leaf without repeating the 3W-zero sponge prefix for every index.
 * LeafHashRow([0;W],i) executes floor(3W/8) identical zero-rate blocks, then
 * absorbs the remaining zero coordinates, i and the mandatory `1` padding.
 */
class ZeroRowLeafFactory
{
private:
    alg_hash::State m_prefix{};
    uint32_t m_pending_zeroes{0};

public:
    explicit ZeroRowLeafFactory(uint32_t batch_columns)
    {
        const uint64_t coordinates =
            3 * static_cast<uint64_t>(batch_columns);
        const uint64_t full_blocks =
            coordinates / alg_hash::kAlgHashRate;
        m_pending_zeroes =
            static_cast<uint32_t>(
                coordinates % alg_hash::kAlgHashRate);
        for (uint64_t block = 0; block < full_blocks; ++block) {
            // Add-absorbing a full all-zero rate block changes no lane.
            alg_hash::Permute(m_prefix);
        }
    }

    Fri3AlgDigest operator()(uint32_t index) const
    {
        alg_hash::State state = m_prefix;
        uint32_t pending = m_pending_zeroes;
        auto absorb =
            [&](Fp value) {
                state[pending] =
                    Add(state[pending], Canonical(value));
                if (++pending == alg_hash::kAlgHashRate) {
                    alg_hash::Permute(state);
                    pending = 0;
                }
            };
        absorb(gkr_field::FromU64(index));
        absorb(gkr_field::FromU64(1)); // injective 10* padding marker
        if (pending != 0) {
            // The remaining padding lanes are zero.
            alg_hash::Permute(state);
        }
        return {state[0], state[1], state[2], state[3]};
    }
};

} // namespace

Fri3AlgDualZeroVerifierFixtureResult
BuildFri3AlgDualZeroVerifierFixture(
    uint32_t batch_columns, uint32_t n_coeffs,
    const uint256& fs_seed, uint64_t pow_grind_nonce)
{
    Fri3AlgDualZeroVerifierFixtureResult out;
    auto fail = [&](const std::string& reason) {
        out.note = "zero verifier fixture: " + reason;
        return out;
    };
    if (batch_columns == 0 ||
        batch_columns > kRCFri3AlgBatchMaxColumns) {
        return fail("bad column count");
    }
    if (n_coeffs == 0 ||
        (n_coeffs & (n_coeffs - 1)) != 0 ||
        n_coeffs > (uint64_t{1} << kRCFriMaxColumnLog2)) {
        return fail("bad coefficient domain");
    }
    const uint64_t n_lde_wide =
        static_cast<uint64_t>(n_coeffs) * kRCFriBlowup;
    if (n_lde_wide >
            (uint64_t{1} << kRCFriMaxLdeLog2) ||
        n_lde_wide > std::numeric_limits<uint32_t>::max()) {
        return fail("LDE guard");
    }
    const uint32_t n_lde = static_cast<uint32_t>(n_lde_wide);
    const uint32_t n_folds = Fri3AlgLog2Exact(n_coeffs);

    // These are honest, complete, index-bound trees.  Index binding means
    // zero-valued leaves are not repeated digests, so no O(log N) shortcut is
    // sound.  Retaining the levels avoids rebuilding all trees after FS fixes
    // the query indices.
    const ZeroRowLeafFactory row_leaf(batch_columns);
    AlgMerkleTree row_tree =
        BuildFixtureMerkleTree(
            n_lde, row_leaf, out.merkle_nodes_built);
    if (row_tree.levels.empty()) return fail("row tree construction");

    std::vector<AlgMerkleTree> fold_trees;
    fold_trees.reserve(static_cast<size_t>(n_folds) + 1);
    uint32_t fold_width = n_lde;
    for (uint32_t layer = 0; layer <= n_folds; ++layer) {
        fold_trees.push_back(
            BuildFixtureMerkleTree(
                fold_width,
                [](uint32_t index) {
                    return alg_hash::LeafHash(
                        Fp3::Zero(), index);
                },
                out.merkle_nodes_built));
        if (fold_trees.back().levels.empty()) {
            return fail("fold tree construction");
        }
        if (layer < n_folds) fold_width /= 2;
    }
    if (fold_width != kRCFriBlowup) {
        return fail("terminal fold width");
    }

    for (uint32_t lane = 0;
         lane < kRCFri3AlgDualNumLanes; ++lane) {
        Fri3AlgBatchProof& proof = out.proof.lane[lane];
        proof.version = kRCFri3AlgDualLaneProofVersion;
        proof.pow_grind_nonce = pow_grind_nonce;
        proof.blowup = kRCFriBlowup;
        proof.n_coeffs = n_coeffs;
        proof.row_commit = {row_tree.root, n_lde};
        proof.column_len.assign(batch_columns, n_coeffs);
        proof.evals_z1.assign(batch_columns, Fp3::Zero());
        proof.evals_z2.assign(batch_columns, Fp3::Zero());
        proof.final_value = Fp3::Zero();

        const Fri3AlgProtocolConfig config =
            DualLaneConfigForScenario(
                lane,
                Fri3AlgDualCommitmentScenario::
                    SharedMasterDerivedChildren);
        const uint256 lane_seed =
            Fri3AlgDualLaneSeed(
                fs_seed, pow_grind_nonce, lane);
        Fri3AlgFs fs =
            Fri3AlgBatchFsInit(
                lane_seed, pow_grind_nonce, n_coeffs,
                proof.row_commit, proof.column_len, config);

        std::vector<Fp3> batch_coefficients;
        if (!ProtocolBatchCoefficients(
                fs, config, batch_columns,
                batch_coefficients, proof.lambda)) {
            return fail("batch coefficient sampling exhausted");
        }
        uint32_t z_counter = 0;
        if (!Fri3AlgBatchSampleZ(
                fs, z_counter, nullptr, config, proof.z1) ||
            !Fri3AlgBatchSampleZ(
                fs, z_counter, &proof.z1, config, proof.z2)) {
            return fail("bounded OOD selection exhausted");
        }
        fs.AbsorbFp3(proof.z1);
        fs.AbsorbFp3(proof.z2);
        for (uint32_t column = 0;
             column < batch_columns; ++column) {
            fs.AbsorbFp3(Fp3::Zero());
            fs.AbsorbFp3(Fp3::Zero());
        }
        if (!ProtocolChallengeFp3(
                fs, config, "fra3_w", 0, proof.w1) ||
            !ProtocolChallengeFp3(
                fs, config, "fra3_w", 1, proof.w2)) {
            return fail("DEEP weight sampling exhausted");
        }
        fs.AbsorbFp3(proof.w1);
        fs.AbsorbFp3(proof.w2);

        proof.fold_layers.reserve(fold_trees.size());
        proof.fold_challenges.reserve(n_folds);
        for (uint32_t layer = 0;
             layer < fold_trees.size(); ++layer) {
            const uint32_t layer_width = n_lde >> layer;
            proof.fold_layers.push_back(
                {fold_trees[layer].root, layer_width});
            fs.AbsorbAlgRoot(fold_trees[layer].root);
            if (layer < n_folds) {
                Fp3 beta{};
                if (!ProtocolChallengeFp3(
                        fs, config, "fra3_fold",
                        layer, beta)) {
                    return fail("fold challenge sampling exhausted");
                }
                proof.fold_challenges.push_back(beta);
            }
        }

        proof.queries.reserve(
            kRCFri3AlgDualQueriesPerLane);
        for (uint32_t query = 0;
             query < kRCFri3AlgDualQueriesPerLane; ++query) {
            Fri3AlgBatchQuery opening;
            if (!ProtocolChallengeIndex(
                    fs, config, "fra3_query", query,
                    n_lde, opening.index)) {
                return fail("query-index sampling failed");
            }
            opening.row.values.assign(
                batch_columns, Fp3::Zero());
            opening.row.siblings =
                PathFromAlgTree(row_tree, opening.index);
            opening.steps.reserve(n_folds);
            uint32_t index = opening.index;
            for (uint32_t layer = 0;
                 layer < n_folds; ++layer) {
                const uint32_t layer_width = n_lde >> layer;
                const uint32_t half = layer_width / 2;
                const uint32_t even_index = index % half;
                Fri3AlgFoldStep step;
                step.even_index = even_index;
                step.odd_index = even_index + half;
                step.even = Fp3::Zero();
                step.odd = Fp3::Zero();
                step.even_siblings =
                    PathFromAlgTree(
                        fold_trees[layer], step.even_index);
                step.odd_siblings =
                    PathFromAlgTree(
                        fold_trees[layer], step.odd_index);
                opening.steps.push_back(std::move(step));
                index = even_index;
            }
            proof.queries.push_back(std::move(opening));
        }
    }

    out.proof.master_statement_binding =
        Fri3AlgDualMasterBinding(
            fs_seed, out.proof.lane[0], out.proof.lane[1]);
    for (uint32_t lane = 0;
         lane < kRCFri3AlgDualNumLanes; ++lane) {
        out.proof.lane_child_binding[lane] =
            Fri3AlgDualChildBinding(
                out.proof.master_statement_binding, lane,
                out.proof.lane[lane].row_commit.root);
    }
    std::vector<unsigned char> encoded;
    out.proof_bytes =
        SerializeFri3AlgDualBatchProof(out.proof, encoded);
    if (out.proof_bytes == 0) {
        return fail("canonical serialization");
    }
    out.ok = true;
    out.note =
        "diagnostic all-zero V5 verifier fixture; exact index-bound "
        "Merkle paths, no FFTs; not episode completeness or prover cost";
    return out;
}

static Fri3AlgDualTranscriptProgram
BuildFri3AlgDualTranscriptProgramConfigured(
    const Fri3AlgDualBatchProof& proof,
    const Fri3AlgDualProtocolSuite& suite)
{
    Fri3AlgDualTranscriptProgram out;
    out.envelope_version =
        suite.envelope_version;
    out.lane_version =
        suite.lane_version;
    out.queries_per_lane =
        suite.queries_per_lane;
    auto fail = [&](const std::string& reason) {
        out.note = reason;
        return out;
    };
    if (proof.version != suite.envelope_version) {
        return fail("dual transcript program: bad envelope version");
    }
    if (!Fri3AlgDualSameStatement(
            proof.lane[0], proof.lane[1])) {
        return fail(
            "dual transcript program: lane statement mismatch");
    }
    const Fri3AlgBatchProof& first = proof.lane[0];
    if (first.version != suite.lane_version ||
        proof.lane[1].version !=
            suite.lane_version) {
        return fail("dual transcript program: bad lane version");
    }
    if (first.column_len.empty() ||
        first.column_len.size() >
            kRCFri3AlgBatchMaxColumns) {
        return fail("dual transcript program: bad column count");
    }
    if (first.n_coeffs == 0 ||
        (first.n_coeffs & (first.n_coeffs - 1)) != 0) {
        return fail("dual transcript program: bad coefficient domain");
    }
    const uint64_t n_lde =
        static_cast<uint64_t>(first.n_coeffs) *
        first.blowup;
    if (n_lde >
            std::numeric_limits<uint32_t>::max() ||
        first.row_commit.n_leaves != n_lde) {
        return fail("dual transcript program: bad LDE domain");
    }
    const uint32_t folds =
        Fri3AlgLog2Exact(first.n_coeffs);
    for (uint32_t lane = 0;
         lane < kRCFri3AlgDualNumLanes; ++lane) {
        if (proof.lane[lane].fold_challenges.size() !=
                folds ||
            proof.lane[lane].fold_layers.size() !=
                static_cast<uint64_t>(folds) + 1 ||
            proof.lane[lane].queries.size() !=
                suite.queries_per_lane) {
            return fail(
                "dual transcript program: non-canonical lane schedule");
        }
    }

    out.batch_columns =
        static_cast<uint32_t>(first.column_len.size());
    out.n_coeffs = first.n_coeffs;
    out.n_lde = static_cast<uint32_t>(n_lde);
    out.fold_challenges_per_lane = folds;
    out.independent_batch_draws_per_lane =
        out.batch_columns;
    out.uniform_fp3_draws_per_lane =
        static_cast<uint64_t>(out.batch_columns) +
        out.ood_draws_per_lane +
        out.deep_weight_draws_per_lane +
        out.fold_challenges_per_lane;
    out.uniform_fp3_hashes_per_lane =
        out.uniform_fp3_draws_per_lane *
        kRCFri3AlgDualUniformHashBlocks;
    out.query_index_hashes_per_lane =
        suite.queries_per_lane;
    out.challenge_hashes_total =
        kRCFri3AlgDualNumLanes *
        (out.uniform_fp3_hashes_per_lane +
         out.query_index_hashes_per_lane);
    out.fixed_ood_schedule = true;
    out.independent_batching = true;
    out.lane_order_semantic = true;
    out.valid = true;
    out.note =
        std::string("canonical finite ") +
        suite.name + " transcript program";
    return out;
}

Fri3AlgDualTranscriptProgram
BuildFri3AlgDualTranscriptProgram(
    const Fri3AlgDualBatchProof& proof)
{
    return
        BuildFri3AlgDualTranscriptProgramConfigured(
            proof, kFri3AlgDualQ128V5Suite);
}

Fri3AlgDualTranscriptProgram
BuildFri3AlgDualQ136TranscriptProgram(
    const Fri3AlgDualBatchProof& proof)
{
    return
        BuildFri3AlgDualTranscriptProgramConfigured(
            proof, kFri3AlgDualQ136V6Suite);
}

static Fri3AlgDualTranscriptWitness
BuildFri3AlgDualTranscriptWitnessConfigured(
    const Fri3AlgDualBatchProof& proof,
    const uint256& fs_seed,
    const Fri3AlgDualProtocolSuite& suite)
{
    Fri3AlgDualTranscriptWitness out;
    auto fail = [&](const std::string& reason) {
        out.note = reason;
        return out;
    };

    out.program =
        BuildFri3AlgDualTranscriptProgramConfigured(
            proof, suite);
    if (!out.program.valid) return fail(out.program.note);
    if (proof.version != suite.envelope_version) {
        return fail("dual transcript: bad envelope version");
    }
    if (!Fri3AlgDualSameStatement(
            proof.lane[0], proof.lane[1])) {
        return fail("dual transcript: lane statement mismatch");
    }
    out.common_statement_bound = true;

    out.master_statement_binding =
        Fri3AlgDualMasterBinding(
            fs_seed, proof.lane[0], proof.lane[1],
            suite);
    if (out.master_statement_binding !=
        proof.master_statement_binding) {
        return fail("dual transcript: master binding mismatch");
    }
    for (uint32_t lane = 0;
         lane < kRCFri3AlgDualNumLanes; ++lane) {
        out.lane_child_binding[lane] =
            Fri3AlgDualChildBinding(
                out.master_statement_binding, lane,
                proof.lane[lane].row_commit.root,
                suite);
        if (out.lane_child_binding[lane] !=
            proof.lane_child_binding[lane]) {
            return fail(
                "dual transcript: child binding mismatch");
        }
    }
    out.ordered_lanes_bound = true;

    for (uint32_t lane = 0;
         lane < kRCFri3AlgDualNumLanes; ++lane) {
        const Fri3AlgBatchProof& lane_proof =
            proof.lane[lane];
        Fri3AlgDualLaneTranscriptWitness& lane_out =
            out.lane[lane];
        lane_out.lane = lane;

        auto lane_fail = [&](const std::string& reason) {
            lane_out.note = reason;
            out.note =
                "dual transcript lane " +
                std::to_string(lane) + ": " + reason;
            return out;
        };

        if (lane_proof.version !=
            suite.lane_version) {
            return lane_fail("bad lane version");
        }
        if (lane_proof.column_len.empty() ||
            lane_proof.column_len.size() >
                kRCFri3AlgBatchMaxColumns) {
            return lane_fail("bad column count");
        }
        if (lane_proof.queries.size() !=
            suite.queries_per_lane) {
            return lane_fail("bad query count");
        }
        if (lane_proof.fold_layers.empty() ||
            lane_proof.fold_challenges.size() + 1 !=
                lane_proof.fold_layers.size()) {
            return lane_fail("bad fold shape");
        }
        if (lane_proof.evals_z1.size() !=
                lane_proof.column_len.size() ||
            lane_proof.evals_z2.size() !=
                lane_proof.column_len.size()) {
            return lane_fail("bad evaluation count");
        }
        if (lane_proof.n_coeffs == 0 ||
            lane_proof.row_commit.n_leaves == 0) {
            return lane_fail("bad common domain");
        }

        const Fri3AlgProtocolConfig& config =
            DualLaneConfig(lane, suite);
        lane_out.lane_seed =
            Fri3AlgDualLaneSeed(
                fs_seed,
                lane_proof.pow_grind_nonce, lane,
                suite);
        Fri3AlgFs fs =
            Fri3AlgBatchFsInit(
                lane_out.lane_seed,
                lane_proof.pow_grind_nonce,
                lane_proof.n_coeffs,
                lane_proof.row_commit,
                lane_proof.column_len,
                config);

        Fp3 encoded_first{};
        if (!ProtocolBatchCoefficients(
                fs, config,
                static_cast<uint32_t>(
                    lane_proof.column_len.size()),
                lane_out.batch_coefficients,
                encoded_first)) {
            return lane_fail(
                "batch coefficient sampling exhausted");
        }
        if (!Eq(encoded_first, lane_proof.lambda)) {
            return lane_fail("batch coefficient mismatch");
        }
        lane_out.independent_coefficients_replayed = true;

        uint32_t candidate_index = 0;
        for (Fp3& candidate :
             lane_out.ood_candidates) {
            if (!ProtocolChallengeFp3(
                    fs, config, "fra3_z",
                    candidate_index++, candidate)) {
                return lane_fail(
                    "OOD candidate sampling exhausted");
            }
        }
        bool selected_z1 = false;
        for (uint32_t i = 0;
             i < kRCFri3AlgDualOodCandidates; ++i) {
            const Fp3& candidate =
                lane_out.ood_candidates[i];
            if (!Fri3AlgHasExtCoord(candidate)) continue;
            lane_out.selected_z1 = candidate;
            selected_z1 = true;
            break;
        }
        bool selected_z2 = false;
        for (uint32_t i = kRCFri3AlgDualOodCandidates;
             i < 2 * kRCFri3AlgDualOodCandidates; ++i) {
            const Fp3& candidate =
                lane_out.ood_candidates[i];
            if (!Fri3AlgHasExtCoord(candidate) ||
                Eq(candidate, lane_out.selected_z1)) {
                continue;
            }
            lane_out.selected_z2 = candidate;
            selected_z2 = true;
            break;
        }
        if (!selected_z1 || !selected_z2) {
            return lane_fail("bounded OOD selection exhausted");
        }
        if (!Eq(lane_out.selected_z1, lane_proof.z1) ||
            !Eq(lane_out.selected_z2, lane_proof.z2)) {
            return lane_fail("OOD selection mismatch");
        }
        fs.AbsorbFp3(lane_out.selected_z1);
        fs.AbsorbFp3(lane_out.selected_z2);
        lane_out.fixed_ood_schedule_replayed = true;

        for (uint32_t i = 0;
             i < lane_proof.column_len.size(); ++i) {
            fs.AbsorbFp3(lane_proof.evals_z1[i]);
            fs.AbsorbFp3(lane_proof.evals_z2[i]);
        }
        if (!ProtocolChallengeFp3(
                fs, config, "fra3_w", 0, lane_out.w1) ||
            !ProtocolChallengeFp3(
                fs, config, "fra3_w", 1, lane_out.w2)) {
            return lane_fail(
                "DEEP weight sampling exhausted");
        }
        if (!Eq(lane_out.w1, lane_proof.w1) ||
            !Eq(lane_out.w2, lane_proof.w2)) {
            return lane_fail("DEEP weight mismatch");
        }
        fs.AbsorbFp3(lane_out.w1);
        fs.AbsorbFp3(lane_out.w2);

        lane_out.fold_challenges.reserve(
            lane_proof.fold_challenges.size());
        for (uint32_t i = 0;
             i < lane_proof.fold_layers.size(); ++i) {
            fs.AbsorbAlgRoot(
                lane_proof.fold_layers[i].root);
            if (i + 1 <
                lane_proof.fold_layers.size()) {
                Fp3 challenge{};
                if (!ProtocolChallengeFp3(
                        fs, config, "fra3_fold", i,
                        challenge)) {
                    return lane_fail(
                        "fold sampling exhausted");
                }
                lane_out.fold_challenges.push_back(
                    challenge);
                if (!Eq(
                        challenge,
                        lane_proof.fold_challenges[i])) {
                    return lane_fail(
                        "fold challenge mismatch");
                }
            }
        }
        lane_out.folds_replayed = true;

        lane_out.query_indices.reserve(
            suite.queries_per_lane);
        for (uint32_t query = 0;
             query < suite.queries_per_lane;
             ++query) {
            uint32_t index = 0;
            if (!ProtocolChallengeIndex(
                    fs, config, "fra3_query", query,
                    lane_proof.row_commit.n_leaves,
                    index)) {
                return lane_fail(
                    "query-index sampling failed");
            }
            lane_out.query_indices.push_back(index);
            if (index !=
                lane_proof.queries[query].index) {
                return lane_fail(
                    "query-index mismatch");
            }
        }
        lane_out.queries_replayed = true;
        lane_out.valid = true;
        lane_out.note =
            std::string(suite.name) +
            " lane transcript replay ok";
    }

    out.valid = true;
    out.note =
        std::string(suite.name) +
        " ordered transcript replay ok";
    return out;
}

Fri3AlgDualTranscriptWitness
BuildFri3AlgDualTranscriptWitness(
    const Fri3AlgDualBatchProof& proof,
    const uint256& fs_seed)
{
    return
        BuildFri3AlgDualTranscriptWitnessConfigured(
            proof, fs_seed,
            kFri3AlgDualQ128V5Suite);
}

Fri3AlgDualTranscriptWitness
BuildFri3AlgDualQ136TranscriptWitness(
    const Fri3AlgDualBatchProof& proof,
    const uint256& fs_seed)
{
    return
        BuildFri3AlgDualTranscriptWitnessConfigured(
            proof, fs_seed,
            kFri3AlgDualQ136V6Suite);
}

static bool Fri3AlgDualBatchVerifyForScenarioConfigured(
    const Fri3AlgDualBatchProof& proof, const uint256& fs_seed,
    Fri3AlgDualCommitmentScenario scenario,
    const Fri3AlgDualProtocolSuite& suite,
    std::string* why)
{
    auto fail = [&](const std::string& reason) {
        if (why) *why = reason;
        return false;
    };
    if (!KnownDualCommitmentScenario(scenario))
        return fail("dual: unknown commitment scenario");
    if (proof.version != suite.envelope_version)
        return fail("dual: bad envelope version");
    if (!Fri3AlgDualSameStatement(proof.lane[0], proof.lane[1]))
        return fail("dual: lane statement mismatch");
    if (scenario ==
            Fri3AlgDualCommitmentScenario::SharedMasterDerivedChildren &&
        !AlgDigestEq(proof.lane[0].row_commit.root,
                     proof.lane[1].row_commit.root)) {
        // The selected hybrid has one common row commitment.  Merely hashing
        // two unrelated roots into the outer "master" changes it into a
        // different two-commitment protocol and invalidates the advertised
        // common-commitment reduction boundary.
        return fail("dual: shared row commitment mismatch");
    }
    if (!Fri3AlgDualBindingsMatch(
            proof, fs_seed, suite))
        return fail("dual: master/child binding mismatch");
    if (proof.lane[0].version !=
            suite.lane_version ||
        proof.lane[1].version !=
            suite.lane_version) {
        return fail("dual: bad lane version");
    }
    if (proof.lane[0].queries.size() !=
            suite.queries_per_lane ||
        proof.lane[1].queries.size() !=
            suite.queries_per_lane) {
        return fail("dual: lane query count");
    }
    const int proximity_bits =
        suite.queries_per_lane ==
                kRCFri3AlgDualQ136QueriesPerLane
            ? Fri3AlgDualQ136ProximityBoundBits()
            : Fri3AlgDualProximityBoundBits();
    if (proximity_bits <
        kRCFri3AlgTargetSoundnessBits) {
        return fail("dual: proximity parameters");
    }

    // The two complete repetitions are independent verification jobs after
    // the common-statement/binding checks above.  Allocate cores to these
    // outer jobs first; parallelizing inner Merkle paths while leaving the
    // second lane idle measured worse on production hardware.
    std::array<std::future<std::pair<bool, std::string>>,
               kRCFri3AlgDualNumLanes>
        lane_jobs;
    for (uint32_t lane = 0;
         lane < kRCFri3AlgDualNumLanes; ++lane) {
        lane_jobs[lane] = std::async(
            std::launch::async,
            [&, lane]() {
                const uint256 lane_seed =
                    Fri3AlgDualLaneSeed(
                        fs_seed,
                        proof.lane[lane].pow_grind_nonce,
                        lane, suite);
                std::string lane_why;
                const Fri3AlgProtocolConfig config =
                    DualLaneConfigForScenario(
                        lane, scenario, suite);
                const bool accepted =
                    Fri3AlgBatchVerifyConfigured(
                        proof.lane[lane], lane_seed,
                        config, &lane_why);
                return std::make_pair(
                    accepted, std::move(lane_why));
            });
    }
    for (uint32_t lane = 0;
         lane < kRCFri3AlgDualNumLanes; ++lane) {
        const auto result = lane_jobs[lane].get();
        if (!result.first) {
            return fail(
                "dual: lane " + std::to_string(lane) +
                ": " + result.second);
        }
    }
    if (why) {
        *why =
            std::string(
                "Fri3AlgDualBatchVerify ok (") +
            suite.name +
            " independent batching; "
            "common-commitment hybrid reduction pending)";
    }
    return true;
}

bool Fri3AlgDualBatchVerifyForScenario(
    const Fri3AlgDualBatchProof& proof,
    const uint256& fs_seed,
    Fri3AlgDualCommitmentScenario scenario,
    std::string* why)
{
    return
        Fri3AlgDualBatchVerifyForScenarioConfigured(
            proof, fs_seed, scenario,
            kFri3AlgDualQ128V5Suite, why);
}

bool Fri3AlgDualBatchVerify(const Fri3AlgDualBatchProof& proof,
                            const uint256& fs_seed, std::string* why)
{
    return Fri3AlgDualBatchVerifyForScenario(
        proof, fs_seed,
        Fri3AlgDualCommitmentScenario::SharedMasterDerivedChildren,
        why);
}

bool Fri3AlgDualQ136BatchVerify(
    const Fri3AlgDualBatchProof& proof,
    const uint256& fs_seed, std::string* why)
{
    return Fri3AlgDualQ136BatchVerifyForScenario(
        proof, fs_seed,
        Fri3AlgDualCommitmentScenario::
            SharedMasterDerivedChildren,
        why);
}

bool Fri3AlgDualQ136BatchVerifyForScenario(
    const Fri3AlgDualBatchProof& proof,
    const uint256& fs_seed,
    Fri3AlgDualCommitmentScenario scenario,
    std::string* why)
{
    return
        Fri3AlgDualBatchVerifyForScenarioConfigured(
            proof, fs_seed, scenario,
            kFri3AlgDualQ136V6Suite, why);
}

static std::optional<size_t>
EstimateFri3AlgDualBatchProofBytesConfigured(
    uint32_t batch_columns, uint32_t n_coeffs,
    uint32_t queries_per_lane)
{
    if (batch_columns == 0 ||
        batch_columns > kRCFri3AlgBatchMaxColumns ||
        n_coeffs == 0 ||
        (n_coeffs & (n_coeffs - 1)) != 0 ||
        n_coeffs > (uint64_t{1} << kRCFriMaxColumnLog2) ||
        static_cast<uint64_t>(n_coeffs) * kRCFriBlowup >
            (uint64_t{1} << kRCFriMaxLdeLog2)) {
        return std::nullopt;
    }

    const uint64_t folds = Fri3AlgLog2Exact(n_coeffs);
    const uint64_t row_path_depth = folds + 4; // blowup = 2^4
    const uint64_t width = batch_columns;
    constexpr uint64_t FP3_BYTES = 24;
    constexpr uint64_t DIGEST_BYTES = 32;
    const uint64_t queries = queries_per_lane;

    // Fixed lane prefix through query count:
    // header/row shape + column lengths + lambda/z1/z2 + two evaluation
    // vectors + w1/w2 + fold-layer roots + terminal + fold challenges.
    const unsigned __int128 lane_fixed =
        64 +
        4 * static_cast<unsigned __int128>(width) +
        3 * FP3_BYTES +
        2 * (4 + FP3_BYTES *
                     static_cast<unsigned __int128>(width)) +
        2 * FP3_BYTES +
        4 + 36 * static_cast<unsigned __int128>(folds + 1) +
        FP3_BYTES +
        4 + FP3_BYTES * static_cast<unsigned __int128>(folds) +
        4;

    // Query row opening followed by every half-domain fold opening. At fold L
    // both values are opened against a tree of depth row_path_depth-L.
    const unsigned __int128 fold_path_depth_sum =
        static_cast<unsigned __int128>(folds) * row_path_depth -
        static_cast<unsigned __int128>(folds) * (folds - 1) / 2;
    const unsigned __int128 query_bytes =
        16 +
        FP3_BYTES * static_cast<unsigned __int128>(width) +
        DIGEST_BYTES * row_path_depth +
        64 * static_cast<unsigned __int128>(folds) +
        64 * fold_path_depth_sum;
    const unsigned __int128 lane_bytes =
        lane_fixed + queries * query_bytes;

    // Dual envelope: magic/version/lane count, master, two child bindings,
    // then lane id + encoded-size prefix for each lane.
    const unsigned __int128 total =
        124 + kRCFri3AlgDualNumLanes * lane_bytes;
    if (total > std::numeric_limits<size_t>::max()) {
        return std::nullopt;
    }
    return static_cast<size_t>(total);
}

std::optional<size_t>
EstimateFri3AlgDualBatchProofBytes(
    uint32_t batch_columns, uint32_t n_coeffs)
{
    return
        EstimateFri3AlgDualBatchProofBytesConfigured(
            batch_columns, n_coeffs,
            kRCFri3AlgDualQueriesPerLane);
}

std::optional<size_t>
EstimateFri3AlgDualQ136BatchProofBytes(
    uint32_t batch_columns, uint32_t n_coeffs)
{
    return
        EstimateFri3AlgDualBatchProofBytesConfigured(
            batch_columns, n_coeffs,
            kRCFri3AlgDualQ136QueriesPerLane);
}

static size_t
SerializeFri3AlgDualBatchProofConfigured(
    const Fri3AlgDualBatchProof& proof,
    std::vector<unsigned char>& out,
    const Fri3AlgDualProtocolSuite& suite)
{
    out.clear();
    if (proof.version != suite.envelope_version) {
        return 0;
    }
    AppendLE32(out, suite.envelope_magic);
    AppendLE32(out, proof.version);
    AppendLE32(out, kRCFri3AlgDualNumLanes);
    AppendBytes(out, proof.master_statement_binding.data(), 32);
    for (const uint256& child : proof.lane_child_binding) {
        AppendBytes(out, child.data(), 32);
    }
    for (uint32_t lane = 0; lane < kRCFri3AlgDualNumLanes; ++lane) {
        if (proof.lane[lane].version !=
                suite.lane_version ||
            proof.lane[lane].queries.size() !=
                suite.queries_per_lane) {
            out.clear();
            return 0;
        }
        std::vector<unsigned char> encoded_lane;
        const size_t encoded_size =
            SerializeFri3AlgBatchProof(proof.lane[lane], encoded_lane);
        if (encoded_size != encoded_lane.size()) {
            out.clear();
            return 0;
        }
        if (encoded_lane.size() > kRCFriMaxProofBytesHard) {
            out.clear();
            return 0;
        }
        AppendLE32(out, lane);
        AppendLE32(out, static_cast<uint32_t>(encoded_lane.size()));
        AppendBytes(out, encoded_lane.data(), encoded_lane.size());
    }
    if (out.size() > suite.max_proof_bytes) {
        out.clear();
        return 0;
    }
    return out.size();
}

size_t SerializeFri3AlgDualBatchProof(
    const Fri3AlgDualBatchProof& proof,
    std::vector<unsigned char>& out)
{
    return SerializeFri3AlgDualBatchProofConfigured(
        proof, out, kFri3AlgDualQ128V5Suite);
}

size_t SerializeFri3AlgDualQ136BatchProof(
    const Fri3AlgDualBatchProof& proof,
    std::vector<unsigned char>& out)
{
    return SerializeFri3AlgDualBatchProofConfigured(
        proof, out, kFri3AlgDualQ136V6Suite);
}

static std::optional<Fri3AlgDualBatchProof>
DeserializeFri3AlgDualBatchProofConfigured(
    const std::vector<unsigned char>& in,
    const Fri3AlgDualProtocolSuite& suite)
{
    if (in.size() > suite.max_proof_bytes)
        return std::nullopt;
    const unsigned char* p = in.data();
    const unsigned char* end = in.data() + in.size();
    uint32_t magic = 0;
    uint32_t version = 0;
    uint32_t lane_count = 0;
    if (!ReadLE32Checked(p, end, magic) ||
        magic != suite.envelope_magic)
        return std::nullopt;
    if (!ReadLE32Checked(p, end, version) ||
        version != suite.envelope_version) {
        return std::nullopt;
    }
    if (!ReadLE32Checked(p, end, lane_count) ||
        lane_count != kRCFri3AlgDualNumLanes) {
        return std::nullopt;
    }

    Fri3AlgDualBatchProof proof;
    proof.version = version;
    if (!ReadUint256Checked(p, end, proof.master_statement_binding))
        return std::nullopt;
    for (uint256& child : proof.lane_child_binding) {
        if (!ReadUint256Checked(p, end, child)) return std::nullopt;
    }
    for (uint32_t lane = 0; lane < kRCFri3AlgDualNumLanes; ++lane) {
        uint32_t encoded_lane = 0;
        uint32_t lane_bytes = 0;
        if (!ReadLE32Checked(p, end, encoded_lane) || encoded_lane != lane)
            return std::nullopt;
        if (!ReadLE32Checked(p, end, lane_bytes) ||
            lane_bytes > kRCFriMaxProofBytesHard ||
            static_cast<size_t>(end - p) < lane_bytes) {
            return std::nullopt;
        }
        std::vector<unsigned char> one(p, p + lane_bytes);
        p += lane_bytes;
        auto parsed = DeserializeFri3AlgBatchProofConfigured(
            one, suite.lane_version,
            suite.queries_per_lane,
            /*require_canonical_fp3=*/true);
        if (!parsed.has_value() ||
            parsed->queries.size() !=
                suite.queries_per_lane) {
            return std::nullopt;
        }
        // Re-serialization equality pins the unique canonical encoding.
        std::vector<unsigned char> canonical;
        const size_t canonical_size =
            SerializeFri3AlgBatchProof(*parsed, canonical);
        if (canonical_size != one.size()) return std::nullopt;
        if (canonical != one) return std::nullopt;
        proof.lane[lane] = std::move(*parsed);
    }
    if (p != end || !Fri3AlgDualSameStatement(proof.lane[0], proof.lane[1]))
        return std::nullopt;
    return proof;
}

std::optional<Fri3AlgDualBatchProof>
DeserializeFri3AlgDualBatchProof(
    const std::vector<unsigned char>& in)
{
    return
        DeserializeFri3AlgDualBatchProofConfigured(
            in, kFri3AlgDualQ128V5Suite);
}

std::optional<Fri3AlgDualBatchProof>
DeserializeFri3AlgDualQ136BatchProof(
    const std::vector<unsigned char>& in)
{
    return
        DeserializeFri3AlgDualBatchProofConfigured(
            in, kFri3AlgDualQ136V6Suite);
}

Fri3AlgDualOracleHybridAssessment AssessFri3AlgDualOracleHybrid(
    Fri3AlgDualCommitmentScenario scenario,
    uint32_t batch_columns,
    uint32_t lde_log2,
    uint32_t global_site_log2)
{
    Fri3AlgDualOracleHybridAssessment out;
    out.scenario = scenario;
    out.batch_columns = batch_columns;
    out.lde_log2 = lde_log2;
    out.global_site_log2 = global_site_log2;
    if (!KnownDualCommitmentScenario(scenario) ||
        batch_columns == 0 ||
        batch_columns > kRCFri3AlgBatchMaxColumns ||
        lde_log2 < 4 || lde_log2 > kRCFriMaxLdeLog2 ||
        global_site_log2 > kRCFri3AlgDualAlgHashCollisionBits) {
        out.note = "dual_q128_hybrid:invalid_parameters";
        return out;
    }

    const uint32_t fold_draws = lde_log2 - 4; // blowup = 2^4
    out.independent_batch_draws_per_lane = batch_columns;
    out.uniform_field_draws_per_lane =
        batch_columns +
        2 * kRCFri3AlgDualOodCandidates + // two points, fixed candidates
        2 +                                // DEEP weights
        fold_draws;
    // Lane-seed KDF plus two SHA256d blocks per uniform Fp3 draw plus one
    // direct SHA256d block per exactly-uniform power-of-two query index.
    out.sha_transcript_calls_per_lane =
        1 + 2 * out.uniform_field_draws_per_lane +
        kRCFri3AlgDualQueriesPerLane;
    out.common_commitment_union_floor_bits =
        kRCFri3AlgDualAlgHashCollisionBits - global_site_log2;
    out.independent_batching_executable = true;
    out.all_sha_transcript_calls_lane_prefixed = true;

    if (scenario ==
        Fri3AlgDualCommitmentScenario::FullyDuplicatedLaneCommitments) {
        out.executable = true;
        out.duplicates_poseidon_row_tree = true;
        out.master_statement_binding_executable = true;
        out.ordered_child_binding_executable = true;
        out.all_poseidon_oracle_calls_lane_prefixed =
            kRCFri3AlgDualAlgHashInputsLanePrefixed;
        if (out.common_commitment_union_floor_bits > 0) {
            --out.common_commitment_union_floor_bits;
        }
        out.note =
            "dual_q128_hybrid:two lane-prefixed AlgHash row/fold trees "
            "execute and reject cross-lane substitution; exact algebraic-"
            "oracle-to-NIROP reduction remains open";
        return out;
    }

    out.executable = true;
    out.master_statement_binding_executable = true;
    out.ordered_child_binding_executable = true;
    out.duplicates_poseidon_row_tree = false;
    out.all_poseidon_oracle_calls_lane_prefixed = false;
    out.common_commitment_hybrid_reduction_complete = false;
    out.full_nirop_oracle_separation_proven = false;
    out.formal_soundness_ready = false;
    out.note =
        "dual_q128_hybrid:shared AlgHash master is the selected conditional "
        "V5 backend and rejects substitution; its non-squared binding "
        "hybrid remains open";
    return out;
}

// ============================================================================
// PR-89 Construction 2: enforced per-squeeze grinding tax.
// ============================================================================
uint32_t Fri3AlgLeadingZeroBits(const uint256& digest)
{
    uint32_t bits = 0;
    for (uint32_t i = 0; i < 32; ++i) {
        const unsigned char b = digest.data()[i];
        if (b == 0) {
            bits += 8;
            continue;
        }
        // Count leading zero bits within this byte, MSB-first.
        for (int shift = 7; shift >= 0; --shift) {
            if ((b >> shift) & 1u) return bits;
            ++bits;
        }
    }
    return bits; // all-zero digest
}

uint256 Fri3AlgSqueezeGrindDigest(
    const std::vector<unsigned char>& squeeze_input, uint64_t nonce)
{
    std::vector<unsigned char> buf(squeeze_input);
    AppendLE64(buf, nonce);
    return Sha256dBytes(buf.data(), buf.size());
}

bool Fri3AlgCheckSqueezeGrind(
    const std::vector<unsigned char>& squeeze_input, uint64_t nonce, uint32_t g)
{
    if (g == 0) return true;
    if (g > 256) return false;
    return Fri3AlgLeadingZeroBits(
               Fri3AlgSqueezeGrindDigest(squeeze_input, nonce)) >= g;
}

std::optional<uint64_t> Fri3AlgGrindSqueeze(
    const std::vector<unsigned char>& squeeze_input, uint32_t g,
    uint64_t max_iters)
{
    if (g == 0) return uint64_t{0};
    if (g > 256) return std::nullopt;
    // Fail fast on a target no prover can actually meet, rather than spinning
    // for the full budget. The VERIFIER predicate is unaffected and still
    // accepts any g <= 256, so this cannot weaken a check.
    if (g > kRCFri3AlgMaxGrindableBits) return std::nullopt;
    // A g-bit predicate needs 2^g expected trials. The former flat 2^34 default
    // was SMALLER than the advertised kRCFri3AlgJointQGrindBits = 40 target, so
    // an honest prover at the shipped g exhausted the range ~98.4% of the time
    // (P(hit) = 1 - exp(-2^34/2^40) = 0.0155). Derive the bound from g instead:
    // 2^(g+10) gives P(exhaust) = exp(-1024), i.e. never in practice.
    if (max_iters == 0) {
        max_iters = uint64_t{1} << (g + kGrindIterationSlackBits);
    }
    for (uint64_t nonce = 0; nonce < max_iters; ++nonce) {
        if (Fri3AlgLeadingZeroBits(
                Fri3AlgSqueezeGrindDigest(squeeze_input, nonce)) >= g) {
            return nonce;
        }
    }
    return std::nullopt;
}

// ============================================================================
// PR-89 Construction 2, FIELD-NATIVE difficulty predicate (see header for the
// VACUITY TRAP this deliberately avoids).
// ============================================================================
uint32_t Fri3AlgTrailingZeroBitsFp(Fp x)
{
    const uint64_t v = gkr_field::Canonical(x);
    if (v == 0) return 64;
    uint32_t bits = 0;
    while (((v >> bits) & 1u) == 0) ++bits;
    return bits;
}

bool Fri3AlgCheckAlgebraicGrind(Fp lane0, uint32_t g)
{
    if (g == 0) return true;
    if (g > kRCFri3AlgMaxAlgebraicGrindBits) return false;
    return Fri3AlgTrailingZeroBitsFp(lane0) >= g;
}

namespace {

// Column layout for the predicate AIR: 64 bit columns, the recomposed value,
// then the high-32 AND chain used by the canonicity check.
constexpr uint32_t kGrindPredBits = 64;
constexpr uint32_t kGrindPredHighBits = 32;      // bits 32..63
constexpr uint32_t kGrindPredAndChunk = 6;       // 6 bits/step => alg_degree 7
constexpr uint32_t kGrindPredAndSteps =
    (kGrindPredHighBits + kGrindPredAndChunk - 1) / kGrindPredAndChunk; // 6
constexpr uint32_t kGrindPredValueCol = kGrindPredBits;          // 64
constexpr uint32_t kGrindPredAndBase = kGrindPredValueCol + 1;   // 65
constexpr uint32_t kGrindPredColumns = kGrindPredAndBase + kGrindPredAndSteps;

} // namespace

Fri3AlgGrindPredicateAirV1 BuildFri3AlgGrindPredicateAirV1(
    Fp lane0, uint32_t g, bool use_aliased_witness)
{
    Fri3AlgGrindPredicateAirV1 out;
    out.tax_bits = g;
    out.bit_columns = kGrindPredBits;
    out.n_rows = 2; // structural minimum; the predicate is one logical row
    out.n_columns = kGrindPredColumns;
    if (g == 0 || g > kRCFri3AlgMaxAlgebraicGrindBits) {
        out.note = "grind predicate: g out of range";
        return out;
    }

    // The witness the PROVER supplies: either the true canonical decomposition
    // of lane0, or the aliased B = x + p an attacker would use to fake the tax.
    const uint64_t canonical = gkr_field::Canonical(lane0);
    uint64_t bits_source = canonical;
    if (use_aliased_witness) {
        // B = x + p is only representable in 64 bits when x < 2^32 - 1.
        const unsigned __int128 aliased =
            static_cast<unsigned __int128>(canonical) +
            static_cast<unsigned __int128>(gkr_field::kP);
        if (aliased >> 64) {
            out.note = "grind predicate: value admits no 64-bit alias";
            return out;
        }
        bits_source = static_cast<uint64_t>(aliased);
    }

    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = out.n_rows;
    cs.n_columns = out.n_columns;
    cs.preprocessed_pin_ood = true;

    // --- (1) booleanity of every bit column.
    for (uint32_t bit = 0; bit < kGrindPredBits; ++bit) {
        aq::AirConstraint<gf::Fp3> boolean;
        boolean.name = "stage3.fri3alg.grind.bit_boolean";
        boolean.kind = aq::AirKind::kEverywhere;
        boolean.alg_degree = 2;
        boolean.eval = [bit](const std::vector<gf::Fp3>& row,
                             const std::vector<gf::Fp3>&) {
            return gf::Mul(row[bit],
                           gf::Sub(row[bit], gf::Fp3::One()));
        };
        cs.constraints.push_back(std::move(boolean));
    }
    out.booleanity_constrained = true;

    // --- (2) recomposition: value == sum b_i 2^i (mod p).
    {
        aq::AirConstraint<gf::Fp3> rec;
        rec.name = "stage3.fri3alg.grind.recomposition";
        rec.kind = aq::AirKind::kEverywhere;
        rec.alg_degree = 1;
        rec.eval = [](const std::vector<gf::Fp3>& row,
                      const std::vector<gf::Fp3>&) {
            gf::Fp3 acc = gf::Fp3::Zero();
            gf::Fp3 power = gf::Fp3::One();
            for (uint32_t bit = 0; bit < kGrindPredBits; ++bit) {
                acc = gf::Add(acc, gf::Mul(power, row[bit]));
                power = gf::Add(power, power);
            }
            return gf::Sub(row[kGrindPredValueCol], acc);
        };
        cs.constraints.push_back(std::move(rec));
    }

    // --- (3) high-32 AND chain: and_k == and_{k-1} * prod(next 6 high bits).
    for (uint32_t step = 0; step < kGrindPredAndSteps; ++step) {
        const uint32_t first = kGrindPredHighBits + step * kGrindPredAndChunk;
        const uint32_t last =
            std::min<uint32_t>(first + kGrindPredAndChunk, kGrindPredBits);
        aq::AirConstraint<gf::Fp3> chain;
        chain.name = "stage3.fri3alg.grind.high_and_chain";
        chain.kind = aq::AirKind::kEverywhere;
        chain.alg_degree = kGrindPredAndChunk + 1;
        chain.eval = [step, first, last](const std::vector<gf::Fp3>& row,
                                         const std::vector<gf::Fp3>&) {
            gf::Fp3 prod = (step == 0)
                               ? gf::Fp3::One()
                               : row[kGrindPredAndBase + step - 1];
            for (uint32_t bit = first; bit < last; ++bit) {
                prod = gf::Mul(prod, row[bit]);
            }
            return gf::Sub(row[kGrindPredAndBase + step], prod);
        };
        cs.constraints.push_back(std::move(chain));
    }

    // --- (4) canonicity: NOT(high 32 bits all one AND low 32 bits nonzero).
    // Encoded as and_last * low32 == 0. Without this, B = x + p is accepted and
    // the tax can be claimed on a value that does not satisfy it.
    {
        aq::AirConstraint<gf::Fp3> canon;
        canon.name = "stage3.fri3alg.grind.canonicity";
        canon.kind = aq::AirKind::kEverywhere;
        canon.alg_degree = 2;
        canon.eval = [](const std::vector<gf::Fp3>& row,
                        const std::vector<gf::Fp3>&) {
            gf::Fp3 low = gf::Fp3::Zero();
            gf::Fp3 power = gf::Fp3::One();
            for (uint32_t bit = 0; bit < kGrindPredHighBits; ++bit) {
                low = gf::Add(low, gf::Mul(power, row[bit]));
                power = gf::Add(power, power);
            }
            return gf::Mul(
                row[kGrindPredAndBase + kGrindPredAndSteps - 1], low);
        };
        cs.constraints.push_back(std::move(canon));
    }
    out.canonicity_constrained = true;

    // --- (5) the tax itself: the low g bits are zero.
    for (uint32_t bit = 0; bit < g; ++bit) {
        aq::AirConstraint<gf::Fp3> tax;
        tax.name = "stage3.fri3alg.grind.tax_bit_zero";
        tax.kind = aq::AirKind::kEverywhere;
        tax.alg_degree = 1;
        tax.eval = [bit](const std::vector<gf::Fp3>& row,
                         const std::vector<gf::Fp3>&) { return row[bit]; };
        cs.constraints.push_back(std::move(tax));
    }
    out.tax_constrained = true;

    // Materialise the witness row and count ACTUAL violations.
    std::vector<gf::Fp3> row(out.n_columns, gf::Fp3::Zero());
    for (uint32_t bit = 0; bit < kGrindPredBits; ++bit) {
        row[bit] = gf::Fp3::FromFp(
            gf::FromU64((bits_source >> bit) & 1u));
    }
    row[kGrindPredValueCol] = gf::Fp3::FromFp(lane0);
    for (uint32_t step = 0; step < kGrindPredAndSteps; ++step) {
        const uint32_t first = kGrindPredHighBits + step * kGrindPredAndChunk;
        const uint32_t last =
            std::min<uint32_t>(first + kGrindPredAndChunk, kGrindPredBits);
        gf::Fp3 prod = (step == 0)
                           ? gf::Fp3::One()
                           : row[kGrindPredAndBase + step - 1];
        for (uint32_t bit = first; bit < last; ++bit) {
            prod = gf::Mul(prod, row[bit]);
        }
        row[kGrindPredAndBase + step] = prod;
    }
    const std::vector<gf::Fp3> next = row; // constant across the 2-row domain
    for (const auto& c : cs.constraints) {
        if (!gf::Eq(c.eval(row, next), gf::Fp3::Zero())) ++out.violations;
        out.max_alg_degree = std::max(out.max_alg_degree, c.alg_degree);
    }

    out.n_constraints = static_cast<uint32_t>(cs.constraints.size());
    out.valid = true;
    out.note = "field-native grind predicate: bit-decomposed with canonicity "
               "(NOT the vacuous lane0 == 2^g*h form)";
    return out;
}

// ============================================================================
// PR-89 Construction 2: ALGEBRAIC taxed deciding squeeze (NOT ACTIVATED).
// ============================================================================
namespace {

// A uint64 is absorbed as TWO 32-bit lanes. Absorbing it as one FromU64 lane
// would be lossy — FromU64 reduces mod p, so 2^32 - 1 distinct u64 values
// collide onto the same lane and the transcript would not be injective.
void AppendU64Lanes(std::vector<Fp>& lanes, uint64_t v)
{
    lanes.push_back(gf::FromU64(v & 0xFFFFFFFFull));
    lanes.push_back(gf::FromU64((v >> 32) & 0xFFFFFFFFull));
}

} // namespace

Fri3AlgDigest Fri3AlgAlgebraicTranscriptDigest(const std::vector<Fp>& lanes,
                                               uint64_t domain)
{
    std::vector<Fp> buf;
    buf.reserve(lanes.size() + 2);
    AppendU64Lanes(buf, domain);
    buf.insert(buf.end(), lanes.begin(), lanes.end());
    // SpongeHashFp applies injective 10*-padding at rate 8, so the domain
    // prefix is a genuine separator rather than a collidable prefix.
    return alg_hash::SpongeHashFp(buf);
}

Fri3AlgDigest Fri3AlgAlgebraicSqueeze(const std::vector<Fp>& sigma_core,
                                      uint64_t nonce)
{
    std::vector<Fp> buf(sigma_core);
    AppendU64Lanes(buf, nonce);
    return Fri3AlgAlgebraicTranscriptDigest(buf, kRCFri3AlgTaxedQDomain);
}

bool Fri3AlgCheckAlgebraicSqueezeGrind(const std::vector<Fp>& sigma_core,
                                       uint64_t nonce, uint32_t g)
{
    if (g == 0) return true;
    if (g > kRCFri3AlgMaxAlgebraicGrindBits) return false;
    return Fri3AlgCheckAlgebraicGrind(
        Fri3AlgAlgebraicSqueeze(sigma_core, nonce)[0], g);
}

std::optional<uint64_t> Fri3AlgGrindAlgebraicSqueeze(
    const std::vector<Fp>& sigma_core, uint32_t g, uint64_t max_iters)
{
    if (g == 0) return uint64_t{0};
    if (g > kRCFri3AlgMaxAlgebraicGrindBits) return std::nullopt;
    if (g > kRCFri3AlgMaxGrindableBits) return std::nullopt;
    if (max_iters == 0) {
        max_iters = uint64_t{1} << (g + kGrindIterationSlackBits);
    }
    for (uint64_t nonce = 0; nonce < max_iters; ++nonce) {
        if (Fri3AlgCheckAlgebraicGrind(
                Fri3AlgAlgebraicSqueeze(sigma_core, nonce)[0], g)) {
            return nonce;
        }
    }
    return std::nullopt;
}

uint32_t Fri3AlgAlgebraicQueryIndex(const Fri3AlgDigest& sigma, uint32_t j,
                                    uint32_t n_lde)
{
    if (n_lde == 0 || (n_lde & (n_lde - 1)) != 0) return 0;
    std::vector<Fp> buf;
    buf.reserve(alg_hash::kAlgHashDigestLen + 2);
    for (uint32_t lane = 0; lane < alg_hash::kAlgHashDigestLen; ++lane) {
        buf.push_back(sigma[lane]);
    }
    AppendU64Lanes(buf, j);
    const Fri3AlgDigest d =
        Fri3AlgAlgebraicTranscriptDigest(buf, kRCFri3AlgTaxedQIndexDomain);
    const uint32_t le32 =
        static_cast<uint32_t>(gf::Canonical(d[0]) & 0xFFFFFFFFull);
    return le32 & (n_lde - 1);
}

// ===========================================================================
// PR-89 g4, TRANSCRIPT HALF — implementation.
//
// SOUNDNESS ARGUMENT, in full, for replacing verbatim absorption of the OOD
// evaluation vectors by a commitment.
//
// WHAT THE SHIPPED TRANSCRIPT ACTUALLY BUYS.  Be precise about the property
// being preserved, because it is weaker than "the transcript binds the
// evaluations".  The shipped Q192 V3 order is
//     roots -> alpha -> z1,z2 -> claims E -> w1,w2 -> folds -> queries,
// i.e. the batching vector alpha is fixed BEFORE the claims.  Under that
// order the individual claims are NOT bound at all, and this is already an
// executable finding in this tree, not a new observation: the verifier's only
// algebraic use of E is through the two batched values
//     v_s = sum_i alpha_i * z_s^{shift_i} * E_s[i],
// and AuditFri3AlgAdaptiveEvaluationOrder exhibits, in closed form, a
// nonzero delta with delta_i = 1 and
// delta_j = -(alpha_i z^{shift_i})/(alpha_j z^{shift_j}) that changes E while
// leaving both v_s fixed; `legacy_order_individual_eval_binding` is hard false
// there.  Absorbing E verbatim therefore does exactly ONE thing: it makes
// every POST-CLAIM challenge -- w1, w2, every fold beta, every query index --
// a function of the whole 2W-cell claim vector, so a prover who moves any cell
// must redo the entire fold and query phase against fresh challenges.  It
// removes adaptivity; it does not bind cells.
//
// WHAT THE COMMITMENT PRESERVES.  Absorbing C = Commit(z1,z2,E) instead makes
// every post-claim challenge a function of C.  The map E |-> C is the same
// Poseidon2 sponge (rate 8, capacity 4) that this backend already uses as its
// Merkle hash, so:
//   * for any two claim vectors E != E', the challenges differ UNLESS
//     Commit(E) = Commit(E'), i.e. unless the adversary exhibits a sponge
//     collision.  alg_hash::BindingEffectiveCollisionFloorBits(B256) = 128,
//     and that same 128 already appears as the "shared Poseidon2 collision"
//     term of the single-lane BCS/rbr ledger, so this introduces NO new
//     assumption and NO new term -- it reuses one already charged.
//   * conditioned on no collision, the adversary's view is EXACTLY the view
//     he had under verbatim absorption: challenges are a deterministic
//     function of the same data, drawn after it.  The reduction is therefore
//     an identity, not a new argument.
//
// WHAT AN ADVERSARY COULD DO IF BINDING WERE WEAKER.  Suppose Commit were
// only q-to-one on some subset -- concretely, suppose he could find E' != E
// with Commit(E') = Commit(E).  Then he could run the honest prover to
// completion on E, obtain w1, w2, the betas and the query indices, build and
// commit the fold layers for the DEEP composition of E, and only THEN ship
// E'.  The verifier would replay the transcript, get the identical challenges
// (same commitment), and proceed.  Whether that forgery then passes is
// decided by the DEEP identity at the queried points, which reconstructs
// v_s from E' -- so the attack succeeds precisely when E' also preserves
// v_1 and v_2, i.e. when the collision lands inside the order-audit kernel.
// The cost of that is a 2^128 collision search intersected with a linear
// constraint; the shipped verbatim transcript gives no protection against the
// kernel either (see above), so this is not a regression, but it is exactly
// why the commitment must be COLLISION-RESISTANT and not merely "some
// function of E".
//
// WHY v1,v2 IS NOT AN ACCEPTABLE SUBSTITUTE -- AND THIS IS THE WHOLE POINT.
// Absorbing the two batched values instead of a commitment looks like the
// same idea and is a different thing entirely.  E |-> (v1,v2) is LINEAR and
// its image is 2-dimensional over a 2W-dimensional domain, so it has a kernel
// of dimension 2W-2, and that kernel is not merely large but CONSTRUCTIBLE
// with two field inversions -- the audit's delta above.  Under that variant
// the adversary does not need any collision search at all: he computes a
// preserving delta directly, and the post-claim challenges do not move.  The
// gap between the two designs is 2^128 versus 2^0.
//
// WHAT THIS CHANGE DOES NOT FIX.  It does not create individual-cell binding,
// because that is an ORDERING property (alpha must be drawn AFTER the claims;
// AuditFri3AlgAdaptiveEvaluationOrder's
// post_claim_random_batching_blocks_adaptive_kernel and the V2 multi-row
// codec's transcript order are the fix) and not a hashing property.  This
// lane deliberately keeps the shipped V3 ordering so that an A/B against
// kFri3AlgQ192V3Config isolates the transcript LAYOUT.  Combining the two --
// short preimages AND post-claim alpha -- is a separate, compatible step and
// is NOT claimed here.
//
// The shape commitment (term (i)) needs a much shorter argument: column_len is
// public shape data that the verifier is shipped in the clear and validates
// structurally (each in [1, n], FriNextPow2(max) == n) before FS replay.
// Committing to it preserves the only property the loop provided, namely that
// the very first challenge already depends on the whole shape vector.
// ===========================================================================

namespace {

/** Fp3 -> three canonical Goldilocks lanes, coordinate order. */
void AppendFp3Lanes(std::vector<Fp>& lanes, const Fp3& v)
{
    lanes.push_back(gf::Canonical(v.c0));
    lanes.push_back(gf::Canonical(v.c1));
    lanes.push_back(gf::Canonical(v.c2));
}

void AppendDigestLanes(std::vector<Fp>& lanes, const Fri3AlgDigest& d)
{
    for (uint32_t i = 0; i < alg_hash::kAlgHashDigestLen; ++i) {
        lanes.push_back(gf::Canonical(d[i]));
    }
}

/** uint256 -> EIGHT 32-bit lanes. NOT four 64-bit lanes: a 64-bit limb can
 *  exceed p, FromU64 would reduce it, and two distinct seeds would alias onto
 *  one lane sequence. Same reason AppendU64Lanes splits. */
void AppendUint256Lanes(std::vector<Fp>& lanes, const uint256& v)
{
    for (uint32_t word = 0; word < 8; ++word) {
        uint32_t packed = 0;
        for (uint32_t byte = 0; byte < 4; ++byte) {
            packed |= static_cast<uint32_t>(v.data()[4 * word + byte])
                      << (8 * byte);
        }
        lanes.push_back(gf::FromU64(packed));
    }
}

[[nodiscard]] uint64_t Fri3AlgNextPow2U64(uint64_t v)
{
    uint64_t p = 1;
    while (p < v) p <<= 1;
    return p;
}

/** SHA256d compressions needed to hash a `bytes`-long transcript prefix, using
 *  the SAME accounting as
 *  stage3_fs_selection_air::MeasureAlgebraicQueryIndexReplayCostV1: length
 *  block + padding on the first hash, plus one compression for the second.
 *  The per-challenge label suffix (~15 B) is NOT counted, exactly as there, so
 *  the two cost models stay directly comparable. */
[[nodiscard]] uint64_t Fri3AlgShaCompressionsForPrefix(uint64_t bytes)
{
    return (bytes + 9 + 63) / 64 + 1;
}

/** Vertical SHA AIR schedule (hash_air.cpp
 *  BuildFixedProgramVerticalWitnessBoundaryInstance):
 *  scheduled_instances = max(2, next_pow2(compressions)), LANE_ROWS = 1024. */
[[nodiscard]] uint64_t Fri3AlgShaAirRowsForCompressions(uint64_t compressions)
{
    return std::max<uint64_t>(2, Fri3AlgNextPow2U64(compressions)) * 1024;
}

} // namespace

Fri3AlgDigest Fri3AlgShapeCommit(uint32_t n_coeffs,
                                 const std::vector<uint32_t>& column_len)
{
    std::vector<Fp> lanes;
    lanes.reserve(column_len.size() + 2);
    lanes.push_back(gf::FromU64(column_len.size()));
    lanes.push_back(gf::FromU64(n_coeffs));
    for (const uint32_t len : column_len) {
        lanes.push_back(gf::FromU64(len));
    }
    return Fri3AlgAlgebraicTranscriptDigest(lanes, kRCFri3AlgShapeCommitDomain);
}

Fri3AlgDigest Fri3AlgOodEvalCommit(const Fp3& z1, const Fp3& z2,
                                   const std::vector<Fp3>& evals_z1,
                                   const std::vector<Fp3>& evals_z2)
{
    std::vector<Fp> lanes;
    lanes.reserve(3 * (evals_z1.size() + evals_z2.size()) + 8);
    // Both counts, then both vectors in full: no min()/truncation, so a
    // malformed (unequal-length) pair still hashes injectively rather than
    // silently colliding with a well-formed one.
    lanes.push_back(gf::FromU64(evals_z1.size()));
    lanes.push_back(gf::FromU64(evals_z2.size()));
    AppendFp3Lanes(lanes, z1);
    AppendFp3Lanes(lanes, z2);
    for (const Fp3& e : evals_z1) AppendFp3Lanes(lanes, e);
    for (const Fp3& e : evals_z2) AppendFp3Lanes(lanes, e);
    return Fri3AlgAlgebraicTranscriptDigest(lanes,
                                            kRCFri3AlgOodEvalCommitDomain);
}

std::vector<Fp> Fri3AlgAlgebraicSigmaCore(const uint256& fs_seed,
                                          const Fri3AlgBatchProof& proof)
{
    std::vector<Fp> lanes;
    // Own separator lane pair. Fri3AlgAlgebraicSqueeze will additionally
    // prefix kRCFri3AlgTaxedQDomain, so a sigma_core can never be confused
    // with a bare lane vector supplied by a caller.
    AppendU64Lanes(lanes, kRCFri3AlgSigmaCoreDomain);
    lanes.push_back(gf::FromU64(proof.version));
    AppendUint256Lanes(lanes, fs_seed);
    AppendU64Lanes(lanes, proof.pow_grind_nonce);
    lanes.push_back(gf::FromU64(proof.blowup));
    lanes.push_back(gf::FromU64(proof.n_coeffs));
    lanes.push_back(gf::FromU64(proof.column_len.size()));
    AppendDigestLanes(lanes, proof.row_commit.root);
    // The two W-proportional bodies enter as their commitments -- this is what
    // keeps sigma_core O(log n) rather than O(W), and it is the same binding
    // the transcript itself now uses.
    AppendDigestLanes(lanes,
                      Fri3AlgShapeCommit(proof.n_coeffs, proof.column_len));
    AppendDigestLanes(lanes, Fri3AlgOodEvalCommit(proof.z1, proof.z2,
                                                  proof.evals_z1,
                                                  proof.evals_z2));
    AppendFp3Lanes(lanes, proof.lambda);
    AppendFp3Lanes(lanes, proof.z1);
    AppendFp3Lanes(lanes, proof.z2);
    AppendFp3Lanes(lanes, proof.w1);
    AppendFp3Lanes(lanes, proof.w2);
    lanes.push_back(gf::FromU64(proof.fold_layers.size()));
    for (const Fri3AlgLayerCommit& layer : proof.fold_layers) {
        lanes.push_back(gf::FromU64(layer.n_leaves));
        AppendDigestLanes(lanes, layer.root);
    }
    lanes.push_back(gf::FromU64(proof.fold_challenges.size()));
    for (const Fp3& beta : proof.fold_challenges) AppendFp3Lanes(lanes, beta);
    AppendFp3Lanes(lanes, proof.final_value);
    return lanes;
}

Fp3 Fri3AlgAlgebraicChallengeFp3(const std::vector<Fp>& core,
                                 Fri3AlgAlgebraicDrawKind kind, uint32_t idx)
{
    std::vector<Fp> lanes;
    lanes.reserve(core.size() + 3);
    lanes.insert(lanes.end(), core.begin(), core.end());
    lanes.push_back(gf::FromU64(static_cast<uint32_t>(kind)));
    AppendU64Lanes(lanes, idx);
    const Fri3AlgDigest d = Fri3AlgAlgebraicTranscriptDigest(
        lanes, kRCFri3AlgAlgebraicFp3DrawDomain);
    // Three sponge output lanes ARE three Goldilocks field elements. No
    // rejection sampler, no failure tail: the SHA route's
    // Fri3AlgSelectUniformFp3Words exists only because SHA emits BYTES, which
    // must be rejected when a 64-bit word lands in [p, 2^64).
    return Fp3{gf::Canonical(d[0]), gf::Canonical(d[1]), gf::Canonical(d[2])};
}

Fri3AlgTranscriptReplayCostV1 MeasureFri3AlgTranscriptReplayCostV1(
    uint32_t child_w, uint32_t column_len)
{
    Fri3AlgTranscriptReplayCostV1 out;
    out.child_w = child_w;
    if (child_w == 0 || child_w > kRCFri3AlgBatchMaxColumns ||
        column_len == 0) {
        out.note = "fri3_alg_transcript_cost:shape";
        return out;
    }

    // Deterministic non-degenerate columns; the transcript LENGTH does not
    // depend on the values, but a degenerate all-zero input can make the
    // terminal-layer constancy check trivial, so vary them.
    std::vector<std::vector<Fp3>> columns(child_w);
    for (uint32_t c = 0; c < child_w; ++c) {
        columns[c].resize(column_len);
        for (uint32_t k = 0; k < column_len; ++k) {
            columns[c][k] = Fp3{gf::FromU64(1 + 7ull * c + 11ull * k),
                                gf::FromU64(3 + 5ull * c + 2ull * k),
                                gf::FromU64(9 + 13ull * c + 17ull * k)};
        }
    }
    const uint256 seed = uint256::ONE;

    const auto run = [&](const Fri3AlgProtocolConfig& config,
                         std::vector<Fri3AlgTranscriptChallengeCostV1>& trace,
                         uint32_t& n_coeffs_out) {
        std::vector<Fri3AlgTranscriptChallengeCostV1> raw;
        Fri3AlgBatchCommitResult r = Fri3AlgBatchCommitConfigured(
            columns, seed, 0, config, /*stream_column_lde=*/false,
            /*reused_row_tree=*/nullptr, /*built_row_tree_out=*/nullptr,
            /*terminal_fold_transcript_out=*/nullptr,
            /*fs_prefix_trace_out=*/&raw);
        if (!r.ok) return false;
        n_coeffs_out = r.proof.n_coeffs;
        trace = std::move(raw);
        return true;
    };

    std::vector<Fri3AlgTranscriptChallengeCostV1> legacy_raw;
    std::vector<Fri3AlgTranscriptChallengeCostV1> short_raw;
    uint32_t n_legacy = 0;
    uint32_t n_short = 0;
    if (!run(kFri3AlgQ192V3Config, legacy_raw, n_legacy) ||
        !run(kFri3AlgQ192ShortFsV7Config, short_raw, n_short) ||
        n_legacy != n_short || legacy_raw.size() != short_raw.size()) {
        out.note = "fri3_alg_transcript_cost:prove_failed_or_asymmetric";
        return out;
    }
    out.n_coeffs = n_legacy;
    out.queries = kRCFri3AlgNumQueries;

    const auto fill = [](std::vector<Fri3AlgTranscriptChallengeCostV1>& raw,
                         std::vector<Fri3AlgTranscriptChallengeCostV1>& first,
                         uint64_t& total_rows, uint64_t& max_rows) {
        for (Fri3AlgTranscriptChallengeCostV1& e : raw) {
            e.compressions = Fri3AlgShaCompressionsForPrefix(e.prefix_bytes);
            e.rows = Fri3AlgShaAirRowsForCompressions(e.compressions);
            total_rows += e.rows;
            max_rows = std::max(max_rows, e.rows);
            bool seen = false;
            for (const Fri3AlgTranscriptChallengeCostV1& f : first) {
                if (f.label == e.label) { seen = true; break; }
            }
            if (!seen) first.push_back(e);
        }
    };
    fill(legacy_raw, out.legacy, out.legacy_total_rows, out.legacy_max_rows);
    fill(short_raw, out.short_fs, out.short_fs_total_rows,
         out.short_fs_max_rows);

    // The short-transcript preimage contains no per-column term at all: W
    // enters only as the single LE32 count and inside two fixed-width
    // commitments. A caller proves width-independence by comparing two widths;
    // this flag records the STRUCTURAL fact that no entry's prefix scales with
    // W, which the two-width test in the unit suite checks empirically.
    out.short_fs_width_independent = true;
    out.valid = true;
    out.note = "fri3_alg_transcript_cost:measured_on_production_transcript";
    return out;
}

// ============================================================================
// PR-89 Construction 1: Pi_JQ joint query squeeze.
// ============================================================================
namespace {

// JointQ reuses the executable Q136 lane configs/codec but domain-separates its
// lane seeds (distinct envelope tag) and binds sigma_Q into the master binding.
constexpr Fri3AlgDualProtocolSuite kFri3AlgJointQSuite{
    kRCFri3AlgJointQProofMagic,
    kRCFri3AlgDualQ136ProofVersion, // envelope codec version (byte-identical)
    kRCFri3AlgDualQ136LaneProofVersion,
    kRCFri3AlgDualQ136QueriesPerLane,
    kRCFri3AlgJointQEnvelopeDomainTag,
    kRCFri3AlgDualQ136Lane0DomainTag,
    kRCFri3AlgDualQ136Lane1DomainTag,
    kRCFri3AlgJointQMasterBindingDomainTag,
    kRCFri3AlgJointQChildBindingDomainTag,
    kRCFri3AlgDualQ136MaxProofBytesHard,
    &kFri3AlgDualQ136Lane0Config,
    &kFri3AlgDualQ136Lane1Config,
    "JOINTQ dual-Q136",
};

// Preimage of the deciding squeeze sigma_Q (the enforced tax nonce is appended
// by Fri3AlgSqueezeGrindDigest): the squeeze binds BOTH lanes' terminal
// transcripts T_0,T_1 under a shared row root.
std::vector<unsigned char> Fri3AlgJointQSigmaCorePreimage(
    const uint256& fs_seed, uint64_t pow_grind_nonce,
    const Fri3AlgDigest& row_root, const uint256& t0, const uint256& t1)
{
    std::vector<unsigned char> pre;
    AppendBytes(pre,
                reinterpret_cast<const unsigned char*>(
                    kRCFri3AlgJointQQueryTag),
                std::strlen(kRCFri3AlgJointQQueryTag));
    AppendLE32(pre, kRCFri3AlgJointQProofVersion);
    AppendBytes(pre, fs_seed.data(), 32);
    AppendLE64(pre, pow_grind_nonce);
    AppendAlgDigest(pre, row_root);
    AppendBytes(pre, t0.data(), 32);
    AppendBytes(pre, t1.data(), 32);
    return pre;
}

// Master binding that additionally absorbs sigma_Q (Pi_JQ requirement).
uint256 Fri3AlgJointQMasterBinding(const uint256& fs_seed,
                                   const Fri3AlgBatchProof& lane0,
                                   const Fri3AlgBatchProof& lane1,
                                   const uint256& sigma_q)
{
    std::vector<unsigned char> buf;
    AppendBytes(buf,
                reinterpret_cast<const unsigned char*>(
                    kRCFri3AlgJointQMasterBindingDomainTag),
                std::strlen(kRCFri3AlgJointQMasterBindingDomainTag));
    AppendLE32(buf, kRCFri3AlgJointQProofVersion);
    AppendBytes(buf, fs_seed.data(), 32);
    AppendLE64(buf, lane0.pow_grind_nonce);
    AppendLE32(buf, lane0.blowup);
    AppendLE32(buf, lane0.n_coeffs);
    AppendLE32(buf, lane0.row_commit.n_leaves);
    AppendLE32(buf, static_cast<uint32_t>(lane0.column_len.size()));
    for (const uint32_t len : lane0.column_len) AppendLE32(buf, len);
    AppendAlgDigest(buf, lane0.row_commit.root);
    AppendAlgDigest(buf, lane1.row_commit.root);
    AppendBytes(buf, sigma_q.data(), 32);
    return Sha256dBytes(buf.data(), buf.size());
}

} // namespace

uint32_t Fri3AlgJointQIndex(const uint256& sigma_q, uint32_t lane, uint32_t j,
                            uint32_t n_lde)
{
    if (n_lde == 0 || (n_lde & (n_lde - 1)) != 0) return 0;
    return Fri3AlgJointQIndexInternal(sigma_q, lane, j, n_lde);
}

Fri3AlgJointQCommitResult Fri3AlgJointQBatchCommit(
    const std::vector<std::vector<Fp3>>& columns, const uint256& fs_seed,
    uint64_t pow_grind_nonce, uint32_t grind_bits)
{
    Fri3AlgJointQCommitResult out;
    out.grind_bits = grind_bits;
    out.proof.version = kRCFri3AlgDualQ136ProofVersion;

    // Pass 1: run both lanes to the terminal fold to capture T_0,T_1 and the
    // shared row root. The per-lane query indices produced here are discarded.
    std::array<uint256, kRCFri3AlgDualNumLanes> t_lane{};
    Fri3AlgDigest row_root{};
    for (uint32_t lane = 0; lane < kRCFri3AlgDualNumLanes; ++lane) {
        const uint256 lane_seed = Fri3AlgDualLaneSeed(
            fs_seed, pow_grind_nonce, lane, kFri3AlgJointQSuite);
        const Fri3AlgProtocolConfig config = DualLaneConfigForScenario(
            lane, Fri3AlgDualCommitmentScenario::SharedMasterDerivedChildren,
            kFri3AlgJointQSuite);
        uint256 tl{};
        Fri3AlgBatchCommitResult probe = Fri3AlgBatchCommitConfigured(
            columns, lane_seed, pow_grind_nonce, config,
            /*stream_column_lde=*/false, nullptr, nullptr, &tl);
        if (!probe.ok) {
            out.note = "jointq probe lane " + std::to_string(lane) + ": " +
                       probe.note;
            return out;
        }
        t_lane[lane] = tl;
        if (lane == 0) row_root = probe.proof.row_commit.root;
    }

    // Deciding squeeze + enforced per-squeeze tax (Construction 2, fused).
    const std::vector<unsigned char> sigma_core =
        Fri3AlgJointQSigmaCorePreimage(fs_seed, pow_grind_nonce, row_root,
                                       t_lane[0], t_lane[1]);
    std::optional<uint64_t> nonce = Fri3AlgGrindSqueeze(sigma_core, grind_bits);
    if (!nonce.has_value()) {
        out.note = "jointq: grinding tax nonce search exhausted";
        return out;
    }
    out.joint_query_grind_nonce = *nonce;
    out.joint_query_sigma = Fri3AlgSqueezeGrindDigest(sigma_core, *nonce);

    // Pass 2: re-run both lanes opening every query at the joint index.
    for (uint32_t lane = 0; lane < kRCFri3AlgDualNumLanes; ++lane) {
        const uint256 lane_seed = Fri3AlgDualLaneSeed(
            fs_seed, pow_grind_nonce, lane, kFri3AlgJointQSuite);
        Fri3AlgProtocolConfig config = DualLaneConfigForScenario(
            lane, Fri3AlgDualCommitmentScenario::SharedMasterDerivedChildren,
            kFri3AlgJointQSuite);
        config.joint_query = true;
        config.joint_query_sigma = &out.joint_query_sigma;
        config.joint_query_lane = lane;
        Fri3AlgBatchCommitResult lane_result = Fri3AlgBatchCommitConfigured(
            columns, lane_seed, pow_grind_nonce, config,
            /*stream_column_lde=*/false, nullptr, nullptr, nullptr);
        if (!lane_result.ok) {
            out.note = "jointq final lane " + std::to_string(lane) + ": " +
                       lane_result.note;
            return out;
        }
        out.proof.lane[lane] = std::move(lane_result.proof);
    }
    if (!Fri3AlgDualSameStatement(out.proof.lane[0], out.proof.lane[1])) {
        out.note = "jointq prover produced different lane statements";
        return out;
    }
    if (!AlgDigestEq(out.proof.lane[0].row_commit.root,
                     out.proof.lane[1].row_commit.root)) {
        out.note = "jointq prover produced different shared row commitments";
        return out;
    }
    out.proof.master_statement_binding = Fri3AlgJointQMasterBinding(
        fs_seed, out.proof.lane[0], out.proof.lane[1], out.joint_query_sigma);
    for (uint32_t lane = 0; lane < kRCFri3AlgDualNumLanes; ++lane) {
        out.proof.lane_child_binding[lane] = Fri3AlgDualChildBinding(
            out.proof.master_statement_binding, lane,
            out.proof.lane[lane].row_commit.root, kFri3AlgJointQSuite);
    }
    std::vector<unsigned char> encoded;
    out.proof_bytes = SerializeFri3AlgDualQ136BatchProof(out.proof, encoded);
    if (out.proof_bytes == 0 ||
        out.proof_bytes > kFri3AlgJointQSuite.max_proof_bytes) {
        out.note = "jointq proof exceeds codec bound";
        return out;
    }
    out.ok = true;
    out.note = "experimental Pi_JQ joint-query dual-Q136 with enforced "
               "per-squeeze grinding tax; NIROP/global reductions pending";
    return out;
}

bool Fri3AlgJointQBatchVerify(const Fri3AlgDualBatchProof& proof,
                              uint64_t joint_query_grind_nonce,
                              const uint256& fs_seed, uint32_t grind_bits,
                              std::string* why)
{
    auto fail = [&](const char* w) {
        if (why) *why = w ? w : "Fri3AlgJointQBatchVerify failed";
        return false;
    };
    if (proof.version != kRCFri3AlgDualQ136ProofVersion)
        return fail("jointq bad envelope version");
    if (!Fri3AlgDualSameStatement(proof.lane[0], proof.lane[1]))
        return fail("jointq different lane statements");
    if (!AlgDigestEq(proof.lane[0].row_commit.root,
                     proof.lane[1].row_commit.root))
        return fail("jointq different shared row commitments");

    // Pass 1: replay both lanes to the terminal fold to recompute T_0,T_1.
    std::array<uint256, kRCFri3AlgDualNumLanes> t_lane{};
    for (uint32_t lane = 0; lane < kRCFri3AlgDualNumLanes; ++lane) {
        const uint256 lane_seed = Fri3AlgDualLaneSeed(
            fs_seed, proof.lane[lane].pow_grind_nonce, lane,
            kFri3AlgJointQSuite);
        const Fri3AlgProtocolConfig config = DualLaneConfigForScenario(
            lane, Fri3AlgDualCommitmentScenario::SharedMasterDerivedChildren,
            kFri3AlgJointQSuite);
        uint256 tl{};
        std::string lane_why;
        if (!Fri3AlgBatchVerifyConfigured(proof.lane[lane], lane_seed, config,
                                          &lane_why, &tl,
                                          /*terminal_fold_only=*/true)) {
            if (why) *why = "jointq lane " + std::to_string(lane) +
                            " terminal-fold replay: " + lane_why;
            return false;
        }
        t_lane[lane] = tl;
    }

    // Enforced per-squeeze tax (Construction 2): one verifier hash.
    const std::vector<unsigned char> sigma_core =
        Fri3AlgJointQSigmaCorePreimage(fs_seed, proof.lane[0].pow_grind_nonce,
                                       proof.lane[0].row_commit.root, t_lane[0],
                                       t_lane[1]);
    if (!Fri3AlgCheckSqueezeGrind(sigma_core, joint_query_grind_nonce,
                                  grind_bits))
        return fail("jointq enforced grinding tax not satisfied");
    const uint256 sigma_q =
        Fri3AlgSqueezeGrindDigest(sigma_core, joint_query_grind_nonce);

    // sigma_Q-absorbing master/child bindings.
    if (Fri3AlgJointQMasterBinding(fs_seed, proof.lane[0], proof.lane[1],
                                   sigma_q) !=
        proof.master_statement_binding)
        return fail("jointq master binding mismatch");
    for (uint32_t lane = 0; lane < kRCFri3AlgDualNumLanes; ++lane) {
        if (Fri3AlgDualChildBinding(proof.master_statement_binding, lane,
                                    proof.lane[lane].row_commit.root,
                                    kFri3AlgJointQSuite) !=
            proof.lane_child_binding[lane])
            return fail("jointq child binding mismatch");
    }

    // Pass 2: full verify each lane with every query index bound to the joint
    // squeeze. A per-lane last-round regrind that changed either lane's T_l
    // changes sigma_Q, hence every lane's expected joint index, and is rejected.
    for (uint32_t lane = 0; lane < kRCFri3AlgDualNumLanes; ++lane) {
        const uint256 lane_seed = Fri3AlgDualLaneSeed(
            fs_seed, proof.lane[lane].pow_grind_nonce, lane,
            kFri3AlgJointQSuite);
        Fri3AlgProtocolConfig config = DualLaneConfigForScenario(
            lane, Fri3AlgDualCommitmentScenario::SharedMasterDerivedChildren,
            kFri3AlgJointQSuite);
        config.joint_query = true;
        config.joint_query_sigma = &sigma_q;
        config.joint_query_lane = lane;
        std::string lane_why;
        if (!Fri3AlgBatchVerifyConfigured(proof.lane[lane], lane_seed, config,
                                          &lane_why)) {
            if (why) *why = "jointq lane " + std::to_string(lane) + ": " +
                            lane_why;
            return false;
        }
    }
    return true;
}

} // namespace matmul::v4::rc
