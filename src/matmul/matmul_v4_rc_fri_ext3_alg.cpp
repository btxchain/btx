// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_fri_ext3_alg.h>

#include <matmul/matmul_v4_rc_fri_ext3.h> // Sha256dBytes (FS transcript only)

#include <algorithm>
#include <cstring>
#include <string>

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
// path-local Q=148 query count (spec §5.2).

namespace matmul::v4::rc {
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
bool ReadFp3Checked(const unsigned char*& p, const unsigned char* end, Fp3& out)
{
    uint64_t a = 0, b = 0, c = 0;
    if (!ReadLE64Checked(p, end, a) || !ReadLE64Checked(p, end, b) ||
        !ReadLE64Checked(p, end, c))
        return false;
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

/** Field-native Merkle tree; node = alg_hash::Compress (2→1 over Fp^4). */
struct AlgMerkleTree {
    std::vector<std::vector<Fri3AlgDigest>> levels; // levels[0] = leaf digests
    Fri3AlgDigest root{};
};

/** Build from precomputed leaf digests (row tree: LeafHashRow; fold layers:
 *  LeafHash). Odd-pad by duplicating the last node — same shape as the SHA
 *  BuildMerkleTree, though LDE sizes here are always powers of two. */
AlgMerkleTree BuildAlgMerkleTreeFromLeaves(std::vector<Fri3AlgDigest> leaves)
{
    AlgMerkleTree t;
    if (leaves.empty()) return t; // root = all-zero digest (callers reject empty)
    t.levels.push_back(std::move(leaves));
    std::vector<Fri3AlgDigest> level = t.levels[0];
    while (level.size() > 1) {
        if (level.size() % 2 == 1) level.push_back(level.back());
        std::vector<Fri3AlgDigest> next;
        next.reserve(level.size() / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            next.push_back(alg_hash::Compress(level[i], level[i + 1]));
        }
        t.levels.push_back(next);
        level = std::move(next);
    }
    t.root = t.levels.back()[0];
    return t;
}

/** Fold-layer tree: leaf i = alg_hash::LeafHash(evals[i], i). */
AlgMerkleTree BuildAlgMerkleTree(const std::vector<Fp3>& evals)
{
    std::vector<Fri3AlgDigest> leaves(evals.size());
    for (size_t i = 0; i < evals.size(); ++i) {
        leaves[i] = alg_hash::LeafHash(evals[i], static_cast<uint32_t>(i));
    }
    return BuildAlgMerkleTreeFromLeaves(std::move(leaves));
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

    Fri3AlgFs(const uint256& fs_seed, uint64_t pow_grind_nonce, uint32_t blowup, uint32_t n_coeffs)
    {
        AppendBytes(buf, reinterpret_cast<const unsigned char*>(kRCFri3AlgBatchDomainTag),
                    sizeof(kRCFri3AlgBatchDomainTag) - 1);
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

    Fp3 ChallengeFp3(const char* label, uint32_t idx)
    {
        std::vector<unsigned char> tmp = buf;
        const size_t n = std::strlen(label);
        tmp.insert(tmp.end(), reinterpret_cast<const unsigned char*>(label),
                   reinterpret_cast<const unsigned char*>(label) + n);
        AppendLE32(tmp, idx);
        // 24 of the 32 SHA256d bytes feed the Fp3 draw (~2^192 challenge space).
        return FromChallengeBytes3(Sha256dBytes(tmp.data(), tmp.size()).data());
    }

    uint32_t ChallengeIndex(const char* label, uint32_t idx, uint32_t modulus)
    {
        if (modulus == 0) return 0;
        const Fp3 ch = ChallengeFp3(label, idx);
        // Use full 128-bit-ish entropy via (c0 || c1) mod modulus.
        const unsigned __int128 wide =
            (static_cast<unsigned __int128>(Canonical(ch.c1)) << 64) | Canonical(ch.c0);
        return static_cast<uint32_t>(wide % modulus);
    }
};

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
Fri3AlgDigest AlgMerkleRootConstantLayer(const Fp3& value, uint32_t n_leaves)
{
    std::vector<Fp3> consts(n_leaves, value);
    return BuildAlgMerkleTree(consts).root;
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

bool VerifyFoldStep(const Fri3AlgFoldStep& step, const Fri3AlgDigest& root, uint32_t n_leaves,
                    const Fp3& beta, uint32_t idx, Fp3& out_folded, std::string* why)
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

    if (!Fri3AlgVerifyPath(alg_hash::LeafHash(step.even, i), i, step.even_siblings, root,
                           n_leaves)) {
        return fail("fold even merkle");
    }
    if (!Fri3AlgVerifyPath(alg_hash::LeafHash(step.odd, step.odd_index), step.odd_index,
                           step.odd_siblings, root, n_leaves)) {
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
std::vector<Fri3AlgDigest> RowLeafDigests(const std::vector<std::vector<Fp3>>& column_lde,
                                          uint32_t n_lde)
{
    const uint32_t W = static_cast<uint32_t>(column_lde.size());
    std::vector<Fri3AlgDigest> leaves(n_lde);
    std::vector<Fp3> row(W);
    for (uint32_t i = 0; i < n_lde; ++i) {
        for (uint32_t c = 0; c < W; ++c) row[c] = column_lde[c][i];
        leaves[i] = alg_hash::LeafHashRow(row, i);
    }
    return leaves;
}

/** Batch FS preamble: domain-separated from every SHA-path transcript; the
 *  SINGLE row root replaces the per-column root list of the SHA batch. */
Fri3AlgFs Fri3AlgBatchFsInit(const uint256& fs_seed, uint64_t pow_grind_nonce, uint32_t n_coeffs,
                             const Fri3AlgLayerCommit& row_commit,
                             const std::vector<uint32_t>& column_len)
{
    Fri3AlgFs fs(fs_seed, pow_grind_nonce, kRCFriBlowup, n_coeffs);
    AppendLE32(fs.buf, kRCFri3AlgBatchProofVersion);
    AppendLE32(fs.buf, static_cast<uint32_t>(column_len.size()));
    for (const uint32_t len : column_len) AppendLE32(fs.buf, len);
    fs.AbsorbAlgRoot(row_commit.root);
    return fs;
}

/** Dual-OOD sampling: FS challenges rejected until (c1,c2)!=(0,0) (⇒ ∉ D) and
 *  distinct. The rejection counter is deterministic, so prover and verifier agree. */
Fp3 Fri3AlgBatchSampleZ(Fri3AlgFs& fs, uint32_t& ctr, const Fp3* distinct_from)
{
    while (true) {
        const Fp3 z = fs.ChallengeFp3("fra3_z", ctr++);
        if (!Fri3AlgHasExtCoord(z)) continue; // require nonzero extension part
        if (distinct_from != nullptr && Eq(z, *distinct_from)) continue;
        return z;
    }
}

} // namespace

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
    if (n_leaves == 0 || index >= n_leaves) return false;
    Fri3AlgDigest cur = leaf_digest;
    uint32_t idx = index;
    uint32_t width = n_leaves;
    size_t si = 0;
    while (width > 1) {
        if (width % 2 == 1) ++width; // match prover pad
        if (si >= siblings.size()) return false;
        const Fri3AlgDigest& sib = siblings[si++];
        if ((idx & 1u) == 0) cur = alg_hash::Compress(cur, sib);
        else cur = alg_hash::Compress(sib, cur);
        idx >>= 1;
        width /= 2;
    }
    return AlgDigestEq(cur, root) && si == siblings.size();
}

Fri3AlgDigest Fri3AlgBatchRowRoot(const std::vector<std::vector<Fp3>>& columns, uint32_t n_coeffs)
{
    if (columns.empty() || columns.size() > kRCFri3AlgBatchMaxColumns || n_coeffs == 0 ||
        (n_coeffs & (n_coeffs - 1)) != 0 ||
        static_cast<uint64_t>(n_coeffs) * kRCFriBlowup > (uint64_t{1} << kRCFriMaxLdeLog2)) {
        return Fri3AlgDigest{};
    }
    const uint32_t n_lde = n_coeffs * kRCFriBlowup;
    std::vector<std::vector<Fp3>> column_lde(columns.size());
    for (size_t i = 0; i < columns.size(); ++i) {
        if (columns[i].empty() || columns[i].size() > n_coeffs) return Fri3AlgDigest{};
        std::vector<Fp3> padded(n_coeffs, Fp3::Zero());
        for (size_t j = 0; j < columns[i].size(); ++j) padded[j] = columns[i][j];
        column_lde[i] = LdeFromCoeffs(padded, kRCFriBlowup);
    }
    return BuildAlgMerkleTreeFromLeaves(RowLeafDigests(column_lde, n_lde)).root;
}

Fri3AlgBatchCommitResult Fri3AlgBatchCommit(const std::vector<std::vector<Fp3>>& columns,
                                            const uint256& fs_seed, uint64_t pow_grind_nonce)
{
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

    Fri3AlgBatchProof& p = out.proof;
    p.version = kRCFri3AlgBatchProofVersion;
    p.pow_grind_nonce = pow_grind_nonce;
    p.blowup = kRCFriBlowup;
    p.n_coeffs = n;
    p.column_len.resize(W);
    out.column_lde.resize(W);
    for (uint32_t i = 0; i < W; ++i) {
        p.column_len[i] = static_cast<uint32_t>(columns[i].size());
        std::vector<Fp3> padded(n, Fp3::Zero());
        for (size_t j = 0; j < columns[i].size(); ++j) padded[j] = columns[i][j];
        out.column_lde[i] = LdeFromCoeffs(padded, kRCFriBlowup);
    }
    // ROW-WISE commitment (§2.3): ONE tree; leaf i = LeafHashRow of the whole
    // W-value row at LDE index i — one opening path per query instead of W.
    AlgMerkleTree row_tree = BuildAlgMerkleTreeFromLeaves(RowLeafDigests(out.column_lde, n_lde));
    p.row_commit.root = row_tree.root;
    p.row_commit.n_leaves = n_lde;

    // FS: the row root absorbed BEFORE any challenge (commit-then-challenge).
    Fri3AlgFs fs = Fri3AlgBatchFsInit(fs_seed, pow_grind_nonce, n, p.row_commit, p.column_len);

    // RLC λ over all columns (single batched instance).
    p.lambda = fs.ChallengeFp3("fra3_lambda", 0);
    fs.AbsorbFp3(p.lambda);

    // Dual OOD: two independent points; single-z caps the bindable degree.
    uint32_t zctr = 0;
    p.z1 = Fri3AlgBatchSampleZ(fs, zctr, nullptr);
    p.z2 = Fri3AlgBatchSampleZ(fs, zctr, &p.z1);
    fs.AbsorbFp3(p.z1);
    fs.AbsorbFp3(p.z2);

    // Claimed per-column evaluations at both OOD points (the opening primitive).
    p.evals_z1.resize(W);
    p.evals_z2.resize(W);
    for (uint32_t i = 0; i < W; ++i) {
        p.evals_z1[i] = EvalPolyCoeffs(columns[i], p.z1);
        p.evals_z2[i] = EvalPolyCoeffs(columns[i], p.z2);
        fs.AbsorbFp3(p.evals_z1[i]);
        fs.AbsorbFp3(p.evals_z2[i]);
    }
    p.w1 = fs.ChallengeFp3("fra3_w", 0);
    p.w2 = fs.ChallengeFp3("fra3_w", 1);
    fs.AbsorbFp3(p.w1);
    fs.AbsorbFp3(p.w2);

    // U = Σ λ^{i−1}·X^{n−len_i}·P_i (degree-shift = maximal-degree enforcement).
    std::vector<Fp3> lam_pow(W);
    lam_pow[0] = Fp3::One();
    for (uint32_t i = 1; i < W; ++i) lam_pow[i] = Mul(lam_pow[i - 1], p.lambda);
    std::vector<Fp3> U(n, Fp3::Zero());
    for (uint32_t i = 0; i < W; ++i) {
        const uint32_t shift = n - p.column_len[i];
        for (size_t j = 0; j < columns[i].size(); ++j) {
            U[shift + j] = Add(U[shift + j], Mul(lam_pow[i], columns[i][j]));
        }
    }
    // v_s = U(z_s) recomputed from the per-column claims (exactly equal for an
    // honest prover; the verifier recomputes the same way — that binds claims).
    Fp3 v1 = Fp3::Zero(), v2 = Fp3::Zero();
    for (uint32_t i = 0; i < W; ++i) {
        const uint32_t shift = n - p.column_len[i];
        v1 = Add(v1, Mul(Mul(lam_pow[i], PowFp3(p.z1, shift)), p.evals_z1[i]));
        v2 = Add(v2, Mul(Mul(lam_pow[i], PowFp3(p.z2, shift)), p.evals_z2[i]));
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
        AlgMerkleTree tree = BuildAlgMerkleTree(cur);
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
        const Fp3 beta =
            fs.ChallengeFp3("fra3_fold", static_cast<uint32_t>(p.fold_challenges.size()));
        p.fold_challenges.push_back(beta);
        std::vector<Fp3> next;
        if (!HalfDomainFoldLayer(cur, beta, next)) {
            out.note = "half-domain fold failed (x=0)";
            return out;
        }
        cur = std::move(next);
    }

    // Queries: Q = 148 (path-local, spec §5.2). The SAME index opens the ROW
    // (one path carrying all W values) AND G's fold path.
    p.queries.reserve(kRCFri3AlgNumQueries);
    for (uint32_t qi = 0; qi < kRCFri3AlgNumQueries; ++qi) {
        Fri3AlgBatchQuery q;
        q.index = fs.ChallengeIndex("fra3_query", qi, n_lde);
        q.row.values.resize(W);
        for (uint32_t i = 0; i < W; ++i) q.row.values[i] = out.column_lde[i][q.index];
        q.row.siblings = PathFromAlgTree(row_tree, q.index);
        uint32_t idx = q.index;
        q.steps.reserve(n_folds);
        for (uint32_t L = 0; L < n_folds; ++L) {
            q.steps.push_back(OpenFoldStep(g_layers[L], g_trees[L], idx));
            const uint32_t half = p.fold_layers[L].n_leaves / 2;
            idx = idx % half;
        }
        p.queries.push_back(std::move(q));
    }

    std::vector<unsigned char> ser;
    out.proof_bytes = SerializeFri3AlgBatchProof(p, ser);
    out.ok = true;
    out.note = kRCFri3AlgBatchSoundnessStatement;
    return out;
}

bool Fri3AlgBatchVerify(const Fri3AlgBatchProof& proof, const uint256& fs_seed, std::string* why)
{
    auto fail = [&](const char* w) {
        if (why) *why = w ? w : "Fri3AlgBatchVerify failed";
        return false;
    };
    if (proof.version != kRCFri3AlgBatchProofVersion) return fail("bad batch version");
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
    // Path-local soundness parameters: Q=148, hard cap, g=40, blowup=16
    // (statically asserted in the header; re-checked here fail-closed).
    if (proof.queries.size() != kRCFri3AlgNumQueries) return fail("query count");
    if (proof.queries.size() > kRCFri3AlgMaxQueriesHard) return fail("query count hard");
    if (!Fri3AlgClaimedBitsMeetTarget()) return fail("soundness params");

    // FS replay: every challenge recomputed from the transcript and compared.
    Fri3AlgFs fs = Fri3AlgBatchFsInit(fs_seed, proof.pow_grind_nonce, n, proof.row_commit,
                                      proof.column_len);
    {
        const Fp3 lambda = fs.ChallengeFp3("fra3_lambda", 0);
        if (!Eq(lambda, proof.lambda)) return fail("lambda mismatch");
        fs.AbsorbFp3(lambda);
    }
    {
        uint32_t zctr = 0;
        const Fp3 z1 = Fri3AlgBatchSampleZ(fs, zctr, nullptr);
        if (!Eq(z1, proof.z1)) return fail("z1 mismatch");
        const Fp3 z2 = Fri3AlgBatchSampleZ(fs, zctr, &z1);
        if (!Eq(z2, proof.z2)) return fail("z2 mismatch");
        fs.AbsorbFp3(z1);
        fs.AbsorbFp3(z2);
    }
    if (!Fri3AlgHasExtCoord(proof.z1) || !Fri3AlgHasExtCoord(proof.z2) ||
        Fri3AlgPointInDomain(proof.z1, n_lde) || Fri3AlgPointInDomain(proof.z2, n_lde) ||
        Eq(proof.z1, proof.z2)) {
        return fail("OOD points invalid");
    }
    for (uint32_t i = 0; i < W; ++i) {
        fs.AbsorbFp3(proof.evals_z1[i]);
        fs.AbsorbFp3(proof.evals_z2[i]);
    }
    {
        const Fp3 w1 = fs.ChallengeFp3("fra3_w", 0);
        const Fp3 w2 = fs.ChallengeFp3("fra3_w", 1);
        if (!Eq(w1, proof.w1) || !Eq(w2, proof.w2)) return fail("deep weights mismatch");
        fs.AbsorbFp3(w1);
        fs.AbsorbFp3(w2);
    }
    for (size_t i = 0; i < proof.fold_layers.size(); ++i) {
        fs.AbsorbAlgRoot(proof.fold_layers[i].root);
        if (i + 1 < proof.fold_layers.size()) {
            const Fp3 beta = fs.ChallengeFp3("fra3_fold", static_cast<uint32_t>(i));
            if (!Eq(beta, proof.fold_challenges[i])) return fail("fold challenge mismatch");
        }
    }
    if (!AlgDigestEq(AlgMerkleRootConstantLayer(proof.final_value, proof.blowup),
                     proof.fold_layers.back().root)) {
        return fail("final constant layer root");
    }

    // v_s = U(z_s) from the per-column claims — the DEEP identity below binds
    // every claimed (C_i(z1), C_i(z2)) to the committed words.
    std::vector<Fp3> lam_pow(W);
    lam_pow[0] = Fp3::One();
    for (uint32_t i = 1; i < W; ++i) lam_pow[i] = Mul(lam_pow[i - 1], proof.lambda);
    Fp3 v1 = Fp3::Zero(), v2 = Fp3::Zero();
    for (uint32_t i = 0; i < W; ++i) {
        const uint32_t shift = n - proof.column_len[i];
        v1 = Add(v1, Mul(Mul(lam_pow[i], PowFp3(proof.z1, shift)), proof.evals_z1[i]));
        v2 = Add(v2, Mul(Mul(lam_pow[i], PowFp3(proof.z2, shift)), proof.evals_z2[i]));
    }

    const uint32_t n_folds = static_cast<uint32_t>(proof.fold_challenges.size());
    for (uint32_t qi = 0; qi < kRCFri3AlgNumQueries; ++qi) {
        const Fri3AlgBatchQuery& q = proof.queries[qi];
        const uint32_t expect = fs.ChallengeIndex("fra3_query", qi, n_lde);
        if (q.index != expect) return fail("query index");
        if (q.row.values.size() != W) return fail("query row width");
        if (q.steps.size() != n_folds) return fail("query steps");

        // ONE row opening: recompute leaf i = LeafHashRow(row, i) from the
        // opened values, then ONE path into row_commit (§2.3).
        if (!Fri3AlgVerifyPath(alg_hash::LeafHashRow(q.row.values, q.index), q.index,
                               q.row.siblings, proof.row_commit.root, n_lde)) {
            return fail("row merkle");
        }
        const Fp3 x = DomainPoint(n_lde, q.index);
        Fp3 U_x = Fp3::Zero();
        for (uint32_t i = 0; i < W; ++i) {
            const uint32_t shift = n - proof.column_len[i];
            U_x = Add(U_x, Mul(Mul(lam_pow[i], PowFp3(x, shift)), q.row.values[i]));
        }

        // Dual-OOD DEEP identity at the query site.
        const Fp3 g_expect =
            Add(Mul(proof.w1, Mul(Sub(U_x, v1), Inv(Sub(x, proof.z1)))),
                Mul(proof.w2, Mul(Sub(U_x, v2), Inv(Sub(x, proof.z2)))));

        if (n_folds == 0) {
            // Constant G codeword bound by terminal root; must match DEEP identity.
            if (!Eq(g_expect, proof.final_value)) return fail("deep identity");
            continue;
        }

        uint32_t idx = q.index;
        Fp3 claimed{};
        bool have_claimed = false;
        for (uint32_t L = 0; L < n_folds; ++L) {
            const Fri3AlgFoldStep& step = q.steps[L];
            Fp3 folded{};
            std::string step_why;
            if (!VerifyFoldStep(step, proof.fold_layers[L].root, proof.fold_layers[L].n_leaves,
                                proof.fold_challenges[L], idx, folded, &step_why)) {
                return fail(step_why.c_str());
            }
            const uint32_t half = proof.fold_layers[L].n_leaves / 2;
            const Fp3 leaf_here = (idx < half) ? step.even : step.odd;
            if (L == 0) {
                if (!Eq(leaf_here, g_expect)) return fail("deep identity");
            } else if (have_claimed && !Eq(leaf_here, claimed)) {
                return fail("fold path consistency");
            }
            claimed = folded;
            have_claimed = true;
            idx = idx % half;
        }
        if (!Eq(claimed, proof.final_value)) return fail("final fold value");
    }

    if (why) *why = "Fri3AlgBatchVerify ok";
    return true;
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

std::optional<Fri3AlgBatchProof> DeserializeFri3AlgBatchProof(const std::vector<unsigned char>& in)
{
    if (in.size() > kRCFriMaxProofBytesHard) return std::nullopt;
    const unsigned char* p = in.data();
    const unsigned char* end = in.data() + in.size();
    uint32_t magic = 0, version = 0;
    if (!ReadLE32Checked(p, end, magic) || magic != kRCFri3AlgBatchProofMagic) return std::nullopt;
    if (!ReadLE32Checked(p, end, version) || version != kRCFri3AlgBatchProofVersion)
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
    if (!ReadFp3Checked(p, end, proof.lambda)) return std::nullopt;
    if (!ReadFp3Checked(p, end, proof.z1)) return std::nullopt;
    if (!ReadFp3Checked(p, end, proof.z2)) return std::nullopt;
    uint32_t n_e1 = 0, n_e2 = 0;
    if (!ReadLE32Checked(p, end, n_e1) || n_e1 != n_cols) return std::nullopt;
    proof.evals_z1.resize(n_e1);
    for (auto& e : proof.evals_z1) {
        if (!ReadFp3Checked(p, end, e)) return std::nullopt;
    }
    if (!ReadLE32Checked(p, end, n_e2) || n_e2 != n_cols) return std::nullopt;
    proof.evals_z2.resize(n_e2);
    for (auto& e : proof.evals_z2) {
        if (!ReadFp3Checked(p, end, e)) return std::nullopt;
    }
    if (!ReadFp3Checked(p, end, proof.w1)) return std::nullopt;
    if (!ReadFp3Checked(p, end, proof.w2)) return std::nullopt;
    uint32_t n_layers = 0;
    if (!ReadLE32Checked(p, end, n_layers) || n_layers == 0 || n_layers > 64) return std::nullopt;
    proof.fold_layers.resize(n_layers);
    for (auto& lc : proof.fold_layers) {
        if (!ReadAlgDigestChecked(p, end, lc.root)) return std::nullopt;
        if (!ReadLE32Checked(p, end, lc.n_leaves)) return std::nullopt;
    }
    if (!ReadFp3Checked(p, end, proof.final_value)) return std::nullopt;
    uint32_t n_ch = 0;
    if (!ReadLE32Checked(p, end, n_ch) || n_ch > 64) return std::nullopt;
    proof.fold_challenges.resize(n_ch);
    for (auto& c : proof.fold_challenges) {
        if (!ReadFp3Checked(p, end, c)) return std::nullopt;
    }
    uint32_t n_q = 0;
    if (!ReadLE32Checked(p, end, n_q) || n_q > kRCFri3AlgMaxQueriesHard) return std::nullopt;
    proof.queries.resize(n_q);
    for (auto& q : proof.queries) {
        if (!ReadLE32Checked(p, end, q.index)) return std::nullopt;
        uint32_t n_rv = 0;
        if (!ReadLE32Checked(p, end, n_rv) || n_rv != n_cols) return std::nullopt;
        q.row.values.resize(n_rv);
        for (auto& v : q.row.values) {
            if (!ReadFp3Checked(p, end, v)) return std::nullopt;
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
            if (!ReadFp3Checked(p, end, st.even)) return std::nullopt;
            if (!ReadFp3Checked(p, end, st.odd)) return std::nullopt;
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

} // namespace matmul::v4::rc
