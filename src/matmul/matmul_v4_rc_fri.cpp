// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_fri.h>

#include <crypto/common.h>
#include <crypto/sha256.h>

#include <algorithm>
#include <cstring>
#include <string>

namespace matmul::v4::rc {
namespace {

using gkr_field::Add;
using gkr_field::Canonical;
using gkr_field::Eq;
using gkr_field::Fp;
using gkr_field::FromChallengeBytes2;
using gkr_field::Inv;
using gkr_field::Mul;
using gkr_field::Sub;

/** Goldilocks 2^32-th root of unity: 7^((p-1)/2^32). */
constexpr Fp kOmega2_32 = 0x185629dcda58878cULL;

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

void BitReverse(std::vector<Fp2>& a)
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

/** In-place radix-2 NTT over Fp2 using base-field roots embedded as (ω, 0). */
void NttFp2(std::vector<Fp2>& a, bool inverse)
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
                const Fp2 u = a[i + j];
                const Fp2 v = Mul(a[i + j + len / 2], Fp2::FromFp(w));
                a[i + j] = Add(u, v);
                a[i + j + len / 2] = Sub(u, v);
                w = Mul(w, w_len);
            }
        }
    }
    if (inverse) {
        const Fp inv_n = Inv(static_cast<Fp>(n));
        const Fp2 inv = Fp2::FromFp(inv_n);
        for (auto& x : a) x = Mul(x, inv);
    }
}

/** LDE: coeffs (deg < n) → evaluations on size-(blowup*n) subgroup. */
std::vector<Fp2> LdeFromCoeffs(const std::vector<Fp2>& coeffs, uint32_t blowup)
{
    const uint32_t n = static_cast<uint32_t>(coeffs.size());
    const uint32_t N = n * blowup;
    std::vector<Fp2> padded(N, Fp2::Zero());
    for (size_t i = 0; i < coeffs.size(); ++i) padded[i] = coeffs[i];
    NttFp2(padded, /*inverse=*/false);
    return padded;
}

struct MerkleTree {
    std::vector<std::vector<uint256>> levels; // levels[0] = leaves
    uint256 root{};
};

MerkleTree BuildMerkleTree(const std::vector<Fp2>& evals)
{
    MerkleTree t;
    if (evals.empty()) {
        t.root = Sha256dBytes(reinterpret_cast<const unsigned char*>("FRI_EMPTY"), 9);
        return t;
    }
    std::vector<uint256> level(evals.size());
    for (size_t i = 0; i < evals.size(); ++i) {
        level[i] = FriLeafHash(evals[i], static_cast<uint32_t>(i));
    }
    t.levels.push_back(level);
    while (level.size() > 1) {
        if (level.size() % 2 == 1) level.push_back(level.back());
        std::vector<uint256> next;
        next.reserve(level.size() / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            next.push_back(FriNodeHash(level[i], level[i + 1]));
        }
        t.levels.push_back(next);
        level = std::move(next);
    }
    t.root = t.levels.back()[0];
    return t;
}

std::vector<uint256> PathFromTree(const MerkleTree& tree, uint32_t index)
{
    std::vector<uint256> siblings;
    if (tree.levels.empty()) return siblings;
    uint32_t idx = index;
    for (size_t li = 0; li + 1 < tree.levels.size(); ++li) {
        auto level = tree.levels[li];
        // Match BuildMerkleTree's odd-pad (pad is only in the next-level build;
        // reconstruct padded width for sibling lookup).
        if (level.size() % 2 == 1) level.push_back(level.back());
        const uint32_t sib = idx ^ 1u;
        siblings.push_back(level[sib]);
        idx >>= 1;
    }
    return siblings;
}

/** Commit-then-challenge FS state for FRI layers + queries. */
struct FriFs {
    std::vector<unsigned char> buf;

    FriFs(const uint256& fs_seed, uint64_t pow_grind_nonce, uint32_t blowup, uint32_t n_coeffs)
    {
        AppendBytes(buf, reinterpret_cast<const unsigned char*>(kRCFriDomainTag),
                    sizeof(kRCFriDomainTag) - 1);
        AppendBytes(buf, fs_seed.data(), 32);
        AppendLE64(buf, pow_grind_nonce);
        AppendLE32(buf, blowup);
        AppendLE32(buf, n_coeffs);
    }

    void AbsorbRoot(const uint256& root) { AppendBytes(buf, root.data(), 32); }
    void AbsorbFp2(const Fp2& v) { AppendFp2(buf, v); }

    Fp2 ChallengeFp2(const char* label, uint32_t idx)
    {
        std::vector<unsigned char> tmp = buf;
        const size_t n = std::strlen(label);
        tmp.insert(tmp.end(), reinterpret_cast<const unsigned char*>(label),
                   reinterpret_cast<const unsigned char*>(label) + n);
        AppendLE32(tmp, idx);
        return FromChallengeBytes2(Sha256dBytes(tmp.data(), tmp.size()).data());
    }

    uint32_t ChallengeIndex(const char* label, uint32_t idx, uint32_t modulus)
    {
        if (modulus == 0) return 0;
        const Fp2 ch = ChallengeFp2(label, idx);
        // Use full 128-bit-ish entropy via (c0 || c1) mod modulus.
        const unsigned __int128 wide =
            (static_cast<unsigned __int128>(Canonical(ch.c1)) << 64) | Canonical(ch.c0);
        return static_cast<uint32_t>(wide % modulus);
    }
};

/** log2(n) for n = 2^k ≥ 1. */
uint32_t FriLog2Exact(uint32_t n)
{
    uint32_t log = 0;
    while (n > 1) {
        n >>= 1;
        ++log;
    }
    return log;
}

Fp2 DomainPoint(uint32_t n0, uint32_t index)
{
    return Fp2::FromFp(PowFp(OmegaForSize(n0), index));
}

/** z ∈ D (size-n_lde LDE subgroup on the c1=0 base-field line)? */
bool FriPointInDomain(const Fp2& z, uint32_t n_lde)
{
    if (Canonical(z.c1) != 0) return false;
    return Canonical(PowFp(z.c0, n_lde)) == 1;
}

/**
 * OOD sample: FS challenges until the Fp2 extension coefficient is nonzero.
 * c1!=0 ⇒ automatically ∉ D (D embeds on the c1=0 line). Rejection is
 * deterministic so prover and verifier agree on the counter.
 */
Fp2 FriSampleOodZ(FriFs& fs, const char* label, uint32_t& ctr)
{
    while (true) {
        const Fp2 z = fs.ChallengeFp2(label, ctr++);
        if (Canonical(z.c1) != 0) return z;
    }
}

/**
 * v5 half-domain fold: pair i with i+N/2.
 *   even = (f(x)+f(-x))/2, odd = (f(x)-f(-x))/(2x), next = even + β·odd
 * Returns false if x=0 (fail closed; should not occur on subgroup points).
 */
bool HalfDomainFoldLayer(const std::vector<Fp2>& cur, const Fp2& beta, std::vector<Fp2>& next)
{
    const uint32_t N = static_cast<uint32_t>(cur.size());
    if (N < 2 || (N % 2) != 0) return false;
    const uint32_t half = N / 2;
    next.resize(half);
    const Fp2 inv2 = Inv(Fp2::FromFp(2));
    for (uint32_t i = 0; i < half; ++i) {
        const Fp2 f_x = cur[i];
        const Fp2 f_neg = cur[i + half];
        const Fp2 x = DomainPoint(N, i);
        if (gkr_field::IsZero(x)) return false;
        const Fp2 even = Mul(Add(f_x, f_neg), inv2);
        const Fp2 odd = Mul(Sub(f_x, f_neg), Mul(inv2, Inv(x)));
        next[i] = Add(even, Mul(beta, odd));
    }
    return true;
}

/** Algebraic fold of one opened pair (same formula as HalfDomainFoldLayer). */
bool HalfDomainFoldPair(const Fp2& f_x, const Fp2& f_neg, const Fp2& x, const Fp2& beta,
                        Fp2& out_folded)
{
    if (gkr_field::IsZero(x)) return false;
    const Fp2 inv2 = Inv(Fp2::FromFp(2));
    const Fp2 even = Mul(Add(f_x, f_neg), inv2);
    const Fp2 odd = Mul(Sub(f_x, f_neg), Mul(inv2, Inv(x)));
    out_folded = Add(even, Mul(beta, odd));
    return true;
}

/** Merkle root of blowup identical constant leaves (terminal v5 layer). */
uint256 MerkleRootConstantLayer(const Fp2& value, uint32_t n_leaves)
{
    std::vector<Fp2> consts(n_leaves, value);
    return BuildMerkleTree(consts).root;
}

FriFoldStep OpenFoldStep(const std::vector<Fp2>& evals, const MerkleTree& tree, uint32_t idx)
{
    FriFoldStep step;
    const uint32_t n = static_cast<uint32_t>(evals.size());
    const uint32_t half = n / 2;
    const uint32_t i = idx % half;
    step.even_index = i;
    step.odd_index = i + half;
    step.even = evals[i];
    step.odd = evals[i + half];
    step.even_siblings = PathFromTree(tree, i);
    step.odd_siblings = PathFromTree(tree, i + half);
    return step;
}

bool VerifyFoldStep(const FriFoldStep& step, const uint256& root, uint32_t n_leaves,
                    const Fp2& beta, uint32_t idx, Fp2& out_folded, std::string* why)
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

    FriMerklePath pe;
    pe.index = i;
    pe.leaf = step.even;
    pe.siblings = step.even_siblings;
    FriMerklePath po;
    po.index = step.odd_index;
    po.leaf = step.odd;
    po.siblings = step.odd_siblings;
    if (!FriVerifyPath(pe, root, n_leaves)) return fail("fold even merkle");
    if (!FriVerifyPath(po, root, n_leaves)) return fail("fold odd merkle");

    const Fp2 x = DomainPoint(n_leaves, i);
    if (!HalfDomainFoldPair(step.even, step.odd, x, beta, out_folded)) {
        return fail("fold x=0");
    }
    return true;
}

Fp2 PowFp2(Fp2 base, uint64_t exp)
{
    Fp2 result = Fp2::One();
    while (exp > 0) {
        if (exp & 1u) result = Mul(result, base);
        base = Mul(base, base);
        exp >>= 1;
    }
    return result;
}

Fp2 EvalPolyCoeffs(const std::vector<Fp2>& coeffs, const Fp2& z)
{
    Fp2 acc = Fp2::Zero();
    for (size_t i = coeffs.size(); i-- > 0;) {
        acc = Add(Mul(acc, z), coeffs[i]);
    }
    return acc;
}

/** Quotient coeffs of (P(X) − v) / (X − z). Requires P(z)=v. */
std::vector<Fp2> SyntheticQuotient(const std::vector<Fp2>& coeffs, const Fp2& z, const Fp2& v)
{
    if (coeffs.size() <= 1) return {};
    std::vector<Fp2> num = coeffs;
    num[0] = Sub(num[0], v);
    const size_t n = num.size();
    std::vector<Fp2> q(n - 1, Fp2::Zero());
    q[n - 2] = num[n - 1];
    for (size_t k = n - 1; k-- > 1;) {
        q[k - 1] = Add(num[k], Mul(z, q[k]));
    }
    return q;
}

} // namespace

uint32_t FriNextPow2(uint32_t n)
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

uint256 FriLeafHash(const Fp2& v, uint32_t index)
{
    std::vector<unsigned char> buf;
    AppendBytes(buf, reinterpret_cast<const unsigned char*>(kRCFriDomainTag),
                sizeof(kRCFriDomainTag) - 1);
    AppendBytes(buf, reinterpret_cast<const unsigned char*>("leaf"), 4);
    AppendLE32(buf, index);
    AppendFp2(buf, v);
    return Sha256dBytes(buf.data(), buf.size());
}

uint256 FriNodeHash(const uint256& left, const uint256& right)
{
    std::vector<unsigned char> buf;
    AppendBytes(buf, reinterpret_cast<const unsigned char*>(kRCFriDomainTag),
                sizeof(kRCFriDomainTag) - 1);
    AppendBytes(buf, reinterpret_cast<const unsigned char*>("node"), 4);
    AppendBytes(buf, left.data(), 32);
    AppendBytes(buf, right.data(), 32);
    return Sha256dBytes(buf.data(), buf.size());
}

FriMerklePath FriOpenIndex(const std::vector<Fp2>& evals, uint32_t index)
{
    FriMerklePath path;
    if (evals.empty()) return path;
    const uint32_t n = static_cast<uint32_t>(evals.size());
    path.index = index % n;
    path.leaf = evals[path.index];
    const MerkleTree tree = BuildMerkleTree(evals);
    path.siblings = PathFromTree(tree, path.index);
    return path;
}

bool FriVerifyPath(const FriMerklePath& path, const uint256& root, uint32_t n_leaves)
{
    if (n_leaves == 0 || path.index >= n_leaves) return false;
    uint256 cur = FriLeafHash(path.leaf, path.index);
    uint32_t idx = path.index;
    uint32_t width = n_leaves;
    size_t si = 0;
    while (width > 1) {
        if (width % 2 == 1) ++width; // match prover pad
        if (si >= path.siblings.size()) return false;
        const uint256& sib = path.siblings[si++];
        if ((idx & 1u) == 0) cur = FriNodeHash(cur, sib);
        else cur = FriNodeHash(sib, cur);
        idx >>= 1;
        width /= 2;
    }
    return cur == root && si == path.siblings.size();
}

FriCommitResult FriCommitAndFoldImpl(const std::vector<Fp2>& coeffs, const uint256& fs_seed,
                                     uint64_t pow_grind_nonce, bool enable_deep,
                                     const Fp2* forced_deep_z)
{
    FriCommitResult out;
    if (coeffs.empty()) {
        out.note = "empty coeffs";
        return out;
    }
    const uint32_t n = FriNextPow2(static_cast<uint32_t>(coeffs.size()));
    if ((n * static_cast<uint64_t>(kRCFriBlowup)) > (uint64_t{1} << kRCFriMaxLdeLog2)) {
        out.note = "LDE domain too large";
        return out;
    }

    std::vector<Fp2> coeff_pow2(n, Fp2::Zero());
    for (size_t i = 0; i < coeffs.size(); ++i) coeff_pow2[i] = coeffs[i];

    out.lde_evals = LdeFromCoeffs(coeff_pow2, kRCFriBlowup);
    out.proof.version = kRCFriProofVersion;
    out.proof.pow_grind_nonce = pow_grind_nonce;
    out.proof.blowup = kRCFriBlowup;
    out.proof.n_coeffs = n;

    FriFs fs(fs_seed, pow_grind_nonce, kRCFriBlowup, n);

    // Exactly log2(n_coeffs) half-domain folds; terminal layer size = blowup.
    const uint32_t n_folds = FriLog2Exact(n);
    std::vector<Fp2> cur = out.lde_evals;
    std::vector<MerkleTree> trees;
    for (uint32_t fold = 0;; ++fold) {
        MerkleTree tree = BuildMerkleTree(cur);
        FriLayerCommit lc;
        lc.n_leaves = static_cast<uint32_t>(cur.size());
        lc.root = tree.root;
        out.proof.layers.push_back(lc);
        out.layer_evals.push_back(cur);
        trees.push_back(std::move(tree));
        fs.AbsorbRoot(lc.root);

        if (fold == n_folds) {
            if (cur.size() != kRCFriBlowup) {
                out.note = "terminal layer size != blowup";
                return out;
            }
            out.proof.final_value = cur[0];
            for (size_t i = 1; i < cur.size(); ++i) {
                if (!Eq(cur[i], out.proof.final_value)) {
                    out.note = "terminal layer not constant";
                    return out;
                }
            }
            break;
        }

        const Fp2 beta =
            fs.ChallengeFp2("fri_fold", static_cast<uint32_t>(out.proof.fold_challenges.size()));
        out.proof.fold_challenges.push_back(beta);
        std::vector<Fp2> next;
        if (!HalfDomainFoldLayer(cur, beta, next)) {
            out.note = "half-domain fold failed (x=0)";
            return out;
        }
        cur = std::move(next);
    }

    std::vector<Fp2> quot_lde;
    MerkleTree quot_tree;
    bool deep_habock_merkle = false;
    if (enable_deep) {
        out.proof.has_deep = true;
        const uint32_t n0_lde = static_cast<uint32_t>(out.lde_evals.size());
        if (forced_deep_z) {
            out.proof.deep_z_forced = true;
            out.proof.deep_z = *forced_deep_z;
            fs.AbsorbFp2(out.proof.deep_z); // bind fixed z (no FS sample)
            // Haböck I(1): z=1 ∈ D — bind via layer-0 Merkle opening, not quotient.
            deep_habock_merkle = FriPointInDomain(out.proof.deep_z, n0_lde);
        } else {
            out.proof.deep_z_forced = false;
            uint32_t zctr = 0;
            out.proof.deep_z = FriSampleOodZ(fs, "deep_z", zctr);
            fs.AbsorbFp2(out.proof.deep_z);
        }
        out.proof.deep_eval = EvalPolyCoeffs(coeff_pow2, out.proof.deep_z);
        fs.AbsorbFp2(out.proof.deep_eval);

        if (deep_habock_merkle) {
            // Forced z∈D: only z=1 is supported (LogUp Σ / Haböck I(1)).
            if (!Eq(out.proof.deep_z, Fp2::One())) {
                out.note = "forced in-domain deep_z must be 1 (Haböck)";
                return out;
            }
            out.proof.deep_domain_index = 0; // DomainPoint(n0, 0) == 1
            if (!Eq(out.lde_evals[0], out.proof.deep_eval)) {
                out.note = "Haböck P(1) LDE mismatch";
                return out;
            }
            out.proof.deep_domain_siblings = PathFromTree(trees[0], 0);
            // No quotient FRI / deep_quot_* on Haböck path.
        } else {
            std::vector<Fp2> quot =
                SyntheticQuotient(coeff_pow2, out.proof.deep_z, out.proof.deep_eval);
            if (quot.empty()) quot.push_back(Fp2::Zero());
            // Pad Q to the same coeff length as P so LDE domains / indices coincide.
            if (quot.size() < coeff_pow2.size()) quot.resize(coeff_pow2.size(), Fp2::Zero());
            auto quot_c = FriCommitAndFold(quot, fs_seed, pow_grind_nonce ^ uint64_t{0xD33D},
                                           /*enable_deep=*/false);
            if (!quot_c.ok) {
                out.note = "deep quot FRI failed";
                return out;
            }
            out.proof.deep_quot_fri = std::make_shared<FriProof>(std::move(quot_c.proof));
            quot_lde = std::move(quot_c.lde_evals);
            if (out.proof.deep_quot_fri->layers.empty()) {
                out.note = "deep quot empty layers";
                return out;
            }
            // Reported quotient root/count MUST equal nested FRI layer-0.
            out.proof.deep_quot_root = out.proof.deep_quot_fri->layers[0].root;
            out.proof.deep_quot_n_leaves = out.proof.deep_quot_fri->layers[0].n_leaves;
            quot_tree = BuildMerkleTree(quot_lde);
            if (quot_tree.root != out.proof.deep_quot_root ||
                static_cast<uint32_t>(quot_lde.size()) != out.proof.deep_quot_n_leaves) {
                out.note = "deep quot root/count != nested FRI layer-0";
                return out;
            }
            fs.AbsorbRoot(out.proof.deep_quot_root);
            fs.AbsorbRoot(out.proof.deep_quot_fri->layers[0].root);
        }
    }

    const uint32_t n0 = out.proof.layers[0].n_leaves;
    out.proof.queries.reserve(kRCFriNumQueries);
    for (uint32_t qi = 0; qi < kRCFriNumQueries; ++qi) {
        FriQueryOpening q;
        q.index = fs.ChallengeIndex("fri_query", qi, n0);
        uint32_t idx = q.index;
        q.steps.reserve(n_folds);
        for (uint32_t L = 0; L < n_folds; ++L) {
            q.steps.push_back(OpenFoldStep(out.layer_evals[L], trees[L], idx));
            const uint32_t half = out.proof.layers[L].n_leaves / 2;
            idx = idx % half;
        }
        if (enable_deep && !deep_habock_merkle && !quot_lde.empty()) {
            if (quot_lde.size() != out.lde_evals.size()) {
                out.note = "deep quot LDE size mismatch";
                out.ok = false;
                return out;
            }
            q.deep_quot_leaf = quot_lde[q.index];
            q.deep_quot_siblings = PathFromTree(quot_tree, q.index);
        }
        out.proof.queries.push_back(std::move(q));
    }

    std::vector<unsigned char> ser;
    out.proof_bytes = SerializeFriProof(out.proof, ser);
    out.ok = true;
    out.note = kRCFriSoundnessStatement;
    return out;
}

bool FriVerify(const FriProof& proof, const uint256& fs_seed, std::string* why)
{
    auto fail = [&](const char* w) {
        if (why) *why = w ? w : "FriVerify failed";
        return false;
    };
    if (proof.version != kRCFriProofVersion) return fail("bad fri version");
    if (proof.blowup != kRCFriBlowup) return fail("bad blowup");
    if (proof.layers.empty()) return fail("no layers");
    if (proof.layers.size() > kRCFriMaxFoldLayersHard) return fail("FRI depth");
    if (proof.n_coeffs == 0 || proof.n_coeffs > kRCFriMaxCoeffsHard ||
        (proof.n_coeffs & (proof.n_coeffs - 1)) != 0)
        return fail("n_coeffs not pow2");
    if (proof.layers[0].n_leaves != proof.n_coeffs * proof.blowup) return fail("LDE size");
    const uint32_t n_folds_expect = FriLog2Exact(proof.n_coeffs);
    if (proof.fold_challenges.size() != n_folds_expect) return fail("fold count");
    if (proof.fold_challenges.size() + 1 != proof.layers.size()) return fail("layer/challenge count");
    if (proof.layers.back().n_leaves != proof.blowup) return fail("final layer not blowup");
    if (proof.queries.size() != kRCFriNumQueries) return fail("query count");
    if (proof.queries.size() > kRCFriMaxQueriesHard) return fail("query count hard");

    for (size_t i = 0; i + 1 < proof.layers.size(); ++i) {
        if (proof.layers[i].n_leaves < 2 || (proof.layers[i].n_leaves % 2) != 0)
            return fail("layer parity");
        if (proof.layers[i].n_leaves / 2 != proof.layers[i + 1].n_leaves) return fail("layer size");
    }

    FriFs fs(fs_seed, proof.pow_grind_nonce, proof.blowup, proof.n_coeffs);
    for (size_t i = 0; i < proof.layers.size(); ++i) {
        fs.AbsorbRoot(proof.layers[i].root);
        if (i + 1 < proof.layers.size()) {
            const Fp2 beta = fs.ChallengeFp2("fri_fold", static_cast<uint32_t>(i));
            if (!Eq(beta, proof.fold_challenges[i])) return fail("fold challenge mismatch");
        }
    }

    // Terminal B-constant layer: reconstruct Merkle root of B identical leaves.
    if (MerkleRootConstantLayer(proof.final_value, proof.blowup) != proof.layers.back().root) {
        return fail("final constant layer root");
    }

    if (proof.has_deep) {
        const uint32_t n0_lde = proof.layers[0].n_leaves;
        const bool habock =
            proof.deep_z_forced && FriPointInDomain(proof.deep_z, n0_lde);
        if (proof.deep_z_forced) {
            fs.AbsorbFp2(proof.deep_z);
        } else {
            uint32_t zctr = 0;
            const Fp2 z = FriSampleOodZ(fs, "deep_z", zctr);
            if (!Eq(z, proof.deep_z)) return fail("deep_z");
            if (Canonical(proof.deep_z.c1) == 0) return fail("deep_z c1==0");
            fs.AbsorbFp2(proof.deep_z);
        }
        fs.AbsorbFp2(proof.deep_eval);

        if (habock) {
            // Haböck I(1): z=1 ∈ D — layer-0 Merkle opening of P, no quotient.
            if (!Eq(proof.deep_z, Fp2::One())) return fail("habock deep_z not 1");
            if (proof.deep_quot_fri) return fail("unexpected deep quot");
            if (proof.deep_quot_n_leaves != 0) return fail("habock unexpected quot leaves");
            if (proof.deep_domain_index != 0) return fail("habock domain index");
            FriMerklePath mp;
            mp.index = proof.deep_domain_index;
            mp.leaf = proof.deep_eval;
            mp.siblings = proof.deep_domain_siblings;
            if (!FriVerifyPath(mp, proof.layers[0].root, proof.layers[0].n_leaves)) {
                return fail("habock domain merkle");
            }
        } else {
            if (!proof.deep_quot_fri) return fail("missing deep quot FRI");
            if (proof.deep_quot_fri->layers.empty()) return fail("deep quot empty");
            if (proof.deep_quot_root != proof.deep_quot_fri->layers[0].root) {
                return fail("deep_quot_root != nested FRI layer-0");
            }
            if (proof.deep_quot_n_leaves != proof.deep_quot_fri->layers[0].n_leaves) {
                return fail("deep_quot_n_leaves != nested FRI layer-0");
            }
            if (proof.deep_quot_n_leaves == 0) return fail("deep quot leaves");
            fs.AbsorbRoot(proof.deep_quot_root);
            fs.AbsorbRoot(proof.deep_quot_fri->layers[0].root);
            std::string qw;
            if (!FriVerify(*proof.deep_quot_fri, fs_seed, &qw)) return fail(qw.c_str());
        }
    } else if (proof.deep_quot_fri) {
        return fail("unexpected deep quot");
    }

    const uint32_t n0 = proof.layers[0].n_leaves;
    const uint32_t n_folds = static_cast<uint32_t>(proof.fold_challenges.size());
    const bool deep_ood = proof.has_deep && !(proof.deep_z_forced && FriPointInDomain(proof.deep_z, n0));

    for (uint32_t qi = 0; qi < kRCFriNumQueries; ++qi) {
        const FriQueryOpening& q = proof.queries[qi];
        const uint32_t expect = fs.ChallengeIndex("fri_query", qi, n0);
        if (q.index != expect) return fail("query index");
        if (q.steps.size() != n_folds) return fail("query steps");

        uint32_t idx = q.index;
        Fp2 claimed{};
        bool have_claimed = false;
        Fp2 p_at_x = Fp2::Zero();

        if (n_folds == 0) {
            // Constant codeword: P(x) = final_value on the LDE (bound by terminal root).
            p_at_x = proof.final_value;
            have_claimed = true;
            claimed = proof.final_value;
        }

        for (uint32_t L = 0; L < n_folds; ++L) {
            const FriFoldStep& step = q.steps[L];
            Fp2 folded{};
            std::string step_why;
            if (!VerifyFoldStep(step, proof.layers[L].root, proof.layers[L].n_leaves,
                                proof.fold_challenges[L], idx, folded, &step_why)) {
                return fail(step_why.c_str());
            }
            const uint32_t half = proof.layers[L].n_leaves / 2;
            const Fp2 leaf_here = (idx < half) ? step.even : step.odd;
            if (L == 0) p_at_x = leaf_here;
            if (have_claimed) {
                if (!Eq(leaf_here, claimed)) return fail("fold path consistency");
            }
            claimed = folded;
            have_claimed = true;
            idx = idx % half;
        }

        if (!have_claimed || !Eq(claimed, proof.final_value)) return fail("final fold value");

        if (deep_ood) {
            FriMerklePath qp;
            qp.index = q.index;
            qp.leaf = q.deep_quot_leaf;
            qp.siblings = q.deep_quot_siblings;
            if (q.index >= proof.deep_quot_n_leaves) return fail("deep quot index");
            if (!FriVerifyPath(qp, proof.deep_quot_root, proof.deep_quot_n_leaves)) {
                return fail("deep quot merkle");
            }
            const Fp2 x = DomainPoint(n0, q.index);
            const Fp2 rhs = Add(Mul(q.deep_quot_leaf, Sub(x, proof.deep_z)), proof.deep_eval);
            if (!Eq(p_at_x, rhs)) return fail("deep identity");
        }
    }

    if (why) *why = "FriVerify ok";
    return true;
}

bool FriForgeFlippedEvalMustFail(const FriCommitResult& honest, const uint256& fs_seed,
                                 uint32_t flip_index, std::string* why)
{
    if (!honest.ok || honest.lde_evals.empty() || honest.proof.layers.empty()) {
        if (why) *why = "no honest proof";
        return false; // forge helper itself failed — not a verify-pass
    }
    FriProof forged = honest.proof;
    // Flip one LDE eval conceptually: recompute ONLY layer-0 root from a
    // tampered leaf hash while retaining old multi-layer openings.
    const uint32_t n0 = forged.layers[0].n_leaves;
    const uint32_t idx = flip_index % n0;
    Fp2 flipped = honest.lde_evals[idx];
    flipped.c0 ^= 1;
    // Rebuild layer-0 Merkle root from tampered leaf, keep openings.
    std::vector<Fp2> tampered = honest.lde_evals;
    tampered[idx] = flipped;
    forged.layers[0].root = BuildMerkleTree(tampered).root;
    // Keep old queries/openings → inconsistent with new root OR with folds.
    std::string local;
    const bool ok = FriVerify(forged, fs_seed, &local);
    if (why) *why = ok ? "FORGE PASSED (bug)" : local;
    return !ok; // true iff verify correctly rejected
}

size_t SerializeFriProof(const FriProof& proof, std::vector<unsigned char>& out)
{
    out.clear();
    AppendLE32(out, kRCFriProofMagic);
    AppendLE32(out, proof.version);
    AppendLE64(out, proof.pow_grind_nonce);
    AppendLE32(out, proof.blowup);
    AppendLE32(out, proof.n_coeffs);
    AppendLE32(out, static_cast<uint32_t>(proof.layers.size()));
    for (const auto& lc : proof.layers) {
        AppendBytes(out, lc.root.data(), 32);
        AppendLE32(out, lc.n_leaves);
    }
    AppendFp2(out, proof.final_value);
    AppendLE32(out, static_cast<uint32_t>(proof.fold_challenges.size()));
    for (const auto& c : proof.fold_challenges) AppendFp2(out, c);
    AppendLE32(out, static_cast<uint32_t>(proof.queries.size()));
    for (const auto& q : proof.queries) {
        AppendLE32(out, q.index);
        AppendLE32(out, static_cast<uint32_t>(q.steps.size()));
        for (const auto& st : q.steps) {
            AppendLE32(out, st.even_index);
            AppendLE32(out, st.odd_index);
            AppendFp2(out, st.even);
            AppendFp2(out, st.odd);
            AppendLE32(out, static_cast<uint32_t>(st.even_siblings.size()));
            for (const auto& s : st.even_siblings) AppendBytes(out, s.data(), 32);
            AppendLE32(out, static_cast<uint32_t>(st.odd_siblings.size()));
            for (const auto& s : st.odd_siblings) AppendBytes(out, s.data(), 32);
        }
        AppendFp2(out, q.deep_quot_leaf);
        AppendLE32(out, static_cast<uint32_t>(q.deep_quot_siblings.size()));
        for (const auto& s : q.deep_quot_siblings) AppendBytes(out, s.data(), 32);
    }
    out.push_back(proof.has_deep ? 1 : 0);
    out.push_back(proof.deep_z_forced ? 1 : 0);
    if (proof.has_deep) {
        AppendFp2(out, proof.deep_z);
        AppendFp2(out, proof.deep_eval);
        AppendBytes(out, proof.deep_quot_root.data(), 32);
        AppendLE32(out, proof.deep_quot_n_leaves);
        std::vector<unsigned char> nested;
        if (proof.deep_quot_fri) {
            (void)SerializeFriProof(*proof.deep_quot_fri, nested);
        }
        AppendLE32(out, static_cast<uint32_t>(nested.size()));
        AppendBytes(out, nested.data(), nested.size());
        AppendLE32(out, proof.deep_domain_index);
        AppendLE32(out, static_cast<uint32_t>(proof.deep_domain_siblings.size()));
        for (const auto& s : proof.deep_domain_siblings) AppendBytes(out, s.data(), 32);
    }
    return out.size();
}

std::optional<FriProof> DeserializeFriProofDepth(const std::vector<unsigned char>& in,
                                                 uint32_t depth);

std::optional<FriProof> DeserializeFriProof(const std::vector<unsigned char>& in)
{
    return DeserializeFriProofDepth(in, /*depth=*/0);
}

std::optional<FriProof> DeserializeFriProofDepth(const std::vector<unsigned char>& in, uint32_t depth)
{
    if (in.size() > kRCFriMaxProofBytesHard) return std::nullopt;
    if (depth > kRCFriMaxNestedDeepHard) return std::nullopt;
    const unsigned char* p = in.data();
    const unsigned char* end = in.data() + in.size();
    uint32_t magic = 0, version = 0;
    if (!ReadLE32Checked(p, end, magic) || magic != kRCFriProofMagic) return std::nullopt;
    if (!ReadLE32Checked(p, end, version) || version != kRCFriProofVersion) return std::nullopt;
    FriProof proof;
    proof.version = version;
    if (!ReadLE64Checked(p, end, proof.pow_grind_nonce)) return std::nullopt;
    if (!ReadLE32Checked(p, end, proof.blowup)) return std::nullopt;
    if (!ReadLE32Checked(p, end, proof.n_coeffs)) return std::nullopt;
    if (proof.n_coeffs == 0 || proof.n_coeffs > kRCFriMaxCoeffsHard) return std::nullopt;
    uint32_t n_layers = 0;
    if (!ReadLE32Checked(p, end, n_layers) || n_layers == 0 ||
        n_layers > kRCFriMaxFoldLayersHard)
        return std::nullopt;
    proof.layers.resize(n_layers);
    for (auto& lc : proof.layers) {
        if (!ReadBytesChecked(p, end, lc.root.data(), 32)) return std::nullopt;
        if (!ReadLE32Checked(p, end, lc.n_leaves)) return std::nullopt;
        if (lc.n_leaves > kRCFriMaxCoeffsHard * kRCFriBlowup) return std::nullopt;
    }
    if (!ReadFp2Checked(p, end, proof.final_value)) return std::nullopt;
    uint32_t n_ch = 0;
    if (!ReadLE32Checked(p, end, n_ch) || n_ch > kRCFriMaxFoldLayersHard) return std::nullopt;
    proof.fold_challenges.resize(n_ch);
    for (auto& c : proof.fold_challenges) {
        if (!ReadFp2Checked(p, end, c)) return std::nullopt;
    }
    uint32_t n_q = 0;
    if (!ReadLE32Checked(p, end, n_q) || n_q > kRCFriMaxQueriesHard) return std::nullopt;
    proof.queries.resize(n_q);
    for (auto& q : proof.queries) {
        if (!ReadLE32Checked(p, end, q.index)) return std::nullopt;
        uint32_t n_steps = 0;
        if (!ReadLE32Checked(p, end, n_steps) || n_steps > kRCFriMaxFoldLayersHard)
            return std::nullopt;
        q.steps.resize(n_steps);
        for (auto& st : q.steps) {
            if (!ReadLE32Checked(p, end, st.even_index)) return std::nullopt;
            if (!ReadLE32Checked(p, end, st.odd_index)) return std::nullopt;
            if (!ReadFp2Checked(p, end, st.even)) return std::nullopt;
            if (!ReadFp2Checked(p, end, st.odd)) return std::nullopt;
            uint32_t n_es = 0, n_os = 0;
            if (!ReadLE32Checked(p, end, n_es) || n_es > kRCFriMaxFoldLayersHard)
                return std::nullopt;
            st.even_siblings.resize(n_es);
            for (auto& s : st.even_siblings) {
                if (!ReadBytesChecked(p, end, s.data(), 32)) return std::nullopt;
            }
            if (!ReadLE32Checked(p, end, n_os) || n_os > kRCFriMaxFoldLayersHard)
                return std::nullopt;
            st.odd_siblings.resize(n_os);
            for (auto& s : st.odd_siblings) {
                if (!ReadBytesChecked(p, end, s.data(), 32)) return std::nullopt;
            }
        }
        if (!ReadFp2Checked(p, end, q.deep_quot_leaf)) return std::nullopt;
        uint32_t n_ds = 0;
        if (!ReadLE32Checked(p, end, n_ds) || n_ds > kRCFriMaxFoldLayersHard) return std::nullopt;
        q.deep_quot_siblings.resize(n_ds);
        for (auto& s : q.deep_quot_siblings) {
            if (!ReadBytesChecked(p, end, s.data(), 32)) return std::nullopt;
        }
    }
    if (p >= end) return std::nullopt;
    proof.has_deep = (*p++ != 0);
    if (p >= end) return std::nullopt;
    proof.deep_z_forced = (*p++ != 0);
    if (proof.has_deep) {
        if (!ReadFp2Checked(p, end, proof.deep_z)) return std::nullopt;
        if (!ReadFp2Checked(p, end, proof.deep_eval)) return std::nullopt;
        if (!ReadBytesChecked(p, end, proof.deep_quot_root.data(), 32)) return std::nullopt;
        if (!ReadLE32Checked(p, end, proof.deep_quot_n_leaves)) return std::nullopt;
        uint32_t nested_n = 0;
        if (!ReadLE32Checked(p, end, nested_n) || nested_n > kRCFriMaxProofBytesHard)
            return std::nullopt;
        std::vector<unsigned char> nested(nested_n);
        if (!ReadBytesChecked(p, end, nested.data(), nested_n)) return std::nullopt;
        if (nested_n == 0) {
            proof.deep_quot_fri = nullptr; // Haböck path: no nested quotient FRI
        } else {
            auto quot = DeserializeFriProofDepth(nested, depth + 1);
            if (!quot) return std::nullopt;
            proof.deep_quot_fri = std::make_shared<FriProof>(std::move(*quot));
        }
        if (!ReadLE32Checked(p, end, proof.deep_domain_index)) return std::nullopt;
        uint32_t n_dsib = 0;
        if (!ReadLE32Checked(p, end, n_dsib) || n_dsib > kRCFriMaxFoldLayersHard)
            return std::nullopt;
        proof.deep_domain_siblings.resize(n_dsib);
        for (auto& s : proof.deep_domain_siblings) {
            if (!ReadBytesChecked(p, end, s.data(), 32)) return std::nullopt;
        }
    }
    if (p != end) return std::nullopt;
    return proof;
}


FriCommitResult FriCommitAndFold(const std::vector<Fp2>& coeffs, const uint256& fs_seed,
                                 uint64_t pow_grind_nonce, bool enable_deep)
{
    return FriCommitAndFoldImpl(coeffs, fs_seed, pow_grind_nonce, enable_deep, nullptr);
}

FriCommitResult FriCommitAndFoldDeepAt(const std::vector<Fp2>& coeffs, const uint256& fs_seed,
                                       const Fp2& deep_z, uint64_t pow_grind_nonce)
{
    return FriCommitAndFoldImpl(coeffs, fs_seed, pow_grind_nonce, /*enable_deep=*/true, &deep_z);
}

Fp2 FriEvalPoly(const std::vector<Fp2>& coeffs, const Fp2& z)
{
    Fp2 acc = Fp2::Zero();
    for (size_t i = coeffs.size(); i-- > 0;) {
        acc = gkr_field::Add(gkr_field::Mul(acc, z), coeffs[i]);
    }
    return acc;
}

// ============================================================================
// Batched FRI (v7 substrate) — see the construction note in the header and
// blueprint §2.1–2.3. Reuses the shipped fold/query helpers verbatim.
// ============================================================================

namespace {

/** z ∈ D (the size-n_lde LDE subgroup, embedded in the c1=0 base-field line)? */
bool FriBatchPointInDomain(const Fp2& z, uint32_t n_lde)
{
    return FriPointInDomain(z, n_lde);
}

/** Batch FS preamble: domain-separated from the legacy per-instance FRI. */
FriFs FriBatchFsInit(const uint256& fs_seed, uint64_t pow_grind_nonce, uint32_t n_coeffs,
                     const std::vector<FriLayerCommit>& columns,
                     const std::vector<uint32_t>& column_len)
{
    FriFs fs(fs_seed, pow_grind_nonce, kRCFriBlowup, n_coeffs);
    AppendBytes(fs.buf, reinterpret_cast<const unsigned char*>(kRCFriBatchDomainTag),
                sizeof(kRCFriBatchDomainTag) - 1);
    AppendLE32(fs.buf, kRCFriBatchProofVersion);
    AppendLE32(fs.buf, static_cast<uint32_t>(columns.size()));
    for (const uint32_t len : column_len) AppendLE32(fs.buf, len);
    for (const auto& c : columns) fs.AbsorbRoot(c.root);
    return fs;
}

/** Dual-OOD sampling: FS challenges rejected until Fp2.c1!=0 (⇒ ∉ D) and distinct.
 *  The rejection counter is deterministic, so prover and verifier agree. */
Fp2 FriBatchSampleZ(FriFs& fs, uint32_t& ctr, uint32_t /*n_lde*/, const Fp2* distinct_from)
{
    while (true) {
        const Fp2 z = fs.ChallengeFp2("frib_z", ctr++);
        if (Canonical(z.c1) == 0) continue; // require nonzero extension coeff
        if (distinct_from != nullptr && Eq(z, *distinct_from)) continue;
        return z;
    }
}

} // namespace

uint256 FriBatchColumnRoot(const std::vector<Fp2>& column, uint32_t n_coeffs)
{
    if (column.empty() || n_coeffs == 0 || (n_coeffs & (n_coeffs - 1)) != 0 ||
        column.size() > n_coeffs ||
        static_cast<uint64_t>(n_coeffs) * kRCFriBlowup > (uint64_t{1} << kRCFriMaxLdeLog2)) {
        return uint256{};
    }
    std::vector<Fp2> padded(n_coeffs, Fp2::Zero());
    for (size_t i = 0; i < column.size(); ++i) padded[i] = column[i];
    const auto lde = LdeFromCoeffs(padded, kRCFriBlowup);
    return BuildMerkleTree(lde).root;
}

FriBatchCommitResult FriBatchCommit(const std::vector<std::vector<Fp2>>& columns,
                                    const uint256& fs_seed, uint64_t pow_grind_nonce)
{
    FriBatchCommitResult out;
    if (columns.empty() || columns.size() > kRCFriBatchMaxColumns) {
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
        // CPU soft guard (matches FriCommitAndFold). The PROTOCOL cap is
        // κ=2^28 / LDE 2^32; consensus-dim proving stays over_budget/PARKED.
        out.note = "LDE domain too large (CPU guard)";
        return out;
    }
    const uint32_t n_lde = n * kRCFriBlowup;
    const uint32_t W = static_cast<uint32_t>(columns.size());

    FriBatchProof& p = out.proof;
    p.version = kRCFriBatchProofVersion;
    p.pow_grind_nonce = pow_grind_nonce;
    p.blowup = kRCFriBlowup;
    p.n_coeffs = n;
    p.column_len.resize(W);
    p.columns.resize(W);
    out.column_lde.resize(W);
    std::vector<MerkleTree> col_trees(W);
    for (uint32_t i = 0; i < W; ++i) {
        p.column_len[i] = static_cast<uint32_t>(columns[i].size());
        std::vector<Fp2> padded(n, Fp2::Zero());
        for (size_t j = 0; j < columns[i].size(); ++j) padded[j] = columns[i][j];
        out.column_lde[i] = LdeFromCoeffs(padded, kRCFriBlowup);
        col_trees[i] = BuildMerkleTree(out.column_lde[i]);
        p.columns[i].root = col_trees[i].root;
        p.columns[i].n_leaves = n_lde;
    }

    // FS: all column roots absorbed BEFORE any challenge (commit-then-challenge).
    FriFs fs = FriBatchFsInit(fs_seed, pow_grind_nonce, n, p.columns, p.column_len);

    // RLC λ over all columns (single batched instance — §2.3).
    p.lambda = fs.ChallengeFp2("frib_lambda", 0);
    fs.AbsorbFp2(p.lambda);

    // Dual OOD (§2.2): two independent points; single-z caps degree at 2^24.
    uint32_t zctr = 0;
    p.z1 = FriBatchSampleZ(fs, zctr, n_lde, nullptr);
    p.z2 = FriBatchSampleZ(fs, zctr, n_lde, &p.z1);
    fs.AbsorbFp2(p.z1);
    fs.AbsorbFp2(p.z2);

    // Claimed per-column evaluations at both OOD points (the opening primitive).
    p.evals_z1.resize(W);
    p.evals_z2.resize(W);
    for (uint32_t i = 0; i < W; ++i) {
        p.evals_z1[i] = EvalPolyCoeffs(columns[i], p.z1);
        p.evals_z2[i] = EvalPolyCoeffs(columns[i], p.z2);
        fs.AbsorbFp2(p.evals_z1[i]);
        fs.AbsorbFp2(p.evals_z2[i]);
    }
    p.w1 = fs.ChallengeFp2("frib_w", 0);
    p.w2 = fs.ChallengeFp2("frib_w", 1);
    fs.AbsorbFp2(p.w1);
    fs.AbsorbFp2(p.w2);

    // U = Σ λ^{i−1}·X^{n−len_i}·P_i (degree-shift = maximal-degree enforcement).
    std::vector<Fp2> lam_pow(W);
    lam_pow[0] = Fp2::One();
    for (uint32_t i = 1; i < W; ++i) lam_pow[i] = Mul(lam_pow[i - 1], p.lambda);
    std::vector<Fp2> U(n, Fp2::Zero());
    for (uint32_t i = 0; i < W; ++i) {
        const uint32_t shift = n - p.column_len[i];
        for (size_t j = 0; j < columns[i].size(); ++j) {
            U[shift + j] = Add(U[shift + j], Mul(lam_pow[i], columns[i][j]));
        }
    }
    // v_s = U(z_s) recomputed from the per-column claims (exactly equal for an
    // honest prover; the verifier recomputes the same way — that binds claims).
    Fp2 v1 = Fp2::Zero(), v2 = Fp2::Zero();
    for (uint32_t i = 0; i < W; ++i) {
        const uint32_t shift = n - p.column_len[i];
        v1 = Add(v1, Mul(Mul(lam_pow[i], PowFp2(p.z1, shift)), p.evals_z1[i]));
        v2 = Add(v2, Mul(Mul(lam_pow[i], PowFp2(p.z2, shift)), p.evals_z2[i]));
    }

    // DEEP composition G = w1·(U−v1)/(X−z1) + w2·(U−v2)/(X−z2), deg G < n−1.
    std::vector<Fp2> q1 = SyntheticQuotient(U, p.z1, v1);
    std::vector<Fp2> q2 = SyntheticQuotient(U, p.z2, v2);
    q1.resize(n, Fp2::Zero());
    q2.resize(n, Fp2::Zero());
    std::vector<Fp2> G(n);
    for (uint32_t j = 0; j < n; ++j) {
        G[j] = Add(Mul(p.w1, q1[j]), Mul(p.w2, q2[j]));
    }

    // Fold-commit phase on G — v5 half-domain fold × log2(n), terminal B-constant.
    const uint32_t n_folds = FriLog2Exact(n);
    std::vector<Fp2> cur = LdeFromCoeffs(G, kRCFriBlowup);
    std::vector<MerkleTree> g_trees;
    std::vector<std::vector<Fp2>> g_layers;
    for (uint32_t fold = 0;; ++fold) {
        MerkleTree tree = BuildMerkleTree(cur);
        FriLayerCommit lc;
        lc.n_leaves = static_cast<uint32_t>(cur.size());
        lc.root = tree.root;
        p.fold_layers.push_back(lc);
        g_layers.push_back(cur);
        g_trees.push_back(std::move(tree));
        fs.AbsorbRoot(lc.root);
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
        const Fp2 beta =
            fs.ChallengeFp2("frib_fold", static_cast<uint32_t>(p.fold_challenges.size()));
        p.fold_challenges.push_back(beta);
        std::vector<Fp2> next;
        if (!HalfDomainFoldLayer(cur, beta, next)) {
            out.note = "half-domain fold failed (x=0)";
            return out;
        }
        cur = std::move(next);
    }

    // Queries: SAME index set opens every column AND G's fold path.
    p.queries.reserve(kRCFriBatchNumQueries);
    for (uint32_t qi = 0; qi < kRCFriBatchNumQueries; ++qi) {
        FriBatchQuery q;
        q.index = fs.ChallengeIndex("frib_query", qi, n_lde);
        q.columns.resize(W);
        for (uint32_t i = 0; i < W; ++i) {
            q.columns[i].value = out.column_lde[i][q.index];
            q.columns[i].siblings = PathFromTree(col_trees[i], q.index);
        }
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
    out.proof_bytes = SerializeFriBatchProof(p, ser);
    out.ok = true;
    out.note = kRCFriBatchSoundnessStatement;
    return out;
}

bool FriBatchVerify(const FriBatchProof& proof, const uint256& fs_seed, std::string* why)
{
    auto fail = [&](const char* w) {
        if (why) *why = w ? w : "FriBatchVerify failed";
        return false;
    };
    if (proof.version != kRCFriBatchProofVersion) return fail("bad batch version");
    if (proof.blowup != kRCFriBlowup) return fail("bad blowup");
    const uint32_t n = proof.n_coeffs;
    if (n == 0 || (n & (n - 1)) != 0) return fail("n_coeffs not pow2");
    if (n > (uint64_t{1} << kRCFriMaxColumnLog2)) return fail("n_coeffs exceeds kappa");
    if (static_cast<uint64_t>(n) * kRCFriBlowup > (uint64_t{1} << kRCFriMaxLdeLog2)) return fail("LDE guard");
    const uint32_t n_lde = n * kRCFriBlowup;
    const uint32_t W = static_cast<uint32_t>(proof.columns.size());
    if (W == 0 || W > kRCFriBatchMaxColumns) return fail("bad column count");
    if (proof.column_len.size() != W) return fail("column_len size");
    uint32_t max_len = 0;
    for (uint32_t i = 0; i < W; ++i) {
        if (proof.column_len[i] == 0 || proof.column_len[i] > n) return fail("column len");
        if (proof.columns[i].n_leaves != n_lde) return fail("column n_leaves");
        max_len = std::max(max_len, proof.column_len[i]);
    }
    if (FriNextPow2(max_len) != n) return fail("n_coeffs not canonical");
    if (proof.evals_z1.size() != W || proof.evals_z2.size() != W) return fail("eval count");
    if (proof.fold_layers.empty()) return fail("no fold layers");
    if (proof.fold_layers[0].n_leaves != n_lde) return fail("fold LDE size");
    const uint32_t n_folds_expect = FriLog2Exact(n);
    if (proof.fold_challenges.size() != n_folds_expect) return fail("fold count");
    if (proof.fold_challenges.size() + 1 != proof.fold_layers.size())
        return fail("fold layer/challenge count");
    if (proof.fold_layers.back().n_leaves != proof.blowup) return fail("final layer not blowup");
    for (size_t i = 0; i + 1 < proof.fold_layers.size(); ++i) {
        if (proof.fold_layers[i].n_leaves < 2 || (proof.fold_layers[i].n_leaves % 2) != 0)
            return fail("fold layer parity");
        if (proof.fold_layers[i].n_leaves / 2 != proof.fold_layers[i + 1].n_leaves)
            return fail("fold layer size");
    }
    if (proof.queries.size() != kRCFriBatchNumQueries) return fail("query count");

    // FS replay: every challenge recomputed from the transcript and compared.
    FriFs fs = FriBatchFsInit(fs_seed, proof.pow_grind_nonce, n, proof.columns,
                              proof.column_len);
    {
        const Fp2 lambda = fs.ChallengeFp2("frib_lambda", 0);
        if (!Eq(lambda, proof.lambda)) return fail("lambda mismatch");
        fs.AbsorbFp2(lambda);
    }
    {
        uint32_t zctr = 0;
        const Fp2 z1 = FriBatchSampleZ(fs, zctr, n_lde, nullptr);
        if (!Eq(z1, proof.z1)) return fail("z1 mismatch");
        const Fp2 z2 = FriBatchSampleZ(fs, zctr, n_lde, &z1);
        if (!Eq(z2, proof.z2)) return fail("z2 mismatch");
        fs.AbsorbFp2(z1);
        fs.AbsorbFp2(z2);
    }
    if (Canonical(proof.z1.c1) == 0 || Canonical(proof.z2.c1) == 0 ||
        FriBatchPointInDomain(proof.z1, n_lde) || FriBatchPointInDomain(proof.z2, n_lde) ||
        Eq(proof.z1, proof.z2)) {
        return fail("OOD points invalid");
    }
    for (uint32_t i = 0; i < W; ++i) {
        fs.AbsorbFp2(proof.evals_z1[i]);
        fs.AbsorbFp2(proof.evals_z2[i]);
    }
    {
        const Fp2 w1 = fs.ChallengeFp2("frib_w", 0);
        const Fp2 w2 = fs.ChallengeFp2("frib_w", 1);
        if (!Eq(w1, proof.w1) || !Eq(w2, proof.w2)) return fail("deep weights mismatch");
        fs.AbsorbFp2(w1);
        fs.AbsorbFp2(w2);
    }
    for (size_t i = 0; i < proof.fold_layers.size(); ++i) {
        fs.AbsorbRoot(proof.fold_layers[i].root);
        if (i + 1 < proof.fold_layers.size()) {
            const Fp2 beta = fs.ChallengeFp2("frib_fold", static_cast<uint32_t>(i));
            if (!Eq(beta, proof.fold_challenges[i])) return fail("fold challenge mismatch");
        }
    }
    if (MerkleRootConstantLayer(proof.final_value, proof.blowup) != proof.fold_layers.back().root) {
        return fail("final constant layer root");
    }

    // v_s = U(z_s) from the per-column claims — the DEEP identity below binds
    // every claimed (C_i(z1), C_i(z2)) to the committed words.
    std::vector<Fp2> lam_pow(W);
    lam_pow[0] = Fp2::One();
    for (uint32_t i = 1; i < W; ++i) lam_pow[i] = Mul(lam_pow[i - 1], proof.lambda);
    Fp2 v1 = Fp2::Zero(), v2 = Fp2::Zero();
    for (uint32_t i = 0; i < W; ++i) {
        const uint32_t shift = n - proof.column_len[i];
        v1 = Add(v1, Mul(Mul(lam_pow[i], PowFp2(proof.z1, shift)), proof.evals_z1[i]));
        v2 = Add(v2, Mul(Mul(lam_pow[i], PowFp2(proof.z2, shift)), proof.evals_z2[i]));
    }

    const uint32_t n_folds = static_cast<uint32_t>(proof.fold_challenges.size());
    for (uint32_t qi = 0; qi < kRCFriBatchNumQueries; ++qi) {
        const FriBatchQuery& q = proof.queries[qi];
        const uint32_t expect = fs.ChallengeIndex("frib_query", qi, n_lde);
        if (q.index != expect) return fail("query index");
        if (q.columns.size() != W) return fail("query column count");
        if (q.steps.size() != n_folds) return fail("query steps");

        // Per-column Merkle openings at the query index.
        const Fp2 x = DomainPoint(n_lde, q.index);
        Fp2 U_x = Fp2::Zero();
        for (uint32_t i = 0; i < W; ++i) {
            FriMerklePath path;
            path.index = q.index;
            path.leaf = q.columns[i].value;
            path.siblings = q.columns[i].siblings;
            if (!FriVerifyPath(path, proof.columns[i].root, n_lde)) {
                return fail("column merkle");
            }
            const uint32_t shift = n - proof.column_len[i];
            U_x = Add(U_x, Mul(Mul(lam_pow[i], PowFp2(x, shift)), q.columns[i].value));
        }

        // Dual-OOD DEEP identity at the query site.
        const Fp2 g_expect =
            Add(Mul(proof.w1, Mul(Sub(U_x, v1), Inv(Sub(x, proof.z1)))),
                Mul(proof.w2, Mul(Sub(U_x, v2), Inv(Sub(x, proof.z2)))));

        if (n_folds == 0) {
            // Constant G codeword bound by terminal root; must match DEEP identity.
            if (!Eq(g_expect, proof.final_value)) return fail("deep identity");
            continue;
        }

        uint32_t idx = q.index;
        Fp2 claimed{};
        bool have_claimed = false;
        for (uint32_t L = 0; L < n_folds; ++L) {
            const FriFoldStep& step = q.steps[L];
            Fp2 folded{};
            std::string step_why;
            if (!VerifyFoldStep(step, proof.fold_layers[L].root, proof.fold_layers[L].n_leaves,
                                proof.fold_challenges[L], idx, folded, &step_why)) {
                return fail(step_why.c_str());
            }
            const uint32_t half = proof.fold_layers[L].n_leaves / 2;
            const Fp2 leaf_here = (idx < half) ? step.even : step.odd;
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

    if (why) *why = "FriBatchVerify ok";
    return true;
}

size_t SerializeFriBatchProof(const FriBatchProof& proof, std::vector<unsigned char>& out)
{
    out.clear();
    AppendLE32(out, kRCFriBatchProofMagic);
    AppendLE32(out, proof.version);
    AppendLE64(out, proof.pow_grind_nonce);
    AppendLE32(out, proof.blowup);
    AppendLE32(out, proof.n_coeffs);
    AppendLE32(out, static_cast<uint32_t>(proof.columns.size()));
    for (const auto& c : proof.columns) {
        AppendBytes(out, c.root.data(), 32);
        AppendLE32(out, c.n_leaves);
    }
    AppendLE32(out, static_cast<uint32_t>(proof.column_len.size()));
    for (const uint32_t len : proof.column_len) AppendLE32(out, len);
    AppendFp2(out, proof.lambda);
    AppendFp2(out, proof.z1);
    AppendFp2(out, proof.z2);
    AppendLE32(out, static_cast<uint32_t>(proof.evals_z1.size()));
    for (const auto& e : proof.evals_z1) AppendFp2(out, e);
    AppendLE32(out, static_cast<uint32_t>(proof.evals_z2.size()));
    for (const auto& e : proof.evals_z2) AppendFp2(out, e);
    AppendFp2(out, proof.w1);
    AppendFp2(out, proof.w2);
    AppendLE32(out, static_cast<uint32_t>(proof.fold_layers.size()));
    for (const auto& lc : proof.fold_layers) {
        AppendBytes(out, lc.root.data(), 32);
        AppendLE32(out, lc.n_leaves);
    }
    AppendFp2(out, proof.final_value);
    AppendLE32(out, static_cast<uint32_t>(proof.fold_challenges.size()));
    for (const auto& c : proof.fold_challenges) AppendFp2(out, c);
    AppendLE32(out, static_cast<uint32_t>(proof.queries.size()));
    for (const auto& q : proof.queries) {
        AppendLE32(out, q.index);
        AppendLE32(out, static_cast<uint32_t>(q.columns.size()));
        for (const auto& co : q.columns) {
            AppendFp2(out, co.value);
            AppendLE32(out, static_cast<uint32_t>(co.siblings.size()));
            for (const auto& s : co.siblings) AppendBytes(out, s.data(), 32);
        }
        AppendLE32(out, static_cast<uint32_t>(q.steps.size()));
        for (const auto& st : q.steps) {
            AppendLE32(out, st.even_index);
            AppendLE32(out, st.odd_index);
            AppendFp2(out, st.even);
            AppendFp2(out, st.odd);
            AppendLE32(out, static_cast<uint32_t>(st.even_siblings.size()));
            for (const auto& s : st.even_siblings) AppendBytes(out, s.data(), 32);
            AppendLE32(out, static_cast<uint32_t>(st.odd_siblings.size()));
            for (const auto& s : st.odd_siblings) AppendBytes(out, s.data(), 32);
        }
    }
    return out.size();
}

std::optional<FriBatchProof> DeserializeFriBatchProof(const std::vector<unsigned char>& in)
{
    const unsigned char* p = in.data();
    const unsigned char* end = in.data() + in.size();
    uint32_t magic = 0, version = 0;
    if (!ReadLE32Checked(p, end, magic) || magic != kRCFriBatchProofMagic) return std::nullopt;
    if (!ReadLE32Checked(p, end, version) || version != kRCFriBatchProofVersion)
        return std::nullopt;
    FriBatchProof proof;
    proof.version = version;
    if (!ReadLE64Checked(p, end, proof.pow_grind_nonce)) return std::nullopt;
    if (!ReadLE32Checked(p, end, proof.blowup)) return std::nullopt;
    if (!ReadLE32Checked(p, end, proof.n_coeffs)) return std::nullopt;
    uint32_t n_cols = 0;
    if (!ReadLE32Checked(p, end, n_cols) || n_cols == 0 || n_cols > kRCFriBatchMaxColumns)
        return std::nullopt;
    proof.columns.resize(n_cols);
    for (auto& c : proof.columns) {
        if (!ReadBytesChecked(p, end, c.root.data(), 32)) return std::nullopt;
        if (!ReadLE32Checked(p, end, c.n_leaves)) return std::nullopt;
    }
    uint32_t n_lens = 0;
    if (!ReadLE32Checked(p, end, n_lens) || n_lens != n_cols) return std::nullopt;
    proof.column_len.resize(n_lens);
    for (auto& len : proof.column_len) {
        if (!ReadLE32Checked(p, end, len)) return std::nullopt;
    }
    if (!ReadFp2Checked(p, end, proof.lambda)) return std::nullopt;
    if (!ReadFp2Checked(p, end, proof.z1)) return std::nullopt;
    if (!ReadFp2Checked(p, end, proof.z2)) return std::nullopt;
    uint32_t n_e1 = 0, n_e2 = 0;
    if (!ReadLE32Checked(p, end, n_e1) || n_e1 != n_cols) return std::nullopt;
    proof.evals_z1.resize(n_e1);
    for (auto& e : proof.evals_z1) {
        if (!ReadFp2Checked(p, end, e)) return std::nullopt;
    }
    if (!ReadLE32Checked(p, end, n_e2) || n_e2 != n_cols) return std::nullopt;
    proof.evals_z2.resize(n_e2);
    for (auto& e : proof.evals_z2) {
        if (!ReadFp2Checked(p, end, e)) return std::nullopt;
    }
    if (!ReadFp2Checked(p, end, proof.w1)) return std::nullopt;
    if (!ReadFp2Checked(p, end, proof.w2)) return std::nullopt;
    uint32_t n_layers = 0;
    if (!ReadLE32Checked(p, end, n_layers) || n_layers == 0 || n_layers > 64) return std::nullopt;
    proof.fold_layers.resize(n_layers);
    for (auto& lc : proof.fold_layers) {
        if (!ReadBytesChecked(p, end, lc.root.data(), 32)) return std::nullopt;
        if (!ReadLE32Checked(p, end, lc.n_leaves)) return std::nullopt;
    }
    if (!ReadFp2Checked(p, end, proof.final_value)) return std::nullopt;
    uint32_t n_ch = 0;
    if (!ReadLE32Checked(p, end, n_ch) || n_ch > 64) return std::nullopt;
    proof.fold_challenges.resize(n_ch);
    for (auto& c : proof.fold_challenges) {
        if (!ReadFp2Checked(p, end, c)) return std::nullopt;
    }
    uint32_t n_q = 0;
    if (!ReadLE32Checked(p, end, n_q) || n_q > 256) return std::nullopt;
    proof.queries.resize(n_q);
    for (auto& q : proof.queries) {
        if (!ReadLE32Checked(p, end, q.index)) return std::nullopt;
        uint32_t n_qc = 0;
        if (!ReadLE32Checked(p, end, n_qc) || n_qc != n_cols) return std::nullopt;
        q.columns.resize(n_qc);
        for (auto& co : q.columns) {
            if (!ReadFp2Checked(p, end, co.value)) return std::nullopt;
            uint32_t n_s = 0;
            if (!ReadLE32Checked(p, end, n_s) || n_s > 64) return std::nullopt;
            co.siblings.resize(n_s);
            for (auto& s : co.siblings) {
                if (!ReadBytesChecked(p, end, s.data(), 32)) return std::nullopt;
            }
        }
        uint32_t n_steps = 0;
        if (!ReadLE32Checked(p, end, n_steps) || n_steps > 64) return std::nullopt;
        q.steps.resize(n_steps);
        for (auto& st : q.steps) {
            if (!ReadLE32Checked(p, end, st.even_index)) return std::nullopt;
            if (!ReadLE32Checked(p, end, st.odd_index)) return std::nullopt;
            if (!ReadFp2Checked(p, end, st.even)) return std::nullopt;
            if (!ReadFp2Checked(p, end, st.odd)) return std::nullopt;
            uint32_t n_es = 0, n_os = 0;
            if (!ReadLE32Checked(p, end, n_es) || n_es > 64) return std::nullopt;
            st.even_siblings.resize(n_es);
            for (auto& s : st.even_siblings) {
                if (!ReadBytesChecked(p, end, s.data(), 32)) return std::nullopt;
            }
            if (!ReadLE32Checked(p, end, n_os) || n_os > 64) return std::nullopt;
            st.odd_siblings.resize(n_os);
            for (auto& s : st.odd_siblings) {
                if (!ReadBytesChecked(p, end, s.data(), 32)) return std::nullopt;
            }
        }
    }
    if (p != end) return std::nullopt;
    return proof;
}

} // namespace matmul::v4::rc
