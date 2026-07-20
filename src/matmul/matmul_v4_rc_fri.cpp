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

FriFoldStep OpenFoldStep(const std::vector<Fp2>& evals, const MerkleTree& tree, uint32_t idx)
{
    FriFoldStep step;
    const uint32_t n = static_cast<uint32_t>(evals.size());
    const uint32_t ei = (idx & ~1u) % n;
    step.even_index = ei;
    step.even = evals[ei];
    step.odd = evals[ei + 1];
    step.even_siblings = PathFromTree(tree, ei);
    step.odd_siblings = PathFromTree(tree, ei + 1);
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
    const uint32_t ei = idx & ~1u;
    if (step.even_index != ei) return fail("fold even_index");
    if (ei + 1 >= n_leaves) return fail("fold pair OOB");

    FriMerklePath pe;
    pe.index = ei;
    pe.leaf = step.even;
    pe.siblings = step.even_siblings;
    FriMerklePath po;
    po.index = ei + 1;
    po.leaf = step.odd;
    po.siblings = step.odd_siblings;
    if (!FriVerifyPath(pe, root, n_leaves)) return fail("fold even merkle");
    if (!FriVerifyPath(po, root, n_leaves)) return fail("fold odd merkle");

    out_folded = Add(step.even, Mul(beta, step.odd));
    return true;
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

FriCommitResult FriCommitAndFold(const std::vector<Fp2>& coeffs, const uint256& fs_seed,
                                 uint64_t pow_grind_nonce)
{
    FriCommitResult out;
    if (coeffs.empty()) {
        out.note = "empty coeffs";
        return out;
    }
    const uint32_t n = FriNextPow2(static_cast<uint32_t>(coeffs.size()));
    if ((n * static_cast<uint64_t>(kRCFriBlowup)) > (1u << 24)) {
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

    std::vector<Fp2> cur = out.lde_evals;
    std::vector<MerkleTree> trees;
    while (true) {
        MerkleTree tree = BuildMerkleTree(cur);
        FriLayerCommit lc;
        lc.n_leaves = static_cast<uint32_t>(cur.size());
        lc.root = tree.root;
        out.proof.layers.push_back(lc);
        out.layer_evals.push_back(cur);
        trees.push_back(std::move(tree));
        fs.AbsorbRoot(lc.root);

        if (cur.size() == 1) {
            out.proof.final_value = cur[0];
            break;
        }

        const Fp2 beta =
            fs.ChallengeFp2("fri_fold", static_cast<uint32_t>(out.proof.fold_challenges.size()));
        out.proof.fold_challenges.push_back(beta);
        std::vector<Fp2> next(cur.size() / 2);
        for (size_t i = 0; i < next.size(); ++i) {
            next[i] = Add(cur[2 * i], Mul(beta, cur[2 * i + 1]));
        }
        cur = std::move(next);
    }

    const uint32_t n0 = out.proof.layers[0].n_leaves;
    const uint32_t n_folds = static_cast<uint32_t>(out.proof.fold_challenges.size());
    out.proof.queries.reserve(kRCFriNumQueries);
    for (uint32_t qi = 0; qi < kRCFriNumQueries; ++qi) {
        FriQueryOpening q;
        q.index = fs.ChallengeIndex("fri_query", qi, n0);
        uint32_t idx = q.index;
        q.steps.reserve(n_folds);
        for (uint32_t L = 0; L < n_folds; ++L) {
            q.steps.push_back(OpenFoldStep(out.layer_evals[L], trees[L], idx));
            idx >>= 1;
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
    if (proof.n_coeffs == 0 || (proof.n_coeffs & (proof.n_coeffs - 1)) != 0)
        return fail("n_coeffs not pow2");
    if (proof.layers[0].n_leaves != proof.n_coeffs * proof.blowup) return fail("LDE size");
    if (proof.fold_challenges.size() + 1 != proof.layers.size()) return fail("layer/challenge count");
    if (proof.layers.back().n_leaves != 1) return fail("final layer not singleton");
    if (proof.queries.size() != kRCFriNumQueries) return fail("query count");

    // Layer sizes must exact-halve until the final singleton.
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

    // Final layer root must commit the claimed constant.
    {
        FriMerklePath fin;
        fin.index = 0;
        fin.leaf = proof.final_value;
        if (!FriVerifyPath(fin, proof.layers.back().root, 1)) return fail("final root");
    }

    const uint32_t n0 = proof.layers[0].n_leaves;
    const uint32_t n_folds = static_cast<uint32_t>(proof.fold_challenges.size());

    for (uint32_t qi = 0; qi < kRCFriNumQueries; ++qi) {
        const FriQueryOpening& q = proof.queries[qi];
        const uint32_t expect = fs.ChallengeIndex("fri_query", qi, n0);
        if (q.index != expect) return fail("query index");
        if (q.steps.size() != n_folds) return fail("query steps");

        uint32_t idx = q.index;
        Fp2 claimed{};
        bool have_claimed = false;

        for (uint32_t L = 0; L < n_folds; ++L) {
            const FriFoldStep& step = q.steps[L];
            Fp2 folded{};
            std::string step_why;
            if (!VerifyFoldStep(step, proof.layers[L].root, proof.layers[L].n_leaves,
                                proof.fold_challenges[L], idx, folded, &step_why)) {
                return fail(step_why.c_str());
            }
            // Consistency with previous fold claim at this layer index.
            if (have_claimed) {
                const Fp2 leaf_here = (idx & 1u) ? step.odd : step.even;
                if (!Eq(leaf_here, claimed)) return fail("fold path consistency");
            }
            claimed = folded;
            have_claimed = true;
            idx >>= 1;
        }

        if (!have_claimed || !Eq(claimed, proof.final_value)) return fail("final fold value");
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

std::optional<FriProof> DeserializeFriProof(const std::vector<unsigned char>& in)
{
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
    uint32_t n_layers = 0;
    if (!ReadLE32Checked(p, end, n_layers) || n_layers == 0 || n_layers > 64) return std::nullopt;
    proof.layers.resize(n_layers);
    for (auto& lc : proof.layers) {
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
        uint32_t n_steps = 0;
        if (!ReadLE32Checked(p, end, n_steps) || n_steps > 64) return std::nullopt;
        q.steps.resize(n_steps);
        for (auto& st : q.steps) {
            if (!ReadLE32Checked(p, end, st.even_index)) return std::nullopt;
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
