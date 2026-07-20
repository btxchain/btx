// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_fri.h>

#include <crypto/common.h>
#include <crypto/sha256.h>

#include <cstring>
#include <string>

namespace matmul::v4::rc {
namespace {

using gkr_field::Add;
using gkr_field::Canonical;
using gkr_field::FromChallengeBytes2;
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

Fp2 ChallengeFromSeed(const uint256& seed, const char* label, uint32_t idx)
{
    std::vector<unsigned char> buf;
    const size_t n = std::strlen(label);
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(label),
               reinterpret_cast<const unsigned char*>(label) + n);
    AppendBytes(buf, seed.data(), 32);
    AppendLE32(buf, idx);
    return FromChallengeBytes2(Sha256dBytes(buf.data(), buf.size()).data());
}

std::vector<uint256> BuildMerkleLeaves(const std::vector<Fp2>& evals)
{
    std::vector<uint256> leaves(evals.size());
    for (size_t i = 0; i < evals.size(); ++i) {
        leaves[i] = FriLeafHash(evals[i], static_cast<uint32_t>(i));
    }
    return leaves;
}

uint256 MerkleRootFromLeaves(std::vector<uint256> level)
{
    if (level.empty()) {
        return Sha256dBytes(reinterpret_cast<const unsigned char*>("FRI_EMPTY"), 9);
    }
    while (level.size() > 1) {
        if (level.size() % 2 == 1) level.push_back(level.back());
        std::vector<uint256> next;
        next.reserve(level.size() / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            next.push_back(FriNodeHash(level[i], level[i + 1]));
        }
        level = std::move(next);
    }
    return level[0];
}

std::vector<uint256> MerklePathSiblings(const std::vector<Fp2>& evals, uint32_t index)
{
    auto level = BuildMerkleLeaves(evals);
    std::vector<uint256> siblings;
    uint32_t idx = index;
    while (level.size() > 1) {
        if (level.size() % 2 == 1) level.push_back(level.back());
        const uint32_t sib = idx ^ 1u;
        siblings.push_back(level[sib]);
        std::vector<uint256> next;
        next.reserve(level.size() / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            next.push_back(FriNodeHash(level[i], level[i + 1]));
        }
        level = std::move(next);
        idx >>= 1;
    }
    return siblings;
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

FriMerklePath FriOpenIndex(const std::vector<Fp2>& evals_pow2, uint32_t index)
{
    FriMerklePath path;
    path.index = index;
    if (evals_pow2.empty()) return path;
    const uint32_t n = static_cast<uint32_t>(evals_pow2.size());
    path.index = index % n;
    path.leaf = evals_pow2[path.index];
    path.siblings = MerklePathSiblings(evals_pow2, path.index);
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

FriCommitResult FriCommitAndFold(const std::vector<Fp2>& evals, const uint256& fs_seed,
                                 uint32_t n_openings)
{
    FriCommitResult out;
    if (evals.empty()) {
        out.note = "empty evals";
        return out;
    }
    const uint32_t n = FriNextPow2(static_cast<uint32_t>(evals.size()));
    out.evals_pow2.assign(n, Fp2::Zero());
    for (size_t i = 0; i < evals.size(); ++i) out.evals_pow2[i] = evals[i];

    std::vector<Fp2> cur = out.evals_pow2;
    uint32_t layer_i = 0;
    while (true) {
        FriLayerCommit lc;
        lc.n_leaves = static_cast<uint32_t>(cur.size());
        lc.root = MerkleRootFromLeaves(BuildMerkleLeaves(cur));
        out.proof.layers.push_back(lc);
        if (cur.size() == 1) {
            out.proof.final_value = cur[0];
            break;
        }
        const Fp2 beta = ChallengeFromSeed(fs_seed, "fri_fold", layer_i++);
        out.proof.fold_challenges.push_back(beta);
        std::vector<Fp2> next(cur.size() / 2);
        for (size_t i = 0; i < next.size(); ++i) {
            // even + beta * odd (degree-1 fold scaffold)
            next[i] = Add(cur[2 * i], Mul(beta, cur[2 * i + 1]));
        }
        cur = std::move(next);
    }

    const uint32_t n0 = out.proof.layers[0].n_leaves;
    const uint32_t q = std::max(1u, std::min(n_openings, n0));
    for (uint32_t i = 0; i < q; ++i) {
        const Fp2 ch = ChallengeFromSeed(fs_seed, "fri_query", i);
        const uint32_t idx = static_cast<uint32_t>(Canonical(ch.c0) % n0);
        out.proof.openings.push_back(FriOpenIndex(out.evals_pow2, idx));
    }

    std::vector<unsigned char> ser;
    out.proof_bytes = SerializeFriProof(out.proof, ser);
    out.ok = true;
    out.note = "FRI scaffold commit+fold (SHA256 Merkle; NOT production FRI)";
    out.proof.version = kRCFriProofVersion;
    return out;
}

bool FriVerify(const FriProof& proof, const uint256& fs_seed, std::string* why)
{
    auto fail = [&](const char* w) {
        if (why) *why = w ? w : "FriVerify failed";
        return false;
    };
    if (proof.version != kRCFriProofVersion) return fail("bad fri version");
    if (proof.layers.empty()) return fail("no layers");
    if (proof.layers[0].n_leaves == 0) return fail("empty layer0");
    if (proof.fold_challenges.size() + 1 != proof.layers.size()) return fail("layer/challenge count");

    // Re-derive fold challenges and check they match the proof echo.
    for (size_t i = 0; i < proof.fold_challenges.size(); ++i) {
        const Fp2 beta = ChallengeFromSeed(fs_seed, "fri_fold", static_cast<uint32_t>(i));
        if (!gkr_field::Eq(beta, proof.fold_challenges[i])) return fail("fold challenge mismatch");
        if (proof.layers[i].n_leaves != proof.layers[i + 1].n_leaves * 2 &&
            !(proof.layers[i].n_leaves == 1 && i + 1 == proof.layers.size() - 1)) {
            // Allow only exact halving for the scaffold.
            if (proof.layers[i].n_leaves / 2 != proof.layers[i + 1].n_leaves)
                return fail("layer size");
        }
    }

    // Verify Merkle openings against layer-0 root.
    const uint256& root0 = proof.layers[0].root;
    const uint32_t n0 = proof.layers[0].n_leaves;
    if (proof.openings.empty()) return fail("no openings");
    for (size_t qi = 0; qi < proof.openings.size(); ++qi) {
        const Fp2 ch = ChallengeFromSeed(fs_seed, "fri_query", static_cast<uint32_t>(qi));
        const uint32_t expect = static_cast<uint32_t>(Canonical(ch.c0) % n0);
        if (proof.openings[qi].index != expect) return fail("query index");
        if (!FriVerifyPath(proof.openings[qi], root0, n0)) return fail("merkle path");
    }

    if (proof.layers.back().n_leaves != 1) return fail("final layer not singleton");
    // Full RS proximity / sibling fold-check is Stage-I audit work.
    if (why) *why = "FriVerify ok (scaffold)";
    return true;
}

size_t SerializeFriProof(const FriProof& proof, std::vector<unsigned char>& out)
{
    out.clear();
    AppendLE32(out, kRCFriProofMagic);
    AppendLE32(out, proof.version);
    AppendLE32(out, static_cast<uint32_t>(proof.layers.size()));
    for (const auto& lc : proof.layers) {
        AppendBytes(out, lc.root.data(), 32);
        AppendLE32(out, lc.n_leaves);
    }
    AppendFp2(out, proof.final_value);
    AppendLE32(out, static_cast<uint32_t>(proof.fold_challenges.size()));
    for (const auto& c : proof.fold_challenges) AppendFp2(out, c);
    AppendLE32(out, static_cast<uint32_t>(proof.openings.size()));
    for (const auto& op : proof.openings) {
        AppendLE32(out, op.index);
        AppendFp2(out, op.leaf);
        AppendLE32(out, static_cast<uint32_t>(op.siblings.size()));
        for (const auto& s : op.siblings) AppendBytes(out, s.data(), 32);
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
    uint32_t n_op = 0;
    if (!ReadLE32Checked(p, end, n_op) || n_op > 64) return std::nullopt;
    proof.openings.resize(n_op);
    for (auto& op : proof.openings) {
        if (!ReadLE32Checked(p, end, op.index)) return std::nullopt;
        if (!ReadFp2Checked(p, end, op.leaf)) return std::nullopt;
        uint32_t n_sib = 0;
        if (!ReadLE32Checked(p, end, n_sib) || n_sib > 64) return std::nullopt;
        op.siblings.resize(n_sib);
        for (auto& s : op.siblings) {
            if (!ReadBytesChecked(p, end, s.data(), 32)) return std::nullopt;
        }
    }
    if (p != end) return std::nullopt;
    return proof;
}

} // namespace matmul::v4::rc
