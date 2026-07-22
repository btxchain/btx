// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_alg_hash.h>

#include <matmul/matmul_v4_rc_fri_ext3.h> // Sha256dBytes (deterministic XOF)
#include <uint256.h>

#include <cassert>
#include <cstddef>
#include <cstring>
#include <vector>

// Poseidon2-Goldilocks permutation `AlgHash` — implementation of spec §1
// (scratchpad/stage-c-buildable-spec.md). All non-frozen constants (RC_ext,
// RC_int, μ, node/leaf domain seeds) are derived by the domain-separated
// SHA256d counter-XOF `SampleFp` below and pinned by checksum + golden vectors
// in src/test/matmul_v4_rc_alg_hash_tests.cpp. The external matrix M_E
// (block-circulant of the fixed MDS M4) is a FROZEN literal, not generated.

namespace matmul::v4::rc::alg_hash {
namespace {

using gkr_field::Add;
using gkr_field::Canonical;
using gkr_field::Inv;
using gkr_field::kP;
using gkr_field::Mul;
using gkr_field::Sub;

// ----------------------------------------------------------------------------
// SampleFp — unbiased field sampling (spec §1.6, frozen procedure)
// ----------------------------------------------------------------------------

void AppendLE32(std::vector<unsigned char>& buf, uint32_t v)
{
    for (int i = 0; i < 4; ++i) {
        buf.push_back(static_cast<unsigned char>((v >> (8 * i)) & 0xFF));
    }
}

void AppendLabel(std::vector<unsigned char>& buf, const char* label)
{
    const size_t n = std::strlen(label);
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(label),
               reinterpret_cast<const unsigned char*>(label) + n);
}

[[nodiscard]] std::vector<unsigned char> TagBase(const char* label)
{
    std::vector<unsigned char> buf;
    AppendLabel(buf, kAlgHashDomainTag); // DOM (no NUL)
    AppendLabel(buf, label);
    return buf;
}

/**
 * SampleFp(tag): h = Sha256dBytes(tag ‖ LE32(ctr)); w = LE_u64(h[0..8));
 * accept iff w < floor(2^64/p)·p, return w mod p. For Goldilocks
 * 2^64 mod p = 2^32 − 1, so floor(2^64/p)·p = 2^64 − (2^32 − 1) = p and the
 * acceptance condition is simply w < p (reject probability ≈ 2^-32).
 *
 * The optional predicate extends the SAME rejection counter to structural
 * constraints (spec §1.4's μ_i ∉ {0, −1}): a draw failing the predicate is
 * rejected exactly like a biased draw and ctr advances — deterministic and
 * re-derivable with no second counter.
 */
template <typename Pred>
[[nodiscard]] Fp SampleFpFiltered(const std::vector<unsigned char>& tag, Pred pred)
{
    for (uint32_t ctr = 0;; ++ctr) {
        std::vector<unsigned char> buf = tag;
        AppendLE32(buf, ctr);
        const uint256 h = Sha256dBytes(buf.data(), buf.size());
        uint64_t w = 0;
        for (int i = 0; i < 8; ++i) {
            w |= static_cast<uint64_t>(h.data()[i]) << (8 * i);
        }
        if (w < kP && pred(static_cast<Fp>(w))) return static_cast<Fp>(w);
    }
}

[[nodiscard]] Fp SampleFp(const std::vector<unsigned char>& tag)
{
    return SampleFpFiltered(tag, [](Fp) { return true; });
}

// ----------------------------------------------------------------------------
// Constant tables (spec §1.4/§1.5): RC_ext, RC_int, μ, node/leaf domain seeds
// ----------------------------------------------------------------------------

[[nodiscard]] AlgHashConstants GenerateConstants()
{
    AlgHashConstants c;
    for (uint32_t r = 0; r < kAlgHashFullRounds; ++r) {
        for (uint32_t i = 0; i < kAlgHashT; ++i) {
            std::vector<unsigned char> tag = TagBase("RCE");
            AppendLE32(tag, r);
            AppendLE32(tag, i);
            c.rc_ext[r][i] = SampleFp(tag);
        }
    }
    for (uint32_t r = 0; r < kAlgHashPartialRounds; ++r) {
        std::vector<unsigned char> tag = TagBase("RCI");
        AppendLE32(tag, r);
        c.rc_int[r] = SampleFp(tag);
    }
    for (uint32_t i = 0; i < kAlgHashT; ++i) {
        std::vector<unsigned char> tag = TagBase("MU");
        AppendLE32(tag, i);
        // μ_i ∉ {0, −1}: μ_i = 0 zeroes a diagonal term; μ_i = −1 makes
        // row i of M_I = J + diag(μ) orthogonal to e_i's contribution.
        c.mu[i] = SampleFpFiltered(tag, [](Fp v) { return v != 0 && v != kP - 1; });
    }
    c.node_domain = SampleFp(TagBase("NODE"));
    c.leaf_domain = SampleFp(TagBase("LEAF"));
    assert(c.node_domain != c.leaf_domain); // node/leaf domain separation

    // M_I = J + diag(μ) invertibility (matrix-determinant lemma):
    // det = (∏ μ_i)·(1 + Σ μ_i^{-1}). μ_i ≠ 0 was enforced above; the full
    // determinant is astronomically unlikely to vanish for XOF-derived μ and
    // is re-checked by Gaussian elimination in the unit tests.
    Fp prod = 1;
    Fp inv_sum = 1;
    for (uint32_t i = 0; i < kAlgHashT; ++i) {
        prod = Mul(prod, c.mu[i]);
        inv_sum = Add(inv_sum, Inv(c.mu[i]));
    }
    assert(Mul(prod, inv_sum) != 0);
    return c;
}

// ----------------------------------------------------------------------------
// S-box x ↦ x^7 and its inverse x ↦ x^e, e = 7^{-1} mod (p−1)
// ----------------------------------------------------------------------------

[[nodiscard]] Fp Pow7(Fp x)
{
    const Fp x2 = Mul(x, x);
    const Fp x3 = Mul(x2, x);
    const Fp x4 = Mul(x2, x2);
    return Mul(x4, x3);
}

[[nodiscard]] Fp PowMod(Fp base, uint64_t exp)
{
    Fp result = 1;
    Fp b = Canonical(base);
    while (exp > 0) {
        if (exp & 1u) result = Mul(result, b);
        b = Mul(b, b);
        exp >>= 1;
    }
    return result;
}

/** e = 7^{-1} mod (p−1) by extended Euclid; gcd(7, p−1) = 1 so e exists. */
[[nodiscard]] uint64_t InverseSboxExponent()
{
    const unsigned __int128 m = kP - 1; // 2^64 − 2^32
    __int128 old_r = 7, r = static_cast<__int128>(m);
    __int128 old_s = 1, s = 0;
    while (r != 0) {
        const __int128 q = old_r / r;
        const __int128 tr = old_r - q * r;
        old_r = r;
        r = tr;
        const __int128 ts = old_s - q * s;
        old_s = s;
        s = ts;
    }
    assert(old_r == 1); // gcd(7, p−1) = 1
    if (old_s < 0) old_s += static_cast<__int128>(m);
    return static_cast<uint64_t>(old_s);
}

// ----------------------------------------------------------------------------
// Linear layers: M_E (frozen block-circulant of M4) and M_I = J + diag(μ)
// ----------------------------------------------------------------------------

/** FROZEN Poseidon2 MDS block M4 = [5 7 1 3; 4 6 1 1; 1 3 5 7; 1 1 4 6]. */
constexpr Fp kM4[4][4] = {
    {5, 7, 1, 3},
    {4, 6, 1, 1},
    {1, 3, 5, 7},
    {1, 1, 4, 6},
};

/** In-place y = M4 · b on four consecutive lanes. */
void ApplyM4(Fp* b)
{
    Fp y[4];
    for (int i = 0; i < 4; ++i) {
        Fp acc = 0;
        for (int j = 0; j < 4; ++j) {
            acc = Add(acc, Mul(kM4[i][j], b[j]));
        }
        y[i] = acc;
    }
    for (int i = 0; i < 4; ++i) b[i] = y[i];
}

// ----------------------------------------------------------------------------
// Inverse-layer caches (test/audit path only): explicit M_E^{-1}, M_I^{-1}
// ----------------------------------------------------------------------------

using Matrix12 = std::array<std::array<Fp, kAlgHashT>, kAlgHashT>;

/** Gauss–Jordan inverse over Fp. Asserts nonsingularity (both layer matrices
 *  are invertible by construction; re-verified in the unit tests). */
[[nodiscard]] Matrix12 InvertMatrix(const Matrix12& m)
{
    Matrix12 a = m;
    Matrix12 inv{};
    for (uint32_t i = 0; i < kAlgHashT; ++i) inv[i][i] = 1;
    for (uint32_t col = 0; col < kAlgHashT; ++col) {
        uint32_t pivot = col;
        while (pivot < kAlgHashT && Canonical(a[pivot][col]) == 0) ++pivot;
        assert(pivot < kAlgHashT);
        std::swap(a[pivot], a[col]);
        std::swap(inv[pivot], inv[col]);
        const Fp inv_p = Inv(a[col][col]);
        for (uint32_t j = 0; j < kAlgHashT; ++j) {
            a[col][j] = Mul(a[col][j], inv_p);
            inv[col][j] = Mul(inv[col][j], inv_p);
        }
        for (uint32_t row = 0; row < kAlgHashT; ++row) {
            if (row == col || Canonical(a[row][col]) == 0) continue;
            const Fp f = a[row][col];
            for (uint32_t j = 0; j < kAlgHashT; ++j) {
                a[row][j] = Sub(a[row][j], Mul(f, a[col][j]));
                inv[row][j] = Sub(inv[row][j], Mul(f, inv[col][j]));
            }
        }
    }
    return inv;
}

void ApplyMatrix(const Matrix12& m, State& s)
{
    State out{};
    for (uint32_t i = 0; i < kAlgHashT; ++i) {
        Fp acc = 0;
        for (uint32_t j = 0; j < kAlgHashT; ++j) {
            acc = Add(acc, Mul(m[i][j], s[j]));
        }
        out[i] = acc;
    }
    s = out;
}

/** Forward layer matrix from its action on the standard basis. */
template <typename Layer>
[[nodiscard]] Matrix12 MatrixOfLayer(Layer layer)
{
    Matrix12 m{};
    for (uint32_t j = 0; j < kAlgHashT; ++j) {
        State e{};
        e[j] = 1;
        layer(e);
        for (uint32_t i = 0; i < kAlgHashT; ++i) m[i][j] = e[i];
    }
    return m;
}

struct InverseTables {
    Matrix12 me_inv;
    Matrix12 mi_inv;
    uint64_t sbox_inv_exp;
};

[[nodiscard]] const InverseTables& GetInverseTables()
{
    static const InverseTables t = [] {
        InverseTables it;
        it.me_inv = InvertMatrix(MatrixOfLayer([](State& s) { ApplyExternalMatrix(s); }));
        it.mi_inv = InvertMatrix(MatrixOfLayer([](State& s) { ApplyInternalMatrix(s); }));
        it.sbox_inv_exp = InverseSboxExponent();
        return it;
    }();
    return t;
}

} // namespace

const AlgHashConstants& GetAlgHashConstants()
{
    static const AlgHashConstants c = GenerateConstants();
    return c;
}

void ApplyExternalMatrix(State& s)
{
    // M_E = circ(2·M4, M4, M4): y_b = M4·s_b per block, Σ = y_0 + y_1 + y_2,
    // output block b = y_b + Σ.
    for (int b = 0; b < 3; ++b) ApplyM4(&s[4 * b]);
    for (int k = 0; k < 4; ++k) {
        const Fp sum = Add(Add(s[k], s[4 + k]), s[8 + k]);
        for (int b = 0; b < 3; ++b) s[4 * b + k] = Add(s[4 * b + k], sum);
    }
}

void ApplyInternalMatrix(State& s)
{
    const AlgHashConstants& c = GetAlgHashConstants();
    Fp sigma = 0;
    for (uint32_t j = 0; j < kAlgHashT; ++j) sigma = Add(sigma, s[j]);
    for (uint32_t i = 0; i < kAlgHashT; ++i) {
        s[i] = Add(sigma, Mul(c.mu[i], s[i]));
    }
}

void Permute(State& s)
{
    const AlgHashConstants& c = GetAlgHashConstants();
    constexpr uint32_t kHalfFull = kAlgHashFullRounds / 2;

    ApplyExternalMatrix(s); // Poseidon2: external layer once up front

    for (uint32_t r = 0; r < kHalfFull; ++r) { // 4 initial full rounds
        for (uint32_t i = 0; i < kAlgHashT; ++i) {
            s[i] = Pow7(Add(s[i], c.rc_ext[r][i]));
        }
        ApplyExternalMatrix(s);
    }
    for (uint32_t r = 0; r < kAlgHashPartialRounds; ++r) { // 22 partial rounds
        s[0] = Pow7(Add(s[0], c.rc_int[r]));
        ApplyInternalMatrix(s);
    }
    for (uint32_t r = 0; r < kHalfFull; ++r) { // 4 final full rounds
        for (uint32_t i = 0; i < kAlgHashT; ++i) {
            s[i] = Pow7(Add(s[i], c.rc_ext[kHalfFull + r][i]));
        }
        ApplyExternalMatrix(s);
    }
}

void InversePermute(State& s)
{
    const AlgHashConstants& c = GetAlgHashConstants();
    const InverseTables& inv = GetInverseTables();
    constexpr uint32_t kHalfFull = kAlgHashFullRounds / 2;

    for (uint32_t r = kHalfFull; r-- > 0;) { // undo 4 final full rounds
        ApplyMatrix(inv.me_inv, s);
        for (uint32_t i = 0; i < kAlgHashT; ++i) {
            s[i] = Sub(PowMod(s[i], inv.sbox_inv_exp), c.rc_ext[kHalfFull + r][i]);
        }
    }
    for (uint32_t r = kAlgHashPartialRounds; r-- > 0;) { // undo 22 partial rounds
        ApplyMatrix(inv.mi_inv, s);
        s[0] = Sub(PowMod(s[0], inv.sbox_inv_exp), c.rc_int[r]);
    }
    for (uint32_t r = kHalfFull; r-- > 0;) { // undo 4 initial full rounds
        ApplyMatrix(inv.me_inv, s);
        for (uint32_t i = 0; i < kAlgHashT; ++i) {
            s[i] = Sub(PowMod(s[i], inv.sbox_inv_exp), c.rc_ext[r][i]);
        }
    }
    ApplyMatrix(inv.me_inv, s); // undo the up-front external layer
}

Digest Compress(const Digest& left, const Digest& right)
{
    State s{};
    for (uint32_t i = 0; i < kAlgHashDigestLen; ++i) {
        s[i] = Canonical(left[i]);
        s[kAlgHashDigestLen + i] = Canonical(right[i]);
    }
    s[2 * kAlgHashDigestLen] = GetAlgHashConstants().node_domain; // capacity seed D
    Permute(s);
    return Digest{s[0], s[1], s[2], s[3]};
}

Digest LeafHash(const Fp3& v, uint32_t index)
{
    State s{};
    s[0] = Canonical(v.c0);
    s[1] = Canonical(v.c1);
    s[2] = Canonical(v.c2);
    s[3] = gkr_field::FromU64(index);
    s[4] = GetAlgHashConstants().leaf_domain; // capacity seed Le (≠ D)
    Permute(s);
    return Digest{s[0], s[1], s[2], s[3]};
}

Digest LeafHashRow(const std::vector<Fp3>& row, uint32_t index)
{
    std::vector<Fp> xs;
    xs.reserve(3 * row.size() + 1);
    for (const Fp3& v : row) {
        xs.push_back(Canonical(v.c0));
        xs.push_back(Canonical(v.c1));
        xs.push_back(Canonical(v.c2));
    }
    xs.push_back(gkr_field::FromU64(index));
    return SpongeHashFp(xs);
}

Digest SpongeHashFp(const std::vector<Fp>& xs)
{
    // 10*-padding over Fp: ALWAYS append 1, then 0s to the next rate multiple
    // (a full extra block when |xs| ≡ 0 mod R) — injective on Fp lists.
    std::vector<Fp> padded;
    padded.reserve(xs.size() + kAlgHashRate);
    for (const Fp x : xs) padded.push_back(Canonical(x));
    padded.push_back(1);
    while (padded.size() % kAlgHashRate != 0) padded.push_back(0);

    State s{}; // capacity lanes [8..12) stay 0 → variable-length domain
    for (size_t off = 0; off < padded.size(); off += kAlgHashRate) {
        for (uint32_t j = 0; j < kAlgHashRate; ++j) {
            s[j] = Add(s[j], padded[off + j]); // add-absorb into rate lanes
        }
        Permute(s);
    }
    return Digest{s[0], s[1], s[2], s[3]}; // single squeeze = 256-bit digest
}

Digest SpongeHashFp3(const std::vector<Fp3>& xs)
{
    std::vector<Fp> flat;
    flat.reserve(3 * xs.size());
    for (const Fp3& v : xs) {
        // Canonical injective embedding, coordinate order c0, c1, c2
        // (matches ToU64Triple, matmul_v4_rc_gkr_field_ext3.h:182).
        flat.push_back(Canonical(v.c0));
        flat.push_back(Canonical(v.c1));
        flat.push_back(Canonical(v.c2));
    }
    return SpongeHashFp(flat);
}

} // namespace matmul::v4::rc::alg_hash
