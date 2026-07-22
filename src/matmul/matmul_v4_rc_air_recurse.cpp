// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_air_recurse.h>

#include <matmul/matmul_v4_rc_fri.h> // FriNextPow2

#include <algorithm>
#include <cassert>
#include <cstring>
#include <functional>
#include <utility>

// Poseidon2-as-AIR gadget — implementation. See the header for the flattened
// 130-cell layout contract. The one non-obvious piece is the SYMBOLIC AFFINE
// PASS: every S-box input and every permutation output lane is an Fp-affine
// form over the 130 witnessed cells, derived ONCE by replaying the
// permutation's linear structure over affine forms instead of field elements
// (round-constant additions land in the constant slot; each S-box position
// substitutes the fresh witness-cell variable instead of applying x^7). The
// constraint closures then evaluate a precomputed dot product + one x^7 —
// degree exactly 7 in the row values, and structurally identical to the real
// permutation because both use ApplyM4/M_E/M_I coefficient-for-coefficient.

namespace matmul::v4::rc::air_recurse {

namespace aq = air_quotient;
namespace ah = alg_hash;
namespace gf = gkr_field;

namespace {

using ah::AlgHashConstants;
using ah::GetAlgHashConstants;
using ah::kAlgHashDigestLen;
using ah::kAlgHashFullRounds;
using ah::kAlgHashPartialRounds;
using ah::kAlgHashT;
using ah::State;

constexpr uint32_t kHalfFull = kAlgHashFullRounds / 2;

/** x^7 over Fp (mirrors alg_hash's S-box; 4 multiplications). */
[[nodiscard]] Fp Pow7Fp(Fp x)
{
    const Fp x2 = gf::Mul(x, x);
    const Fp x3 = gf::Mul(x2, x);
    const Fp x4 = gf::Mul(x2, x2);
    return gf::Mul(x4, x3);
}

/** x^7 over Fp3 (the constraint-side S-box; agrees with Pow7Fp on Fp ⊂ Fp3). */
[[nodiscard]] Fp3 Pow7Ext(const Fp3& x)
{
    const Fp3 x2 = gf::Mul(x, x);
    const Fp3 x3 = gf::Mul(x2, x);
    const Fp3 x4 = gf::Mul(x2, x2);
    return gf::Mul(x4, x3);
}

/** Fp-scalar multiple of an Fp3 value: c·(a0,a1,a2) = (c·a0, c·a1, c·a2)
 *  (= Mul(FromFp(c), a); the coordinate form saves the full extension mul). */
[[nodiscard]] Fp3 MulScalar(Fp c, const Fp3& a)
{
    return Fp3{gf::Mul(c, a.c0), gf::Mul(c, a.c1), gf::Mul(c, a.c2)};
}

// ---------------------------------------------------------------------------
// Symbolic affine pass: Fp-affine forms over the 130 cells + constant slot.
// ---------------------------------------------------------------------------

/** Affine form a[0]·cell_0 + … + a[129]·cell_129 + a[130] (constant slot). */
using Affine = std::array<Fp, kPermCellsPerPerm + 1>;
constexpr uint32_t kConstSlot = kPermCellsPerPerm;

[[nodiscard]] Affine CellVar(uint32_t cell)
{
    Affine a{};
    a[cell] = 1;
    return a;
}

void AddConst(Affine& a, Fp c) { a[kConstSlot] = gf::Add(a[kConstSlot], c); }

/** M4 block action on four affine forms (same coefficients as ah::ApplyM4). */
void ApplyM4Affine(Affine* b)
{
    // FROZEN Poseidon2 MDS block M4 (spec §1.3; mirrored from alg_hash.cpp —
    // the layer-consistency unit test pins the two against each other).
    static constexpr Fp kM4[4][4] = {
        {5, 7, 1, 3},
        {4, 6, 1, 1},
        {1, 3, 5, 7},
        {1, 1, 4, 6},
    };
    Affine y[4];
    for (int i = 0; i < 4; ++i) {
        Affine acc{};
        for (int j = 0; j < 4; ++j) {
            for (uint32_t k = 0; k <= kConstSlot; ++k) {
                acc[k] = gf::Add(acc[k], gf::Mul(kM4[i][j], b[j][k]));
            }
        }
        y[i] = acc;
    }
    for (int i = 0; i < 4; ++i) b[i] = y[i];
}

/** M_E = circ(2·M4, M4, M4) on 12 affine forms (mirrors ApplyExternalMatrix). */
void ApplyExternalAffine(std::array<Affine, kAlgHashT>& s)
{
    for (int b = 0; b < 3; ++b) ApplyM4Affine(&s[4 * b]);
    for (int k = 0; k < 4; ++k) {
        Affine sum{};
        for (uint32_t c = 0; c <= kConstSlot; ++c) {
            sum[c] = gf::Add(gf::Add(s[k][c], s[4 + k][c]), s[8 + k][c]);
        }
        for (int b = 0; b < 3; ++b) {
            for (uint32_t c = 0; c <= kConstSlot; ++c) {
                s[4 * b + k][c] = gf::Add(s[4 * b + k][c], sum[c]);
            }
        }
    }
}

/** M_I = J + diag(μ) on 12 affine forms (mirrors ApplyInternalMatrix). */
void ApplyInternalAffine(std::array<Affine, kAlgHashT>& s, const AlgHashConstants& c)
{
    Affine sigma{};
    for (uint32_t j = 0; j < kAlgHashT; ++j) {
        for (uint32_t k = 0; k <= kConstSlot; ++k) sigma[k] = gf::Add(sigma[k], s[j][k]);
    }
    for (uint32_t i = 0; i < kAlgHashT; ++i) {
        for (uint32_t k = 0; k <= kConstSlot; ++k) {
            s[i][k] = gf::Add(sigma[k], gf::Mul(c.mu[i], s[i][k]));
        }
    }
}

/** The precomputed affine forms: S-box inputs A_s and output lanes Out_j. */
struct PermAffineTables {
    std::array<Affine, kPermSboxCells> sbox_in;
    std::array<Affine, kAlgHashT> out;
};

/**
 * Replay the permutation's linear skeleton symbolically: state lanes are
 * affine forms; at each S-box position record the (RC-shifted) input form
 * and SUBSTITUTE the fresh witness-cell variable. Identical control flow to
 * ah::Permute, with Pow7 replaced by {record, substitute}.
 */
[[nodiscard]] PermAffineTables BuildPermAffineTables()
{
    const AlgHashConstants& c = GetAlgHashConstants();
    PermAffineTables t;

    std::array<Affine, kAlgHashT> st;
    for (uint32_t i = 0; i < kAlgHashT; ++i) st[i] = CellVar(i); // input lanes
    ApplyExternalAffine(st);                                     // up-front M_E

    for (uint32_t r = 0; r < kHalfFull; ++r) { // 4 initial full rounds
        for (uint32_t i = 0; i < kAlgHashT; ++i) {
            const uint32_t s = SboxIndexInitialFull(r, i);
            t.sbox_in[s] = st[i];
            AddConst(t.sbox_in[s], c.rc_ext[r][i]);
            st[i] = CellVar(kPermInputCells + s);
        }
        ApplyExternalAffine(st);
    }
    for (uint32_t r = 0; r < kAlgHashPartialRounds; ++r) { // 22 partial rounds
        const uint32_t s = SboxIndexPartial(r);
        t.sbox_in[s] = st[0];
        AddConst(t.sbox_in[s], c.rc_int[r]);
        st[0] = CellVar(kPermInputCells + s);
        ApplyInternalAffine(st, c);
    }
    for (uint32_t r = 0; r < kHalfFull; ++r) { // 4 final full rounds
        for (uint32_t i = 0; i < kAlgHashT; ++i) {
            const uint32_t s = SboxIndexFinalFull(r, i);
            t.sbox_in[s] = st[i];
            AddConst(t.sbox_in[s], c.rc_ext[kHalfFull + r][i]);
            st[i] = CellVar(kPermInputCells + s);
        }
        ApplyExternalAffine(st);
    }
    t.out = st; // outputs: linear in the final round's 12 S-box cells
    return t;
}

[[nodiscard]] const PermAffineTables& GetPermAffineTables()
{
    static const PermAffineTables t = BuildPermAffineTables();
    return t;
}

/** Evaluate an affine form at an Fp3 row (degree 1; skips zero coefficients). */
[[nodiscard]] Fp3 EvalAffine(const Affine& a, const std::vector<Fp3>& row, uint32_t base)
{
    Fp3 acc = Fp3::FromFp(a[kConstSlot]);
    for (uint32_t i = 0; i < kPermCellsPerPerm; ++i) {
        if (gf::Canonical(a[i]) == 0) continue;
        acc = gf::Add(acc, MulScalar(a[i], row[base + i]));
    }
    return acc;
}

} // namespace

// ---------------------------------------------------------------------------
// Constraint builders.
// ---------------------------------------------------------------------------

std::vector<aq::AirConstraint<Fp3>> BuildPermRoundConstraints(const PermLayout& layout)
{
    const PermAffineTables* tables = &GetPermAffineTables();
    std::vector<aq::AirConstraint<Fp3>> out;
    out.reserve(kPermSboxCells);
    for (uint32_t s = 0; s < kPermSboxCells; ++s) {
        aq::AirConstraint<Fp3> c;
        c.name = s < SboxIndexPartial(0)                          ? "recurse.perm.sbox.full_i"
                 : s < SboxIndexPartial(kAlgHashPartialRounds)    ? "recurse.perm.sbox.partial"
                                                                  : "recurse.perm.sbox.full_f";
        c.kind = aq::AirKind::kEverywhere;
        c.alg_degree = ah::kAlgHashSboxPower; // 7
        c.eval = [layout, tables, s](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
            const Fp3 x = EvalAffine(tables->sbox_in[s], cur, layout.base);
            return gf::Sub(cur[layout.SboxCol(s)], Pow7Ext(x));
        };
        out.push_back(std::move(c));
    }
    return out;
}

std::vector<aq::AirConstraint<Fp3>> BuildCompressCapacityConstraints(const PermLayout& layout)
{
    // state = [L0..L3, R0..R3, D, 0, 0, 0] (spec §1.7): pin the 4 capacity
    // lanes; the 8 rate lanes are the free child-digest inputs.
    const Fp3 node_domain = Fp3::FromFp(GetAlgHashConstants().node_domain);
    std::vector<aq::AirConstraint<Fp3>> out;
    out.reserve(ah::kAlgHashCapacity);
    {
        aq::AirConstraint<Fp3> c;
        c.name = "recurse.compress.capacity.domain";
        c.kind = aq::AirKind::kEverywhere;
        c.alg_degree = 1;
        const uint32_t col = layout.InputCol(2 * kAlgHashDigestLen); // in_8
        c.eval = [col, node_domain](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
            return gf::Sub(cur[col], node_domain);
        };
        out.push_back(std::move(c));
    }
    for (uint32_t i = 2 * kAlgHashDigestLen + 1; i < kAlgHashT; ++i) { // in_9..in_11
        aq::AirConstraint<Fp3> c;
        c.name = "recurse.compress.capacity.zero";
        c.kind = aq::AirKind::kEverywhere;
        c.alg_degree = 1;
        const uint32_t col = layout.InputCol(i);
        c.eval = [col](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
            return cur[col];
        };
        out.push_back(std::move(c));
    }
    return out;
}

Fp3 PermOutputLane(const PermLayout& layout, const std::vector<Fp3>& row, uint32_t lane)
{
    assert(lane < kAlgHashT);
    return EvalAffine(GetPermAffineTables().out[lane], row, layout.base);
}

Fp3 PermSboxInput(const PermLayout& layout, const std::vector<Fp3>& row, uint32_t s)
{
    assert(s < kPermSboxCells);
    return EvalAffine(GetPermAffineTables().sbox_in[s], row, layout.base);
}

std::vector<aq::AirConstraint<Fp3>> BuildMerkleGlueConstraints(const MerkleGlueLayout& layout)
{
    std::vector<aq::AirConstraint<Fp3>> out;
    out.reserve(1 + 2 * kAlgHashDigestLen + ah::kAlgHashCapacity + kAlgHashDigestLen);
    const Fp3 one = Fp3::One();

    // Direction-bit booleanity b·(b−1) = 0 (spec §3.2 B, degree 2).
    {
        aq::AirConstraint<Fp3> c;
        c.name = "recurse.merkle.dir.bool";
        c.kind = aq::AirKind::kEverywhere;
        c.alg_degree = 2;
        const uint32_t col = layout.dir_col;
        c.eval = [col, one](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
            return gf::Mul(cur[col], gf::Sub(cur[col], one));
        };
        out.push_back(std::move(c));
    }
    // Input wiring (acc, sib) in mp_dir order (degree-2 selection):
    //   in_j     = (1−b)·acc_j + b·sib_j     (b = 0: acc is the LEFT child)
    //   in_{4+j} = (1−b)·sib_j + b·acc_j
    for (uint32_t j = 0; j < kAlgHashDigestLen; ++j) {
        const uint32_t acc = layout.acc_base + j;
        const uint32_t sib = layout.sib_base + j;
        const uint32_t in_l = layout.perm.InputCol(j);
        const uint32_t in_r = layout.perm.InputCol(kAlgHashDigestLen + j);
        const uint32_t dir = layout.dir_col;
        {
            aq::AirConstraint<Fp3> c;
            c.name = "recurse.merkle.wire.left";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 2;
            c.eval = [in_l, acc, sib, dir, one](const std::vector<Fp3>& cur,
                                                const std::vector<Fp3>&) {
                const Fp3 sel = gf::Add(gf::Mul(gf::Sub(one, cur[dir]), cur[acc]),
                                        gf::Mul(cur[dir], cur[sib]));
                return gf::Sub(cur[in_l], sel);
            };
            out.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name = "recurse.merkle.wire.right";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 2;
            c.eval = [in_r, acc, sib, dir, one](const std::vector<Fp3>& cur,
                                                const std::vector<Fp3>&) {
                const Fp3 sel = gf::Add(gf::Mul(gf::Sub(one, cur[dir]), cur[sib]),
                                        gf::Mul(cur[dir], cur[acc]));
                return gf::Sub(cur[in_r], sel);
            };
            out.push_back(std::move(c));
        }
    }
    // Node capacity pins [D, 0, 0, 0].
    for (auto& c : BuildCompressCapacityConstraints(layout.perm)) out.push_back(std::move(c));
    // Accumulator update acc_j(next) = Out_j(cur) — the parent digest re-enters
    // the running accumulator on the next row (degree 1, transition).
    for (uint32_t j = 0; j < kAlgHashDigestLen; ++j) {
        aq::AirConstraint<Fp3> c;
        c.name = "recurse.merkle.acc.update";
        c.kind = aq::AirKind::kTransition;
        c.alg_degree = 1;
        const uint32_t acc = layout.acc_base + j;
        const PermLayout perm = layout.perm;
        c.eval = [acc, perm, j](const std::vector<Fp3>& cur, const std::vector<Fp3>& next) {
            return gf::Sub(next[acc], PermOutputLane(perm, cur, j));
        };
        out.push_back(std::move(c));
    }
    return out;
}

std::vector<aq::AirConstraint<Fp3>>
BuildMerkleRootBoundaryConstraints(uint32_t acc_base, const ah::Digest& root)
{
    std::vector<aq::AirConstraint<Fp3>> out;
    out.reserve(kAlgHashDigestLen);
    for (uint32_t j = 0; j < kAlgHashDigestLen; ++j) {
        aq::AirConstraint<Fp3> c;
        c.name = "recurse.merkle.root.pin";
        c.kind = aq::AirKind::kLastRow;
        c.alg_degree = 1;
        const uint32_t col = acc_base + j;
        const Fp3 want = Fp3::FromFp(root[j]);
        c.eval = [col, want](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
            return gf::Sub(cur[col], want);
        };
        out.push_back(std::move(c));
    }
    return out;
}

// ---------------------------------------------------------------------------
// Honest-witness builders.
// ---------------------------------------------------------------------------

PermWitness BuildPermWitness(const State& input)
{
    const AlgHashConstants& c = GetAlgHashConstants();
    PermWitness w;
    for (uint32_t i = 0; i < kAlgHashT; ++i) w.cells[i] = gf::Canonical(input[i]);

    // Replay ah::Permute (same control flow), recording each S-box output.
    State s = input;
    ah::ApplyExternalMatrix(s);
    for (uint32_t r = 0; r < kHalfFull; ++r) {
        for (uint32_t i = 0; i < kAlgHashT; ++i) {
            s[i] = Pow7Fp(gf::Add(s[i], c.rc_ext[r][i]));
            w.cells[kPermInputCells + SboxIndexInitialFull(r, i)] = s[i];
        }
        ah::ApplyExternalMatrix(s);
    }
    for (uint32_t r = 0; r < kAlgHashPartialRounds; ++r) {
        s[0] = Pow7Fp(gf::Add(s[0], c.rc_int[r]));
        w.cells[kPermInputCells + SboxIndexPartial(r)] = s[0];
        ah::ApplyInternalMatrix(s);
    }
    for (uint32_t r = 0; r < kHalfFull; ++r) {
        for (uint32_t i = 0; i < kAlgHashT; ++i) {
            s[i] = Pow7Fp(gf::Add(s[i], c.rc_ext[kHalfFull + r][i]));
            w.cells[kPermInputCells + SboxIndexFinalFull(r, i)] = s[i];
        }
        ah::ApplyExternalMatrix(s);
    }
    w.output = s;

    // Cross-check the recording against the primitive itself (cheap; the
    // constraint-satisfaction unit tests re-verify through the affine forms).
    State ref = input;
    ah::Permute(ref);
    for (uint32_t i = 0; i < kAlgHashT; ++i) {
        assert(gf::Canonical(ref[i]) == gf::Canonical(w.output[i]));
    }
    return w;
}

void WritePermWitness(const PermLayout& layout, const PermWitness& w, std::vector<Fp3>& row)
{
    assert(row.size() >= layout.End());
    for (uint32_t i = 0; i < kPermCellsPerPerm; ++i) {
        row[layout.base + i] = Fp3::FromFp(w.cells[i]);
    }
}

std::vector<Fp3> BuildCompressWitnessRow(const PermLayout& layout, const ah::Digest& left,
                                         const ah::Digest& right)
{
    State s{};
    for (uint32_t i = 0; i < kAlgHashDigestLen; ++i) {
        s[i] = gf::Canonical(left[i]);
        s[kAlgHashDigestLen + i] = gf::Canonical(right[i]);
    }
    s[2 * kAlgHashDigestLen] = GetAlgHashConstants().node_domain;
    std::vector<Fp3> row(layout.End(), Fp3::Zero());
    WritePermWitness(layout, BuildPermWitness(s), row);
    return row;
}

void FillMerkleGlueRow(const MerkleGlueLayout& layout, const ah::Digest& acc,
                       const ah::Digest& sib, bool dir_bit, std::vector<Fp3>& row,
                       ah::Digest* parent_out)
{
    const ah::Digest& left = dir_bit ? sib : acc;
    const ah::Digest& right = dir_bit ? acc : sib;
    State s{};
    for (uint32_t i = 0; i < kAlgHashDigestLen; ++i) {
        s[i] = gf::Canonical(left[i]);
        s[kAlgHashDigestLen + i] = gf::Canonical(right[i]);
    }
    s[2 * kAlgHashDigestLen] = GetAlgHashConstants().node_domain;
    const PermWitness w = BuildPermWitness(s);
    WritePermWitness(layout.perm, w, row);
    row[layout.dir_col] = dir_bit ? Fp3::One() : Fp3::Zero();
    for (uint32_t j = 0; j < kAlgHashDigestLen; ++j) {
        row[layout.acc_base + j] = Fp3::FromFp(gf::Canonical(acc[j]));
        row[layout.sib_base + j] = Fp3::FromFp(gf::Canonical(sib[j]));
    }
    if (parent_out != nullptr) {
        for (uint32_t j = 0; j < kAlgHashDigestLen; ++j) (*parent_out)[j] = w.output[j];
    }
}

// ---------------------------------------------------------------------------
// Measurement (spec §3.4 feasibility gate).
// ---------------------------------------------------------------------------

aq::AirConstraintSystem<Fp3> BuildSinglePermCompressSystem(uint32_t n_rows)
{
    aq::AirConstraintSystem<Fp3> cs;
    cs.n_rows = n_rows;
    cs.n_columns = kPermCellsPerPerm;
    const PermLayout layout{0};
    cs.constraints = BuildPermRoundConstraints(layout);
    for (auto& c : BuildCompressCapacityConstraints(layout)) {
        cs.constraints.push_back(std::move(c));
    }
    return cs;
}

PermGadgetMeasurement MeasureSinglePermCompress(uint32_t n_rows)
{
    const aq::AirConstraintSystem<Fp3> cs = BuildSinglePermCompressSystem(n_rows);
    PermGadgetMeasurement m;
    m.cells_per_perm = cs.n_columns;
    m.n_constraints = static_cast<uint32_t>(cs.constraints.size());
    m.n_sbox_constraints = kPermSboxCells;
    for (const auto& c : cs.constraints) {
        if (c.alg_degree > m.max_alg_degree) m.max_alg_degree = c.alg_degree;
    }
    m.n_rows = n_rows;
    m.max_composed_degree = cs.MaxComposedDegreeBound();
    m.quotient_len = cs.QuotientLen();
    m.cells_per_merkle_level = MerkleGlueLayout::kCellsPerLevel;
    return m;
}

// ============================================================================
// PIECE 4 — V_CS (FRI-verifier-as-AIR) + ProveAggregate / VerifyAggregate.
// WIDE one-query-per-row layout; every constraint kEverywhere (reads `cur`).
// See the header block for the layout and the faithfulness argument.
// ============================================================================

namespace {

using AlgB3 = aq::AirFriBackendAlg<Fp3>;
using aq::AirConstraint;
using aq::AirConstraintSystem;
using aq::AirKind;
using ah::Digest;

// ---- base-field domain helpers (mirror matmul_v4_rc_fri_ext3_alg.cpp) -------
constexpr Fp kOmega2_32R = 0x185629dcda58878cULL;
Fp PowFpR(Fp base, uint64_t exp)
{
    Fp r = 1;
    base = gf::Canonical(base);
    while (exp > 0) {
        if (exp & 1u) r = gf::Mul(r, base);
        base = gf::Mul(base, base);
        exp >>= 1;
    }
    return r;
}
Fp OmegaForSizeR(uint32_t n)
{
    uint32_t logn = 0, t = n;
    while (t > 1) { t >>= 1; ++logn; }
    return PowFpR(kOmega2_32R, 1ULL << (32 - logn));
}
Fp3 DomainPointR(uint32_t n0, uint32_t index) { return Fp3::FromFp(PowFpR(OmegaForSizeR(n0), index)); }
uint32_t Log2ExactR(uint32_t n) { uint32_t l = 0; while (n > 1) { n >>= 1; ++l; } return l; }
Fp3 Pow3R(Fp3 b, uint64_t e) { Fp3 r = Fp3::One(); while (e) { if (e & 1u) r = gf::Mul(r, b); b = gf::Mul(b, b); e >>= 1; } return r; }

// Column offsets of ONE fold layer's blocks + siblings within a child block.
struct FoldCols {
    uint32_t depth{0};
    uint32_t even_leaf{0};
    std::vector<uint32_t> even_comp;   // depth bases
    std::vector<uint32_t> even_sib;    // depth sibling-column bases (4 cols each)
    uint32_t odd_leaf{0};
    std::vector<uint32_t> odd_comp;
    std::vector<uint32_t> odd_sib;
    uint32_t folded_col{0};            // witnessed folded value (Fp3 -> 1 col slot stores c0; use 1 Fp3 col)
};

// Preprocessed (public, per-query) columns of ONE child block: global indices.
struct PreCols {
    uint32_t idx_fp{0};                // Fp(query index)
    std::vector<uint32_t> row_dir;     // D dir bits for the row path
    // per fold layer
    struct FoldPre {
        uint32_t even_leaf_idx{0};
        uint32_t odd_leaf_idx{0};
        std::vector<uint32_t> even_dir;
        std::vector<uint32_t> odd_dir;
        uint32_t x{0};                 // DomainPoint(n_leaves, i)
        uint32_t leaf_sel{0};          // 1 iff idx_l < half at this layer
    };
    std::vector<FoldPre> folds;
    // deep / per-point
    std::vector<uint32_t> xpow;        // W+1 : x_lde^{shift_i}
    uint32_t invd1{0};                 // 1/(x_lde - z1)
    uint32_t invd2{0};                 // 1/(x_lde - z2)
    uint32_t zh{0};                    // y^N - 1, y = g*x_lde
};

struct ChildLayout {
    uint32_t base{0};                  // first WITNESS column of this child block
    uint32_t W{0}, D{0}, nf{0};
    // row path (witness)
    uint32_t row_leaf{0};
    std::vector<uint32_t> row_comp;    // D
    std::vector<uint32_t> row_sib;     // D (4 cols each)
    std::vector<FoldCols> folds;
    uint32_t witness_end{0};           // first column past this child's witness cols
    PreCols pre;                       // filled during preprocessed allocation
    uint32_t perms{0};                 // perm blocks in this child (measurement)
};

struct VcsLayout {
    uint32_t k{0};
    VerifierAirFamilies fam;
    std::vector<ChildLayout> children;
    uint32_t n_witness_cols{0};
    uint32_t n_cols{0};                // witness + preprocessed
    uint32_t queries{0};
    uint32_t child_n_lde{0};
    uint32_t child_n_coeffs{0};
    uint32_t child_N{0};
};

// Allocate witness columns for a child block (perm blocks 130 each + siblings).
uint32_t AllocChildWitness(ChildLayout& c, uint32_t start, const ChildPublicInputs& sh,
                           const VerifierAirFamilies& fam)
{
    c.base = start;
    uint32_t col = start;
    auto perm_block = [&]() { const uint32_t b = col; col += kPermCellsPerPerm; ++c.perms; return b; };
    auto dig4 = [&]() { const uint32_t b = col; col += kAlgHashDigestLen; return b; };
    c.W = sh.child_w; c.D = sh.merkle_depth; c.nf = sh.n_folds;
    if (fam.row_merkle) {
        c.row_leaf = perm_block();
        for (uint32_t j = 0; j < c.D; ++j) c.row_comp.push_back(perm_block());
        for (uint32_t j = 0; j < c.D; ++j) c.row_sib.push_back(dig4());
    }
    if (fam.fold) {
        for (uint32_t l = 0; l < c.nf; ++l) {
            FoldCols f;
            f.depth = c.D - l;
            f.even_leaf = perm_block();
            for (uint32_t j = 0; j < f.depth; ++j) f.even_comp.push_back(perm_block());
            for (uint32_t j = 0; j < f.depth; ++j) f.even_sib.push_back(dig4());
            f.odd_leaf = perm_block();
            for (uint32_t j = 0; j < f.depth; ++j) f.odd_comp.push_back(perm_block());
            for (uint32_t j = 0; j < f.depth; ++j) f.odd_sib.push_back(dig4());
            if (fam.deep) { f.folded_col = col; col += 1; } // witnessed folded value (Fp3)
            c.folds.push_back(std::move(f));
        }
    }
    c.witness_end = col;
    return col;
}

// Allocate preprocessed columns for a child block (after all witness columns).
uint32_t AllocChildPreproc(ChildLayout& c, uint32_t start, const VerifierAirFamilies& fam)
{
    uint32_t col = start;
    auto one = [&]() { return col++; };
    c.pre.idx_fp = one();
    if (fam.row_merkle) for (uint32_t j = 0; j < c.D; ++j) c.pre.row_dir.push_back(one());
    if (fam.fold) {
        for (uint32_t l = 0; l < c.nf; ++l) {
            PreCols::FoldPre fp;
            fp.even_leaf_idx = one();
            fp.odd_leaf_idx = one();
            const uint32_t depth = c.D - l;
            for (uint32_t j = 0; j < depth; ++j) fp.even_dir.push_back(one());
            for (uint32_t j = 0; j < depth; ++j) fp.odd_dir.push_back(one());
            fp.x = one();
            fp.leaf_sel = one();
            c.pre.folds.push_back(std::move(fp));
        }
    }
    if (fam.deep) {
        for (uint32_t i = 0; i <= c.W; ++i) c.pre.xpow.push_back(one());
        c.pre.invd1 = one();
        c.pre.invd2 = one();
    }
    if (fam.per_point) c.pre.zh = one();
    return col;
}

VcsLayout ComputeLayout(uint32_t k, const std::vector<ChildPublicInputs>& shapes,
                        const VerifierAirFamilies& fam)
{
    VcsLayout L;
    L.k = k;
    L.fam = fam;
    L.children.resize(k);
    uint32_t col = 0;
    for (uint32_t c = 0; c < k; ++c) col = AllocChildWitness(L.children[c], col, shapes[c], fam);
    L.n_witness_cols = col;
    for (uint32_t c = 0; c < k; ++c) col = AllocChildPreproc(L.children[c], col, fam);
    L.n_cols = col;
    L.queries = static_cast<uint32_t>(shapes[0].query_index.size());
    L.child_n_lde = shapes[0].child_n_lde;
    L.child_n_coeffs = shapes[0].child_n_coeffs;
    L.child_N = shapes[0].child_n_rows;
    return L;
}

// ---- constraint helpers -----------------------------------------------------
// Add the 118 S-box identities of a perm block at `base`.
void EmitPermSbox(std::vector<AirConstraint<Fp3>>& out, uint32_t base)
{
    for (auto& c : BuildPermRoundConstraints(PermLayout{base})) out.push_back(std::move(c));
}
// Pin an input lane to a constant.
void EmitInputConst(std::vector<AirConstraint<Fp3>>& out, uint32_t base, uint32_t lane, Fp3 val)
{
    AirConstraint<Fp3> c;
    c.name = "vcs.perm.in.const"; c.kind = AirKind::kEverywhere; c.alg_degree = 1;
    const uint32_t col = PermLayout{base}.InputCol(lane);
    c.eval = [col, val](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
        return gf::Sub(cur[col], val);
    };
    out.push_back(std::move(c));
}
// Pin an input lane equal to a (preprocessed) column value.
void EmitInputEqCol(std::vector<AirConstraint<Fp3>>& out, uint32_t base, uint32_t lane, uint32_t src)
{
    AirConstraint<Fp3> c;
    c.name = "vcs.perm.in.eqcol"; c.kind = AirKind::kEverywhere; c.alg_degree = 1;
    const uint32_t col = PermLayout{base}.InputCol(lane);
    c.eval = [col, src](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
        return gf::Sub(cur[col], cur[src]);
    };
    out.push_back(std::move(c));
}

// Compress-block input wiring: acc = prev block output (PermOutputLane), sib =
// witness digest columns, dir = preprocessed bit. Mirrors Fri3AlgVerifyPath:
//   bit==0 -> Compress(acc, sib) ; bit==1 -> Compress(sib, acc).
// Emits 8 digest-coord wires + capacity pins [D,0,0,0].
void EmitCompressWiring(std::vector<AirConstraint<Fp3>>& out, uint32_t block_base,
                        uint32_t prev_base, uint32_t sib_base, uint32_t dir_col, Fp3 node_domain)
{
    const PermLayout blk{block_base};
    const PermLayout prev{prev_base};
    for (uint32_t j = 0; j < kAlgHashDigestLen; ++j) {
        const uint32_t in_l = blk.InputCol(j);
        const uint32_t in_r = blk.InputCol(kAlgHashDigestLen + j);
        const uint32_t sib = sib_base + j;
        { // left = (1-bit)*acc + bit*sib
            AirConstraint<Fp3> c;
            c.name = "vcs.merkle.wire.left"; c.kind = AirKind::kEverywhere; c.alg_degree = 2;
            c.eval = [in_l, sib, dir_col, prev, j](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
                const Fp3 acc = PermOutputLane(prev, cur, j);
                const Fp3 sel = gf::Add(gf::Mul(gf::Sub(Fp3::One(), cur[dir_col]), acc),
                                        gf::Mul(cur[dir_col], cur[sib]));
                return gf::Sub(cur[in_l], sel);
            };
            out.push_back(std::move(c));
        }
        { // right = (1-bit)*sib + bit*acc
            AirConstraint<Fp3> c;
            c.name = "vcs.merkle.wire.right"; c.kind = AirKind::kEverywhere; c.alg_degree = 2;
            c.eval = [in_r, sib, dir_col, prev, j](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
                const Fp3 acc = PermOutputLane(prev, cur, j);
                const Fp3 sel = gf::Add(gf::Mul(gf::Sub(Fp3::One(), cur[dir_col]), cur[sib]),
                                        gf::Mul(cur[dir_col], acc));
                return gf::Sub(cur[in_r], sel);
            };
            out.push_back(std::move(c));
        }
    }
    EmitInputConst(out, block_base, 2 * kAlgHashDigestLen, node_domain);       // in_8 = D
    for (uint32_t l = 2 * kAlgHashDigestLen + 1; l < kAlgHashT; ++l)
        EmitInputConst(out, block_base, l, Fp3::Zero());                        // in_9..11 = 0
}

// Pin PermOutputLane(base,0..3) == a global root constant.
void EmitRootPin(std::vector<AirConstraint<Fp3>>& out, uint32_t last_base, const Digest& root)
{
    const PermLayout last{last_base};
    for (uint32_t j = 0; j < kAlgHashDigestLen; ++j) {
        AirConstraint<Fp3> c;
        c.name = "vcs.merkle.root.pin"; c.kind = AirKind::kEverywhere; c.alg_degree = 1;
        const Fp3 want = Fp3::FromFp(gf::Canonical(root[j]));
        c.eval = [last, j, want](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
            return gf::Sub(PermOutputLane(last, cur, j), want);
        };
        out.push_back(std::move(c));
    }
}

// Read an Fp3 "value" that is stored as consecutive-coordinate input lanes of a
// perm block: lanes (l, l+1, l+2) -> (c0,c1,c2).
Fp3 ReadTriple(const std::vector<Fp3>& cur, uint32_t base, uint32_t lane0)
{
    const PermLayout p{base};
    return Fp3{cur[p.InputCol(lane0)].c0, cur[p.InputCol(lane0 + 1)].c0, cur[p.InputCol(lane0 + 2)].c0};
}

} // namespace (Piece 4 internals)

// ---------------------------------------------------------------------------
// ExtractChildPublicInputs
// ---------------------------------------------------------------------------
ChildPublicInputs ExtractChildPublicInputs(const aq::AirConstraintSystem<Fp3>& child_cs,
                                           const aq::AirQuotientProof<Fp3, AlgB3>& child,
                                           const uint256& child_fs_seed)
{
    ChildPublicInputs pi;
    const auto& b = child.batch;
    pi.child_n_rows = child_cs.n_rows;
    pi.child_w = child_cs.n_columns;
    pi.child_quotient_len = child_cs.QuotientLen();
    pi.child_n_coeffs = b.n_coeffs;
    pi.child_n_lde = b.n_coeffs * kRCFriBlowup;
    pi.merkle_depth = Log2ExactR(pi.child_n_lde);
    pi.n_folds = Log2ExactR(b.n_coeffs);
    auto unpack = [](const uint256& u) -> Digest {
        auto d = Fri3AlgDigestFromUint256(u);
        return d ? *d : Digest{};
    };
    pi.row_commit_root = b.row_commit.root;
    pi.rt_root = unpack(child.trace_commit);
    for (uint32_t l = 0; l < pi.n_folds; ++l) pi.fold_roots.push_back(b.fold_layers[l].root);
    pi.fri_lambda = b.lambda;
    pi.z1 = b.z1; pi.z2 = b.z2; pi.w1 = b.w1; pi.w2 = b.w2;
    pi.final_value = b.final_value;
    pi.fold_challenges = b.fold_challenges;
    pi.column_len = b.column_len;
    pi.evals_z1 = b.evals_z1;
    pi.evals_z2 = b.evals_z2;
    for (const auto& q : b.queries) pi.query_index.push_back(q.index);
    // AIR-level lambda (airq_lambda) — recompute from R_T (row-wise: 1 root).
    {
        std::vector<uint256> roots{child.trace_commit};
        const uint256 d = aq::AirChallengeDigest(child_fs_seed, "airq_lambda", roots,
                                                 {pi.child_n_rows, pi.child_quotient_len, pi.child_w});
        pi.air_lambda = gf::FromChallengeBytes3(d.data());
    }
    pi.child_constraints = child_cs.constraints;
    pi.ok = true;
    return pi;
}

// ---------------------------------------------------------------------------
// BuildVerifierAIRPinned
// ---------------------------------------------------------------------------
aq::AirConstraintSystem<Fp3> BuildVerifierAIRPinned(uint32_t k,
                                                    const std::vector<ChildPublicInputs>& pis,
                                                    const VerifierAirFamilies& fam)
{
    aq::AirConstraintSystem<Fp3> cs;
    const VcsLayout L = ComputeLayout(k, pis, fam);
    const uint32_t Q = L.queries;
    const uint32_t N = FriNextPow2(std::max<uint32_t>(2, Q));
    cs.n_rows = N;
    cs.n_columns = L.n_cols;
    cs.preprocessed_pin_ood = true;

    const Fp3 node_domain = Fp3::FromFp(ah::GetAlgHashConstants().node_domain);
    const Fp3 leaf_domain = Fp3::FromFp(ah::GetAlgHashConstants().leaf_domain);
    const Fp3 g = Fp3::FromFp(aq::kAirCosetShift);

    for (uint32_t ci = 0; ci < k; ++ci) {
        const ChildLayout& c = L.children[ci];
        const ChildPublicInputs& pi = pis[ci];
        auto& K = cs.constraints;

        // ---- (B) ROW-OPENING MERKLE ----
        if (fam.row_merkle) {
            // Row-leaf block: SpongeHashFp over [values(3(W+1)), idx, pad1, 0..].
            EmitPermSbox(K, c.row_leaf);
            const uint32_t nabs = 3 * (c.W + 1); // absorbed value lanes
            // (values in_0..nabs-1 are FREE — the opened row values.)
            EmitInputEqCol(K, c.row_leaf, nabs, c.pre.idx_fp);       // in_nabs = index
            EmitInputConst(K, c.row_leaf, nabs + 1, Fp3::One());     // pad 1
            for (uint32_t l = nabs + 2; l < kAlgHashT; ++l)
                EmitInputConst(K, c.row_leaf, l, Fp3::Zero());       // rest 0 (rate pad + capacity)
            // Compress chain.
            uint32_t prev = c.row_leaf;
            for (uint32_t j = 0; j < c.D; ++j) {
                EmitPermSbox(K, c.row_comp[j]);
                EmitCompressWiring(K, c.row_comp[j], prev, c.row_sib[j], c.pre.row_dir[j], node_domain);
                prev = c.row_comp[j];
            }
            EmitRootPin(K, prev, pi.row_commit_root);
        }

        // ---- (B/C/E) FOLD ----
        if (fam.fold) {
            for (uint32_t l = 0; l < c.nf; ++l) {
                const FoldCols& f = c.folds[l];
                const auto& fp = c.pre.folds[l];
                const Digest& froot = pi.fold_roots[l];
                // even leaf: LeafHash(even, even_index): in0..2=even, in3=idx, in4=Le, rest 0.
                EmitPermSbox(K, f.even_leaf);
                EmitInputEqCol(K, f.even_leaf, 3, fp.even_leaf_idx);
                EmitInputConst(K, f.even_leaf, 4, leaf_domain);
                for (uint32_t la = 5; la < kAlgHashT; ++la) EmitInputConst(K, f.even_leaf, la, Fp3::Zero());
                uint32_t prev = f.even_leaf;
                for (uint32_t j = 0; j < f.depth; ++j) {
                    EmitPermSbox(K, f.even_comp[j]);
                    EmitCompressWiring(K, f.even_comp[j], prev, f.even_sib[j], fp.even_dir[j], node_domain);
                    prev = f.even_comp[j];
                }
                EmitRootPin(K, prev, froot);
                // odd leaf + path.
                EmitPermSbox(K, f.odd_leaf);
                EmitInputEqCol(K, f.odd_leaf, 3, fp.odd_leaf_idx);
                EmitInputConst(K, f.odd_leaf, 4, leaf_domain);
                for (uint32_t la = 5; la < kAlgHashT; ++la) EmitInputConst(K, f.odd_leaf, la, Fp3::Zero());
                prev = f.odd_leaf;
                for (uint32_t j = 0; j < f.depth; ++j) {
                    EmitPermSbox(K, f.odd_comp[j]);
                    EmitCompressWiring(K, f.odd_comp[j], prev, f.odd_sib[j], fp.odd_dir[j], node_domain);
                    prev = f.odd_comp[j];
                }
                EmitRootPin(K, prev, froot);
                // (C) fold relation: 2*x*folded = x*(even+odd) + beta*(even-odd).
                {
                    const Fp3 beta = pi.fold_challenges[l];
                    const uint32_t even_leaf = f.even_leaf, odd_leaf = f.odd_leaf, xcol = fp.x, foldc = f.folded_col;
                    AirConstraint<Fp3> con;
                    con.name = "vcs.fold.relation"; con.kind = AirKind::kEverywhere; con.alg_degree = 2;
                    con.eval = [even_leaf, odd_leaf, xcol, foldc, beta](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
                        const Fp3 ev = ReadTriple(cur, even_leaf, 0);
                        const Fp3 od = ReadTriple(cur, odd_leaf, 0);
                        const Fp3 x = cur[xcol];
                        const Fp3 folded = cur[foldc];
                        const Fp3 lhs = gf::Mul(gf::Mul(Fp3::FromFp(2), x), folded);
                        const Fp3 rhs = gf::Add(gf::Mul(x, gf::Add(ev, od)), gf::Mul(beta, gf::Sub(ev, od)));
                        return gf::Sub(lhs, rhs);
                    };
                    K.push_back(std::move(con));
                }
            }
        }

        // ---- (E) DEEP dual-OOD + fold-path leaf consistency ----
        // (D) per-point identity C(y) = Q(y)*Z_H(y).
        if (fam.deep || fam.per_point) {
            // shared: v1, v2 (global consts from evals).
            std::vector<Fp3> lam_pow(pi.child_w + 1);
            lam_pow[0] = Fp3::One();
            for (uint32_t i = 1; i <= pi.child_w; ++i) lam_pow[i] = gf::Mul(lam_pow[i - 1], pi.fri_lambda);
            Fp3 v1 = Fp3::Zero(), v2 = Fp3::Zero();
            for (uint32_t i = 0; i <= pi.child_w; ++i) {
                const uint32_t shift = pi.child_n_coeffs - pi.column_len[i];
                v1 = gf::Add(v1, gf::Mul(gf::Mul(lam_pow[i], Pow3R(pi.z1, shift)), pi.evals_z1[i]));
                v2 = gf::Add(v2, gf::Mul(gf::Mul(lam_pow[i], Pow3R(pi.z2, shift)), pi.evals_z2[i]));
            }
            const uint32_t rl = c.row_leaf, W = c.W;
            const std::vector<uint32_t> xpow = c.pre.xpow;
            // U_x closure (reads row-leaf value lanes + xpow preprocessed).
            auto eval_Ux = [rl, W, xpow, lam_pow](const std::vector<Fp3>& cur) {
                Fp3 U = Fp3::Zero();
                for (uint32_t i = 0; i <= W; ++i) {
                    const Fp3 val = ReadTriple(cur, rl, 3 * i);
                    U = gf::Add(U, gf::Mul(gf::Mul(lam_pow[i], cur[xpow[i]]), val));
                }
                return U;
            };
            if (fam.deep && fam.fold && c.nf > 0) {
                // g_expect = w1*(U-v1)*invd1 + w2*(U-v2)*invd2, checked == leaf_here(L=0).
                const FoldCols& f0 = c.folds[0];
                const auto& fp0 = c.pre.folds[0];
                const Fp3 w1 = pi.w1, w2 = pi.w2;
                const uint32_t invd1 = c.pre.invd1, invd2 = c.pre.invd2;
                const uint32_t even_leaf = f0.even_leaf, odd_leaf = f0.odd_leaf, leaf_sel = fp0.leaf_sel;
                AirConstraint<Fp3> con;
                con.name = "vcs.deep.identity"; con.kind = AirKind::kEverywhere; con.alg_degree = 2;
                con.eval = [eval_Ux, v1, v2, w1, w2, invd1, invd2, even_leaf, odd_leaf, leaf_sel](
                               const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
                    const Fp3 U = eval_Ux(cur);
                    const Fp3 g_expect = gf::Add(gf::Mul(w1, gf::Mul(gf::Sub(U, v1), cur[invd1])),
                                                 gf::Mul(w2, gf::Mul(gf::Sub(U, v2), cur[invd2])));
                    const Fp3 ev = ReadTriple(cur, even_leaf, 0);
                    const Fp3 od = ReadTriple(cur, odd_leaf, 0);
                    const Fp3 leaf_here = gf::Add(gf::Mul(cur[leaf_sel], ev),
                                                  gf::Mul(gf::Sub(Fp3::One(), cur[leaf_sel]), od));
                    return gf::Sub(leaf_here, g_expect);
                };
                K.push_back(std::move(con));
                // final: folded(last) == final_value  (nf-layer chaining terminal).
                const uint32_t foldc = c.folds[c.nf - 1].folded_col;
                const Fp3 fv = pi.final_value;
                AirConstraint<Fp3> con2;
                con2.name = "vcs.deep.final"; con2.kind = AirKind::kEverywhere; con2.alg_degree = 1;
                con2.eval = [foldc, fv](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
                    return gf::Sub(cur[foldc], fv);
                };
                K.push_back(std::move(con2));
                // intermediate chaining folded_{l-1} == leaf_here_l (l>0).
                for (uint32_t l = 1; l < c.nf; ++l) {
                    const uint32_t prev_fold = c.folds[l - 1].folded_col;
                    const uint32_t even_leaf_l = c.folds[l].even_leaf, odd_leaf_l = c.folds[l].odd_leaf;
                    const uint32_t leaf_sel_l = c.pre.folds[l].leaf_sel;
                    AirConstraint<Fp3> con3;
                    con3.name = "vcs.deep.chain"; con3.kind = AirKind::kEverywhere; con3.alg_degree = 2;
                    con3.eval = [prev_fold, even_leaf_l, odd_leaf_l, leaf_sel_l](
                                    const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
                        const Fp3 ev = ReadTriple(cur, even_leaf_l, 0);
                        const Fp3 od = ReadTriple(cur, odd_leaf_l, 0);
                        const Fp3 leaf_here = gf::Add(gf::Mul(cur[leaf_sel_l], ev),
                                                      gf::Mul(gf::Sub(Fp3::One(), cur[leaf_sel_l]), od));
                        return gf::Sub(cur[prev_fold], leaf_here);
                    };
                    K.push_back(std::move(con3));
                }
            }
            if (fam.per_point) {
                // C(y) = Σ_i air_lambda^i * R_i(cur_child) ; qv = row.values[W].
                // (kEverywhere child constraints only -> sel_i = 1.)
                const Fp3 air_lambda = pi.air_lambda;
                std::vector<aq::AirConstraint<Fp3>> child_cons = pi.child_constraints;
                const uint32_t zh = c.pre.zh;
                AirConstraint<Fp3> con;
                con.name = "vcs.perpoint"; con.kind = AirKind::kEverywhere;
                uint32_t md = 1;
                for (const auto& cc : child_cons) md = std::max(md, cc.alg_degree);
                con.alg_degree = md;
                con.eval = [rl, W, zh, air_lambda, child_cons](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
                    std::vector<Fp3> cur_child(W);
                    for (uint32_t i = 0; i < W; ++i) cur_child[i] = ReadTriple(cur, rl, 3 * i);
                    const Fp3 qv = ReadTriple(cur, rl, 3 * W);
                    Fp3 C = Fp3::Zero(), lp = Fp3::One();
                    for (const auto& cc : child_cons) {
                        C = gf::Add(C, gf::Mul(lp, cc.eval(cur_child, cur_child)));
                        lp = gf::Mul(lp, air_lambda);
                    }
                    return gf::Sub(C, gf::Mul(qv, cur[zh]));
                };
                K.push_back(std::move(con));
            }
        }
    }

    // ---- preprocessed column canonical values (per query, padded) ----
    auto add_pre = [&](uint32_t col, const std::function<Fp3(uint32_t qi)>& f) {
        std::vector<Fp3> vals(N);
        for (uint32_t r = 0; r < N; ++r) {
            const uint32_t qi = (r < Q) ? r : (Q - 1);
            vals[r] = f(qi);
        }
        cs.preprocessed.emplace_back(col, std::move(vals));
    };
    for (uint32_t ci = 0; ci < k; ++ci) {
        const ChildLayout& c = L.children[ci];
        const ChildPublicInputs& pi = pis[ci];
        const uint32_t n_lde = pi.child_n_lde;
        add_pre(c.pre.idx_fp, [&](uint32_t qi) { return Fp3::FromFp(gf::FromU64(pi.query_index[qi])); });
        if (fam.row_merkle)
            for (uint32_t j = 0; j < c.D; ++j)
                add_pre(c.pre.row_dir[j], [&pi, j](uint32_t qi) {
                    return Fp3::FromFp(gf::FromU64((pi.query_index[qi] >> j) & 1u));
                });
        if (fam.fold) {
            for (uint32_t l = 0; l < c.nf; ++l) {
                const auto& fp = c.pre.folds[l];
                const uint32_t nleaves = n_lde >> l;
                const uint32_t half = nleaves / 2;
                // idx reduction through layers 0..l-1 (native: idx = idx % half_t).
                auto reduced = [&pi, l](uint32_t qi) {
                    uint32_t idx = pi.query_index[qi];
                    for (uint32_t t = 0; t < l; ++t) { const uint32_t h = (pi.child_n_lde >> t) / 2; idx = idx % h; }
                    return idx;
                };
                const uint32_t depth = c.D - l;
                add_pre(fp.even_leaf_idx, [reduced, half](uint32_t qi) {
                    return Fp3::FromFp(gf::FromU64(reduced(qi) % half));
                });
                add_pre(fp.odd_leaf_idx, [reduced, half](uint32_t qi) {
                    return Fp3::FromFp(gf::FromU64(reduced(qi) % half + half));
                });
                for (uint32_t j = 0; j < depth; ++j)
                    add_pre(fp.even_dir[j], [reduced, half, j](uint32_t qi) {
                        return Fp3::FromFp(gf::FromU64(((reduced(qi) % half) >> j) & 1u));
                    });
                for (uint32_t j = 0; j < depth; ++j)
                    add_pre(fp.odd_dir[j], [reduced, half, j](uint32_t qi) {
                        return Fp3::FromFp(gf::FromU64((((reduced(qi) % half) + half) >> j) & 1u));
                    });
                add_pre(fp.x, [reduced, half, nleaves](uint32_t qi) {
                    return DomainPointR(nleaves, reduced(qi) % half);
                });
                add_pre(fp.leaf_sel, [reduced, half](uint32_t qi) {
                    return Fp3::FromFp(gf::FromU64((reduced(qi) < half) ? 1u : 0u));
                });
            }
        }
        if (fam.deep) {
            for (uint32_t i = 0; i <= c.W; ++i) {
                const uint32_t shift = pi.child_n_coeffs - pi.column_len[i];
                add_pre(c.pre.xpow[i], [&pi, n_lde, shift](uint32_t qi) {
                    return Pow3R(DomainPointR(n_lde, pi.query_index[qi]), shift);
                });
            }
            add_pre(c.pre.invd1, [&pi, n_lde](uint32_t qi) {
                const Fp3 x = DomainPointR(n_lde, pi.query_index[qi]);
                return gf::Inv(gf::Sub(x, pi.z1));
            });
            add_pre(c.pre.invd2, [&pi, n_lde](uint32_t qi) {
                const Fp3 x = DomainPointR(n_lde, pi.query_index[qi]);
                return gf::Inv(gf::Sub(x, pi.z2));
            });
        }
        if (fam.per_point) {
            add_pre(c.pre.zh, [&pi, n_lde, g](uint32_t qi) {
                const Fp3 x = DomainPointR(n_lde, pi.query_index[qi]);
                const Fp3 y = gf::Mul(g, x);
                return gf::Sub(Pow3R(y, pi.child_n_rows), Fp3::One());
            });
        }
    }
    return cs;
}

aq::AirConstraintSystem<Fp3> BuildVerifierAIR(uint32_t k, const ChildPublicInputs& shape,
                                              const VerifierAirFamilies& fam)
{
    std::vector<ChildPublicInputs> shapes(k, shape);
    return BuildVerifierAIRPinned(k, shapes, fam);
}

VerifierAirMeasurement MeasureVerifierAIR(uint32_t k, const std::vector<ChildPublicInputs>& pis,
                                          const VerifierAirFamilies& fam)
{
    const aq::AirConstraintSystem<Fp3> cs = BuildVerifierAIRPinned(k, pis, fam);
    const VcsLayout L = ComputeLayout(k, pis, fam);
    VerifierAirMeasurement m;
    m.k = k;
    m.n_rows = cs.n_rows;
    m.n_columns = cs.n_columns;
    m.n_constraints = static_cast<uint32_t>(cs.constraints.size());
    for (const auto& con : cs.constraints) m.max_alg_degree = std::max(m.max_alg_degree, con.alg_degree);
    m.quotient_len = cs.QuotientLen();
    m.cell_count = static_cast<uint64_t>(cs.n_columns) * cs.n_rows;
    m.queries = L.queries;
    m.perms_per_query = L.children.empty() ? 0 : L.children[0].perms;
    return m;
}

namespace {

// Write one honest perm block (BuildPermWitness) at `base` into `row`.
void WriteBlock(std::vector<Fp3>& row, uint32_t base, const ah::State& in)
{
    WritePermWitness(PermLayout{base}, BuildPermWitness(in), row);
}
Digest BlockDigest(const ah::State& in)
{
    const PermWitness w = BuildPermWitness(in);
    return Digest{w.output[0], w.output[1], w.output[2], w.output[3]};
}
ah::State CompressState(const Digest& acc, const Digest& sib, bool bit, Fp node_domain)
{
    const Digest& left = bit ? sib : acc;
    const Digest& right = bit ? acc : sib;
    ah::State s{};
    for (uint32_t i = 0; i < kAlgHashDigestLen; ++i) {
        s[i] = gf::Canonical(left[i]);
        s[kAlgHashDigestLen + i] = gf::Canonical(right[i]);
    }
    s[2 * kAlgHashDigestLen] = node_domain;
    return s;
}
void SetDigestCols(std::vector<Fp3>& row, uint32_t base, const Digest& d)
{
    for (uint32_t j = 0; j < kAlgHashDigestLen; ++j) row[base + j] = Fp3::FromFp(gf::Canonical(d[j]));
}

// Honestly fill one child's per-query columns for row `r` (query qi).
void FillChildRow(std::vector<Fp3>& row, const ChildLayout& c, const ChildPublicInputs& pi,
                  const aq::AirQuotientProof<Fp3, AlgB3>& child, uint32_t qi,
                  const VerifierAirFamilies& fam)
{
    const Fp node_domain = ah::GetAlgHashConstants().node_domain;
    const Fp leaf_domain = ah::GetAlgHashConstants().leaf_domain;
    const auto& q = child.batch.queries[qi];

    if (fam.row_merkle) {
        // Row-leaf sponge state (single block; W+1 small).
        ah::State s{};
        uint32_t lane = 0;
        for (uint32_t i = 0; i <= c.W; ++i) {
            s[lane++] = gf::Canonical(q.row.values[i].c0);
            s[lane++] = gf::Canonical(q.row.values[i].c1);
            s[lane++] = gf::Canonical(q.row.values[i].c2);
        }
        s[lane++] = gf::FromU64(q.index); // idx
        s[lane++] = 1;                     // pad 1  (remaining rate + capacity stay 0)
        WriteBlock(row, c.row_leaf, s);
        Digest acc = BlockDigest(s);
        for (uint32_t j = 0; j < c.D; ++j) {
            const bool bit = ((q.index >> j) & 1u) != 0;
            SetDigestCols(row, c.row_sib[j], q.row.siblings[j]);
            const ah::State cs = CompressState(acc, q.row.siblings[j], bit, node_domain);
            WriteBlock(row, c.row_comp[j], cs);
            acc = BlockDigest(cs);
        }
    }
    if (fam.fold) {
        for (uint32_t l = 0; l < c.nf; ++l) {
            const FoldCols& f = c.folds[l];
            const auto& step = q.steps[l];
            const uint32_t nleaves = pi.child_n_lde >> l;
            // even leaf
            {
                ah::State s{};
                s[0] = gf::Canonical(step.even.c0); s[1] = gf::Canonical(step.even.c1);
                s[2] = gf::Canonical(step.even.c2); s[3] = gf::FromU64(step.even_index);
                s[4] = leaf_domain;
                WriteBlock(row, f.even_leaf, s);
                Digest acc = BlockDigest(s);
                for (uint32_t j = 0; j < f.depth; ++j) {
                    const bool bit = ((step.even_index >> j) & 1u) != 0;
                    SetDigestCols(row, f.even_sib[j], step.even_siblings[j]);
                    const ah::State cs = CompressState(acc, step.even_siblings[j], bit, node_domain);
                    WriteBlock(row, f.even_comp[j], cs);
                    acc = BlockDigest(cs);
                }
            }
            // odd leaf
            {
                ah::State s{};
                s[0] = gf::Canonical(step.odd.c0); s[1] = gf::Canonical(step.odd.c1);
                s[2] = gf::Canonical(step.odd.c2); s[3] = gf::FromU64(step.odd_index);
                s[4] = leaf_domain;
                WriteBlock(row, f.odd_leaf, s);
                Digest acc = BlockDigest(s);
                for (uint32_t j = 0; j < f.depth; ++j) {
                    const bool bit = ((step.odd_index >> j) & 1u) != 0;
                    SetDigestCols(row, f.odd_sib[j], step.odd_siblings[j]);
                    const ah::State cs = CompressState(acc, step.odd_siblings[j], bit, node_domain);
                    WriteBlock(row, f.odd_comp[j], cs);
                    acc = BlockDigest(cs);
                }
            }
            // folded value (HalfDomainFoldPair) — witnessed for the (C) relation.
            if (fam.deep) {
                const Fp3 x = DomainPointR(nleaves, step.even_index);
                const Fp3 beta = pi.fold_challenges[l];
                const Fp3 inv2 = gf::Inv(Fp3::FromFp(2));
                const Fp3 even = gf::Mul(gf::Add(step.even, step.odd), inv2);
                const Fp3 odd = gf::Mul(gf::Sub(step.even, step.odd), gf::Mul(inv2, gf::Inv(x)));
                row[f.folded_col] = gf::Add(even, gf::Mul(beta, odd));
            }
        }
    }
}

} // namespace (Piece 4 witness)

AggregateWitness BuildAggregateWitness(const aq::AirConstraintSystem<Fp3>& child_cs,
                                       const std::vector<aq::AirQuotientProof<Fp3, AlgB3>>& children,
                                       const uint256& child_fs_seed, const VerifierAirFamilies& fam)
{
    AggregateWitness out;
    const uint32_t k = static_cast<uint32_t>(children.size());
    if (k == 0) { out.note = "no children"; return out; }
    out.pis.resize(k);
    for (uint32_t ci = 0; ci < k; ++ci)
        out.pis[ci] = ExtractChildPublicInputs(child_cs, children[ci], child_fs_seed);
    for (const auto& pi : out.pis) {
        if (3 * (pi.child_w + 1) + 1 > alg_hash::kAlgHashRate) {
            out.note = "child W too large: row-leaf sponge needs multiple blocks (not arithmetized)";
            return out;
        }
    }
    out.cs = BuildVerifierAIRPinned(k, out.pis, fam);
    const VcsLayout L = ComputeLayout(k, out.pis, fam);
    out.n_witness_cols = L.n_witness_cols;
    const uint32_t N = out.cs.n_rows, Q = L.queries;

    out.columns.assign(out.cs.n_columns, std::vector<Fp3>(N, Fp3::Zero()));
    for (const auto& [col, vals] : out.cs.preprocessed)
        for (uint32_t r = 0; r < N; ++r) out.columns[col][r] = vals[r];
    std::vector<Fp3> row(out.cs.n_columns, Fp3::Zero());
    for (uint32_t r = 0; r < N; ++r) {
        const uint32_t qi = (r < Q) ? r : (Q - 1);
        std::fill(row.begin(), row.begin() + L.n_witness_cols, Fp3::Zero());
        for (uint32_t ci = 0; ci < k; ++ci)
            FillChildRow(row, L.children[ci], out.pis[ci], children[ci], qi, fam);
        for (uint32_t col = 0; col < L.n_witness_cols; ++col) out.columns[col][r] = row[col];
    }
    out.ok = true;
    return out;
}

uint32_t CountWitnessViolationsOnH(const aq::AirConstraintSystem<Fp3>& cs,
                                   const std::vector<std::vector<Fp3>>& columns,
                                   uint32_t* first_row, std::string* first_name)
{
    const uint32_t N = cs.n_rows, W = cs.n_columns;
    std::vector<Fp3> cur(W), nxt(W);
    uint32_t bad = 0;
    for (uint32_t r = 0; r < N; ++r) {
        for (uint32_t c = 0; c < W; ++c) { cur[c] = columns[c][r]; nxt[c] = columns[c][(r + 1) % N]; }
        for (const auto& con : cs.constraints) {
            bool applies = true;
            if (con.kind == aq::AirKind::kTransition) applies = (r + 1 < N);
            else if (con.kind == aq::AirKind::kFirstRow) applies = (r == 0);
            else if (con.kind == aq::AirKind::kLastRow) applies = (r + 1 == N);
            if (!applies) continue;
            if (!gf::IsZero(con.eval(cur, nxt))) {
                if (bad == 0) {
                    if (first_row) *first_row = r;
                    if (first_name) *first_name = con.name ? con.name : "";
                }
                ++bad;
            }
        }
    }
    return bad;
}

AggregateResult ProveAggregate(const aq::AirConstraintSystem<Fp3>& child_cs,
                               const std::vector<aq::AirQuotientProof<Fp3, AlgB3>>& children,
                               const uint256& child_fs_seed, const uint256& fs_seed,
                               const VerifierAirFamilies& fam)
{
    AggregateResult out;
    out.fs_seed = fs_seed;
    AggregateWitness w = BuildAggregateWitness(child_cs, children, child_fs_seed, fam);
    if (!w.ok) { out.note = w.note; return out; }
    out.pis = w.pis;
    out.measurement = MeasureVerifierAIR(static_cast<uint32_t>(children.size()), w.pis, fam);

    aq::AirProveOptions opt;
    opt.force_commit_on_inexact = true; // commit even if inexact -> Verify must reject
    aq::AirQuotientProveResult<Fp3, AlgB3> pr =
        aq::AirQuotientProve<Fp3, AlgB3>(w.cs, w.columns, fs_seed, opt);
    out.witness_satisfies = pr.division_exact;
    out.proof = pr.proof;
    out.ok = pr.ok;
    out.note = pr.note;
    return out;
}

bool VerifyAggregate(const aq::AirQuotientProof<Fp3, AlgB3>& root,
                     const std::vector<ChildPublicInputs>& pis, const uint256& fs_seed, uint32_t k,
                     const VerifierAirFamilies& fam, std::string* why)
{
    const aq::AirConstraintSystem<Fp3> cs = BuildVerifierAIRPinned(k, pis, fam);
    return aq::AirQuotientVerify<Fp3, AlgB3>(cs, root, fs_seed, why);
}

bool VerifyEpisodeAggregate(const EpisodeAggregateProof& agg, const uint256& episode_seed,
                            std::string* why)
{
    auto fail = [&](const std::string& m) {
        if (why) *why = "v7c:agg:" + m;
        return false;
    };
    if (agg.k == 0) return fail("k_zero");
    if (agg.pis.size() != agg.k) return fail("pins_arity_mismatch");
    // FS-bind the aggregate to THIS episode: verify under the episode seed, not
    // a seed carried in the proof — a root built for another episode fails the
    // λ / challenge re-derivation inside VerifyAggregate.
    std::string w;
    if (!VerifyAggregate(agg.root, agg.pis, episode_seed, agg.k, agg.families, &w)) {
        return fail(w);
    }
    return true;
}

} // namespace matmul::v4::rc::air_recurse
