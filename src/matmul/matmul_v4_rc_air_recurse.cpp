// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_air_recurse.h>

#include <cassert>
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

} // namespace matmul::v4::rc::air_recurse
