// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_air_recurse.h>

#include <matmul/matmul_v4_rc_fri.h> // FriNextPow2
#include <hash.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstring>
#include <functional>
#include <limits>
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
using ah::kAlgHashRate;

// Number of sponge blocks the row leaf occupies. LeafHashRow feeds
// ah::SpongeHashFp a stream of L = 3*(W+1)+1 field elements (each of the W+1
// opened row values flattened as (c0,c1,c2), then the query index). The 10*-
// padding ALWAYS appends a 1 and then 0s up to a multiple of the rate R=8 (a
// FULL extra block when L is already rate-aligned), so the block count is
// n_blocks = L/8 + 1 uniformly (floor division: the always-appended 1 forces at
// least one padding element, i.e. one more block than floor(L/8)). Mirrors
// SpongeHashFp exactly; W in {1,2,7,26} -> {1,2,4,11} blocks.
[[nodiscard]] uint32_t RowLeafNBlocks(uint32_t W)
{
    const uint32_t L = 3 * (W + 1) + 1;
    return L / kAlgHashRate + 1;
}

/** Generic row-leaf block count for exactly `n_values` Fp3 values plus the
 *  row index. RowLeafNBlocks(W) is the batch-row specialization n_values=W+1. */
[[nodiscard]] uint32_t RowLeafNBlocksForValues(uint32_t n_values)
{
    const uint32_t L = 3 * n_values + 1;
    return L / kAlgHashRate + 1;
}

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
    uint32_t next_idx_fp{0};           // Fp(query index + omega_H step)
    std::vector<uint32_t> next_dir;    // D dir bits for supplemental next row
    std::vector<uint32_t> trace_dir;   // D dir bits for R_T cross-opening
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
    uint32_t transition_selector{0};   // y - h_last
    uint32_t first_selector{0};        // Z_H(y)/(y - 1)
    uint32_t last_selector{0};         // Z_H(y)/(y - h_last)
};

struct ChildLayout {
    uint32_t base{0};                  // first WITNESS column of this child block
    uint32_t W{0}, D{0}, nf{0};
    // row path (witness)
    std::vector<uint32_t> row_leaf_blocks; // n_blocks sponge perm strips (multi-block LeafHashRow)
    uint32_t row_leaf{0};              // = row_leaf_blocks[0] (block holding the first value lanes)
    std::vector<uint32_t> row_comp;    // D
    std::vector<uint32_t> row_sib;     // D (4 cols each)
    // Supplemental next-row opening against row_commit_root.
    std::vector<uint32_t> next_leaf_blocks;
    std::vector<uint32_t> next_comp;   // D
    std::vector<uint32_t> next_sib;    // D (4 cols each)
    // Current trace-only row cross-opening against rt_root.
    std::vector<uint32_t> trace_leaf_blocks;
    std::vector<uint32_t> trace_comp;  // D
    std::vector<uint32_t> trace_sib;   // D (4 cols each)
    std::vector<FoldCols> folds;
    // Public evaluation claims materialized as witness columns and consumed
    // directly by vcs.deep.identity. One Fp3 witness column per claim.
    std::vector<uint32_t> evals_z1;
    std::vector<uint32_t> evals_z2;
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
        const uint32_t nb = RowLeafNBlocks(c.W); // multi-block LeafHashRow sponge
        for (uint32_t b = 0; b < nb; ++b) c.row_leaf_blocks.push_back(perm_block());
        c.row_leaf = c.row_leaf_blocks[0];
        for (uint32_t j = 0; j < c.D; ++j) c.row_comp.push_back(perm_block());
        for (uint32_t j = 0; j < c.D; ++j) c.row_sib.push_back(dig4());
    }
    if (fam.next_row) {
        const uint32_t nb = RowLeafNBlocksForValues(c.W + 1);
        for (uint32_t b = 0; b < nb; ++b)
            c.next_leaf_blocks.push_back(perm_block());
        for (uint32_t j = 0; j < c.D; ++j)
            c.next_comp.push_back(perm_block());
        for (uint32_t j = 0; j < c.D; ++j)
            c.next_sib.push_back(dig4());
    }
    if (fam.trace_binding) {
        const uint32_t nb = RowLeafNBlocksForValues(c.W);
        for (uint32_t b = 0; b < nb; ++b)
            c.trace_leaf_blocks.push_back(perm_block());
        for (uint32_t j = 0; j < c.D; ++j)
            c.trace_comp.push_back(perm_block());
        for (uint32_t j = 0; j < c.D; ++j)
            c.trace_sib.push_back(dig4());
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
    if (fam.deep) {
        for (uint32_t i = 0; i <= c.W; ++i)
            c.evals_z1.push_back(col++);
        for (uint32_t i = 0; i <= c.W; ++i)
            c.evals_z2.push_back(col++);
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
    if (fam.next_row) {
        c.pre.next_idx_fp = one();
        for (uint32_t j = 0; j < c.D; ++j)
            c.pre.next_dir.push_back(one());
    }
    if (fam.trace_binding) {
        for (uint32_t j = 0; j < c.D; ++j)
            c.pre.trace_dir.push_back(one());
    }
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
    if (fam.per_point) {
        c.pre.zh = one();
        c.pre.transition_selector = one();
        c.pre.first_selector = one();
        c.pre.last_selector = one();
    }
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

// ---- multi-block row-leaf sponge (LeafHashRow / SpongeHashFp) ----------------
// The row leaf absorbs L = 3*(W+1)+1 field elements across n_blocks sponge
// blocks (RowLeafNBlocks). Block b add-absorbs stream position p = 8b+j onto the
// carried rate lane j of the previous block's OUTPUT (0 for block 0); the
// capacity lanes [8,12) carry the previous block's output capacity (0 for block
// 0). This mirrors ah::SpongeHashFp exactly. The absorbed value coords are FREE
// opened row values (input lane = carry + value, value unpinned — the perm S-box
// identities + the Merkle root pin bind them through the digest); only the
// appended index / pad-1 / pad-0 and the capacity carries are pinned.

// input(block,lane) = carry(lane) + val, carry = prev block output lane (0 if b==0).
void EmitAbsorbConst(std::vector<AirConstraint<Fp3>>& out, uint32_t block_base, bool has_prev,
                     uint32_t prev_base, uint32_t lane, Fp3 val)
{
    if (!has_prev) { EmitInputConst(out, block_base, lane, val); return; }
    AirConstraint<Fp3> c;
    c.name = "vcs.sponge.absorb.const"; c.kind = AirKind::kEverywhere; c.alg_degree = 1;
    const uint32_t col = PermLayout{block_base}.InputCol(lane);
    const PermLayout prev{prev_base};
    c.eval = [col, prev, lane, val](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
        return gf::Sub(cur[col], gf::Add(PermOutputLane(prev, cur, lane), val));
    };
    out.push_back(std::move(c));
}
// input(block,lane) = carry(lane) + cur[src] (src = preprocessed absorbed value col).
void EmitAbsorbCol(std::vector<AirConstraint<Fp3>>& out, uint32_t block_base, bool has_prev,
                   uint32_t prev_base, uint32_t lane, uint32_t src)
{
    if (!has_prev) { EmitInputEqCol(out, block_base, lane, src); return; }
    AirConstraint<Fp3> c;
    c.name = "vcs.sponge.absorb.col"; c.kind = AirKind::kEverywhere; c.alg_degree = 1;
    const uint32_t col = PermLayout{block_base}.InputCol(lane);
    const PermLayout prev{prev_base};
    c.eval = [col, prev, lane, src](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
        return gf::Sub(cur[col], gf::Add(PermOutputLane(prev, cur, lane), cur[src]));
    };
    out.push_back(std::move(c));
}
// capacity carry: input(block,lane) = prev block output lane (0 if b==0).
void EmitCapacityCarry(std::vector<AirConstraint<Fp3>>& out, uint32_t block_base, bool has_prev,
                       uint32_t prev_base, uint32_t lane)
{
    if (!has_prev) { EmitInputConst(out, block_base, lane, Fp3::Zero()); return; }
    AirConstraint<Fp3> c;
    c.name = "vcs.sponge.capacity.carry"; c.kind = AirKind::kEverywhere; c.alg_degree = 1;
    const uint32_t col = PermLayout{block_base}.InputCol(lane);
    const PermLayout prev{prev_base};
    c.eval = [col, prev, lane](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
        return gf::Sub(cur[col], PermOutputLane(prev, cur, lane));
    };
    out.push_back(std::move(c));
}

// Emit the whole multi-block row-leaf sponge. `blocks` are the n_blocks perm
// strips, `idx_col` the preprocessed Fp(row index) column, and `n_values` is
// the exact number of Fp3 values authenticated by this tree.
void EmitRowLeafSponge(std::vector<AirConstraint<Fp3>>& out, const std::vector<uint32_t>& blocks,
                       uint32_t idx_col, uint32_t n_values)
{
    const uint32_t nabs = 3 * n_values; // value coord positions [0, nabs)
    const uint32_t p_idx = nabs;       // appended query index
    const uint32_t p_pad1 = nabs + 1;  // 10*-padding: the appended 1
    const uint32_t nb = static_cast<uint32_t>(blocks.size());
    for (uint32_t b = 0; b < nb; ++b) {
        EmitPermSbox(out, blocks[b]);
        const bool has_prev = (b > 0);
        const uint32_t prev = has_prev ? blocks[b - 1] : 0;
        for (uint32_t j = 0; j < kAlgHashRate; ++j) { // rate lanes: absorb
            const uint32_t p = b * kAlgHashRate + j;
            if (p < nabs) continue; // FREE opened row value coord (unpinned input lane)
            if (p == p_idx) EmitAbsorbCol(out, blocks[b], has_prev, prev, j, idx_col);
            else if (p == p_pad1) EmitAbsorbConst(out, blocks[b], has_prev, prev, j, Fp3::One());
            else EmitAbsorbConst(out, blocks[b], has_prev, prev, j, Fp3::Zero()); // pad 0
        }
        for (uint32_t j = kAlgHashRate; j < kAlgHashT; ++j) // capacity lanes: carry
            EmitCapacityCarry(out, blocks[b], has_prev, prev, j);
    }
}

/** Emit one complete authenticated row opening: row-leaf sponge, D Merkle
 *  compressions, and equality of the terminal digest to `root`. */
void EmitAuthenticatedRowPath(
    std::vector<AirConstraint<Fp3>>& out,
    const std::vector<uint32_t>& leaf_blocks,
    const std::vector<uint32_t>& comp,
    const std::vector<uint32_t>& siblings,
    const std::vector<uint32_t>& directions,
    uint32_t idx_col, uint32_t n_values,
    const Digest& root, Fp3 node_domain)
{
    EmitRowLeafSponge(out, leaf_blocks, idx_col, n_values);
    uint32_t prev = leaf_blocks.back();
    for (uint32_t j = 0; j < comp.size(); ++j) {
        EmitPermSbox(out, comp[j]);
        EmitCompressWiring(out, comp[j], prev, siblings[j],
                           directions[j], node_domain);
        prev = comp[j];
    }
    EmitRootPin(out, prev, root);
}

// Read absorbed coord at stream position p across the multi-block row leaf: for
// block b>0 the raw absorbed coord is (input lane) - (prev block output lane),
// since the sponge add-absorbs onto the carried rate lane.
Fp3 ReadRowLeafCoord(const std::vector<Fp3>& cur, const std::vector<uint32_t>& blocks, uint32_t p)
{
    const uint32_t b = p / kAlgHashRate, j = p % kAlgHashRate;
    const Fp3 in = cur[PermLayout{blocks[b]}.InputCol(j)];
    if (b == 0) return in;
    return gf::Sub(in, PermOutputLane(PermLayout{blocks[b - 1]}, cur, j));
}
// Row value i (Fp3 flattened as coords 3i,3i+1,3i+2) — the multi-block analogue
// of ReadTriple(cur, row_leaf, 3*i). Honest cells are base-field embeddings, so
// the coordinate is the .c0 component (degree 1 in the witness cells).
Fp3 ReadRowLeafValue(const std::vector<Fp3>& cur, const std::vector<uint32_t>& blocks, uint32_t i)
{
    return Fp3{ReadRowLeafCoord(cur, blocks, 3 * i).c0, ReadRowLeafCoord(cur, blocks, 3 * i + 1).c0,
               ReadRowLeafCoord(cur, blocks, 3 * i + 2).c0};
}

/** Equality-link two row-leaf sponges value-by-value. This is the explicit
 *  cross-opening linkage between the batch full-row tree and R_T's
 *  trace-only tree; equality is over Fp3, not merely their terminal hashes. */
void EmitRowValueEquality(
    std::vector<AirConstraint<Fp3>>& out,
    const std::vector<uint32_t>& left,
    const std::vector<uint32_t>& right,
    uint32_t n_values)
{
    for (uint32_t i = 0; i < n_values; ++i) {
        AirConstraint<Fp3> c;
        c.name = "vcs.row.cross_opening.equal";
        c.kind = AirKind::kEverywhere;
        c.alg_degree = 1;
        c.eval = [left, right, i](
                     const std::vector<Fp3>& cur,
                     const std::vector<Fp3>&) {
            return gf::Sub(ReadRowLeafValue(cur, left, i),
                           ReadRowLeafValue(cur, right, i));
        };
        out.push_back(std::move(c));
    }
}

} // namespace (Piece 4 internals)

std::vector<VerifierAirRowRootOutput>
DescribeVerifierAIRRowRootOutputs(
    const std::vector<ChildPublicInputs>& pis,
    const VerifierAirFamilies& fam)
{
    std::vector<VerifierAirRowRootOutput> out;
    if (pis.empty() || !fam.row_merkle) return out;
    const VcsLayout layout = ComputeLayout(
        static_cast<uint32_t>(pis.size()), pis, fam);
    out.reserve(pis.size() * kAlgHashDigestLen);
    for (uint32_t child = 0;
         child < layout.children.size(); ++child) {
        const ChildLayout& c = layout.children[child];
        if (c.row_leaf_blocks.empty()) return {};
        const uint32_t terminal =
            c.row_comp.empty()
                ? c.row_leaf_blocks.back()
                : c.row_comp.back();
        for (uint32_t limb = 0;
             limb < kAlgHashDigestLen; ++limb) {
            out.push_back({child, limb, terminal});
        }
    }
    return out;
}

Fp3 EvaluateVerifierAIRRowRootOutput(
    const VerifierAirRowRootOutput& output,
    const std::vector<Fp3>& row)
{
    if (output.digest_limb >= kAlgHashDigestLen ||
        output.terminal_permutation_base >
            row.size() ||
        row.size() - output.terminal_permutation_base <
            kPermCellsPerPerm) {
        return Fp3::Zero();
    }
    return PermOutputLane(
        PermLayout{output.terminal_permutation_base},
        row, output.digest_limb);
}

aq::AirConstraint<Fp3>
BuildVerifierAIRRowRootExportConstraint(
    const VerifierAirRowRootOutput& output,
    uint32_t export_column,
    uint32_t selector_column)
{
    aq::AirConstraint<Fp3> constraint;
    constraint.name =
        "vcs.export.row_root_terminal.selected_alias";
    constraint.kind = aq::AirKind::kEverywhere;
    constraint.alg_degree = 2;
    constraint.eval =
        [output, export_column, selector_column](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            if (export_column >= cur.size() ||
                selector_column >= cur.size()) {
                return Fp3::One();
            }
            return gf::Mul(
                cur[selector_column],
                gf::Sub(
                    cur[export_column],
                    EvaluateVerifierAIRRowRootOutput(
                        output, cur)));
        };
    return constraint;
}

std::vector<VerifierAirTranscriptOutput>
DescribeVerifierAIRFullTranscriptOutputs(
    const std::vector<ChildPublicInputs>& pis,
    const VerifierAirFamilies& fam)
{
    std::vector<VerifierAirTranscriptOutput> out;
    if (pis.empty() || !fam.row_merkle || !fam.trace_binding ||
        !fam.fold || !fam.deep) {
        return out;
    }
    const VcsLayout layout = ComputeLayout(
        static_cast<uint32_t>(pis.size()), pis, fam);

    // The V6 master statement absorbs both ordered row roots first.
    for (uint32_t child = 0;
         child < layout.children.size(); ++child) {
        const ChildLayout& c = layout.children[child];
        if (c.row_leaf_blocks.empty()) return {};
        const uint32_t terminal =
            c.row_comp.empty()
                ? c.row_leaf_blocks.back()
                : c.row_comp.back();
        for (uint32_t limb = 0;
             limb < kAlgHashDigestLen; ++limb) {
            out.push_back({
                VerifierAirTranscriptOutputKind::RowRoot,
                child, limb, 0, terminal,
                "vcs.row.root.pin"});
        }
    }

    // Then each lane absorbs its trace root, evaluations and fold roots.
    for (uint32_t child = 0;
         child < layout.children.size(); ++child) {
        const ChildLayout& c = layout.children[child];
        if (c.trace_leaf_blocks.empty() ||
            c.evals_z1.size() != c.W + 1 ||
            c.evals_z2.size() != c.W + 1 ||
            c.folds.size() != c.nf) {
            return {};
        }
        const uint32_t trace_terminal =
            c.trace_comp.empty()
                ? c.trace_leaf_blocks.back()
                : c.trace_comp.back();
        for (uint32_t limb = 0;
             limb < kAlgHashDigestLen; ++limb) {
            out.push_back({
                VerifierAirTranscriptOutputKind::TraceRoot,
                child, limb, 0, trace_terminal,
                "vcs.trace.root.pin"});
        }
        for (uint32_t index = 0; index <= c.W; ++index) {
            for (uint32_t coordinate = 0;
                 coordinate < 3; ++coordinate) {
                out.push_back({
                    VerifierAirTranscriptOutputKind::EvaluationZ1,
                    child, index, coordinate, c.evals_z1[index],
                    "vcs.deep.identity"});
            }
        }
        for (uint32_t index = 0; index <= c.W; ++index) {
            for (uint32_t coordinate = 0;
                 coordinate < 3; ++coordinate) {
                out.push_back({
                    VerifierAirTranscriptOutputKind::EvaluationZ2,
                    child, index, coordinate, c.evals_z2[index],
                    "vcs.deep.identity"});
            }
        }
        for (uint32_t fold = 0; fold < c.nf; ++fold) {
            const FoldCols& f = c.folds[fold];
            const uint32_t terminal =
                f.even_comp.empty()
                    ? f.even_leaf
                    : f.even_comp.back();
            for (uint32_t limb = 0;
                 limb < kAlgHashDigestLen; ++limb) {
                out.push_back({
                    VerifierAirTranscriptOutputKind::FoldRoot,
                    child, fold, limb, terminal,
                    "vcs.fold.root.pin"});
            }
        }
    }
    return out;
}

std::vector<VerifierAirParentOutput>
DescribeVerifierAIRParentOutputs(
    const std::vector<ChildPublicInputs>& pis,
    uint32_t child_index,
    const VerifierAirFamilies& fam)
{
    std::vector<VerifierAirParentOutput> out;
    if (child_index >= pis.size() ||
        !fam.row_merkle || !fam.next_row ||
        !fam.trace_binding || !fam.per_point) {
        return out;
    }
    const VcsLayout layout = ComputeLayout(
        static_cast<uint32_t>(pis.size()), pis, fam);
    if (child_index >= layout.children.size()) return {};
    const ChildLayout& child = layout.children[child_index];
    const ChildPublicInputs& pi = pis[child_index];
    if (child.row_leaf_blocks.empty() ||
        child.next_leaf_blocks.empty() ||
        child.trace_leaf_blocks.empty() ||
        child.pre.folds.empty() ||
        child.row_comp.empty() ||
        child.trace_comp.empty()) {
        return {};
    }

    auto row_value =
        [&](VerifierAirParentOutputKind kind,
            uint32_t item,
            const std::vector<uint32_t>& blocks) {
            VerifierAirParentOutput value;
            value.kind = kind;
            value.child_index = child_index;
            value.item_index = item;
            value.row_leaf_blocks = blocks;
            out.push_back(std::move(value));
        };
    for (uint32_t column = 0;
         column < child.W; ++column) {
        row_value(
            VerifierAirParentOutputKind::CurrentOpening,
            column, child.row_leaf_blocks);
    }
    for (uint32_t column = 0;
         column < child.W; ++column) {
        row_value(
            VerifierAirParentOutputKind::NextOpening,
            column, child.next_leaf_blocks);
    }
    row_value(
        VerifierAirParentOutputKind::QuotientOpening,
        child.W, child.row_leaf_blocks);

    VerifierAirParentOutput query;
    query.kind =
        VerifierAirParentOutputKind::QueryIndex;
    query.child_index = child_index;
    query.source_column = child.pre.idx_fp;
    out.push_back(query);

    // For layer zero, fp.x is omega^(index mod N/2) and leaf_sel is one
    // exactly in the first half. Thus (2*leaf_sel-1)*fp.x is omega^index.
    VerifierAirParentOutput point;
    point.kind =
        VerifierAirParentOutputKind::EvaluationPoint;
    point.child_index = child_index;
    point.source_column = child.pre.folds[0].x;
    point.auxiliary_column =
        child.pre.folds[0].leaf_sel;
    out.push_back(point);

    VerifierAirParentOutput next_point = point;
    next_point.kind =
        VerifierAirParentOutputKind::NextEvaluationPoint;
    next_point.public_scalar = Fp3::FromFp(
        OmegaForSizeR(pi.child_n_rows));
    out.push_back(next_point);

    VerifierAirParentOutput challenge;
    challenge.kind =
        VerifierAirParentOutputKind::AirConstraintChallenge;
    challenge.child_index = child_index;
    challenge.public_scalar = pi.air_lambda;
    out.push_back(challenge);

    const uint32_t row_terminal = child.row_comp.back();
    const uint32_t trace_terminal =
        child.trace_comp.back();
    for (uint32_t limb = 0;
         limb < kAlgHashDigestLen; ++limb) {
        VerifierAirParentOutput root;
        root.kind =
            VerifierAirParentOutputKind::RowRootLimb;
        root.child_index = child_index;
        root.item_index = limb;
        root.terminal_permutation_base =
            row_terminal;
        out.push_back(root);
    }
    for (uint32_t limb = 0;
         limb < kAlgHashDigestLen; ++limb) {
        VerifierAirParentOutput root;
        root.kind =
            VerifierAirParentOutputKind::TraceRootLimb;
        root.child_index = child_index;
        root.item_index = limb;
        root.terminal_permutation_base =
            trace_terminal;
        out.push_back(root);
    }
    return out;
}

Fp3 EvaluateVerifierAIRParentOutput(
    const VerifierAirParentOutput& output,
    const std::vector<Fp3>& row)
{
    switch (output.kind) {
    case VerifierAirParentOutputKind::CurrentOpening:
    case VerifierAirParentOutputKind::NextOpening:
    case VerifierAirParentOutputKind::QuotientOpening:
        if (output.row_leaf_blocks.empty()) {
            return Fp3::Zero();
        }
        return ReadRowLeafValue(
            row, output.row_leaf_blocks,
            output.item_index);
    case VerifierAirParentOutputKind::QueryIndex:
        return row.at(output.source_column);
    case VerifierAirParentOutputKind::EvaluationPoint:
    case VerifierAirParentOutputKind::NextEvaluationPoint: {
        const Fp3 sign = gf::Sub(
            gf::Mul(
                Fp3::FromFp(2),
                row.at(output.auxiliary_column)),
            Fp3::One());
        const Fp3 point = gf::Mul(
            sign, row.at(output.source_column));
        return output.kind ==
                VerifierAirParentOutputKind::
                    NextEvaluationPoint
            ? gf::Mul(point, output.public_scalar)
            : point;
    }
    case VerifierAirParentOutputKind::
            AirConstraintChallenge:
        return output.public_scalar;
    case VerifierAirParentOutputKind::RowRootLimb:
    case VerifierAirParentOutputKind::TraceRootLimb:
        return PermOutputLane(
            PermLayout{
                output.terminal_permutation_base},
            row, output.item_index);
    }
    return Fp3::Zero();
}

aq::AirConstraint<Fp3>
BuildVerifierAIRParentOutputConstraint(
    const VerifierAirParentOutput& output,
    uint32_t export_column,
    uint32_t selector_column)
{
    aq::AirConstraint<Fp3> constraint;
    constraint.name =
        "vcs.parent_output.same_trace_alias";
    constraint.kind = aq::AirKind::kEverywhere;
    constraint.alg_degree =
        output.kind ==
                    VerifierAirParentOutputKind::
                        EvaluationPoint ||
                output.kind ==
                    VerifierAirParentOutputKind::
                        NextEvaluationPoint
            ? 3
            : 2;
    constraint.eval =
        [output, export_column, selector_column](
            const std::vector<Fp3>& current,
            const std::vector<Fp3>&) {
            return gf::Mul(
                current[selector_column],
                gf::Sub(
                    current[export_column],
                    EvaluateVerifierAIRParentOutput(
                        output, current)));
        };
    return constraint;
}

Fp3 EvaluateVerifierAIRTranscriptOutput(
    const VerifierAirTranscriptOutput& output,
    const std::vector<Fp3>& row)
{
    switch (output.kind) {
    case VerifierAirTranscriptOutputKind::RowRoot:
    case VerifierAirTranscriptOutputKind::TraceRoot:
        if (output.item_index >= kAlgHashDigestLen ||
            output.source_column > row.size() ||
            row.size() - output.source_column <
                kPermCellsPerPerm) {
            return Fp3::Zero();
        }
        return PermOutputLane(
            PermLayout{output.source_column}, row,
            output.item_index);
    case VerifierAirTranscriptOutputKind::FoldRoot:
        if (output.coordinate >= kAlgHashDigestLen ||
            output.source_column > row.size() ||
            row.size() - output.source_column <
                kPermCellsPerPerm) {
            return Fp3::Zero();
        }
        return PermOutputLane(
            PermLayout{output.source_column}, row,
            output.coordinate);
    case VerifierAirTranscriptOutputKind::EvaluationZ1:
    case VerifierAirTranscriptOutputKind::EvaluationZ2:
        if (output.source_column >= row.size()) {
            return Fp3::Zero();
        }
        if (output.coordinate == 0) {
            return Fp3::FromFp(
                gf::Canonical(row[output.source_column].c0));
        }
        if (output.coordinate == 1) {
            return Fp3::FromFp(
                gf::Canonical(row[output.source_column].c1));
        }
        if (output.coordinate == 2) {
            return Fp3::FromFp(
                gf::Canonical(row[output.source_column].c2));
        }
        return Fp3::Zero();
    }
    return Fp3::Zero();
}

aq::AirConstraint<Fp3>
BuildVerifierAIRTranscriptExportConstraint(
    const VerifierAirTranscriptOutput& output,
    uint32_t export_column,
    uint32_t selector_column)
{
    aq::AirConstraint<Fp3> constraint;
    constraint.name =
        "vcs.export.full_transcript.selected_alias";
    constraint.kind = aq::AirKind::kEverywhere;
    constraint.alg_degree = 2;
    constraint.eval =
        [output, export_column, selector_column](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            if (export_column >= cur.size() ||
                selector_column >= cur.size()) {
                return Fp3::One();
            }
            return gf::Mul(
                cur[selector_column],
                gf::Sub(
                    cur[export_column],
                    EvaluateVerifierAIRTranscriptOutput(
                        output, cur)));
        };
    return constraint;
}

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
    // PR-89 blocker #6 (H1): under independent-coefficient batching the single
    // Q192 base proof persists only the scalar lambda (= coefficients[0]).
    // Recover the full W = child_w+1 independent batching-coefficient vector by
    // replaying the single-lane FS transcript (analogue of the per-lane
    // BuildFri3AlgDualTranscriptWitness) and thread it as a public input so
    // BuildVerifierAIRPinned consumes the true independent draw rather than
    // reconstructing geometric powers lam_pow[i]=lam_pow[i-1]*fri_lambda.
    //
    // Only genuine single-Q192 proofs (matching the Q192 config's proof
    // version) are replayed here: the dual-lane V5 callers reuse this extractor
    // on per-lane VIEWS whose batch carries a different version and then install
    // the correct per-lane coefficients from their own dual transcript replay,
    // so this block must leave those untouched rather than fail closed on them.
    if (Fri3AlgQ192IndependentBatching() &&
        b.version == kRCFri3AlgBatchProofVersion) {
        // Bind this extraction to the independent-coefficient regime. On an
        // honest proof the transcript replay recovers the full W = child_w+1
        // vector. On a corrupted transcript (e.g. a tampered row commitment)
        // the replay legitimately fails; we then leave fri_batch_coefficients
        // EMPTY so BuildVerifierAIRPinned zero-fills the DEEP batching weights
        // and the verifier AIR becomes unsatisfiable — fail closed, but without
        // emitting a half-built public-input record that would crash the
        // downstream CS builders.
        pi.independent_fri_batching = true;
        std::vector<Fp3> coeffs;
        if (Fri3AlgReplayBatchCoefficients(b, child_fs_seed, coeffs) &&
            coeffs.size() == static_cast<size_t>(pi.child_w) + 1) {
            pi.fri_batch_coefficients = std::move(coeffs);
        }
    }
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
            // Row-leaf sponge (multi-block LeafHashRow over [values(3(W+1)), idx,
            // pad1, 0..], 10*-padded to n_blocks rate blocks). Absorb-carry +
            // capacity-carry wiring mirrors ah::SpongeHashFp exactly; the leaf
            // digest is the LAST block's output lanes [0..4).
            EmitRowLeafSponge(K, c.row_leaf_blocks, c.pre.idx_fp, c.W + 1);
            // Compress chain (leaf digest = last sponge block's output).
            uint32_t prev = c.row_leaf_blocks.back();
            for (uint32_t j = 0; j < c.D; ++j) {
                EmitPermSbox(K, c.row_comp[j]);
                EmitCompressWiring(K, c.row_comp[j], prev, c.row_sib[j], c.pre.row_dir[j], node_domain);
                prev = c.row_comp[j];
            }
            EmitRootPin(K, prev, pi.row_commit_root);
        }

        // ---- SUPPLEMENTAL NEXT-ROW OPENING ----
        // Authenticate every trace column at y·omega_H (plus the quotient
        // column carried in the same batch row) against row_commit_root. The
        // trace portion is consumed by per-point transition/boundary rules.
        if (fam.next_row) {
            EmitAuthenticatedRowPath(
                K, c.next_leaf_blocks, c.next_comp, c.next_sib,
                c.pre.next_dir, c.pre.next_idx_fp, c.W + 1,
                pi.row_commit_root, node_domain);
        }

        // ---- TRACE-COMMITMENT CROSS-OPENING ----
        // Bind the current trace values already opened under row_commit_root
        // to the trace-only root R_T that seeded airq_lambda.
        if (fam.trace_binding) {
            EmitAuthenticatedRowPath(
                K, c.trace_leaf_blocks, c.trace_comp, c.trace_sib,
                c.pre.trace_dir, c.pre.idx_fp, c.W,
                pi.rt_root, node_domain);
            if (fam.row_merkle) {
                EmitRowValueEquality(
                    K, c.row_leaf_blocks, c.trace_leaf_blocks, c.W);
            }
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
            if (fam.deep) {
                // Materialize every public evaluation claim in the witness.
                // These pins prevent query-row-specific substitutions, while
                // vcs.deep.identity below consumes the very same columns.
                for (uint32_t i = 0; i <= c.W; ++i) {
                    for (uint32_t which = 0; which < 2; ++which) {
                        const uint32_t column =
                            which == 0
                                ? c.evals_z1[i]
                                : c.evals_z2[i];
                        const Fp3 expected =
                            which == 0
                                ? pi.evals_z1[i]
                                : pi.evals_z2[i];
                        AirConstraint<Fp3> pin;
                        pin.name = which == 0
                            ? "vcs.deep.eval_z1.public_pin"
                            : "vcs.deep.eval_z2.public_pin";
                        pin.kind = AirKind::kEverywhere;
                        pin.alg_degree = 1;
                        pin.eval =
                            [column, expected](
                                const std::vector<Fp3>& cur,
                                const std::vector<Fp3>&) {
                                return gf::Sub(
                                    cur[column], expected);
                            };
                        K.push_back(std::move(pin));
                    }
                }
            }
            // shared: v1, v2 (global consts from evals).
            std::vector<Fp3> lam_pow(pi.child_w + 1);
            if (pi.independent_fri_batching) {
                if (pi.fri_batch_coefficients.size() !=
                    pi.child_w + 1) {
                    // A malformed public input must make the system
                    // unsatisfiable, never silently fall back to V3.
                    std::fill(
                        lam_pow.begin(), lam_pow.end(),
                        Fp3::Zero());
                } else {
                    lam_pow = pi.fri_batch_coefficients;
                }
            } else {
                lam_pow[0] = Fp3::One();
                for (uint32_t i = 1; i <= pi.child_w; ++i)
                    lam_pow[i] =
                        gf::Mul(lam_pow[i - 1], pi.fri_lambda);
            }
            std::vector<Fp3> z1_weights(pi.child_w + 1);
            std::vector<Fp3> z2_weights(pi.child_w + 1);
            for (uint32_t i = 0; i <= pi.child_w; ++i) {
                const uint32_t shift = pi.child_n_coeffs - pi.column_len[i];
                z1_weights[i] =
                    gf::Mul(lam_pow[i], Pow3R(pi.z1, shift));
                z2_weights[i] =
                    gf::Mul(lam_pow[i], Pow3R(pi.z2, shift));
            }
            const std::vector<uint32_t> evals_z1 = c.evals_z1;
            const std::vector<uint32_t> evals_z2 = c.evals_z2;
            auto eval_claim =
                [](const std::vector<Fp3>& cur,
                   const std::vector<uint32_t>& columns,
                   const std::vector<Fp3>& weights) {
                    Fp3 value = Fp3::Zero();
                    for (uint32_t i = 0;
                         i < columns.size(); ++i) {
                        value = gf::Add(
                            value,
                            gf::Mul(weights[i], cur[columns[i]]));
                    }
                    return value;
                };
            const std::vector<uint32_t> rlb = c.row_leaf_blocks;
            const uint32_t W = c.W;
            const std::vector<uint32_t> xpow = c.pre.xpow;
            // U_x closure (reads the multi-block row-leaf value lanes + xpow).
            auto eval_Ux = [rlb, W, xpow, lam_pow](const std::vector<Fp3>& cur) {
                Fp3 U = Fp3::Zero();
                for (uint32_t i = 0; i <= W; ++i) {
                    const Fp3 val = ReadRowLeafValue(cur, rlb, i);
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
                con.eval = [eval_Ux, eval_claim, evals_z1,
                            evals_z2, z1_weights, z2_weights,
                            w1, w2, invd1, invd2, even_leaf,
                            odd_leaf, leaf_sel](
                               const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
                    const Fp3 U = eval_Ux(cur);
                    const Fp3 v1 = eval_claim(
                        cur, evals_z1, z1_weights);
                    const Fp3 v2 = eval_claim(
                        cur, evals_z2, z2_weights);
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
                // C(y) = Σ_i air_lambda^i * sel_i(y) *
                // R_i(cur_child,next_child); qv = row.values[W]. The next
                // values come from the supplemental row_commit opening.
                const Fp3 air_lambda = pi.air_lambda;
                std::vector<aq::AirConstraint<Fp3>> child_cons = pi.child_constraints;
                const uint32_t zh = c.pre.zh;
                const uint32_t trans_sel = c.pre.transition_selector;
                const uint32_t first_sel = c.pre.first_selector;
                const uint32_t last_sel = c.pre.last_selector;
                const std::vector<uint32_t> next_rlb =
                    fam.next_row ? c.next_leaf_blocks : rlb;
                if (!fam.next_row) {
                    AirConstraint<Fp3> required;
                    required.name = "vcs.next_row.required";
                    required.kind = AirKind::kEverywhere;
                    required.alg_degree = 0;
                    required.eval = [](const std::vector<Fp3>&,
                                       const std::vector<Fp3>&) {
                        return Fp3::One();
                    };
                    K.push_back(std::move(required));
                }
                AirConstraint<Fp3> con;
                con.name = "vcs.perpoint"; con.kind = AirKind::kEverywhere;
                uint32_t md = 1;
                for (const auto& cc : child_cons) {
                    const uint32_t selector_degree =
                        cc.kind == AirKind::kEverywhere ? 0U : 1U;
                    md = std::max(md, cc.alg_degree + selector_degree);
                }
                con.alg_degree = md;
                con.eval = [rlb, next_rlb, W, zh, trans_sel, first_sel,
                            last_sel, air_lambda, child_cons](
                               const std::vector<Fp3>& cur,
                               const std::vector<Fp3>&) {
                    std::vector<Fp3> cur_child(W), next_child(W);
                    for (uint32_t i = 0; i < W; ++i) {
                        cur_child[i] = ReadRowLeafValue(cur, rlb, i);
                        next_child[i] =
                            ReadRowLeafValue(cur, next_rlb, i);
                    }
                    const Fp3 qv = ReadRowLeafValue(cur, rlb, W);
                    Fp3 C = Fp3::Zero(), lp = Fp3::One();
                    for (const auto& cc : child_cons) {
                        Fp3 selector = Fp3::One();
                        switch (cc.kind) {
                        case AirKind::kEverywhere:
                            break;
                        case AirKind::kTransition:
                            selector = cur[trans_sel];
                            break;
                        case AirKind::kFirstRow:
                            selector = cur[first_sel];
                            break;
                        case AirKind::kLastRow:
                            selector = cur[last_sel];
                            break;
                        }
                        C = gf::Add(
                            C, gf::Mul(lp, gf::Mul(
                                   selector,
                                   cc.eval(cur_child, next_child))));
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
        if (fam.next_row) {
            const uint32_t step = n_lde / pi.child_n_rows;
            add_pre(c.pre.next_idx_fp, [&pi, n_lde, step](uint32_t qi) {
                return Fp3::FromFp(gf::FromU64(
                    (pi.query_index[qi] + step) % n_lde));
            });
            for (uint32_t j = 0; j < c.D; ++j) {
                add_pre(c.pre.next_dir[j],
                        [&pi, n_lde, step, j](uint32_t qi) {
                    const uint32_t idx =
                        (pi.query_index[qi] + step) % n_lde;
                    return Fp3::FromFp(
                        gf::FromU64((idx >> j) & 1u));
                });
            }
        }
        if (fam.trace_binding) {
            for (uint32_t j = 0; j < c.D; ++j) {
                add_pre(c.pre.trace_dir[j], [&pi, j](uint32_t qi) {
                    return Fp3::FromFp(gf::FromU64(
                        (pi.query_index[qi] >> j) & 1u));
                });
            }
        }
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
            const Fp3 h_first = Fp3::One();
            const Fp3 h_last = Fp3::FromFp(
                PowFpR(OmegaForSizeR(pi.child_n_rows),
                       pi.child_n_rows - 1));
            auto point = [&pi, n_lde, g](uint32_t qi) {
                const Fp3 x =
                    DomainPointR(n_lde, pi.query_index[qi]);
                return gf::Mul(g, x);
            };
            auto zh_at = [&pi, point](uint32_t qi) {
                const Fp3 y = point(qi);
                return gf::Sub(Pow3R(y, pi.child_n_rows),
                               Fp3::One());
            };
            add_pre(c.pre.zh, [&pi, n_lde, g](uint32_t qi) {
                const Fp3 x = DomainPointR(n_lde, pi.query_index[qi]);
                const Fp3 y = gf::Mul(g, x);
                return gf::Sub(Pow3R(y, pi.child_n_rows), Fp3::One());
            });
            add_pre(c.pre.transition_selector,
                    [point, h_last](uint32_t qi) {
                return gf::Sub(point(qi), h_last);
            });
            add_pre(c.pre.first_selector,
                    [point, zh_at, h_first](uint32_t qi) {
                return gf::Mul(
                    zh_at(qi),
                    gf::Inv(gf::Sub(point(qi), h_first)));
            });
            add_pre(c.pre.last_selector,
                    [point, zh_at, h_last](uint32_t qi) {
                return gf::Mul(
                    zh_at(qi),
                    gf::Inv(gf::Sub(point(qi), h_last)));
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

Digest FillRowLeafWitness(
    std::vector<Fp3>& row,
    const std::vector<uint32_t>& blocks,
    const std::vector<Fp3>& values,
    uint32_t index)
{
    std::vector<Fp> xs;
    xs.reserve(3 * values.size() + 1);
    for (const Fp3& value : values) {
        xs.push_back(gf::Canonical(value.c0));
        xs.push_back(gf::Canonical(value.c1));
        xs.push_back(gf::Canonical(value.c2));
    }
    xs.push_back(gf::FromU64(index));
    xs.push_back(1);
    while (xs.size() % kAlgHashRate != 0) xs.push_back(0);
    ah::State state{};
    for (uint32_t b = 0; b < blocks.size(); ++b) {
        for (uint32_t j = 0; j < kAlgHashRate; ++j) {
            state[j] = gf::Add(
                state[j], xs[b * kAlgHashRate + j]);
        }
        const PermWitness witness = BuildPermWitness(state);
        WritePermWitness(PermLayout{blocks[b]}, witness, row);
        state = witness.output;
    }
    return Digest{state[0], state[1], state[2], state[3]};
}

void FillAuthenticatedRowPathWitness(
    std::vector<Fp3>& row,
    const std::vector<uint32_t>& leaf_blocks,
    const std::vector<uint32_t>& comp,
    const std::vector<uint32_t>& sibling_cols,
    const std::vector<Fp3>& values,
    uint32_t index,
    const std::vector<Digest>& siblings,
    Fp node_domain)
{
    Digest acc =
        FillRowLeafWitness(row, leaf_blocks, values, index);
    for (uint32_t j = 0; j < comp.size(); ++j) {
        const bool bit = ((index >> j) & 1u) != 0;
        SetDigestCols(row, sibling_cols[j], siblings[j]);
        const ah::State state =
            CompressState(acc, siblings[j], bit, node_domain);
        WriteBlock(row, comp[j], state);
        acc = BlockDigest(state);
    }
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
        FillAuthenticatedRowPathWitness(
            row, c.row_leaf_blocks, c.row_comp, c.row_sib,
            q.row.values, q.index, q.row.siblings, node_domain);
    }
    if (fam.next_row) {
        const auto& opening = child.next_openings[qi][0];
        FillAuthenticatedRowPathWitness(
            row, c.next_leaf_blocks, c.next_comp, c.next_sib,
            opening.values, opening.index, opening.siblings,
            node_domain);
    }
    if (fam.trace_binding) {
        const auto& opening = child.next_openings[qi][1];
        const std::vector<Fp3> trace_values(
            q.row.values.begin(), q.row.values.begin() + c.W);
        FillAuthenticatedRowPathWitness(
            row, c.trace_leaf_blocks, c.trace_comp, c.trace_sib,
            trace_values, opening.index, opening.siblings,
            node_domain);
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
    if (fam.deep) {
        for (uint32_t i = 0; i < c.evals_z1.size(); ++i) {
            row[c.evals_z1[i]] = pi.evals_z1[i];
            row[c.evals_z2[i]] = pi.evals_z2[i];
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
    // Multi-block row-leaf absorption (RowLeafNBlocks) supports any W; the former
    // single-block guard (3*(W+1)+1 > kAlgHashRate) is removed.
    out.cs = BuildVerifierAIRPinned(k, out.pis, fam);
    const VcsLayout L = ComputeLayout(k, out.pis, fam);
    out.n_witness_cols = L.n_witness_cols;
    const uint32_t N = out.cs.n_rows, Q = L.queries;

    for (uint32_t ci = 0; ci < k; ++ci) {
        const auto& child = children[ci];
        const auto& pi = out.pis[ci];
        if (child.batch.queries.size() != Q) {
            out.note = "child query count mismatch";
            return out;
        }
        if ((fam.next_row || fam.trace_binding) &&
            child.next_openings.size() != Q) {
            out.note = "supplemental opening count mismatch";
            return out;
        }
        for (uint32_t qi = 0; qi < Q; ++qi) {
            const auto& query = child.batch.queries[qi];
            if ((fam.row_merkle || fam.trace_binding) &&
                query.row.values.size() != pi.child_w + 1) {
                out.note = "query row width mismatch";
                return out;
            }
            if (fam.next_row || fam.trace_binding) {
                const auto& openings = child.next_openings[qi];
                if (openings.size() != 2) {
                    out.note = "supplemental opening width mismatch";
                    return out;
                }
                if (fam.next_row &&
                    (openings[0].values.size() != pi.child_w + 1 ||
                     openings[0].siblings.size() != pi.merkle_depth)) {
                    out.note = "next-row opening shape mismatch";
                    return out;
                }
                if (fam.trace_binding &&
                    (!openings[1].values.empty() ||
                     openings[1].siblings.size() != pi.merkle_depth)) {
                    out.note = "trace-binding opening shape mismatch";
                    return out;
                }
            }
        }
    }

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

AggregateWitness BuildAggregateWitnessHeterogeneous(
    const std::vector<aq::AirConstraintSystem<Fp3>>& child_css,
    const std::vector<
        aq::AirQuotientProof<Fp3, AggregateWitness::AlgB3>>&
        children,
    const std::vector<uint256>& child_fs_seeds,
    const VerifierAirFamilies& fam)
{
    AggregateWitness out;
    const uint32_t k = static_cast<uint32_t>(children.size());
    if (k == 0 || child_css.size() != k ||
        child_fs_seeds.size() != k) {
        out.note = "heterogeneous child shape";
        return out;
    }
    out.pis.resize(k);
    for (uint32_t ci = 0; ci < k; ++ci) {
        out.pis[ci] = ExtractChildPublicInputs(
            child_css[ci], children[ci],
            child_fs_seeds[ci]);
    }
    out.cs = BuildVerifierAIRPinned(k, out.pis, fam);
    const VcsLayout layout = ComputeLayout(k, out.pis, fam);
    out.n_witness_cols = layout.n_witness_cols;
    const uint32_t n_rows = out.cs.n_rows;
    const uint32_t queries = layout.queries;

    for (uint32_t ci = 0; ci < k; ++ci) {
        const auto& child = children[ci];
        const auto& pi = out.pis[ci];
        if (child.batch.queries.size() != queries) {
            out.note = "heterogeneous child query count mismatch";
            return out;
        }
        if ((fam.next_row || fam.trace_binding) &&
            child.next_openings.size() != queries) {
            out.note =
                "heterogeneous supplemental opening count mismatch";
            return out;
        }
        for (uint32_t qi = 0; qi < queries; ++qi) {
            const auto& query = child.batch.queries[qi];
            if ((fam.row_merkle || fam.trace_binding) &&
                query.row.values.size() != pi.child_w + 1) {
                out.note =
                    "heterogeneous query row width mismatch";
                return out;
            }
            if (fam.next_row || fam.trace_binding) {
                const auto& openings =
                    child.next_openings[qi];
                if (openings.size() != 2) {
                    out.note =
                        "heterogeneous supplemental opening width mismatch";
                    return out;
                }
                if (fam.next_row &&
                    (openings[0].values.size() !=
                         pi.child_w + 1 ||
                     openings[0].siblings.size() !=
                         pi.merkle_depth)) {
                    out.note =
                        "heterogeneous next-row opening shape mismatch";
                    return out;
                }
                if (fam.trace_binding &&
                    (!openings[1].values.empty() ||
                     openings[1].siblings.size() !=
                         pi.merkle_depth)) {
                    out.note =
                        "heterogeneous trace-binding opening shape mismatch";
                    return out;
                }
            }
        }
    }

    out.columns.assign(
        out.cs.n_columns,
        std::vector<Fp3>(n_rows, Fp3::Zero()));
    for (const auto& [column, values] :
         out.cs.preprocessed) {
        for (uint32_t row = 0; row < n_rows; ++row) {
            out.columns[column][row] = values[row];
        }
    }
    std::vector<Fp3> row(
        out.cs.n_columns, Fp3::Zero());
    for (uint32_t r = 0; r < n_rows; ++r) {
        const uint32_t query =
            r < queries ? r : queries - 1;
        std::fill(
            row.begin(),
            row.begin() + layout.n_witness_cols,
            Fp3::Zero());
        for (uint32_t ci = 0; ci < k; ++ci) {
            FillChildRow(
                row, layout.children[ci], out.pis[ci],
                children[ci], query, fam);
        }
        for (uint32_t column = 0;
             column < layout.n_witness_cols; ++column) {
            out.columns[column][r] = row[column];
        }
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

namespace {

constexpr char kDualV5AirProofCommitDomain[] =
    "BTX_RC_RECURSE_DUAL_V5_AIR_PROOF_V1";
constexpr char kDualV5TranscriptCommitDomain[] =
    "BTX_RC_RECURSE_DUAL_V5_TRANSCRIPT_V1";
constexpr char kDualV5PinsCommitDomain[] =
    "BTX_RC_RECURSE_DUAL_V5_CHILD_PINS_V1";
constexpr char kDualV5LanePisCommitDomain[] =
    "BTX_RC_RECURSE_DUAL_V5_LANE_PIS_V1";
constexpr char kDualV5ParentSeedDomain[] =
    "BTX_RC_RECURSE_DUAL_V5_PARENT_SEED_V1";

void HashFp3R(HashWriter& hash, const Fp3& value)
{
    hash << gf::Canonical(value.c0);
    hash << gf::Canonical(value.c1);
    hash << gf::Canonical(value.c2);
}

void HashDigestR(HashWriter& hash, const Fri3AlgDigest& digest)
{
    for (const Fp limb : digest) hash << gf::Canonical(limb);
}

void HashFp3VectorR(HashWriter& hash, const std::vector<Fp3>& values)
{
    hash << static_cast<uint32_t>(values.size());
    for (const Fp3& value : values) HashFp3R(hash, value);
}

void HashDigestVectorR(HashWriter& hash,
                       const std::vector<Fri3AlgDigest>& values)
{
    hash << static_cast<uint32_t>(values.size());
    for (const auto& value : values) HashDigestR(hash, value);
}

void HashDualQueryR(HashWriter& hash, const Fri3AlgBatchQuery& query)
{
    hash << query.index;
    HashFp3VectorR(hash, query.row.values);
    HashDigestVectorR(hash, query.row.siblings);
    hash << static_cast<uint32_t>(query.steps.size());
    for (const auto& step : query.steps) {
        hash << step.even_index;
        hash << step.odd_index;
        HashFp3R(hash, step.even);
        HashFp3R(hash, step.odd);
        HashDigestVectorR(hash, step.even_siblings);
        HashDigestVectorR(hash, step.odd_siblings);
    }
}

void HashAirRowPathR(HashWriter& hash, const aq::AirAlgRowPath& path)
{
    hash << path.index;
    HashFp3VectorR(hash, path.values);
    HashDigestVectorR(hash, path.siblings);
}

uint256 CommitDualV5LanePis(
    const std::vector<ChildPublicInputs>& lane_pis)
{
    HashWriter hash;
    hash << kDualV5LanePisCommitDomain;
    hash << static_cast<uint32_t>(lane_pis.size());
    for (const ChildPublicInputs& pi : lane_pis) {
        hash << pi.child_n_rows;
        hash << pi.child_w;
        hash << pi.child_quotient_len;
        hash << pi.child_n_coeffs;
        hash << pi.child_n_lde;
        hash << pi.merkle_depth;
        hash << pi.n_folds;
        HashDigestR(hash, pi.row_commit_root);
        HashDigestR(hash, pi.rt_root);
        hash << static_cast<uint32_t>(pi.fold_roots.size());
        for (const auto& root : pi.fold_roots) HashDigestR(hash, root);
        HashFp3R(hash, pi.fri_lambda);
        HashFp3R(hash, pi.z1);
        HashFp3R(hash, pi.z2);
        HashFp3R(hash, pi.w1);
        HashFp3R(hash, pi.w2);
        HashFp3R(hash, pi.final_value);
        HashFp3R(hash, pi.air_lambda);
        hash << pi.independent_fri_batching;
        HashFp3VectorR(hash, pi.fri_batch_coefficients);
        HashFp3VectorR(hash, pi.fold_challenges);
        hash << static_cast<uint32_t>(pi.column_len.size());
        for (const uint32_t length : pi.column_len) hash << length;
        HashFp3VectorR(hash, pi.evals_z1);
        HashFp3VectorR(hash, pi.evals_z2);
        hash << static_cast<uint32_t>(pi.query_index.size());
        for (const uint32_t query : pi.query_index) hash << query;
        // Constraint closures are not serializable. The fixed relation
        // registry authenticates their identity; these metadata catch
        // reorder/shape/substitution errors at this boundary.
        hash << static_cast<uint32_t>(pi.child_constraints.size());
        for (const auto& constraint : pi.child_constraints) {
            hash << std::string(constraint.name ? constraint.name : "");
            hash << static_cast<uint8_t>(constraint.kind);
            hash << constraint.alg_degree;
        }
    }
    return hash.GetHash();
}

uint256 DeriveDualV5ParentSeed(
    const uint256& parent_fs_seed,
    const uint256& pin_commitment,
    const uint256& lane_pis_commitment)
{
    HashWriter hash;
    hash << kDualV5ParentSeedDomain;
    hash << parent_fs_seed;
    hash << pin_commitment;
    hash << lane_pis_commitment;
    return hash.GetHash();
}

std::vector<aq::AirQuotientProof<Fp3, AlgB3>>
NormalizeDualV5LaneProofs(
    const std::vector<DualAlgAirProof>& children)
{
    std::vector<aq::AirQuotientProof<Fp3, AlgB3>> lanes;
    lanes.reserve(children.size() * kRCFri3AlgDualNumLanes);
    for (const DualAlgAirProof& child : children) {
        for (uint32_t lane = 0; lane < kRCFri3AlgDualNumLanes; ++lane) {
            aq::AirQuotientProof<Fp3, AlgB3> view;
            view.batch = child.batch.repeated.lane[lane];
            view.trace_commit = child.trace_commit;
            const size_t begin =
                static_cast<size_t>(lane) *
                kRCFri3AlgDualQueriesPerLane;
            const size_t end =
                begin + kRCFri3AlgDualQueriesPerLane;
            if (end <= child.next_openings.size()) {
                view.next_openings.insert(
                    view.next_openings.end(),
                    child.next_openings.begin() + begin,
                    child.next_openings.begin() + end);
            }
            lanes.push_back(std::move(view));
        }
    }
    return lanes;
}

} // namespace

uint256 ComputeDualV5AirProofCommitment(
    const DualAlgAirProof& proof)
{
    std::vector<unsigned char> envelope;
    if (SerializeFri3AlgDualBatchProof(
            proof.batch.repeated, envelope) != envelope.size() ||
        envelope.empty()) {
        return {};
    }
    HashWriter hash;
    hash << kDualV5AirProofCommitDomain;
    hash << static_cast<uint32_t>(envelope.size());
    for (const unsigned char byte : envelope) hash << byte;

    // Bind the flattened AIR view as well. Native verification requires it to
    // equal the authoritative ordered envelope, but hashing it here prevents a
    // caller from treating a detached view as the same recursive child.
    hash << proof.batch.n_coeffs;
    hash << proof.batch.row_commit.n_leaves;
    HashDigestR(hash, proof.batch.row_commit.root);
    hash << static_cast<uint32_t>(proof.batch.column_len.size());
    for (const uint32_t length : proof.batch.column_len) hash << length;
    HashFp3R(hash, proof.batch.z1);
    HashFp3R(hash, proof.batch.z2);
    HashFp3VectorR(hash, proof.batch.evals_z1);
    HashFp3VectorR(hash, proof.batch.evals_z2);
    hash << static_cast<uint32_t>(proof.batch.queries.size());
    for (const auto& query : proof.batch.queries) HashDualQueryR(hash, query);

    hash << proof.trace_commit;
    hash << static_cast<uint32_t>(proof.next_openings.size());
    for (const auto& paths : proof.next_openings) {
        hash << static_cast<uint32_t>(paths.size());
        for (const auto& path : paths) HashAirRowPathR(hash, path);
    }
    return hash.GetHash();
}

uint256 ComputeDualV5TranscriptCommitment(
    const Fri3AlgDualTranscriptWitness& transcript)
{
    if (!transcript.valid || !transcript.program.valid) return {};
    HashWriter hash;
    hash << kDualV5TranscriptCommitDomain;
    const auto& program = transcript.program;
    hash << program.envelope_version;
    hash << program.lane_version;
    hash << program.lanes;
    hash << program.batch_columns;
    hash << program.n_coeffs;
    hash << program.n_lde;
    hash << program.fold_challenges_per_lane;
    hash << program.queries_per_lane;
    hash << program.independent_batch_draws_per_lane;
    hash << program.ood_draws_per_lane;
    hash << program.deep_weight_draws_per_lane;
    hash << program.uniform_fp3_draws_per_lane;
    hash << program.uniform_fp3_hashes_per_lane;
    hash << program.query_index_hashes_per_lane;
    hash << program.challenge_hashes_total;
    hash << program.fixed_ood_schedule;
    hash << program.independent_batching;
    hash << program.lane_order_semantic;
    hash << transcript.master_statement_binding;
    for (const uint256& binding : transcript.lane_child_binding)
        hash << binding;
    for (const auto& lane : transcript.lane) {
        hash << lane.lane;
        hash << lane.lane_seed;
        HashFp3VectorR(hash, lane.batch_coefficients);
        for (const Fp3& candidate : lane.ood_candidates)
            HashFp3R(hash, candidate);
        HashFp3R(hash, lane.selected_z1);
        HashFp3R(hash, lane.selected_z2);
        HashFp3R(hash, lane.w1);
        HashFp3R(hash, lane.w2);
        HashFp3VectorR(hash, lane.fold_challenges);
        hash << static_cast<uint32_t>(lane.query_indices.size());
        for (const uint32_t query : lane.query_indices) hash << query;
        hash << lane.independent_coefficients_replayed;
        hash << lane.fixed_ood_schedule_replayed;
        hash << lane.folds_replayed;
        hash << lane.queries_replayed;
    }
    hash << transcript.common_statement_bound;
    hash << transcript.ordered_lanes_bound;
    return hash.GetHash();
}

uint256 CommitDualV5RecursiveChildPins(
    const std::vector<DualV5RecursiveChildPin>& pins)
{
    HashWriter hash;
    hash << kDualV5PinsCommitDomain;
    hash << static_cast<uint32_t>(pins.size());
    for (const auto& pin : pins) {
        hash << pin.air_proof_commitment;
        hash << pin.transcript_commitment;
        hash << pin.master_statement_binding;
        for (const uint256& binding : pin.lane_child_binding)
            hash << binding;
        for (const uint256& root : pin.lane_row_root) hash << root;
        hash << pin.host_reports_native_air_accepted;
        hash << pin.host_reports_exact_transcript_replayed;
        hash << pin.host_reports_ordered_lane_binding_checked;
    }
    return hash.GetHash();
}

DualV5AggregateWitness BuildDualV5AggregateWitness(
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const std::vector<DualAlgAirProof>& children,
    const uint256& child_fs_seed,
    const VerifierAirFamilies& fam)
{
    DualV5AggregateWitness out;
    if (children.empty() || children.size() > 4) {
        out.note = "dual v5 aggregate: child count";
        return out;
    }
    if (fam.per_point && !fam.next_row) {
        out.note =
            "dual v5 aggregate: per-point relation requires authenticated "
            "next-row openings";
        return out;
    }
    out.child_pins.resize(children.size());
    std::vector<std::vector<Fp3>> lane_batch_coefficients(
        children.size() * kRCFri3AlgDualNumLanes);
    for (size_t child_index = 0;
         child_index < children.size(); ++child_index) {
        const DualAlgAirProof& child = children[child_index];
        std::string why;
        const auto verify_begin = std::chrono::steady_clock::now();
        const bool accepted =
            aq::AirQuotientVerify<Fp3, DualAlgB3>(
                child_cs, child, child_fs_seed, &why);
        out.native_verify_micros +=
            static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - verify_begin)
                    .count());
        if (!accepted) {
            out.note = "dual v5 aggregate: child " +
                       std::to_string(child_index) +
                       " rejected: " + why;
            return out;
        }

        const auto transcript_begin =
            std::chrono::steady_clock::now();
        const Fri3AlgDualTranscriptWitness transcript =
            BuildFri3AlgDualTranscriptWitness(
                child.batch.repeated, child_fs_seed);
        out.transcript_replay_micros +=
            static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - transcript_begin)
                    .count());
        if (!transcript.valid ||
            !transcript.common_statement_bound ||
            !transcript.ordered_lanes_bound) {
            out.note = "dual v5 aggregate: child " +
                       std::to_string(child_index) +
                       " transcript: " + transcript.note;
            return out;
        }
        for (uint32_t lane = 0;
             lane < kRCFri3AlgDualNumLanes; ++lane) {
            lane_batch_coefficients[
                child_index * kRCFri3AlgDualNumLanes + lane] =
                transcript.lane[lane].batch_coefficients;
        }
        DualV5RecursiveChildPin& pin =
            out.child_pins[child_index];
        pin.air_proof_commitment =
            ComputeDualV5AirProofCommitment(child);
        pin.transcript_commitment =
            ComputeDualV5TranscriptCommitment(transcript);
        pin.master_statement_binding =
            child.batch.repeated.master_statement_binding;
        pin.lane_child_binding =
            child.batch.repeated.lane_child_binding;
        for (uint32_t lane = 0;
             lane < kRCFri3AlgDualNumLanes; ++lane) {
            pin.lane_row_root[lane] =
                Fri3AlgDigestToUint256(
                    child.batch.repeated.lane[lane]
                        .row_commit.root);
        }
        pin.host_reports_native_air_accepted = true;
        pin.host_reports_exact_transcript_replayed = true;
        pin.host_reports_ordered_lane_binding_checked =
            transcript.master_statement_binding ==
                pin.master_statement_binding &&
            transcript.lane_child_binding ==
                pin.lane_child_binding;
        if (pin.air_proof_commitment.IsNull() ||
            pin.transcript_commitment.IsNull() ||
            !pin.host_reports_ordered_lane_binding_checked) {
            out.note =
                "dual v5 aggregate: child binding mismatch";
            return out;
        }
    }

    const auto normalized_begin =
        std::chrono::steady_clock::now();
    const auto lane_views = NormalizeDualV5LaneProofs(children);
    out.normalized = BuildAggregateWitness(
        child_cs, lane_views, child_fs_seed, fam);
    out.normalized_witness_micros =
        static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - normalized_begin)
                .count());
    if (!out.normalized.ok ||
        out.normalized.pis.size() !=
            children.size() * kRCFri3AlgDualNumLanes) {
        out.note = "dual v5 aggregate: normalized witness: " +
                   out.normalized.note;
        return out;
    }
    for (size_t lane = 0;
         lane < out.normalized.pis.size(); ++lane) {
        ChildPublicInputs& pi = out.normalized.pis[lane];
        if (lane_batch_coefficients[lane].size() !=
            pi.child_w + 1) {
            out.note =
                "dual v5 aggregate: independent coefficient shape";
            return out;
        }
        pi.fri_batch_coefficients =
            lane_batch_coefficients[lane];
        pi.independent_fri_batching = true;
    }
    // BuildAggregateWitness laid out and filled the proof-derived witness with
    // legacy public inputs. Independent batching changes no witness column;
    // it changes the DEEP constraint constants. Rebuild the pinned CS and
    // refresh its canonical preprocessed columns before scanning.
    out.normalized.cs = BuildVerifierAIRPinned(
        static_cast<uint32_t>(out.normalized.pis.size()),
        out.normalized.pis, fam);
    if (out.normalized.columns.size() !=
        out.normalized.cs.n_columns) {
        out.note =
            "dual v5 aggregate: normalized column shape changed";
        return out;
    }
    for (const auto& [column, values] :
         out.normalized.cs.preprocessed) {
        if (column >= out.normalized.columns.size() ||
            values.size() != out.normalized.cs.n_rows) {
            out.note =
                "dual v5 aggregate: normalized preprocessed shape";
            return out;
        }
        out.normalized.columns[column] = values;
    }
    for (size_t child = 0; child < children.size(); ++child) {
        for (uint32_t lane = 0;
             lane < kRCFri3AlgDualNumLanes; ++lane) {
            const size_t pi_index =
                child * kRCFri3AlgDualNumLanes + lane;
            if (Fri3AlgDigestToUint256(
                    out.normalized.pis[pi_index]
                        .row_commit_root) !=
                out.child_pins[child].lane_row_root[lane]) {
                out.note =
                    "dual v5 aggregate: normalized lane root mismatch";
                return out;
            }
        }
    }
    const auto scan_begin = std::chrono::steady_clock::now();
    uint32_t first_bad_row = 0;
    std::string first_bad_name;
    out.normalized_violations = CountWitnessViolationsOnH(
        out.normalized.cs, out.normalized.columns,
        &first_bad_row, &first_bad_name);
    out.normalized_scan_micros =
        static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - scan_begin)
                .count());
    if (out.normalized_violations != 0) {
        out.note =
            "dual v5 aggregate: normalized witness violations=" +
            std::to_string(out.normalized_violations) +
            " first_row=" + std::to_string(first_bad_row) +
            " first=" + first_bad_name;
        return out;
    }
    const uint256 pins =
        CommitDualV5RecursiveChildPins(out.child_pins);
    const uint256 lane_pis =
        CommitDualV5LanePis(out.normalized.pis);
    HashWriter statement;
    statement << kDualV5ParentSeedDomain;
    statement << pins;
    statement << lane_pis;
    out.child_statement_commitment = statement.GetHash();
    out.ok = true;
    out.note =
        "dual v5 aggregate: native+normalized verifier witness accepted; "
        "next-row and R_T cross-openings constrained; "
        "SHA transcript equations remain outside AIR";
    return out;
}

DualV5AggregateResult ProveAggregateDualV5Checked(
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const std::vector<DualAlgAirProof>& children,
    const uint256& child_fs_seed,
    const uint256& parent_fs_seed,
    const VerifierAirFamilies& fam)
{
    DualV5AggregateResult out;
    DualV5AggregateWitness witness =
        BuildDualV5AggregateWitness(
            child_cs, children, child_fs_seed, fam);
    if (!witness.ok) {
        out.note = witness.note;
        return out;
    }
    out.lane_pis = witness.normalized.pis;
    out.child_pins = witness.child_pins;
    out.child_statement_commitment =
        witness.child_statement_commitment;
    const uint256 pin_commitment =
        CommitDualV5RecursiveChildPins(out.child_pins);
    const uint256 lane_pis_commitment =
        CommitDualV5LanePis(out.lane_pis);
    out.effective_fs_seed = DeriveDualV5ParentSeed(
        parent_fs_seed, pin_commitment,
        lane_pis_commitment);
    out.measurement = MeasureVerifierAIR(
        static_cast<uint32_t>(out.lane_pis.size()),
        out.lane_pis, fam);
    out.all_vcs_families_enabled =
        fam.row_merkle && fam.fold &&
        fam.deep && fam.per_point &&
        fam.next_row && fam.trace_binding;
    // Even with every current algebraic V_CS family selected, the
    // SHA/master-binding and full Fiat-Shamir replay equations are open.
    out.production_semantics_complete = false;

    const auto prove_begin = std::chrono::steady_clock::now();
    auto proved = aq::AirQuotientProve<Fp3, DualAlgB3>(
        witness.normalized.cs, witness.normalized.columns,
        out.effective_fs_seed, {});
    out.root_prove_micros =
        static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - prove_begin)
                .count());
    out.witness_satisfies = proved.division_exact;
    out.proof = std::move(proved.proof);
    out.ok = proved.ok && proved.division_exact;
    out.note = out.ok
                   ? "dual v5 aggregate: normalized parent proof emitted; "
                     "consensus authority remains off"
                   : "dual v5 aggregate: parent prove: " +
                         proved.note;
    return out;
}

bool VerifyAggregateDualV5Diagnostic(
    const DualAlgAirProof& root,
    const std::vector<ChildPublicInputs>& lane_pis,
    const std::vector<DualV5RecursiveChildPin>& child_pins,
    const uint256& parent_fs_seed,
    const VerifierAirFamilies& fam,
    std::string* why)
{
    auto fail = [&](const std::string& reason) {
        if (why != nullptr)
            *why = "dual-v5-aggregate:" + reason;
        return false;
    };
    if (child_pins.empty() || child_pins.size() > 4 ||
        lane_pis.size() !=
            child_pins.size() * kRCFri3AlgDualNumLanes) {
        return fail("child shape");
    }
    for (size_t child = 0; child < child_pins.size(); ++child) {
        const auto& pin = child_pins[child];
        if (!pin.host_reports_native_air_accepted ||
            !pin.host_reports_exact_transcript_replayed ||
            !pin.host_reports_ordered_lane_binding_checked ||
            pin.air_proof_commitment.IsNull() ||
            pin.transcript_commitment.IsNull() ||
            pin.master_statement_binding.IsNull()) {
            return fail("unverified child pin");
        }
        for (uint32_t lane = 0;
             lane < kRCFri3AlgDualNumLanes; ++lane) {
            const size_t pi_index =
                child * kRCFri3AlgDualNumLanes + lane;
            if (Fri3AlgDigestToUint256(
                    lane_pis[pi_index].row_commit_root) !=
                pin.lane_row_root[lane] ||
                pin.lane_child_binding[lane].IsNull()) {
                return fail("lane binding");
            }
        }
    }
    const uint256 effective_seed = DeriveDualV5ParentSeed(
        parent_fs_seed,
        CommitDualV5RecursiveChildPins(child_pins),
        CommitDualV5LanePis(lane_pis));
    const auto cs = BuildVerifierAIRPinned(
        static_cast<uint32_t>(lane_pis.size()),
        lane_pis, fam);
    std::string air_why;
    if (!aq::AirQuotientVerify<Fp3, DualAlgB3>(
            cs, root, effective_seed, &air_why)) {
        return fail("root:" + air_why);
    }
    if (why != nullptr)
        *why =
            "dual-v5-aggregate:ok-diagnostic-host-claims-not-recursive";
    return true;
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

AggregateResult ProveAggregateChecked(
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const std::vector<aq::AirQuotientProof<Fp3, AlgB3>>& children,
    const uint256& child_fs_seed, const uint256& fs_seed,
    const VerifierAirFamilies& fam)
{
    AggregateResult out;
    out.fs_seed = fs_seed;
    if (children.empty()) {
        out.note = "checked aggregate: no children";
        return out;
    }
    for (uint32_t child = 0; child < children.size(); ++child) {
        std::string why;
        if (!aq::AirQuotientVerify<Fp3, AlgB3>(
                child_cs, children[child], child_fs_seed, &why)) {
            out.note =
                "checked aggregate: child " +
                std::to_string(child) + " rejected: " + why;
            return out;
        }
    }
    out = ProveAggregate(
        child_cs, children, child_fs_seed, fs_seed, fam);
    if (out.ok && !out.witness_satisfies) {
        out.ok = false;
        out.note =
            "checked aggregate: accepted children produced inexact mirror";
    }
    return out;
}

namespace {

uint64_t EstimateAlgAirProofBytes(
    const aq::AirQuotientProof<Fp3, AlgB3>& proof)
{
    std::vector<unsigned char> batch;
    const size_t batch_size =
        SerializeFri3AlgBatchProof(proof.batch, batch);
    if (batch_size != batch.size()) {
        return std::numeric_limits<uint64_t>::max();
    }
    uint64_t bytes =
        static_cast<uint64_t>(batch_size) + 32 + 4;
    for (const auto& paths : proof.next_openings) {
        bytes += 4;
        for (const auto& path : paths) {
            bytes += 8;
            bytes +=
                static_cast<uint64_t>(path.values.size()) *
                3 * sizeof(uint64_t);
            bytes +=
                static_cast<uint64_t>(path.siblings.size()) *
                ah::kAlgHashDigestLen * sizeof(uint64_t);
        }
    }
    return bytes;
}

uint64_t MicrosSince(
    const std::chrono::steady_clock::time_point& start)
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start)
            .count());
}

} // namespace

AggregateExecutionProfile ProveAggregateCheckedProfiled(
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const std::vector<aq::AirQuotientProof<Fp3, AlgB3>>& children,
    const uint256& child_fs_seed, const uint256& fs_seed,
    const VerifierAirFamilies& fam)
{
    AggregateExecutionProfile out;
    out.aggregate.fs_seed = fs_seed;
    if (children.empty() || children.size() > 4) {
        out.note = "profiled aggregate: child count";
        return out;
    }
    for (const auto& child : children) {
        const uint64_t bytes = EstimateAlgAirProofBytes(child);
        if (bytes == std::numeric_limits<uint64_t>::max() ||
            out.child_proof_bytes >
                std::numeric_limits<uint64_t>::max() - bytes) {
            out.note = "profiled aggregate: proof size";
            return out;
        }
        out.child_proof_bytes += bytes;
    }

    auto phase = std::chrono::steady_clock::now();
    for (uint32_t child = 0; child < children.size(); ++child) {
        std::string why;
        if (!aq::AirQuotientVerify<Fp3, AlgB3>(
                child_cs, children[child],
                child_fs_seed, &why)) {
            out.child_verify_micros = MicrosSince(phase);
            out.note =
                "profiled aggregate: child " +
                std::to_string(child) +
                " rejected: " + why;
            return out;
        }
    }
    out.child_verify_micros = MicrosSince(phase);

    phase = std::chrono::steady_clock::now();
    AggregateWitness witness =
        BuildAggregateWitness(
            child_cs, children, child_fs_seed, fam);
    out.witness_build_micros = MicrosSince(phase);
    if (!witness.ok) {
        out.note =
            "profiled aggregate: witness: " + witness.note;
        return out;
    }
    out.witness_cells =
        static_cast<uint64_t>(witness.cs.n_rows) *
        witness.cs.n_columns;

    phase = std::chrono::steady_clock::now();
    uint32_t first_row = 0;
    std::string first_name;
    const uint32_t violations =
        CountWitnessViolationsOnH(
            witness.cs, witness.columns,
            &first_row, &first_name);
    out.witness_scan_micros = MicrosSince(phase);
    if (violations != 0) {
        out.note =
            "profiled aggregate: mirror violation row=" +
            std::to_string(first_row) +
            " constraint=" + first_name;
        return out;
    }

    out.aggregate.pis = witness.pis;
    out.aggregate.measurement =
        MeasureVerifierAIR(
            static_cast<uint32_t>(children.size()),
            witness.pis, fam);
    phase = std::chrono::steady_clock::now();
    aq::AirProveOptions options;
    options.force_commit_on_inexact = false;
    auto proved =
        aq::AirQuotientProve<Fp3, AlgB3>(
            witness.cs, witness.columns, fs_seed, options);
    out.root_prove_micros = MicrosSince(phase);
    out.aggregate.witness_satisfies =
        proved.division_exact;
    out.aggregate.proof = std::move(proved.proof);
    out.aggregate.ok =
        proved.ok && proved.division_exact;
    out.aggregate.note = proved.note;
    if (!out.aggregate.ok) {
        out.note =
            "profiled aggregate: root prove: " + proved.note;
        return out;
    }
    out.root_proof_bytes =
        EstimateAlgAirProofBytes(out.aggregate.proof);
    if (out.root_proof_bytes ==
        std::numeric_limits<uint64_t>::max()) {
        out.note = "profiled aggregate: root proof size";
        out.aggregate.ok = false;
        return out;
    }
    out.complete = true;
    out.note = "profiled aggregate: complete";
    return out;
}

StreamingAggregateLevelResult ProveAggregateLevelStreaming(
    uint64_t input_proofs, uint32_t max_children,
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const uint256& child_fs_seed,
    const uint256& level_fs_seed,
    const StreamingProofLoader& loader,
    const StreamingAggregateSink& sink,
    const VerifierAirFamilies& fam)
{
    StreamingAggregateLevelResult out;
    out.input_proofs = input_proofs;
    out.max_children = max_children;
    if (input_proofs == 0 || max_children == 0 ||
        max_children > 4 || !loader || !sink) {
        out.note = "streaming aggregate: invalid configuration";
        return out;
    }

    uint64_t input = 0;
    uint64_t node = 0;
    while (input < input_proofs) {
        const uint32_t count =
            static_cast<uint32_t>(
                std::min<uint64_t>(
                    max_children,
                    input_proofs - input));
        std::vector<aq::AirQuotientProof<Fp3, AlgB3>>
            children;
        children.reserve(count);
        uint64_t batch_bytes = 0;
        for (uint32_t child = 0; child < count; ++child) {
            aq::AirQuotientProof<Fp3, AlgB3> proof;
            std::string why;
            if (!loader(input + child, proof, &why)) {
                out.note =
                    "streaming aggregate: load: " + why;
                return out;
            }
            const uint64_t bytes =
                EstimateAlgAirProofBytes(proof);
            if (bytes ==
                    std::numeric_limits<uint64_t>::max() ||
                batch_bytes >
                    std::numeric_limits<uint64_t>::max() -
                        bytes) {
                out.note =
                    "streaming aggregate: proof size";
                return out;
            }
            batch_bytes += bytes;
            children.push_back(std::move(proof));
        }
        out.peak_loaded_children =
            std::max(out.peak_loaded_children, count);
        out.peak_child_proof_bytes =
            std::max(
                out.peak_child_proof_bytes, batch_bytes);

        HashWriter node_seed_writer;
        node_seed_writer << "BTX_RC_STREAMING_AGG_NODE_V1";
        node_seed_writer << level_fs_seed;
        node_seed_writer << node;
        const uint256 node_seed = node_seed_writer.GetHash();
        AggregateExecutionProfile profile =
            ProveAggregateCheckedProfiled(
                child_cs, children, child_fs_seed,
                node_seed, fam);
        out.child_verify_micros +=
            profile.child_verify_micros;
        out.witness_build_micros +=
            profile.witness_build_micros;
        out.witness_scan_micros +=
            profile.witness_scan_micros;
        out.root_prove_micros +=
            profile.root_prove_micros;
        out.peak_witness_cells =
            std::max(
                out.peak_witness_cells,
                profile.witness_cells);
        const uint64_t witness_bytes =
            profile.witness_cells >
                    std::numeric_limits<uint64_t>::max() /
                        sizeof(Fp3)
                ? std::numeric_limits<uint64_t>::max()
                : profile.witness_cells * sizeof(Fp3);
        const uint64_t live_bytes =
            witness_bytes >
                    std::numeric_limits<uint64_t>::max() -
                        batch_bytes
                ? std::numeric_limits<uint64_t>::max()
                : witness_bytes + batch_bytes;
        out.peak_estimated_live_bytes =
            std::max(
                out.peak_estimated_live_bytes,
                live_bytes);
        if (!profile.complete) {
            out.note =
                "streaming aggregate: node " +
                std::to_string(node) + ": " +
                profile.note;
            return out;
        }
        std::string sink_why;
        if (!sink(node, std::move(profile), &sink_why)) {
            out.note =
                "streaming aggregate: sink: " +
                sink_why;
            return out;
        }
        input += count;
        ++node;
    }
    out.output_nodes = node;
    out.complete = true;
    out.note = "streaming aggregate: complete";
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
