// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Gate tests for the Poseidon2-as-AIR gadget (matmul_v4_rc_air_recurse.{h,cpp};
// spec §6 Piece 3 of scratchpad/stage-c-buildable-spec.md):
//   (a) the honest witness for one Compress SATISFIES every constraint (each
//       eval() returns Fp3 zero) and the virtual output lanes match
//       alg_hash::Compress — completeness of the flattened 130-cell layout;
//   (b) DIFFERENTIAL: flipping any single witness cell (all 130 exhaustively,
//       plus targeted partial/full/input/last-round flips) makes at least one
//       constraint eval() nonzero — the system becomes unsatisfiable;
//   (c) THE FEASIBILITY MEASUREMENT (spec §3.4 gate): cells_per_perm == 130
//       ≤ 150, 122 constraints (118 deg-7 S-box + 4 deg-1 capacity), max
//       alg_degree 7, MaxComposedDegreeBound = 7·(N−1), QuotientLen ≈ 6N;
//   plus the Merkle-path glue (§3.2 B): an honest multi-level path satisfies
//   booleanity/wiring/capacity/accumulator/root constraints and dir-bit,
//   sibling, and accumulator tampers each break it.

#include <matmul/matmul_v4_rc_air_recurse.h>

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_alg_hash.h>
#include <matmul/matmul_v4_rc_gkr_field.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <vector>

namespace ah = matmul::v4::rc::alg_hash;
namespace aq = matmul::v4::rc::air_quotient;
namespace ar = matmul::v4::rc::air_recurse;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_air_recurse_tests, BasicTestingSetup)

namespace {

using gf::Fp3;

const ah::Digest kLeft{1, 2, 3, 4};
const ah::Digest kRight{5, 6, 7, 8};

/** All constraints of the single-permutation compression identity. */
std::vector<aq::AirConstraint<Fp3>> CompressConstraints(const ar::PermLayout& layout)
{
    std::vector<aq::AirConstraint<Fp3>> cons = ar::BuildPermRoundConstraints(layout);
    for (auto& c : ar::BuildCompressCapacityConstraints(layout)) cons.push_back(std::move(c));
    return cons;
}

/** Nonzero eval count on a single row (cur = next; no transitions here). */
int CountNonzero(const std::vector<aq::AirConstraint<Fp3>>& cons, const std::vector<Fp3>& row)
{
    int n = 0;
    for (const auto& c : cons) {
        if (!gf::IsZero(c.eval(row, row))) ++n;
    }
    return n;
}

} // namespace

// (a) Honest witness for one Compress satisfies every constraint and the
//     virtual digest equals alg_hash::Compress.
BOOST_AUTO_TEST_CASE(air_recurse_honest_compress_witness_satisfies)
{
    const ar::PermLayout layout{0};
    const auto cons = CompressConstraints(layout);
    const std::vector<Fp3> row = ar::BuildCompressWitnessRow(layout, kLeft, kRight);

    BOOST_CHECK_EQUAL(row.size(), ar::kPermCellsPerPerm);
    for (const auto& c : cons) {
        BOOST_CHECK_MESSAGE(gf::IsZero(c.eval(row, row)), "constraint not satisfied: " << c.name);
    }
    const ah::Digest want = ah::Compress(kLeft, kRight);
    for (uint32_t j = 0; j < ah::kAlgHashDigestLen; ++j) {
        BOOST_CHECK(gf::Eq(ar::PermOutputLane(layout, row, j), Fp3::FromFp(want[j])));
    }
}

// (a) All 12 virtual output affine forms reproduce Permute on a generic state.
BOOST_AUTO_TEST_CASE(air_recurse_output_forms_match_permute)
{
    const ar::PermLayout layout{0};
    ah::State st{};
    for (uint32_t i = 0; i < ah::kAlgHashT; ++i) st[i] = 100 + i;

    const ar::PermWitness w = ar::BuildPermWitness(st);
    std::vector<Fp3> row(layout.End(), Fp3::Zero());
    ar::WritePermWitness(layout, w, row);

    ah::State ref = st;
    ah::Permute(ref);
    for (uint32_t j = 0; j < ah::kAlgHashT; ++j) {
        BOOST_CHECK(gf::Eq(ar::PermOutputLane(layout, row, j), Fp3::FromFp(gf::Canonical(ref[j]))));
    }
    BOOST_CHECK_EQUAL(CountNonzero(ar::BuildPermRoundConstraints(layout), row), 0);
}

// (b) Differential: every single-cell flip (exhaustive over all 130 cells)
//     makes at least one constraint nonzero — the flipped S-box output is
//     pinned by its own identity, and x ↦ x^7 injectivity propagates input
//     flips into the round-0 identities.
BOOST_AUTO_TEST_CASE(air_recurse_single_cell_flip_unsatisfiable)
{
    const ar::PermLayout layout{0};
    const auto cons = CompressConstraints(layout);
    const std::vector<Fp3> row = ar::BuildCompressWitnessRow(layout, kLeft, kRight);

    for (uint32_t i = 0; i < ar::kPermCellsPerPerm; ++i) {
        std::vector<Fp3> bad = row;
        bad[i] = gf::Add(bad[i], Fp3::One());
        BOOST_CHECK_MESSAGE(CountNonzero(cons, bad) >= 1,
                            "flip of cell " << i << " left the system satisfiable");
    }
    // A last-round S-box flip must also move the virtual digest.
    std::vector<Fp3> bad = row;
    const uint32_t s = ar::SboxIndexFinalFull(3, 7);
    bad[layout.SboxCol(s)] = gf::Add(bad[layout.SboxCol(s)], Fp3::One());
    const ah::Digest want = ah::Compress(kLeft, kRight);
    bool digest_changed = false;
    for (uint32_t j = 0; j < ah::kAlgHashDigestLen; ++j) {
        if (!gf::Eq(ar::PermOutputLane(layout, bad, j), Fp3::FromFp(want[j]))) digest_changed = true;
    }
    BOOST_CHECK(digest_changed);
    BOOST_CHECK_GE(CountNonzero(cons, bad), 1);
}

// Merkle-path glue (§3.2 B): honest 3-level path satisfies everything,
// including the kTransition accumulator chain and the kLastRow root pin;
// dir-bit / sibling / accumulator tampers each break it.
BOOST_AUTO_TEST_CASE(air_recurse_merkle_glue_path)
{
    ar::MerkleGlueLayout g;
    g.perm = ar::PermLayout{0};
    g.dir_col = ar::kPermCellsPerPerm;      // 130
    g.acc_base = g.dir_col + 1;             // 131..134
    g.sib_base = g.acc_base + 4;            // 135..138
    const uint32_t width = ar::MerkleGlueLayout::kCellsPerLevel; // 139
    const auto glue = ar::BuildMerkleGlueConstraints(g);
    BOOST_CHECK_EQUAL(glue.size(), 17U); // 1 bool + 8 wiring + 4 capacity + 4 acc

    ah::Digest acc = ah::Compress(kLeft, kRight); // level-0 accumulator
    ah::Digest ref = acc;
    const bool dirs[3] = {false, true, true};
    std::vector<std::vector<Fp3>> rows;
    for (int lvl = 0; lvl < 3; ++lvl) {
        const ah::Digest sib{uint64_t(90 + lvl), uint64_t(91 + lvl), uint64_t(92 + lvl),
                             uint64_t(93 + lvl)};
        std::vector<Fp3> r(width, Fp3::Zero());
        ah::Digest parent{};
        ar::FillMerkleGlueRow(g, acc, sib, dirs[lvl], r, &parent);
        rows.push_back(std::move(r));
        acc = parent;
        ref = dirs[lvl] ? ah::Compress(sib, ref) : ah::Compress(ref, sib);
    }
    for (uint32_t j = 0; j < ah::kAlgHashDigestLen; ++j) {
        BOOST_CHECK_EQUAL(gf::Canonical(acc[j]), gf::Canonical(ref[j]));
    }
    // Terminal row: carries the root in mp_acc, itself an honest dummy block
    // (the kEverywhere families must hold on every row — see the header note).
    {
        std::vector<Fp3> r(width, Fp3::Zero());
        ar::FillMerkleGlueRow(g, acc, ah::Digest{0, 0, 0, 0}, false, r, nullptr);
        rows.push_back(std::move(r));
    }
    const auto root_pin = ar::BuildMerkleRootBoundaryConstraints(g.acc_base, ref);

    const auto eval_all = [&](const std::vector<std::vector<Fp3>>& rs) {
        int nz = 0;
        const size_t last = rs.size() - 1;
        for (size_t i = 0; i < rs.size(); ++i) {
            for (const auto& c : glue) {
                if (c.kind == aq::AirKind::kTransition && i == last) continue;
                const std::vector<Fp3>& next = (i == last) ? rs[i] : rs[i + 1];
                if (!gf::IsZero(c.eval(rs[i], next))) ++nz;
            }
        }
        for (const auto& c : root_pin) {
            if (!gf::IsZero(c.eval(rs[last], rs[last]))) ++nz;
        }
        return nz;
    };
    BOOST_CHECK_EQUAL(eval_all(rows), 0);

    auto tampered = rows;
    tampered[1][g.dir_col] = Fp3::FromFp(2); // non-boolean direction bit
    BOOST_CHECK_GE(eval_all(tampered), 1);
    tampered = rows;
    tampered[2][g.sib_base + 1] = gf::Add(tampered[2][g.sib_base + 1], Fp3::One());
    BOOST_CHECK_GE(eval_all(tampered), 1);
    tampered = rows;
    tampered[3][g.acc_base + 0] = gf::Add(tampered[3][g.acc_base + 0], Fp3::One());
    BOOST_CHECK_GE(eval_all(tampered), 1); // root pin breaks
}

// (c) THE FEASIBILITY MEASUREMENT (spec §3.4): the number the whole recursion
//     budget model rests on. Print the full breakdown.
BOOST_AUTO_TEST_CASE(air_recurse_feasibility_measurement)
{
    constexpr uint32_t kN = 1024;
    const ar::PermGadgetMeasurement m = ar::MeasureSinglePermCompress(kN);

    BOOST_TEST_MESSAGE("=== spec §3.4 feasibility measurement (one permutation) ===");
    BOOST_TEST_MESSAGE("cells_per_perm         = " << m.cells_per_perm
                                                   << " (12 input + 118 S-box witnesses)");
    BOOST_TEST_MESSAGE("n_constraints          = " << m.n_constraints << " ("
                                                   << m.n_sbox_constraints
                                                   << " S-box deg-7 + 4 capacity deg-1)");
    BOOST_TEST_MESSAGE("max alg_degree         = " << m.max_alg_degree);
    BOOST_TEST_MESSAGE("MaxComposedDegreeBound = " << m.max_composed_degree << " at N = "
                                                   << m.n_rows << " (= 7*(N-1))");
    BOOST_TEST_MESSAGE("QuotientLen            = " << m.quotient_len << " (~ 6N, spec §3.3)");
    BOOST_TEST_MESSAGE("cells per Merkle level = " << m.cells_per_merkle_level
                                                   << " (perm 130 + dir 1 + acc 4 + sib 4)");

    BOOST_CHECK_LE(m.cells_per_perm, 150U);   // the §3.4 feasibility gate
    BOOST_CHECK_EQUAL(m.cells_per_perm, 130U); // 118 S-box + 12 in (§3.4 exactly)
    BOOST_CHECK_EQUAL(m.n_constraints, 122U);
    BOOST_CHECK_EQUAL(m.n_sbox_constraints, 118U);
    BOOST_CHECK_EQUAL(m.max_alg_degree, 7U);
    BOOST_CHECK_EQUAL(m.max_composed_degree, 7ULL * (kN - 1));
    BOOST_CHECK_EQUAL(m.quotient_len, 7 * (kN - 1) - kN + 1);
    BOOST_CHECK_EQUAL(m.cells_per_merkle_level, 139U);

    // The assembled system itself (Piece-4 consumer interface).
    const aq::AirConstraintSystem<Fp3> cs = ar::BuildSinglePermCompressSystem(kN);
    BOOST_CHECK_EQUAL(cs.n_columns, 130U);
    BOOST_CHECK_EQUAL(cs.constraints.size(), 122U);
    BOOST_CHECK_EQUAL(cs.MaxComposedDegreeBound(), 7ULL * (kN - 1));
}

// ---------------------------------------------------------------------------
// Piece 4 (V_CS) — the differential equivalence (spec §6 Piece 4b). Fast path:
// "V_CS witness satisfies every constraint on H" ⇔ "native AirQuotientVerify
// accepts the child". Uses BuildAggregateWitness + CountWitnessViolationsOnH so
// the check runs without the (heavy) full FRI prove; the full FRI prove/verify
// wrapping is exercised by the standalone selfcheck (scratchpad/recurse4b_*).
// ---------------------------------------------------------------------------
namespace {
using AlgB3 = aq::AirFriBackendAlg<Fp3>;

aq::AirConstraintSystem<Fp3> ToyChildCS()
{
    aq::AirConstraintSystem<Fp3> cs;
    cs.n_rows = 2;
    cs.n_columns = 1;
    aq::AirConstraint<Fp3> b;
    b.name = "toy.bool";
    b.kind = aq::AirKind::kEverywhere;
    b.alg_degree = 2;
    b.eval = [](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
        return gf::Mul(cur[0], gf::Sub(cur[0], Fp3::One()));
    };
    cs.constraints.push_back(std::move(b));
    return cs;
}
uint256 SeedByte(unsigned char v)
{
    uint256 u;
    for (int i = 0; i < 32; ++i) u.data()[i] = static_cast<unsigned char>(v + i);
    return u;
}
// V_CS satisfiable (all constraints vanish on H) for a given child proof.
bool VcsSatisfiable(const aq::AirConstraintSystem<Fp3>& child_cs,
                    const aq::AirQuotientProof<Fp3, AlgB3>& c, const uint256& seed,
                    const ar::VerifierAirFamilies& fam)
{
    ar::AggregateWitness w = ar::BuildAggregateWitness(child_cs, {c}, seed, fam);
    if (!w.ok) return false;
    return ar::CountWitnessViolationsOnH(w.cs, w.columns) == 0;
}
} // namespace

BOOST_AUTO_TEST_CASE(piece4_vcs_differential_equivalence)
{
    const uint256 child_seed = SeedByte(11);
    const aq::AirConstraintSystem<Fp3> child_cs = ToyChildCS();
    const std::vector<std::vector<Fp3>> cols = {{Fp3::FromFp(0), Fp3::FromFp(1)}};

    auto pr = aq::AirQuotientProve<Fp3, AlgB3>(child_cs, cols, child_seed, {});
    BOOST_REQUIRE(pr.ok && pr.division_exact);
    const aq::AirQuotientProof<Fp3, AlgB3> child = pr.proof;
    BOOST_REQUIRE((aq::AirQuotientVerify<Fp3, AlgB3>(child_cs, child, child_seed, nullptr)));

    const ar::VerifierAirFamilies fam; // full mirror: row + fold + deep + per-point

    // (i) honest: native accepts AND V_CS satisfiable.
    BOOST_CHECK(VcsSatisfiable(child_cs, child, child_seed, fam));

    // (ii) tampered opened row value: native rejects AND V_CS UNsatisfiable.
    {
        auto c = child;
        c.batch.queries[0].row.values[0].c0 =
            gf::Add(c.batch.queries[0].row.values[0].c0, gf::FromU64(1));
        BOOST_CHECK((!aq::AirQuotientVerify<Fp3, AlgB3>(child_cs, c, child_seed, nullptr)));
        BOOST_CHECK(!VcsSatisfiable(child_cs, c, child_seed, fam));
    }
    // (iii) tampered fold value.
    {
        auto c = child;
        c.batch.queries[0].steps[0].even.c0 =
            gf::Add(c.batch.queries[0].steps[0].even.c0, gf::FromU64(1));
        BOOST_CHECK((!aq::AirQuotientVerify<Fp3, AlgB3>(child_cs, c, child_seed, nullptr)));
        BOOST_CHECK(!VcsSatisfiable(child_cs, c, child_seed, fam));
    }
    // (iv) tampered root/commitment.
    {
        auto c = child;
        c.batch.row_commit.root[0] = gf::Add(c.batch.row_commit.root[0], gf::FromU64(1));
        BOOST_CHECK((!aq::AirQuotientVerify<Fp3, AlgB3>(child_cs, c, child_seed, nullptr)));
        BOOST_CHECK(!VcsSatisfiable(child_cs, c, child_seed, fam));
    }
}

BOOST_AUTO_TEST_CASE(piece4_vcs_cell_budget_and_k2)
{
    const uint256 child_seed = SeedByte(11);
    const aq::AirConstraintSystem<Fp3> child_cs = ToyChildCS();
    const std::vector<std::vector<Fp3>> cols = {{Fp3::FromFp(0), Fp3::FromFp(1)}};
    auto pr = aq::AirQuotientProve<Fp3, AlgB3>(child_cs, cols, child_seed, {});
    BOOST_REQUIRE(pr.ok);
    const ar::ChildPublicInputs sh =
        ar::ExtractChildPublicInputs(child_cs, pr.proof, child_seed);
    const ar::VerifierAirFamilies fam;

    const ar::VerifierAirMeasurement m1 = ar::MeasureVerifierAIR(1, {sh}, fam);
    BOOST_TEST_MESSAGE("V_CS k=1 cells=" << m1.cell_count << " cols=" << m1.n_columns
                                         << " rows=" << m1.n_rows
                                         << " perms/query=" << m1.perms_per_query);
    BOOST_CHECK_EQUAL(m1.max_alg_degree, 7U);
    BOOST_CHECK_LE(m1.cell_count, (1ULL << 20)); // k=1 under 2^20

    const ar::VerifierAirMeasurement m2 = ar::MeasureVerifierAIR(2, {sh, sh}, fam);
    BOOST_TEST_MESSAGE("V_CS k=2 cells=" << m2.cell_count << " cols=" << m2.n_columns);
    BOOST_CHECK_LE(m2.cell_count, (1ULL << 21)); // k=2 under 2^21 (spec §3.4)

    // k=2 honest satisfiable; one tampered child ⇒ unsatisfiable.
    auto w = ar::BuildAggregateWitness(child_cs, {pr.proof, pr.proof}, child_seed, fam);
    BOOST_REQUIRE(w.ok);
    BOOST_CHECK_EQUAL(ar::CountWitnessViolationsOnH(w.cs, w.columns), 0U);
    auto c2 = pr.proof;
    c2.batch.queries[0].steps[0].even.c0 =
        gf::Add(c2.batch.queries[0].steps[0].even.c0, gf::FromU64(1));
    auto w2 = ar::BuildAggregateWitness(child_cs, {pr.proof, c2}, child_seed, fam);
    BOOST_REQUIRE(w2.ok);
    BOOST_CHECK_GT(ar::CountWitnessViolationsOnH(w2.cs, w2.columns), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
