// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ============================================================================
// CONSTRUCTION I acceptance obligations (matmul_v4_rc_gkr_eval.{h,cpp}) —
// finite-field algebra over F_p (Goldilocks) / K = F_{p^2}:
//
//  (a) COMPLETENESS: a valid assignment (u, z, y = ũ(z)) — every check an
//      exact polynomial identity — is accepted exactly.
//  (b) SEPARATION BOUND: the composed eq-kernel summation-reduction +
//      batched low-degree opening detects any invalid claim set except with
//      probability ≤ 2^-74 after the 2^40 grinding budget
//      (RCGkrConstructionISeparationBits(); derivation in the header).
//  (c) COUNTEREXAMPLES: on explicit invalid assignments the checked identity
//      evaluates to a NONZERO field element and the checking routine rejects:
//      an internally-consistent transcript for y' ≠ ũ(z) is detected exactly
//      at the Stage-2 root binding (eval:identity_z1/z2); a wrong batched
//      γ-combination is detected at Stage 1; the valid assignment passes.
// ============================================================================

#include <matmul/matmul_v4_rc_fri.h>
#include <matmul/matmul_v4_rc_gkr.h>
#include <matmul/matmul_v4_rc_gkr_eval.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_gkr_eval_tests, BasicTestingSetup)

namespace {

uint256 MakeSeed(uint8_t fill)
{
    uint256 seed;
    for (int i = 0; i < 32; ++i) seed.data()[i] = fill;
    return seed;
}

std::vector<rc::Fp2> MakeColumn(size_t n, int64_t a, int64_t b)
{
    std::vector<rc::Fp2> c(n);
    for (size_t i = 0; i < n; ++i) {
        c[i] = gf::FromSigned2(a * static_cast<int64_t>(i * i) + b * static_cast<int64_t>(i) - 7);
    }
    return c;
}

std::vector<rc::Fp2> MakePoint(std::initializer_list<std::pair<uint64_t, uint64_t>> coords)
{
    std::vector<rc::Fp2> p;
    for (const auto& c : coords) p.push_back(gf::Fp2{c.first, c.second});
    return p;
}

/** eq(r, bits(index)) = Π_b (index_b ? r_b : 1−r_b) — little-endian. */
rc::Fp2 EqFactorAt(const std::vector<rc::Fp2>& r, uint32_t index)
{
    rc::Fp2 acc = rc::Fp2::One();
    for (size_t b = 0; b < r.size(); ++b) {
        acc = gf::Mul(acc, ((index >> b) & 1u) ? r[b] : gf::Sub(rc::Fp2::One(), r[b]));
    }
    return acc;
}

/** Direct double-sum matrix MLE M̃(r_row, r_col) for a row-major rows×cols
 *  matrix with power-of-two cols (independent recomputation for the helper
 *  tests — deliberately NOT via RCGkrMleEval1D2). */
rc::Fp2 MatrixMleDirect(const std::vector<rc::Fp2>& mat, uint32_t rows, uint32_t cols,
                        const std::vector<rc::Fp2>& r_row, const std::vector<rc::Fp2>& r_col)
{
    rc::Fp2 acc = rc::Fp2::Zero();
    for (uint32_t i = 0; i < rows; ++i) {
        for (uint32_t j = 0; j < cols; ++j) {
            acc = gf::Add(acc, gf::Mul(gf::Mul(mat[static_cast<size_t>(i) * cols + j],
                                               EqFactorAt(r_row, i)),
                                       EqFactorAt(r_col, j)));
        }
    }
    return acc;
}

} // namespace

// ---------------------------------------------------------------------------
// Obligation (b): the separation constants and their composition inputs.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(constr1_separation_constants)
{
    // Composed bound: −log2(ε_total) ≥ 76 post-grinding (header derivation,
    // Fp3 episode regime): FS subtotal (γ + sumcheck + μ + λ/w + dual-OOD)
    // over |K| = p³ ≈ 2^192 ≤ 2^-178.4, ×2^40 ⇒ 2^-138.4; + batched-FRI query
    // term 2^-76.8 (field-independent, now the floor); + SHA256d term 2^-88;
    // total < 2^-76. (Historical Fp2 value: 74, FS-subtotal-dominated.)
    BOOST_CHECK_EQUAL(rc::RCGkrConstructionISeparationBits(), 76);
    BOOST_CHECK_GE(rc::RCGkrConstructionISeparationBits(), rc::kRCFriTargetSoundnessBits + 10);
    // The Stage-2 substrate this composes with (single batched instance).
    BOOST_CHECK_EQUAL(rc::FriBatchSoundnessBoundBits(), 76);
    BOOST_CHECK(rc::FriBatchClaimedBitsMeetTarget());
    // The M ≤ 2^12 / W ≤ 2^12 caps assumed by the (M−1)/|K|, (W+2)/|K| terms.
    BOOST_CHECK_EQUAL(rc::kRCGkrEvalArgMaxClaims, 1u << 12);
    BOOST_CHECK_EQUAL(rc::kRCFriBatchMaxColumns, 1u << 12);
}

// ---------------------------------------------------------------------------
// Obligation (a): COMPLETENESS — valid assignment accepted exactly.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(constr1_completeness_valid_assignment)
{
    const uint256 seed = MakeSeed(0x5A);
    // Three columns; c1 has a NON-power-of-two logical length (zero-pad path).
    std::vector<std::vector<rc::Fp2>> cols;
    cols.push_back(MakeColumn(16, 3, -2)); // column 0, ν=4
    cols.push_back(MakeColumn(12, 5, 11)); // column 1, logical 12 < 16
    cols.push_back(MakeColumn(8, -4, 9));  // column 2, covered by a 3-dim point

    // Four claims, two on the same column (γ-batched into ONE reduction):
    const auto z0 = MakePoint({{3, 1}, {5, 0}, {2, 9}, {8, 4}});
    const auto z1 = MakePoint({{7, 6}, {1, 12}, {0, 3}, {10, 2}});
    const auto z2 = MakePoint({{4, 4}, {9, 1}, {6, 7}, {2, 2}});
    const auto z3 = MakePoint({{11, 5}, {3, 8}, {7, 0}}); // dim 3 covers len 8
    std::vector<rc::RCGkrOpeningClaim> claims;
    claims.push_back({0, z0, rc::RCGkrMleEval1D2(cols[0], z0)});
    claims.push_back({0, z1, rc::RCGkrMleEval1D2(cols[0], z1)});
    claims.push_back({1, z2, rc::RCGkrMleEval1D2(cols[1], z2)});
    claims.push_back({2, z3, rc::RCGkrMleEval1D2(cols[2], z3)});

    const auto pr = rc::BatchedOpeningProve(claims, cols, seed);
    BOOST_REQUIRE_MESSAGE(pr.ok, pr.note);
    std::string why;
    BOOST_CHECK_MESSAGE(rc::BatchedOpeningVerify(claims, pr.proof, seed, &why), why);

    // Stage-1 core consistency: the residuals ARE the column MLEs at the
    // common reduced point r (checked against the independent evaluator).
    const uint32_t nu = 4;
    const auto open = rc::EvalOpenProve(claims, cols, nu, MakeSeed(0x66));
    BOOST_REQUIRE_MESSAGE(open.ok, open.note);
    BOOST_REQUIRE_EQUAL(open.reduced.size(), 3u); // three DISTINCT columns
    BOOST_REQUIRE_EQUAL(open.r.size(), nu);
    for (const auto& red : open.reduced) {
        BOOST_CHECK(gf::Eq(red.value, rc::RCGkrMleEval1D2(cols[red.column_id], open.r)));
    }
    // And the Stage-1 checking routine replays it (statement-bound transcript).
    std::vector<rc::RCGkrOpeningClaim> reduced;
    uint256 bind;
    BOOST_CHECK_MESSAGE(
        rc::EvalOpenVerify(claims, nu, open.proof, MakeSeed(0x66), &reduced, &bind, &why), why);
    BOOST_CHECK_EQUAL(reduced.size(), open.reduced.size());
    BOOST_CHECK(bind == open.bind_digest);
}

// ---------------------------------------------------------------------------
// Obligation (c1): an internally-consistent transcript for y' ≠ ũ(z).
// The Stage-1 algebra is repaired (round sums + chain end), so rejection MUST
// come exactly from the Stage-2 root binding: the Lemma-1.2 identity
// evaluates NONZERO at the bound OOD points (eval:identity_z1).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(constr1_invalid_scalar_detected_at_root_binding)
{
    const uint256 seed = MakeSeed(0xC3);
    std::vector<std::vector<rc::Fp2>> cols;
    cols.push_back(MakeColumn(16, 2, 1));
    cols.push_back(MakeColumn(16, -3, 4));

    const auto z0 = MakePoint({{5, 2}, {8, 8}, {1, 6}, {9, 3}});
    const auto z1 = MakePoint({{2, 7}, {4, 4}, {12, 1}, {0, 5}});
    std::vector<rc::RCGkrOpeningClaim> claims;
    claims.push_back({0, z0, rc::RCGkrMleEval1D2(cols[0], z0)});
    claims.push_back({1, z1, rc::RCGkrMleEval1D2(cols[1], z1)});

    // The invalid assignment: y' = y + 1 ≠ ũ(z) on claim 0.
    auto bad_claims = claims;
    bad_claims[0].value = gf::Add(bad_claims[0].value, rc::Fp2::One());

    // The plain constructing routine refuses to build a transcript for it.
    const auto refused = rc::BatchedOpeningProve(bad_claims, cols, seed);
    BOOST_CHECK(!refused.ok);
    BOOST_CHECK_MESSAGE(refused.note.find("claims disagree") != std::string::npos, refused.note);

    // The strongest internally-consistent transcript survives Stage 1 …
    const auto forged = rc::BatchedOpeningProveInvalidAssignmentForTest(bad_claims, cols, seed);
    BOOST_REQUIRE_MESSAGE(forged.ok, forged.note);
    // … and is detected exactly at the Stage-2 binding: the checking routine
    // reaches (and fails) the OOD identity, i.e. Stage 1 passed.
    std::string why;
    BOOST_CHECK(!rc::BatchedOpeningVerify(bad_claims, forged.proof, seed, &why));
    BOOST_CHECK_MESSAGE(why.rfind("eval:identity", 0) == 0, "expected eval:identity_*, got: " + why);

    // Sanity: the same pipeline on the VALID claims still passes.
    const auto ok = rc::BatchedOpeningProve(claims, cols, seed);
    BOOST_REQUIRE_MESSAGE(ok.ok, ok.note);
    BOOST_CHECK_MESSAGE(rc::BatchedOpeningVerify(claims, ok.proof, seed, &why), why);
}

// ---------------------------------------------------------------------------
// Obligation (c2): a wrong batched γ-combination is detected at Stage 1.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(constr1_wrong_gamma_combination_detected)
{
    const uint256 seed = MakeSeed(0x3D);
    std::vector<std::vector<rc::Fp2>> cols;
    cols.push_back(MakeColumn(8, 1, 3));
    cols.push_back(MakeColumn(8, 6, -1));

    const auto z0 = MakePoint({{4, 9}, {2, 2}, {7, 1}});
    const auto z1 = MakePoint({{1, 3}, {8, 5}, {0, 6}});
    std::vector<rc::RCGkrOpeningClaim> claims;
    claims.push_back({0, z0, rc::RCGkrMleEval1D2(cols[0], z0)});
    claims.push_back({1, z1, rc::RCGkrMleEval1D2(cols[1], z1)});

    const auto pr = rc::BatchedOpeningProve(claims, cols, seed);
    BOOST_REQUIRE_MESSAGE(pr.ok, pr.note);
    std::string why;
    BOOST_REQUIRE(rc::BatchedOpeningVerify(claims, pr.proof, seed, &why));

    // (i) Permuted claims ⇒ the γ-powers multiply the WRONG summands (the
    // combination Σ γ^m·y_m and every eq-weight reassigns) ⇒ Stage-1 reject.
    {
        std::vector<rc::RCGkrOpeningClaim> permuted{claims[1], claims[0]};
        BOOST_CHECK(!rc::BatchedOpeningVerify(permuted, pr.proof, seed, &why));
    }
    // (ii) A foreign FS seed ⇒ different γ (and batch challenges) ⇒ reject.
    {
        BOOST_CHECK(!rc::BatchedOpeningVerify(claims, pr.proof, MakeSeed(0x3E), &why));
    }
    // (iii) A tampered round message breaks the round-sum chain.
    {
        auto bad = pr.proof;
        bad.sumcheck.rounds[0].g0 = gf::Add(bad.sumcheck.rounds[0].g0, rc::Fp2::One());
        BOOST_CHECK(!rc::BatchedOpeningVerify(claims, bad, seed, &why));
        BOOST_CHECK_MESSAGE(why == "eqopen:round_sum", why);
    }
    // (iv) A tampered residual breaks the chain-end identity.
    {
        auto bad = pr.proof;
        bad.sumcheck.column_at_r[0] = gf::Add(bad.sumcheck.column_at_r[0], rc::Fp2::One());
        BOOST_CHECK(!rc::BatchedOpeningVerify(claims, bad, seed, &why));
        BOOST_CHECK_MESSAGE(why == "eqopen:final", why);
    }
}

// ---------------------------------------------------------------------------
// Shape guards: a point that does not cover the column's logical length would
// silently change the claim's meaning (low sub-cube identity) — rejected.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(constr1_point_cover_guards)
{
    const uint256 seed = MakeSeed(0x71);
    std::vector<std::vector<rc::Fp2>> cols;
    cols.push_back(MakeColumn(8, 2, 5)); // needs ≥ 3 coordinates

    const auto z_short = MakePoint({{3, 3}, {6, 1}}); // dim 2 < log2(8)
    std::vector<rc::RCGkrOpeningClaim> claims;
    claims.push_back({0, z_short, rc::Fp2::One()});
    const auto pr = rc::BatchedOpeningProve(claims, cols, seed);
    BOOST_CHECK(!pr.ok);
    BOOST_CHECK_MESSAGE(pr.note.find("point_short") != std::string::npos, pr.note);

    // Checking-routine side: an otherwise-valid transcript queried with a
    // short point is refused before any field work.
    const auto z_ok = MakePoint({{3, 3}, {6, 1}, {2, 8}});
    std::vector<rc::RCGkrOpeningClaim> good;
    good.push_back({0, z_ok, rc::RCGkrMleEval1D2(cols[0], z_ok)});
    const auto ok = rc::BatchedOpeningProve(good, cols, seed);
    BOOST_REQUIRE_MESSAGE(ok.ok, ok.note);
    std::string why;
    BOOST_CHECK(!rc::BatchedOpeningVerify(claims, ok.proof, seed, &why));
    BOOST_CHECK_MESSAGE(why == "constr1:claim_point_short", why);
}

// ---------------------------------------------------------------------------
// G1 — operand-scalar binding pieces: a_at_r = Ã(r_i, r_k), b_at_r =
// B̃(r_k, r_j) as opening claims against the flat row-major columns, the free
// transpose view, and the deterministic gf = a·b chain-end identity.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(g1_operand_scalar_binding)
{
    // 4×4 row-major matrix, power-of-two stride ⇒ flat index = (i<<2)|j.
    const uint32_t rows = 4, colsn = 4, nu = 4;
    const std::vector<rc::Fp2> M = MakeColumn(16, 7, -3);
    const auto r_row = MakePoint({{2, 5}, {9, 1}});
    const auto r_col = MakePoint({{6, 4}, {3, 7}});

    // Direct double-sum vs the flat-column MLE at the built point.
    const rc::Fp2 direct = MatrixMleDirect(M, rows, colsn, r_row, r_col);
    const auto claim = rc::RCGkrMatrixOpeningClaim(/*column_id=*/0, r_row, r_col, nu, direct);
    BOOST_CHECK_EQUAL(claim.point.size(), nu);
    BOOST_CHECK(gf::Eq(rc::RCGkrMleEval1D2(M, claim.point), direct));

    // Transpose is free (§1.2): M̃ᵀ(r,s) = M̃(s,r) against the SAME column.
    std::vector<rc::Fp2> MT(16);
    for (uint32_t i = 0; i < rows; ++i)
        for (uint32_t j = 0; j < colsn; ++j) MT[j * rows + i] = M[i * colsn + j];
    const rc::Fp2 direct_t = MatrixMleDirect(MT, colsn, rows, r_row, r_col);
    const auto claim_t =
        rc::RCGkrMatrixOpeningClaim(0, r_row, r_col, nu, direct_t, /*transposed=*/true);
    BOOST_CHECK(gf::Eq(rc::RCGkrMleEval1D2(M, claim_t.point), direct_t));

    // gf = a_at_r · b_at_r is an exact identity check — never carried free.
    const rc::Fp2 a = gf::Fp2{123, 45}, b = gf::Fp2{67, 89};
    BOOST_CHECK(rc::RCGkrCheckFinalEvalBinding(gf::Mul(a, b), a, b));
    BOOST_CHECK(!rc::RCGkrCheckFinalEvalBinding(gf::Add(gf::Mul(a, b), rc::Fp2::One()), a, b));
}

// ---------------------------------------------------------------------------
// G2 — layer-claim → trace-column-segment binding: aligned segment selection
// via 0/1 high coordinates, and the two-chunk top-variable glue.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(g2_segment_and_chunk_binding)
{
    const std::vector<rc::Fp2> col = MakeColumn(16, 5, 2); // 4 segments of 4
    const auto r = MakePoint({{8, 3}, {1, 9}});

    for (uint64_t s = 0; s < 4; ++s) {
        std::vector<rc::Fp2> seg(col.begin() + s * 4, col.begin() + (s + 1) * 4);
        const auto p = rc::RCGkrSegmentPoint(r, s, /*nu_col=*/4);
        BOOST_CHECK_EQUAL(p.size(), 4u);
        BOOST_CHECK(gf::Eq(rc::RCGkrMleEval1D2(col, p), rc::RCGkrMleEval1D2(seg, r)));
    }

    // Two-chunk glue: Ỹ(r̂, top) = (1−r_top)·chunk0̃(r̂) + r_top·chunk1̃(r̂).
    const auto r3 = MakePoint({{4, 4}, {7, 2}, {5, 5}});
    const rc::Fp2 r_top = gf::Fp2{13, 6};
    std::vector<rc::Fp2> chunk0(col.begin(), col.begin() + 8);
    std::vector<rc::Fp2> chunk1(col.begin() + 8, col.end());
    std::vector<rc::Fp2> glued_point = r3;
    glued_point.push_back(r_top);
    const rc::Fp2 folded = rc::RCGkrFoldChunkClaims(rc::RCGkrMleEval1D2(chunk0, r3),
                                                    rc::RCGkrMleEval1D2(chunk1, r3), r_top);
    BOOST_CHECK(gf::Eq(rc::RCGkrMleEval1D2(col, glued_point), folded));
}

// ---------------------------------------------------------------------------
// G5 — residual binding: acc̃(r) = Ỹ(r) + X̃(r) by MLE linearity; a carried
// acc that differs is rejected deterministically.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(g5_residual_binding)
{
    const std::vector<rc::Fp2> Y = MakeColumn(8, 3, 1);
    const std::vector<rc::Fp2> X = MakeColumn(8, -2, 6);
    std::vector<rc::Fp2> acc(8);
    for (size_t i = 0; i < 8; ++i) acc[i] = gf::Add(Y[i], X[i]);

    const auto r = MakePoint({{9, 2}, {3, 3}, {6, 8}});
    const rc::Fp2 y_at_r = rc::RCGkrMleEval1D2(Y, r);
    const rc::Fp2 x_at_r = rc::RCGkrMleEval1D2(X, r);
    const rc::Fp2 acc_at_r = rc::RCGkrMleEval1D2(acc, r);
    BOOST_CHECK(gf::Eq(acc_at_r, rc::RCGkrResidualAcc(y_at_r, x_at_r)));
    BOOST_CHECK(rc::RCGkrCheckResidualAcc(acc_at_r, y_at_r, x_at_r));
    BOOST_CHECK(
        !rc::RCGkrCheckResidualAcc(gf::Add(acc_at_r, rc::Fp2::One()), y_at_r, x_at_r));
}

// ---------------------------------------------------------------------------
// The native eq evaluator agrees with the eq-kernel coefficient table (the
// §1.3 correspondence both Stage-1 routines rely on).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(eq_kernel_native_agreement)
{
    const auto z = MakePoint({{5, 7}, {2, 1}, {11, 4}});
    const auto kern = rc::RCGkrEqKernelCoeffs(z);
    BOOST_REQUIRE_EQUAL(kern.size(), 8u);
    for (uint32_t i = 0; i < 8; ++i) {
        // Boolean point bits(i): eq(z, bits(i)) is the kernel coefficient.
        std::vector<rc::Fp2> bits;
        for (uint32_t b = 0; b < 3; ++b) {
            bits.push_back(((i >> b) & 1u) ? rc::Fp2::One() : rc::Fp2::Zero());
        }
        BOOST_CHECK(gf::Eq(rc::RCGkrEqAt(z, bits), kern[i]));
        BOOST_CHECK(gf::Eq(EqFactorAt(z, i), kern[i]));
    }
    // Σ_i v_i·kern[i] = ṽ(z) — the inner-product form of the MLE claim.
    const auto v = MakeColumn(8, 4, -9);
    rc::Fp2 ip = rc::Fp2::Zero();
    for (size_t i = 0; i < 8; ++i) ip = gf::Add(ip, gf::Mul(v[i], kern[i]));
    BOOST_CHECK(gf::Eq(ip, rc::RCGkrMleEval1D2(v, z)));
}

BOOST_AUTO_TEST_SUITE_END()
