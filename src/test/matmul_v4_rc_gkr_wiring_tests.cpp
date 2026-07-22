// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// CONSTRUCTION IV acceptance obligations (blueprint Appendix W):
//   (a) COMPLETENESS: u == u' (resp. u' == π(u)) satisfies the identity
//       EXACTLY — for every challenge, not just whp.
//   (b) SEPARATION: the reported −log2 bounds match the construction
//       (equality ℓ/|K|; grand product n/|K| single, squared for dual; K =
//       Fp3, |K| ≈ 2^192 — 2026-07-22 margin restoration) and the historical
//       Fp2 single-challenge grand product is documented BELOW target at
//       κ-sized columns (the origin of the standing dual mandate).
//   (c) COUNTEREXAMPLES (invalid assignments): one-entry difference FAILS
//       equality (the difference-MLE at rho is a NONZERO field element); a
//       non-permutation FAILS the grand product (both with the z built from
//       the wrong data and with a boundary cell overwritten to 1 — the
//       running-product residual is a NONZERO field element); honest cases
//       PASS exactly.

#include <matmul/matmul_v4_rc_gkr.h>
#include <matmul/matmul_v4_rc_gkr_field_ext.h>
#include <matmul/matmul_v4_rc_gkr_wiring.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <numeric>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;
namespace gf = matmul::v4::rc::gkr_field;
using gf::Fp2;

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_gkr_wiring_tests)

namespace {

// Cheap deterministic PRNG (test-only), matching the air-tests convention.
struct Lcg {
    uint64_t s;
    explicit Lcg(uint64_t seed) : s(seed) {}
    uint64_t next()
    {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        return s;
    }
    int8_t nexti8() { return static_cast<int8_t>(next() >> 56); }
};

std::vector<int8_t> RandomI8(Lcg& rng, size_t n)
{
    std::vector<int8_t> v(n);
    for (auto& x : v) x = rng.nexti8();
    return v;
}

std::vector<Fp2> RandomFp2(Lcg& rng, size_t n)
{
    std::vector<Fp2> v;
    v.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        v.push_back(Fp2{rng.next() % gf::kP, rng.next() % gf::kP});
    }
    return v;
}

std::vector<uint64_t> RandomPermutation(Lcg& rng, uint64_t n)
{
    std::vector<uint64_t> pi(n);
    std::iota(pi.begin(), pi.end(), uint64_t{0});
    for (uint64_t i = n; i > 1; --i) {
        const uint64_t j = rng.next() % i;
        std::swap(pi[i - 1], pi[j]);
    }
    return pi;
}

uint256 Seed(uint8_t tag)
{
    uint256 s;
    for (int i = 0; i < 32; ++i) s.data()[i] = static_cast<uint8_t>(tag * 13 + i * 7 + 1);
    return s;
}

} // namespace

// ----------------------------------------------------------------------------
// (a) EQUALITY — completeness and counterexamples
// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(wiring_equality_honest_passes_exactly)
{
    Lcg rng(0xC0FFEE01);
    const auto u = RandomI8(rng, 200); // non-power-of-two: exercises padding
    const auto c = rc::WiringEqualityFromInt8(u, u);
    BOOST_CHECK_EQUAL(c.len_u, 200U);
    BOOST_CHECK_EQUAL(c.ell, 8U); // 200 → 256 = 2^8

    // COMPLETENESS is EXACT: identical columns pass at EVERY rho, including
    // many independent random points (not a whp statement).
    for (uint32_t t = 0; t < 10; ++t) {
        const auto rho = rc::WiringChallengePoint(Seed(static_cast<uint8_t>(t)), "test_rho", t, c.ell);
        const auto r = rc::VerifyWiringEquality(c, rho);
        BOOST_CHECK_MESSAGE(r.ok, r.reason);
    }
    // FS-seeded convenience form.
    const auto r = rc::VerifyWiringEquality(c, Seed(1), /*claim_index=*/0);
    BOOST_CHECK_MESSAGE(r.ok, r.reason);
}

BOOST_AUTO_TEST_CASE(wiring_equality_int64_honest_passes)
{
    Lcg rng(0xC0FFEE02);
    std::vector<int64_t> u(64);
    for (auto& x : u) x = static_cast<int64_t>(rng.next()) >> 3; // |x| < 2^61
    const auto c = rc::WiringEqualityFromInt64(u, u);
    const auto r = rc::VerifyWiringEquality(c, Seed(2), 0);
    BOOST_CHECK_MESSAGE(r.ok, r.reason);
}

BOOST_AUTO_TEST_CASE(wiring_equality_single_entry_diff_fails)
{
    // COUNTEREXAMPLE (c): two columns differing in EXACTLY ONE entry must
    // FAIL — the difference multilinear is nonzero and the FS-derived rho
    // catches it (miss probability ell/|Fp2| ≈ 2^-125 at ell = 8).
    Lcg rng(0xC0FFEE03);
    const auto u = RandomI8(rng, 200);
    auto v = u;
    v[137] = static_cast<int8_t>(v[137] == 42 ? 43 : 42); // one entry differs
    const auto c = rc::WiringEqualityFromInt8(u, v);
    const auto r = rc::VerifyWiringEquality(c, Seed(3), 0);
    BOOST_CHECK(!r.ok);
    BOOST_CHECK_MESSAGE(r.reason.find("d~(rho)") != std::string::npos, r.reason);

    // Also under several independent challenge points (the identity is false
    // as a polynomial; any honest challenge rejects).
    for (uint32_t t = 0; t < 5; ++t) {
        const auto rho = rc::WiringChallengePoint(Seed(static_cast<uint8_t>(40 + t)), "test_rho", t, c.ell);
        BOOST_CHECK(!rc::VerifyWiringEquality(c, rho).ok);
    }
}

BOOST_AUTO_TEST_CASE(wiring_equality_length_mismatch_structural_reject)
{
    Lcg rng(0xC0FFEE04);
    const auto u = RandomI8(rng, 64);
    auto v = u;
    v.push_back(0); // same values, longer column: structurally NOT the same wire
    const auto c = rc::WiringEqualityFromInt8(u, v);
    const auto r = rc::VerifyWiringEquality(c, Seed(4), 0);
    BOOST_CHECK(!r.ok);
    BOOST_CHECK_MESSAGE(r.reason.find("structural") != std::string::npos, r.reason);
}

BOOST_AUTO_TEST_CASE(wiring_equality_opening_claims_emission)
{
    Lcg rng(0xC0FFEE05);
    const auto u = RandomI8(rng, 96);
    const auto c = rc::WiringEqualityFromInt8(u, u);
    const auto rho = rc::WiringChallengePoint(Seed(5), "wire_eq_rho", 0, c.ell);

    std::vector<rc::RCGkrOpeningClaim> claims;
    std::string why;
    BOOST_REQUIRE_MESSAGE(rc::WiringEqualityOpeningClaims(c, rho, /*u_col=*/11, /*v_col=*/29, claims, &why), why);
    BOOST_REQUIRE_EQUAL(claims.size(), 2U);
    BOOST_CHECK_EQUAL(claims[0].column_id, 11U);
    BOOST_CHECK_EQUAL(claims[1].column_id, 29U);
    BOOST_CHECK_EQUAL(claims[0].point.size(), c.ell);
    // Shared value: the checking-routine wiring test is d~(rho) = 0, i.e. the
    // two opened values coincide.
    BOOST_CHECK(gf::Eq(claims[0].value, claims[1].value));

    // Tampered pair refuses to emit a (false) shared-value claim.
    auto v = u;
    v[7] = static_cast<int8_t>(v[7] + 1);
    const auto bad = rc::WiringEqualityFromInt8(u, v);
    std::vector<rc::RCGkrOpeningClaim> bad_claims;
    BOOST_CHECK(!rc::WiringEqualityOpeningClaims(bad, rho, 11, 29, bad_claims, &why));
    BOOST_CHECK(bad_claims.empty());
}

// ----------------------------------------------------------------------------
// (b) PERMUTATION — completeness and counterexamples
// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(wiring_permutation_honest_passes_exactly)
{
    Lcg rng(0xBEEF0001);
    const uint64_t n = 64;
    const auto u = RandomFp2(rng, n);
    const auto pi = RandomPermutation(rng, n);
    std::vector<Fp2> v(n);
    for (uint64_t j = 0; j < n; ++j) v[j] = u[pi[j]]; // claim convention: v_j = u_{pi(j)}

    // COMPLETENESS is EXACT: the honest instance telescopes to z_n = 1 for
    // EVERY challenge pair (the factor multisets coincide term-by-term).
    for (uint8_t t = 0; t < 5; ++t) {
        const auto d = rc::BuildWiringPermutationDual(u, v, pi, Seed(t), /*pair_index=*/t);
        BOOST_REQUIRE_MESSAGE(d.inst1.build_ok, d.inst1.build_note);
        const auto r = rc::VerifyWiringPermutationDual(d);
        BOOST_CHECK_MESSAGE(r.ok, r.reason);
    }

    // Identity permutation degenerates to the copy constraint.
    std::vector<uint64_t> id(n);
    std::iota(id.begin(), id.end(), uint64_t{0});
    const auto d_id = rc::BuildWiringPermutationDual(u, u, id, Seed(9), 0);
    const auto r_id = rc::VerifyWiringPermutationDual(d_id);
    BOOST_CHECK_MESSAGE(r_id.ok, r_id.reason);
}

BOOST_AUTO_TEST_CASE(wiring_permutation_non_permutation_fails)
{
    // COUNTEREXAMPLE (c): u' NOT a permutation of u must FAIL.
    Lcg rng(0xBEEF0002);
    const uint64_t n = 64;
    const auto u = RandomFp2(rng, n);
    const auto pi = RandomPermutation(rng, n);
    std::vector<Fp2> v(n);
    for (uint64_t j = 0; j < n; ++j) v[j] = u[pi[j]];
    v[3] = gf::Add(v[3], Fp2::One()); // now {v_j} is NOT the claimed multiset

    // Invalid assignment, variant 1: z is built faithfully from the WRONG
    // data — the grand product does not telescope to 1 (Schwartz–Zippel:
    // separation probability ≤ n/|Fp2|).
    auto c = rc::BuildWiringPermutation(u, v, pi, rc::WiringChallengeFp2(Seed(10), "b", 0, 0),
                                        rc::WiringChallengeFp2(Seed(10), "g", 0, 0));
    BOOST_REQUIRE_MESSAGE(c.build_ok, c.build_note);
    const auto r1 = rc::VerifyWiringPermutation(c);
    BOOST_CHECK(!r1.ok);
    BOOST_CHECK_MESSAGE(r1.reason.find("grand product") != std::string::npos, r1.reason);

    // Variant 2: overwrite the boundary z_n := 1 — then some STEP identity fails.
    c.z[n] = Fp2::One();
    const auto r2 = rc::VerifyWiringPermutation(c);
    BOOST_CHECK(!r2.ok);
    BOOST_CHECK_MESSAGE(r2.reason.find("step identity") != std::string::npos, r2.reason);

    // Variant 3: perturb an interior z cell to re-balance — a neighboring
    // step breaks instead (the chain is rigid: fixing one row breaks the next).
    auto c3 = rc::BuildWiringPermutation(u, v, pi, c.beta, c.gamma);
    c3.z[17] = gf::Add(c3.z[17], Fp2::One());
    BOOST_CHECK(!rc::VerifyWiringPermutation(c3).ok);

    // Dual form rejects too (either instance suffices).
    const auto d = rc::BuildWiringPermutationDual(u, v, pi, Seed(11), 0);
    BOOST_CHECK(!rc::VerifyWiringPermutationDual(d).ok);
}

BOOST_AUTO_TEST_CASE(wiring_permutation_position_binding)
{
    // Same VALUE multiset, wrong POSITIONS: v = u (values unchanged) but the
    // claimed wiring pi is a non-trivial permutation and u has distinct
    // entries — the (index, value) pairing must catch it.
    Lcg rng(0xBEEF0003);
    const uint64_t n = 32;
    const auto u = RandomFp2(rng, n); // distinct whp
    auto pi = RandomPermutation(rng, n);
    bool nontrivial = false;
    for (uint64_t j = 0; j < n; ++j) nontrivial |= (pi[j] != j);
    BOOST_REQUIRE(nontrivial);

    const auto d = rc::BuildWiringPermutationDual(u, /*v=*/u, pi, Seed(12), 0);
    const auto r = rc::VerifyWiringPermutationDual(d);
    BOOST_CHECK(!r.ok);
}

BOOST_AUTO_TEST_CASE(wiring_permutation_structural_rejects)
{
    Lcg rng(0xBEEF0004);
    const uint64_t n = 16;
    const auto u = RandomFp2(rng, n);

    // pi not injective.
    std::vector<uint64_t> bad_pi(n, 0);
    const auto c1 = rc::BuildWiringPermutation(u, u, bad_pi, Fp2::One(), Fp2::One());
    BOOST_CHECK(!c1.build_ok);
    BOOST_CHECK(!rc::VerifyWiringPermutation(c1).ok);

    // pi out of range.
    std::vector<uint64_t> oob(n);
    std::iota(oob.begin(), oob.end(), uint64_t{0});
    oob[5] = n + 3;
    const auto c2 = rc::BuildWiringPermutation(u, u, oob, Fp2::One(), Fp2::One());
    BOOST_CHECK(!c2.build_ok);

    // size mismatch.
    std::vector<uint64_t> id(n);
    std::iota(id.begin(), id.end(), uint64_t{0});
    auto v_short = u;
    v_short.pop_back();
    const auto c3 = rc::BuildWiringPermutation(u, v_short, id, Fp2::One(), Fp2::One());
    BOOST_CHECK(!c3.build_ok);
}

BOOST_AUTO_TEST_CASE(wiring_permutation_zero_factor_fail_closed)
{
    // gamma chosen so that factor 0 vanishes: u_0 + beta*0 + gamma = 0.
    // Build must fail closed (resample), and verify must reject the instance.
    Lcg rng(0xBEEF0005);
    const uint64_t n = 8;
    const auto u = RandomFp2(rng, n);
    std::vector<uint64_t> id(n);
    std::iota(id.begin(), id.end(), uint64_t{0});
    const Fp2 beta = Fp2::Zero();
    const Fp2 gamma = gf::Neg(u[0]);
    const auto c = rc::BuildWiringPermutation(u, u, id, beta, gamma);
    BOOST_CHECK(!c.build_ok);
    BOOST_CHECK_MESSAGE(c.build_note.find("zero factor") != std::string::npos, c.build_note);
    BOOST_CHECK(!rc::VerifyWiringPermutation(c).ok);
}

BOOST_AUTO_TEST_CASE(wiring_transpose_permutation)
{
    // Materialized transpose reuse: v = uᵀ bound via MakeTransposePermutation.
    Lcg rng(0xBEEF0006);
    const uint32_t rows = 8, cols = 5;
    const auto u8 = RandomI8(rng, size_t{rows} * cols);
    std::vector<int8_t> v8(size_t{rows} * cols);
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t c = 0; c < cols; ++c) {
            v8[size_t{c} * rows + r] = u8[size_t{r} * cols + c];
        }
    }
    const auto pi = rc::MakeTransposePermutation(rows, cols);
    // Check the pi convention directly: v[j] = u[pi[j]].
    for (size_t j = 0; j < pi.size(); ++j) BOOST_REQUIRE_EQUAL(v8[j], u8[pi[j]]);

    std::vector<Fp2> u, v;
    for (int8_t x : u8) u.push_back(Fp2::FromFp(gf::FromSigned(x)));
    for (int8_t x : v8) v.push_back(Fp2::FromFp(gf::FromSigned(x)));
    const auto d = rc::BuildWiringPermutationDual(u, v, pi, Seed(13), 0);
    const auto r = rc::VerifyWiringPermutationDual(d);
    BOOST_CHECK_MESSAGE(r.ok, r.reason);

    // One tampered cell breaks it.
    auto v_bad = v;
    v_bad[9] = gf::Add(v_bad[9], Fp2::One());
    const auto db = rc::BuildWiringPermutationDual(u, v_bad, pi, Seed(13), 0);
    BOOST_CHECK(!rc::VerifyWiringPermutationDual(db).ok);
}

// ----------------------------------------------------------------------------
// SEPARATION BOUND numbers (acceptance obligation (b))
// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(wiring_separation_bound_numbers)
{
    const double tol = 0.05;

    // Challenge field = Fp3 (|K| ≈ 2^192, 2026-07-22 margin restoration; the
    // numbers hold once the WiringChallengeFp2 draw moves to Fp3 — see
    // INTEGRATION_REPORT.md "Fp2 → Fp3 challenge sites").
    // Equality at the κ = 2^28 column cap (ell = 28): ell/|K| ⇒
    // 192 − log2(28) = 187.19 bits pre-grinding; 147.19 after the 2^40 budget.
    const double eq_pre = rc::WiringEqualitySeparationBits(28, /*after_grinding=*/false);
    const double eq_post = rc::WiringEqualitySeparationBits(28, true);
    BOOST_CHECK_CLOSE_FRACTION(eq_pre, 187.19, tol);
    BOOST_CHECK_CLOSE_FRACTION(eq_post, 147.19, tol);
    BOOST_CHECK(eq_post >= 64.0); // clears the target with ≥83 bits margin

    // Grand product, SINGLE challenge pair at n = 2^28: n/|K| ⇒ 164.0 pre,
    // 124.0 post over Fp3. THE DUAL MANDATE STAYS: over the historical Fp2
    // draw the single pair was 100.0 pre / 60.0 post — BELOW the 2^-64 target
    // (asserted from kRCGkrWiringFieldBitsFp2 so the record cannot drift) —
    // and G4 keeps the single form structurally unreachable.
    const double p_single_pre = rc::WiringPermutationSeparationBits(uint64_t{1} << 28, false, false);
    const double p_single_post = rc::WiringPermutationSeparationBits(uint64_t{1} << 28, false, true);
    BOOST_CHECK_CLOSE_FRACTION(p_single_pre, 164.0, tol);
    BOOST_CHECK_CLOSE_FRACTION(p_single_post, 124.0, tol);
    const double p_single_post_fp2 = rc::kRCGkrWiringFieldBitsFp2 - 28.0 - 40.0;
    BOOST_CHECK_CLOSE_FRACTION(p_single_post_fp2, 60.0, tol);
    BOOST_CHECK(p_single_post_fp2 < 64.0); // the dual-mandate origin, on record

    // DUAL (β,γ) at n = 2^28: (n/|K|)² ⇒ 328.0 pre, 288.0 post — cleared.
    const double p_dual_post = rc::WiringPermutationSeparationBits(uint64_t{1} << 28, true, true);
    BOOST_CHECK_CLOSE_FRACTION(p_dual_post, 288.0, tol);
    BOOST_CHECK(p_dual_post >= 64.0);

    // Single-challenge ceiling constant: RETAINED at the conservative
    // Fp2-derived n = 2^23 (which netted 105 pre / 65 post over Fp2); over
    // Fp3 it nets 129 post.
    BOOST_CHECK_EQUAL(rc::kRCGkrWiringSingleChallengeMaxN, uint64_t{1} << 23);
    const double p_ceiling_post =
        rc::WiringPermutationSeparationBits(rc::kRCGkrWiringSingleChallengeMaxN, false, true);
    BOOST_CHECK_CLOSE_FRACTION(p_ceiling_post, 129.0, tol);
    BOOST_CHECK(p_ceiling_post >= 64.0);
    BOOST_CHECK(rc::kRCGkrWiringFieldBitsFp2 - 23.0 - 40.0 >= 64.0);
}

// ----------------------------------------------------------------------------
// Cross-layer binding helper (extract_out(L) == input(L+1))
// ----------------------------------------------------------------------------

namespace {

rc::RCGkrV7WireWitness MakeWire(Lcg& rng, uint32_t m, uint32_t n, uint32_t k)
{
    rc::RCGkrV7WireWitness w;
    w.m = m;
    w.n = n;
    w.k = k;
    w.A = RandomI8(rng, size_t{m} * k);
    w.B = RandomI8(rng, size_t{k} * n);
    w.Y.assign(size_t{m} * n, 0);
    w.extract_in.assign(size_t{m} * n, 0);
    w.extract_out = RandomI8(rng, size_t{m} * n);
    return w;
}

} // namespace

BOOST_AUTO_TEST_CASE(bind_adjacent_layer_wires_honest_chain)
{
    Lcg rng(0xD00D0001);
    // wire0 (4×6) → wire1 A (4×6, direct copy) ; wire1 out (4×5) →
    // wire2 A (5×4, transposed copy) ; wire2 out (5×7) → wire3 (no
    // compatible input: Λ-definitional).
    auto w0 = MakeWire(rng, 4, 6, 3);
    auto w1 = MakeWire(rng, 4, 5, 6);
    auto w2 = MakeWire(rng, 5, 7, 4);
    auto w3 = MakeWire(rng, 9, 2, 11);

    // Honest wiring: consumer inputs equal producer extract_out.
    w1.A = w0.extract_out; // direct: dims (4,6) == (4,6)
    for (uint32_t r = 0; r < 4; ++r) { // transposed: w2.A (5×4) = w1.outᵀ
        for (uint32_t c = 0; c < 5; ++c) {
            w2.A[size_t{c} * 4 + r] = w1.extract_out[size_t{r} * 5 + c];
        }
    }

    const std::vector<rc::RCGkrV7WireWitness> wires{w0, w1, w2, w3};
    const auto bindings = rc::BindAdjacentLayerWires(wires);
    BOOST_REQUIRE_EQUAL(bindings.size(), 3U);
    BOOST_CHECK(bindings[0].kind == rc::WiringBindingKind::Equality);
    BOOST_CHECK_EQUAL(bindings[0].consumer_operand, 'A');
    BOOST_CHECK(bindings[1].kind == rc::WiringBindingKind::Permutation);
    BOOST_CHECK_EQUAL(bindings[1].consumer_operand, 'A');
    BOOST_CHECK(bindings[2].kind == rc::WiringBindingKind::Unbound);

    const auto r = rc::VerifyLayerBindings(bindings, Seed(20));
    BOOST_CHECK_MESSAGE(r.ok, r.reason);
    BOOST_CHECK_MESSAGE(r.reason.find("2 bound") != std::string::npos, r.reason);
    BOOST_CHECK_MESSAGE(r.reason.find("1 unbound") != std::string::npos, r.reason);

    // fail_on_unbound escalates the Λ-definitional pair.
    BOOST_CHECK(!rc::VerifyLayerBindings(bindings, Seed(20), /*fail_on_unbound=*/true).ok);
}

BOOST_AUTO_TEST_CASE(bind_adjacent_layer_wires_tamper_fails)
{
    Lcg rng(0xD00D0002);
    auto w0 = MakeWire(rng, 4, 6, 3);
    auto w1 = MakeWire(rng, 4, 5, 6);
    w1.A = w0.extract_out;

    // Change ONE entry of the consumer operand: the equality binding for pair
    // 0→1 must FAIL — the cross-layer invalid assignment is caught by the
    // polynomial identity (difference-MLE nonzero at rho), not a hash chain.
    w1.A[13] = static_cast<int8_t>(w1.A[13] + 1);
    const std::vector<rc::RCGkrV7WireWitness> wires{w0, w1};
    const auto bindings = rc::BindAdjacentLayerWires(wires);
    BOOST_REQUIRE_EQUAL(bindings.size(), 1U);
    BOOST_REQUIRE(bindings[0].kind == rc::WiringBindingKind::Equality);
    const auto r = rc::VerifyLayerBindings(bindings, Seed(21));
    BOOST_CHECK(!r.ok);
    BOOST_CHECK_MESSAGE(r.reason.find("pair 0->1") != std::string::npos, r.reason);
}

BOOST_AUTO_TEST_SUITE_END()
