// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// G1–G5 INTEGRATION red-team + composed-bound pins (ENC_RC v7 winner proof).
//
// The three Fable constructions were merged and wired into VerifyWinnerProofV7 as
// the in-circuit relations G1–G5 (Construction I evaluation opening; II Extract
// composition; III fixed-reference-vector membership; IV dual-challenge wiring).
// This suite proves TWO things the base v7 soundness suite does not:
//
//  (1) Every internally-consistent episode forgery that the native §5 grounding
//      rejects is ALSO rejected by the standalone construction relations
//      (CheckWinnerProofRelationsV7 → "v7:g<N>:*") — i.e. the constructions catch
//      the forgery, not only the int64 re-derivation. The honest proof passes all
//      of G1–G5.
//
//  (2) The COMPOSED separation bound across the four constructions + the batched-
//      FRI backend is pinned term-by-term and in total, PARAMETRIC in the FRI
//      proximity bound. SHIPPED STATE (2026-07-22 Fp3 challenge cutover): fold
//      Q = 128 with Fp3 challenges on the episode-v7 path (Fri3 codeword FRI).
//      The FS subtotal lifts 72 → 135.5 (|F| = p³ ≈ 2^192), so the composed
//      bound is NON-VACUOUS and FRI-QUERY-dominated at ≈ 76.8 bits
//      (ε_total ≤ 2^-76.8) — clearing 2^-64 by ≈ 12.8 bits (ADEQUATE) and the
//      ≥ 74-bit restored-margin bar. (Historical: Q=128/Fp2 ≈ 71.9
//      FS-dominated; Q=116/Fp2 ≈ 65.8 with an inadequate < 2-bit margin.)
//      The single-challenge wiring path remains excluded by the standing dual
//      mandate (structural; its Fp2 record 60 < 64 is the origin — the Fp3
//      value 124 does NOT relax the mandate). The arbiter stays hard-disabled
//      (kRCGkrFormalSoundnessReady).
//
// HARD RULES honored: int64 reference immutable; arbiter OFF; heights INT32_MAX;
// no existing adversarial test weakened (this suite only ADDS coverage).

#include <arith_uint256.h>
#include <consensus/params.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_fri.h>
#include <matmul/matmul_v4_rc_gkr.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <limits>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_gkr_integration_tests, BasicTestingSetup)

namespace {

CBlockHeader MakeRCHeader(uint64_t nonce)
{
    CBlockHeader header;
    header.nVersion = 0x20000004;
    header.nTime = 1'770'000'000;
    header.nBits = 0x207fffff;
    header.nNonce64 = nonce;
    header.nNonce = static_cast<uint32_t>(nonce);
    for (int i = 0; i < 32; ++i) {
        header.hashPrevBlock.data()[i] = static_cast<unsigned char>(0x51);
        header.hashMerkleRoot.data()[i] = static_cast<unsigned char>(0xa3);
        header.seed_a.data()[i] = static_cast<unsigned char>(0x11);
        header.seed_b.data()[i] = static_cast<unsigned char>(0x22);
    }
    return header;
}

arith_uint256 MaxTarget()
{
    arith_uint256 t;
    t = ~t;
    return t;
}

bool StartsWith(const std::string& s, const char* p) { return s.rfind(p, 0) == 0; }

} // namespace

// ============================================================================
// Honest v7 proof satisfies EVERY G1–G5 in-circuit relation.
// ============================================================================
BOOST_AUTO_TEST_CASE(gkr_integration_honest_passes_all_relations)
{
    BOOST_CHECK_EQUAL(Consensus::Params{}.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK(!rc::EnvRCGkrArbiterEnabled());

    const auto base_header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 real_dig = rc::RecomputeResidentCurriculumReference(base_header, params, 0);
    const arith_uint256 target = MaxTarget();

    CBlockHeader h = base_header;
    h.matmul_digest = real_dig;
    const auto honest = rc::ProveWinnerEpisodeV7(h, params, 0, target, real_dig);
    BOOST_REQUIRE_MESSAGE(honest.timing.ok, honest.timing.note);

    // Full verifier accepts (the G1–G5 gate runs inside it).
    std::string vwhy;
    BOOST_REQUIRE_MESSAGE(rc::VerifyWinnerProofV7(honest.proof, h, 0, target, &vwhy), vwhy);

    // Standalone relations module accepts every relation.
    std::string gwhy;
    const bool gok = rc::VerifyWinnerRelationsV7ForTest(honest.proof, h, 0, target, &gwhy);
    BOOST_CHECK_MESSAGE(gok, std::string("honest failed a G1-G5 relation: ") + gwhy);

    const rc::RCGkrRelationsResult r =
        rc::CheckWinnerProofRelationsV7(honest.proof, h, 0, target);
    BOOST_CHECK(r.ok);
    BOOST_CHECK_GT(r.n_tiles, 0u); // G3 actually ran the Extract composition
}

// ============================================================================
// Each internally-consistent forgery is ALSO caught by the constructions
// (v7:g<N>:*), not only by the native re-derivation grounding.
// ============================================================================
BOOST_AUTO_TEST_CASE(gkr_integration_forgeries_rejected_at_construction_relation)
{
    const auto base_header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 real_dig = rc::RecomputeResidentCurriculumReference(base_header, params, 0);
    const arith_uint256 target = MaxTarget();

    struct Case {
        rc::RCGkrIndepMaliciousKind kind;
        const char* name;
        const char* expected_prefix; // the construction relation that catches it
    };
    const Case cases[] = {
        {rc::RCGkrIndepMaliciousKind::ArbitraryAbFactorization, "ArbitraryAbFactorization", "v7:g1:"},
        {rc::RCGkrIndepMaliciousKind::FabricatedTraceWires, "FabricatedTraceWires", "v7:g1:"},
        {rc::RCGkrIndepMaliciousKind::IdenticalFabricatedLookup, "IdenticalFabricatedLookup", "v7:g3:"},
        {rc::RCGkrIndepMaliciousKind::FabricatedExtractIO, "FabricatedExtractIO", "v7:g5:"},
        {rc::RCGkrIndepMaliciousKind::UnrelatedLayerRoots, "UnrelatedLayerRoots", "v7:g4:"},
    };

    for (const Case& c : cases) {
        const auto forged = rc::ProveMaliciousEpisodeV7ForTest(base_header, params, 0, target,
                                                               real_dig, c.kind);
        BOOST_REQUIRE_MESSAGE(forged.timing.ok,
                              std::string(c.name) + ": forgery prover failed: " +
                                  forged.timing.note);

        CBlockHeader h = base_header;
        h.matmul_digest = forged.proof.claimed_digest;

        // The standalone construction relations reject the forgery.
        std::string gwhy;
        const bool gok = rc::VerifyWinnerRelationsV7ForTest(forged.proof, h, 0, target, &gwhy);
        BOOST_TEST_MESSAGE(std::string("[") + c.name + "] g-relation why=\"" + gwhy + "\"");
        BOOST_CHECK_MESSAGE(!gok, std::string("SOUNDNESS BUG: G1-G5 accepted forgery ") + c.name);
        // Hard: rejection is at a construction relation, not a trivial/ok state.
        BOOST_CHECK_MESSAGE(StartsWith(gwhy, "v7:g"),
                            std::string(c.name) + ": g-relation reason \"" + gwhy +
                                "\" is not a v7:g<N> construction relation");
        // Documented: the specific relation that catches this kind.
        BOOST_CHECK_MESSAGE(StartsWith(gwhy, c.expected_prefix),
                            std::string(c.name) + ": expected " + c.expected_prefix + ", got \"" +
                                gwhy + "\"");

        // And the full verifier still rejects it (native grounding first, as the
        // base v7 soundness suite asserts — unchanged here).
        std::string vwhy;
        const bool vok = rc::VerifyWinnerProofV7(forged.proof, h, 0, target, &vwhy);
        BOOST_CHECK_MESSAGE(!vok, std::string("SOUNDNESS BUG: v7 accepted forgery ") + c.name);
    }
}

// ============================================================================
// COMPOSED separation bound — pin each term and the total, PARAMETRIC in FRI.
// ============================================================================
BOOST_AUTO_TEST_CASE(gkr_integration_composed_separation_bound)
{
    const rc::RCGkrComposedBound b =
        rc::RCGkrComposedSeparation(rc::kRCGkrFriProximityBitsV5);

    // Per-construction terms (post-grind, −log2 acceptance). SHIPPED STATE:
    // Q = 128 fold + Fp3 challenge field on the episode-v7 path
    // (|F| = p³ ≈ 2^192, Fri3 codeword FRI). Legacy Fp2 values in trailing
    // comments (v6/coupled paths, which remain Fp2).
    BOOST_CHECK_CLOSE(b.construction_ii_bits, 144.0, 1e-6);  // composition   (Fp2 was 80)
    BOOST_CHECK_CLOSE(b.construction_iii_bits, 256.0, 1e-6); // dual-α membership (Fp2 was 128)
    BOOST_CHECK_CLOSE(b.construction_iv_bits, 147.19, 1e-3); // wiring = min(eq, dual) (Fp2 83.19)
    BOOST_CHECK_CLOSE(b.wiring_single_bits, 124.0, 1e-6);    // excluded single path (Fp2 was 60)
    BOOST_CHECK_CLOSE(b.sha_bits, 88.0, 1e-6);               // field-independent
    BOOST_CHECK_CLOSE(b.fri_proximity_bits, 76.80, 1e-6);    // Q=128 fold (was 65.85 at Q=116)
    // Construction I standalone sub-bound (floored by the same FRI query term).
    BOOST_CHECK_CLOSE(b.construction_i_bits, 76.0, 1e-6);    // (Fp2 was 74)
    // The FS subtotal itself (Fp3, |F| ≈ 2^192) — now far ABOVE the FRI floor.
    BOOST_CHECK_CLOSE(rc::kRCGkrFsSubtotalSepBits, 135.5, 1e-6); // (Fp2 was 72)

    // The dual-challenge wiring MUST be used: the mandate is STRUCTURAL (G4
    // enforces dual). Its origin is the Fp2 single-challenge record (60 < 64);
    // over Fp3 the single form is 124 — above target — but the field lift does
    // NOT relax the mandate.
    BOOST_CHECK_GE(b.wiring_single_bits, 64.0); // Fp3 single form: 124
    BOOST_CHECK_GE(rc::kRCGkrWiringPermutationDualSepBits, 64.0);
    BOOST_CHECK_GT(rc::kRCGkrWiringPermutationDualSepBits, b.wiring_single_bits);

    // Composed total on the SOUND v5 fold at Q = 128 (Fp3 challenges): the FS
    // subtotal (135.5) sits ≈ 59 bits above the FRI floor (76.80), so the
    // bound is FRI-QUERY-dominated at ≈ 76.8, clearing 2^-64 by ≈ 12.8 bits —
    // ADEQUATE, and ABOVE the 74-bit restored-margin bar.
    BOOST_CHECK(b.fri_dominated);            // FRI (76.80) is the floor, not FS (135.5)
    BOOST_CHECK_GT(b.composed_bits, 64.0);   // clears the target (non-vacuous)
    BOOST_CHECK_GT(b.composed_bits, 76.7);   // actual value ≈ 76.80
    BOOST_CHECK_LT(b.composed_bits, 76.81);  // ...just under the FRI floor (log-sum-exp)
    BOOST_CHECK_GE(b.composed_bits, rc::kRCGkrComposedTargetBits); // ≥ the 74-bit Fp3 bar
    BOOST_CHECK(b.clears_target);
    BOOST_CHECK(!b.inadequate_margin);       // margin ≈ 12.8 ≥ 2 bits: adequacy gate passes
    BOOST_CHECK_GT(b.margin_bits, 12.7);     // actual margin ≈ 12.80 bits
    BOOST_CHECK_LT(b.margin_bits, 12.9);
    // Composed ≤ the smallest INCLUDED term (the FRI proximity floor, 76.80),
    // and within a fraction of a bit of it (log-sum-exp of the larger terms).
    BOOST_CHECK_LE(b.composed_bits, b.fri_proximity_bits + 1e-9);
    BOOST_CHECK_GT(b.composed_bits, b.fri_proximity_bits - 0.5);
    // No INCLUDED term is below target (wiring_single_bits is tracked
    // separately and — over Fp3 — is itself above 64).
    BOOST_CHECK(!b.any_term_below_target);

    // The convenience accessor equals the parametric value at the v5 fold floor.
    BOOST_CHECK_CLOSE(rc::RCGkrComposedSeparationBits(), b.composed_bits, 1e-6);

    // Plugging the conservative integer FRI helper (76 — identical for the
    // Fp2 and Fp3 stacks, field-independent) still lands query-dominated just
    // under 76 and above the 74-bit bar.
    const double integer_view =
        rc::RCGkrComposedSeparationBits(static_cast<double>(rc::Fri3BatchSoundnessBoundBits()));
    BOOST_CHECK_GT(integer_view, 75.9);
    BOOST_CHECK_LT(integer_view, 76.0);
    BOOST_CHECK_GE(integer_view, rc::kRCGkrComposedTargetBits); // ≥ 74 (Fp3 regime)
    BOOST_CHECK_EQUAL(rc::Fri3BatchSoundnessBoundBits(), rc::FriBatchSoundnessBoundBits());
    // Historical record: at the Q=116 fold floor (65.85) the composed bound
    // was ≈ 65.8 with an INADEQUATE (< 2-bit) margin — the state Q=128 fixed
    // (and the Fp3 cutover then lifted the FS subtotal off the floor).
    const rc::RCGkrComposedBound old_b = rc::RCGkrComposedSeparation(65.85);
    BOOST_CHECK_LT(old_b.composed_bits, 66.0);
    BOOST_CHECK_GT(old_b.composed_bits, 65.7);
    BOOST_CHECK(old_b.inadequate_margin);
    BOOST_CHECK(old_b.fri_dominated);        // at Q=116 the FRI floor (65.85) WAS the min
    BOOST_TEST_MESSAGE("composed (SHIPPED: v5 fold, Q=128, Fp3) = " +
                       std::to_string(b.composed_bits) +
                       " ; margin over 64 = " + std::to_string(b.margin_bits) +
                       " ; integer-FRI view = " + std::to_string(integer_view) +
                       " ; historical Q=116 floor = " + std::to_string(old_b.composed_bits));
}

BOOST_AUTO_TEST_SUITE_END()
