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
//      proximity bound. It is FRI-dominated (≈ 65.8 bits, conservatively ≥ 65.7)
//      and CONDITIONAL on the FRI fold being a sound low-degree test; the single-
//      challenge wiring path (60 bits) is BELOW 64 and is excluded (dual
//      mandatory).
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
        rc::RCGkrComposedSeparation(rc::kRCGkrFriProximityBitsV4);

    // Per-construction terms (post-grind, −log2 acceptance).
    BOOST_CHECK_CLOSE(b.construction_ii_bits, 80.0, 1e-6);   // composition
    BOOST_CHECK_CLOSE(b.construction_iii_bits, 128.0, 1e-6); // dual-α membership
    BOOST_CHECK_CLOSE(b.construction_iv_bits, 83.19, 1e-3);  // wiring = min(eq, dual)
    BOOST_CHECK_CLOSE(b.wiring_single_bits, 60.0, 1e-6);     // excluded single path
    BOOST_CHECK_CLOSE(b.sha_bits, 88.0, 1e-6);
    BOOST_CHECK_CLOSE(b.fri_proximity_bits, 65.85, 1e-6);
    // Construction I standalone sub-bound (absorbed into the FS subtotal).
    BOOST_CHECK_CLOSE(b.construction_i_bits, 74.0, 1e-6);

    // The dual-challenge wiring MUST be used: the single-challenge grand product
    // is below the 64-bit target (this is the mandate).
    BOOST_CHECK_LT(b.wiring_single_bits, 64.0);
    BOOST_CHECK_GE(rc::kRCGkrWiringPermutationDualSepBits, 64.0);

    // Composed total: FRI-dominated. Clears 64 but by < 2 bits, and only
    // CONDITIONALLY on the FRI fold being a sound low-degree test.
    BOOST_CHECK(b.fri_conditional);
    BOOST_CHECK_GT(b.composed_bits, 64.0);
    BOOST_CHECK_LT(b.composed_bits, 66.0);
    // Composed ≤ the smallest INCLUDED term (the FRI proximity term), and within
    // a fraction of a bit of it (log-sum-exp of the larger terms).
    BOOST_CHECK_LE(b.composed_bits, b.fri_proximity_bits + 1e-9);
    BOOST_CHECK_GT(b.composed_bits, b.fri_proximity_bits - 0.5);
    // No INCLUDED term is below target (the below-64 path is the EXCLUDED single
    // wiring form, tracked separately).
    BOOST_CHECK(!b.any_term_below_target);
    BOOST_CHECK(b.clears_target);

    // The convenience accessor equals the parametric value at the v4 base.
    BOOST_CHECK_CLOSE(rc::RCGkrComposedSeparationBits(), b.composed_bits, 1e-6);

    // HARDENED path: plugging the batched-FRI target (FriBatchSoundnessBoundBits
    // = 76.x, Q=128) lifts the composed bound (FS subtotal becomes the floor).
    const double hardened =
        rc::RCGkrComposedSeparationBits(static_cast<double>(rc::FriBatchSoundnessBoundBits()));
    BOOST_CHECK_GT(hardened, b.composed_bits);
    BOOST_CHECK_GT(hardened, 70.0);
    BOOST_TEST_MESSAGE("composed (v4 base) = " + std::to_string(b.composed_bits) +
                       " ; composed (Q=128 hardened) = " + std::to_string(hardened));
}

BOOST_AUTO_TEST_SUITE_END()
