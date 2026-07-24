// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// GENUINE v7 soundness red-team (ENC_RC v7 GKR; G1–G5 fold gate).
//
// Motivation: the pre-existing gkr_v7_defeats_independent_malicious test is WEAK.
// It bit-flips an honest v7 proof, so every rejection fires at a TRIVIAL
// consistency gate (final_eval, digest_from_roots, logup_alpha, transcript_hash,
// column_not_grounded) BEFORE the real security mechanism — the in-circuit
// grounding AIRs. It never proves v7 defeats an INTERNALLY-CONSISTENT forgery
// that survives the trivial gates and REACHES the deep mechanism.
//
// This test closes that hole. SCOPE — do not overstate: exactly the FIVE
// EPISODE kinds below are genuine full-malicious-prover, SNARK-sound attacks
// that reach the deep security mechanism. The coupled UnrelatedBankPages case
// (bottom of file) is NOT a full fabricated-witness proof and is NOT in that
// class — see its own banner for why (re-execution-soundness, not SNARK-
// soundness).
//
// The five EPISODE kinds (ArbitraryAbFactorization, FabricatedTraceWires,
// IdenticalFabricatedLookup, FabricatedExtractIO, UnrelatedLayerRoots) each
// build an internally-consistent v7-format forgery via
// ProveMaliciousEpisodeV7ForTest, which runs the FULL honest v7 prover
// machinery (batched-FRI + per-layer sumcheck + eval-argument + dual-α LogUp +
// transcript) over a FABRICATED witness. The resulting RCGkrProofV7 passes
// EVERY trivial/algebraic gate of VerifyWinnerProofV7 (pow_bind,
// header/digest/sigma binding, digest_from_roots, round-seed chain, Λ layout,
// column_not_grounded, FriBatchVerify, per-layer sumcheck, final_eval
// endpoint/product, eval-argument, FS-bound LogUp α's). It can therefore only
// be rejected by the DEEP security mechanism: the §5.4/§5.7/§6.3 in-circuit
// MxExpand / Extract-sampler / tile-tree grounding AIRs (why prefix
// "v7:ground:") or the dual-α LogUp aggregate (why prefix "v7:logup:"). We
// assert the EXACT rejecting relation is one of those and NOT a trivial gate.
// This is genuine SNARK-soundness: the episode verifier accepts a proof only if
// the in-circuit AIRs bind, so a fabricated-witness proof that survives the
// trivial gates is the correct threat model.
//
// HONESTY: for the committed-witness episode kinds (arbitrary A/B
// factorization, fabricated trace, fabricated extract_out) reaching the
// mechanism REQUIRES running the honest prover over the fabricated witness —
// the attacker cannot forge these cheaply. The one exception is the
// non-committed pre-Extract accumulator extract_in, which a cheap honest-proof
// mutation can perturb to reach extract_in:binding with zero prover work; we
// exercise that too.
//
// COUPLED (UnrelatedBankPages) — SCOPE CAVEAT: the coupled verifier is
// re-execution-sound, NOT SNARK-sound. ProveWinnerCoupledV7 is sole-authority:
// it re-derives the entire trace and refuses any digest that is not the
// immutable int64 coupled reference, so a full internally-consistent coupled
// forgery is NOT constructible at all. The coupled case therefore reaches its
// intended F11 page-selection binding (coupled:column_not_grounded) via an
// honest-proof column-root mutation BY NECESSITY — not because we chose the
// weaker attack, but because the sole-authority re-execution admits no
// stronger one. Full coupled SNARK-soundness (a fabricated-witness coupled
// proof reaching an in-circuit AIR) is the AIR follow-on, not claimed here.
//
// HARD RULES honored: int64 reference immutable; VerifyWinnerProofV7 /
// VerifyWinnerCoupledV7 NOT modified; arbiter OFF; heights INT32_MAX.

#include <arith_uint256.h>
#include <consensus/params.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_gkr.h>
#include <matmul/matmul_v4_rc_gkr_coupled.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <limits>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_gkr_v7_soundness_tests, BasicTestingSetup)

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

// A rejection is at the deep SECURITY MECHANISM iff the relation is an in-circuit
// grounding AIR ("v7:ground:") or the dual-α LogUp aggregate ("v7:logup:").
// Everything else in VerifyWinnerProofV7 is a trivial / algebraic-consistency
// gate that fires strictly BEFORE the mechanism.
bool IsMechanismRelation(const std::string& why)
{
    return StartsWith(why, "v7:ground:") || StartsWith(why, "v7:logup:");
}

// Known trivial / pre-mechanism gates — a genuine forgery must survive ALL of
// these. Presence of any of these as the rejecting relation means the test is
// STILL weak (rejection fired before the mechanism).
bool IsTrivialGate(const std::string& why)
{
    static const char* kTrivial[] = {
        "v7:version", "v7:params_invalid", "v7:height", "v7:pow_bind",
        "v7:digest_not_header_bound", "v7:sigma", "v7:round_roots_size",
        "v7:digest_from_roots", "v7:target", "v7:round_seeds", "v7:layout_count",
        "v7:layer_count", "v7:layout_layer_mismatch", "v7:wire_shape",
        "v7:column_not_grounded", "v7:batch_n", "v7:batch_col_count", "v7:fri:",
        "v7:sumcheck", "v7:final_eval_endpoint", "v7:final_eval", "v7:eval:",
        "v7:logup_alpha_unbound", "v7:wiring_count", "v7:transcript_hash",
    };
    for (const char* g : kTrivial)
        if (StartsWith(why, g)) return true;
    return false;
}

} // namespace

// ============================================================================
// EPISODE: for every independent malicious kind, an internally-consistent v7
// forgery reaches the deep in-circuit grounding AIR and v7 REJECTS there.
// ============================================================================
BOOST_AUTO_TEST_CASE(gkr_v7_genuine_defeats_independent_malicious_episode)
{
    // Hard-rule guards: arbiter OFF, heights INT32_MAX.
    BOOST_CHECK_EQUAL(Consensus::Params{}.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(Consensus::Params{}.nMatMulRCCoupledHeight,
                      std::numeric_limits<int32_t>::max());
    BOOST_CHECK(!rc::EnvRCGkrArbiterEnabled());

    const auto base_header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 real_dig = rc::RecomputeResidentCurriculumReference(base_header, params, 0);
    const arith_uint256 target = MaxTarget(); // digest≤target vacuous — algebra is the gate.

    // Honest v7 baseline verifies (sanity: the machinery is sound end-to-end).
    {
        CBlockHeader h = base_header;
        h.matmul_digest = real_dig;
        const auto honest = rc::ProveWinnerEpisodeV7(h, params, 0, target, real_dig);
        BOOST_REQUIRE_MESSAGE(honest.timing.ok, honest.timing.note);
        std::string why;
        BOOST_REQUIRE_MESSAGE(rc::VerifyWinnerProofV7(honest.proof, h, 0, target, &why), why);
    }

    struct Case {
        rc::RCGkrIndepMaliciousKind kind;
        const char* name;
        const char* expected_relation; // documented mechanism the forgery must hit
    };
    const Case cases[] = {
        {rc::RCGkrIndepMaliciousKind::ArbitraryAbFactorization, "ArbitraryAbFactorization",
         "v7:ground:A: (operand MxExpand grounding — alternate factorization, same Y)"},
        {rc::RCGkrIndepMaliciousKind::FabricatedTraceWires, "FabricatedTraceWires",
         "v7:ground:A: (operand MxExpand grounding — trace not the Λ expansion)"},
        {rc::RCGkrIndepMaliciousKind::IdenticalFabricatedLookup, "IdenticalFabricatedLookup",
         "v7:ground:extract_air:out_binding (verifier-defined Extract sampler AIR)"},
        {rc::RCGkrIndepMaliciousKind::FabricatedExtractIO, "FabricatedExtractIO",
         "v7:ground:extract_in:binding (§5.7 extract_in==Y binding)"},
        {rc::RCGkrIndepMaliciousKind::UnrelatedLayerRoots, "UnrelatedLayerRoots",
         "v7:ground:<tile-tree> (§6.3 round_roots bound to the extract stream)"},
    };

    for (const Case& c : cases) {
        // Build the internally-consistent forgery (runs the honest prover over a
        // fabricated witness). It re-seals claimed_digest for UnrelatedLayerRoots.
        const auto forged = rc::ProveMaliciousEpisodeV7ForTest(base_header, params, 0, target,
                                                               real_dig, c.kind);
        BOOST_REQUIRE_MESSAGE(forged.timing.ok,
                              std::string(c.name) + ": forgery prover failed: " +
                                  forged.timing.note);

        // Bind the header to whatever digest the forgery commits (so the trivial
        // header/digest/sigma gates PASS and the forgery reaches the mechanism).
        CBlockHeader h = base_header;
        h.matmul_digest = forged.proof.claimed_digest;

        std::string why;
        const bool ok = rc::VerifyWinnerProofV7(forged.proof, h, 0, target, &why);
        BOOST_TEST_MESSAGE(std::string("[") + c.name + "] v7 why=\"" + why + "\"");

        // v7 MUST reject. If it ACCEPTS an internally-consistent forgery, that is
        // a REAL soundness bug — headline it.
        BOOST_CHECK_MESSAGE(!ok, std::string("SOUNDNESS BUG: v7 ACCEPTED internally-consistent "
                                             "forgery for ") + c.name);
        // The rejection MUST be at the security mechanism, not a trivial gate.
        BOOST_CHECK_MESSAGE(!IsTrivialGate(why),
                            std::string(c.name) + ": rejection fired at a TRIVIAL GATE (\"" + why +
                                "\") — did NOT reach the security mechanism");
        BOOST_CHECK_MESSAGE(IsMechanismRelation(why),
                            std::string(c.name) + ": rejecting relation \"" + why +
                                "\" is not a recognised in-circuit grounding/LogUp mechanism "
                                "(expected " + c.expected_relation + ")");
    }
}

// ============================================================================
// EPISODE (cheap path): the pre-Extract accumulator extract_in is NOT a
// committed column, so a ZERO-WORK mutation of an honest proof survives every
// algebraic gate and reaches the §5.7 extract_in==Y binding — demonstrating the
// mechanism without re-running the prover.
// ============================================================================
BOOST_AUTO_TEST_CASE(gkr_v7_extract_in_binding_is_reached_without_prover_work)
{
    const auto base_header = MakeRCHeader(7);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 real_dig = rc::RecomputeResidentCurriculumReference(base_header, params, 0);
    const arith_uint256 target = MaxTarget();

    CBlockHeader h = base_header;
    h.matmul_digest = real_dig;
    const auto honest = rc::ProveWinnerEpisodeV7(h, params, 0, target, real_dig);
    BOOST_REQUIRE_MESSAGE(honest.timing.ok, honest.timing.note);
    std::string base_why;
    BOOST_REQUIRE_MESSAGE(rc::VerifyWinnerProofV7(honest.proof, h, 0, target, &base_why), base_why);

    rc::RCGkrProofV7 p = honest.proof;
    BOOST_REQUIRE(!p.wires.empty() && !p.wires[0].extract_in.empty());
    p.wires[0].extract_in[0] += 987654321; // unbind from the sumcheck-proven Y (non-committed)

    std::string why;
    const bool ok = rc::VerifyWinnerProofV7(p, h, 0, target, &why);
    BOOST_TEST_MESSAGE(std::string("[extract_in zero-work] v7 why=\"") + why + "\"");
    BOOST_CHECK_MESSAGE(!ok, "SOUNDNESS BUG: v7 accepted a fabricated extract_in");
    BOOST_CHECK_MESSAGE(!IsTrivialGate(why),
                        std::string("extract_in: fired at trivial gate \"") + why + "\"");
    BOOST_CHECK_MESSAGE(StartsWith(why, "v7:ground:extract_in"),
                        std::string("extract_in: expected v7:ground:extract_in:*, got \"") + why +
                            "\"");
}

// ============================================================================
// COUPLED: UnrelatedBankPages. NOT a full fabricated-witness proof and NOT
// SNARK-sound — this is an honest-proof column-root mutation, and it is the
// STRONGEST attack the coupled path admits. The coupled prover
// (ProveWinnerCoupledV7) is SOLE-AUTHORITY / RE-EXECUTION-SOUND: it re-derives
// the entire trace and refuses any digest that is not the immutable int64
// coupled reference, so a full internally-consistent coupled forgery is not
// constructible at all. We therefore take an honest coupled proof and mutate a
// single committed B column root — substituting a genuine-but-UNRELATED real
// bank page (another lobe's committed page root) into slot (b=0,ℓ=0). This
// reaches, BY NECESSITY, the intended F11 page-selection binding:
// coupled:column_not_grounded checks every committed B column against the
// natively scheduled bank page BEFORE the FRI/sumcheck, so the mutation
// survives all prior header/digest/reference/root/layout gates and dies there.
// Full coupled SNARK-soundness (a fabricated-witness coupled proof reaching an
// in-circuit AIR the way the five episode kinds do) is the AIR follow-on, not
// claimed by this test.
// ============================================================================
BOOST_AUTO_TEST_CASE(gkr_v7_genuine_defeats_coupled_unrelated_bank_pages)
{
    BOOST_CHECK(!rc::EnvRCGkrArbiterEnabled());

    const auto header = MakeRCHeader(99);
    const auto coup = rc::MakeToyRCCoupParams();
    const uint256 cdig = rc::RecomputeCoupledPuzzleReference(header, 0, coup);
    const arith_uint256 target = MaxTarget();

    CBlockHeader hc = header;
    hc.matmul_digest = cdig;
    const auto cbase = rc::ProveWinnerCoupledV7(hc, 0, coup, target, cdig);
    BOOST_REQUIRE_MESSAGE(cbase.timing.ok, cbase.timing.note);
    std::string cwhy;
    BOOST_REQUIRE_MESSAGE(rc::VerifyWinnerCoupledV7(cbase.proof, hc, 0, target, &cwhy), cwhy);

    // CoupColIds: base(b) = b*(3*lobes+4); bcol(b,ℓ) = base(b) + 3ℓ + 1.
    const uint32_t lobes = coup.lobes;
    BOOST_REQUIRE_GE(lobes, 2u);
    auto bcol = [&](uint32_t b, uint32_t ell) { return b * (3u * lobes + 4u) + 3u * ell + 1u; };
    const uint32_t victim = bcol(0, 0);
    const uint32_t donor = bcol(0, 1); // a real, committed, but UNRELATED bank page
    BOOST_REQUIRE(donor < cbase.proof.batch.columns.size());
    BOOST_REQUIRE(victim < cbase.proof.batch.columns.size());

    rc::RCGkrCoupledProofV7 cp = cbase.proof;
    uint256 donor_root = cp.batch.columns[donor].root;
    if (donor_root == cp.batch.columns[victim].root) {
        // Degenerate coincidence: force a distinct real-shaped root.
        donor_root.data()[0] ^= 0xFF;
    }
    cp.batch.columns[victim].root = donor_root; // unrelated page swapped into (0,0)

    std::string why;
    const bool ok = rc::VerifyWinnerCoupledV7(cp, hc, 0, target, &why);
    BOOST_TEST_MESSAGE(std::string("[coupled UnrelatedBankPages] v7 why=\"") + why + "\"");
    BOOST_CHECK_MESSAGE(!ok, "SOUNDNESS BUG: coupled v7 accepted an unrelated bank page");
    // column_not_grounded IS the F11 page-selection binding (the deepest B-operand
    // grounding in the coupled verifier), and it is reached only after ALL of the
    // header/digest/reference/root/layout gates pass.
    BOOST_CHECK_MESSAGE(StartsWith(why, "coupled:column_not_grounded"),
                        std::string("coupled: expected coupled:column_not_grounded (F11 page "
                                    "binding), got \"") + why + "\"");
}

BOOST_AUTO_TEST_SUITE_END()
