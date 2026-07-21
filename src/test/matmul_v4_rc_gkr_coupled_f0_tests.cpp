// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ============================================================================
// COUPLED F0 — GENUINE zero-work forgery red-team against VerifyWinnerCoupledV7.
//
// The existing F10/F11 tests in matmul_v4_rc_gkr_coupled_tests.cpp take a fully
// honest ProveWinnerCoupledV7 proof and flip ONE byte. That is NOT a real
// forgery — it is an honest proof with a corrupted field, and it proves nothing
// about an attacker who never ran the coupled puzzle.
//
// This file constructs REAL zero-work coupled attacks: the attacker fabricates
// an RCGkrCoupledProofV7 WITHOUT ever calling ProveWinnerCoupledV7 on the
// target puzzle and WITHOUT computing RecomputeCoupledPuzzleReference for the
// target (header, height, params). The attacker makes the proof as internally
// self-consistent as it can cheaply (correct version/params/height, a valid
// pow_bind over its chosen digest, a header that binds that digest, the public
// sigma) so it reaches the DEEPEST possible verifier check, then we assert
// REJECT and record the exact rejecting relation.
//
// HARD RULES honored: VerifyWinnerCoupledV7 and the int64 reference are NOT
// modified. Arbiter OFF; heights INT32_MAX (asserted in the sibling suite).
// ============================================================================

#include <arith_uint256.h>
#include <crypto/sha256.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_gkr.h>
#include <matmul/matmul_v4_rc_gkr_coupled.h>
#include <primitives/block.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_gkr_coupled_f0_tests, BasicTestingSetup)

namespace {

CBlockHeader MakeCoupledHeader(uint64_t nonce)
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

// Public re-implementation of the verifier's DerivePowBind (which lives in an
// anonymous namespace). It is a plain tagged double-SHA256 that any attacker can
// compute for free — the pow_bind check is NOT the security barrier. Keeping
// this in the test lets the fabricated proof sail past coupled:pow_bind and
// reach the reference-grounding wall.
uint256 AttackerPowBind(const uint256& claimed_digest)
{
    static const char kTag[] = "BTX_RC_GKR_POW_BIND_V4";
    std::vector<unsigned char> buf;
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(kTag),
               reinterpret_cast<const unsigned char*>(kTag) + (sizeof(kTag) - 1));
    buf.insert(buf.end(), claimed_digest.begin(), claimed_digest.end());
    uint8_t d1[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(buf.data(), buf.size()).Finalize(d1);
    uint8_t d2[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(d1, sizeof(d1)).Finalize(d2);
    return uint256{Span<const unsigned char>{d2, sizeof(d2)}};
}

uint256 FillDigest(unsigned char b)
{
    uint256 d;
    for (int i = 0; i < 32; ++i) d.data()[i] = b;
    return d;
}

// Fabricate a fully self-consistent-but-fake proof shell. Every structural size
// is correct (so structural checks pass), every value is arbitrary attacker
// data (never derived from the coupled puzzle). pow_bind is computed for the
// chosen digest; sigma is the public DeriveSigma(header). The ONE thing the
// attacker cannot fake without running the puzzle is claimed_digest == the
// recomputed reference digest.
rc::RCGkrCoupledProofV7 FabricateProof(const CBlockHeader& header, const rc::RCCoupParams& params,
                                       const uint256& claimed_digest)
{
    rc::RCGkrCoupledProofV7 p;
    p.version = rc::kRCGkrProofVersionV7;
    p.params = params;
    p.height = 0;
    p.claimed_digest = claimed_digest;
    p.pow_bind = AttackerPowBind(claimed_digest);
    p.sigma = matmul::v4::DeriveSigma(header); // public, free
    p.bank_root = FillDigest(0xB1);            // arbitrary
    p.barrier_roots.assign(params.barriers, FillDigest(0xC2)); // correct COUNT, fake values
    p.lobes.assign(rc::RCGkrCoupledExpectedLobeCount(params), rc::RCGkrCoupledLobeClaimV7{});
    p.perm_evals.assign(params.barriers, Fp2::Zero());
    p.mix_evals.assign(params.barriers, Fp2::Zero());
    // batch / eval / transcript left default (fake). We do not expect to reach
    // them — the reference-digest wall stops the forgery long before.
    p.transcript_hash = FillDigest(0xD3);
    return p;
}

} // namespace

// ============================================================================
// ATTACK 1 — PURE FABRICATION. No ProveWinnerCoupledV7, no puzzle computation.
// Fabricate everything; digest chosen arbitrarily (all-zero → trivially small).
// EXPECT: REJECT. The attacker cannot make claimed_digest equal the reference
// digest the verifier recomputes for itself.
// ============================================================================
BOOST_AUTO_TEST_CASE(coupled_f0_pure_fabrication_rejected)
{
    auto header = MakeCoupledHeader(7);
    const auto params = rc::MakeToyRCCoupParams();
    const arith_uint256 target = MaxTarget();

    // Attacker picks an arbitrary digest and binds the header + pow_bind to it,
    // WITHOUT ever running the coupled puzzle.
    const uint256 fake_digest = FillDigest(0x00);
    header.matmul_digest = fake_digest; // pass header-binding
    auto p = FabricateProof(header, params, fake_digest);

    std::string why;
    const bool ok = rc::VerifyWinnerCoupledV7(p, header, 0, target, &why);
    BOOST_TEST_MESSAGE("ATTACK1 pure-fabrication verdict: " << (ok ? "ACCEPT" : "REJECT")
                                                            << " (" << why << ")");
    BOOST_CHECK_MESSAGE(!ok, "SOUNDNESS BUG: pure fabrication ACCEPTED");
    // Deepest reachable check is the immutable-reference digest grounding.
    BOOST_CHECK_EQUAL(why, "coupled:digest_mismatch_reference");
}

// ============================================================================
// ATTACK 2 — GROUND-DIGEST vs the TARGET check. The attacker fabricates a TINY
// digest that would satisfy a strict target, aiming to steal the "digest <=
// target" relation with zero coupled work. EXPECT: REJECT — the target is bound
// to the RECOMPUTED reference digest, so the fake tiny digest never even reaches
// the target comparison (dies at the reference grounding first).
// ============================================================================
BOOST_AUTO_TEST_CASE(coupled_f0_ground_digest_target_rejected)
{
    auto header = MakeCoupledHeader(11);
    const auto params = rc::MakeToyRCCoupParams();

    // Strict target: only a digest <= 2 would pass a naive claimed<=target check.
    const arith_uint256 tiny_target(2);

    const uint256 tiny_digest = FillDigest(0x00); // numerically 0 <= target
    header.matmul_digest = tiny_digest;
    auto p = FabricateProof(header, params, tiny_digest);

    std::string why;
    const bool ok = rc::VerifyWinnerCoupledV7(p, header, 0, tiny_target, &why);
    BOOST_TEST_MESSAGE("ATTACK2 ground-digest/target verdict: " << (ok ? "ACCEPT" : "REJECT")
                                                                << " (" << why << ")");
    BOOST_CHECK_MESSAGE(!ok, "SOUNDNESS BUG: fabricated tiny digest ACCEPTED (target stolen)");
    // The verifier grounds the digest against the reference BEFORE the target
    // check, so the fake tiny digest is rejected at the reference wall, proving
    // the target relation cannot be satisfied with zero coupled work.
    BOOST_CHECK_EQUAL(why, "coupled:digest_mismatch_reference");
}

// ============================================================================
// ATTACK 3 — DIFFERENT-PARAMS RELABEL. The attacker honestly runs a DIFFERENT
// coupled puzzle (medium params) — NOT the target (toy) puzzle — obtains a
// genuinely valid proof, then relabels params medium->toy and submits it for
// the toy target. Because the SAME header is used, sigma and pow_bind and the
// header binding all still pass; the only thing that changes is params, so the
// verifier recomputes the TOY reference digest, which differs from the medium
// digest the proof carries. EXPECT: REJECT.
// ============================================================================
BOOST_AUTO_TEST_CASE(coupled_f0_different_params_relabel_rejected)
{
    auto header = MakeCoupledHeader(7);
    const auto toy = rc::MakeToyRCCoupParams();
    const auto medium = rc::MakeMediumRCCoupParams();
    const arith_uint256 target = MaxTarget();

    // Honest proof for the MEDIUM puzzle (a different puzzle; the attacker never
    // runs the toy/target puzzle).
    const uint256 medium_dig = rc::RecomputeCoupledPuzzleReference(header, 0, medium, {}, {}, nullptr);
    header.matmul_digest = medium_dig;
    const auto pr = rc::ProveWinnerCoupledV7(header, 0, medium, target, medium_dig);
    BOOST_REQUIRE_MESSAGE(pr.timing.ok, pr.timing.note);

    // Sanity: the honest medium proof verifies as a medium proof.
    {
        std::string w;
        BOOST_REQUIRE_MESSAGE(rc::VerifyWinnerCoupledV7(pr.proof, header, 0, target, &w), w);
    }

    // RELABEL: claim it is a TOY proof. Header still binds medium_dig, sigma
    // unchanged (same header), pow_bind unchanged (same claimed_digest).
    auto p = pr.proof;
    p.params = toy;

    std::string why;
    const bool ok = rc::VerifyWinnerCoupledV7(p, header, 0, target, &why);
    BOOST_TEST_MESSAGE("ATTACK3 different-params-relabel verdict: " << (ok ? "ACCEPT" : "REJECT")
                                                                    << " (" << why << ")");
    BOOST_CHECK_MESSAGE(!ok, "SOUNDNESS BUG: different-params relabel ACCEPTED");
    // Toy reference digest != medium digest → grounded reject.
    BOOST_CHECK_EQUAL(why, "coupled:digest_mismatch_reference");
}

// ============================================================================
// ATTACK 3b — CROSS-HEADER RELABEL. The attacker honestly runs the toy puzzle
// for a DIFFERENT header (a different nonce — NOT the target block), then
// relabels the proof (including sigma) to the target header. EXPECT: REJECT.
// The target header's recomputed reference digest differs from the foreign
// header's digest the proof carries.
// ============================================================================
BOOST_AUTO_TEST_CASE(coupled_f0_cross_header_relabel_rejected)
{
    const auto params = rc::MakeToyRCCoupParams();
    const arith_uint256 target = MaxTarget();

    // Honest proof for a FOREIGN header (nonce 999) — not the target.
    auto foreign = MakeCoupledHeader(999);
    const uint256 foreign_dig = rc::RecomputeCoupledPuzzleReference(foreign, 0, params, {}, {}, nullptr);
    foreign.matmul_digest = foreign_dig;
    const auto pr = rc::ProveWinnerCoupledV7(foreign, 0, params, target, foreign_dig);
    BOOST_REQUIRE_MESSAGE(pr.timing.ok, pr.timing.note);

    // Target block is a DIFFERENT header (nonce 7). The attacker relabels the
    // foreign proof onto it, including forging sigma + header binding so the
    // forgery reaches the reference-digest wall rather than dying at sigma.
    auto target_header = MakeCoupledHeader(7);
    target_header.matmul_digest = foreign_dig; // pass header binding
    auto p = pr.proof;
    p.sigma = matmul::v4::DeriveSigma(target_header); // relabel sigma to target

    std::string why;
    const bool ok = rc::VerifyWinnerCoupledV7(p, target_header, 0, target, &why);
    BOOST_TEST_MESSAGE("ATTACK3b cross-header-relabel verdict: " << (ok ? "ACCEPT" : "REJECT")
                                                                 << " (" << why << ")");
    BOOST_CHECK_MESSAGE(!ok, "SOUNDNESS BUG: cross-header relabel ACCEPTED");
    BOOST_CHECK_EQUAL(why, "coupled:digest_mismatch_reference");

    // Control: without relabeling sigma, the forgery dies even earlier (at the
    // sigma check) — still a REJECT, just shallower.
    {
        auto p2 = pr.proof; // foreign sigma retained
        std::string w2;
        const bool ok2 = rc::VerifyWinnerCoupledV7(p2, target_header, 0, target, &w2);
        BOOST_CHECK(!ok2);
        BOOST_TEST_MESSAGE("ATTACK3b (no sigma relabel) verdict: REJECT (" << w2 << ")");
    }
}

BOOST_AUTO_TEST_SUITE_END()
