// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// ADVERSARIAL RED-TEAM: genuine, zero-work F0 forgeries against VerifyWinnerProofV7.
//
// The existing gkr_v7_section9_forgery_list_rejected test is a HONEST-PROOF
// MUTATION test: it computes a fully honest proof H = ProveWinnerEpisodeV7(...)
// (which runs the real episode) and flips a single byte. That does NOT model an
// attacker who wants to SKIP the work. This file constructs proofs an attacker
// can produce WITHOUT running the target episode, and asserts the verifier
// rejects each one — capturing the exact rejecting relation.
//
// KEY STRUCTURAL FACT about VerifyWinnerProofV7 (matmul_v4_rc_gkr.cpp):
//   The verifier itself calls RecomputeResidentCurriculumReference(header,
//   proof.episode, height) to obtain true_digest + true round_roots, then
//   rebuilds ALL wires/columns from that ground truth. The proof's own
//   round_roots / batch / layers / eval are only compared for EQUALITY against
//   the recomputed ground truth. It is explicitly "SOUND but NOT succinct"
//   (over_budget=true). Consequently the target check (line ~1366) is on the
//   RECOMPUTED digest, not the proof's claimed digest — grinding a small
//   claimed_digest is worthless. A zero-work forgery cannot pass because
//   producing a header whose recomputed episode digest <= target IS the work.

#include <arith_uint256.h>
#include <hash.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_gkr.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_gkr_f0_tests, BasicTestingSetup)

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

// Replicates the file-local DerivePowBind(d) = SHA256d("BTX_RC_GKR_POW_BIND_V4" || d).
// An attacker knows this formula (no secret); we compute it so a fabricated proof
// sails PAST the cheap pow_bind self-consistency check and dies at the deep
// ground-truth binding — proving zero-work fails even with a maximally
// self-consistent forgery.
uint256 PowBind(const uint256& d)
{
    const char* tag = "BTX_RC_GKR_POW_BIND_V4";
    std::vector<unsigned char> buf(reinterpret_cast<const unsigned char*>(tag),
                                   reinterpret_cast<const unsigned char*>(tag) + std::strlen(tag));
    buf.insert(buf.end(), d.begin(), d.end());
    return Hash(buf);
}

uint256 Digest(uint8_t fill)
{
    uint256 d;
    for (int i = 0; i < 32; ++i) d.data()[i] = fill;
    return d;
}

std::string VerdictWhy(const rc::RCGkrProofV7& p, const CBlockHeader& h, const arith_uint256& t)
{
    std::string why;
    const bool ok = rc::VerifyWinnerProofV7(p, h, 0, t, &why);
    return ok ? std::string("ACCEPT") : ("REJECT:" + why);
}

} // namespace

// ---------------------------------------------------------------------------
// F0 strategy (a): PURE FABRICATION. Attacker never runs the episode. Builds a
// v7 proof by hand: grinds a claimed_digest that is trivially <= target,
// computes the (public, secret-free) pow_bind, sets header.matmul_digest to it,
// fabricates arbitrary round_roots, leaves the expensive succinct machinery
// (batch/layers/eval) empty. NO episode work performed.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(f0_pure_fabrication_zero_work_rejected)
{
    auto header = MakeRCHeader(0xF0);
    const auto params = rc::MakeToyRCEpisodeParams();
    arith_uint256 target;
    target = ~target; // maximal target — an HONEST proof for this header verifies.

    // Attacker's fabricated "winning" digest: a small value, no work done.
    const uint256 forged_digest = Digest(0x01);
    header.matmul_digest = forged_digest; // block header commits the forged digest.

    rc::RCGkrProofV7 p;
    p.version = 7;
    p.episode = params;
    p.height = 0;
    p.claimed_digest = forged_digest;
    p.pow_bind = PowBind(forged_digest);              // passes v7:pow_bind
    p.episode_sigma = matmul::v4::DeriveSigma(header); // passes v7:sigma
    p.round_roots.assign(params.rounds, Digest(0xAB)); // arbitrary fabricated roots
    // batch/layers/eval intentionally EMPTY — attacker skipped arithmetization.

    const std::string v = VerdictWhy(p, header, target);
    BOOST_TEST_MESSAGE("f0(a) pure fabrication -> " << v);
    // Must reject; the forgery dies at the recomputed-reference digest binding,
    // NOT at any self-consistency field the attacker controls.
    BOOST_CHECK(v != "ACCEPT");
    BOOST_CHECK(v.find("digest_mismatch_reference") != std::string::npos);
}

// ---------------------------------------------------------------------------
// F0 strategy (a'): GRIND-TO-TARGET is worthless. Attacker sets a claimed_digest
// that beats an ARBITRARILY TIGHT target (digest = 1 <= tiny target) with zero
// work. The verifier's target test is on the RECOMPUTED digest, so this fails.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(f0_grind_small_digest_defeats_tight_target_rejected)
{
    auto header = MakeRCHeader(0xF1);
    const auto params = rc::MakeToyRCEpisodeParams();
    const arith_uint256 tiny(1); // essentially impossible target

    const uint256 forged_digest = Digest(0x00); // "digest" = 0, beats any target
    header.matmul_digest = forged_digest;

    rc::RCGkrProofV7 p;
    p.version = 7;
    p.episode = params;
    p.height = 0;
    p.claimed_digest = forged_digest;
    p.pow_bind = PowBind(forged_digest);
    p.episode_sigma = matmul::v4::DeriveSigma(header);
    p.round_roots.assign(params.rounds, Digest(0xCD));

    const std::string v = VerdictWhy(p, header, tiny);
    BOOST_TEST_MESSAGE("f0(a') grind-to-tight-target -> " << v);
    BOOST_CHECK(v != "ACCEPT");
    // Recomputed true digest != forged 0 -> digest_mismatch_reference (target
    // test is downstream and equally fatal). Grinding the embedded digest is moot.
    BOOST_CHECK(v.find("digest_mismatch_reference") != std::string::npos);
}

// ---------------------------------------------------------------------------
// F0 strategy (b): REPLAY a DIFFERENT header's honest proof under THIS header.
// Attacker obtains a genuinely honest, fully-computed proof for header_A (all
// the expensive batch/sumcheck/eval for episode A), then relabels the digest to
// header_B and submits. Reuses episode A's work to "prove" header B — zero work
// for B.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(f0_cross_header_replay_rejected)
{
    const auto params = rc::MakeToyRCEpisodeParams();
    arith_uint256 target;
    target = ~target;

    // Honest proof for header_A (this is the attacker's stolen/borrowed proof).
    auto header_a = MakeRCHeader(0xA0);
    const uint256 dig_a = rc::RecomputeResidentCurriculumReference(header_a, params, 0);
    header_a.matmul_digest = dig_a;
    const auto pr_a = rc::ProveWinnerEpisodeV7(header_a, params, 0, target, dig_a);
    BOOST_REQUIRE_MESSAGE(pr_a.timing.ok, pr_a.timing.note);
    {   // sanity: it verifies under its OWN header
        std::string w;
        BOOST_REQUIRE(rc::VerifyWinnerProofV7(pr_a.proof, header_a, 0, target, &w));
    }

    // Target header_B — attacker did NO episode work for it.
    auto header_b = MakeRCHeader(0xB0);
    header_b.matmul_digest = dig_a; // commit episode A's digest into header B

    const std::string v = VerdictWhy(pr_a.proof, header_b, target);
    BOOST_TEST_MESSAGE("f0(b) cross-header replay -> " << v);
    BOOST_CHECK(v != "ACCEPT");
    // header_B's recomputed reference digest != dig_a -> reject.
    BOOST_CHECK(v.find("digest_mismatch_reference") != std::string::npos);
}

// ---------------------------------------------------------------------------
// F0 strategy (c): DIMENSION RELABEL. Attacker cheaply proves a SMALL episode,
// then relabels proof.episode to the (larger) target params, claiming to have
// done the big work. Reuses small-episode work.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(f0_dimension_relabel_rejected)
{
    auto header = MakeRCHeader(0xC0);
    const auto small = rc::MakeToyRCEpisodeParams(); // cheap episode actually run
    arith_uint256 target;
    target = ~target;

    const uint256 dig_small = rc::RecomputeResidentCurriculumReference(header, small, 0);
    header.matmul_digest = dig_small;
    const auto pr = rc::ProveWinnerEpisodeV7(header, small, 0, target, dig_small);
    BOOST_REQUIRE_MESSAGE(pr.timing.ok, pr.timing.note);

    // Bigger "target" params the attacker wants to be credited for.
    rc::RCEpisodeParams big = small;
    big.n_ctx = small.n_ctx * 2; // still %32==0, still valid; different episode
    BOOST_REQUIRE(rc::ValidateRCEpisodeParams(big));

    auto p = pr.proof;
    p.episode = big; // relabel: claim the big episode, ship the small proof body

    const std::string v = VerdictWhy(p, header, target);
    BOOST_TEST_MESSAGE("f0(c) dimension relabel small->big -> " << v);
    BOOST_CHECK(v != "ACCEPT");
    // Recompute(header, big) != dig_small -> reject at the reference binding.
    BOOST_CHECK(v.find("digest_mismatch_reference") != std::string::npos);
}

// ---------------------------------------------------------------------------
// SECOND BINDING LAYER: even an attacker who DID mine the header (so digest +
// round_roots are correct) cannot skip the succinct arithmetization by
// fabricating the batch/layers/eval. This is NOT zero-work, but it shows the
// forged succinct body is bound to ground truth (not merely absorbed like v6).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(f0_fabricated_succinct_body_over_mined_header_rejected)
{
    auto header = MakeRCHeader(0xD0);
    const auto params = rc::MakeToyRCEpisodeParams();
    arith_uint256 target;
    target = ~target;

    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    header.matmul_digest = dig;
    const auto pr = rc::ProveWinnerEpisodeV7(header, params, 0, target, dig);
    BOOST_REQUIRE_MESSAGE(pr.timing.ok, pr.timing.note);

    // Keep the ground-truth-bound fields (digest, sigma, round_roots, seeds),
    // but GARBAGE every committed column root — as if the attacker fabricated the
    // FRI commitment instead of arithmetizing the real wires.
    auto p = pr.proof;
    for (auto& col : p.batch.columns) col.root.data()[0] ^= 0xFF;

    const std::string v = VerdictWhy(p, header, target);
    BOOST_TEST_MESSAGE("f0(D) fabricated succinct body over mined header -> " << v);
    BOOST_CHECK(v != "ACCEPT");
    BOOST_CHECK(v.find("column_not_grounded") != std::string::npos ||
                v.find("batch") != std::string::npos || v.find("fri") != std::string::npos);
}

// ---------------------------------------------------------------------------
// F3 COMPLETION: mutate b_eval INDEPENDENTLY of a_eval (the existing §9 list only
// mutates a_eval). The carried final_eval no longer equals a_eval*b_eval, and the
// eval argument no longer opens the committed B column at b_eval.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(f3_b_eval_independent_mutation_rejected)
{
    auto header = MakeRCHeader(0xE0);
    const auto params = rc::MakeToyRCEpisodeParams();
    arith_uint256 target;
    target = ~target;

    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    header.matmul_digest = dig;
    const auto pr = rc::ProveWinnerEpisodeV7(header, params, 0, target, dig);
    BOOST_REQUIRE_MESSAGE(pr.timing.ok, pr.timing.note);
    {   std::string w;
        BOOST_REQUIRE(rc::VerifyWinnerProofV7(pr.proof, header, 0, target, &w)); }

    auto p = pr.proof;
    p.layers[0].b_eval.c0 ^= 1; // mutate b_eval only

    const std::string v = VerdictWhy(p, header, target);
    BOOST_TEST_MESSAGE("f3 b_eval independent mutation -> " << v);
    BOOST_CHECK(v != "ACCEPT");
    // final_eval == a_eval*b_eval breaks first.
    BOOST_CHECK(v.find("final_eval") != std::string::npos || v.find("eval") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
