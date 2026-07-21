// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Wave 3B — sound COUPLED-puzzle verifier (Relation R5).
//
// Ground truth throughout: RecomputeCoupledPuzzleReference (immutable int64
// reference; sole authority). Every forgery below is a REAL assertion against
// VerifyWinnerCoupledV7 — no fake-passing tests. Arbiter stays OFF and both
// activation heights remain INT32_MAX (asserted).

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

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_gkr_coupled_tests, BasicTestingSetup)

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

/** Λ_coup column ids (must mirror the layout in matmul_v4_rc_gkr_coupled.cpp:
 *  per barrier: L×(A,B,Y) then exchange, post-perm, post-mix, state-out). */
struct ColIds {
    uint32_t lobes;
    uint32_t base(uint32_t b) const { return b * (3 * lobes + 4); }
    uint32_t a(uint32_t b, uint32_t ell) const { return base(b) + 3 * ell; }
    uint32_t bcol(uint32_t b, uint32_t ell) const { return base(b) + 3 * ell + 1; }
    uint32_t y(uint32_t b, uint32_t ell) const { return base(b) + 3 * ell + 2; }
    uint32_t e(uint32_t b) const { return base(b) + 3 * lobes; }
    uint32_t p(uint32_t b) const { return base(b) + 3 * lobes + 1; }
    uint32_t x(uint32_t b) const { return base(b) + 3 * lobes + 2; }
};

} // namespace

// ============================================================================
// POSITIVE PATH — honest coupled proof VERIFIES; digest is byte-for-byte the
// immutable int64 coupled reference; heights/arbiter inert.
// ============================================================================
BOOST_AUTO_TEST_CASE(coupled_v7_positive_path_byte_parity)
{
    BOOST_CHECK_EQUAL(Consensus::Params{}.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(Consensus::Params{}.nMatMulRCCoupledHeight,
                      std::numeric_limits<int32_t>::max());
    BOOST_CHECK(!rc::EnvRCGkrArbiterEnabled());

    auto header = MakeCoupledHeader(42);
    const auto params = rc::MakeToyRCCoupParams();
    const uint256 dig = rc::RecomputeCoupledPuzzleReference(header, /*height=*/0, params);
    header.matmul_digest = dig; // block commits the coupled digest (not in sigma)
    const arith_uint256 target = MaxTarget();

    const auto pr = rc::ProveWinnerCoupledV7(header, 0, params, target, dig);
    BOOST_REQUIRE_MESSAGE(pr.timing.ok, pr.timing.note);
    // Byte-parity: the proof's claimed digest IS the int64 reference digest.
    BOOST_CHECK(pr.proof.claimed_digest == dig);
    BOOST_CHECK(pr.proof.claimed_digest ==
                rc::RecomputeCoupledPuzzleReference(header, 0, params));
    // Structural shape driven by Λ_coup, not prover data.
    BOOST_CHECK_EQUAL(pr.proof.barrier_roots.size(), params.barriers);
    BOOST_CHECK_EQUAL(pr.proof.lobes.size(), rc::RCGkrCoupledExpectedLobeCount(params));
    BOOST_CHECK_EQUAL(pr.proof.batch.columns.size(),
                      rc::RCGkrCoupledExpectedColumnCount(params) + 2); // + eval f,g
    // Dual-α Extract LogUp cleared the target with margin.
    BOOST_CHECK_GT(pr.proof.logup_bits, 64.0);
    // Honestly non-succinct: native grounding ⇒ over_budget.
    BOOST_CHECK(pr.proof.over_budget);
    BOOST_CHECK(pr.timing.over_budget);

    std::string why;
    BOOST_CHECK_MESSAGE(rc::VerifyWinnerCoupledV7(pr.proof, header, 0, target, &why), why);
}

// ============================================================================
// COUPLED FORGERY LIST — F10 / F11 + operand root / opening / barrier root /
// bank root / sigma / dims / target / digest forgeries. Each MUST REJECT.
// ============================================================================
BOOST_AUTO_TEST_CASE(coupled_v7_forgery_list_rejected)
{
    auto header = MakeCoupledHeader(7);
    const auto params = rc::MakeToyRCCoupParams();
    const uint256 dig = rc::RecomputeCoupledPuzzleReference(header, 0, params);
    header.matmul_digest = dig;
    const arith_uint256 target = MaxTarget();

    const auto pr = rc::ProveWinnerCoupledV7(header, 0, params, target, dig);
    BOOST_REQUIRE_MESSAGE(pr.timing.ok, pr.timing.note);
    std::string why;
    BOOST_REQUIRE_MESSAGE(rc::VerifyWinnerCoupledV7(pr.proof, header, 0, target, &why), why);
    const rc::RCGkrCoupledProofV7& H = pr.proof;
    const ColIds ids{params.lobes};

    auto reject_why = [&](const rc::RCGkrCoupledProofV7& p, const CBlockHeader& h,
                          const arith_uint256& t) {
        std::string w;
        const bool ok = rc::VerifyWinnerCoupledV7(p, h, 0, t, &w);
        BOOST_CHECK(!ok);
        return w;
    };

    // F10a — omit a barrier (structural: barrier_roots length is Λ_coup-fixed).
    {
        auto p = H;
        p.barrier_roots.pop_back();
        BOOST_CHECK_EQUAL(reject_why(p, header, target), "coupled:barrier_roots_count");
    }
    // F10b — forge a barrier root (native SHA re-derivation catches it).
    {
        auto p = H;
        p.barrier_roots[1].data()[0] ^= 0xFF;
        BOOST_CHECK_EQUAL(reject_why(p, header, target), "coupled:barrier_root_forged");
    }
    // F11a — forge the page selection: the committed B operand of (b=0,ℓ=0)
    // must be the ROOT of the natively scheduled bank page — any other page
    // (or fabricated page bytes) fails the grounding.
    {
        auto p = H;
        p.batch.columns[ids.bcol(0, 0)].root.data()[0] ^= 0xFF;
        BOOST_CHECK_EQUAL(reject_why(p, header, target), "coupled:column_not_grounded");
    }
    // F11b — forge the material-exchange segment column commitment.
    {
        auto p = H;
        p.batch.columns[ids.e(0)].root.data()[0] ^= 0xFF;
        BOOST_CHECK_EQUAL(reject_why(p, header, target), "coupled:column_not_grounded");
    }
    // F11c — forge the fixed-segment exchange opening (claims lobe output
    // landed in a different segment): exchange_eval must equal the GEMM claim.
    {
        auto p = H;
        p.lobes[0].exchange_eval.c0 ^= 1;
        BOOST_CHECK_EQUAL(reject_why(p, header, target), "coupled:exchange_segment");
    }
    // F11d — forge the permutation binding (post-perm column vs public π_b).
    {
        auto p = H;
        p.perm_evals[0].c0 ^= 1;
        BOOST_CHECK_EQUAL(reject_why(p, header, target), "coupled:perm_eval_forged");
    }
    // F11e — forge the post-perm column commitment itself.
    {
        auto p = H;
        p.batch.columns[ids.p(0)].root.data()[0] ^= 0xFF;
        BOOST_CHECK_EQUAL(reject_why(p, header, target), "coupled:column_not_grounded");
    }
    // Mix-layer forgeries (committed data-movement of the all-to-all).
    {
        auto p = H;
        p.mix_evals[2].c1 ^= 1;
        BOOST_CHECK_EQUAL(reject_why(p, header, target), "coupled:mix_eval_forged");
    }
    {
        auto p = H;
        p.batch.columns[ids.x(1)].root.data()[0] ^= 0xFF;
        BOOST_CHECK_EQUAL(reject_why(p, header, target), "coupled:column_not_grounded");
    }
    // Forge a coupled operand root (A = feed-forward state slice).
    {
        auto p = H;
        p.batch.columns[ids.a(1, 2)].root.data()[0] ^= 0xFF;
        BOOST_CHECK_EQUAL(reject_why(p, header, target), "coupled:column_not_grounded");
    }
    // Forge a coupled opening value (a_eval — Thm 3.1 gf ≡ a·b).
    {
        auto p = H;
        p.lobes[0].a_eval.c0 ^= 1;
        BOOST_CHECK_EQUAL(reject_why(p, header, target), "coupled:final_eval");
    }
    // Forge the sumcheck endpoint (carried final_eval vs chain end).
    {
        auto p = H;
        p.lobes[3].final_eval.c1 ^= 1;
        BOOST_CHECK_EQUAL(reject_why(p, header, target), "coupled:final_eval_endpoint");
    }
    // Forge the GEMM output claim c (trace claim).
    {
        auto p = H;
        p.lobes[1].c_claim.c0 ^= 1;
        // Rejected by the sumcheck chain (first-round sum no longer matches).
        BOOST_CHECK_EQUAL(reject_why(p, header, target), "coupled:sumcheck");
    }
    // Forge the bank root (§7.6 binding).
    {
        auto p = H;
        p.bank_root.data()[0] ^= 0xFF;
        BOOST_CHECK_EQUAL(reject_why(p, header, target), "coupled:bank_root_forged");
    }
    // Forge sigma.
    {
        auto p = H;
        p.sigma.data()[0] ^= 1;
        BOOST_CHECK_EQUAL(reject_why(p, header, target), "coupled:sigma");
    }
    // Forge dimensions (valid-shaped but different coupled puzzle ⇒ the int64
    // reference digest no longer matches the claim).
    {
        auto p = H;
        p.params.lobes = 8; // StateBytes 256: still a valid pow2 shape
        BOOST_CHECK_EQUAL(reject_why(p, header, target), "coupled:digest_mismatch_reference");
    }
    {
        auto p = H;
        p.params.bank_pages += 1;
        BOOST_CHECK_EQUAL(reject_why(p, header, target), "coupled:digest_mismatch_reference");
    }
    // Forge target compliance.
    {
        const arith_uint256 tiny(1);
        BOOST_CHECK_EQUAL(reject_why(H, header, tiny), "coupled:target");
    }
    // Forge the claimed coupled digest (plain flip: pow_bind breaks first).
    {
        auto p = H;
        p.claimed_digest.data()[0] ^= 1;
        BOOST_CHECK_EQUAL(reject_why(p, header, target), "coupled:pow_bind");
    }
    // Consistent digest forger (recomputes pow_bind, re-commits the header):
    // still dies against the immutable reference.
    {
        auto p = H;
        p.claimed_digest.data()[0] ^= 1;
        // Forger-side pow_bind: mirror DerivePowBind via a fresh honest prove
        // attempt is refused (below), so emulate the header binding instead.
        CBlockHeader h2 = header;
        h2.matmul_digest = p.claimed_digest;
        std::string w;
        BOOST_CHECK(!rc::VerifyWinnerCoupledV7(p, h2, 0, target, &w));
        // Either pow_bind (not recomputable without the tag preimage freedom)
        // or the reference digest kills it; both are REJECT.
        BOOST_CHECK(w == "coupled:pow_bind" || w == "coupled:digest_mismatch_reference");
    }
    // Forge LogUp challenge binding.
    {
        auto p = H;
        p.logup_alpha1.c0 ^= 1;
        BOOST_CHECK_EQUAL(reject_why(p, header, target), "coupled:logup_alpha_unbound");
    }
    // Forge the transcript hash.
    {
        auto p = H;
        p.transcript_hash.data()[0] ^= 1;
        BOOST_CHECK_EQUAL(reject_why(p, header, target), "coupled:transcript_hash");
    }
    // Lobe-count forgery (repeat/omit a lobe block).
    {
        auto p = H;
        p.lobes.push_back(p.lobes.back());
        BOOST_CHECK_EQUAL(reject_why(p, header, target), "coupled:lobe_count");
    }
    {
        auto p = H;
        p.lobes.pop_back();
        BOOST_CHECK_EQUAL(reject_why(p, header, target), "coupled:lobe_count");
    }
    // Sanity: the untouched honest proof still verifies.
    BOOST_CHECK_MESSAGE(rc::VerifyWinnerCoupledV7(H, header, 0, target, &why), why);
}

// ============================================================================
// NEVER proves unrelated / toy work — prover-side refusal (both entries).
// ============================================================================
BOOST_AUTO_TEST_CASE(coupled_v7_never_proves_unrelated_work)
{
    auto header = MakeCoupledHeader(42);
    const auto params = rc::MakeToyRCCoupParams();
    const arith_uint256 target = MaxTarget();

    // A digest of UNRELATED work (the episode digest) must be refused.
    const uint256 episode_dig = rc::RecomputeResidentCurriculumReference(
        header, rc::MakeToyRCEpisodeParams(), 0);
    {
        header.matmul_digest = episode_dig;
        const auto pr = rc::ProveWinnerCoupledV7(header, 0, params, target, episode_dig);
        BOOST_CHECK(!pr.timing.ok);
        BOOST_CHECK_EQUAL(pr.timing.note, "coupled_digest_mismatch_refuses_unrelated_work");
        BOOST_CHECK(pr.proof.lobes.empty());
        BOOST_CHECK(pr.proof.barrier_roots.empty());
    }
    // A random digest must be refused.
    {
        uint256 random;
        for (int i = 0; i < 32; ++i) random.data()[i] = static_cast<unsigned char>(0x5a);
        header.matmul_digest = random;
        const auto pr = rc::ProveWinnerCoupledV7(header, 0, params, target, random);
        BOOST_CHECK(!pr.timing.ok);
        BOOST_CHECK_EQUAL(pr.timing.note, "coupled_digest_mismatch_refuses_unrelated_work");
    }
    // A null digest must be refused.
    {
        header.matmul_digest.SetNull();
        const auto pr = rc::ProveWinnerCoupledV7(header, 0, params, target, uint256{});
        BOOST_CHECK(!pr.timing.ok);
    }
    // Legacy entry: same refusals.
    {
        const auto pr = rc::ProveWinnerCoupled(header, 0, params, episode_dig);
        BOOST_CHECK(!pr.timing.ok);
        BOOST_CHECK_EQUAL(pr.timing.note, "coupled_digest_mismatch_refuses_unrelated_work");
        BOOST_CHECK(pr.proof.layers.empty());
        BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
    }
    // A coupled digest computed for DIFFERENT params must be refused for these.
    {
        const auto medium = rc::MakeMediumRCCoupParams();
        const uint256 medium_dig =
            rc::RecomputeCoupledPuzzleReference(header, 0, medium, {}, {}, nullptr);
        const auto pr = rc::ProveWinnerCoupledV7(header, 0, params, target, medium_dig);
        BOOST_CHECK(!pr.timing.ok);
        BOOST_CHECK_EQUAL(pr.timing.note, "coupled_digest_mismatch_refuses_unrelated_work");
    }
}

// ============================================================================
// Legacy ProveWinnerCoupled — no longer fail-closed for a REAL coupled input:
// the bridge produces + self-verifies a real v7 coupled proof.
// ============================================================================
BOOST_AUTO_TEST_CASE(coupled_legacy_entry_real_input_produces_real_proof)
{
    const auto header = MakeCoupledHeader(42);
    const auto params = rc::MakeToyRCCoupParams();
    const uint256 dig = rc::RecomputeCoupledPuzzleReference(header, 0, params);

    const auto pr = rc::ProveWinnerCoupled(header, 0, params, dig);
    BOOST_CHECK_MESSAGE(pr.timing.ok, pr.timing.note);
    BOOST_CHECK(pr.timing.note.find("coupled v7 proven+verified") != std::string::npos);
    // Honestly non-succinct.
    BOOST_CHECK(pr.timing.over_budget);
    BOOST_CHECK_GT(pr.timing.proof_bytes, 0u);
    // The v6 container stays empty (the real proof is the v7 coupled format) —
    // it must NOT look like an episode proof of unrelated work.
    BOOST_CHECK(pr.proof.layers.empty());
    BOOST_CHECK(pr.proof.round_seeds.empty());
    BOOST_CHECK(pr.proof.round_roots.empty());

    // Direct v7 equivalent verifies against the digest-committed header.
    CBlockHeader bound = header;
    bound.matmul_digest = dig;
    const auto v7 = rc::ProveWinnerCoupledV7(bound, 0, params, MaxTarget(), dig);
    BOOST_REQUIRE_MESSAGE(v7.timing.ok, v7.timing.note);
    std::string why;
    BOOST_CHECK_MESSAGE(rc::VerifyWinnerCoupledV7(v7.proof, bound, 0, MaxTarget(), &why), why);
}

// ============================================================================
// Coupled toy golden must be untouched by any of this (the int64 reference is
// immutable): same frozen digest the reference suite pins, re-asserted here
// via mode-equivalence (proving machinery must not perturb the oracle).
// ============================================================================
BOOST_AUTO_TEST_CASE(coupled_v7_reference_oracle_untouched)
{
    const auto header = MakeCoupledHeader(42);
    const auto params = rc::MakeToyRCCoupParams();
    const uint256 before = rc::RecomputeCoupledPuzzleReference(header, 0, params);

    // Run the full prove+verify pipeline...
    CBlockHeader bound = header;
    bound.matmul_digest = before;
    const auto pr = rc::ProveWinnerCoupledV7(bound, 0, params, MaxTarget(), before);
    BOOST_REQUIRE_MESSAGE(pr.timing.ok, pr.timing.note);
    std::string why;
    BOOST_REQUIRE_MESSAGE(rc::VerifyWinnerCoupledV7(pr.proof, bound, 0, MaxTarget(), &why), why);

    // ...and the reference must still produce the byte-identical digest, in
    // every execution mode (digest-invariant policy, §7.5).
    BOOST_CHECK(rc::RecomputeCoupledPuzzleReference(header, 0, params) == before);
    for (const auto mode :
         {rc::RCCoupExecMode::SequentialLobes, rc::RCCoupExecMode::Checkpointed,
          rc::RCCoupExecMode::Streamed, rc::RCCoupExecMode::Resident}) {
        rc::RCCoupOptions opt;
        opt.mode = mode;
        BOOST_CHECK(rc::RecomputeCoupledPuzzleReference(header, 0, params, opt) == before);
    }
}

BOOST_AUTO_TEST_SUITE_END()
