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

#include <algorithm>
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
    // Y column is base(b)+3*ell+2 (not mutated by these root-tamper cases).
    uint32_t e(uint32_t b) const { return base(b) + 3 * lobes; }
    uint32_t p(uint32_t b) const { return base(b) + 3 * lobes + 1; }
    uint32_t x(uint32_t b) const { return base(b) + 3 * lobes + 2; }
    uint32_t s(uint32_t b) const { return base(b) + 3 * lobes + 3; }
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
    BOOST_CHECK_EQUAL(pr.proof.feed_evals.size(), rc::RCGkrCoupledExpectedFeedCount(params));
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

BOOST_AUTO_TEST_CASE(coupled_v7_medium_v3_rows_per_lobe_byte_parity)
{
    auto header = MakeCoupledHeader(84);
    const auto params = rc::MakeMediumV3RCCoupParams();
    const auto options = rc::MakeMediumV3RCCoupOptions();
    BOOST_REQUIRE_EQUAL(params.rows_per_lobe, 32u);
    BOOST_REQUIRE_EQUAL(options.transcript_version, rc::ENC_RC_V3);
    BOOST_REQUIRE(rc::ValidateRCCoupParams(params));

    const uint256 dig =
        rc::RecomputeCoupledPuzzleReference(header, /*height=*/0, params, options, {}, nullptr);
    BOOST_REQUIRE(!dig.IsNull());
    header.matmul_digest = dig;
    const arith_uint256 target = MaxTarget();

    {
        const auto bad = rc::ProveWinnerCoupledV7(header, 0, params, target, dig);
        BOOST_CHECK(!bad.timing.ok);
        BOOST_CHECK_EQUAL(bad.timing.note, "coupled_digest_mismatch_refuses_unrelated_work");
    }

    const auto pr = rc::ProveWinnerCoupledV7(header, 0, params, target, dig, options);
    BOOST_REQUIRE_MESSAGE(pr.timing.ok, pr.timing.note);
    BOOST_CHECK(pr.proof.claimed_digest == dig);
    BOOST_CHECK_EQUAL(pr.proof.params.rows_per_lobe, 32u);
    BOOST_CHECK_EQUAL(pr.proof.params.lobe_width, 64u);
    BOOST_CHECK_EQUAL(pr.proof.options.transcript_version, rc::ENC_RC_V3);
    BOOST_CHECK_EQUAL(pr.proof.options.exchange_rounds, 0u);
    BOOST_CHECK_EQUAL(pr.proof.lobes.size(), rc::RCGkrCoupledExpectedLobeCount(params));
    BOOST_CHECK_EQUAL(pr.proof.feed_evals.size(), rc::RCGkrCoupledExpectedFeedCount(params));
    BOOST_CHECK_EQUAL(pr.proof.batch.columns.size(),
                      rc::RCGkrCoupledExpectedColumnCount(params) + 2);
    BOOST_CHECK(pr.proof.over_budget);
    BOOST_CHECK(pr.timing.over_budget);

    std::string why;
    BOOST_CHECK_MESSAGE(rc::VerifyWinnerCoupledV7(pr.proof, header, 0, target, &why), why);

    auto wrong_options = pr.proof;
    wrong_options.options.transcript_version = rc::ENC_RC_V1;
    BOOST_CHECK(!rc::VerifyWinnerCoupledV7(wrong_options, header, 0, target, &why));
    BOOST_CHECK_EQUAL(why, "coupled:digest_mismatch_reference");
}

BOOST_AUTO_TEST_CASE(coupled_v7_v4_affine_permutation_binding_accepts_and_rejects)
{
    auto header = MakeCoupledHeader(126);
    const auto params = rc::MakeToyRCCoupParams();
    rc::RCCoupOptions options;
    options.transcript_version = rc::ENC_RC_V4;
    options.exchange_rounds = 0;
    BOOST_REQUIRE(rc::RCCoupUsesProofFriendlyPermutation(options.transcript_version));

    const uint256 dig =
        rc::RecomputeCoupledPuzzleReference(header, /*height=*/0, params, options, {}, nullptr);
    BOOST_REQUIRE(!dig.IsNull());
    header.matmul_digest = dig;
    const arith_uint256 target = MaxTarget();

    const auto pr = rc::ProveWinnerCoupledV7(header, 0, params, target, dig, options);
    BOOST_REQUIRE_MESSAGE(pr.timing.ok, pr.timing.note);
    BOOST_CHECK_EQUAL(pr.proof.options.transcript_version, rc::ENC_RC_V4);

    std::string why;
    BOOST_REQUIRE_MESSAGE(rc::VerifyWinnerCoupledV7(pr.proof, header, 0, target, &why), why);

    // In V4 the verifier does not recompute the permutation MLE by scanning the
    // state. The scalar is bound by the eval argument at both p(r_dst) and
    // e(pi^{-1}(r_dst)); mutating it must fail there, not at a native
    // Fisher-Yates gate.
    auto bad = pr.proof;
    bad.perm_evals[0].c0 ^= 1;
    BOOST_CHECK(!rc::VerifyWinnerCoupledV7(bad, header, 0, target, &why));
    BOOST_CHECK_MESSAGE(why != "coupled:perm_eval_forged",
                        std::string("V4 must not use the native Fisher-Yates perm gate; got ") +
                            why);
}

BOOST_AUTO_TEST_CASE(coupled_v7_succinctness_gate_stays_no_go_until_native_grounding_removed)
{
    const auto toy = rc::MakeToyRCCoupParams();
    const auto st = rc::AssessCoupledV7Succinctness(toy);
    BOOST_CHECK(st.params_valid);
    BOOST_CHECK(!st.production_v3_shape);
    BOOST_CHECK(!st.genuinely_succinct);
    BOOST_CHECK(!st.proof_friendly_transcript);
    BOOST_CHECK(st.full_schedule_gemm_proof_bound);
    BOOST_CHECK(st.feed_forward_proof_bound);
    BOOST_CHECK(st.opening_claims_batched);
    BOOST_CHECK(st.verifier_reruns_reference_digest);
    BOOST_CHECK(st.verifier_rebuilds_native_wires);
    BOOST_CHECK(st.verifier_rebuilds_column_roots);
    BOOST_CHECK(!st.bank_pages_proof_bound);
    BOOST_CHECK(!st.permutation_proof_bound);
    BOOST_CHECK(!st.mix_proof_bound);
    BOOST_CHECK(!st.extract_all_tiles_proof_bound);
    BOOST_CHECK(!st.barrier_roots_proof_bound);
    BOOST_CHECK(!st.digest_target_proof_bound);
    BOOST_CHECK(!st.under_stage_i_budget);
    BOOST_CHECK_EQUAL(st.required_extract_tiles, toy.StateBytes() / rc::kRCMxBlockLen);
    BOOST_CHECK_EQUAL(st.current_extract_logup_tile_cap, 16u);

    auto has = [&](const char* blocker) {
        return std::find(st.blockers.begin(), st.blockers.end(), blocker) != st.blockers.end();
    };
    BOOST_CHECK(has("native_reference_digest_replay"));
    BOOST_CHECK(has("native_wire_regeneration"));
    BOOST_CHECK(has("native_column_root_rebuild"));
    BOOST_CHECK(has("bank_pages_not_pcs_bound_under_bank_root"));
    BOOST_CHECK(has("permutation_requires_proof_friendly_transcript"));
    BOOST_CHECK(has("extract_all_tiles_not_proof_bound"));

    std::string why;
    BOOST_CHECK(!rc::RCGkrCoupledV7ReadyForProofOnlyConsensus(toy, &why));
    BOOST_CHECK(why.find("NO-GO") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(coupled_v7_production_v3_succinct_gate_counts_real_work)
{
    const auto prod = rc::MakeProductionV3RCCoupParams();
    const auto st = rc::AssessCoupledV7Succinctness(prod);
    BOOST_CHECK(st.params_valid);
    BOOST_CHECK(st.production_v3_shape);
    BOOST_CHECK(!st.genuinely_succinct);
    BOOST_CHECK_EQUAL(st.state_bytes, uint64_t{8} * 128 * 8192);
    BOOST_CHECK_EQUAL(st.expanded_bank_bytes, uint64_t{1536} * 8192 * 8192);
    BOOST_CHECK_EQUAL(st.packed_bank_bytes, (uint64_t{1536} * 8192 * 8192 * 17) / 32);
    BOOST_CHECK_EQUAL(st.macs_per_nonce,
                      uint64_t{128} * 24 * 8 * 8 * 8192 * 8192);
    BOOST_CHECK_EQUAL(st.required_extract_tiles, st.state_bytes / rc::kRCMxBlockLen);
    BOOST_CHECK_GT(st.required_extract_tiles, st.current_extract_logup_tile_cap);

    std::string why;
    BOOST_CHECK(!rc::RCGkrCoupledV7ReadyForProofOnlyConsensus(prod, &why));
    BOOST_CHECK(why.find("native_reference_digest_replay") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(coupled_v7_relation_status_marks_v4_permutation_as_necessary_not_sufficient)
{
    const auto prod = rc::MakeProductionV3RCCoupParams();
    auto v4_options = rc::MakeV3RCCoupOptions();
    v4_options.transcript_version = rc::ENC_RC_V4;

    const auto st = rc::AssessCoupledV7Succinctness(prod, v4_options);
    BOOST_CHECK(st.params_valid);
    BOOST_CHECK(st.production_v3_shape);
    BOOST_CHECK(st.proof_friendly_transcript);
    BOOST_CHECK(st.permutation_proof_bound);
    BOOST_CHECK(st.full_schedule_gemm_proof_bound);
    BOOST_CHECK(st.feed_forward_proof_bound);
    BOOST_CHECK(st.opening_claims_batched);
    BOOST_CHECK(!st.genuinely_succinct);
    BOOST_CHECK(st.verifier_reruns_reference_digest);
    BOOST_CHECK(st.verifier_rebuilds_native_wires);
    BOOST_CHECK(st.verifier_rebuilds_column_roots);
    BOOST_CHECK(!st.bank_pages_proof_bound);
    BOOST_CHECK(!st.mix_proof_bound);
    BOOST_CHECK(!st.extract_all_tiles_proof_bound);
    BOOST_CHECK(!st.barrier_roots_proof_bound);
    BOOST_CHECK(!st.digest_target_proof_bound);

    std::string why_v4;
    BOOST_CHECK(!rc::RCGkrCoupledV7ReadyForProofOnlyConsensus(prod, v4_options, &why_v4));
    BOOST_CHECK(why_v4.find("NO-GO") != std::string::npos);
    BOOST_CHECK(why_v4.find("native_reference_digest_replay") != std::string::npos);
    BOOST_CHECK_MESSAGE(why_v4.find("permutation_requires_proof_friendly_transcript") ==
                            std::string::npos,
                        "V4 options should clear the permutation blocker but remain NO-GO "
                        "for native grounding/bank/mix/extract/SHA/digest/budget blockers");

    const auto rels = rc::RCGkrCoupledV7RelationStatuses(prod, v4_options);
    auto find_rel = [&](const char* name) {
        return std::find_if(rels.begin(), rels.end(), [&](const auto& r) {
            return r.name == name;
        });
    };

    const auto gemm = find_rel("full-schedule GEMM");
    BOOST_REQUIRE(gemm != rels.end());
    BOOST_CHECK(gemm->proof_bound);
    BOOST_CHECK(gemm->native_grounded);
    BOOST_CHECK(gemm->verifier_sublinear);

    const auto perm = find_rel("permutation");
    BOOST_REQUIRE(perm != rels.end());
    BOOST_CHECK(perm->proof_bound);
    BOOST_CHECK(perm->native_grounded);
    BOOST_CHECK(perm->verifier_sublinear);
    BOOST_CHECK(perm->construction.find("ENC_RC_V4") != std::string::npos);

    const auto feed = find_rel("feed-forward copy");
    BOOST_REQUIRE(feed != rels.end());
    BOOST_CHECK(feed->proof_bound);
    BOOST_CHECK(feed->native_grounded);
    BOOST_CHECK(feed->verifier_sublinear);

    const auto extract = find_rel("Extract all tiles");
    BOOST_REQUIRE(extract != rels.end());
    BOOST_CHECK(!extract->proof_bound);
    BOOST_CHECK(extract->native_grounded);
    BOOST_CHECK(!extract->verifier_sublinear);
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
    // Feed-forward copy relation: committed state_out segment of barrier b
    // must equal next barrier's committed A operand at the sampled point.
    {
        auto p = H;
        BOOST_REQUIRE(!p.feed_evals.empty());
        p.feed_evals[0].c0 ^= 1;
        const std::string w = reject_why(p, header, target);
        BOOST_CHECK_MESSAGE(w.rfind("coupled:opening:", 0) == 0 ||
                                w == "coupled:transcript_hash",
                            w);
    }
    {
        auto p = H;
        p.batch.columns[ids.s(0)].root.data()[0] ^= 0xFF;
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
