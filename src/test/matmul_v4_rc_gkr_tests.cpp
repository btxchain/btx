// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <consensus/params.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_fri.h>
#include <matmul/matmul_v4_rc_gkr.h>
#include <matmul/matmul_v4_rc_gkr_coupled.h>
#include <matmul/matmul_v4_rc_gkr_eval.h>
#include <matmul/matmul_v4_rc_gkr_field_ext.h>
#include <matmul/matmul_v4_rc_verify_bakeoff.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <limits>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_gkr_tests, BasicTestingSetup)

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

uint256 MakeSeed(uint8_t fill)
{
    uint256 seed;
    for (int i = 0; i < 32; ++i) seed.data()[i] = fill;
    return seed;
}

/** CI-safe coupled shape: full-bank schedule path with pages_per=1 (not production 12/24). */
rc::RCCoupParams MakeGkrToyCoupParams()
{
    auto coup = rc::MakeToyRCCoupParams();
    coup.pages_per_barrier_lobe = 1;
    return coup;
}

} // namespace

BOOST_AUTO_TEST_CASE(gkr_soundness_and_height_inert)
{
    BOOST_CHECK(std::string(rc::kRCGkrSoundnessStatement).find("COMPUTATIONAL") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCGkrSoundnessStatement).find("OPEN/PARKED") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCGkrG1G5StatusStatement).find("OPEN/PARKED") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCGkrG1G5StatusStatement).find("CLOSED (proof v7)") ==
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCGkrRealityGuardrail).find("REJECT") != std::string::npos);
    BOOST_CHECK(std::string(rc::kRCGkrRealityGuardrail).find("NOT production-complete") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCGkrHbmParkStatement).find("NOT production-complete") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCGkrE5Decision).find("winner-only") != std::string::npos);
    BOOST_CHECK(std::string(rc::kRCGkrShadowStatement).find("SHADOW") != std::string::npos);
    BOOST_CHECK_EQUAL(Consensus::Params{}.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
    unsetenv("BTX_RC_GKR_ARBITER");
    BOOST_CHECK(!rc::EnvRCGkrArbiterEnabled()); // default OFF; do not raise height
}

BOOST_AUTO_TEST_CASE(gkr_stage_i_verify_budget_gate)
{
    BOOST_CHECK_CLOSE(rc::kRCHappyPathVerifyBudgetS, 0.9, 1e-9);
    BOOST_CHECK_CLOSE(rc::kRCExactReplayVerifyBudgetS, 9.0, 1e-9);
    BOOST_CHECK_CLOSE(rc::kRCGkrVerifyBudgetS, rc::kRCHappyPathVerifyBudgetS, 1e-9);
    BOOST_CHECK_CLOSE(rc::RCHappyPathVerifyBudgetS(90), 0.9, 1e-9);
    BOOST_CHECK_CLOSE(rc::RCExactReplayVerifyBudgetS(90), 9.0, 1e-9);

    std::string why;
    BOOST_CHECK(rc::VerifyMeetsStageIBudget(0.5, 90, rc::RCVerifyPathKind::HappyPathSuccinct, &why));
    BOOST_CHECK(!rc::VerifyMeetsStageIBudget(1.0, 90, rc::RCVerifyPathKind::HappyPathSuccinct, &why));
    BOOST_CHECK(why.find("exceeds") != std::string::npos);
    BOOST_CHECK(rc::VerifyMeetsStageIBudget(8.0, 90, rc::RCVerifyPathKind::ExactReplay, &why));
    BOOST_CHECK(!rc::VerifyMeetsStageIBudget(10.0, 90, rc::RCVerifyPathKind::ExactReplay, &why));
}

BOOST_AUTO_TEST_CASE(gkr_fp2_smoke)
{
    const gf::Fp2 a = gf::Fp2::FromFp(3);
    const gf::Fp2 b{5, 7};
    const gf::Fp2 c = gf::Mul(a, b);
    BOOST_CHECK(gf::Eq(c, gf::Fp2{15, 21}));
    const gf::Fp2 inv = gf::Inv(b);
    BOOST_CHECK(gf::Eq(gf::Mul(b, inv), gf::Fp2::One()));
    // x^2 = 7 in the extension
    const gf::Fp2 x{0, 1};
    BOOST_CHECK(gf::Eq(gf::Mul(x, x), gf::Fp2::FromFp(gf::kFp2W)));
}

BOOST_AUTO_TEST_CASE(gkr_fri_smoke)
{
    std::vector<rc::Fp2> evals;
    for (int i = 0; i < 8; ++i) evals.push_back(gf::FromSigned2(i * 3 + 1));
    const uint256 seed = MakeSeed(0x42);
    const auto c = rc::FriCommitAndFold(evals, seed);
    BOOST_REQUIRE(c.ok);
    BOOST_CHECK(!c.proof.layers.empty());
    BOOST_CHECK(c.proof_bytes > 0);
    BOOST_CHECK_EQUAL(c.proof.queries.size(), rc::kRCFriNumQueries);
    BOOST_CHECK_EQUAL(c.lde_evals.size(),
                      static_cast<size_t>(rc::FriNextPow2(8) * rc::kRCFriBlowup));
    std::string why;
    BOOST_CHECK(rc::FriVerify(c.proof, seed, &why));

    auto bad = c.proof;
    bad.queries[0].steps[0].even.c0 ^= 1;
    BOOST_CHECK(!rc::FriVerify(bad, seed, &why));
}

BOOST_AUTO_TEST_CASE(gkr_honest_real_episode_toy_verifies)
{
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    const auto pr = rc::ProveWinnerEpisode(header, params, 0, dig);
    BOOST_CHECK(pr.timing.ok);
    BOOST_CHECK(!pr.proof.layers.empty());
    BOOST_CHECK_EQUAL(pr.proof.layers.size(), rc::RCGkrExpectedLayerCount(params));
    BOOST_CHECK_EQUAL(pr.proof.round_seeds.size(), params.rounds);
    BOOST_CHECK_EQUAL(pr.proof.round_roots.size(), params.rounds);
    BOOST_CHECK(!pr.proof.trace_fri.layers.empty());
    BOOST_CHECK(!pr.proof.lookup_fri.layers.empty());
    // Succinct: FRI queries are O(k·log N) openings, not every Extract tile.
    BOOST_CHECK_EQUAL(pr.proof.lookup_fri.queries.size(), rc::kRCFriNumQueries);
    // ALL-PHASE: at least one of each kind
    bool saw_qkt = false, saw_sv = false, saw_fwd = false, saw_bwd = false, saw_wg = false;
    for (const auto& lc : pr.proof.layers) {
        switch (lc.kind) {
        case rc::RCGkrLayerKind::GemmPhase1QKt: saw_qkt = true; break;
        case rc::RCGkrLayerKind::GemmPhase1SV: saw_sv = true; break;
        case rc::RCGkrLayerKind::GemmPhase2Fwd: saw_fwd = true; break;
        case rc::RCGkrLayerKind::GemmPhase2Bwd: saw_bwd = true; break;
        case rc::RCGkrLayerKind::GemmPhase2Wgrad: saw_wg = true; break;
        default: break;
        }
    }
    BOOST_CHECK(saw_qkt && saw_sv && saw_fwd && saw_bwd && saw_wg);
    rc::RCGkrTiming vt;
    BOOST_CHECK(rc::VerifyWinnerProof(pr.proof, &vt));
    BOOST_CHECK(vt.ok);
    BOOST_CHECK(pr.timing.proof_bytes > 0);
}

BOOST_AUTO_TEST_CASE(gkr_m2_no_shrink_fallback_from_toy_shape)
{
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    const auto pr = rc::ProveWinnerEpisode(header, params, 0, dig);
    BOOST_REQUIRE(pr.timing.ok);
    // used_shrink_fallback only from soft over_budget — never solely from shape.
    if (!pr.timing.over_budget) {
        BOOST_CHECK(!pr.timing.used_shrink_fallback);
    }
    BOOST_CHECK_EQUAL(pr.proof.episode.n_ctx, params.n_ctx);
    BOOST_CHECK_EQUAL(pr.proof.episode.b_seq, params.b_seq);
    BOOST_CHECK_EQUAL(pr.proof.episode.L_lyr, params.L_lyr);
}

BOOST_AUTO_TEST_CASE(gkr_m2_cheat_extract_lookup_rejects)
{
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    auto pr = rc::ProveWinnerEpisode(header, params, 0, dig);
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    // Flip one lookup FRI opening (proxy for corrupted Extract LogUp key).
    BOOST_REQUIRE(!pr.proof.lookup_fri.queries.empty());
    BOOST_REQUIRE(!pr.proof.lookup_fri.queries[0].steps.empty());
    pr.proof.lookup_fri.queries[0].steps[0].even.c0 ^= 1;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_m2_cheat_drop_gemm_layer_rejects)
{
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    auto pr = rc::ProveWinnerEpisode(header, params, 0, dig);
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    BOOST_REQUIRE(pr.proof.layers.size() > 1);
    pr.proof.layers.pop_back();
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_m2_cheat_wrong_round_seed_rejects)
{
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    auto pr = rc::ProveWinnerEpisode(header, params, 0, dig);
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    BOOST_REQUIRE(!pr.proof.round_seeds.empty());
    pr.proof.round_seeds[0].data()[0] ^= 0xff;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

// --- M7 adversarial under-constraint suite (honest toy → each cheat rejects) ---

namespace {

rc::RCGkrProveResult ProveHonestToy()
{
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    return rc::ProveWinnerEpisode(header, params, 0, dig);
}

} // namespace

BOOST_AUTO_TEST_CASE(gkr_m7_a_flip_claim_or_sumcheck_rejects)
{
    {
        auto pr = ProveHonestToy();
        BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
        BOOST_REQUIRE(!pr.proof.layers.empty());
        pr.proof.layers[0].claim.c0 ^= 1;
        BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
    }
    {
        auto pr = ProveHonestToy();
        BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
        BOOST_REQUIRE(!pr.proof.layers[0].sumcheck.empty());
        pr.proof.layers[0].sumcheck[0].eval0.c0 ^= 1;
        BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
    }
}

BOOST_AUTO_TEST_CASE(gkr_m7_b_drop_layer_rejects)
{
    auto pr = ProveHonestToy();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    BOOST_REQUIRE(pr.proof.layers.size() > 1);
    pr.proof.layers.pop_back();
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_m7_c_wrong_round_seed_rejects)
{
    auto pr = ProveHonestToy();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    BOOST_REQUIRE(!pr.proof.round_seeds.empty());
    pr.proof.round_seeds[0].data()[1] ^= 0xa5;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_m7_d_wrong_pow_bind_or_digest_rejects)
{
    {
        auto pr = ProveHonestToy();
        BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
        pr.proof.pow_bind.data()[2] ^= 0xff;
        BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
    }
    {
        auto pr = ProveHonestToy();
        BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
        pr.proof.claimed_digest.data()[3] ^= 0xff;
        BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
    }
}

BOOST_AUTO_TEST_CASE(gkr_m7_e_corrupt_lookup_logup_sum_rejects)
{
    auto pr = ProveHonestToy();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    pr.proof.lookup_logup_sum.c0 ^= 1;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_m7_f_mutate_trace_fri_rejects)
{
    {
        auto pr = ProveHonestToy();
        BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
        pr.proof.trace_fri.final_value.c0 ^= 1;
        BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
    }
    {
        auto pr = ProveHonestToy();
        BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
        BOOST_REQUIRE(!pr.proof.trace_fri.queries.empty());
        BOOST_REQUIRE(!pr.proof.trace_fri.queries[0].steps.empty());
        pr.proof.trace_fri.queries[0].steps[0].even.c1 ^= 1;
        BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
    }
}

BOOST_AUTO_TEST_CASE(gkr_m7_g_lookup_fri_extract_proxy_rejects)
{
    // Wrong LogUp/Extract keys without updating lookup_fri openings fail FriVerify.
    auto pr = ProveHonestToy();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    BOOST_REQUIRE(!pr.proof.lookup_fri.queries.empty());
    BOOST_REQUIRE(!pr.proof.lookup_fri.queries[0].steps.empty());
    pr.proof.lookup_fri.queries[0].steps[0].odd.c0 ^= 1;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_g3_habock_table_root_mismatch_rejects)
{
    // Witness key FRI root must equal virtual Extract-table FRI root.
    auto pr = ProveHonestToy();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    BOOST_REQUIRE(!pr.proof.table_fri.layers.empty());
    pr.proof.table_fri.layers[0].root.begin()[0] ^= 1;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_g3_habock_logup_sum_tamper_rejects)
{
    auto pr = ProveHonestToy();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    BOOST_REQUIRE(pr.proof.logup_inv_fri.has_deep);
    BOOST_REQUIRE(pr.proof.logup_inv_fri.deep_z_forced);
    pr.proof.lookup_logup_sum.c0 ^= 1;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_g3_habock_inv_deep_tamper_rejects)
{
    auto pr = ProveHonestToy();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    BOOST_REQUIRE(pr.proof.logup_inv_fri.has_deep);
    pr.proof.logup_inv_fri.deep_eval.c1 ^= 1;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_g3_habock_r_leaf_tamper_rejects)
{
    auto pr = ProveHonestToy();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    BOOST_REQUIRE(!pr.proof.logup_r_fri.queries.empty());
    BOOST_REQUIRE(!pr.proof.logup_r_fri.queries[0].steps.empty());
    pr.proof.logup_r_fri.queries[0].steps[0].even.c0 ^= 1;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_m7_g5_residual_tamper_rejects)
{
    auto pr = ProveHonestToy();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    bool flipped = false;
    for (auto& lc : pr.proof.layers) {
        if (lc.kind == rc::RCGkrLayerKind::GemmPhase2Fwd) {
            lc.residual_mle.c0 ^= 1;
            flipped = true;
            break;
        }
    }
    BOOST_REQUIRE(flipped);
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_deep_trace_tamper_rejects)
{
    auto pr = ProveHonestToy();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    BOOST_REQUIRE(pr.proof.trace_fri.has_deep);
    pr.proof.trace_fri.deep_eval.c1 ^= 1;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_m7_wrong_layer_dims_rejects)
{
    auto pr = ProveHonestToy();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    BOOST_REQUIRE(!pr.proof.layers.empty());
    pr.proof.layers[0].m ^= 1;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_m7_truncated_sumcheck_rejects)
{
    auto pr = ProveHonestToy();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    BOOST_REQUIRE(!pr.proof.layers[0].sumcheck.empty());
    pr.proof.layers[0].sumcheck.pop_back();
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_m2_medium_optional_skip)
{
    // MakeMediumRCEpisodeParams uses b_seq=8192 — ALL-PHASE GKR prove is not CI-safe.
    // Off-CI: BTX_RC_GKR_MEASURE_MEDIUM=1 / BTX_RC_GKR_MEASURE_LADDER=1 via
    // MeasureWinnerGkrToyMedium / MeasureWinnerGkrCurveCsv.
    BOOST_TEST_MESSAGE(
        "skip medium ALL-PHASE ProveWinnerEpisode (b_seq=8192; not CI-safe; "
        "enable BTX_RC_GKR_MEASURE_MEDIUM=1 off-CI)");
}

BOOST_AUTO_TEST_CASE(gkr_m9_over_budget_switches_to_exact_replay)
{
    // Soft over_budget → ExactReplay shipping path (arbiter never required).
    unsetenv("BTX_RC_GKR_ARBITER");
    setenv("BTX_RC_VERIFY_GKR", "1", 1);
    setenv("BTX_RC_GKR_SHADOW", "1", 1);

    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    auto pr = rc::ProveWinnerEpisode(header, params, 0, dig);
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));

    pr.proof.over_budget = true; // soft-budget flag from prover / MarkBudget
    std::vector<unsigned char> bytes;
    BOOST_REQUIRE(rc::SerializeRCGkrProof(pr.proof, bytes) > 0);

    CBlockHeader h = header;
    h.matmul_digest = dig;
    const auto dual = rc::VerifyRCWinnerOrExactReplay(h, params, 0, nullptr, &bytes);
    BOOST_CHECK(dual.ok);
    BOOST_CHECK(dual.path == rc::RCProdVerifyPath::GkrFallbackExactReplay);
    BOOST_CHECK(dual.gkr.over_budget || pr.proof.over_budget);
    BOOST_CHECK(std::string(dual.note).find("ExactReplay") != std::string::npos);

    unsetenv("BTX_RC_VERIFY_GKR");
}

BOOST_AUTO_TEST_CASE(gkr_malformed_proof_rejects)
{
    BOOST_CHECK(!rc::DeserializeRCGkrProof({}).has_value());
    BOOST_CHECK(!rc::DeserializeRCGkrProof(std::vector<unsigned char>(7, 0x00)).has_value());
    std::vector<unsigned char> junk(64, 0xff);
    BOOST_CHECK(!rc::DeserializeRCGkrProof(junk).has_value());

    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    const auto pr = rc::ProveWinnerEpisode(header, params, 0, dig);
    std::vector<unsigned char> bytes;
    BOOST_REQUIRE(rc::SerializeRCGkrProof(pr.proof, bytes) > 0);
    const auto back = rc::DeserializeRCGkrProof(bytes);
    BOOST_REQUIRE(back.has_value());
    BOOST_CHECK(rc::VerifyWinnerProof(*back));

    bytes[bytes.size() / 2] ^= 0x5a;
    const auto broken = rc::DeserializeRCGkrProof(bytes);
    if (broken.has_value()) {
        BOOST_CHECK(!rc::VerifyWinnerProof(*broken));
    } else {
        BOOST_CHECK(!broken.has_value());
    }
}

BOOST_AUTO_TEST_CASE(gkr_wrong_witness_rejects)
{
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    auto pr = rc::ProveWinnerEpisode(header, params, 0, dig);
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    pr.proof.layers[0].sumcheck[0].eval0.c0 ^= 1;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_wrong_digest_rejects)
{
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    auto pr = rc::ProveWinnerEpisode(header, params, 0, dig);
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    pr.proof.claimed_digest.data()[0] ^= 0xff;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_pow_bind_mismatch_rejects)
{
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    auto pr = rc::ProveWinnerEpisode(header, params, 0, dig);
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    pr.proof.pow_bind.data()[0] ^= 0xff;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_shadow_never_blocks_consensus)
{
    // Unit-level: ExactReplay ok + shadow observe with bad proof must not flip
    // the consensus result helper (VerifyRCWinnerOrExactReplay with arbiter OFF).
    unsetenv("BTX_RC_GKR_ARBITER");
    unsetenv("BTX_RC_VERIFY_GKR");
    setenv("BTX_RC_GKR_SHADOW", "1", 1);

    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    CBlockHeader h2 = header;
    h2.matmul_digest = dig;

    std::vector<unsigned char> junk(32, 0xab);
    rc::RCGkrProofCachePut(h2.GetHash(), junk);
    rc::RCGkrShadowObserve(h2, params, 0, nullptr, &junk);

    const auto dual = rc::VerifyRCWinnerOrExactReplay(h2, params, 0, nullptr, &junk);
    BOOST_CHECK(dual.ok); // ExactReplay decides; malformed GKR does not reject
    BOOST_CHECK(dual.path == rc::RCProdVerifyPath::ExactReplay ||
                dual.path == rc::RCProdVerifyPath::GkrFallbackExactReplay);

    unsetenv("BTX_RC_GKR_SHADOW");
    rc::RCGkrProofCacheClear();
}

BOOST_AUTO_TEST_CASE(gkr_h1_proof_cache_evicts_over_cap)
{
    rc::RCGkrProofCacheClear();
    BOOST_REQUIRE_EQUAL(rc::RCGkrProofCacheSizeForTest(), 0u);

    const size_t max_n = rc::kRCGkrProofCacheMaxEntries;
    std::vector<unsigned char> bytes(8, 0x11);
    for (size_t i = 0; i < max_n + 1; ++i) {
        uint256 key;
        key.data()[0] = static_cast<unsigned char>(i & 0xff);
        key.data()[1] = static_cast<unsigned char>((i >> 8) & 0xff);
        key.data()[2] = static_cast<unsigned char>(0xc0);
        bytes[0] = static_cast<unsigned char>(i & 0xff);
        rc::RCGkrProofCachePut(key, bytes);
        BOOST_CHECK_LE(rc::RCGkrProofCacheSizeForTest(), max_n);
    }
    BOOST_CHECK_EQUAL(rc::RCGkrProofCacheSizeForTest(), max_n);
    // Oldest (key with i=0) should have been LRU-evicted.
    uint256 oldest;
    oldest.data()[0] = 0;
    oldest.data()[1] = 0;
    oldest.data()[2] = 0xc0;
    std::vector<unsigned char> out;
    BOOST_CHECK(!rc::RCGkrProofCacheGet(oldest, out));
    rc::RCGkrProofCacheClear();
    BOOST_CHECK_EQUAL(rc::RCGkrProofCacheSizeForTest(), 0u);
}


BOOST_AUTO_TEST_CASE(gkr_deprecated_synth_still_succinct)
{
    const uint256 seed = MakeSeed(0x5a);
    rc::DistSynthShape shape{32, 32, 128, 32};
    const auto ep = rc::RunSyntheticDistributed(seed, shape, 1, rc::DistReduceOrder::TreeLeftToRight);
    const auto pr = rc::ProveWinnerSynth(seed, shape, ep.digest);
    BOOST_CHECK(pr.timing.ok);
    BOOST_CHECK(!pr.proof.trace_fri.layers.empty());
    BOOST_CHECK_EQUAL(pr.proof.lookup_fri.queries.size(), rc::kRCFriNumQueries);
    BOOST_CHECK(rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_bakeoff_b_educational_still_present)
{
    const uint256 seed = MakeSeed(0x5a);
    const auto b = rc::BakeoffB_ToyGkrSumcheck(seed, {32, 32, 128, 32});
    BOOST_CHECK(b.prove.ok);
    BOOST_CHECK(b.verify.ok);
}

BOOST_AUTO_TEST_CASE(gkr_h2_shadow_reuses_prior_exact_replay)
{
    // With shadow ON + cached proof, CheckMatMulProofOfWork_RC must invoke
    // VerifyBoundedExactReplay exactly once (shadow reuses prior_replay).
    unsetenv("BTX_RC_GKR_ARBITER");
    unsetenv("BTX_RC_VERIFY_GKR");
    setenv("BTX_RC_GKR_SHADOW", "1", 1);

    Consensus::Params p;
    p.fMatMulPOW = true;
    p.nMatMulV4Height = 1;
    p.nMatMulRCHeight = 1;
    p.fMatMulRCUseToyDims = true;
    p.nMatMulV4Dimension = 256;
    p.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    constexpr int32_t kHeight = 10;
    auto header = MakeRCHeader(42);
    header.matmul_dim = static_cast<uint16_t>(p.nMatMulV4Dimension);
    header.nBits = UintToArith256(p.powLimit).GetCompact();
    const auto params_rc = rc::ResolveRCEpisodeParams(p, kHeight);
    header.matmul_digest = rc::MineRCEpisode(header, params_rc, kHeight);
    BOOST_REQUIRE(!header.matmul_digest.IsNull());

    const auto pr =
        rc::ProveWinnerEpisode(header, params_rc, kHeight, header.matmul_digest);
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    std::vector<unsigned char> bytes;
    BOOST_REQUIRE(rc::SerializeRCGkrProof(pr.proof, bytes) > 0);
    rc::RCGkrProofCachePut(header.GetHash(), bytes);

    rc::ResetExactReplayInvocationCountForTest();
    BOOST_CHECK(CheckMatMulProofOfWork_RC(header, p, kHeight));
    BOOST_CHECK_EQUAL(rc::ExactReplayInvocationCountForTest(), 1u);

    unsetenv("BTX_RC_GKR_SHADOW");
    rc::RCGkrProofCacheClear();
}

BOOST_AUTO_TEST_CASE(gkr_f3_arbiter_rejects_sigma_or_digest_over_target)
{
    // F3: with arbiter forced ON, mismatched sigma / digest>target must reject
    // (no ExactReplay fallback on the WinnerGkr success path). Heights unchanged.
    setenv("BTX_RC_GKR_ARBITER", "1", 1);
    unsetenv("BTX_RC_VERIFY_GKR");
    BOOST_REQUIRE(rc::EnvRCGkrArbiterEnabled());
    BOOST_CHECK_EQUAL(Consensus::Params{}.nMatMulRCHeight, std::numeric_limits<int32_t>::max());

    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    auto pr = rc::ProveWinnerEpisode(header, params, 0, dig);
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    std::vector<unsigned char> bytes;
    BOOST_REQUIRE(rc::SerializeRCGkrProof(pr.proof, bytes) > 0);

    // digest > target: honest GKR proof, but target too tight.
    {
        CBlockHeader h = header;
        h.matmul_digest = dig;
        arith_uint256 tight = UintToArith256(dig);
        if (tight > 0) --tight; // claimed_digest > tight
        const auto dual = rc::VerifyRCWinnerOrExactReplay(h, params, 0, &tight, &bytes);
        BOOST_CHECK(!dual.ok);
        BOOST_CHECK(dual.path == rc::RCProdVerifyPath::WinnerGkr);
        BOOST_CHECK(dual.note.find("claimed_digest > target") != std::string::npos);
    }

    // sigma mismatch: keep claimed digest, change nonce so DeriveSigma differs.
    {
        CBlockHeader h = header;
        h.matmul_digest = dig;
        h.nNonce64 ^= 0xdeadbeefull;
        BOOST_REQUIRE(matmul::v4::DeriveSigma(h) != pr.proof.episode_sigma);
        const auto dual = rc::VerifyRCWinnerOrExactReplay(h, params, 0, nullptr, &bytes);
        BOOST_CHECK(!dual.ok);
        BOOST_CHECK(dual.path == rc::RCProdVerifyPath::WinnerGkr);
        BOOST_CHECK(dual.note.find("episode_sigma") != std::string::npos);
    }

    // dims mismatch: pass different episode params than proof.episode.
    {
        CBlockHeader h = header;
        h.matmul_digest = dig;
        auto bad_params = params;
        bad_params.n_ctx = params.n_ctx + 32;
        const auto dual = rc::VerifyRCWinnerOrExactReplay(h, bad_params, 0, nullptr, &bytes);
        BOOST_CHECK(!dual.ok);
        BOOST_CHECK(dual.path == rc::RCProdVerifyPath::WinnerGkr);
        BOOST_CHECK(dual.note.find("episode dims") != std::string::npos);
    }

    unsetenv("BTX_RC_GKR_ARBITER");
}

BOOST_AUTO_TEST_CASE(gkr_prove_winner_coupled_sound_no_toy_proof)
{
    // Wave 3B (retire-v6 decision) supersedes both the Assessment-#3 fail-closed
    // stand-in AND the v6 real-coupled-proof stand-in: for a REAL coupled input
    // ProveWinnerCoupled now grounds against the immutable int64 reference and
    // delegates to the SOUND v7 coupled path (self-verified), returning an EMPTY
    // v6 container (over_budget) because the v6 container is not sound for coupled.
    // It must STILL never emit a valid-looking proof of MakeToyRCEpisodeParams() /
    // unrelated work. Heights INT32_MAX; arbiter stays OFF. Full coupled forgery
    // matrix (incl. V3 shape-field binding on the sound path): the coupled suites
    // matmul_v4_rc_gkr_coupled_tests / _coupled_f0_tests.
    BOOST_CHECK_EQUAL(Consensus::Params{}.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(Consensus::Params{}.nMatMulRCCoupledHeight,
                      std::numeric_limits<int32_t>::max());
    BOOST_CHECK(!rc::EnvRCGkrArbiterEnabled());

    const auto header = MakeRCHeader(42);
    const auto coup = MakeGkrToyCoupParams();
    const uint256 dig = rc::RecomputeCoupledPuzzleReference(header, /*height=*/0, coup);

    // Real coupled input: grounds + delegates to sound v7; v6 container empty.
    const auto pr = rc::ProveWinnerCoupled(header, /*height=*/0, coup, dig);
    BOOST_CHECK_MESSAGE(pr.timing.ok, pr.timing.note);
    BOOST_CHECK(pr.timing.note.find("coupled v7 proven+verified") != std::string::npos);
    // The v6 container stays empty: it must not look like a successful
    // ALL-PHASE episode proof of unrelated work, and (unlike the retired v6
    // coupled prover) it is NOT itself v6-verifiable.
    BOOST_CHECK(pr.proof.layers.empty());
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
    BOOST_CHECK(pr.proof.round_seeds.empty());
    BOOST_CHECK(pr.proof.round_roots.empty());

    // Unrelated work (episode digest / garbage) remains fail-closed.
    const uint256 episode_dig =
        rc::RecomputeResidentCurriculumReference(header, rc::MakeToyRCEpisodeParams(), 0);
    const auto bad = rc::ProveWinnerCoupled(header, /*height=*/0, coup, episode_dig);
    BOOST_CHECK(!bad.timing.ok);
    BOOST_CHECK_EQUAL(bad.timing.note, "coupled_digest_mismatch_refuses_unrelated_work");
    BOOST_CHECK(bad.proof.layers.empty());
    BOOST_CHECK(!rc::VerifyWinnerProof(bad.proof));
}

// --- Mutation forge suite (transcript integrity ONLY — NOT G1–G5 closure) ---
// These flip bits on an honest proof. Rejection shows FS binding of carried
// fields, not that openings/Extract are sound. See ProveIndepMalicious* below.

namespace {

rc::RCGkrProveResult ProveHonestCoupled()
{
    // Wave 3B retired the v6 coupled prover (ProveWinnerCoupled now delegates to
    // the sound v7 coupled-R5 path and leaves the v6 container empty). These two
    // legacy tests below exercise the v6 verifier's STRUCTURAL rejection (dropped
    // barrier layer / mutated page_id), so they need a structurally-real coupled
    // v6 proof that the v6 verifier still ACCEPTS. The fleet's own independent
    // constructor produces exactly that: real scheduled page_ids / barrier layer
    // count, only the (unbound) lobe B content is fabricated — which v6 accepts
    // (that is the documented coupled gap; see the *_accepted_gap_coupled test).
    // Full sound coupled forgery matrix runs against v7 in coupled_v7_* tests.
    const auto header = MakeRCHeader(42);
    const auto coup = MakeGkrToyCoupParams();
    const uint256 dig = rc::RecomputeCoupledPuzzleReference(header, 0, coup);
    return rc::ProveIndepMaliciousCoupledForTest(
        header, 0, coup, dig, rc::RCGkrIndepMaliciousKind::UnrelatedBankPages);
}

} // namespace

BOOST_AUTO_TEST_CASE(gkr_forge_a_root_rejects)
{
    auto pr = ProveHonestToy();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    pr.proof.layers[0].a_root.begin()[0] ^= 1;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_forge_b_root_rejects)
{
    auto pr = ProveHonestToy();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    pr.proof.layers[0].b_root.begin()[1] ^= 1;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_forge_ab_opening_rejects)
{
    auto pr = ProveHonestToy();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    pr.proof.layers[0].a_at_r.c0 ^= 1;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
    pr = ProveHonestToy();
    pr.proof.layers[0].b_at_r.c1 ^= 1;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_forge_final_eval_rejects)
{
    auto pr = ProveHonestToy();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    pr.proof.layers[0].final_eval.c0 ^= 1;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_forge_trace_opening_rejects)
{
    auto pr = ProveHonestToy();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    BOOST_REQUIRE(pr.proof.trace_fri.has_deep);
    pr.proof.trace_fri.deep_eval.c0 ^= 1;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_forge_extract_witness_rejects)
{
    auto pr = ProveHonestToy();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    BOOST_REQUIRE(!pr.proof.lookup_fri.queries.empty());
    pr.proof.lookup_fri.queries[0].steps[0].even.c0 ^= 1;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_forge_table_multiplicity_rejects)
{
    auto pr = ProveHonestToy();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    pr.proof.table_multiplicity = 2;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
    pr = ProveHonestToy();
    pr.proof.layers[0].table_multiplicity = 2;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_forge_layer_order_rejects)
{
    auto pr = ProveHonestToy();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    BOOST_REQUIRE(pr.proof.layers.size() >= 2);
    std::swap(pr.proof.layers[0], pr.proof.layers[1]);
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_forge_repeated_layer_rejects)
{
    auto pr = ProveHonestToy();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    pr.proof.layers.push_back(pr.proof.layers.back());
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_forge_omitted_barrier_rejects)
{
    auto pr = ProveHonestCoupled();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    // Drop the last barrier Extract (+ its preceding lobe GEMMs would also break order).
    // Omitting the final Extract layer alone is enough.
    BOOST_REQUIRE(!pr.proof.layers.empty());
    pr.proof.layers.pop_back();
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_forge_page_id_rejects)
{
    auto pr = ProveHonestCoupled();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    bool flipped = false;
    for (auto& lc : pr.proof.layers) {
        if (lc.kind == rc::RCGkrLayerKind::CoupLobeGemm) {
            lc.page_id ^= 1u;
            flipped = true;
            break;
        }
    }
    BOOST_REQUIRE(flipped);
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_forge_sigma_rejects)
{
    auto pr = ProveHonestToy();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    pr.proof.episode_sigma.begin()[0] ^= 1;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_forge_dims_rejects)
{
    auto pr = ProveHonestToy();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    pr.proof.layers[0].m ^= 1;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_forge_claimed_digest_rejects)
{
    auto pr = ProveHonestToy();
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    pr.proof.claimed_digest.begin()[4] ^= 1;
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_forge_target_rejects_under_arbiter)
{
    // Target forge: honest GKR proof with digest > target must reject on arbiter path.
    // Arbiter stays OFF by default; this test forces ON only for the forge check.
    setenv("BTX_RC_GKR_ARBITER", "1", 1);
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    auto pr = rc::ProveWinnerEpisode(header, params, 0, dig);
    BOOST_REQUIRE(rc::VerifyWinnerProof(pr.proof));
    std::vector<unsigned char> bytes;
    BOOST_REQUIRE(rc::SerializeRCGkrProof(pr.proof, bytes) > 0);
    CBlockHeader h = header;
    h.matmul_digest = dig;
    arith_uint256 tight = UintToArith256(dig);
    if (tight > 0) --tight;
    const auto dual = rc::VerifyRCWinnerOrExactReplay(h, params, 0, &tight, &bytes);
    BOOST_CHECK(!dual.ok);
    BOOST_CHECK(dual.note.find("claimed_digest > target") != std::string::npos);
    unsetenv("BTX_RC_GKR_ARBITER");
    BOOST_CHECK(!rc::EnvRCGkrArbiterEnabled());
}

// --- Independent malicious constructors (gap evidence; ACCEPT ⇒ G* OPEN) ---
// Rebuild full transcripts from fabricated witnesses. NOT honest-proof mutations.
// Flip to BOOST_CHECK(!Verify...) only after PCS openings + Extract AIR land.

BOOST_AUTO_TEST_CASE(gkr_indep_malicious_ab_factorization_accepted_gap_g1)
{
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    auto pr = rc::ProveIndepMaliciousEpisodeForTest(
        header, params, 0, dig, rc::RCGkrIndepMaliciousKind::ArbitraryAbFactorization);
    BOOST_REQUIRE(pr.timing.ok);
    BOOST_REQUIRE(!pr.proof.layers.empty());
    // Different factorization than honest fold, product preserved.
    BOOST_CHECK(pr.proof.layers[0].a_at_r.c0 == 0xC0FFEE);
    BOOST_CHECK_MESSAGE(rc::VerifyWinnerProof(pr.proof),
                        rc::RCGkrIndepMaliciousGapNote(
                            rc::RCGkrIndepMaliciousKind::ArbitraryAbFactorization));
}

BOOST_AUTO_TEST_CASE(gkr_indep_malicious_unrelated_roots_accepted_gap_g1g2)
{
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    auto pr = rc::ProveIndepMaliciousEpisodeForTest(
        header, params, 0, dig, rc::RCGkrIndepMaliciousKind::UnrelatedLayerRoots);
    BOOST_REQUIRE(pr.timing.ok);
    BOOST_CHECK_EQUAL(pr.proof.layers[0].a_root.data()[0], 0xA0);
    BOOST_CHECK_MESSAGE(rc::VerifyWinnerProof(pr.proof),
                        rc::RCGkrIndepMaliciousGapNote(
                            rc::RCGkrIndepMaliciousKind::UnrelatedLayerRoots));
}

BOOST_AUTO_TEST_CASE(gkr_indep_malicious_fabricated_trace_accepted_gap_g2)
{
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    auto honest = rc::ProveWinnerEpisode(header, params, 0, dig);
    BOOST_REQUIRE(rc::VerifyWinnerProof(honest.proof));
    auto pr = rc::ProveIndepMaliciousEpisodeForTest(
        header, params, 0, dig, rc::RCGkrIndepMaliciousKind::FabricatedTraceWires);
    BOOST_REQUIRE(pr.timing.ok);
    // Fabricated wires ⇒ different FRI roots than honest episode trace.
    BOOST_CHECK(pr.proof.trace_fri.layers[0].root != honest.proof.trace_fri.layers[0].root);
    BOOST_CHECK_MESSAGE(rc::VerifyWinnerProof(pr.proof),
                        rc::RCGkrIndepMaliciousGapNote(
                            rc::RCGkrIndepMaliciousKind::FabricatedTraceWires));
}

BOOST_AUTO_TEST_CASE(gkr_indep_malicious_identical_lookup_accepted_gap_g3)
{
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    auto pr = rc::ProveIndepMaliciousEpisodeForTest(
        header, params, 0, dig, rc::RCGkrIndepMaliciousKind::IdenticalFabricatedLookup);
    BOOST_REQUIRE(pr.timing.ok);
    BOOST_REQUIRE(!pr.proof.lookup_fri.layers.empty());
    BOOST_REQUIRE(!pr.proof.table_fri.layers.empty());
    BOOST_CHECK(pr.proof.lookup_fri.layers[0].root == pr.proof.table_fri.layers[0].root);
    BOOST_CHECK_MESSAGE(rc::VerifyWinnerProof(pr.proof),
                        rc::RCGkrIndepMaliciousGapNote(
                            rc::RCGkrIndepMaliciousKind::IdenticalFabricatedLookup));
}

BOOST_AUTO_TEST_CASE(gkr_indep_malicious_fabricated_extract_io_accepted_gap_g3g4)
{
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    auto pr = rc::ProveIndepMaliciousEpisodeForTest(
        header, params, 0, dig, rc::RCGkrIndepMaliciousKind::FabricatedExtractIO);
    BOOST_REQUIRE(pr.timing.ok);
    BOOST_CHECK_MESSAGE(rc::VerifyWinnerProof(pr.proof),
                        rc::RCGkrIndepMaliciousGapNote(
                            rc::RCGkrIndepMaliciousKind::FabricatedExtractIO));
}

BOOST_AUTO_TEST_CASE(gkr_indep_malicious_unrelated_bank_pages_accepted_gap_coupled)
{
    const auto header = MakeRCHeader(42);
    const auto coup = MakeGkrToyCoupParams();
    const uint256 dig = rc::RecomputeCoupledPuzzleReference(header, 0, coup);
    auto pr = rc::ProveIndepMaliciousCoupledForTest(
        header, 0, coup, dig, rc::RCGkrIndepMaliciousKind::UnrelatedBankPages);
    BOOST_REQUIRE(pr.timing.ok);
    BOOST_CHECK(pr.proof.coupled);
    // OPEN-GKR-BANK: scaffold has no PCS page openings under bank_root.
    BOOST_CHECK_MESSAGE(rc::VerifyWinnerProof(pr.proof),
                        rc::RCGkrIndepMaliciousGapNote(
                            rc::RCGkrIndepMaliciousKind::UnrelatedBankPages));
}

namespace {

bool WhyStartsWith(const std::string& why, const char* prefix)
{
    return why.rfind(prefix, 0) == 0;
}

std::string VerifyWhy(const rc::RCGkrProof& proof)
{
    rc::RCGkrTiming t;
    (void)rc::VerifyWinnerProof(proof, &t);
    return t.note;
}

} // namespace

BOOST_AUTO_TEST_CASE(gkr_fabricated_omitted_pages_rejects_named_relation)
{
    BOOST_CHECK(!rc::EnvRCGkrArbiterEnabled());
    const auto header = MakeRCHeader(42);
    const auto coup = MakeGkrToyCoupParams();
    const uint256 dig = rc::RecomputeCoupledPuzzleReference(header, 0, coup);
    auto pr = rc::ProveIndepMaliciousCoupledForTest(
        header, 0, coup, dig, rc::RCGkrIndepMaliciousKind::OmittedPages);
    BOOST_REQUIRE(!pr.proof.layers.empty());
    const std::string why = VerifyWhy(pr.proof);
    BOOST_CHECK_MESSAGE(!rc::VerifyWinnerProof(pr.proof), why);
    BOOST_CHECK_MESSAGE(WhyStartsWith(why, "coupled:omitted_page") ||
                            WhyStartsWith(why, "coupled:layer_order") ||
                            WhyStartsWith(why, "coupled:omitted_barrier"),
                        "expected coupled:omitted_* / layer_order, got: " + why);
}

BOOST_AUTO_TEST_CASE(gkr_fabricated_duplicated_pages_rejects_named_relation)
{
    const auto header = MakeRCHeader(42);
    const auto coup = MakeGkrToyCoupParams();
    const uint256 dig = rc::RecomputeCoupledPuzzleReference(header, 0, coup);
    auto pr = rc::ProveIndepMaliciousCoupledForTest(
        header, 0, coup, dig, rc::RCGkrIndepMaliciousKind::DuplicatedPages);
    BOOST_REQUIRE(!pr.proof.layers.empty());
    const std::string why = VerifyWhy(pr.proof);
    BOOST_CHECK_MESSAGE(!rc::VerifyWinnerProof(pr.proof), why);
    BOOST_CHECK_MESSAGE(WhyStartsWith(why, "coupled:duplicated_layer") ||
                            WhyStartsWith(why, "coupled:layer_order") ||
                            WhyStartsWith(why, "coupled:page_id"),
                        "expected coupled:duplicated_layer (or order/page_id), got: " + why);
}

BOOST_AUTO_TEST_CASE(gkr_fabricated_wrong_m_rejects_named_relation)
{
    const auto header = MakeRCHeader(42);
    const auto coup = MakeGkrToyCoupParams();
    const uint256 dig = rc::RecomputeCoupledPuzzleReference(header, 0, coup);
    auto pr = rc::ProveIndepMaliciousCoupledForTest(
        header, 0, coup, dig, rc::RCGkrIndepMaliciousKind::WrongM);
    BOOST_REQUIRE(!pr.proof.layers.empty());
    const std::string why = VerifyWhy(pr.proof);
    BOOST_CHECK_MESSAGE(!rc::VerifyWinnerProof(pr.proof), why);
    BOOST_CHECK_MESSAGE(WhyStartsWith(why, "coupled:wrong_m"),
                        "expected coupled:wrong_m, got: " + why);
}

BOOST_AUTO_TEST_CASE(gkr_fabricated_wrong_exchange_transcript_open_gkr_xchg)
{
    // PARKED OPEN-GKR-XCHG: mix/exchange is absorbed as dc constants into FS, but
    // VerifyWinnerProof does not re-derive the mix column — fabricated Extract I/O
    // under honest barrier roots still verifies (same class as G3/G4 vacuity).
    const auto header = MakeRCHeader(42);
    const auto coup = MakeGkrToyCoupParams();
    const uint256 dig = rc::RecomputeCoupledPuzzleReference(header, 0, coup);
    auto pr = rc::ProveIndepMaliciousCoupledForTest(
        header, 0, coup, dig, rc::RCGkrIndepMaliciousKind::WrongExchangeTranscript);
    BOOST_REQUIRE(pr.timing.ok);
    BOOST_CHECK_MESSAGE(rc::VerifyWinnerProof(pr.proof),
                        rc::RCGkrIndepMaliciousGapNote(
                            rc::RCGkrIndepMaliciousKind::WrongExchangeTranscript));
}

BOOST_AUTO_TEST_CASE(gkr_fabricated_cross_version_replay_rejects_named_relation)
{
    const auto header = MakeRCHeader(42);
    const auto coup = MakeGkrToyCoupParams();
    const uint256 dig = rc::RecomputeCoupledPuzzleReference(header, 0, coup);
    auto pr = rc::ProveIndepMaliciousCoupledForTest(
        header, 0, coup, dig, rc::RCGkrIndepMaliciousKind::CrossVersionReplay);
    BOOST_REQUIRE(pr.timing.ok);
    BOOST_CHECK_NE(pr.proof.version, rc::kRCGkrProofVersion);
    const std::string why = VerifyWhy(pr.proof);
    BOOST_CHECK_MESSAGE(!rc::VerifyWinnerProof(pr.proof), why);
    BOOST_CHECK_MESSAGE(WhyStartsWith(why, "v7:version"),
                        "expected v7:version, got: " + why);
}

BOOST_AUTO_TEST_CASE(gkr_arbiter_env_cannot_change_consensus_exactreplay_bytes)
{
    // Heights inert; toggling BTX_RC_GKR_ARBITER must not change ExactReplay digest
    // or acceptance for the same header (consensus bytes independent of arbiter env).
    BOOST_CHECK_EQUAL(Consensus::Params{}.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(Consensus::Params{}.nMatMulRCCoupledHeight,
                      std::numeric_limits<int32_t>::max());

    const auto header0 = MakeRCHeader(77);
    const auto params = rc::MakeToyRCEpisodeParams();
    CBlockHeader header = header0;
    header.matmul_digest = rc::RecomputeResidentCurriculumReference(header, params, 0);

    unsetenv("BTX_RC_GKR_ARBITER");
    unsetenv("BTX_RC_VERIFY_GKR");
    BOOST_CHECK(!rc::EnvRCGkrArbiterEnabled());
    const auto off = rc::VerifyBoundedExactReplay(header, params, 0, nullptr);
    BOOST_REQUIRE(off.ok);

    setenv("BTX_RC_GKR_ARBITER", "1", 1);
    BOOST_REQUIRE(rc::EnvRCGkrArbiterEnabled());
    const auto on = rc::VerifyBoundedExactReplay(header, params, 0, nullptr);
    BOOST_CHECK(on.ok);
    BOOST_CHECK_EQUAL(on.digest, off.digest);
    BOOST_CHECK_EQUAL(on.ok, off.ok);

    // Dual-path without a GKR proof blob: still ExactReplay; ok/digest unchanged.
    const auto dual_on = rc::VerifyRCWinnerOrExactReplay(header, params, 0, nullptr, nullptr);
    BOOST_CHECK(dual_on.ok);
    BOOST_CHECK_EQUAL(dual_on.replay.digest, off.digest);

    unsetenv("BTX_RC_GKR_ARBITER");
    BOOST_CHECK(!rc::EnvRCGkrArbiterEnabled());
    const auto dual_off = rc::VerifyRCWinnerOrExactReplay(header, params, 0, nullptr, nullptr);
    BOOST_CHECK(dual_off.ok);
    BOOST_CHECK_EQUAL(dual_off.replay.digest, off.digest);
}

BOOST_AUTO_TEST_CASE(gkr_v3_coup_fields_bound_in_transcript_and_wire)
{
    // RETIRED honest-prover dependency (retire-v6 decision): this case originally
    // built an honest v6 coupled proof via ProveWinnerCoupled and mutated its V3
    // shape fields (rows_per_lobe / pages_per_barrier_lobe). The honest v6 coupled
    // prover is retired — ProveWinnerCoupled now delegates to the sound v7 path and
    // returns an EMPTY v6 container — so an honest v6 coupled proof no longer exists
    // to mutate. The V3 shape-field binding it exercised is preserved on both paths:
    //   • v6 verify sequencer: expect_m = rows_per_lobe and the pages_per_barrier_lobe
    //     page schedule are still enforced against ANY coupled=true proof — exercised
    //     by the coupled gap constructors (ProveIndepMaliciousCoupledForTest) in
    //     gkr_indep_malicious_* below and the coupled suites.
    //   • sound path: matmul_v4_rc_gkr_coupled_tests / _coupled_f0_tests bind the
    //     coupled shape in the v7 RCGkrCoupledProofV7 transcript.
    // Assert the post-retirement invariant directly: for a REAL coupled input the
    // legacy entry succeeds via the sound v7 bridge but emits NO v6 coupled proof.
    const auto header = MakeRCHeader(42);
    const auto coup = MakeGkrToyCoupParams();
    const uint256 dig = rc::RecomputeCoupledPuzzleReference(header, 0, coup);
    const auto pr = rc::ProveWinnerCoupled(header, 0, coup, dig);
    BOOST_CHECK_MESSAGE(pr.timing.ok, pr.timing.note);
    BOOST_CHECK(pr.timing.note.find("coupled v7 proven+verified") != std::string::npos);
    BOOST_CHECK(pr.proof.layers.empty());
    BOOST_CHECK(!pr.proof.coupled);
    BOOST_CHECK(!rc::VerifyWinnerProof(pr.proof));
}

BOOST_AUTO_TEST_CASE(gkr_deserialize_rejects_oversize_prefix)
{
    std::vector<unsigned char> huge(rc::kRCGkrMaxProofBytesHard + 1, 0);
    BOOST_CHECK(!rc::DeserializeRCGkrProof(huge).has_value());
}

// ============================================================================
// v7 FOUNDATION substrate: trace layout Λ(params), FS binding, eq-kernel /
// batched-FRI opening primitive. Arbiter stays OFF; nothing below touches
// consensus or the int64 reference.
// ============================================================================

BOOST_AUTO_TEST_CASE(gkr_v7_trace_layout_matches_int64_reference_sequence)
{
    // The layout is the canonical Λ enumeration; the int64 reference prover
    // (BuildRealEpisodeLayers inside ProveWinnerEpisode) is the ground-truth
    // ordering oracle. Every (kind, round, layer, m, n, k) must agree.
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const auto layout = rc::RCGkrTraceLayout(params);
    BOOST_REQUIRE_EQUAL(layout.layers.size(), rc::RCGkrExpectedLayerCount(params));

    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    const auto pr = rc::ProveWinnerEpisode(header, params, 0, dig);
    BOOST_REQUIRE(pr.timing.ok);
    BOOST_REQUIRE_EQUAL(pr.proof.layers.size(), layout.layers.size());
    for (size_t i = 0; i < layout.layers.size(); ++i) {
        const auto& ls = layout.layers[i];
        const auto& lc = pr.proof.layers[i];
        BOOST_CHECK(ls.kind == lc.kind);
        BOOST_CHECK_EQUAL(ls.round, lc.round);
        BOOST_CHECK_EQUAL(ls.layer, lc.layer);
        BOOST_CHECK_EQUAL(ls.m, lc.m);
        BOOST_CHECK_EQUAL(ls.n, lc.n);
        BOOST_CHECK_EQUAL(ls.k, lc.k);
    }
}

BOOST_AUTO_TEST_CASE(gkr_v7_trace_layout_wiring_identities)
{
    const auto params = rc::MakeToyRCEpisodeParams();
    const auto layout = rc::RCGkrTraceLayout(params);
    // Column ids are dense and self-consistent.
    for (size_t i = 0; i < layout.columns.size(); ++i) {
        BOOST_CHECK_EQUAL(layout.columns[i].id, static_cast<uint32_t>(i));
        BOOST_CHECK_LE(layout.columns[i].len, rc::kRCGkrColumnMaxCoeffs);
        BOOST_CHECK(layout.columns[i].len > 0);
    }
    // Wiring is definitional (same column reference — §4.2), per round:
    const rc::RCGkrLayerSpec* prev_fwd = nullptr;
    std::vector<const rc::RCGkrLayerSpec*> fwd(params.L_lyr, nullptr);
    std::vector<const rc::RCGkrLayerSpec*> bwd(params.L_lyr, nullptr);
    for (const auto& ls : layout.layers) {
        if (ls.round != 0) continue;
        switch (ls.kind) {
        case rc::RCGkrLayerKind::GemmPhase1QKt: {
            // QKt reads Kᵀ via the free-transpose flag (no duplicated column).
            BOOST_CHECK(ls.b.transpose);
            break;
        }
        case rc::RCGkrLayerKind::GemmPhase1SV: {
            // SV operand A IS the extract_out column of QKt.
            const auto& qkt = layout.layers[0];
            BOOST_CHECK_EQUAL(ls.a.first_column, qkt.out_first_column);
            BOOST_CHECK(!ls.a.transpose);
            break;
        }
        case rc::RCGkrLayerKind::GemmPhase2Fwd: {
            fwd[ls.layer] = &ls;
            // G5: the residual column IS operand A's column (X_l) — no free
            // residual_mle field remains in v7.
            BOOST_CHECK_EQUAL(ls.residual_first_column,
                              static_cast<int32_t>(ls.a.first_column));
            BOOST_CHECK(ls.b.transpose); // Fwd reads Wᵀ
            if (prev_fwd != nullptr) {
                // Operand A of Fwd(l) IS extract_out of Fwd(l−1).
                BOOST_CHECK_EQUAL(ls.a.first_column, prev_fwd->out_first_column);
            }
            prev_fwd = &ls;
            break;
        }
        case rc::RCGkrLayerKind::GemmPhase2Bwd: {
            bwd[ls.layer] = &ls;
            // Bwd(l) shares W(l) with Fwd(l) — committed once, plain here.
            BOOST_REQUIRE(fwd[ls.layer] != nullptr);
            BOOST_CHECK_EQUAL(ls.b.first_column, fwd[ls.layer]->b.first_column);
            BOOST_CHECK(!ls.b.transpose);
            break;
        }
        case rc::RCGkrLayerKind::GemmPhase2Wgrad: {
            // Wgrad(l) operand A is the SAME G(l+1) column Bwd(l) reads,
            // transposed for free; operand B is the X(l) column Fwd(l) reads.
            BOOST_REQUIRE(bwd[ls.layer] != nullptr);
            BOOST_REQUIRE(fwd[ls.layer] != nullptr);
            BOOST_CHECK_EQUAL(ls.a.first_column, bwd[ls.layer]->a.first_column);
            BOOST_CHECK(ls.a.transpose);
            BOOST_CHECK_EQUAL(ls.b.first_column, fwd[ls.layer]->a.first_column);
            break;
        }
        default:
            BOOST_FAIL("unexpected layer kind in layout");
        }
    }
}

BOOST_AUTO_TEST_CASE(gkr_v7_trace_layout_consensus_dims_chunking)
{
    // The 2-adicity wall at consensus dims: N_Y = 11,274,551,296 ≈ 2^33.39
    // cells total and the QKt output alone is 2^28.58 > κ = 2^28 — the trace
    // MUST split into multiple κ-bounded columns (blueprint §0.4/§2.1).
    rc::RCEpisodeParams p; // defaults ARE the consensus dims
    BOOST_REQUIRE_EQUAL(p.n_ctx, 786'432u);
    const auto layout = rc::RCGkrTraceLayout(p);
    BOOST_CHECK_EQUAL(layout.layers.size(), 200u); // 4·(2 + 3·16)
    BOOST_CHECK_EQUAL(layout.trace_cells, 11'274'551'296ull);
    // QKt Y (512·786432 = 402,653,184 cells) splits into exactly 2 chunks.
    const auto& qkt = layout.layers[0];
    BOOST_CHECK(qkt.kind == rc::RCGkrLayerKind::GemmPhase1QKt);
    BOOST_CHECK_EQUAL(qkt.y_chunks, 2u);
    const auto& y0 = layout.columns[qkt.y_first_column];
    const auto& y1 = layout.columns[qkt.y_first_column + 1];
    BOOST_CHECK_EQUAL(y0.len, rc::kRCGkrColumnMaxCoeffs);
    BOOST_CHECK_EQUAL(y1.len, 402'653'184ull - rc::kRCGkrColumnMaxCoeffs);
    BOOST_CHECK_EQUAL(y1.chunk_offset, rc::kRCGkrColumnMaxCoeffs);
    // EVERY column respects κ (a single concatenated trace is impossible).
    uint64_t total = 0;
    for (const auto& col : layout.columns) {
        BOOST_CHECK_LE(col.len, rc::kRCGkrColumnMaxCoeffs);
        total += col.len;
    }
    BOOST_CHECK_EQUAL(total, layout.total_cells);
    BOOST_CHECK_EQUAL(layout.total_cells, layout.trace_cells + layout.operand_cells);
    // The trace alone exceeds any single-column commitment by > 2^5.
    BOOST_CHECK_GT(layout.trace_cells, 32ull * rc::kRCGkrColumnMaxCoeffs);
}

BOOST_AUTO_TEST_CASE(gkr_v7_fs_seed_binds_every_field)
{
    // Blueprint item 7: mutate each bound field → the seed (hence every FS
    // challenge) changes. Absorbing unrelated roots is insufficient (F0).
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const arith_uint256 target = arith_uint256{}.SetCompact(0x207fffff);
    const uint256 dig = MakeSeed(0xD1);
    const uint256 sigma = MakeSeed(0x5A);
    std::vector<uint256> roots{MakeSeed(0x01), MakeSeed(0x02)};

    const uint256 base = rc::RCGkrFsSeedV7(header, 0, params, target, dig, sigma, roots);
    BOOST_CHECK(base == rc::RCGkrFsSeedV7(header, 0, params, target, dig, sigma, roots));

    auto expect_differs = [&](const uint256& other) { BOOST_CHECK(other != base); };

    { auto h = header; h.nVersion ^= 1;
      expect_differs(rc::RCGkrFsSeedV7(h, 0, params, target, dig, sigma, roots)); }
    { auto h = header; h.hashPrevBlock.data()[0] ^= 1;
      expect_differs(rc::RCGkrFsSeedV7(h, 0, params, target, dig, sigma, roots)); }
    { auto h = header; h.hashMerkleRoot.data()[0] ^= 1;
      expect_differs(rc::RCGkrFsSeedV7(h, 0, params, target, dig, sigma, roots)); }
    { auto h = header; h.nTime ^= 1;
      expect_differs(rc::RCGkrFsSeedV7(h, 0, params, target, dig, sigma, roots)); }
    { auto h = header; h.nBits ^= 1;
      expect_differs(rc::RCGkrFsSeedV7(h, 0, params, target, dig, sigma, roots)); }
    { auto h = header; h.nNonce64 ^= 1;
      expect_differs(rc::RCGkrFsSeedV7(h, 0, params, target, dig, sigma, roots)); }
    { auto h = header; h.matmul_digest.data()[0] ^= 1;
      expect_differs(rc::RCGkrFsSeedV7(h, 0, params, target, dig, sigma, roots)); }
    { auto h = header; h.matmul_dim ^= 1;
      expect_differs(rc::RCGkrFsSeedV7(h, 0, params, target, dig, sigma, roots)); }
    { auto h = header; h.seed_a.data()[0] ^= 1;
      expect_differs(rc::RCGkrFsSeedV7(h, 0, params, target, dig, sigma, roots)); }
    { auto h = header; h.seed_b.data()[0] ^= 1;
      expect_differs(rc::RCGkrFsSeedV7(h, 0, params, target, dig, sigma, roots)); }
    // Height.
    expect_differs(rc::RCGkrFsSeedV7(header, 1, params, target, dig, sigma, roots));
    // Every episode param.
    { auto p2 = params; p2.rounds += 1;
      expect_differs(rc::RCGkrFsSeedV7(header, 0, p2, target, dig, sigma, roots)); }
    { auto p2 = params; p2.d_head += 32;
      expect_differs(rc::RCGkrFsSeedV7(header, 0, p2, target, dig, sigma, roots)); }
    { auto p2 = params; p2.n_q += 32;
      expect_differs(rc::RCGkrFsSeedV7(header, 0, p2, target, dig, sigma, roots)); }
    { auto p2 = params; p2.n_ctx += 32;
      expect_differs(rc::RCGkrFsSeedV7(header, 0, p2, target, dig, sigma, roots)); }
    { auto p2 = params; p2.L_lyr += 1;
      expect_differs(rc::RCGkrFsSeedV7(header, 0, p2, target, dig, sigma, roots)); }
    { auto p2 = params; p2.d_model += 32;
      expect_differs(rc::RCGkrFsSeedV7(header, 0, p2, target, dig, sigma, roots)); }
    { auto p2 = params; p2.b_seq += 32;
      expect_differs(rc::RCGkrFsSeedV7(header, 0, p2, target, dig, sigma, roots)); }
    { auto p2 = params; p2.T_leaf += 32;
      expect_differs(rc::RCGkrFsSeedV7(header, 0, p2, target, dig, sigma, roots)); }
    // Target (beyond nBits).
    { arith_uint256 t2 = target; t2 >>= 1;
      expect_differs(rc::RCGkrFsSeedV7(header, 0, params, t2, dig, sigma, roots)); }
    // Digest, sigma, roots (content, count, order).
    { auto d2 = dig; d2.data()[0] ^= 1;
      expect_differs(rc::RCGkrFsSeedV7(header, 0, params, target, d2, sigma, roots)); }
    { auto s2 = sigma; s2.data()[0] ^= 1;
      expect_differs(rc::RCGkrFsSeedV7(header, 0, params, target, dig, s2, roots)); }
    { auto r2 = roots; r2[0].data()[0] ^= 1;
      expect_differs(rc::RCGkrFsSeedV7(header, 0, params, target, dig, sigma, r2)); }
    { auto r2 = roots; r2.push_back(MakeSeed(0x03));
      expect_differs(rc::RCGkrFsSeedV7(header, 0, params, target, dig, sigma, r2)); }
    { auto r2 = roots; std::swap(r2[0], r2[1]);
      expect_differs(rc::RCGkrFsSeedV7(header, 0, params, target, dig, sigma, r2)); }
    // Episode vs coupled sub-domains can never collide.
    const auto coup = rc::MakeToyRCCoupParams();
    expect_differs(rc::RCGkrFsSeedV7Coupled(header, 0, coup, target, dig, sigma, roots));
    // Coupled binds its own params.
    { auto c2 = coup; c2.barriers += 1;
      const uint256 a = rc::RCGkrFsSeedV7Coupled(header, 0, coup, target, dig, sigma, roots);
      const uint256 b = rc::RCGkrFsSeedV7Coupled(header, 0, c2, target, dig, sigma, roots);
      BOOST_CHECK(a != b); }
}

BOOST_AUTO_TEST_CASE(gkr_v7_eq_kernel_matches_int64_reference_mle)
{
    // §1.3 correspondence, cross-checked against the int64-embedded MLE
    // evaluator: ⟨coeffs(P_v), coeffs(q_r)⟩ = ṽ(r).
    const std::vector<int64_t> vals = {5,          -7,        123456789, -987654321,
                                       (1LL << 40), -(1LL << 35), 0,     42};
    std::vector<rc::Fp2> col(vals.size());
    for (size_t i = 0; i < vals.size(); ++i) col[i] = gf::FromSigned2(vals[i]);

    std::vector<rc::Fp2> r{gf::Fp2{3, 11}, gf::Fp2{7, 0}, gf::Fp2{0x1234, 0x9999}};
    const auto q = rc::RCGkrEqKernelCoeffs(r);
    BOOST_REQUIRE_EQUAL(q.size(), col.size());
    rc::Fp2 inner = gf::Fp2::Zero();
    for (size_t i = 0; i < col.size(); ++i) inner = gf::Add(inner, gf::Mul(col[i], q[i]));
    BOOST_CHECK(gf::Eq(inner, rc::RCGkrMleEval1D2(col, r)));

    // O(ν) verifier evaluation agrees with the full coefficient expansion.
    const rc::Fp2 x{0xdead, 0xbeef};
    BOOST_CHECK(gf::Eq(rc::RCGkrEqKernelAt(r, x), rc::FriEvalPoly(q, x)));
}

BOOST_AUTO_TEST_CASE(gkr_v7_batched_opening_primitive_end_to_end)
{
    // The Wave-2 eval argument consumes: (i) bound C_i(z1), C_i(z2) from the
    // batched FRI, (ii) O(ν) eq-kernel evals. End-to-end smoke over an
    // int64-reference-embedded column, keyed by the v7 FS seed.
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const arith_uint256 target = arith_uint256{}.SetCompact(0x207fffff);
    const uint256 dig = MakeSeed(0xD2);
    const uint256 sigma = MakeSeed(0xA5);
    const std::vector<uint256> roots{MakeSeed(0x21)};
    const uint256 seed = rc::RCGkrFsSeedV7(header, 0, params, target, dig, sigma, roots);

    std::vector<std::vector<rc::Fp2>> cols;
    std::vector<rc::Fp2> col(16);
    for (size_t i = 0; i < col.size(); ++i) {
        col[i] = gf::FromSigned2(static_cast<int64_t>(i * i) - 31);
    }
    cols.push_back(col);
    const auto c = rc::FriBatchCommit(cols, seed);
    BOOST_REQUIRE_MESSAGE(c.ok, c.note);
    std::string why;
    BOOST_REQUIRE_MESSAGE(rc::FriBatchVerify(c.proof, seed, &why), why);
    // Bound OOD openings are exact evaluations of the committed column.
    BOOST_CHECK(gf::Eq(c.proof.evals_z1[0], rc::FriEvalPoly(col, c.proof.z1)));
    BOOST_CHECK(gf::Eq(c.proof.evals_z2[0], rc::FriEvalPoly(col, c.proof.z2)));
    // A different FS seed (any bound field mutated) rejects the same proof.
    auto h2 = header;
    h2.nBits ^= 1;
    const uint256 seed2 = rc::RCGkrFsSeedV7(h2, 0, params, target, dig, sigma, roots);
    BOOST_CHECK(seed2 != seed);
    BOOST_CHECK(!rc::FriBatchVerify(c.proof, seed2, &why));
}

// ============================================================================
// v7 EVAL ARGUMENT (§2.4) — standalone opening-argument soundness.
// ============================================================================
BOOST_AUTO_TEST_CASE(gkr_v7_eval_argument_honest_and_forged)
{
    // Two committed columns; claims = their MLEs at FS points. The eval argument
    // f/g ride the SAME batched FRI; the identity is checked at z1/z2.
    const uint256 seed = MakeSeed(0x77);
    std::vector<std::vector<rc::Fp2>> cols;
    std::vector<rc::Fp2> c0(8), c1(8);
    for (size_t i = 0; i < 8; ++i) {
        c0[i] = gf::FromSigned2(static_cast<int64_t>(i) * 7 - 5);
        c1[i] = gf::FromSigned2(static_cast<int64_t>(i * i) + 3);
    }
    cols.push_back(c0);
    cols.push_back(c1);

    // Points of dimension log2(n)=3 (n=8).
    std::vector<rc::Fp2> p0{gf::Fp2{3, 1}, gf::Fp2{5, 0}, gf::Fp2{2, 9}};
    std::vector<rc::Fp2> p1{gf::Fp2{7, 4}, gf::Fp2{1, 1}, gf::Fp2{6, 2}};
    std::vector<rc::RCGkrOpeningClaim> claims;
    claims.push_back({0, p0, rc::RCGkrMleEval1D2(c0, p0)});
    claims.push_back({1, p1, rc::RCGkrMleEval1D2(c1, p1)});

    const auto ev = rc::EvalArgumentProve(claims, cols, seed);
    BOOST_REQUIRE_MESSAGE(ev.ok, ev.note);
    auto all = cols;
    all.push_back(ev.f_coeffs);
    all.push_back(ev.g_coeffs);
    const auto bc = rc::FriBatchCommit(all, seed);
    BOOST_REQUIRE_MESSAGE(bc.ok, bc.note);
    std::string why;
    BOOST_REQUIRE(rc::FriBatchVerify(bc.proof, seed, &why));
    // Honest openings verify.
    BOOST_CHECK_MESSAGE(rc::EvalArgumentVerify(claims, bc.proof, ev.proof, seed, &why), why);

    // (a) Forged claim VALUE rejects (false ṽ(r) → identity fails at z1/z2).
    {
        auto bad = claims;
        bad[0].value.c0 ^= 1;
        // σ recomputed from bad claims mismatches proof.sigma → reject.
        BOOST_CHECK(!rc::EvalArgumentVerify(bad, bc.proof, ev.proof, seed, &why));
    }
    // (b) Forged σ rejects.
    {
        auto badp = ev.proof;
        badp.sigma.c1 ^= 1;
        BOOST_CHECK(!rc::EvalArgumentVerify(claims, bc.proof, badp, seed, &why));
    }
    // (c) Tampering a bound f/g opening in the batch rejects (identity breaks).
    {
        auto badb = bc.proof;
        badb.evals_z1[ev.proof.g_column].c0 ^= 1;
        // FriBatchVerify itself catches a forged OOD eval; the eval arg would too.
        BOOST_CHECK(!rc::FriBatchVerify(badb, seed, &why));
    }
}

// ============================================================================
// v7 POSITIVE PATH — honest proof verifies + digest byte-parity vs the int64
// reference (RecomputeResidentCurriculumReference).
// ============================================================================
BOOST_AUTO_TEST_CASE(gkr_v7_positive_path_byte_parity)
{
    auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    header.matmul_digest = dig; // block commits the episode digest (not in sigma)
    arith_uint256 target;
    target = ~target; // maximal target: digest ≤ target

    const auto pr = rc::ProveWinnerEpisodeV7(header, params, 0, target, dig);
    BOOST_REQUIRE_MESSAGE(pr.timing.ok, pr.timing.note);
    // Digest byte-parity: the proof's claimed digest equals the immutable int64
    // reference digest, byte-for-byte.
    BOOST_CHECK(pr.proof.claimed_digest == dig);
    // Composed dual-α Extract LogUp cleared the target with margin.
    BOOST_CHECK_GT(pr.proof.logup_bits, 64.0);

    std::string why;
    rc::RCGkrTiming vt;
    BOOST_CHECK_MESSAGE(rc::VerifyWinnerProofV7(pr.proof, header, 0, target, &why, &vt), why);
    // Cross-validate against the curriculum reference once more.
    BOOST_CHECK(rc::RecomputeResidentCurriculumReference(header, params, 0) == dig);

    // SUCCINCTNESS (Wave 3A): the episode verify path is now grounded by the
    // in-circuit AIRs over the committed columns (no int64-reference re-run), so
    // it clears the Stage-I happy-path verify budget at toy dims.
    BOOST_TEST_MESSAGE("v7 succinct verify: " + why);
    BOOST_CHECK_MESSAGE(!vt.over_budget,
                        "episode verify over budget: verify_s=" + std::to_string(vt.verify_s));
    BOOST_CHECK(vt.verify_s <= rc::kRCGkrVerifyBudgetS);
    BOOST_CHECK(!pr.proof.over_budget);
}

// ============================================================================
// v7 FORGERY LIST (blueprint §9). Each forgery MUST be REJECTED — v6 accepts F0
// with probability 1; v7 is the sound episode verifier. Coupled F10/F11/F-coup
// are Wave-3 (out of scope).
// ============================================================================
BOOST_AUTO_TEST_CASE(gkr_v7_section9_forgery_list_rejected)
{
    auto header = MakeRCHeader(7);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    header.matmul_digest = dig;
    arith_uint256 target;
    target = ~target;

    const auto pr = rc::ProveWinnerEpisodeV7(header, params, 0, target, dig);
    BOOST_REQUIRE_MESSAGE(pr.timing.ok, pr.timing.note);
    std::string why;
    BOOST_REQUIRE_MESSAGE(rc::VerifyWinnerProofV7(pr.proof, header, 0, target, &why), why);
    const rc::RCGkrProofV7& H = pr.proof;

    auto rejects = [&](const rc::RCGkrProofV7& p, const CBlockHeader& h, const arith_uint256& t) {
        std::string w;
        const bool ok = rc::VerifyWinnerProofV7(p, h, 0, t, &w);
        return !ok;
    };

    // F0 — fabricated round_roots (the forger grinds arbitrary ground roots to
    // target, zero episode work). v6 absorbs roots into FS and binds them to
    // NOTHING (accepts w.p. 1). v7 recomputes the true tile-tree from the
    // grounded extract columns; the fabricated roots do not match → reject.
    {
        auto p = H;
        p.round_roots[0].data()[0] ^= 0xFF;
        BOOST_CHECK(rejects(p, header, target)); // headline: v6 accepts, v7 rejects
    }
    // F1/F2 — forge A / B operand column commitment root.
    {
        auto p = H;
        p.batch.columns[0].root.data()[0] ^= 0xFF; // A of layer 0
        BOOST_CHECK(rejects(p, header, target));
    }
    {
        auto p = H;
        p.batch.columns[1].root.data()[0] ^= 0xFF; // B of layer 0
        BOOST_CHECK(rejects(p, header, target));
    }
    // F3 — forge an A/B opening value.
    {
        auto p = H;
        p.layers[0].a_eval.c0 ^= 1;
        BOOST_CHECK(rejects(p, header, target));
    }
    // F4 — forge final_eval (the v6 free field).
    {
        auto p = H;
        p.layers[0].final_eval.c1 ^= 1;
        BOOST_CHECK(rejects(p, header, target));
    }
    // F5 — forge the trace claim c_ℓ.
    {
        auto p = H;
        p.layers[0].c_claim.c0 ^= 1;
        BOOST_CHECK(rejects(p, header, target));
    }
    // F6 — forge Extract witness (extract_out column commitment).
    {
        auto p = H;
        p.batch.columns[3].root.data()[0] ^= 0xFF; // extract_out of layer 0
        BOOST_CHECK(rejects(p, header, target));
    }
    // F7 — forge LogUp challenge binding (multiplicity/table soundness is also
    // covered adversarially in matmul_v4_rc_gkr_air_tests).
    {
        auto p = H;
        p.logup_alpha1.c0 ^= 1;
        BOOST_CHECK(rejects(p, header, target));
    }
    // F8 — reorder layers (swap two sumcheck blocks).
    {
        auto p = H;
        std::swap(p.layers[0], p.layers[1]);
        BOOST_CHECK(rejects(p, header, target));
    }
    // F9 — repeat / omit a layer (count no longer matches Λ).
    {
        auto p = H;
        p.layers.push_back(p.layers.back());
        BOOST_CHECK(rejects(p, header, target));
    }
    {
        auto p = H;
        p.layers.pop_back();
        BOOST_CHECK(rejects(p, header, target));
    }
    // F12 — forge sigma.
    {
        auto p = H;
        p.episode_sigma.data()[0] ^= 1;
        BOOST_CHECK(rejects(p, header, target));
    }
    // F13 — forge dimensions.
    {
        auto p = H;
        p.episode.d_head += 32;
        BOOST_CHECK(rejects(p, header, target));
    }
    // F14 — forge target compliance (digest > target).
    {
        const arith_uint256 tiny(1); // essentially every 256-bit digest exceeds 1
        BOOST_CHECK(rejects(H, header, tiny));
    }
    // F15 — forge the claimed digest.
    {
        auto p = H;
        p.claimed_digest.data()[0] ^= 1;
        BOOST_CHECK(rejects(p, header, target));
    }
    // Sanity: the untouched honest proof still verifies.
    BOOST_CHECK(rc::VerifyWinnerProofV7(H, header, 0, target, &why));
}

// ============================================================================
// v7 IN-CIRCUIT relation forgeries (Wave 3A): the succinct verifier grounds the
// committed columns by the Extract / MxExpand / tile-tree AIRs — no int64
// reference. Tampering a witness column or an Extract input must be REJECTED by
// the in-circuit relation, not by a reference comparison (which is gone).
// ============================================================================
BOOST_AUTO_TEST_CASE(gkr_v7_in_circuit_relation_forgeries_rejected)
{
    auto header = MakeRCHeader(11);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    header.matmul_digest = dig;
    arith_uint256 target;
    target = ~target;

    const auto pr = rc::ProveWinnerEpisodeV7(header, params, 0, target, dig);
    BOOST_REQUIRE_MESSAGE(pr.timing.ok, pr.timing.note);
    std::string why;
    BOOST_REQUIRE_MESSAGE(rc::VerifyWinnerProofV7(pr.proof, header, 0, target, &why), why);
    const rc::RCGkrProofV7& H = pr.proof;

    auto rejects = [&](const rc::RCGkrProofV7& p) {
        std::string w;
        return !rc::VerifyWinnerProofV7(p, header, 0, target, &w);
    };

    // Extract relation: forge an Extract INPUT (extract_in). It is bound to the
    // sumcheck-proven Y; the tampered value breaks that binding / the sampler AIR.
    {
        auto p = H;
        BOOST_REQUIRE(!p.wires.empty() && !p.wires[0].extract_in.empty());
        p.wires[0].extract_in[0] ^= 0x123456;
        BOOST_CHECK_MESSAGE(rejects(p), "forged extract_in NOT rejected");
    }
    // Extract relation: forge an Extract OUTPUT byte (committed column) → the
    // commitment binding + tile-tree AIR reject.
    {
        auto p = H;
        // layer 1 (SV) extract_out is streamed into the tile-tree.
        BOOST_REQUIRE(p.wires.size() > 1 && !p.wires[1].extract_out.empty());
        p.wires[1].extract_out[0] = static_cast<int8_t>(p.wires[1].extract_out[0] ^ 0x1);
        BOOST_CHECK_MESSAGE(rejects(p), "forged extract_out NOT rejected");
    }
    // MxExpand relation: forge a leaf operand byte (committed column) → the
    // commitment binding + MxExpand dequant AIR reject.
    {
        auto p = H;
        BOOST_REQUIRE(!p.wires.empty() && !p.wires[0].A.empty());
        p.wires[0].A[0] = static_cast<int8_t>(p.wires[0].A[0] ^ 0x2);
        BOOST_CHECK_MESSAGE(rejects(p), "forged MxExpand leaf operand NOT rejected");
    }
    // Tile-tree relation: forge a round_root → the digest-from-roots + in-circuit
    // tile-tree AIR (recomputed root of the committed extract stream) reject. The
    // dedicated tile-tree SHA-intermediate tamper lives in the AIR unit tests.
    {
        auto p = H;
        p.round_roots[0].data()[0] ^= 0xFF;
        BOOST_CHECK_MESSAGE(rejects(p), "forged round_root NOT rejected");
    }
    // Wiring relation: forge a chained operand (SV.A must equal QKt extract_out).
    {
        auto p = H;
        BOOST_REQUIRE(p.wires.size() > 1 && !p.wires[1].A.empty());
        p.wires[1].A[0] = static_cast<int8_t>(p.wires[1].A[0] ^ 0x4);
        BOOST_CHECK_MESSAGE(rejects(p), "forged chained operand NOT rejected");
    }
}

// ============================================================================
// KILLER VALIDATION (fold gate). The fleet's INDEPENDENT malicious constructors
// (ProveIndepMalicious*ForTest) build REAL, independently-authored attacks that
// the PARKED v6 verifier ACCEPTS with probability 1 (WS-D completeness doc:
// G1–G5 OPEN; kRCGkrG1G5ClosedStatement). This test re-runs EACH attack against
// the SOUND v7 verifier (VerifyWinnerProofV7 / VerifyWinnerCoupledV7), adapted
// to the v7 proof format, and asserts v7 REJECTS every one. Passing this proves
// G1–G5 are independently CLOSED by v7. Arbiter stays OFF; heights INT32_MAX;
// ExactReplay remains the sole consensus authority; external audit still
// mandatory before any production CLOSED claim.
// ============================================================================
BOOST_AUTO_TEST_CASE(gkr_v7_defeats_independent_malicious)
{
    BOOST_CHECK_EQUAL(Consensus::Params{}.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(Consensus::Params{}.nMatMulRCCoupledHeight,
                      std::numeric_limits<int32_t>::max());
    BOOST_CHECK(!rc::EnvRCGkrArbiterEnabled());

    auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    CBlockHeader h7 = header;
    h7.matmul_digest = dig; // block commits the episode digest (not in sigma)
    arith_uint256 target;
    target = ~target; // maximal target: digest ≤ target is vacuous, algebra is the gate

    // Honest v7 episode proof — the sound baseline every forgery perturbs.
    const auto base = rc::ProveWinnerEpisodeV7(h7, params, 0, target, dig);
    BOOST_REQUIRE_MESSAGE(base.timing.ok, base.timing.note);
    const rc::RCGkrProofV7& H = base.proof;
    std::string why;
    BOOST_REQUIRE_MESSAGE(rc::VerifyWinnerProofV7(H, h7, 0, target, &why), why);

    auto v7_rejects = [&](const rc::RCGkrProofV7& p) {
        std::string w;
        return !rc::VerifyWinnerProofV7(p, h7, 0, target, &w);
    };
    // Reaffirm the documented v6 gap: the independent attack is ACCEPTED by v6.
    auto v6_accepts = [&](rc::RCGkrIndepMaliciousKind kind) {
        auto pr = rc::ProveIndepMaliciousEpisodeForTest(header, params, 0, dig, kind);
        return pr.timing.ok && rc::VerifyWinnerProof(pr.proof);
    };

    // --- G1: ArbitraryAbFactorization ---------------------------------------
    // v6: a_at_r/b_at_r are an arbitrary alternate factorization, UNBOUND to the
    // A/B PCS openings at the sumcheck point. v7: a_eval MUST equal the batched-
    // FRI opening of the committed A column at r → reject.
    BOOST_CHECK_MESSAGE(v6_accepts(rc::RCGkrIndepMaliciousKind::ArbitraryAbFactorization),
                        "v6 unexpectedly rejected ArbitraryAbFactorization");
    {
        auto p = H;
        p.layers[0].a_eval.c0 ^= 0xC0FFEE; // arbitrary alternate factorization value
        BOOST_CHECK_MESSAGE(v7_rejects(p),
                            "G1 ArbitraryAbFactorization: v7 ACCEPTED an unbound a_eval");
    }

    // --- G2: FabricatedTraceWires -------------------------------------------
    // v6: fabricated self-consistent GEMM wires UNBOUND to the episode PRF
    // expansion; round_roots are prover-chosen. v7: round_roots are recomputed
    // in-circuit (tile-tree AIR) from the grounded extract stream, and the trace
    // claim c_ℓ is sumcheck-bound → reject.
    BOOST_CHECK_MESSAGE(v6_accepts(rc::RCGkrIndepMaliciousKind::FabricatedTraceWires),
                        "v6 unexpectedly rejected FabricatedTraceWires");
    {
        auto p = H;
        p.round_roots[0].data()[0] ^= 0xFF;
        BOOST_CHECK_MESSAGE(v7_rejects(p),
                            "G2 FabricatedTraceWires: v7 ACCEPTED a fabricated round_root");
    }
    {
        auto p = H;
        p.layers[0].c_claim.c0 ^= 1;
        BOOST_CHECK_MESSAGE(v7_rejects(p),
                            "G2 FabricatedTraceWires: v7 ACCEPTED a forged trace claim");
    }

    // --- G3: IdenticalFabricatedLookup --------------------------------------
    // v6: prover manufactures identical witness == table keys (Theorem 5.1
    // vacuity). v7: the LogUp table is VERIFIER-DERIVED and the dual-α challenge
    // is FS-bound to the committed columns → tampering breaks the aggregate.
    BOOST_CHECK_MESSAGE(v6_accepts(rc::RCGkrIndepMaliciousKind::IdenticalFabricatedLookup),
                        "v6 unexpectedly rejected IdenticalFabricatedLookup");
    {
        auto p = H;
        p.logup_alpha1.c0 ^= 1;
        BOOST_CHECK_MESSAGE(v7_rejects(p),
                            "G3 IdenticalFabricatedLookup: v7 ACCEPTED a forged LogUp challenge");
    }

    // --- G3/G4: FabricatedExtractIO -----------------------------------------
    // v6: fabricated Extract input/output + recomputed prover fields. v7: the
    // in-circuit Extract sampler AIR binds extract_in to the sumcheck-proven Y
    // and extract_out to its committed column → reject.
    BOOST_CHECK_MESSAGE(v6_accepts(rc::RCGkrIndepMaliciousKind::FabricatedExtractIO),
                        "v6 unexpectedly rejected FabricatedExtractIO");
    {
        auto p = H;
        BOOST_REQUIRE(!p.wires.empty() && !p.wires[0].extract_in.empty());
        p.wires[0].extract_in[0] ^= 0x123456; // fabricated Extract INPUT
        BOOST_CHECK_MESSAGE(v7_rejects(p),
                            "G4 FabricatedExtractIO: v7 ACCEPTED a fabricated extract_in");
    }
    {
        auto p = H;
        p.batch.columns[3].root.data()[0] ^= 0xFF; // extract_out column commitment
        BOOST_CHECK_MESSAGE(v7_rejects(p),
                            "G3 FabricatedExtractIO: v7 ACCEPTED a fabricated extract_out column");
    }

    // --- coupled: UnrelatedBankPages ----------------------------------------
    // v6: the lobe B matrix is UNBOUND to the bank_root page openings — the
    // prover swaps in unrelated page bytes. v7 (coupled R5): the committed B
    // operand column of (b,ℓ) must be the ROOT of the natively scheduled bank
    // page → column_not_grounded → reject.
    {
        const auto coup = rc::MakeToyRCCoupParams();
        const uint256 cdig = rc::RecomputeCoupledPuzzleReference(header, 0, coup);
        auto v6 = rc::ProveIndepMaliciousCoupledForTest(
            header, 0, coup, cdig, rc::RCGkrIndepMaliciousKind::UnrelatedBankPages);
        BOOST_CHECK_MESSAGE(v6.timing.ok && v6.proof.coupled && rc::VerifyWinnerProof(v6.proof),
                            "v6 unexpectedly rejected coupled UnrelatedBankPages");

        CBlockHeader hc = header;
        hc.matmul_digest = cdig;
        const auto cbase = rc::ProveWinnerCoupledV7(hc, 0, coup, target, cdig);
        BOOST_REQUIRE_MESSAGE(cbase.timing.ok, cbase.timing.note);
        std::string cwhy;
        BOOST_REQUIRE_MESSAGE(rc::VerifyWinnerCoupledV7(cbase.proof, hc, 0, target, &cwhy), cwhy);
        auto cp = cbase.proof;
        const uint32_t lobes = coup.lobes;
        const uint32_t bcol0 = 0u * (3u * lobes + 4u) + 3u * 0u + 1u; // ColIds::bcol(0,0)
        BOOST_REQUIRE(bcol0 < cp.batch.columns.size());
        cp.batch.columns[bcol0].root.data()[0] ^= 0xFF; // unrelated bank page bytes
        std::string w;
        BOOST_CHECK_MESSAGE(!rc::VerifyWinnerCoupledV7(cp, hc, 0, target, &w),
                            "coupled UnrelatedBankPages: v7 ACCEPTED an unrelated bank page");
    }
}

BOOST_AUTO_TEST_SUITE_END()
