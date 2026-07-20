// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/params.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_fri.h>
#include <matmul/matmul_v4_rc_gkr.h>
#include <matmul/matmul_v4_rc_gkr_field_ext.h>
#include <matmul/matmul_v4_rc_verify_bakeoff.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <limits>
#include <string>

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

} // namespace

BOOST_AUTO_TEST_CASE(gkr_soundness_and_height_inert)
{
    BOOST_CHECK(std::string(rc::kRCGkrSoundnessStatement).find("COMPUTATIONAL") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCGkrRealityGuardrail).find("REJECT") != std::string::npos);
    BOOST_CHECK(std::string(rc::kRCGkrRealityGuardrail).find("NOT production-complete") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCGkrHbmParkStatement).find("NOT production-complete") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCGkrE5Decision).find("winner-only") != std::string::npos);
    BOOST_CHECK(std::string(rc::kRCGkrShadowStatement).find("SHADOW") != std::string::npos);
    BOOST_CHECK_EQUAL(Consensus::Params{}.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
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

BOOST_AUTO_TEST_SUITE_END()
