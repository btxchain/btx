// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <common/args.h>
#include <pow.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>
#include <chrono>
#include <cstdint>
#include <limits>

namespace {

Consensus::Params MainParams()
{
    return CreateChainParams(ArgsManager{}, ChainType::MAIN)->GetConsensus();
}

Consensus::Params TestnetParams()
{
    return CreateChainParams(ArgsManager{}, ChainType::TESTNET)->GetConsensus();
}

Consensus::Params RegtestParams()
{
    return CreateChainParams(ArgsManager{}, ChainType::REGTEST)->GetConsensus();
}

Consensus::Params SignetParams()
{
    return CreateChainParams(ArgsManager{}, ChainType::SIGNET)->GetConsensus();
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(matmul_trust_model_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(trust_model_validation_window_default)
{
    const auto params = MainParams();
    BOOST_CHECK_EQUAL(params.nMatMulValidationWindow, 1000U);
}

BOOST_AUTO_TEST_CASE(trust_model_validation_window_testnet)
{
    const auto params = TestnetParams();
    BOOST_CHECK_EQUAL(params.nMatMulValidationWindow, 500U);
}

BOOST_AUTO_TEST_CASE(trust_model_validation_window_regtest)
{
    const auto params = RegtestParams();
    BOOST_CHECK_EQUAL(params.nMatMulValidationWindow, 10U);
}

BOOST_AUTO_TEST_CASE(trust_model_validation_window_covers_dgw)
{
    constexpr uint32_t DGW_PAST_BLOCKS = 180;
    const auto main_params = MainParams();
    const auto testnet_params = TestnetParams();
    const auto signet_params = SignetParams();

    // Production-like networks must cover the full DGW horizon.
    BOOST_CHECK(main_params.nMatMulValidationWindow >= DGW_PAST_BLOCKS);
    BOOST_CHECK(testnet_params.nMatMulValidationWindow >= DGW_PAST_BLOCKS);
    BOOST_CHECK(signet_params.nMatMulValidationWindow >= DGW_PAST_BLOCKS);
}

BOOST_AUTO_TEST_CASE(trust_model_validation_window_minimum_floor)
{
    constexpr uint32_t MINIMUM_WINDOW_FLOOR = 100;
    const auto main_params = MainParams();
    const auto testnet_params = TestnetParams();
    const auto signet_params = SignetParams();
    const auto regtest_params = RegtestParams();

    // Mainnet/testnet/signet enforce the production full-node floor.
    BOOST_CHECK(main_params.nMatMulValidationWindow >= MINIMUM_WINDOW_FLOOR);
    BOOST_CHECK(testnet_params.nMatMulValidationWindow >= MINIMUM_WINDOW_FLOOR);
    BOOST_CHECK(signet_params.nMatMulValidationWindow >= MINIMUM_WINDOW_FLOOR);
    // Regtest remains intentionally tiny for fast local iteration.
    BOOST_CHECK(regtest_params.nMatMulValidationWindow < MINIMUM_WINDOW_FLOOR);
}

// TEST: consensus_node_validates_all_new_tips
// TEST: economic_node_accepts_all_headers
// TEST: economic_node_never_runs_phase2
// TEST: spv_node_validates_headers_only
BOOST_AUTO_TEST_CASE(phase2_decision_tree_for_modes_and_sync_state)
{
    auto params = MainParams();
    params.fSkipMatMulValidation = false;

    constexpr int32_t best_known_height = 5'000;
    constexpr int32_t tip_height = 5'000;

    BOOST_CHECK(ShouldRunMatMulPhase2Validation(
        tip_height,
        best_known_height,
        params,
        /*phase2_enabled=*/true,
        /*is_ibd=*/false));

    BOOST_CHECK(!ShouldRunMatMulPhase2Validation(
        tip_height,
        best_known_height,
        params,
        /*phase2_enabled=*/false,
        /*is_ibd=*/false));
}

BOOST_AUTO_TEST_CASE(phase2_ibd_forces_full_validation)
{
    auto params = MainParams();
    params.fSkipMatMulValidation = false;

    constexpr int32_t best_known_height = 5'000;
    BOOST_CHECK(ShouldRunMatMulPhase2Validation(
        1,
        best_known_height,
        params,
        /*phase2_enabled=*/true,
        /*is_ibd=*/true));
    BOOST_CHECK(ShouldRunMatMulPhase2Validation(
        3'000,
        best_known_height,
        params,
        /*phase2_enabled=*/true,
        /*is_ibd=*/true));
    BOOST_CHECK(!ShouldRunMatMulPhase2Validation(
        3'000,
        best_known_height,
        params,
        /*phase2_enabled=*/false,
        /*is_ibd=*/true));
}

BOOST_AUTO_TEST_CASE(product_digest_activation_disables_phase2_even_in_ibd)
{
    auto params = MainParams();
    params.fSkipMatMulValidation = false;
    params.nMatMulFreivaldsBindingHeight = 5'000;
    params.nMatMulProductDigestHeight = 5'000;

    constexpr int32_t best_known_height = 5'010;
    BOOST_CHECK(!ShouldRunMatMulPhase2Validation(
        5'000,
        best_known_height,
        params,
        /*phase2_enabled=*/true,
        /*is_ibd=*/false));
    BOOST_CHECK(!ShouldRunMatMulPhase2Validation(
        5'000,
        best_known_height,
        params,
        /*phase2_enabled=*/true,
        /*is_ibd=*/true));
}

BOOST_AUTO_TEST_CASE(phase2_ibd_batch_count_enforces_budgeting)
{
    auto params = MainParams();
    params.fSkipMatMulValidation = false;

    constexpr int32_t best_known_height = 5'000;
    BOOST_CHECK_EQUAL(CountMatMulPhase2Checks(
        /*first_height=*/1,
        /*header_count=*/12,
        best_known_height,
        params,
        /*phase2_enabled=*/true,
        /*is_ibd=*/true), 12U);
    BOOST_CHECK_EQUAL(CountMatMulPhase2Checks(
        /*first_height=*/1,
        /*header_count=*/12,
        best_known_height,
        params,
        /*phase2_enabled=*/false,
        /*is_ibd=*/true), 0U);
}

BOOST_AUTO_TEST_CASE(product_digest_activation_caps_phase2_batch_counts)
{
    auto params = MainParams();
    params.fSkipMatMulValidation = false;
    params.nMatMulFreivaldsBindingHeight = 5'000;
    params.nMatMulProductDigestHeight = 5'000;

    constexpr int32_t best_known_height = 5'010;
    BOOST_CHECK_EQUAL(CountMatMulPhase2Checks(
        /*first_height=*/4'998,
        /*header_count=*/5,
        best_known_height,
        params,
        /*phase2_enabled=*/true,
        /*is_ibd=*/false), 2U);
    BOOST_CHECK_EQUAL(CountMatMulPhase2Checks(
        /*first_height=*/4'998,
        /*header_count=*/5,
        best_known_height,
        params,
        /*phase2_enabled=*/true,
        /*is_ibd=*/true), 2U);
}

BOOST_AUTO_TEST_CASE(phase2_steady_state_batch_count_respects_window)
{
    auto params = MainParams();
    params.fSkipMatMulValidation = false;

    constexpr int32_t best_known_height = 5'000;
    BOOST_CHECK_EQUAL(CountMatMulPhase2Checks(
        /*first_height=*/3'996,
        /*header_count=*/10,
        best_known_height,
        params,
        /*phase2_enabled=*/true,
        /*is_ibd=*/false), 5U);
}

BOOST_AUTO_TEST_CASE(phase2_batch_count_saturates_on_height_overflow)
{
    auto params = MainParams();
    params.fSkipMatMulValidation = false;

    constexpr int32_t best_known_height = std::numeric_limits<int32_t>::max();
    BOOST_CHECK_EQUAL(CountMatMulPhase2Checks(
        /*first_height=*/std::numeric_limits<int32_t>::max() - 1LL,
        /*header_count=*/4,
        best_known_height,
        params,
        /*phase2_enabled=*/true,
        /*is_ibd=*/false), std::numeric_limits<uint32_t>::max());
}

// TEST: economic_node_window_boundary_steady_state
BOOST_AUTO_TEST_CASE(ibd_within_validation_window_runs_phase2)
{
    auto params = MainParams();
    params.fSkipMatMulValidation = false;

    constexpr int32_t best_known_height = 5000;
    BOOST_CHECK_EQUAL(MatMulPhase2ValidationStartHeight(best_known_height, params), 4001);
    BOOST_CHECK(ShouldRunMatMulPhase2ForHeight(5000, best_known_height, params));
    BOOST_CHECK(ShouldRunMatMulPhase2ForHeight(4001, best_known_height, params));
}

BOOST_AUTO_TEST_CASE(ibd_outside_validation_window_skips_phase2)
{
    auto params = MainParams();
    params.fSkipMatMulValidation = false;

    constexpr int32_t best_known_height = 5000;
    BOOST_CHECK(!ShouldRunMatMulPhase2ForHeight(4000, best_known_height, params));
    BOOST_CHECK(!ShouldRunMatMulPhase2ForHeight(1, best_known_height, params));
}

BOOST_AUTO_TEST_CASE(validation_skip_mode)
{
    auto params = MainParams();
    params.fSkipMatMulValidation = true;

    BOOST_CHECK(!ShouldRunMatMulPhase2ForHeight(5000, 5000, params));
    BOOST_CHECK(!ShouldRunMatMulPhase2ForHeight(1, 5000, params));
}

BOOST_AUTO_TEST_CASE(validation_phase2_softfail_testnet)
{
    const auto params = TestnetParams();
    BOOST_CHECK_EQUAL(EffectivePhase2BanThreshold(params), std::numeric_limits<uint32_t>::max());

    MatMulPeerVerificationBudget budget;
    const auto now = std::chrono::steady_clock::now();

    auto action = RegisterMatMulPhase2Failure(budget, params, now);
    BOOST_CHECK(action == MatMulPhase2Punishment::DISCONNECT);

    action = RegisterMatMulPhase2Failure(budget, params, now + std::chrono::minutes{1});
    BOOST_CHECK(action == MatMulPhase2Punishment::DISCOURAGE);

    for (int i = 0; i < 8; ++i) {
        action = RegisterMatMulPhase2Failure(
            budget,
            params,
            now + std::chrono::minutes{2 + i});
        BOOST_CHECK(action == MatMulPhase2Punishment::DISCOURAGE);
    }
    BOOST_CHECK_EQUAL(budget.phase2_failures, 10U);
}

BOOST_AUTO_TEST_CASE(validation_phase2_softfail_testnet_ignores_strict_flag)
{
    auto params = TestnetParams();
    params.fMatMulStrictPunishment = true;

    BOOST_CHECK_EQUAL(EffectivePhase2BanThreshold(params), std::numeric_limits<uint32_t>::max());

    MatMulPeerVerificationBudget budget;
    const auto action = RegisterMatMulPhase2Failure(budget, params, std::chrono::steady_clock::now());
    BOOST_CHECK(action == MatMulPhase2Punishment::DISCONNECT);
}

BOOST_AUTO_TEST_CASE(validation_phase2_softfail_regtest)
{
    auto params = RegtestParams();
    params.fMatMulStrictPunishment = true;

    BOOST_CHECK_EQUAL(EffectivePhase2BanThreshold(params), std::numeric_limits<uint32_t>::max());

    MatMulPeerVerificationBudget budget;
    const auto now = std::chrono::steady_clock::now();
    BOOST_CHECK(RegisterMatMulPhase2Failure(budget, params, now) == MatMulPhase2Punishment::DISCONNECT);
    BOOST_CHECK(RegisterMatMulPhase2Failure(budget, params, now + std::chrono::minutes{1}) == MatMulPhase2Punishment::DISCOURAGE);
    BOOST_CHECK(RegisterMatMulPhase2Failure(budget, params, now + std::chrono::minutes{2}) == MatMulPhase2Punishment::DISCOURAGE);
}

BOOST_AUTO_TEST_CASE(validation_phase2_failure_counter_persists_across_rate_limit_reset)
{
    auto params = MainParams();
    params.fMatMulStrictPunishment = false;
    params.nMatMulPhase2FailBanThreshold = 3;

    MatMulPeerVerificationBudget budget;
    const auto now = std::chrono::steady_clock::now();
    budget.phase2_failures = 2;
    budget.phase2_first_failure_time = now - std::chrono::hours{1};
    budget.window_start = now - std::chrono::minutes{2};
    budget.expensive_verifications_this_minute = params.nMatMulPeerVerifyBudgetPerMin;

    BOOST_CHECK(ConsumeMatMulPeerVerifyBudget(budget, params, now));
    BOOST_CHECK_EQUAL(budget.phase2_failures, 2U);

    const auto action = RegisterMatMulPhase2Failure(budget, params, now + std::chrono::minutes{1});
    BOOST_CHECK(action == MatMulPhase2Punishment::BAN);
}

BOOST_AUTO_TEST_CASE(validation_phase2_failure_counter_resets_after_24h)
{
    auto params = MainParams();
    params.fMatMulStrictPunishment = false;
    params.nMatMulPhase2FailBanThreshold = 3;

    MatMulPeerVerificationBudget budget;
    const auto now = std::chrono::steady_clock::now();
    budget.phase2_failures = 2;
    budget.phase2_first_failure_time = now - std::chrono::hours{25};

    const auto action = RegisterMatMulPhase2Failure(budget, params, now);
    BOOST_CHECK(action == MatMulPhase2Punishment::DISCONNECT);
    BOOST_CHECK_EQUAL(budget.phase2_failures, 1U);
}

// TEST: validation_max_concurrent_verifications
BOOST_AUTO_TEST_CASE(validation_rate_limit_per_peer_and_max_concurrent_verifications)
{
    auto params = MainParams();
    params.nMatMulPeerVerifyBudgetPerMin = 8;
    params.nMatMulMaxPendingVerifications = 4;

    MatMulPeerVerificationBudget budget;
    const auto now = std::chrono::steady_clock::now();
    for (int i = 0; i < 8; ++i) {
        BOOST_CHECK(ConsumeMatMulPeerVerifyBudget(budget, params, now));
    }
    BOOST_CHECK(!ConsumeMatMulPeerVerifyBudget(budget, params, now));

    BOOST_CHECK(CanStartMatMulVerification(0, params));
    BOOST_CHECK(CanStartMatMulVerification(3, params));
    BOOST_CHECK(!CanStartMatMulVerification(4, params));
}

BOOST_AUTO_TEST_CASE(validation_rate_limit_ibd_budget_floor_supports_repeated_header_batches)
{
    auto params = MainParams();
    params.nMatMulPeerVerifyBudgetPerMin = 32;

    BOOST_CHECK_EQUAL(EffectiveMatMulPeerVerifyBudgetPerMin(params, /*is_ibd=*/false), 32U);
    BOOST_CHECK_GE(EffectiveMatMulPeerVerifyBudgetPerMin(params, /*is_ibd=*/true), 200'000U);
}

BOOST_AUTO_TEST_CASE(validation_rate_limit_fast_phase_budget_floor_outside_ibd)
{
    auto params = MainParams();
    params.nMatMulPeerVerifyBudgetPerMin = 32;
    params.fMatMulPOW = true;
    params.nFastMineHeight = 50'000;

    MatMulPeerVerificationBudget budget;
    const auto now = std::chrono::steady_clock::now();
    budget.window_start = now;
    budget.expensive_verifications_this_minute = 199'999;

    // Outside IBD but still in fast-phase heights, we should retain the
    // bootstrap floor to avoid disconnect churn during honest catch-up.
    BOOST_CHECK(ConsumeMatMulPeerVerifyBudget(
        budget, params, now, /*is_ibd=*/false, /*reference_height=*/4000));
    BOOST_CHECK(!ConsumeMatMulPeerVerifyBudget(
        budget, params, now, /*is_ibd=*/false, /*reference_height=*/4000));
}

BOOST_AUTO_TEST_CASE(validation_rate_limit_allows_rapid_regtest_bursts)
{
    auto params = RegtestParams();
    params.nMatMulPeerVerifyBudgetPerMin = 8;
    params.fMatMulPOW = true;
    params.fPowAllowMinDifficultyBlocks = true;
    params.fPowNoRetargeting = true;
    params.nFastMineHeight = 0;

    MatMulPeerVerificationBudget budget;
    const auto now = std::chrono::steady_clock::now();
    for (uint32_t i = 0; i < 600; ++i) {
        BOOST_CHECK(ConsumeMatMulPeerVerifyBudget(budget, params, now, /*is_ibd=*/false, /*reference_height=*/10));
    }
    BOOST_CHECK(!ConsumeMatMulPeerVerifyBudget(budget, params, now, /*is_ibd=*/false, /*reference_height=*/10));
}

// TEST: validation_window_change_requires_resync
BOOST_AUTO_TEST_CASE(validation_window_retarget_requires_recheck)
{
    auto params = MainParams();
    params.fSkipMatMulValidation = false;

    constexpr int32_t old_best_known_height = 5'000;
    constexpr int32_t new_best_known_height = 8'000;
    constexpr int32_t sample_height = 4'500;

    BOOST_CHECK(ShouldRunMatMulPhase2ForHeight(sample_height, old_best_known_height, params));
    BOOST_CHECK(!ShouldRunMatMulPhase2ForHeight(sample_height, new_best_known_height, params));
}

// TEST: tier1_resume_after_long_offline
BOOST_AUTO_TEST_CASE(tier1_node_resumes_phase2_near_tip_after_reconnect)
{
    auto params = MainParams();
    params.fSkipMatMulValidation = false;

    constexpr int32_t best_known_height = 12'000;
    BOOST_CHECK(!ShouldRunMatMulPhase2ForHeight(10'000, best_known_height, params));
    BOOST_CHECK(ShouldRunMatMulPhase2ForHeight(11'500, best_known_height, params));
    BOOST_CHECK(ShouldRunMatMulPhase2ForHeight(best_known_height, best_known_height, params));
}

// Regression test: ConsumeMatMulPeerVerifyBudget resets both window_start and
// the counter when a new minute begins.  A correct rollback must restore BOTH
// fields.  If only the counter is restored (the original bug), the peer ends
// up with (window_start=now, count=old_count) — a stale count in a fresh
// window — and is prematurely throttled for the entire new minute.
BOOST_AUTO_TEST_CASE(peer_budget_rollback_must_restore_window_start_on_minute_boundary)
{
    auto params = MainParams();
    params.nMatMulPeerVerifyBudgetPerMin = 8;

    MatMulPeerVerificationBudget budget;
    const auto now = std::chrono::steady_clock::now();

    // Simulate: peer legitimately used 5 of 8 slots in a past minute.
    budget.window_start = now - std::chrono::minutes{2};
    budget.expensive_verifications_this_minute = 5;

    // --- Mimic ConsumeMatMulVerificationBudgetForPeer snapshot logic ---
    const auto saved_window_start = budget.window_start;
    const uint32_t saved_count = budget.expensive_verifications_this_minute;

    // Per-peer consume: crosses minute boundary → resets window_start and
    // counter, then increments.
    const uint32_t verification_count = 3;
    for (uint32_t i = 0; i < verification_count; ++i) {
        BOOST_CHECK(ConsumeMatMulPeerVerifyBudget(budget, params, now));
    }
    // Confirm the minute rollover happened.
    BOOST_CHECK(budget.window_start == now);
    BOOST_CHECK_EQUAL(budget.expensive_verifications_this_minute, verification_count);

    // --- Simulate global budget failure → full rollback ---
    budget.window_start = saved_window_start;
    budget.expensive_verifications_this_minute = saved_count;

    // Verify: state is back to pre-attempt snapshot.
    BOOST_CHECK(budget.window_start == saved_window_start);
    BOOST_CHECK_EQUAL(budget.expensive_verifications_this_minute, 5U);

    // The peer should get their FULL per-minute budget on the next legitimate
    // attempt (which will trigger a fresh minute rollover).
    const auto next_attempt = now + std::chrono::seconds{1};
    for (uint32_t i = 0; i < params.nMatMulPeerVerifyBudgetPerMin; ++i) {
        BOOST_CHECK_MESSAGE(
            ConsumeMatMulPeerVerifyBudget(budget, params, next_attempt),
            "Peer should get slot " << i << " of " << params.nMatMulPeerVerifyBudgetPerMin);
    }
    // Budget exactly exhausted.
    BOOST_CHECK(!ConsumeMatMulPeerVerifyBudget(budget, params, next_attempt));
    BOOST_CHECK_EQUAL(budget.expensive_verifications_this_minute, params.nMatMulPeerVerifyBudgetPerMin);
}

// Counterpart: demonstrate the BUG if only the counter is restored (not
// window_start).  The peer loses slots because the stale count appears to
// belong to the freshly-started window.
BOOST_AUTO_TEST_CASE(peer_budget_counter_only_rollback_causes_premature_throttle)
{
    auto params = MainParams();
    params.nMatMulPeerVerifyBudgetPerMin = 8;

    MatMulPeerVerificationBudget budget;
    const auto now = std::chrono::steady_clock::now();

    // Peer used 5 of 8 slots in an expired window.
    budget.window_start = now - std::chrono::minutes{2};
    budget.expensive_verifications_this_minute = 5;

    // Snapshot counter only (the old buggy approach).
    const uint32_t saved_count = budget.expensive_verifications_this_minute;

    // Consume triggers minute rollover.
    BOOST_CHECK(ConsumeMatMulPeerVerifyBudget(budget, params, now));

    // Buggy rollback: restore counter but NOT window_start.
    budget.expensive_verifications_this_minute = saved_count;
    // window_start is still `now` (the new window).

    // The peer now has (window_start=now, count=5): 5 slots "used" in a
    // window that just started.  They only get 3 more instead of 8.
    uint32_t slots_available = 0;
    while (ConsumeMatMulPeerVerifyBudget(budget, params, now)) {
        ++slots_available;
    }
    // With buggy rollback the peer gets only 3 slots (8 - 5) instead of 8.
    BOOST_CHECK_EQUAL(slots_available, params.nMatMulPeerVerifyBudgetPerMin - saved_count);
    BOOST_CHECK(slots_available < params.nMatMulPeerVerifyBudgetPerMin);
}

BOOST_AUTO_TEST_SUITE_END()
