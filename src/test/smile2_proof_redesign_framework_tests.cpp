// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/util/setup_common.h>
#include <test/util/smile2_proof_redesign_harness.h>

#include <boost/test/unit_test.hpp>

namespace {

void RelaxBudgetForStructuralTest(btx::test::smile2redesign::MetricBudget& budget, bool include_tx_budget)
{
    // The fast-profile budgets are intended to flag performance regressions in
    // dedicated benchmark/reporting runs. For this unit test we want stable
    // validation of correctness and report wiring across developer machines, so
    // give the measured values ample headroom.
    budget.max_proof_bytes = 1'000'000;
    if (include_tx_budget) budget.max_tx_bytes = 1'500'000;
    budget.max_build_median_ns = 600'000'000'000LL;
    budget.max_verify_median_ns = 60'000'000'000LL;
}

btx::test::smile2redesign::ProofRedesignFrameworkConfig MakeStructuralFrameworkTestConfig()
{
    auto config = btx::test::smile2redesign::MakeFastProofRedesignFrameworkConfig();
    for (auto& scenario : config.ct_scenarios) {
        RelaxBudgetForStructuralTest(scenario.budget, /*include_tx_budget=*/false);
    }
    for (auto& scenario : config.direct_send_scenarios) {
        RelaxBudgetForStructuralTest(scenario.budget, /*include_tx_budget=*/true);
    }
    for (auto& scenario : config.ingress_scenarios) {
        RelaxBudgetForStructuralTest(scenario.budget, /*include_tx_budget=*/true);
    }
    return config;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(smile2_proof_redesign_framework_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(framework_report_captures_correctness_integrity_size_and_runtime)
{
    const UniValue report = btx::test::smile2redesign::BuildProofRedesignFrameworkReport(
        MakeStructuralFrameworkTestConfig());

    BOOST_REQUIRE(report.isObject());
    BOOST_CHECK_EQUAL(report.find_value("format_version").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(report.find_value("report_kind").get_str(), "smile2_proof_redesign_framework");
    BOOST_CHECK_EQUAL(report.find_value("status").get_str(), "all_checks_passed");

    const UniValue& summary = report.find_value("summary");
    BOOST_REQUIRE(summary.isObject());
    BOOST_CHECK(summary.find_value("all_ct_checks_pass").get_bool());
    BOOST_CHECK(summary.find_value("all_direct_send_checks_pass").get_bool());
    BOOST_CHECK(summary.find_value("all_ingress_checks_pass").get_bool());
    BOOST_CHECK(summary.find_value("all_account_registry_checks_pass").get_bool());
    BOOST_CHECK(summary.find_value("overall_pass").get_bool());

    const UniValue& ct_scenarios = report.find_value("ct_scenarios");
    BOOST_REQUIRE(ct_scenarios.isArray());
    BOOST_REQUIRE_EQUAL(ct_scenarios.size(), 2U);
    for (size_t i = 0; i < ct_scenarios.size(); ++i) {
        const UniValue& scenario = ct_scenarios[i];
        BOOST_REQUIRE(scenario.isObject());
        BOOST_CHECK_EQUAL(scenario.find_value("status").get_str(), "passed");
        BOOST_CHECK(scenario.find_value("verified").get_bool());
        BOOST_CHECK(scenario.find_value("roundtrip_verified").get_bool());
        BOOST_CHECK(scenario.find_value("same_seed_deterministic").get_bool());
        BOOST_CHECK(scenario.find_value("different_seed_verified").get_bool());
        BOOST_CHECK(scenario.find_value("different_seed_distinct").get_bool());
        BOOST_CHECK(scenario.find_value("all_tamper_cases_rejected").get_bool());
        BOOST_CHECK(scenario.find_value("budget_pass").get_bool());
        BOOST_CHECK_GT(scenario.find_value("proof_bytes").getInt<int64_t>(), 0);
        BOOST_CHECK_GT(scenario.find_value("prove_ns").getInt<int64_t>(), 0);
        BOOST_CHECK_GT(scenario.find_value("verify_ns").getInt<int64_t>(), 0);
        const UniValue& tamper_cases = scenario.find_value("tamper_cases");
        BOOST_REQUIRE(tamper_cases.isArray());
        BOOST_CHECK_GE(tamper_cases.size(), 5U);
    }

    const UniValue& direct_send = report.find_value("direct_send_scenarios");
    BOOST_REQUIRE(direct_send.isArray());
    BOOST_REQUIRE_EQUAL(direct_send.size(), 1U);
    BOOST_CHECK_EQUAL(direct_send[0].find_value("scenario").get_str(), "1x2");
    BOOST_CHECK_EQUAL(direct_send[0].find_value("status").get_str(), "passed");
    BOOST_CHECK(direct_send[0].find_value("budget_pass").get_bool());
    BOOST_CHECK_GT(direct_send[0].find_value("tx_bytes").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(direct_send[0].find_value("proof_bytes").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(direct_send[0].find_value("envelope_bytes").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(direct_send[0].find_value("build_median_ns").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(direct_send[0].find_value("verify_median_ns").getInt<int64_t>(), 0);

    const UniValue& ingress = report.find_value("ingress_scenarios");
    BOOST_REQUIRE(ingress.isArray());
    BOOST_REQUIRE_EQUAL(ingress.size(), 1U);
    BOOST_CHECK_EQUAL(ingress[0].find_value("status").get_str(), "built_and_checked");
    BOOST_CHECK(ingress[0].find_value("budget_pass").get_bool());
    BOOST_CHECK_GT(ingress[0].find_value("tx_bytes").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(ingress[0].find_value("proof_bytes").getInt<int64_t>(), 0);

    const UniValue& envelope = report.find_value("envelope_footprint");
    BOOST_REQUIRE(envelope.isObject());
    BOOST_CHECK_GT(envelope.find_value("direct_send_output_bytes").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(envelope.find_value("minimal_direct_send_output_bytes").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(envelope.find_value("compact_public_account_bytes").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(envelope.find_value("compact_public_key_bytes").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(envelope.find_value("compact_public_coin_t0_bytes").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(envelope.find_value("compact_public_coin_tmsg_bytes").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(envelope.find_value("encrypted_note_payload_bytes").getInt<int64_t>(), 0);
    BOOST_CHECK_LT(envelope.find_value("direct_send_output_framing_bytes").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(envelope.find_value("exact_compact_public_account_transport_floor_bytes").getInt<int64_t>(),
                   envelope.find_value("direct_send_output_bytes").getInt<int64_t>());
    BOOST_CHECK_GT(
        envelope.find_value("exact_compact_public_account_transport_delta_vs_current_bytes").getInt<int64_t>(),
        0);
    BOOST_CHECK(envelope.find_value("exact_compact_public_account_transport_non_improving").get_bool());
    BOOST_CHECK_GT(envelope.find_value("hypothetical_public_keyless_output_bytes").getInt<int64_t>(), 0);
    BOOST_CHECK_LT(envelope.find_value("hypothetical_t0_less_output_bytes").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(envelope.find_value("hypothetical_note_commitment_plus_tmsg_output_bytes").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(envelope.find_value("hypothetical_note_commitment_only_output_bytes").getInt<int64_t>(), 0);

    const UniValue& account_registry = report.find_value("account_registry_design");
    BOOST_REQUIRE(account_registry.isObject());
    BOOST_CHECK_EQUAL(account_registry.find_value("status").get_str(), "passed");
    BOOST_CHECK(account_registry.find_value("all_checks_pass").get_bool());

    const UniValue& family_footprints = account_registry.find_value("family_output_footprints");
    BOOST_REQUIRE(family_footprints.isArray());
    BOOST_REQUIRE_EQUAL(family_footprints.size(), 4U);
    for (size_t i = 0; i < family_footprints.size(); ++i) {
        const UniValue& family = family_footprints[i];
        BOOST_CHECK(family.find_value("passed").get_bool());
        BOOST_CHECK_GT(family.find_value("current_output_bytes").getInt<int64_t>(), 0);
        BOOST_CHECK_GT(family.find_value("minimal_output_bytes").getInt<int64_t>(), 0);
        BOOST_CHECK_GT(family.find_value("bytes_saved").getInt<int64_t>(), 0);
        BOOST_CHECK(family.find_value("payload_preserved").get_bool());
        BOOST_CHECK(family.find_value("minimal_roundtrip").get_bool());
    }

    const UniValue& projections = account_registry.find_value("direct_send_tx_projections");
    BOOST_REQUIRE(projections.isArray());
    BOOST_REQUIRE_EQUAL(projections.size(), 1U);
    BOOST_CHECK(projections[0].find_value("passed").get_bool());
    BOOST_CHECK_LT(projections[0].find_value("projected_tx_bytes").getInt<int64_t>(),
                   projections[0].find_value("baseline_tx_bytes").getInt<int64_t>());

    const UniValue& registry_sequence = account_registry.find_value("registry_sequence");
    BOOST_REQUIRE(registry_sequence.isObject());
    BOOST_CHECK_EQUAL(registry_sequence.find_value("status").get_str(), "passed");
    BOOST_CHECK(registry_sequence.find_value("stale_root_rejected").get_bool());
    BOOST_CHECK(registry_sequence.find_value("stale_spend_witness_rejected").get_bool());
    BOOST_CHECK(registry_sequence.find_value("spent_snapshot_rejected").get_bool());
    BOOST_CHECK(registry_sequence.find_value("duplicate_snapshot_rejected").get_bool());
    BOOST_CHECK(registry_sequence.find_value("light_client_proof_valid").get_bool());
    BOOST_CHECK(registry_sequence.find_value("snapshot_roundtrip").get_bool());
    BOOST_CHECK_GT(registry_sequence.find_value("snapshot_bytes").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(registry_sequence.find_value("sample_light_client_proof_wire_bytes").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(registry_sequence.find_value("sample_spend_witness_wire_bytes").getInt<int64_t>(), 0);
    BOOST_CHECK_LT(registry_sequence.find_value("sample_spend_witness_wire_bytes").getInt<int64_t>(),
                   registry_sequence.find_value("sample_light_client_proof_wire_bytes").getInt<int64_t>());
    const UniValue& registry_tamper = registry_sequence.find_value("tamper_cases");
    BOOST_REQUIRE(registry_tamper.isArray());
    BOOST_CHECK_GE(registry_tamper.size(), 5U);

    const UniValue& launch_readiness = account_registry.find_value("launch_readiness");
    BOOST_REQUIRE(launch_readiness.isObject());
    BOOST_CHECK_EQUAL(launch_readiness.find_value("status").get_str(), "ready");
    BOOST_CHECK(launch_readiness.find_value("launch_ready").get_bool());
    BOOST_CHECK(launch_readiness.find_value("base_direct_smile_launch_ready").get_bool());
    BOOST_CHECK(launch_readiness.find_value("account_registry_activation_ready").get_bool());
    BOOST_CHECK_EQUAL(launch_readiness.find_value("blocker_count").getInt<int>(), 0);
    const UniValue& launch_blockers = launch_readiness.find_value("blockers");
    BOOST_REQUIRE(launch_blockers.isArray());
    BOOST_REQUIRE_EQUAL(launch_blockers.size(), 0U);
}

BOOST_AUTO_TEST_CASE(framework_report_rejects_invalid_config)
{
    auto config = btx::test::smile2redesign::MakeFastProofRedesignFrameworkConfig();
    config.measured_iterations = 0;
    BOOST_CHECK_THROW(btx::test::smile2redesign::BuildProofRedesignFrameworkReport(config),
                      std::runtime_error);

    config = btx::test::smile2redesign::MakeFastProofRedesignFrameworkConfig();
    config.ct_scenarios[0].input_amounts.clear();
    BOOST_CHECK_THROW(btx::test::smile2redesign::BuildProofRedesignFrameworkReport(config),
                      std::runtime_error);
}

BOOST_AUTO_TEST_CASE(launch_baseline_config_tracks_live_ingress_ceiling)
{
    const auto config = btx::test::smile2redesign::MakeLaunchBaselineProofRedesignFrameworkConfig();
    BOOST_REQUIRE_EQUAL(config.ingress_scenarios.size(), 1U);
    const auto& ingress = config.ingress_scenarios[0];
    BOOST_CHECK(ingress.backend_kind == btx::test::ingress::ProofRuntimeBackendKind::SMILE);
    BOOST_CHECK_EQUAL(ingress.reserve_output_count, 1U);
    BOOST_CHECK_EQUAL(ingress.leaf_count, 63U);
    BOOST_REQUIRE(ingress.budget.max_proof_bytes.has_value());
    BOOST_REQUIRE(ingress.budget.max_tx_bytes.has_value());
    BOOST_REQUIRE(ingress.budget.max_build_median_ns.has_value());
    BOOST_REQUIRE(ingress.budget.max_verify_median_ns.has_value());
    BOOST_CHECK_EQUAL(*ingress.budget.max_proof_bytes, 300000U);
    BOOST_CHECK_EQUAL(*ingress.budget.max_tx_bytes, 350000U);
    BOOST_CHECK_EQUAL(*ingress.budget.max_build_median_ns, 130'000'000'000LL);
    BOOST_CHECK_EQUAL(*ingress.budget.max_verify_median_ns, 7'000'000'000LL);
}

BOOST_AUTO_TEST_SUITE_END()
