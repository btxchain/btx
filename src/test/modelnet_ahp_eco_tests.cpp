// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// AHP-ECO-01  ahp_eco_01_stale_reward_preview
// AHP-ECO-02  ahp_eco_02_free_does_not_become_paid
// AHP-ECO-03  ahp_eco_03_bounty_inspection_only
// AHP-ECO-04  ahp_eco_04_separate_approved_funding
// AHP-ECO-05  ahp_eco_05_reorg_knowledge
// AHP-ECO-06  ahp_eco_06_observation_source_spoof

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <modelnet/package_economy.h>
#include <modelnet/package_pjson.h>
#include <modelnet/policy.h>
#include <modelnet/types.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <optional>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_ahp_eco_tests, BasicTestingSetup)

namespace {

UniValue ReleaseCore()
{
    UniValue core(UniValue::VOBJ);
    core.pushKV("version", 2);
    core.pushKV("network", "REGTEST");
    core.pushKV("package_type", "RELEASE");
    UniValue refs(UniValue::VARR);
    UniValue ref(UniValue::VOBJ);
    ref.pushKV("kind", "RELEASE");
    ref.pushKV("id", std::string(96, 'a'));
    refs.push_back(ref);
    core.pushKV("economy_refs", refs);
    UniValue ah(UniValue::VOBJ);
    UniValue ac(UniValue::VOBJ);
    ac.pushKV("retrieval_mode", "FREE_ONLY");
    ac.pushKV("source_policy", "NATIVE_ONLY");
    ah.pushKV("acquisition", ac);
    core.pushKV("agent_handoff", ah);
    return core;
}

UniValue BountyCore()
{
    UniValue core(UniValue::VOBJ);
    core.pushKV("version", 2);
    core.pushKV("network", "REGTEST");
    core.pushKV("package_type", "BOUNTY");
    UniValue refs(UniValue::VARR);
    UniValue ref(UniValue::VOBJ);
    ref.pushKV("kind", "BOUNTY");
    ref.pushKV("id", std::string(96, 'c'));
    refs.push_back(ref);
    core.pushKV("economy_refs", refs);
    UniValue ah(UniValue::VOBJ);
    UniValue ac(UniValue::VOBJ);
    ac.pushKV("retrieval_mode", "FREE_ONLY");
    ac.pushKV("source_policy", "NATIVE_ONLY");
    ah.pushKV("acquisition", ac);
    core.pushKV("agent_handoff", ah);
    return core;
}

} // namespace

BOOST_AUTO_TEST_CASE(ahp_eco_01_stale_reward_preview)
{
    const UniValue core = ReleaseCore();
    std::vector<unsigned char> before;
    std::string enc_err;
    BOOST_REQUIRE(modelnet::EncodePjson1(core, before, enc_err));

    UniValue cached(UniValue::VOBJ);
    cached.pushKV("object_id", std::string(96, 'a'));
    cached.pushKV("observed_at_ms", "1");
    cached.pushKV("source", "REMOTE_OBSERVATION");
    cached.pushKV("state", "FUNDED_AWAITING_RELEASE");
    cached.pushKV("percent_funded", 87);

    UniValue local(UniValue::VOBJ);
    local.pushKV("object_id", std::string(96, 'a'));
    local.pushKV("observed_at_ms", "2");
    local.pushKV("source", "LOCAL_CHAIN");
    local.pushKV("state", "FUNDING");
    local.pushKV("confirmed_funded_atoms", 10);
    local.pushKV("percent_funded", 2);

    modelnet::PackageRewardPreview preview;
    std::string err_code, err;
    BOOST_REQUIRE_MESSAGE(
        modelnet::EvaluatePackageRewardPreview(core, cached, local, preview, err_code, err), err);
    BOOST_CHECK(preview.cached_stale);
    BOOST_CHECK(preview.preview_is_observation);
    BOOST_CHECK(!preview.controls_spending);
    BOOST_CHECK_EQUAL(preview.automatic_spend_atoms, 0);
    BOOST_CHECK_EQUAL(modelnet::PackageAutomaticSpendAtoms(), 0);
    BOOST_CHECK_EQUAL(preview.cached_state, "FUNDED_AWAITING_RELEASE");
    BOOST_CHECK_EQUAL(preview.current_state, "FUNDING");
    BOOST_CHECK(preview.json["cached_stale"].get_bool());
    BOOST_CHECK(preview.json["cached_percent_funded_ignored"].get_bool());
    BOOST_CHECK(preview.json["preview_is_observation"].get_bool());
    BOOST_CHECK(!preview.json["controls_spending"].get_bool());
    BOOST_CHECK_EQUAL(preview.json["automatic_spend_atoms"].getInt<int64_t>(), 0);

    std::vector<unsigned char> after;
    BOOST_REQUIRE(modelnet::EncodePjson1(core, after, enc_err));
    BOOST_CHECK(modelnet::Pjson1Equals(before, after));
    BOOST_CHECK(!core.exists("percent_funded"));
    BOOST_CHECK(!core.exists("state"));
}

BOOST_AUTO_TEST_CASE(ahp_eco_02_free_does_not_become_paid)
{
    const UniValue core = ReleaseCore();
    UniValue planned;
    std::string err_code, err;
    BOOST_REQUIRE_MESSAGE(
        modelnet::PlanFreeOnlyAwaitingRelease(core, /*elapsed_ms=*/7 * 24 * 3600 * 1000LL, planned, err_code, err),
        err);
    BOOST_CHECK_EQUAL(err_code, "WAITING_FOR_PUBLIC_RELEASE");
    BOOST_CHECK_EQUAL(planned["status"].get_str(), "WAITING_FOR_PUBLIC_RELEASE");
    BOOST_CHECK_EQUAL(planned["retrieval_mode"].get_str(), "FREE_ONLY");
    BOOST_CHECK_EQUAL(planned["automatic_spend_atoms"].getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(planned["spent_atoms"].getInt<int64_t>(), 0);
    BOOST_CHECK(!planned["converted_to_paid"].get_bool());
    BOOST_CHECK(planned["timer_cannot_convert_to_paid"].get_bool());
    BOOST_CHECK_EQUAL(planned["funding_option"].get_str(), "explicit_existing_rpc");

    modelnet::PaidPlan paid;
    paid.price_atoms = 1;
    paid.fee_atoms = 0;
    paid.safe = true;
    paid.deliverable = true;
    paid.total_eta_s = 1;
    paid.requires_release = true;
    modelnet::PlanChoice choice = modelnet::PlanChoice::PAID;
    BOOST_REQUIRE(modelnet::ChoosePlan(modelnet::RetrievalMode::FREE_ONLY, std::nullopt, &paid, 1000, true, 1, 1000,
                                       true, choice, err));
    BOOST_CHECK(choice != modelnet::PlanChoice::PAID);
    BOOST_CHECK_EQUAL(modelnet::PackageAutomaticSpendAtoms(), 0);
}

BOOST_AUTO_TEST_CASE(ahp_eco_03_bounty_inspection_only)
{
    const UniValue core = BountyCore();
    modelnet::PackageRewardPreview preview;
    std::string err_code, err;
    BOOST_REQUIRE_MESSAGE(
        modelnet::EvaluatePackageRewardPreview(core, UniValue(UniValue::VOBJ), UniValue(UniValue::VOBJ), preview,
                                               err_code, err),
        err);
    BOOST_CHECK_EQUAL(preview.automatic_spend_atoms, 0);
    BOOST_CHECK(preview.preview_is_observation);
    BOOST_CHECK(!preview.controls_spending);
    BOOST_CHECK_EQUAL(preview.json["automatic_spend_atoms"].getInt<int64_t>(), 0);
    BOOST_CHECK(preview.json["preview_is_observation"].get_bool());
    BOOST_CHECK(!preview.json["controls_spending"].get_bool());
    BOOST_CHECK(!preview.json.exists("wallet_signed"));
    BOOST_CHECK(!preview.json.exists("winning_model"));
    BOOST_CHECK(!core.exists("wallet_seed"));
}

BOOST_AUTO_TEST_CASE(ahp_eco_04_separate_approved_funding)
{
    BOOST_CHECK_EQUAL(modelnet::PackageAutomaticSpendAtoms(), 0);
    UniValue planned;
    std::string err_code, err;
    BOOST_REQUIRE_MESSAGE(
        modelnet::PlanFreeOnlyAwaitingRelease(ReleaseCore(), /*elapsed_ms=*/1, planned, err_code, err), err);
    BOOST_CHECK_EQUAL(planned["funding_option"].get_str(), "explicit_existing_rpc");
    BOOST_CHECK_EQUAL(planned["automatic_spend_atoms"].getInt<int64_t>(), 0);
    BOOST_CHECK(!planned.exists("wallet_signed") || !planned["wallet_signed"].get_bool());
    BOOST_CHECK(!planned.exists("mint_wallet_signed"));
    BOOST_TEST_MESSAGE("AHP-ECO-04 remainder NOT_RUN: live wallet sign");
}

BOOST_AUTO_TEST_CASE(ahp_eco_05_reorg_knowledge)
{
    const UniValue core = ReleaseCore();
    UniValue cached(UniValue::VOBJ);
    cached.pushKV("object_id", std::string(96, 'a'));
    cached.pushKV("source", "REMOTE_OBSERVATION");
    cached.pushKV("state", "OPEN");
    cached.pushKV("percent_funded", 40);

    UniValue local(UniValue::VOBJ);
    local.pushKV("object_id", std::string(96, 'a'));
    local.pushKV("source", "LOCAL_CHAIN");
    local.pushKV("state", "CLOSED");
    local.pushKV("percent_funded", 40);

    modelnet::PackageRewardPreview preview;
    std::string err_code, err;
    BOOST_REQUIRE_MESSAGE(
        modelnet::EvaluatePackageRewardPreview(core, cached, local, preview, err_code, err), err);
    BOOST_CHECK(preview.cached_stale);
    BOOST_CHECK(preview.preview_is_observation);
    BOOST_CHECK(!preview.controls_spending);
    BOOST_CHECK_EQUAL(preview.automatic_spend_atoms, 0);
    BOOST_CHECK_EQUAL(preview.cached_state, "OPEN");
    BOOST_CHECK_EQUAL(preview.current_state, "CLOSED");
}

BOOST_AUTO_TEST_CASE(ahp_eco_06_observation_source_spoof)
{
    const UniValue core = ReleaseCore();
    UniValue cached(UniValue::VOBJ);
    cached.pushKV("object_id", std::string(96, 'a'));
    cached.pushKV("source", "LOCAL_CHAIN");
    cached.pushKV("percent_funded", 100);
    cached.pushKV("state", "FUNDED");

    UniValue local(UniValue::VOBJ);

    modelnet::PackageRewardPreview preview;
    std::string err_code, err;
    BOOST_REQUIRE_MESSAGE(
        modelnet::EvaluatePackageRewardPreview(core, cached, local, preview, err_code, err), err);
    BOOST_CHECK(preview.cached_stale || (preview.json.exists("cached_percent_funded_ignored") &&
                                         preview.json["cached_percent_funded_ignored"].get_bool()));
    BOOST_CHECK(preview.preview_is_observation);
    BOOST_CHECK(!preview.controls_spending);
    BOOST_CHECK_EQUAL(preview.automatic_spend_atoms, 0);
    BOOST_CHECK(preview.json["preview_is_observation"].get_bool());
    BOOST_CHECK(!preview.json["controls_spending"].get_bool());
}

BOOST_AUTO_TEST_SUITE_END()
