// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/capability_bridge.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_grant_tests, BasicTestingSetup)

namespace {

modelnet::LocalCapabilityGrant Grant(std::string grant_id, int64_t expires_at_ms, std::string effect)
{
    modelnet::LocalCapabilityGrant grant;
    grant.grant_id = std::move(grant_id);
    grant.expires_at_ms = expires_at_ms;
    grant.json = UniValue(UniValue::VOBJ);
    UniValue effects(UniValue::VARR);
    effects.push_back(effect);
    grant.json.pushKV("effects", effects);
    return grant;
}

} // namespace

BOOST_AUTO_TEST_CASE(permit_from_grant_rejects_empty_expired_and_missing_effect)
{
    std::string err;
    modelnet::ActionPermit permit;

    modelnet::LocalCapabilityGrant empty_id = Grant("", 5'000, "infer");
    BOOST_CHECK(!modelnet::PermitFromGrant(empty_id, "infer", "fp", 1'000, permit, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PERMIT");
    BOOST_CHECK(permit.permit_id.empty());

    modelnet::LocalCapabilityGrant expired = Grant("grant-expired", 1'000, "infer");
    BOOST_CHECK(!modelnet::PermitFromGrant(expired, "infer", "fp", 1'001, permit, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PERMIT");

    modelnet::LocalCapabilityGrant live = Grant("grant-live", 5'000, "infer");
    BOOST_CHECK(!modelnet::PermitFromGrant(live, "train", "fp", 1'000, permit, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PERMIT");

    modelnet::LocalCapabilityGrant no_effects = Grant("grant-none", 5'000, "infer");
    no_effects.json = UniValue(UniValue::VOBJ);
    BOOST_CHECK(!modelnet::PermitFromGrant(no_effects, "infer", "fp", 1'000, permit, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PERMIT");
}

BOOST_AUTO_TEST_CASE(permit_from_grant_issues_one_use_permit)
{
    BOOST_CHECK(!modelnet::ResearchMaySpend());

    const modelnet::LocalCapabilityGrant grant = Grant("grant-1", 5'000, "infer");
    modelnet::ActionPermit permit;
    std::string err = "stale";
    BOOST_CHECK(modelnet::PermitFromGrant(grant, "infer", "fp-1", 1'000, permit, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!permit.permit_id.empty());
    BOOST_CHECK_EQUAL(permit.grant_id, "grant-1");
    BOOST_CHECK_EQUAL(permit.effect, "infer");
    BOOST_CHECK_EQUAL(permit.parameter_fingerprint, "fp-1");
    BOOST_CHECK_EQUAL(permit.not_after_ms, 5'000);
    BOOST_CHECK(permit.generation != 0);
    BOOST_CHECK(!modelnet::ResearchMaySpend());

    modelnet::ActionGate gate;
    BOOST_CHECK(gate.Issue(permit, err));
    BOOST_CHECK(gate.Consume(permit.permit_id, permit.effect, permit.generation, 1'000, "fp-1", err));
    BOOST_CHECK(!gate.Consume(permit.permit_id, permit.effect, permit.generation, 1'000, "fp-1", err));
    BOOST_CHECK_EQUAL(err, "BTX035_REPLAY");
    BOOST_CHECK(!modelnet::ResearchMaySpend());
}

BOOST_AUTO_TEST_SUITE_END()
