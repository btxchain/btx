// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/action_authority.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_runtime_tests, BasicTestingSetup)

namespace {

modelnet::ActionPermit Permit(std::string id, uint64_t generation, std::string effect, int64_t not_after_ms,
                              std::string fingerprint)
{
    modelnet::ActionPermit permit;
    permit.permit_id = std::move(id);
    permit.grant_id = "local-capability-grant";
    permit.generation = generation;
    permit.effect = std::move(effect);
    permit.not_after_ms = not_after_ms;
    permit.parameter_fingerprint = std::move(fingerprint);
    return permit;
}

} // namespace

BOOST_AUTO_TEST_CASE(action_permit_one_use)
{
    BOOST_CHECK(!modelnet::ResearchMaySpend());

    modelnet::ActionGate gate;
    std::string err;
    modelnet::ActionPermit missing_id = Permit("p1", 1, "read", 5'000, "fp");
    missing_id.permit_id.clear();
    BOOST_CHECK(!gate.Issue(missing_id, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PERMIT");

    modelnet::ActionPermit missing_effect = Permit("p1", 1, "read", 5'000, "fp");
    missing_effect.effect.clear();
    BOOST_CHECK(!gate.Issue(missing_effect, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PERMIT");

    BOOST_CHECK(!gate.Issue(Permit("p0", 0, "read", 5'000, "fp"), err));
    BOOST_CHECK_EQUAL(err, "BTX035_PERMIT");

    BOOST_CHECK(!gate.Issue(Permit("spend", 1, "wallet.spend", 5'000, "fp"), err));
    BOOST_CHECK_EQUAL(err, "BTX035_PERMIT");

    const modelnet::ActionPermit permit = Permit("p1", 7, "read", 5'000, "fp-a");
    BOOST_CHECK(gate.Issue(permit, err));

    BOOST_CHECK(!gate.Consume("p1", "write", 7, 1'000, "fp-a", err));
    BOOST_CHECK_EQUAL(err, "BTX035_PERMIT");
    BOOST_CHECK(!gate.Consume("p1", "read", 8, 1'000, "fp-a", err));
    BOOST_CHECK_EQUAL(err, "BTX035_PERMIT");
    BOOST_CHECK(!gate.Consume("p1", "read", 7, 1'000, "fp-b", err));
    BOOST_CHECK_EQUAL(err, "BTX035_PERMIT");

    BOOST_CHECK(gate.Consume("p1", "read", 7, 1'000, "fp-a", err));
    BOOST_CHECK(!gate.Consume("p1", "read", 7, 1'000, "fp-a", err));
    BOOST_CHECK_EQUAL(err, "BTX035_REPLAY");
}

BOOST_AUTO_TEST_CASE(action_permit_escalation)
{
    modelnet::ActionGate gate;
    std::string err;
    const std::vector<std::string> parent{"read", "infer"};
    BOOST_CHECK(gate.Attenuate(parent, {"read"}, err));
    BOOST_CHECK(gate.Attenuate(parent, {"infer", "read"}, err));

    BOOST_CHECK(!gate.Attenuate(parent, {}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ATTENUATE");
    BOOST_CHECK(!gate.Attenuate(parent, {"read", "exec"}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ATTENUATE");
    BOOST_CHECK(!gate.Attenuate(parent, {"wallet.spend"}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ATTENUATE");
    BOOST_CHECK(!gate.Attenuate({"read", "wallet.spend"}, {"wallet.spend"}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ATTENUATE");
    BOOST_CHECK(!modelnet::ResearchMaySpend());
}

BOOST_AUTO_TEST_CASE(action_gate_pause)
{
    modelnet::ActionGate gate;
    std::string err;
    BOOST_REQUIRE(gate.Issue(Permit("p-pause", 3, "infer", 9'000, "fp"), err));
    gate.Pause();
    BOOST_CHECK(!gate.Consume("p-pause", "infer", 3, 1'000, "fp", err));
    BOOST_CHECK_EQUAL(err, "BTX035_PAUSED");
}

BOOST_AUTO_TEST_CASE(action_gate_revoke)
{
    modelnet::ActionGate gate;
    std::string err;
    BOOST_REQUIRE(gate.Issue(Permit("p-revoke", 3, "infer", 9'000, "fp"), err));
    gate.Revoke();
    BOOST_CHECK(!gate.Consume("p-revoke", "infer", 3, 1'000, "fp", err));
    BOOST_CHECK_EQUAL(err, "BTX035_REVOKED");
}

BOOST_AUTO_TEST_CASE(action_permit_expiry)
{
    modelnet::ActionGate gate;
    std::string err;
    BOOST_REQUIRE(gate.Issue(Permit("p-exp", 4, "read", 1'000, "fp"), err));
    BOOST_CHECK(!gate.Consume("p-exp", "read", 4, 1'001, "fp", err));
    BOOST_CHECK_EQUAL(err, "BTX035_EXPIRED");
    BOOST_CHECK(gate.Consume("p-exp", "read", 4, 1'000, "fp", err));
}

BOOST_AUTO_TEST_CASE(logical_physical_split)
{
    modelnet::ActionGate gate;
    gate.CancelLogical("op1");
    modelnet::OperationDisposition after_cancel = gate.Disposition("op1");
    BOOST_CHECK_EQUAL(after_cancel.logical_state, "CANCELLED");
    BOOST_CHECK(after_cancel.physical_state.empty());

    gate.ReportPhysical("op1", "STILL_RUNNING");
    const modelnet::OperationDisposition split = gate.Disposition("op1");
    BOOST_CHECK_EQUAL(split.logical_state, "CANCELLED");
    BOOST_CHECK_EQUAL(split.physical_state, "STILL_RUNNING");

    BOOST_CHECK(!gate.UnknownEffect("op1"));
    const modelnet::OperationDisposition unknown = gate.Disposition("op1");
    BOOST_CHECK_EQUAL(unknown.uncertainty, "UNKNOWN");
    BOOST_CHECK_EQUAL(unknown.logical_state, "CANCELLED");
    BOOST_CHECK_EQUAL(unknown.physical_state, "STILL_RUNNING");
    BOOST_CHECK(!modelnet::ResearchMaySpend());
}

BOOST_AUTO_TEST_SUITE_END()
