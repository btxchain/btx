// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agreehold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_agreehold_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_agreement)
{
    modelnet::SwarmAgreeHold agreement;
    agreement.agreement_id.clear();
    agreement.agreed = false;
    agreement.want_settle = false;
    std::string err;
    const modelnet::SwarmAgreeHoldResult result = modelnet::SwarmHoldAgreement(agreement, err);
    BOOST_CHECK_EQUAL(result.code, "AGREEMENT");
    BOOST_CHECK_EQUAL(err, "AGREEMENT");
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_CASE(agreed_not_settled)
{
    modelnet::SwarmAgreeHold agreement;
    agreement.agreement_id = "agree-1";
    agreement.agreed = true;
    agreement.want_settle = false;
    std::string err;
    const modelnet::SwarmAgreeHoldResult result = modelnet::SwarmHoldAgreement(agreement, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_SETTLED");
    BOOST_CHECK_EQUAL(err, "NOT_SETTLED");
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_CASE(want_settle_held)
{
    modelnet::SwarmAgreeHold agreement;
    agreement.agreement_id = "agree-2";
    agreement.agreed = false;
    agreement.want_settle = true;
    std::string err;
    const modelnet::SwarmAgreeHoldResult result = modelnet::SwarmHoldAgreement(agreement, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmAgreeHold agreement;
    agreement.agreement_id = "agree-3";
    agreement.agreed = false;
    agreement.want_settle = false;
    std::string err = "stale";
    const modelnet::SwarmAgreeHoldResult result = modelnet::SwarmHoldAgreement(agreement, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_SUITE_END()
