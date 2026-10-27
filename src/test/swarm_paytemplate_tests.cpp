// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paytemplate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_paytemplate_tests, BasicTestingSetup)

static modelnet::SwarmPayTemplate NotedPay()
{
    modelnet::SwarmPayTemplate pay;
    pay.channel_id = "ch";
    pay.signer = true;
    pay.want_broadcast = false;
    pay.atoms = 100;
    return pay;
}

BOOST_AUTO_TEST_CASE(empty_channel_is_channel)
{
    modelnet::SwarmPayTemplate pay = NotedPay();
    pay.channel_id.clear();
    std::string err = "prior";
    const modelnet::SwarmPayTemplateResult result = modelnet::SwarmRecordFundingTemplate(pay, err);
    BOOST_CHECK_EQUAL(result.broadcast, false);
    BOOST_CHECK_EQUAL(result.mined, false);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(signer_false_is_signer)
{
    modelnet::SwarmPayTemplate pay = NotedPay();
    pay.signer = false;
    std::string err = "prior";
    const modelnet::SwarmPayTemplateResult result = modelnet::SwarmRecordFundingTemplate(pay, err);
    BOOST_CHECK_EQUAL(result.broadcast, false);
    BOOST_CHECK_EQUAL(result.mined, false);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "SIGNER");
    BOOST_CHECK_EQUAL(err, "SIGNER");
}

BOOST_AUTO_TEST_CASE(negative_atoms_are_range)
{
    modelnet::SwarmPayTemplate pay = NotedPay();
    pay.atoms = -1;
    std::string err = "prior";
    const modelnet::SwarmPayTemplateResult result = modelnet::SwarmRecordFundingTemplate(pay, err);
    BOOST_CHECK_EQUAL(result.broadcast, false);
    BOOST_CHECK_EQUAL(result.mined, false);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "RANGE");
    BOOST_CHECK_EQUAL(err, "RANGE");
}

BOOST_AUTO_TEST_CASE(want_broadcast_is_held)
{
    modelnet::SwarmPayTemplate pay = NotedPay();
    pay.signer = true;
    pay.atoms = 100;
    pay.want_broadcast = true;
    std::string err = "prior";
    const modelnet::SwarmPayTemplateResult result = modelnet::SwarmRecordFundingTemplate(pay, err);
    BOOST_CHECK_EQUAL(result.broadcast, false);
    BOOST_CHECK_EQUAL(result.mined, false);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(signed_positive_template_is_noted)
{
    modelnet::SwarmPayTemplate pay = NotedPay();
    pay.signer = true;
    pay.atoms = 100;
    pay.want_broadcast = false;
    std::string err = "prior";
    const modelnet::SwarmPayTemplateResult result = modelnet::SwarmRecordFundingTemplate(pay, err);
    BOOST_CHECK_EQUAL(result.broadcast, false);
    BOOST_CHECK_EQUAL(result.mined, false);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
