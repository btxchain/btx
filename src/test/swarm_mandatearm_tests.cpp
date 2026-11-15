// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_mandatearm.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_mandatearm_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(initial_unarmed)
{
    modelnet::SwarmMandateArm arm;
    BOOST_CHECK_EQUAL(arm.automatic_spend(), "0");
    BOOST_CHECK(!arm.armed());
    BOOST_CHECK_EQUAL(arm.atoms_moved(), 0);
}

BOOST_AUTO_TEST_CASE(research_key_not_signed)
{
    modelnet::SwarmMandateArm arm;
    std::string err;
    BOOST_CHECK(!arm.Arm(5, true, true, false, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK_EQUAL(arm.automatic_spend(), "0");
    BOOST_CHECK(!arm.armed());
    BOOST_CHECK_EQUAL(arm.atoms_moved(), 0);
}

BOOST_AUTO_TEST_CASE(scheduler_not_signed)
{
    modelnet::SwarmMandateArm arm;
    std::string err;
    BOOST_CHECK(!arm.Arm(5, true, false, true, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK_EQUAL(arm.automatic_spend(), "0");
    BOOST_CHECK(!arm.armed());
    BOOST_CHECK_EQUAL(arm.atoms_moved(), 0);
}

BOOST_AUTO_TEST_CASE(operator_unsigned_not_signed)
{
    modelnet::SwarmMandateArm arm;
    std::string err;
    BOOST_CHECK(!arm.Arm(5, false, false, false, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK_EQUAL(arm.automatic_spend(), "0");
    BOOST_CHECK(!arm.armed());
    BOOST_CHECK_EQUAL(arm.atoms_moved(), 0);
}

BOOST_AUTO_TEST_CASE(bound_zero)
{
    modelnet::SwarmMandateArm arm;
    std::string err;
    BOOST_CHECK(!arm.Arm(0, true, false, false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(arm.automatic_spend(), "0");
    BOOST_CHECK(!arm.armed());
    BOOST_CHECK_EQUAL(arm.atoms_moved(), 0);
}

BOOST_AUTO_TEST_CASE(arm_then_replay)
{
    modelnet::SwarmMandateArm arm;
    std::string err = "stale";
    BOOST_REQUIRE(arm.Arm(5, true, false, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(arm.armed());
    BOOST_CHECK_EQUAL(arm.automatic_spend(), "5");
    BOOST_CHECK_EQUAL(arm.atoms_moved(), 0);

    BOOST_CHECK(!arm.Arm(9, true, false, false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(arm.armed());
    BOOST_CHECK_EQUAL(arm.automatic_spend(), "5");
    BOOST_CHECK_EQUAL(arm.atoms_moved(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
