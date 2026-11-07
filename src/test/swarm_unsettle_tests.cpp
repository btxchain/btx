// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_unsettle.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_unsettle_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_earning_id_is_unsettled)
{
    std::string err = "prior";
    modelnet::SwarmEarning earning;
    earning.earning_id = "";
    earning.atoms = 100;
    const modelnet::SwarmEarningResult result = modelnet::SwarmNoteEarning(earning, err);
    BOOST_CHECK(!result.recorded);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "UNSETTLED");
    BOOST_CHECK_EQUAL(err, "UNSETTLED");
}

BOOST_AUTO_TEST_CASE(non_positive_atoms_are_unsettled)
{
    std::string err = "prior";
    modelnet::SwarmEarning earning;
    earning.earning_id = "earn-1";
    earning.atoms = 0;
    const modelnet::SwarmEarningResult zero = modelnet::SwarmNoteEarning(earning, err);
    BOOST_CHECK(!zero.recorded);
    BOOST_CHECK(!zero.settled);
    BOOST_CHECK(!zero.broadcast);
    BOOST_CHECK_EQUAL(zero.atoms, 0);
    BOOST_CHECK_EQUAL(zero.code, "UNSETTLED");
    BOOST_CHECK_EQUAL(err, "UNSETTLED");

    earning.atoms = -1;
    const modelnet::SwarmEarningResult negative = modelnet::SwarmNoteEarning(earning, err);
    BOOST_CHECK(!negative.recorded);
    BOOST_CHECK(!negative.settled);
    BOOST_CHECK(!negative.broadcast);
    BOOST_CHECK_EQUAL(negative.atoms, 0);
    BOOST_CHECK_EQUAL(negative.code, "UNSETTLED");
    BOOST_CHECK_EQUAL(err, "UNSETTLED");
}

BOOST_AUTO_TEST_CASE(want_broadcast_is_forbidden_even_before_a_crash)
{
    std::string err = "prior";
    modelnet::SwarmEarning earning;
    earning.earning_id = "earn-1";
    earning.atoms = 250;
    earning.crash_before_settlement = true;
    earning.want_broadcast = true;
    const modelnet::SwarmEarningResult result = modelnet::SwarmNoteEarning(earning, err);
    BOOST_CHECK(!result.recorded);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "BROADCAST_FORBIDDEN");
    BOOST_CHECK_EQUAL(err, "BROADCAST_FORBIDDEN");
}

BOOST_AUTO_TEST_CASE(crash_before_settlement_is_held)
{
    std::string err = "prior";
    modelnet::SwarmEarning earning;
    earning.earning_id = "earn-1";
    earning.atoms = 250;
    earning.crash_before_settlement = true;
    const modelnet::SwarmEarningResult result = modelnet::SwarmNoteEarning(earning, err);
    BOOST_CHECK(result.recorded);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.atoms, earning.atoms);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(noted_earning_is_recorded)
{
    std::string err = "prior";
    modelnet::SwarmEarning earning;
    earning.earning_id = "earn-1";
    earning.atoms = 250;
    const modelnet::SwarmEarningResult result = modelnet::SwarmNoteEarning(earning, err);
    BOOST_CHECK(result.recorded);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.atoms, earning.atoms);
    BOOST_CHECK_EQUAL(result.code, "RECORDED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
