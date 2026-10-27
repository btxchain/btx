// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_capact/swarm_capact.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_capact_act_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(ungranted_act_returns_not_acted_and_records_nothing)
{
    modelnet::SwarmCapAct plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.granted("cap-a"));
    BOOST_REQUIRE(!plane.acted("cap-a"));
    BOOST_REQUIRE(plane.grant_count() == 0);
    BOOST_REQUIRE(plane.action_count() == 0);

    BOOST_REQUIRE(!plane.Act("cap-a", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_ACTED");
    BOOST_REQUIRE(!plane.granted("cap-a"));
    BOOST_REQUIRE(!plane.acted("cap-a"));
    BOOST_REQUIRE(plane.grant_count() == 0);
    BOOST_REQUIRE(plane.action_count() == 0);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(granted_act_records_once_and_returns_true)
{
    modelnet::SwarmCapAct plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Grant("cap-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.granted("cap-a"));
    BOOST_REQUIRE(!plane.acted("cap-a"));
    BOOST_REQUIRE(plane.action_count() == 0);

    BOOST_REQUIRE(plane.Act("cap-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.granted("cap-a"));
    BOOST_REQUIRE(plane.acted("cap-a"));
    BOOST_REQUIRE(plane.grant_count() == 1);
    BOOST_REQUIRE(plane.action_count() == 1);
    BOOST_REQUIRE(!plane.acted("cap-b"));
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(acting_one_name_does_not_grant_or_record_another)
{
    modelnet::SwarmCapAct plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Grant("cap-a", err));
    BOOST_REQUIRE(plane.Act("cap-a", err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Act("cap-b", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_ACTED");
    BOOST_REQUIRE(plane.granted("cap-a"));
    BOOST_REQUIRE(!plane.granted("cap-b"));
    BOOST_REQUIRE(plane.acted("cap-a"));
    BOOST_REQUIRE(!plane.acted("cap-b"));
    BOOST_REQUIRE(plane.grant_count() == 1);
    BOOST_REQUIRE(plane.action_count() == 1);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
