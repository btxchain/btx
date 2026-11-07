// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_capact/swarm_capact.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_capact_replay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(duplicate_grant_is_replay_and_keeps_the_first)
{
    modelnet::SwarmCapAct plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Grant("cap-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.granted("cap-a"));
    BOOST_REQUIRE(plane.grant_count() == 1);

    err = "prior";
    BOOST_REQUIRE(!plane.Grant("cap-a", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.granted("cap-a"));
    BOOST_REQUIRE(!plane.acted("cap-a"));
    BOOST_REQUIRE(plane.grant_count() == 1);
    BOOST_REQUIRE(plane.action_count() == 0);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");

    BOOST_REQUIRE(plane.Act("cap-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.acted("cap-a"));
    BOOST_REQUIRE(plane.action_count() == 1);
    BOOST_REQUIRE(plane.grant_count() == 1);
}

BOOST_AUTO_TEST_CASE(second_act_is_replay_and_does_not_add_a_record)
{
    modelnet::SwarmCapAct plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Grant("cap-a", err));
    BOOST_REQUIRE(plane.Act("cap-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.acted("cap-a"));
    BOOST_REQUIRE(plane.action_count() == 1);

    err = "prior";
    BOOST_REQUIRE(!plane.Act("cap-a", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.granted("cap-a"));
    BOOST_REQUIRE(plane.acted("cap-a"));
    BOOST_REQUIRE(plane.grant_count() == 1);
    BOOST_REQUIRE(plane.action_count() == 1);

    err = "prior";
    BOOST_REQUIRE(!plane.Act("cap-a", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.action_count() == 1);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(a_different_name_is_not_a_replay)
{
    modelnet::SwarmCapAct plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Grant("cap-a", err));
    BOOST_REQUIRE(plane.Grant("cap-b", err));
    BOOST_REQUIRE(plane.Act("cap-a", err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Act("cap-a", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");

    BOOST_REQUIRE(plane.Act("cap-b", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.acted("cap-a"));
    BOOST_REQUIRE(plane.acted("cap-b"));
    BOOST_REQUIRE(plane.grant_count() == 2);
    BOOST_REQUIRE(plane.action_count() == 2);

    err = "prior";
    BOOST_REQUIRE(!plane.Grant("cap-a", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.grant_count() == 2);
    BOOST_REQUIRE(plane.action_count() == 2);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
