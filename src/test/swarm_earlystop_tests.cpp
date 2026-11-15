// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_earlystop.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_earlystop_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(rising_score_can_promote)
{
    modelnet::SwarmEarlyStop gate;
    std::string err = "stale";

    BOOST_CHECK(!gate.Open("", 3, err));
    BOOST_CHECK_EQUAL(err, "EXPERIMENT");
    BOOST_CHECK_EQUAL(gate.remaining(""), -1);
    BOOST_CHECK(!gate.stopped(""));

    BOOST_CHECK(!gate.Open("rise", 0, err));
    BOOST_CHECK_EQUAL(err, "BUDGET");
    BOOST_CHECK_EQUAL(gate.remaining("rise"), -1);

    BOOST_CHECK(!gate.Open("rise", -2, err));
    BOOST_CHECK_EQUAL(err, "BUDGET");
    BOOST_CHECK_EQUAL(gate.remaining("rise"), -1);

    BOOST_REQUIRE(gate.Open("rise", 3, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(gate.remaining("rise"), 3);
    BOOST_CHECK_EQUAL(gate.score("rise"), -1);
    BOOST_CHECK(!gate.stopped("rise"));

    BOOST_CHECK(!gate.Open("rise", 9, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(gate.remaining("rise"), 3);

    BOOST_CHECK(!gate.Promote("rise", err));
    BOOST_CHECK_EQUAL(err, "STEP");
    BOOST_CHECK_EQUAL(gate.remaining("rise"), 3);
    BOOST_CHECK_EQUAL(gate.score("rise"), -1);

    BOOST_CHECK(!gate.Step("missing", 100, err));
    BOOST_CHECK_EQUAL(err, "EXPERIMENT");
    BOOST_CHECK_EQUAL(gate.remaining("missing"), -1);
    BOOST_CHECK_EQUAL(gate.remaining("rise"), 3);

    BOOST_CHECK(!gate.Step("rise", -1, err));
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK_EQUAL(gate.remaining("rise"), 3);
    BOOST_CHECK_EQUAL(gate.score("rise"), -1);

    BOOST_REQUIRE(gate.Step("rise", 1000, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(gate.remaining("rise"), 2);
    BOOST_CHECK_EQUAL(gate.score("rise"), 1000);
    BOOST_CHECK(!gate.stopped("rise"));

    BOOST_REQUIRE(gate.Step("rise", 2500, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(gate.remaining("rise"), 1);
    BOOST_CHECK_EQUAL(gate.score("rise"), 2500);
    BOOST_CHECK(!gate.stopped("rise"));

    BOOST_REQUIRE(gate.Promote("rise", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(gate.remaining("rise"), 1);
    BOOST_CHECK_EQUAL(gate.score("rise"), 2500);
    BOOST_CHECK(!gate.stopped("rise"));

    BOOST_REQUIRE(gate.Step("rise", 2500, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(gate.remaining("rise"), 0);
    BOOST_CHECK_EQUAL(gate.score("rise"), 2500);
    BOOST_CHECK(!gate.stopped("rise"));

    BOOST_CHECK(!gate.Step("rise", 9000, err));
    BOOST_CHECK_EQUAL(err, "STOPPED");
    BOOST_CHECK_EQUAL(gate.remaining("rise"), 0);
    BOOST_CHECK_EQUAL(gate.score("rise"), 2500);
    BOOST_CHECK(!gate.stopped("rise"));

    BOOST_REQUIRE(gate.Promote("rise", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!gate.stopped("rise"));
    BOOST_CHECK_EQUAL(gate.score("rise"), 2500);
}

BOOST_AUTO_TEST_CASE(falling_score_stops_and_cannot_promote)
{
    modelnet::SwarmEarlyStop gate;
    std::string err = "stale";

    BOOST_REQUIRE(gate.Open("fall", 5, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!gate.stopped("fall"));

    BOOST_REQUIRE(gate.Step("fall", 8000, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(gate.remaining("fall"), 4);
    BOOST_CHECK_EQUAL(gate.score("fall"), 8000);
    BOOST_CHECK(!gate.stopped("fall"));

    BOOST_REQUIRE(gate.Step("fall", 7999, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(gate.stopped("fall"));
    BOOST_CHECK_EQUAL(gate.remaining("fall"), 0);
    BOOST_CHECK_EQUAL(gate.score("fall"), 7999);

    BOOST_CHECK(!gate.Step("fall", -5, err));
    BOOST_CHECK_EQUAL(err, "STOPPED");
    BOOST_CHECK_EQUAL(gate.score("fall"), 7999);
    BOOST_CHECK_EQUAL(gate.remaining("fall"), 0);
    BOOST_CHECK(gate.stopped("fall"));

    BOOST_CHECK(!gate.Step("fall", 100000, err));
    BOOST_CHECK_EQUAL(err, "STOPPED");
    BOOST_CHECK_EQUAL(gate.score("fall"), 7999);
    BOOST_CHECK_EQUAL(gate.remaining("fall"), 0);

    BOOST_CHECK(!gate.Promote("fall", err));
    BOOST_CHECK_EQUAL(err, "STOPPED");
    BOOST_CHECK(gate.stopped("fall"));
    BOOST_CHECK_EQUAL(gate.score("fall"), 7999);
    BOOST_CHECK_EQUAL(gate.remaining("fall"), 0);

    BOOST_CHECK(!gate.Promote("fall", err));
    BOOST_CHECK_EQUAL(err, "STOPPED");
    BOOST_CHECK(gate.stopped("fall"));

    BOOST_CHECK(!gate.Promote("absent", err));
    BOOST_CHECK_EQUAL(err, "EXPERIMENT");
    BOOST_CHECK(!gate.stopped("absent"));
}

BOOST_AUTO_TEST_SUITE_END()
