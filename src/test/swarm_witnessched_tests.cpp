// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_witnessched.h>
#include <test/util/setup_common.h>

#include <string>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_witnessched_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(record_rules)
{
    modelnet::SwarmWitnessSched sched;
    std::string err;

    BOOST_CHECK(!sched.Record("", false, true, err));
    BOOST_CHECK_EQUAL(err, "TX");
    BOOST_CHECK(!sched.signed_ok(""));

    BOOST_CHECK(!sched.Record("sched", true, true, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK(!sched.signed_ok("sched"));

    BOOST_CHECK(!sched.Record("sched", true, true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!sched.signed_ok("sched"));

    BOOST_CHECK(!sched.Record("nocover", false, false, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK(!sched.signed_ok("nocover"));

    BOOST_CHECK(!sched.Record("nocover", false, true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!sched.signed_ok("nocover"));

    err = "stale";
    BOOST_REQUIRE(sched.Record("fresh", false, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(sched.signed_ok("fresh"));

    BOOST_CHECK(!sched.Record("fresh", true, true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(sched.signed_ok("fresh"));
}

BOOST_AUTO_TEST_SUITE_END()
