// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_remedy/remedy.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_remedy_read_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(revoked_read_is_not_recorded)
{
    modelnet::SwarmRemedy remedy;
    std::string err = "prior";

    BOOST_REQUIRE(!remedy.Revoke("", err));
    BOOST_REQUIRE_EQUAL(err, "MEMBER");
    BOOST_REQUIRE(!remedy.revoked(""));
    BOOST_REQUIRE(!remedy.read_recorded(""));

    BOOST_REQUIRE(!remedy.Read("", err));
    BOOST_REQUIRE_EQUAL(err, "MEMBER");
    BOOST_REQUIRE(!remedy.read_recorded(""));

    BOOST_REQUIRE(remedy.Read("sponsor", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(remedy.read_recorded("sponsor"));
    BOOST_REQUIRE(!remedy.revoked("sponsor"));

    BOOST_REQUIRE(remedy.Revoke("worker", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(remedy.revoked("worker"));

    err = "prior";
    BOOST_REQUIRE(!remedy.Revoke("worker", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(remedy.revoked("worker"));

    err = "prior";
    BOOST_REQUIRE(!remedy.Read("worker", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_READ");
    BOOST_REQUIRE(!remedy.read_recorded("worker"));
    BOOST_REQUIRE(remedy.read_recorded("sponsor"));

    BOOST_REQUIRE(remedy.Read("auditor", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(remedy.read_recorded("auditor"));
    BOOST_REQUIRE(remedy.Revoke("auditor", err));
    BOOST_REQUIRE(remedy.revoked("auditor"));

    err = "prior";
    BOOST_REQUIRE(!remedy.Read("auditor", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_READ");
    BOOST_REQUIRE(remedy.read_recorded("auditor"));
    BOOST_REQUIRE(!remedy.read_recorded("worker"));
    BOOST_REQUIRE(!remedy.broadcast());
    BOOST_REQUIRE_EQUAL(remedy.bytes_moved(), 0);
    BOOST_REQUIRE(!remedy.mined());
    BOOST_REQUIRE(!remedy.secret_released());
}

BOOST_AUTO_TEST_SUITE_END()
