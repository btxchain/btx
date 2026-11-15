// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_capcover.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_capcover_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_capability_id)
{
    modelnet::SwarmCapCover cap;
    cap.capability_id.clear();
    cap.covered = false;
    cap.want_act = false;
    std::string err;
    const modelnet::SwarmCapCoverResult result = modelnet::SwarmNoteCapability(cap, err);
    BOOST_CHECK(!result.acted);
    BOOST_CHECK_EQUAL(result.code, "CAPABILITY");
    BOOST_CHECK_EQUAL(err, "CAPABILITY");
}

BOOST_AUTO_TEST_CASE(uncovered_want_act_false)
{
    modelnet::SwarmCapCover cap;
    cap.capability_id = "cap-a";
    cap.covered = false;
    cap.want_act = false;
    std::string err;
    const modelnet::SwarmCapCoverResult result = modelnet::SwarmNoteCapability(cap, err);
    BOOST_CHECK(!result.acted);
    BOOST_CHECK_EQUAL(result.code, "NOT_ACTED");
    BOOST_CHECK_EQUAL(err, "NOT_ACTED");
}

BOOST_AUTO_TEST_CASE(want_act_held)
{
    modelnet::SwarmCapCover cap;
    cap.capability_id = "cap-b";
    cap.covered = true;
    cap.want_act = true;
    std::string err;
    const modelnet::SwarmCapCoverResult result = modelnet::SwarmNoteCapability(cap, err);
    BOOST_CHECK(!result.acted);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmCapCover cap;
    cap.capability_id = "cap-c";
    cap.covered = true;
    cap.want_act = false;
    std::string err = "stale";
    const modelnet::SwarmCapCoverResult result = modelnet::SwarmNoteCapability(cap, err);
    BOOST_CHECK(!result.acted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
