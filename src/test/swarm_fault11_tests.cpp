// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault11.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fault11_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_candidate_id)
{
    modelnet::SwarmFault11 note;
    note.regressed = true;
    note.want_roll = true;
    std::string err = "stale";
    const modelnet::SwarmFault11Result result = modelnet::SwarmRecoverFault11(note, err);
    BOOST_CHECK_EQUAL(result.code, "CANDIDATE");
    BOOST_CHECK(!result.rolled);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(err, "CANDIDATE");
}

BOOST_AUTO_TEST_CASE(regressed_even_when_want_roll)
{
    modelnet::SwarmFault11 note;
    note.candidate_id = "canary-a";
    note.regressed = true;
    note.want_roll = true;
    std::string err = "stale";
    const modelnet::SwarmFault11Result result = modelnet::SwarmRecoverFault11(note, err);
    BOOST_CHECK_EQUAL(result.code, "REGRESSION");
    BOOST_CHECK(!result.rolled);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(err, "REGRESSION");
}

BOOST_AUTO_TEST_CASE(want_roll_held)
{
    modelnet::SwarmFault11 note;
    note.candidate_id = "canary-a";
    note.want_roll = true;
    std::string err = "stale";
    const modelnet::SwarmFault11Result result = modelnet::SwarmRecoverFault11(note, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.rolled);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmFault11 note;
    note.candidate_id = "canary-a";
    std::string err = "stale";
    const modelnet::SwarmFault11Result result = modelnet::SwarmRecoverFault11(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.rolled);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
