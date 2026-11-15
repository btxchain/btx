// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notdep.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notdep_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_dep_id)
{
    modelnet::SwarmNotDep note;
    std::string err = "stale";
    const modelnet::SwarmNotDepResult result = modelnet::SwarmNoteNotDep(note, err);
    BOOST_CHECK_EQUAL(result.code, "DEP");
    BOOST_CHECK(!result.detected);
    BOOST_CHECK(!result.required);
    BOOST_CHECK_EQUAL(err, "DEP");
}

BOOST_AUTO_TEST_CASE(want_detect_not_detected)
{
    modelnet::SwarmNotDep note;
    note.dep_id = "dep-1";
    note.want_detect = true;
    std::string err = "stale";
    const modelnet::SwarmNotDepResult result = modelnet::SwarmNoteNotDep(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_DETECTED");
    BOOST_CHECK(!result.detected);
    BOOST_CHECK(!result.required);
    BOOST_CHECK_EQUAL(err, "NOT_DETECTED");
}

BOOST_AUTO_TEST_CASE(noted_clears_err)
{
    modelnet::SwarmNotDep note;
    note.dep_id = "dep-1";
    std::string err = "stale";
    const modelnet::SwarmNotDepResult result = modelnet::SwarmNoteNotDep(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.detected);
    BOOST_CHECK(!result.required);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
