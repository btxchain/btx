// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofork2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnofork2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_branch_id_is_branch)
{
    modelnet::SwarmNotNoFork2 note;
    note.branch_id.clear();
    note.incompatible = true;
    note.want_average = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFork2Result result = modelnet::SwarmNoteNotNoFork2(note, err);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "BRANCH");
    BOOST_CHECK_EQUAL(err, "BRANCH");
}

BOOST_AUTO_TEST_CASE(incompatible_without_want_average_is_forked)
{
    modelnet::SwarmNotNoFork2 note;
    note.branch_id = "branch-1";
    note.incompatible = true;
    note.want_average = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoFork2Result result = modelnet::SwarmNoteNotNoFork2(note, err);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "FORKED");
    BOOST_CHECK_EQUAL(err, "FORKED");
}

BOOST_AUTO_TEST_CASE(want_average_is_held)
{
    modelnet::SwarmNotNoFork2 note;
    note.branch_id = "branch-1";
    note.incompatible = false;
    note.want_average = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFork2Result result = modelnet::SwarmNoteNotNoFork2(note, err);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(compatible_without_want_average_is_noted)
{
    modelnet::SwarmNotNoFork2 note;
    note.branch_id = "branch-1";
    note.incompatible = false;
    note.want_average = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoFork2Result result = modelnet::SwarmNoteNotNoFork2(note, err);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
