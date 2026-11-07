// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofork.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnofork_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_branch_id_is_branch)
{
    modelnet::SwarmNotNoFork note;
    note.branch_id.clear();
    note.compatible = false;
    note.want_merge = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoForkResult result = modelnet::SwarmNoteNotNoFork(note, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "BRANCH");
    BOOST_CHECK_EQUAL(err, "BRANCH");
}

BOOST_AUTO_TEST_CASE(incompatible_without_want_merge_is_fork)
{
    modelnet::SwarmNotNoFork note;
    note.branch_id = "branch-1";
    note.compatible = false;
    note.want_merge = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoForkResult result = modelnet::SwarmNoteNotNoFork(note, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "FORK");
    BOOST_CHECK_EQUAL(err, "FORK");
}

BOOST_AUTO_TEST_CASE(want_merge_is_fork)
{
    modelnet::SwarmNotNoFork note;
    note.branch_id = "branch-1";
    note.compatible = true;
    note.want_merge = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoForkResult result = modelnet::SwarmNoteNotNoFork(note, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "FORK");
    BOOST_CHECK_EQUAL(err, "FORK");
}

BOOST_AUTO_TEST_CASE(compatible_without_want_merge_is_noted)
{
    modelnet::SwarmNotNoFork note;
    note.branch_id = "branch-1";
    note.compatible = true;
    note.want_merge = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoForkResult result = modelnet::SwarmNoteNotNoFork(note, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
