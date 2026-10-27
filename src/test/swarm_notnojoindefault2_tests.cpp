// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnojoindefault2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnojoindefault2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmNotNoJoinDefault2 note;
    std::string err = "prior";
    const modelnet::SwarmNotNoJoinDefault2Result result = modelnet::SwarmNoteNotNoJoinDefault2(note, err);
    BOOST_CHECK_EQUAL(result.left, false);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_leave_is_held)
{
    modelnet::SwarmNotNoJoinDefault2 note;
    note.node_id = "node-1";
    note.want_leave = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoJoinDefault2Result result = modelnet::SwarmNoteNotNoJoinDefault2(note, err);
    BOOST_CHECK_EQUAL(result.left, false);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_is_noted)
{
    modelnet::SwarmNotNoJoinDefault2 note;
    note.node_id = "node-1";
    note.want_leave = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoJoinDefault2Result result = modelnet::SwarmNoteNotNoJoinDefault2(note, err);
    BOOST_CHECK_EQUAL(result.left, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
