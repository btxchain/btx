// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoswarmdjoin2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoswarmdjoin2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_name_id)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSwarmdJoin2 note;
    note.sidecar = true;
    note.want_launch = true;
    const modelnet::SwarmNotNoSwarmdJoin2Result result = modelnet::SwarmNoteNotNoSwarmdJoin2(note, err);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "NAME");
    BOOST_CHECK_EQUAL(err, "NAME");
}

BOOST_AUTO_TEST_CASE(sidecar)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSwarmdJoin2 note;
    note.name_id = "name-1";
    note.sidecar = true;
    note.want_launch = false;
    const modelnet::SwarmNotNoSwarmdJoin2Result result = modelnet::SwarmNoteNotNoSwarmdJoin2(note, err);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "NOT_LAUNCHED");
    BOOST_CHECK_EQUAL(err, "NOT_LAUNCHED");
}

BOOST_AUTO_TEST_CASE(want_launch)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSwarmdJoin2 note;
    note.name_id = "name-1";
    note.sidecar = false;
    note.want_launch = true;
    const modelnet::SwarmNotNoSwarmdJoin2Result result = modelnet::SwarmNoteNotNoSwarmdJoin2(note, err);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSwarmdJoin2 note;
    note.name_id = "name-1";
    note.sidecar = false;
    note.want_launch = false;
    const modelnet::SwarmNotNoSwarmdJoin2Result result = modelnet::SwarmNoteNotNoSwarmdJoin2(note, err);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
