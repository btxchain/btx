// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoregtest2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoregtest2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_check_id)
{
    modelnet::SwarmNotNoRegtest2 note;
    note.isolated = true;
    note.want_mine = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoRegtest2Result result = modelnet::SwarmNoteNotNoRegtest2(note, err);
    BOOST_CHECK_EQUAL(result.code, "CHECK");
    BOOST_CHECK_EQUAL(err, "CHECK");
    BOOST_CHECK(!result.mined);
    BOOST_CHECK_EQUAL(result.blocks, 0);
}

BOOST_AUTO_TEST_CASE(isolated_check)
{
    modelnet::SwarmNotNoRegtest2 note;
    note.check_id = "check-a";
    note.isolated = true;
    note.want_mine = false;
    std::string err = "stale";
    const modelnet::SwarmNotNoRegtest2Result result = modelnet::SwarmNoteNotNoRegtest2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_MINED");
    BOOST_CHECK_EQUAL(err, "NOT_MINED");
    BOOST_CHECK(!result.mined);
    BOOST_CHECK_EQUAL(result.blocks, 0);
}

BOOST_AUTO_TEST_CASE(want_mine)
{
    modelnet::SwarmNotNoRegtest2 note;
    note.check_id = "check-a";
    note.want_mine = true;
    std::string err;
    const modelnet::SwarmNotNoRegtest2Result result = modelnet::SwarmNoteNotNoRegtest2(note, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!result.mined);
    BOOST_CHECK_EQUAL(result.blocks, 0);
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    modelnet::SwarmNotNoRegtest2 note;
    note.check_id = "check-a";
    std::string err = "stale";
    const modelnet::SwarmNotNoRegtest2Result result = modelnet::SwarmNoteNotNoRegtest2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.mined);
    BOOST_CHECK_EQUAL(result.blocks, 0);
}

BOOST_AUTO_TEST_SUITE_END()
