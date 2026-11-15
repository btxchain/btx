// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnointeger82.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnointeger82_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_pair_id_is_pair)
{
    std::string err = "prior";
    modelnet::SwarmNotNoInteger82 note;
    const modelnet::SwarmNotNoInteger82Result result = modelnet::SwarmNoteNotNoInteger82(note, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.code, "PAIR");
    BOOST_CHECK_EQUAL(err, "PAIR");
}

BOOST_AUTO_TEST_CASE(want_add_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoInteger82 note;
    note.pair_id = "pair-1";
    note.want_add = true;
    const modelnet::SwarmNotNoInteger82Result result = modelnet::SwarmNoteNotNoInteger82(note, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoInteger82 note;
    note.pair_id = "pair-1";
    note.want_add = false;
    const modelnet::SwarmNotNoInteger82Result result = modelnet::SwarmNoteNotNoInteger82(note, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
