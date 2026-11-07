// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoonech.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoonech_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_pool_id_is_pool)
{
    modelnet::SwarmNotNoOneCh note;
    note.pool_id.clear();
    note.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoOneChResult result = modelnet::SwarmNoteNotNoOneCh(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.channels, 0);
    BOOST_CHECK_EQUAL(result.code, "POOL");
    BOOST_CHECK_EQUAL(err, "POOL");
}

BOOST_AUTO_TEST_CASE(want_open_is_one)
{
    modelnet::SwarmNotNoOneCh note;
    note.pool_id = "pool-1";
    note.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoOneChResult result = modelnet::SwarmNoteNotNoOneCh(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.channels, 0);
    BOOST_CHECK_EQUAL(result.code, "ONE");
    BOOST_CHECK_EQUAL(err, "ONE");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoOneCh note;
    note.pool_id = "pool-1";
    note.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoOneChResult result = modelnet::SwarmNoteNotNoOneCh(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.channels, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
