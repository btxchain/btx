// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnordmaabsent2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnordmaabsent2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_engine_id_is_engine)
{
    std::string err = "prior";
    modelnet::SwarmNotNoRdmaAbsent2 note;
    note.rdma_absent = true;
    note.want_move = true;
    const modelnet::SwarmNotNoRdmaAbsent2Result result = modelnet::SwarmNoteNotNoRdmaAbsent2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ENGINE");
    BOOST_CHECK_EQUAL(err, "ENGINE");
}

BOOST_AUTO_TEST_CASE(rdma_absent_is_engine_absent)
{
    std::string err = "prior";
    modelnet::SwarmNotNoRdmaAbsent2 note;
    note.engine_id = "engine-1";
    note.rdma_absent = true;
    note.want_move = false;
    const modelnet::SwarmNotNoRdmaAbsent2Result result = modelnet::SwarmNoteNotNoRdmaAbsent2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(want_move_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoRdmaAbsent2 note;
    note.engine_id = "engine-1";
    note.rdma_absent = false;
    note.want_move = true;
    const modelnet::SwarmNotNoRdmaAbsent2Result result = modelnet::SwarmNoteNotNoRdmaAbsent2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoRdmaAbsent2 note;
    note.engine_id = "engine-1";
    note.rdma_absent = false;
    note.want_move = false;
    const modelnet::SwarmNotNoRdmaAbsent2Result result = modelnet::SwarmNoteNotNoRdmaAbsent2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
