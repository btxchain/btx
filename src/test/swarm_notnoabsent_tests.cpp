// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoabsent.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoabsent_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_engine_id_is_engine)
{
    std::string err = "prior";
    modelnet::SwarmNotNoAbsent note;
    note.present = false;
    note.want_move = true;
    const modelnet::SwarmNotNoAbsentResult result = modelnet::SwarmNoteNotNoAbsent(note, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(!result.transferred);
    BOOST_CHECK_EQUAL(result.code, "ENGINE");
    BOOST_CHECK_EQUAL(err, "ENGINE");
}

BOOST_AUTO_TEST_CASE(absent_engine_is_engine_absent)
{
    std::string err = "prior";
    modelnet::SwarmNotNoAbsent note;
    note.engine_id = "engine-1";
    note.present = false;
    note.want_move = false;
    const modelnet::SwarmNotNoAbsentResult result = modelnet::SwarmNoteNotNoAbsent(note, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(!result.transferred);
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(want_move_with_present_is_engine_absent)
{
    std::string err = "prior";
    modelnet::SwarmNotNoAbsent note;
    note.engine_id = "engine-1";
    note.present = true;
    note.want_move = true;
    const modelnet::SwarmNotNoAbsentResult result = modelnet::SwarmNoteNotNoAbsent(note, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(!result.transferred);
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(plain_present_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoAbsent note;
    note.engine_id = "engine-1";
    note.present = true;
    note.want_move = false;
    const modelnet::SwarmNotNoAbsentResult result = modelnet::SwarmNoteNotNoAbsent(note, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(!result.transferred);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
