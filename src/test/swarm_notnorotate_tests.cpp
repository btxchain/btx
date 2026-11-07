// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorotate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnorotate_tests, BasicTestingSetup)

static modelnet::SwarmNotNoRotate NotedNote()
{
    modelnet::SwarmNotNoRotate note;
    note.key_id = "key-1";
    note.want_rotate = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_key_id_is_key)
{
    modelnet::SwarmNotNoRotate note = NotedNote();
    note.key_id.clear();
    note.want_rotate = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoRotateResult result = modelnet::SwarmNoteNotNoRotate(note, err);
    BOOST_CHECK(!result.rotated);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "KEY");
    BOOST_CHECK_EQUAL(err, "KEY");
}

BOOST_AUTO_TEST_CASE(want_rotate_is_refused)
{
    modelnet::SwarmNotNoRotate note = NotedNote();
    note.want_rotate = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoRotateResult result = modelnet::SwarmNoteNotNoRotate(note, err);
    BOOST_CHECK(!result.rotated);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "REFUSED");
    BOOST_CHECK_EQUAL(err, "REFUSED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoRotate note = NotedNote();
    note.want_rotate = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoRotateResult result = modelnet::SwarmNoteNotNoRotate(note, err);
    BOOST_CHECK(!result.rotated);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
