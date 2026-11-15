// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notrepeat.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notrepeat_tests, BasicTestingSetup)

static modelnet::SwarmNotRepeat NotedNote()
{
    modelnet::SwarmNotRepeat note;
    note.parent_id = "parent-1";
    note.want_repeat = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_parent_id_is_parent)
{
    modelnet::SwarmNotRepeat note = NotedNote();
    note.parent_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotRepeatResult result = modelnet::SwarmNoteNotRepeat(note, err);
    BOOST_CHECK(!result.repeated);
    BOOST_CHECK_EQUAL(result.code, "PARENT");
    BOOST_CHECK_EQUAL(err, "PARENT");
}

BOOST_AUTO_TEST_CASE(want_repeat_is_not_repeated)
{
    modelnet::SwarmNotRepeat note = NotedNote();
    note.want_repeat = true;
    std::string err = "prior";
    const modelnet::SwarmNotRepeatResult result = modelnet::SwarmNoteNotRepeat(note, err);
    BOOST_CHECK(!result.repeated);
    BOOST_CHECK_EQUAL(result.code, "NOT_REPEATED");
    BOOST_CHECK_EQUAL(err, "NOT_REPEATED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotRepeat note = NotedNote();
    note.want_repeat = false;
    std::string err = "prior";
    const modelnet::SwarmNotRepeatResult result = modelnet::SwarmNoteNotRepeat(note, err);
    BOOST_CHECK(!result.repeated);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
