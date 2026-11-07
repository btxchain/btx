// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notadopt.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notadopt_tests, BasicTestingSetup)

static modelnet::SwarmNotAdopt NotedNote()
{
    modelnet::SwarmNotAdopt note;
    note.descendant_id = "descendant-1";
    note.want_adopt = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_descendant_id_is_descendant)
{
    modelnet::SwarmNotAdopt note = NotedNote();
    note.descendant_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotAdoptResult result = modelnet::SwarmNoteNotAdopt(note, err);
    BOOST_CHECK(!result.adopted);
    BOOST_CHECK_EQUAL(result.code, "DESCENDANT");
    BOOST_CHECK_EQUAL(err, "DESCENDANT");
}

BOOST_AUTO_TEST_CASE(want_adopt_is_not_adopted)
{
    modelnet::SwarmNotAdopt note = NotedNote();
    note.want_adopt = true;
    std::string err = "prior";
    const modelnet::SwarmNotAdoptResult result = modelnet::SwarmNoteNotAdopt(note, err);
    BOOST_CHECK(!result.adopted);
    BOOST_CHECK_EQUAL(result.code, "NOT_ADOPTED");
    BOOST_CHECK_EQUAL(err, "NOT_ADOPTED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotAdopt note = NotedNote();
    note.want_adopt = false;
    std::string err = "prior";
    const modelnet::SwarmNotAdoptResult result = modelnet::SwarmNoteNotAdopt(note, err);
    BOOST_CHECK(!result.adopted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
