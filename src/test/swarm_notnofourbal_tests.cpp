// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofourbal.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnofourbal_tests, BasicTestingSetup)

static modelnet::SwarmNotNoFourBal NotedNote()
{
    modelnet::SwarmNotNoFourBal note;
    note.book_id = "book-1";
    note.mixed = false;
    note.want_merge = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_book_id_is_book)
{
    modelnet::SwarmNotNoFourBal note = NotedNote();
    note.book_id.clear();
    note.mixed = true;
    note.want_merge = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFourBalResult result = modelnet::SwarmNoteNotNoFourBal(note, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "BOOK");
    BOOST_CHECK_EQUAL(err, "BOOK");
}

BOOST_AUTO_TEST_CASE(mixed_is_separate)
{
    modelnet::SwarmNotNoFourBal note = NotedNote();
    note.mixed = true;
    note.want_merge = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoFourBalResult result = modelnet::SwarmNoteNotNoFourBal(note, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "SEPARATE");
    BOOST_CHECK_EQUAL(err, "SEPARATE");
}

BOOST_AUTO_TEST_CASE(want_merge_is_held)
{
    modelnet::SwarmNotNoFourBal note = NotedNote();
    note.mixed = false;
    note.want_merge = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFourBalResult result = modelnet::SwarmNoteNotNoFourBal(note, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoFourBal note = NotedNote();
    note.mixed = false;
    note.want_merge = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoFourBalResult result = modelnet::SwarmNoteNotNoFourBal(note, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
