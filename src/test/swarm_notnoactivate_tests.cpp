// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoactivate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoactivate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_book_id_is_book)
{
    modelnet::SwarmNotNoActivate note;
    note.verified = false;
    note.want_activate = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoActivateResult result = modelnet::SwarmNoteNotNoActivate(note, err);
    BOOST_CHECK(!result.activated);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "BOOK");
    BOOST_CHECK_EQUAL(err, "BOOK");
}

BOOST_AUTO_TEST_CASE(verified_false_is_not_verified_when_want_activate_is_false)
{
    modelnet::SwarmNotNoActivate note;
    note.book_id = "book-1";
    note.verified = false;
    note.want_activate = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoActivateResult result = modelnet::SwarmNoteNotNoActivate(note, err);
    BOOST_CHECK(!result.activated);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_VERIFIED");
    BOOST_CHECK_EQUAL(err, "NOT_VERIFIED");
}

BOOST_AUTO_TEST_CASE(want_activate_is_held)
{
    modelnet::SwarmNotNoActivate note;
    note.book_id = "book-1";
    note.verified = true;
    note.want_activate = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoActivateResult result = modelnet::SwarmNoteNotNoActivate(note, err);
    BOOST_CHECK(!result.activated);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoActivate note;
    note.book_id = "book-1";
    note.verified = true;
    note.want_activate = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoActivateResult result = modelnet::SwarmNoteNotNoActivate(note, err);
    BOOST_CHECK(!result.activated);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
