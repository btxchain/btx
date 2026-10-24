// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnokvpage2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnokvpage2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoKvPage2 NotedNote()
{
    modelnet::SwarmNotNoKvPage2 note;
    note.page_id = "page-1";
    note.incompatible = false;
    note.want_share = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_page_id_is_page)
{
    modelnet::SwarmNotNoKvPage2 note = NotedNote();
    note.page_id.clear();
    note.incompatible = true;
    note.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoKvPage2Result result = modelnet::SwarmNoteNotNoKvPage2(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "PAGE");
    BOOST_CHECK_EQUAL(err, "PAGE");
}

BOOST_AUTO_TEST_CASE(incompatible_without_want_share_is_not_shared)
{
    modelnet::SwarmNotNoKvPage2 note = NotedNote();
    note.incompatible = true;
    note.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoKvPage2Result result = modelnet::SwarmNoteNotNoKvPage2(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_SHARED");
    BOOST_CHECK_EQUAL(err, "NOT_SHARED");
}

BOOST_AUTO_TEST_CASE(want_share_is_held)
{
    modelnet::SwarmNotNoKvPage2 note = NotedNote();
    note.incompatible = false;
    note.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoKvPage2Result result = modelnet::SwarmNoteNotNoKvPage2(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoKvPage2 note = NotedNote();
    note.incompatible = false;
    note.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoKvPage2Result result = modelnet::SwarmNoteNotNoKvPage2(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
