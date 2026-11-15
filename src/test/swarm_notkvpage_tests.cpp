// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notkvpage.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notkvpage_tests, BasicTestingSetup)

static modelnet::SwarmNotKvPage NotedNote()
{
    modelnet::SwarmNotKvPage note;
    note.page_id = "page-1";
    note.compatible = true;
    note.want_share = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_page_id_is_page)
{
    modelnet::SwarmNotKvPage note = NotedNote();
    note.page_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotKvPageResult result = modelnet::SwarmNoteNotKvPage(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "PAGE");
    BOOST_CHECK_EQUAL(err, "PAGE");
}

BOOST_AUTO_TEST_CASE(incompatible_without_want_share_is_separate)
{
    modelnet::SwarmNotKvPage note = NotedNote();
    note.compatible = false;
    note.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmNotKvPageResult result = modelnet::SwarmNoteNotKvPage(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "SEPARATE");
    BOOST_CHECK_EQUAL(err, "SEPARATE");
}

BOOST_AUTO_TEST_CASE(want_share_with_compatible_is_held)
{
    modelnet::SwarmNotKvPage note = NotedNote();
    note.compatible = true;
    note.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmNotKvPageResult result = modelnet::SwarmNoteNotKvPage(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_compatible_note_is_noted)
{
    modelnet::SwarmNotKvPage note = NotedNote();
    note.compatible = true;
    note.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmNotKvPageResult result = modelnet::SwarmNoteNotKvPage(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
