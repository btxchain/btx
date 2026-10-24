// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocatalog.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocatalog_tests, BasicTestingSetup)

static modelnet::SwarmNotNoCatalog NotedNote()
{
    modelnet::SwarmNotNoCatalog note;
    note.entry_id = "entry-1";
    note.want_authority = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_entry_id_is_entry)
{
    modelnet::SwarmNotNoCatalog note = NotedNote();
    note.entry_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotNoCatalogResult result = modelnet::SwarmNoteNotNoCatalog(note, err);
    BOOST_CHECK(!result.authority);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "ENTRY");
    BOOST_CHECK_EQUAL(err, "ENTRY");
}

BOOST_AUTO_TEST_CASE(want_authority_is_not_authority)
{
    modelnet::SwarmNotNoCatalog note = NotedNote();
    note.want_authority = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCatalogResult result = modelnet::SwarmNoteNotNoCatalog(note, err);
    BOOST_CHECK(!result.authority);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NOT_AUTHORITY");
    BOOST_CHECK_EQUAL(err, "NOT_AUTHORITY");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoCatalog note = NotedNote();
    note.want_authority = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCatalogResult result = modelnet::SwarmNoteNotNoCatalog(note, err);
    BOOST_CHECK(!result.authority);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
