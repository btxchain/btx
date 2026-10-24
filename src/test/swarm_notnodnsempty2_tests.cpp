// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnodnsempty2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnodnsempty2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_list_id_is_list)
{
    modelnet::SwarmNotNoDnsEmpty2 note;
    note.want_add = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoDnsEmpty2Result result = modelnet::SwarmNoteNotNoDnsEmpty2(note, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.code, "LIST");
    BOOST_CHECK_EQUAL(err, "LIST");
}

BOOST_AUTO_TEST_CASE(want_add_is_held)
{
    modelnet::SwarmNotNoDnsEmpty2 note;
    note.list_id = "list-1";
    note.want_add = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoDnsEmpty2Result result = modelnet::SwarmNoteNotNoDnsEmpty2(note, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoDnsEmpty2 note;
    note.list_id = "list-1";
    note.want_add = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoDnsEmpty2Result result = modelnet::SwarmNoteNotNoDnsEmpty2(note, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
