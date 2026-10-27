// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoadmin.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoadmin_tests, BasicTestingSetup)

static modelnet::SwarmNotNoAdmin NotedNote()
{
    modelnet::SwarmNotNoAdmin note;
    note.admin_id = "admin-1";
    note.want_move_refund = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_admin_id_is_admin)
{
    modelnet::SwarmNotNoAdmin note = NotedNote();
    note.admin_id.clear();
    note.want_move_refund = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAdminResult result = modelnet::SwarmNoteNotNoAdmin(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.height, 0);
    BOOST_CHECK_EQUAL(result.code, "ADMIN");
    BOOST_CHECK_EQUAL(err, "ADMIN");
}

BOOST_AUTO_TEST_CASE(want_move_refund_is_refused)
{
    modelnet::SwarmNotNoAdmin note = NotedNote();
    note.want_move_refund = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAdminResult result = modelnet::SwarmNoteNotNoAdmin(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.height, 0);
    BOOST_CHECK_EQUAL(result.code, "REFUSED");
    BOOST_CHECK_EQUAL(err, "REFUSED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoAdmin note = NotedNote();
    note.want_move_refund = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAdminResult result = modelnet::SwarmNoteNotNoAdmin(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.height, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
