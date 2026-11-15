// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notadmin.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notadmin_tests, BasicTestingSetup)

static modelnet::SwarmNotAdmin NotedNote()
{
    modelnet::SwarmNotAdmin note;
    note.admin_id = "admin-1";
    note.want_move = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_admin_id_is_admin)
{
    modelnet::SwarmNotAdmin note = NotedNote();
    note.admin_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotAdminResult result = modelnet::SwarmNoteNotAdmin(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.height_changed);
    BOOST_CHECK_EQUAL(result.code, "ADMIN");
    BOOST_CHECK_EQUAL(err, "ADMIN");
}

BOOST_AUTO_TEST_CASE(want_move_is_refused)
{
    modelnet::SwarmNotAdmin note = NotedNote();
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotAdminResult result = modelnet::SwarmNoteNotAdmin(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.height_changed);
    BOOST_CHECK_EQUAL(result.code, "REFUSED");
    BOOST_CHECK_EQUAL(err, "REFUSED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotAdmin note = NotedNote();
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotAdminResult result = modelnet::SwarmNoteNotAdmin(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.height_changed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
