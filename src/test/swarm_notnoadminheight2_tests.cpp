// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoadminheight2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoadminheight2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoAdminHeight2 NotedNote()
{
    modelnet::SwarmNotNoAdminHeight2 note;
    note.admin_id = "admin-1";
    note.want_move = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_admin_id_yields_admin)
{
    modelnet::SwarmNotNoAdminHeight2 note = NotedNote();
    note.admin_id.clear();
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAdminHeight2Result result = modelnet::SwarmNoteNotNoAdminHeight2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "ADMIN");
    BOOST_CHECK_EQUAL(err, "ADMIN");
}

BOOST_AUTO_TEST_CASE(want_move_true_yields_held)
{
    modelnet::SwarmNotNoAdminHeight2 note = NotedNote();
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAdminHeight2Result result = modelnet::SwarmNoteNotNoAdminHeight2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(neither_yields_noted)
{
    modelnet::SwarmNotNoAdminHeight2 note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoAdminHeight2Result result = modelnet::SwarmNoteNotNoAdminHeight2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
