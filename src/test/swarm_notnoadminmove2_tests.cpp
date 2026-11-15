// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoadminmove2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoadminmove2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_refund_id_is_refund)
{
    modelnet::SwarmNotNoAdminMove2 note;
    note.refund_id.clear();
    note.admin = true;
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAdminMove2Result result = modelnet::SwarmNoteNotNoAdminMove2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.height, 0);
    BOOST_CHECK_EQUAL(result.code, "REFUND");
    BOOST_CHECK_EQUAL(err, "REFUND");
}

BOOST_AUTO_TEST_CASE(admin_without_want_move_is_not_moved)
{
    modelnet::SwarmNotNoAdminMove2 note;
    note.refund_id = "refund-1";
    note.admin = true;
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAdminMove2Result result = modelnet::SwarmNoteNotNoAdminMove2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.height, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_MOVED");
    BOOST_CHECK_EQUAL(err, "NOT_MOVED");
}

BOOST_AUTO_TEST_CASE(want_move_is_held)
{
    modelnet::SwarmNotNoAdminMove2 note;
    note.refund_id = "refund-1";
    note.admin = false;
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAdminMove2Result result = modelnet::SwarmNoteNotNoAdminMove2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.height, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoAdminMove2 note;
    note.refund_id = "refund-1";
    note.admin = false;
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAdminMove2Result result = modelnet::SwarmNoteNotNoAdminMove2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.height, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
