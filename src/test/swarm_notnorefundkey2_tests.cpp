// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorefundkey2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnorefundkey2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_admin_id_is_admin)
{
    modelnet::SwarmNotNoRefundKey2 note;
    note.admin_id.clear();
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoRefundKey2Result result = modelnet::SwarmNoteNotNoRefundKey2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "ADMIN");
    BOOST_CHECK_EQUAL(err, "ADMIN");
}

BOOST_AUTO_TEST_CASE(want_move_is_held)
{
    modelnet::SwarmNotNoRefundKey2 note;
    note.admin_id = "admin-1";
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoRefundKey2Result result = modelnet::SwarmNoteNotNoRefundKey2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_is_noted)
{
    modelnet::SwarmNotNoRefundKey2 note;
    note.admin_id = "admin-1";
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoRefundKey2Result result = modelnet::SwarmNoteNotNoRefundKey2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
