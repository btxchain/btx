// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_refundkey.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_refundkey_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_lot_id_is_refund)
{
    std::string err = "prior";
    modelnet::SwarmRefundKeyMove move;
    move.lot_id.clear();
    move.admin = false;
    move.want_move_refund_key = false;
    const modelnet::SwarmRefundKeyResult result = modelnet::SwarmNoteRefundKey(move, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "REFUND");
    BOOST_CHECK_EQUAL(err, "REFUND");
}

BOOST_AUTO_TEST_CASE(empty_lot_id_wins_over_admin_and_want_move)
{
    std::string err = "prior";
    modelnet::SwarmRefundKeyMove move;
    move.lot_id.clear();
    move.admin = true;
    move.want_move_refund_key = true;
    const modelnet::SwarmRefundKeyResult result = modelnet::SwarmNoteRefundKey(move, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "REFUND");
    BOOST_CHECK_EQUAL(err, "REFUND");
}

BOOST_AUTO_TEST_CASE(want_move_refund_key_is_immutable_even_when_admin)
{
    std::string err = "prior";
    modelnet::SwarmRefundKeyMove move;
    move.lot_id = "lot-1";
    move.admin = true;
    move.want_move_refund_key = true;
    const modelnet::SwarmRefundKeyResult result = modelnet::SwarmNoteRefundKey(move, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "IMMUTABLE");
    BOOST_CHECK_EQUAL(err, "IMMUTABLE");
}

BOOST_AUTO_TEST_CASE(admin_cannot_move_the_sponsor_refund_key)
{
    std::string err = "prior";
    modelnet::SwarmRefundKeyMove move;
    move.lot_id = "lot-1";
    move.admin = true;
    move.want_move_refund_key = false;
    const modelnet::SwarmRefundKeyResult result = modelnet::SwarmNoteRefundKey(move, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmRefundKeyMove move;
    move.lot_id = "lot-1";
    move.admin = false;
    move.want_move_refund_key = false;
    const modelnet::SwarmRefundKeyResult result = modelnet::SwarmNoteRefundKey(move, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
