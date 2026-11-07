// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_refundheight.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_refundheight_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_lot_id_is_height)
{
    std::string err = "prior";
    modelnet::SwarmRefundHeightMove move;
    move.lot_id.clear();
    move.height = 10;
    move.admin = false;
    move.want_change_height = false;
    const modelnet::SwarmRefundHeightResult result = modelnet::SwarmNoteRefundHeight(move, err);
    BOOST_CHECK(!result.changed);
    BOOST_CHECK_EQUAL(result.code, "HEIGHT");
    BOOST_CHECK_EQUAL(err, "HEIGHT");
}

BOOST_AUTO_TEST_CASE(height_below_one_is_height)
{
    std::string err = "prior";
    modelnet::SwarmRefundHeightMove move;
    move.lot_id = "lot-1";
    move.height = 0;
    move.admin = false;
    move.want_change_height = false;
    const modelnet::SwarmRefundHeightResult zero = modelnet::SwarmNoteRefundHeight(move, err);
    BOOST_CHECK(!zero.changed);
    BOOST_CHECK_EQUAL(zero.code, "HEIGHT");
    BOOST_CHECK_EQUAL(err, "HEIGHT");

    move.height = -1;
    const modelnet::SwarmRefundHeightResult negative = modelnet::SwarmNoteRefundHeight(move, err);
    BOOST_CHECK(!negative.changed);
    BOOST_CHECK_EQUAL(negative.code, "HEIGHT");
    BOOST_CHECK_EQUAL(err, "HEIGHT");
}

BOOST_AUTO_TEST_CASE(height_wins_over_admin_and_want_change)
{
    std::string err = "prior";
    modelnet::SwarmRefundHeightMove move;
    move.lot_id.clear();
    move.height = 0;
    move.admin = true;
    move.want_change_height = true;
    const modelnet::SwarmRefundHeightResult result = modelnet::SwarmNoteRefundHeight(move, err);
    BOOST_CHECK(!result.changed);
    BOOST_CHECK_EQUAL(result.code, "HEIGHT");
    BOOST_CHECK_EQUAL(err, "HEIGHT");
}

BOOST_AUTO_TEST_CASE(want_change_height_is_immutable_even_when_admin)
{
    std::string err = "prior";
    modelnet::SwarmRefundHeightMove move;
    move.lot_id = "lot-1";
    move.height = 10;
    move.admin = true;
    move.want_change_height = true;
    const modelnet::SwarmRefundHeightResult result = modelnet::SwarmNoteRefundHeight(move, err);
    BOOST_CHECK(!result.changed);
    BOOST_CHECK_EQUAL(result.code, "IMMUTABLE");
    BOOST_CHECK_EQUAL(err, "IMMUTABLE");
}

BOOST_AUTO_TEST_CASE(admin_cannot_move_the_sponsor_refund_height)
{
    std::string err = "prior";
    modelnet::SwarmRefundHeightMove move;
    move.lot_id = "lot-1";
    move.height = 10;
    move.admin = true;
    move.want_change_height = false;
    const modelnet::SwarmRefundHeightResult result = modelnet::SwarmNoteRefundHeight(move, err);
    BOOST_CHECK(!result.changed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmRefundHeightMove move;
    move.lot_id = "lot-1";
    move.height = 1;
    move.admin = false;
    move.want_change_height = false;
    const modelnet::SwarmRefundHeightResult result = modelnet::SwarmNoteRefundHeight(move, err);
    BOOST_CHECK(!result.changed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
