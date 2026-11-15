// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_poolepoch.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_poolepoch_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_pool_or_epoch_below_one_is_epoch)
{
    std::string err = "prior";
    modelnet::SwarmPoolEpoch missing;
    missing.stored_epoch = 2;
    missing.next_epoch = 1;
    missing.want_move_obligations = true;
    const modelnet::SwarmPoolEpochResult no_id = modelnet::SwarmNotePoolEpoch(missing, err);
    BOOST_CHECK(!no_id.moved);
    BOOST_CHECK_EQUAL(no_id.code, "EPOCH");
    BOOST_CHECK_EQUAL(err, "EPOCH");

    modelnet::SwarmPoolEpoch stored_zero;
    stored_zero.pool_id = "pool-a";
    stored_zero.stored_epoch = 0;
    stored_zero.next_epoch = 1;
    stored_zero.want_move_obligations = true;
    const modelnet::SwarmPoolEpochResult zero_stored = modelnet::SwarmNotePoolEpoch(stored_zero, err);
    BOOST_CHECK(!zero_stored.moved);
    BOOST_CHECK_EQUAL(zero_stored.code, "EPOCH");
    BOOST_CHECK_EQUAL(err, "EPOCH");

    modelnet::SwarmPoolEpoch stored_negative;
    stored_negative.pool_id = "pool-a";
    stored_negative.stored_epoch = -1;
    stored_negative.next_epoch = 4;
    const modelnet::SwarmPoolEpochResult negative_stored = modelnet::SwarmNotePoolEpoch(stored_negative, err);
    BOOST_CHECK(!negative_stored.moved);
    BOOST_CHECK_EQUAL(negative_stored.code, "EPOCH");
    BOOST_CHECK_EQUAL(err, "EPOCH");

    modelnet::SwarmPoolEpoch next_zero;
    next_zero.pool_id = "pool-a";
    next_zero.stored_epoch = 3;
    next_zero.next_epoch = 0;
    next_zero.want_move_obligations = true;
    const modelnet::SwarmPoolEpochResult zero_next = modelnet::SwarmNotePoolEpoch(next_zero, err);
    BOOST_CHECK(!zero_next.moved);
    BOOST_CHECK_EQUAL(zero_next.code, "EPOCH");
    BOOST_CHECK_EQUAL(err, "EPOCH");

    modelnet::SwarmPoolEpoch next_negative;
    next_negative.pool_id = "pool-a";
    next_negative.stored_epoch = 3;
    next_negative.next_epoch = -2;
    const modelnet::SwarmPoolEpochResult negative_next = modelnet::SwarmNotePoolEpoch(next_negative, err);
    BOOST_CHECK(!negative_next.moved);
    BOOST_CHECK_EQUAL(negative_next.code, "EPOCH");
    BOOST_CHECK_EQUAL(err, "EPOCH");
}

BOOST_AUTO_TEST_CASE(next_epoch_at_or_below_stored_is_stale_even_when_move_is_requested)
{
    std::string err = "prior";
    modelnet::SwarmPoolEpoch lower;
    lower.pool_id = "pool-a";
    lower.stored_epoch = 5;
    lower.next_epoch = 4;
    lower.want_move_obligations = true;
    const modelnet::SwarmPoolEpochResult behind = modelnet::SwarmNotePoolEpoch(lower, err);
    BOOST_CHECK(!behind.moved);
    BOOST_CHECK_EQUAL(behind.code, "STALE");
    BOOST_CHECK_EQUAL(err, "STALE");

    modelnet::SwarmPoolEpoch same;
    same.pool_id = "pool-a";
    same.stored_epoch = 5;
    same.next_epoch = 5;
    same.want_move_obligations = true;
    const modelnet::SwarmPoolEpochResult equal = modelnet::SwarmNotePoolEpoch(same, err);
    BOOST_CHECK(!equal.moved);
    BOOST_CHECK_EQUAL(equal.code, "STALE");
    BOOST_CHECK_EQUAL(err, "STALE");

    modelnet::SwarmPoolEpoch equal_without_move;
    equal_without_move.pool_id = "pool-a";
    equal_without_move.stored_epoch = 5;
    equal_without_move.next_epoch = 5;
    equal_without_move.want_move_obligations = false;
    const modelnet::SwarmPoolEpochResult held = modelnet::SwarmNotePoolEpoch(equal_without_move, err);
    BOOST_CHECK(!held.moved);
    BOOST_CHECK_EQUAL(held.code, "STALE");
    BOOST_CHECK_EQUAL(err, "STALE");
}

BOOST_AUTO_TEST_CASE(higher_epoch_does_not_move_old_obligations)
{
    std::string err = "prior";
    modelnet::SwarmPoolEpoch note;
    note.pool_id = "pool-a";
    note.stored_epoch = 1;
    note.next_epoch = 2;
    note.want_move_obligations = true;
    const modelnet::SwarmPoolEpochResult result = modelnet::SwarmNotePoolEpoch(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "IMMUTABLE");
    BOOST_CHECK_EQUAL(err, "IMMUTABLE");

    modelnet::SwarmPoolEpoch later;
    later.pool_id = "pool-a";
    later.stored_epoch = 5;
    later.next_epoch = 9;
    later.want_move_obligations = true;
    const modelnet::SwarmPoolEpochResult ahead = modelnet::SwarmNotePoolEpoch(later, err);
    BOOST_CHECK(!ahead.moved);
    BOOST_CHECK_EQUAL(ahead.code, "IMMUTABLE");
    BOOST_CHECK_EQUAL(err, "IMMUTABLE");
}

BOOST_AUTO_TEST_CASE(noted_clears_err_and_does_not_move)
{
    std::string err = "prior";
    modelnet::SwarmPoolEpoch note;
    note.pool_id = "pool-a";
    note.stored_epoch = 1;
    note.next_epoch = 2;
    note.want_move_obligations = false;
    const modelnet::SwarmPoolEpochResult result = modelnet::SwarmNotePoolEpoch(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
