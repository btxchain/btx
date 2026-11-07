// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_islandcur.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_islandcur_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_island_is_island)
{
    std::string err = "prior";
    modelnet::SwarmIslandCursor cursor;
    cursor.island_id.clear();
    cursor.recipe_id = "recipe-a";
    cursor.checkpoint_id = "ckpt-a";
    cursor.step = 3;
    cursor.cursor = 8;
    cursor.grant = true;
    cursor.want_run = true;
    const modelnet::SwarmIslandCursorResult result = modelnet::SwarmAdvanceIslandCursor(cursor, err);
    BOOST_CHECK_EQUAL(result.code, "ISLAND");
    BOOST_CHECK_EQUAL(err, "ISLAND");
    BOOST_CHECK_EQUAL(result.step, 0);
    BOOST_CHECK_EQUAL(result.cursor, 0);
    BOOST_CHECK(!result.running);
    BOOST_CHECK(!result.bytes_moved);
}

BOOST_AUTO_TEST_CASE(empty_recipe_with_checkpoint_is_recipe)
{
    std::string err = "prior";
    modelnet::SwarmIslandCursor cursor;
    cursor.island_id = "island-a";
    cursor.recipe_id.clear();
    cursor.checkpoint_id = "ckpt-a";
    cursor.step = 3;
    cursor.cursor = 8;
    cursor.grant = true;
    cursor.want_run = false;
    const modelnet::SwarmIslandCursorResult result = modelnet::SwarmAdvanceIslandCursor(cursor, err);
    BOOST_CHECK_EQUAL(result.code, "RECIPE");
    BOOST_CHECK_EQUAL(err, "RECIPE");
    BOOST_CHECK_EQUAL(result.step, 3);
    BOOST_CHECK_EQUAL(result.cursor, 8);
    BOOST_CHECK(!result.running);
    BOOST_CHECK(!result.bytes_moved);
}

BOOST_AUTO_TEST_CASE(grant_false_with_both_ids_is_dataset)
{
    std::string err = "prior";
    modelnet::SwarmIslandCursor cursor;
    cursor.island_id = "island-a";
    cursor.recipe_id = "recipe-a";
    cursor.checkpoint_id = "ckpt-a";
    cursor.step = 3;
    cursor.cursor = 8;
    cursor.grant = false;
    cursor.want_run = false;
    const modelnet::SwarmIslandCursorResult result = modelnet::SwarmAdvanceIslandCursor(cursor, err);
    BOOST_CHECK_EQUAL(result.code, "DATASET");
    BOOST_CHECK_EQUAL(err, "DATASET");
    BOOST_CHECK_EQUAL(result.step, 3);
    BOOST_CHECK_EQUAL(result.cursor, 8);
    BOOST_CHECK(!result.running);
    BOOST_CHECK(!result.bytes_moved);
}

BOOST_AUTO_TEST_CASE(want_run_with_grant_is_held)
{
    std::string err = "prior";
    modelnet::SwarmIslandCursor cursor;
    cursor.island_id = "island-a";
    cursor.recipe_id = "recipe-a";
    cursor.checkpoint_id = "ckpt-a";
    cursor.step = 3;
    cursor.cursor = 8;
    cursor.grant = true;
    cursor.want_run = true;
    const modelnet::SwarmIslandCursorResult result = modelnet::SwarmAdvanceIslandCursor(cursor, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK_EQUAL(result.step, 3);
    BOOST_CHECK_EQUAL(result.cursor, 8);
    BOOST_CHECK(!result.running);
    BOOST_CHECK(!result.bytes_moved);
}

BOOST_AUTO_TEST_CASE(noted_advances_step_and_cursor)
{
    std::string err = "prior";
    modelnet::SwarmIslandCursor cursor;
    cursor.island_id = "island-a";
    cursor.recipe_id = "recipe-a";
    cursor.checkpoint_id = "ckpt-a";
    cursor.step = 3;
    cursor.cursor = 8;
    cursor.grant = true;
    cursor.want_run = false;
    const modelnet::SwarmIslandCursorResult result = modelnet::SwarmAdvanceIslandCursor(cursor, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(result.step, 4);
    BOOST_CHECK_EQUAL(result.cursor, 9);
    BOOST_CHECK(!result.running);
    BOOST_CHECK(!result.bytes_moved);
}

BOOST_AUTO_TEST_SUITE_END()
