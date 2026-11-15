// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_island.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_island_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(matching_update_within_the_limit_is_accepted)
{
    modelnet::SwarmIslandUpdate update;
    update.island_id = "island-a";
    update.recipe = "recipe-v1";
    update.base_checkpoint = "ckpt-1";
    update.update_digest = "digest-1";
    update.staleness = 2;
    update.bytes_averaged = true;
    std::string err = "prior";
    BOOST_CHECK(modelnet::SwarmAcceptIslandUpdate(update, "recipe-v1", "ckpt-1", 5, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!update.bytes_averaged);
}

BOOST_AUTO_TEST_CASE(staleness_equal_to_the_limit_is_accepted)
{
    modelnet::SwarmIslandUpdate update;
    update.island_id = "island-a";
    update.recipe = "recipe-v1";
    update.base_checkpoint = "ckpt-1";
    update.update_digest = "digest-1";
    update.staleness = 5;
    update.bytes_averaged = true;
    std::string err = "prior";
    BOOST_CHECK(modelnet::SwarmAcceptIslandUpdate(update, "recipe-v1", "ckpt-1", 5, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!update.bytes_averaged);
}

BOOST_AUTO_TEST_CASE(staleness_one_past_the_limit_is_stale)
{
    modelnet::SwarmIslandUpdate update;
    update.island_id = "island-a";
    update.recipe = "recipe-v1";
    update.base_checkpoint = "ckpt-1";
    update.update_digest = "digest-1";
    update.staleness = 6;
    std::string err;
    BOOST_CHECK(!modelnet::SwarmAcceptIslandUpdate(update, "recipe-v1", "ckpt-1", 5, err));
    BOOST_CHECK_EQUAL(err, "STALE_UPDATE");
    BOOST_CHECK(!update.bytes_averaged);
}

BOOST_AUTO_TEST_CASE(recipe_mismatch_is_incompatible)
{
    modelnet::SwarmIslandUpdate update;
    update.island_id = "island-a";
    update.recipe = "recipe-other";
    update.base_checkpoint = "ckpt-1";
    update.update_digest = "digest-1";
    update.staleness = 1;
    std::string err;
    BOOST_CHECK(!modelnet::SwarmAcceptIslandUpdate(update, "recipe-v1", "ckpt-1", 5, err));
    BOOST_CHECK_EQUAL(err, "INCOMPATIBLE");
    BOOST_CHECK(!update.bytes_averaged);
}

BOOST_AUTO_TEST_CASE(empty_digest_is_update)
{
    modelnet::SwarmIslandUpdate update;
    update.island_id = "island-a";
    update.recipe = "recipe-v1";
    update.base_checkpoint = "ckpt-1";
    update.update_digest.clear();
    update.staleness = 1;
    std::string err;
    BOOST_CHECK(!modelnet::SwarmAcceptIslandUpdate(update, "recipe-v1", "ckpt-1", 5, err));
    BOOST_CHECK_EQUAL(err, "UPDATE");
    BOOST_CHECK(!update.bytes_averaged);
}

BOOST_AUTO_TEST_SUITE_END()
