// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_staleisland.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_staleisland_tests, BasicTestingSetup)

static modelnet::SwarmStaleIsland NotedIsland()
{
    modelnet::SwarmStaleIsland island;
    island.island_id = "island-1";
    island.stale = false;
    island.want_admit = false;
    return island;
}

BOOST_AUTO_TEST_CASE(empty_island_is_island)
{
    modelnet::SwarmStaleIsland island = NotedIsland();
    island.island_id.clear();
    island.stale = false;
    island.want_admit = false;
    std::string err = "prior";
    const modelnet::SwarmStaleIslandResult result = modelnet::SwarmNoteStaleIsland(island, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "ISLAND");
    BOOST_CHECK_EQUAL(err, "ISLAND");
}

BOOST_AUTO_TEST_CASE(stale_want_admit_false_is_not_admitted)
{
    modelnet::SwarmStaleIsland island = NotedIsland();
    island.stale = true;
    island.want_admit = false;
    std::string err = "prior";
    const modelnet::SwarmStaleIslandResult result = modelnet::SwarmNoteStaleIsland(island, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "NOT_ADMITTED");
    BOOST_CHECK_EQUAL(err, "NOT_ADMITTED");
}

BOOST_AUTO_TEST_CASE(want_admit_stale_false_is_held)
{
    modelnet::SwarmStaleIsland island = NotedIsland();
    island.stale = false;
    island.want_admit = true;
    std::string err = "prior";
    const modelnet::SwarmStaleIslandResult result = modelnet::SwarmNoteStaleIsland(island, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(stale_false_want_admit_false_is_noted)
{
    modelnet::SwarmStaleIsland island = NotedIsland();
    island.stale = false;
    island.want_admit = false;
    std::string err = "prior";
    const modelnet::SwarmStaleIslandResult result = modelnet::SwarmNoteStaleIsland(island, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
