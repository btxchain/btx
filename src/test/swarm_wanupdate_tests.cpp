// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_wanupdate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_wanupdate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_island)
{
    modelnet::SwarmWanUpdate island;
    island.island_id.clear();
    island.want_exchange = false;
    std::string err;
    const modelnet::SwarmWanUpdateResult result = modelnet::SwarmNoteWanUpdate(island, err);
    BOOST_CHECK(!result.exchanged);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "ISLAND");
    BOOST_CHECK_EQUAL(err, "ISLAND");
}

BOOST_AUTO_TEST_CASE(want_exchange_held)
{
    modelnet::SwarmWanUpdate island;
    island.island_id = "island-a";
    island.want_exchange = true;
    std::string err;
    const modelnet::SwarmWanUpdateResult result = modelnet::SwarmNoteWanUpdate(island, err);
    BOOST_CHECK(!result.exchanged);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmWanUpdate island;
    island.island_id = "island-b";
    island.want_exchange = false;
    std::string err = "stale";
    const modelnet::SwarmWanUpdateResult result = modelnet::SwarmNoteWanUpdate(island, err);
    BOOST_CHECK(!result.exchanged);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
