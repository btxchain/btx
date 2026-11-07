// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_trajstore.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_trajstore_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_item_is_item)
{
    modelnet::SwarmTrajStore item;
    item.want_store = true;
    std::string err = "prior";
    const modelnet::SwarmTrajStoreResult result = modelnet::SwarmNoteTrajStore(item, err);
    BOOST_CHECK(!result.stored);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "ITEM");
    BOOST_CHECK_EQUAL(err, "ITEM");
}

BOOST_AUTO_TEST_CASE(want_store_is_held)
{
    modelnet::SwarmTrajStore item;
    item.item_id = "item-a";
    item.want_store = true;
    std::string err = "prior";
    const modelnet::SwarmTrajStoreResult result = modelnet::SwarmNoteTrajStore(item, err);
    BOOST_CHECK(!result.stored);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_store_false_is_noted)
{
    modelnet::SwarmTrajStore item;
    item.item_id = "item-a";
    item.want_store = false;
    std::string err = "prior";
    const modelnet::SwarmTrajStoreResult result = modelnet::SwarmNoteTrajStore(item, err);
    BOOST_CHECK(!result.stored);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
