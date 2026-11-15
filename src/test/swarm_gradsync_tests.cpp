// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_gradsync.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_gradsync_tests, BasicTestingSetup)

static modelnet::SwarmGradSync NotedUpdate()
{
    modelnet::SwarmGradSync update;
    update.update_id = "update-1";
    update.want_sync = false;
    return update;
}

BOOST_AUTO_TEST_CASE(empty_update_is_update)
{
    modelnet::SwarmGradSync update = NotedUpdate();
    update.update_id.clear();
    update.want_sync = true;
    std::string err = "prior";
    const modelnet::SwarmGradSyncResult result = modelnet::SwarmNoteGradSync(update, err);
    BOOST_CHECK(!result.synced);
    BOOST_CHECK_EQUAL(result.bytes_moved, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "UPDATE");
    BOOST_CHECK_EQUAL(err, "UPDATE");
}

BOOST_AUTO_TEST_CASE(want_sync_true_is_held)
{
    modelnet::SwarmGradSync update = NotedUpdate();
    update.want_sync = true;
    std::string err = "prior";
    const modelnet::SwarmGradSyncResult result = modelnet::SwarmNoteGradSync(update, err);
    BOOST_CHECK(!result.synced);
    BOOST_CHECK_EQUAL(result.bytes_moved, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_sync_false_is_noted)
{
    modelnet::SwarmGradSync update = NotedUpdate();
    update.want_sync = false;
    std::string err = "prior";
    const modelnet::SwarmGradSyncResult result = modelnet::SwarmNoteGradSync(update, err);
    BOOST_CHECK(!result.synced);
    BOOST_CHECK_EQUAL(result.bytes_moved, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
