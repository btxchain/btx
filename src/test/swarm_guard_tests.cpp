// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_guard.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <set>

BOOST_FIXTURE_TEST_SUITE(swarm_guard_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(quarantine_a_bad_page_and_a_peer_path_do_not_move_bytes)
{
    std::set<std::string> blocked{"bad"};
    std::string err;
    BOOST_CHECK(!modelnet::SwarmOfferWork(blocked, "bad", err));
    BOOST_CHECK_EQUAL(err, "QUARANTINE");
    BOOST_CHECK(modelnet::SwarmOfferWork(blocked, "ok", err));

    const modelnet::SwarmRecompute again = modelnet::SwarmRecomputeAfter(true, false, false, false, err);
    BOOST_CHECK(again.recompute);
    BOOST_CHECK(!again.bytes_moved);
    BOOST_CHECK_EQUAL(again.code, "RECOMPUTE");
    const modelnet::SwarmRecompute held = modelnet::SwarmRecomputeAfter(false, false, false, false, err);
    BOOST_CHECK(!held.recompute);
    BOOST_CHECK(!held.bytes_moved);

    int64_t bytes = 0;
    BOOST_REQUIRE(modelnet::SwarmKvBytes(2, 4, 8, 16, 2, bytes, err));
    BOOST_CHECK_EQUAL(bytes, 2 * 2 * 4 * 8 * 16 * 2);
    BOOST_CHECK(!modelnet::SwarmKvBytes(0, 4, 8, 16, 2, bytes, err));
    BOOST_CHECK_EQUAL(err, "KV_GEOMETRY");

    BOOST_CHECK(!modelnet::SwarmCacheStandsAlone(false, false, true, false, false, err));
    BOOST_CHECK_EQUAL(err, "CACHE_ASSURANCE");
    BOOST_CHECK(modelnet::SwarmCacheStandsAlone(false, false, false, false, false, err));

    BOOST_CHECK(!modelnet::SwarmAcceptStorageKey("../piece", err));
    BOOST_CHECK_EQUAL(err, "PEER_PATH");
    BOOST_CHECK(modelnet::SwarmAcceptStorageKey("ab", err));

    BOOST_CHECK(!modelnet::SwarmManifestPieceCount(16385, err));
    BOOST_CHECK_EQUAL(err, "MANIFEST_CAP");
    BOOST_CHECK(modelnet::SwarmManifestPieceCount(16384, err));

    bool measured = true;
    BOOST_CHECK(!modelnet::SwarmRecordMeasurement(true, false, measured, err));
    BOOST_CHECK(!measured);
    BOOST_CHECK_EQUAL(err, "MEASUREMENT");
    BOOST_REQUIRE(modelnet::SwarmRecordMeasurement(true, true, measured, err));
    BOOST_CHECK(measured);
}

BOOST_AUTO_TEST_SUITE_END()
