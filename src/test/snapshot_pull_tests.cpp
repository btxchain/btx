// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/snapshot_pull/snapshot_pull.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::SnapshotPull& eng)
{
    std::string err;
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.logical_peers(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(snapshot_pull_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(matching_pull)
{
    modelnet::SnapshotPull eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Publish(static_cast<int64_t>(1), "", "body-a", err));
    BOOST_CHECK_EQUAL(err, modelnet::SNAPSHOT_PULL_FIELD);
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored(""));
    BOOST_CHECK(!eng.Publish(static_cast<int64_t>(1), "digest-a", "", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("digest-a"));
    BOOST_CHECK(!eng.Publish(static_cast<int64_t>(0), "digest-a", "body-a", err));
    BOOST_CHECK_EQUAL(err, modelnet::SNAPSHOT_PULL_SEQUENCE);
    BOOST_CHECK_EQUAL(err, "SEQUENCE");
    BOOST_CHECK(!eng.stored("digest-a"));
    BOOST_CHECK_EQUAL(eng.sequence("digest-a"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.pulled(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Pull(static_cast<int64_t>(1), "digest-a", err));
    BOOST_CHECK_EQUAL(err, modelnet::SNAPSHOT_PULL_MISMATCH);
    BOOST_CHECK_EQUAL(err, "MISMATCH");
    BOOST_CHECK_EQUAL(eng.pulled(), static_cast<int64_t>(0));

    BOOST_REQUIRE(eng.Publish(static_cast<int64_t>(1), "digest-a", "body-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("digest-a"));
    BOOST_CHECK_EQUAL(eng.body("digest-a"), "body-a");
    BOOST_CHECK_EQUAL(eng.sequence("digest-a"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    BOOST_REQUIRE(eng.Pull(static_cast<int64_t>(1), "digest-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.pulled(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.body("digest-a"), "body-a");
    BOOST_CHECK_EQUAL(eng.sequence("digest-a"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.logical_peers(), static_cast<int64_t>(2));
    Idle(eng);
    BOOST_CHECK_EQUAL(eng.pulled(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.body("digest-a"), "body-a");
}

BOOST_AUTO_TEST_CASE(replaced_body)
{
    modelnet::SnapshotPull eng;
    std::string err = "stale";
    BOOST_REQUIRE(eng.Publish(static_cast<int64_t>(1), "digest-a", "body-a", err));
    BOOST_CHECK(err.empty());

    BOOST_CHECK(eng.Replace("digest-a", "body-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.body("digest-a"), "body-a");

    BOOST_CHECK(!eng.Replace("digest-a", "body-b", err));
    BOOST_CHECK_EQUAL(err, modelnet::SNAPSHOT_PULL_MISMATCH);
    BOOST_CHECK_EQUAL(err, "MISMATCH");
    BOOST_CHECK_EQUAL(eng.body("digest-a"), "body-a");
    BOOST_CHECK_EQUAL(eng.sequence("digest-a"), static_cast<int64_t>(1));
    BOOST_CHECK(eng.stored("digest-a"));

    BOOST_CHECK(!eng.Publish(static_cast<int64_t>(2), "digest-a", "body-b", err));
    BOOST_CHECK_EQUAL(err, "MISMATCH");
    BOOST_CHECK_EQUAL(eng.body("digest-a"), "body-a");
    BOOST_CHECK_EQUAL(eng.sequence("digest-a"), static_cast<int64_t>(1));

    BOOST_CHECK(!eng.Replace("digest-b", "body-b", err));
    BOOST_CHECK_EQUAL(err, "MISMATCH");
    BOOST_CHECK(!eng.stored("digest-b"));
    BOOST_CHECK(eng.body("digest-b").empty());

    BOOST_REQUIRE(eng.Pull(static_cast<int64_t>(1), "digest-a", err));
    BOOST_CHECK_EQUAL(eng.pulled(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.body("digest-a"), "body-a");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(lower_sequence)
{
    modelnet::SnapshotPull eng;
    std::string err = "stale";
    BOOST_REQUIRE(eng.Publish(static_cast<int64_t>(2), "digest-a", "body-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.sequence("digest-a"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.pulled(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Pull(static_cast<int64_t>(1), "digest-a", err));
    BOOST_CHECK_EQUAL(err, modelnet::SNAPSHOT_PULL_ROLLBACK);
    BOOST_CHECK_EQUAL(err, "ROLLBACK");
    BOOST_CHECK_EQUAL(eng.body("digest-a"), "body-a");
    BOOST_CHECK_EQUAL(eng.sequence("digest-a"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.pulled(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Publish(static_cast<int64_t>(1), "digest-a", "body-a", err));
    BOOST_CHECK_EQUAL(err, "ROLLBACK");
    BOOST_CHECK_EQUAL(eng.body("digest-a"), "body-a");
    BOOST_CHECK_EQUAL(eng.sequence("digest-a"), static_cast<int64_t>(2));

    BOOST_REQUIRE(eng.Pull(static_cast<int64_t>(2), "digest-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.pulled(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.body("digest-a"), "body-a");
    BOOST_CHECK_EQUAL(eng.sequence("digest-a"), static_cast<int64_t>(2));

    BOOST_REQUIRE(eng.Publish(static_cast<int64_t>(4), "digest-a", "body-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.body("digest-a"), "body-a");
    BOOST_CHECK_EQUAL(eng.sequence("digest-a"), static_cast<int64_t>(4));
    BOOST_CHECK(!eng.Pull(static_cast<int64_t>(3), "digest-a", err));
    BOOST_CHECK_EQUAL(err, "ROLLBACK");
    BOOST_CHECK_EQUAL(eng.body("digest-a"), "body-a");
    BOOST_CHECK_EQUAL(eng.sequence("digest-a"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.pulled(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(hosts_two)
{
    modelnet::SnapshotPull eng;
    std::string err = "stale";
    BOOST_REQUIRE(eng.Publish(static_cast<int64_t>(1), "digest-a", "body-a", err));
    BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.logical_peers(), static_cast<int64_t>(2));

    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, modelnet::SNAPSHOT_PULL_HOSTS);
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.logical_peers(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.body("digest-a"), "body-a");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.release_qualified());
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
