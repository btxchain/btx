// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/fleet_rollout/fleet_rollout.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::FleetRollout& roll)
{
    std::string err;
    BOOST_CHECK(!roll.launched());
    BOOST_CHECK(!roll.gpu());
    BOOST_CHECK(!roll.broadcast());
    BOOST_CHECK(!roll.qualified());
    BOOST_CHECK(!roll.release_qualified());
    BOOST_CHECK(!roll.hardware_qualified());
    BOOST_CHECK(!roll.passed());
    BOOST_CHECK_EQUAL(roll.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(roll.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(roll.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(roll.automatic_spend(), "0");
    BOOST_CHECK(!roll.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(roll.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!roll.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!roll.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!roll.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!roll.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(fleet_rollout_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(one_stored_rollout)
{
    modelnet::FleetRollout roll;
    std::string err;
    BOOST_CHECK(!roll.Start("roll-a", "complete", err));
    BOOST_CHECK_EQUAL(err, "STATE");
    BOOST_CHECK(!roll.stored("roll-a"));
    BOOST_CHECK(roll.text("roll-a").empty());
    BOOST_CHECK(roll.Start("roll-a", "staged-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(roll.stored("roll-a"));
    BOOST_CHECK_EQUAL(roll.text("roll-a"), "staged-a");
    BOOST_CHECK(!roll.Start("roll-a", "staged-a", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(roll.text("roll-a"), "staged-a");
    BOOST_CHECK(!roll.Start("roll-a", "staged-b", err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK_EQUAL(roll.text("roll-a"), "staged-a");
    BOOST_CHECK(!roll.Start("roll-a", "complete", err));
    BOOST_CHECK_EQUAL(err, "STATE");
    BOOST_CHECK(roll.stored("roll-a"));
    BOOST_CHECK_EQUAL(roll.text("roll-a"), "staged-a");
    BOOST_CHECK(!roll.launched());
    BOOST_CHECK(!roll.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    Idle(roll);
}

BOOST_AUTO_TEST_SUITE_END()
