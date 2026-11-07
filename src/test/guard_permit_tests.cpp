// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/guard_permit/guard_permit.h>
#include <modelnet/guard_machine.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::GuardPermitEngine& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.process_present());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.process_present());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(guard_permit_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(one_execute_then_replay)
{
    modelnet::GuardPermitEngine eng;
    std::string err = "stale";
    modelnet::GuardPermit permit;
    const int64_t now = static_cast<int64_t>(1000000);
    BOOST_CHECK(eng.Prepare("observe", "fp", static_cast<uint64_t>(1), now, permit, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!permit.secret.empty());
    BOOST_CHECK(eng.Execute(permit.secret, now, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.process_present());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());

    BOOST_CHECK(!eng.Execute(permit.secret, now, err));
    BOOST_CHECK_EQUAL(err, "BTX035_REPLAY");
    BOOST_CHECK(!eng.Execute(permit.secret, now + static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, "BTX035_REPLAY");
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.process_present());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(pause_leaves_process_absent)
{
    modelnet::GuardPermitEngine eng;
    std::string err = "stale";
    modelnet::GuardPermit permit;
    const int64_t now = static_cast<int64_t>(2000000);
    BOOST_CHECK(eng.Prepare("observe", "fp", static_cast<uint64_t>(1), now, permit, err));
    BOOST_CHECK(err.empty());

    eng.Pause();
    BOOST_CHECK(!eng.Execute(permit.secret, now, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PAUSED");
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.process_present());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    eng.Resume();
    BOOST_CHECK(!eng.Execute(permit.secret, now, err));
    BOOST_CHECK_EQUAL(err, "BTX035_REVOKED");
    BOOST_REQUIRE(eng.Prepare("observe", "fp", static_cast<uint64_t>(2), now, permit, err));
    BOOST_CHECK(eng.Execute(permit.secret, now, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.Execute(permit.secret, now, err));
    BOOST_CHECK_EQUAL(err, "BTX035_REPLAY");
    BOOST_CHECK(!eng.process_present());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
