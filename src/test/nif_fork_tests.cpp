// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_fork/nif_fork.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(nif_fork_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(reserve_refusals_store_nothing)
{
    modelnet::NifFork fork;
    std::string err;
    BOOST_CHECK(!fork.Reserve("", static_cast<int64_t>(1), static_cast<int64_t>(1), static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "REQUEST");
    BOOST_CHECK(!fork.Reserve("b", static_cast<int64_t>(0), static_cast<int64_t>(1), static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK(!fork.Reserve("e", static_cast<int64_t>(1), static_cast<int64_t>(5), static_cast<int64_t>(5), err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK_EQUAL(fork.used(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(reserve_past_capacity_keeps_used)
{
    modelnet::NifFork fork;
    std::string err;
    BOOST_CHECK(fork.Reserve("a", static_cast<int64_t>(60), static_cast<int64_t>(1), static_cast<int64_t>(10), err));
    BOOST_CHECK_EQUAL(fork.used(), static_cast<int64_t>(60));
    BOOST_CHECK(!fork.Reserve("a", static_cast<int64_t>(1), static_cast<int64_t>(1), static_cast<int64_t>(10), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(fork.used(), static_cast<int64_t>(60));
    BOOST_CHECK(!fork.Reserve("b", static_cast<int64_t>(50), static_cast<int64_t>(1), static_cast<int64_t>(10), err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(fork.used(), static_cast<int64_t>(60));
}

BOOST_AUTO_TEST_CASE(pinned_release_does_not_free)
{
    modelnet::NifFork fork;
    std::string err;
    BOOST_CHECK(!fork.Pin("missing", static_cast<int64_t>(3), err));
    BOOST_CHECK_EQUAL(err, "REQUEST");
    BOOST_CHECK(fork.Reserve("job", static_cast<int64_t>(60), static_cast<int64_t>(1), static_cast<int64_t>(9), err));
    BOOST_CHECK(fork.Pin("job", static_cast<int64_t>(3), err));
    BOOST_CHECK(!fork.Release("job", err));
    BOOST_CHECK_EQUAL(err, "PINNED");
    BOOST_CHECK_EQUAL(fork.used(), static_cast<int64_t>(60));
    BOOST_CHECK(fork.Complete("job", static_cast<int64_t>(3), err));
    BOOST_CHECK(fork.Release("job", err));
    BOOST_CHECK_EQUAL(fork.used(), static_cast<int64_t>(0));
    BOOST_CHECK(!fork.Release("job", err));
    BOOST_CHECK_EQUAL(err, "REQUEST");
    BOOST_CHECK_EQUAL(fork.used(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(two_devices_are_hardware)
{
    modelnet::NifFork fork;
    std::string err;
    BOOST_CHECK(fork.Eligible(static_cast<int64_t>(1), static_cast<int64_t>(1), static_cast<int64_t>(50), static_cast<int64_t>(49), err));
    BOOST_CHECK(!fork.Eligible(static_cast<int64_t>(2), static_cast<int64_t>(1), static_cast<int64_t>(50), static_cast<int64_t>(49), err));
    BOOST_CHECK_EQUAL(err, "HARDWARE");
    BOOST_CHECK(!fork.Eligible(static_cast<int64_t>(1), static_cast<int64_t>(2), static_cast<int64_t>(50), static_cast<int64_t>(49), err));
    BOOST_CHECK_EQUAL(err, "HARDWARE");
    BOOST_CHECK(!fork.Eligible(static_cast<int64_t>(1), static_cast<int64_t>(1), static_cast<int64_t>(50), static_cast<int64_t>(50), err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK_EQUAL(fork.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!fork.gpu());
}

BOOST_AUTO_TEST_CASE(vendor_execute_is_absent)
{
    modelnet::NifFork fork;
    std::string err;
    BOOST_CHECK(!modelnet::NifDtEngineLinked("deepinfer"));
    BOOST_CHECK(!fork.ExecuteVendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(fork.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!fork.vendor_qualified());
    BOOST_CHECK(!fork.launched());
    BOOST_CHECK(!fork.gpu());
    BOOST_CHECK(!fork.broadcast());
    BOOST_CHECK_EQUAL(fork.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(fork.pin(), "774ce244b87cc0eb8d4b94ab9f5de2ab22049f01");
    BOOST_CHECK_EQUAL(fork.physical_hosts(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_SUITE_END()
