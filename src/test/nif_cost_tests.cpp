// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_cost/nif_cost.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(nif_cost_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(mean_10_uncertainty_5_fits_15_not_14)
{
    modelnet::NifCost cost;
    std::string err = "stale";
    BOOST_CHECK_EQUAL(cost.mean_us("p"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(cost.uncertainty_us("p"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(cost.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!cost.hardware_qualified());

    BOOST_CHECK(cost.Estimate("p", static_cast<int64_t>(10), static_cast<int64_t>(5), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(cost.mean_us("p"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(cost.uncertainty_us("p"), static_cast<int64_t>(5));

    BOOST_CHECK(!cost.Accept("p", static_cast<int64_t>(14), err));
    BOOST_CHECK_EQUAL(err, "OVER");
    BOOST_CHECK(!cost.accepted("p"));
    BOOST_CHECK(!cost.placed("p"));
    BOOST_CHECK(!cost.Place("p", err));
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
    BOOST_CHECK(!cost.placed("p"));
    BOOST_CHECK_EQUAL(cost.mean_us("p"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(cost.uncertainty_us("p"), static_cast<int64_t>(5));

    BOOST_CHECK(cost.Accept("p", static_cast<int64_t>(15), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(cost.accepted("p"));
    BOOST_CHECK(!cost.placed("p"));
    BOOST_CHECK(!cost.hardware_qualified());
    BOOST_CHECK(cost.Place("p", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(cost.placed("p"));
    BOOST_CHECK(!cost.hardware_qualified());
    BOOST_CHECK(!cost.launched());
    BOOST_CHECK(!cost.gpu());
    BOOST_CHECK(!cost.broadcast());
    BOOST_CHECK_EQUAL(cost.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(cost.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(cost.physical_hosts(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_CASE(unqualified_device_stores_nothing)
{
    modelnet::NifCost cost;
    std::string err = "stale";
    BOOST_CHECK(!cost.Estimate("bare", static_cast<int64_t>(10), static_cast<int64_t>(5), false, err));
    BOOST_CHECK_EQUAL(err, "HARDWARE");
    BOOST_CHECK_EQUAL(cost.mean_us("bare"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(cost.uncertainty_us("bare"), static_cast<int64_t>(0));
    BOOST_CHECK(!cost.accepted("bare"));
    BOOST_CHECK(!cost.placed("bare"));
    BOOST_CHECK(!cost.Accept("bare", static_cast<int64_t>(15), err));
    BOOST_CHECK_EQUAL(err, "PEER");
    BOOST_CHECK(!cost.Place("bare", err));
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
    BOOST_CHECK(!cost.hardware_qualified());
    BOOST_CHECK_EQUAL(cost.physical_hosts(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_CASE(second_estimate_keeps_10_and_5)
{
    modelnet::NifCost cost;
    std::string err = "stale";
    BOOST_CHECK(cost.Estimate("p", static_cast<int64_t>(10), static_cast<int64_t>(5), true, err));
    BOOST_CHECK(!cost.Estimate("p", static_cast<int64_t>(1), static_cast<int64_t>(2), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(cost.mean_us("p"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(cost.uncertainty_us("p"), static_cast<int64_t>(5));

    BOOST_CHECK(cost.Estimate("q", static_cast<int64_t>(7), static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(cost.mean_us("p"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(cost.uncertainty_us("p"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(cost.mean_us("q"), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(cost.uncertainty_us("q"), static_cast<int64_t>(1));

    BOOST_CHECK(cost.Accept("p", static_cast<int64_t>(15), err));
    BOOST_CHECK(!cost.Accept("p", static_cast<int64_t>(14), err));
    BOOST_CHECK_EQUAL(err, "OVER");
    BOOST_CHECK(cost.accepted("p"));
    BOOST_CHECK(!cost.placed("p"));
    BOOST_CHECK_EQUAL(cost.mean_us("p"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(cost.uncertainty_us("p"), static_cast<int64_t>(5));
    BOOST_CHECK(!cost.hardware_qualified());
    BOOST_CHECK(!cost.launched());
    BOOST_CHECK(!cost.gpu());
    BOOST_CHECK(!cost.broadcast());
    BOOST_CHECK_EQUAL(cost.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(empty_peer_and_negative_uncertainty_store_nothing)
{
    modelnet::NifCost cost;
    std::string err = "stale";
    BOOST_CHECK(!cost.Estimate("", static_cast<int64_t>(10), static_cast<int64_t>(5), true, err));
    BOOST_CHECK_EQUAL(err, "PEER");
    BOOST_CHECK_EQUAL(cost.mean_us(""), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(cost.uncertainty_us(""), static_cast<int64_t>(0));

    BOOST_CHECK(!cost.Estimate("neg", static_cast<int64_t>(10), static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(cost.mean_us("neg"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(cost.uncertainty_us("neg"), static_cast<int64_t>(0));
    BOOST_CHECK(!cost.Accept("neg", static_cast<int64_t>(15), err));
    BOOST_CHECK_EQUAL(err, "PEER");
    BOOST_CHECK(!cost.Accept("missing", static_cast<int64_t>(15), err));
    BOOST_CHECK_EQUAL(err, "PEER");
    BOOST_CHECK(!cost.Place("missing", err));
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
    BOOST_CHECK(!cost.Place("", err));
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
    BOOST_CHECK(!cost.hardware_qualified());
    BOOST_CHECK_EQUAL(cost.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!cost.launched());
    BOOST_CHECK(!cost.gpu());
    BOOST_CHECK(!cost.broadcast());
    BOOST_CHECK_EQUAL(cost.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
