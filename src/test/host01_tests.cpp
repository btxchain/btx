// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/host01/host01.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(host01_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cpu_and_gpu_bind_refuses_loopback)
{
    modelnet::Host01 host;
    std::string err = "stale";

    BOOST_CHECK(!host.Ready(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(host.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!host.bound("cpu"));
    BOOST_CHECK(!host.bound("gpu"));

    BOOST_CHECK(!host.Bind("worker", "cpu-node", err));
    BOOST_CHECK_EQUAL(err, "ROLE");
    BOOST_CHECK(!host.bound("cpu"));
    BOOST_CHECK(!host.bound("gpu"));
    BOOST_CHECK(host.endpoint("cpu").empty());

    BOOST_CHECK(!host.Bind("cpu", "", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!host.bound("cpu"));

    const std::string scheme = std::string("mark") + "://" + std::string("token");
    BOOST_CHECK(!host.Bind("cpu", scheme, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!host.bound("cpu"));
    BOOST_CHECK(host.endpoint("cpu").empty());

    BOOST_CHECK(!host.Bind("cpu", "localhost", err));
    BOOST_CHECK_EQUAL(err, "LOOPBACK");
    BOOST_CHECK(!host.bound("cpu"));

    BOOST_CHECK(!host.Bind("gpu", "127.0.0.1", err));
    BOOST_CHECK_EQUAL(err, "LOOPBACK");
    BOOST_CHECK(!host.bound("gpu"));
    BOOST_CHECK_EQUAL(host.physical_hosts(), static_cast<int64_t>(1));

    BOOST_CHECK(host.Bind("cpu", "cpu-node", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(host.bound("cpu"));
    BOOST_CHECK_EQUAL(host.endpoint("cpu"), "cpu-node");
    BOOST_CHECK_EQUAL(host.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!host.Ready(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);

    BOOST_CHECK(!host.Bind("cpu", "cpu-other", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(host.endpoint("cpu"), "cpu-node");

    BOOST_CHECK(host.Bind("gpu", "gpu-node", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(host.bound("gpu"));
    BOOST_CHECK_EQUAL(host.endpoint("gpu"), "gpu-node");
    BOOST_CHECK(host.Ready(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(host.physical_hosts(), static_cast<int64_t>(2));

    BOOST_CHECK(!host.Bind("gpu", "gpu-other", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(host.endpoint("gpu"), "gpu-node");
    BOOST_CHECK_EQUAL(host.endpoint("cpu"), "cpu-node");

    BOOST_CHECK(!host.Bind("disk", "cpu-node", err));
    BOOST_CHECK_EQUAL(err, "ROLE");
    BOOST_CHECK(host.bound("cpu"));
    BOOST_CHECK(host.bound("gpu"));
    BOOST_CHECK_EQUAL(host.physical_hosts(), static_cast<int64_t>(2));

    BOOST_CHECK(!host.passed());
    BOOST_CHECK(!host.release_qualified());
    BOOST_CHECK(!host.gpu_passed());
    BOOST_CHECK(!host.windows_passed());
    BOOST_CHECK(!host.hardware_qualified());
    BOOST_CHECK_EQUAL(host.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
}

BOOST_AUTO_TEST_SUITE_END()
