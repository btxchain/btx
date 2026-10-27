// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_memorycap.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_memorycap_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmMemoryCap cap;
    cap.node_id.clear();
    cap.requested_mib = 512;
    cap.no_device = false;
    cap.want_raise = false;
    std::string err = "prior";
    const modelnet::SwarmMemoryCapResult result = modelnet::SwarmCapMemory(cap, err);
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.memory_mib, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(no_device_is_vram_zero)
{
    modelnet::SwarmMemoryCap cap;
    cap.node_id = "node-1";
    cap.requested_mib = 512;
    cap.no_device = true;
    cap.want_raise = false;
    std::string err = "prior";
    const modelnet::SwarmMemoryCapResult result = modelnet::SwarmCapMemory(cap, err);
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.memory_mib, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "VRAM_ZERO");
    BOOST_CHECK_EQUAL(err, "VRAM_ZERO");
}

BOOST_AUTO_TEST_CASE(requested_mib_above_cap_is_capped)
{
    modelnet::SwarmMemoryCap cap;
    cap.node_id = "node-1";
    cap.requested_mib = 32768;
    cap.no_device = false;
    cap.want_raise = false;
    std::string err = "prior";
    const modelnet::SwarmMemoryCapResult result = modelnet::SwarmCapMemory(cap, err);
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.memory_mib, int64_t{16384});
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(want_raise_in_range_is_held)
{
    modelnet::SwarmMemoryCap cap;
    cap.node_id = "node-1";
    cap.requested_mib = 512;
    cap.no_device = false;
    cap.want_raise = true;
    std::string err = "prior";
    const modelnet::SwarmMemoryCapResult result = modelnet::SwarmCapMemory(cap, err);
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.memory_mib, int64_t{512});
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(in_range_without_raise_is_noted)
{
    modelnet::SwarmMemoryCap cap;
    cap.node_id = "node-1";
    cap.requested_mib = 512;
    cap.no_device = false;
    cap.want_raise = false;
    std::string err = "prior";
    const modelnet::SwarmMemoryCapResult result = modelnet::SwarmCapMemory(cap, err);
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.memory_mib, int64_t{512});
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
