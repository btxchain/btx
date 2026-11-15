// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_readfence/readfence.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_readfence_accept_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(non_positive_or_oversized_is_truncated)
{
    modelnet::SwarmReadFence fence;
    std::string err = "prior";

    BOOST_REQUIRE(!fence.accepted());
    BOOST_REQUIRE_EQUAL(fence.accepted_size(), 0);

    BOOST_REQUIRE(!fence.Accept(0, err));
    BOOST_REQUIRE_EQUAL(err, "TRUNCATED");
    BOOST_REQUIRE(!fence.accepted());
    BOOST_REQUIRE_EQUAL(fence.accepted_size(), 0);
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
    BOOST_REQUIRE(!fence.cuda_buffer());

    err = "prior";
    BOOST_REQUIRE(!fence.Accept(-1, err));
    BOOST_REQUIRE_EQUAL(err, "TRUNCATED");
    BOOST_REQUIRE(!fence.accepted());
    BOOST_REQUIRE_EQUAL(fence.accepted_size(), 0);

    err = "prior";
    BOOST_REQUIRE(!fence.Accept(33554433, err));
    BOOST_REQUIRE_EQUAL(err, "TRUNCATED");
    BOOST_REQUIRE(!fence.accepted());
    BOOST_REQUIRE_EQUAL(fence.accepted_size(), 0);
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
    BOOST_REQUIRE(!fence.cuda_buffer());
    BOOST_REQUIRE(!fence.process_started());
}

BOOST_AUTO_TEST_CASE(size_inside_the_cap_is_stored)
{
    modelnet::SwarmReadFence fence;
    std::string err = "prior";

    BOOST_REQUIRE(fence.Accept(1, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(fence.accepted());
    BOOST_REQUIRE_EQUAL(fence.accepted_size(), 1);
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
    BOOST_REQUIRE(!fence.cuda_buffer());

    BOOST_REQUIRE(fence.Accept(33554432, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(fence.accepted());
    BOOST_REQUIRE_EQUAL(fence.accepted_size(), 33554432);
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
    BOOST_REQUIRE(!fence.cuda_buffer());
    BOOST_REQUIRE(!fence.process_started());
}

BOOST_AUTO_TEST_CASE(truncated_accept_leaves_the_stored_size)
{
    modelnet::SwarmReadFence fence;
    std::string err = "prior";

    BOOST_REQUIRE(fence.Accept(64, err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!fence.Accept(0, err));
    BOOST_REQUIRE_EQUAL(err, "TRUNCATED");
    BOOST_REQUIRE(fence.accepted());
    BOOST_REQUIRE_EQUAL(fence.accepted_size(), 64);

    err = "prior";
    BOOST_REQUIRE(!fence.Accept(33554433, err));
    BOOST_REQUIRE_EQUAL(err, "TRUNCATED");
    BOOST_REQUIRE_EQUAL(fence.accepted_size(), 64);

    err = "prior";
    BOOST_REQUIRE(!fence.Accept(static_cast<int64_t>(-5), err));
    BOOST_REQUIRE_EQUAL(err, "TRUNCATED");
    BOOST_REQUIRE_EQUAL(fence.accepted_size(), 64);
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
    BOOST_REQUIRE(!fence.cuda_buffer());
}

BOOST_AUTO_TEST_SUITE_END()
