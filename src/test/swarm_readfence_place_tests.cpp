// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_readfence/readfence.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_readfence_place_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_page_or_family_stores_nothing)
{
    modelnet::SwarmReadFence fence;
    std::string err = "prior";

    BOOST_REQUIRE(!fence.Place("", "fam", err));
    BOOST_REQUIRE_EQUAL(err, "PAGE");
    BOOST_REQUIRE(!fence.placed(""));
    BOOST_REQUIRE(fence.family("").empty());
    BOOST_REQUIRE_EQUAL(fence.page_count(), 0u);
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
    BOOST_REQUIRE(!fence.cuda_buffer());
    BOOST_REQUIRE(!fence.process_started());

    err = "prior";
    BOOST_REQUIRE(!fence.Place("page", "", err));
    BOOST_REQUIRE_EQUAL(err, "PAGE");
    BOOST_REQUIRE(!fence.placed("page"));
    BOOST_REQUIRE_EQUAL(fence.page_count(), 0u);
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);

    err = "prior";
    BOOST_REQUIRE(!fence.Place("", "", err));
    BOOST_REQUIRE_EQUAL(err, "PAGE");
    BOOST_REQUIRE_EQUAL(fence.page_count(), 0u);
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(place_stores_family_and_moves_no_bytes)
{
    modelnet::SwarmReadFence fence;
    std::string err = "prior";

    BOOST_REQUIRE(fence.Place("page", "fam", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(fence.placed("page"));
    BOOST_REQUIRE_EQUAL(fence.family("page"), "fam");
    BOOST_REQUIRE_EQUAL(fence.page_count(), 1u);
    BOOST_REQUIRE(!fence.placed("other"));
    BOOST_REQUIRE(fence.family("other").empty());
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
    BOOST_REQUIRE(!fence.cuda_buffer());
    BOOST_REQUIRE(!fence.process_started());
    BOOST_REQUIRE(!fence.qualified());
    BOOST_REQUIRE(!fence.advertised());
    BOOST_REQUIRE(!fence.installed());
}

BOOST_AUTO_TEST_CASE(empty_place_does_not_clear_a_stored_page)
{
    modelnet::SwarmReadFence fence;
    std::string err = "prior";

    BOOST_REQUIRE(fence.Place("page", "fam", err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!fence.Place("page", "", err));
    BOOST_REQUIRE_EQUAL(err, "PAGE");
    BOOST_REQUIRE_EQUAL(fence.family("page"), "fam");
    BOOST_REQUIRE_EQUAL(fence.page_count(), 1u);

    err = "prior";
    BOOST_REQUIRE(!fence.Place("", "other", err));
    BOOST_REQUIRE_EQUAL(err, "PAGE");
    BOOST_REQUIRE_EQUAL(fence.family("page"), "fam");
    BOOST_REQUIRE_EQUAL(fence.page_count(), 1u);
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
    BOOST_REQUIRE(!fence.cuda_buffer());
}

BOOST_AUTO_TEST_CASE(second_place_replaces_only_the_family)
{
    modelnet::SwarmReadFence fence;
    std::string err = "prior";

    BOOST_REQUIRE(fence.Place("page", "fam", err));
    BOOST_REQUIRE(fence.Place("page", "next", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(fence.family("page"), "next");
    BOOST_REQUIRE_EQUAL(fence.page_count(), 1u);
    BOOST_REQUIRE(fence.placed("page"));

    BOOST_REQUIRE(fence.Place("other", "fam", err));
    BOOST_REQUIRE_EQUAL(fence.page_count(), 2u);
    BOOST_REQUIRE_EQUAL(fence.family("other"), "fam");
    BOOST_REQUIRE_EQUAL(fence.family("page"), "next");
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
    BOOST_REQUIRE(!fence.cuda_buffer());
}

BOOST_AUTO_TEST_SUITE_END()
