// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cachepair/swarm_cachepair.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_cachepair_bytes_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(recorded_pair_moves_no_bytes_and_launches_nothing)
{
    modelnet::SwarmCachePair plane;
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.cuda_buffer());
    BOOST_REQUIRE(!plane.launched());

    std::string err = "prior";
    BOOST_REQUIRE(!plane.Place("", "mem-a", err));
    BOOST_REQUIRE_EQUAL(err, "PAGE");
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.cuda_buffer());
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.page_count() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Place("page-a", "", err));
    BOOST_REQUIRE_EQUAL(err, "MEMBER");
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.share_count() == 0);

    err = "prior";
    BOOST_REQUIRE(plane.Place("page-a", "mem-a", err));
    BOOST_REQUIRE(err.empty());
    err = "prior";
    BOOST_REQUIRE(!plane.Share("page-a", err));
    BOOST_REQUIRE_EQUAL(err, "ALONE");
    BOOST_REQUIRE(plane.share_count() == 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.cuda_buffer());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(plane.Place("page-a", "mem-b", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.member_count("page-a") == 2);
    err = "prior";
    BOOST_REQUIRE(plane.Share("page-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.shared("page-a"));
    BOOST_REQUIRE(plane.share_count() == 1);
    BOOST_REQUIRE(plane.shared_members("page-a").size() == 2);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.cuda_buffer());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Share("page-a", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.share_count() == 1);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.cuda_buffer());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Share("", err));
    BOOST_REQUIRE_EQUAL(err, "PAGE");
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.cuda_buffer());
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.share_count() == 1);
}

BOOST_AUTO_TEST_SUITE_END()
