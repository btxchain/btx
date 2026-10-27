// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cachepair/swarm_cachepair.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_cachepair_place_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_page_stores_nothing)
{
    modelnet::SwarmCachePair plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Place("", "mem-a", err));
    BOOST_REQUIRE_EQUAL(err, "PAGE");
    BOOST_REQUIRE(!plane.placed("", "mem-a"));
    BOOST_REQUIRE(plane.member_count("") == 0);
    BOOST_REQUIRE(plane.page_count() == 0);
    BOOST_REQUIRE(plane.members("").empty());
    BOOST_REQUIRE(!plane.shared(""));
    BOOST_REQUIRE(plane.share_count() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Place("", "", err));
    BOOST_REQUIRE_EQUAL(err, "PAGE");
    BOOST_REQUIRE(!plane.placed("", ""));
    BOOST_REQUIRE(plane.page_count() == 0);
    BOOST_REQUIRE(plane.share_count() == 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.cuda_buffer());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(empty_member_stores_nothing)
{
    modelnet::SwarmCachePair plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Place("page-a", "", err));
    BOOST_REQUIRE_EQUAL(err, "MEMBER");
    BOOST_REQUIRE(!plane.placed("page-a", ""));
    BOOST_REQUIRE(!plane.placed("page-a", "mem-a"));
    BOOST_REQUIRE(plane.member_count("page-a") == 0);
    BOOST_REQUIRE(plane.page_count() == 0);
    BOOST_REQUIRE(plane.members("page-a").empty());
    BOOST_REQUIRE(!plane.shared("page-a"));

    err = "prior";
    BOOST_REQUIRE(!plane.Share("page-a", err));
    BOOST_REQUIRE_EQUAL(err, "PAGE");
    BOOST_REQUIRE(plane.share_count() == 0);
    BOOST_REQUIRE(plane.shared_members("page-a").empty());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.cuda_buffer());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(same_page_and_member_is_replay_and_keeps_first)
{
    modelnet::SwarmCachePair plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Place("page-a", "mem-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.placed("page-a", "mem-a"));
    BOOST_REQUIRE(plane.member_count("page-a") == 1);
    BOOST_REQUIRE(plane.page_count() == 1);
    BOOST_REQUIRE(!plane.shared("page-a"));

    err = "prior";
    BOOST_REQUIRE(!plane.Place("page-a", "mem-a", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.placed("page-a", "mem-a"));
    BOOST_REQUIRE(plane.member_count("page-a") == 1);
    BOOST_REQUIRE(plane.page_count() == 1);
    BOOST_REQUIRE(plane.members("page-a").size() == 1);
    BOOST_REQUIRE_EQUAL(plane.members("page-a").at(0), "mem-a");

    err = "prior";
    BOOST_REQUIRE(!plane.Place("page-a", "mem-a", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.member_count("page-a") == 1);

    err = "prior";
    BOOST_REQUIRE(plane.Place("page-a", "mem-b", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.placed("page-a", "mem-a"));
    BOOST_REQUIRE(plane.placed("page-a", "mem-b"));
    BOOST_REQUIRE(plane.member_count("page-a") == 2);

    err = "prior";
    BOOST_REQUIRE(!plane.Place("page-a", "mem-a", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.placed("page-a", "mem-b"));
    BOOST_REQUIRE(plane.member_count("page-a") == 2);
    BOOST_REQUIRE(plane.page_count() == 1);

    err = "prior";
    BOOST_REQUIRE(plane.Place("page-b", "mem-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.placed("page-b", "mem-a"));
    BOOST_REQUIRE(!plane.placed("page-b", "mem-b"));
    BOOST_REQUIRE(plane.page_count() == 2);
    BOOST_REQUIRE(plane.member_count("page-a") == 2);
    BOOST_REQUIRE(plane.member_count("page-b") == 1);
    BOOST_REQUIRE(plane.share_count() == 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.cuda_buffer());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
