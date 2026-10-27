// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cachepair/swarm_cachepair.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_cachepair_share_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(one_member_is_alone_and_records_nothing)
{
    modelnet::SwarmCachePair plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Place("page-a", "mem-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.member_count("page-a") == 1);

    err = "prior";
    BOOST_REQUIRE(!plane.Share("page-a", err));
    BOOST_REQUIRE_EQUAL(err, "ALONE");
    BOOST_REQUIRE(!plane.shared("page-a"));
    BOOST_REQUIRE(plane.share_count() == 0);
    BOOST_REQUIRE(plane.shared_members("page-a").empty());
    BOOST_REQUIRE(plane.placed("page-a", "mem-a"));
    BOOST_REQUIRE(plane.member_count("page-a") == 1);

    err = "prior";
    BOOST_REQUIRE(!plane.Place("page-a", "mem-a", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    err = "prior";
    BOOST_REQUIRE(!plane.Share("page-a", err));
    BOOST_REQUIRE_EQUAL(err, "ALONE");
    BOOST_REQUIRE(plane.share_count() == 0);
    BOOST_REQUIRE(plane.member_count("page-a") == 1);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.cuda_buffer());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(empty_and_unknown_page_are_page)
{
    modelnet::SwarmCachePair plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Share("", err));
    BOOST_REQUIRE_EQUAL(err, "PAGE");
    BOOST_REQUIRE(!plane.shared(""));
    BOOST_REQUIRE(plane.share_count() == 0);
    BOOST_REQUIRE(plane.page_count() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Share("missing", err));
    BOOST_REQUIRE_EQUAL(err, "PAGE");
    BOOST_REQUIRE(!plane.shared("missing"));
    BOOST_REQUIRE(plane.share_count() == 0);
    BOOST_REQUIRE(plane.shared_members("missing").empty());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.cuda_buffer());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(two_members_record_one_share_and_second_is_replay)
{
    modelnet::SwarmCachePair plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Place("page-a", "mem-b", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.Place("page-a", "mem-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.member_count("page-a") == 2);
    BOOST_REQUIRE(!plane.shared("page-a"));

    err = "prior";
    BOOST_REQUIRE(plane.Share("page-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.shared("page-a"));
    BOOST_REQUIRE(plane.share_count() == 1);
    const std::vector<std::string> recorded = plane.shared_members("page-a");
    BOOST_REQUIRE(recorded.size() == 2);
    BOOST_REQUIRE_EQUAL(recorded.at(0), "mem-a");
    BOOST_REQUIRE_EQUAL(recorded.at(1), "mem-b");
    BOOST_REQUIRE(plane.placed("page-a", "mem-a"));
    BOOST_REQUIRE(plane.placed("page-a", "mem-b"));
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.cuda_buffer());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Share("page-a", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.share_count() == 1);
    BOOST_REQUIRE(plane.shared_members("page-a").size() == 2);

    err = "prior";
    BOOST_REQUIRE(!plane.Share("page-a", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.share_count() == 1);
    BOOST_REQUIRE_EQUAL(plane.shared_members("page-a").at(0), "mem-a");
    BOOST_REQUIRE_EQUAL(plane.shared_members("page-a").at(1), "mem-b");

    err = "prior";
    BOOST_REQUIRE(plane.Place("page-a", "mem-c", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.member_count("page-a") == 3);
    err = "prior";
    BOOST_REQUIRE(!plane.Share("page-a", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.share_count() == 1);
    BOOST_REQUIRE(plane.shared_members("page-a").size() == 2);
    BOOST_REQUIRE(plane.placed("page-a", "mem-c"));
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.cuda_buffer());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(each_page_records_its_own_share)
{
    modelnet::SwarmCachePair plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Place("page-a", "mem-a", err));
    BOOST_REQUIRE(plane.Place("page-a", "mem-b", err));
    BOOST_REQUIRE(plane.Place("page-b", "mem-a", err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(plane.Share("page-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.share_count() == 1);
    BOOST_REQUIRE(plane.shared("page-a"));

    err = "prior";
    BOOST_REQUIRE(!plane.Share("page-b", err));
    BOOST_REQUIRE_EQUAL(err, "ALONE");
    BOOST_REQUIRE(!plane.shared("page-b"));
    BOOST_REQUIRE(plane.share_count() == 1);
    BOOST_REQUIRE(plane.shared("page-a"));

    err = "prior";
    BOOST_REQUIRE(plane.Place("page-b", "mem-b", err));
    BOOST_REQUIRE(err.empty());
    err = "prior";
    BOOST_REQUIRE(plane.Share("page-b", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.shared("page-b"));
    BOOST_REQUIRE(plane.share_count() == 2);
    BOOST_REQUIRE(plane.shared_members("page-b").size() == 2);

    err = "prior";
    BOOST_REQUIRE(!plane.Share("page-a", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.share_count() == 2);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.cuda_buffer());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
