// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_distillrec.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_distillrec_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(record_stores_the_child)
{
    modelnet::SwarmDistillRec rec;
    BOOST_CHECK(!rec.Has("child-a"));

    std::string err = "prior";
    BOOST_CHECK(!rec.Record("", "teacher-a", "digest-a", err));
    BOOST_CHECK_EQUAL(err, "DISTILL");
    BOOST_CHECK(!rec.Has(""));

    err = "prior";
    BOOST_CHECK(!rec.Record("child-a", "", "digest-a", err));
    BOOST_CHECK_EQUAL(err, "DISTILL");
    BOOST_CHECK(!rec.Has("child-a"));

    err = "prior";
    BOOST_CHECK(!rec.Record("child-a", "teacher-a", "", err));
    BOOST_CHECK_EQUAL(err, "DISTILL");
    BOOST_CHECK(!rec.Has("child-a"));

    err = "prior";
    BOOST_REQUIRE(rec.Record("child-a", "teacher-a", "digest-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(rec.Has("child-a"));
    BOOST_CHECK(!rec.Has("teacher-a"));

    err = "prior";
    BOOST_CHECK(!rec.Record("child-a", "teacher-b", "digest-b", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(rec.Has("child-a"));
    BOOST_CHECK(!rec.Has("teacher-b"));

    err = "prior";
    BOOST_REQUIRE(rec.Record("child-b", "teacher-b", "digest-b", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(rec.Has("child-a"));
    BOOST_CHECK(rec.Has("child-b"));
}

BOOST_AUTO_TEST_CASE(self_is_refused)
{
    modelnet::SwarmDistillRec rec;
    std::string err = "prior";
    BOOST_CHECK(!rec.Record("same", "same", "digest-a", err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK(!rec.Has("same"));

    err = "prior";
    BOOST_REQUIRE(rec.Record("child-a", "teacher-a", "digest-a", err));
    BOOST_CHECK(err.empty());

    err = "prior";
    BOOST_CHECK(!rec.Record("child-a", "child-a", "digest-b", err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK(rec.Has("child-a"));
    BOOST_CHECK(!rec.Has("teacher-a"));
}

BOOST_AUTO_TEST_CASE(merge_is_refused_and_leaves_the_record)
{
    modelnet::SwarmDistillRec rec;
    std::string err = "prior";
    BOOST_REQUIRE(rec.Record("child-a", "teacher-a", "digest-a", err));
    BOOST_REQUIRE(rec.Record("child-b", "teacher-b", "digest-b", err));
    BOOST_CHECK(rec.Has("child-a"));
    BOOST_CHECK(rec.Has("child-b"));

    err = "prior";
    BOOST_CHECK(!rec.Merge("child-a", "child-b", err));
    BOOST_CHECK_EQUAL(err, "NOT_MERGED");
    BOOST_CHECK(rec.Has("child-a"));
    BOOST_CHECK(rec.Has("child-b"));
    BOOST_CHECK(!rec.Has("teacher-a"));
    BOOST_CHECK(!rec.Has("teacher-b"));

    err = "prior";
    BOOST_CHECK(!rec.Merge("", "", err));
    BOOST_CHECK_EQUAL(err, "NOT_MERGED");
    BOOST_CHECK(rec.Has("child-a"));
    BOOST_CHECK(rec.Has("child-b"));
    BOOST_CHECK(!rec.Has(""));

    err = "prior";
    BOOST_CHECK(!rec.Record("child-a", "teacher-c", "digest-c", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(rec.Has("child-a"));
    BOOST_CHECK(rec.Has("child-b"));
}

BOOST_AUTO_TEST_SUITE_END()
