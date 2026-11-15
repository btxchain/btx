// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_quorumgate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_quorumgate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_report_author_or_domain_is_report)
{
    modelnet::SwarmQuorumGate gate;
    std::string err = "prior";
    BOOST_CHECK(!gate.Submit("", "author-a", "domain-a", err));
    BOOST_CHECK_EQUAL(err, "REPORT");

    err = "prior";
    BOOST_CHECK(!gate.Submit("report-a", "", "domain-a", err));
    BOOST_CHECK_EQUAL(err, "REPORT");

    err = "prior";
    BOOST_CHECK(!gate.Submit("report-a", "author-a", "", err));
    BOOST_CHECK_EQUAL(err, "REPORT");

    err = "prior";
    BOOST_CHECK(!gate.Submit("", "", "", err));
    BOOST_CHECK_EQUAL(err, "REPORT");

    err = "prior";
    BOOST_CHECK(!gate.Open(err));
    BOOST_CHECK_EQUAL(err, "QUORUM");
}

BOOST_AUTO_TEST_CASE(duplicate_report_is_replay)
{
    modelnet::SwarmQuorumGate gate;
    std::string err = "prior";
    BOOST_REQUIRE(gate.Submit("report-a", "author-a", "domain-a", err));
    BOOST_CHECK(err.empty());

    err = "prior";
    BOOST_CHECK(!gate.Submit("report-a", "author-b", "domain-b", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");

    err = "prior";
    BOOST_CHECK(!gate.Open(err));
    BOOST_CHECK_EQUAL(err, "QUORUM");
}

BOOST_AUTO_TEST_CASE(one_author_is_refused)
{
    modelnet::SwarmQuorumGate gate;
    std::string err = "prior";
    BOOST_REQUIRE(gate.Submit("report-a", "author-a", "domain-a", err));
    BOOST_CHECK(err.empty());

    err = "prior";
    BOOST_CHECK(!gate.Open(err));
    BOOST_CHECK_EQUAL(err, "QUORUM");

    err = "prior";
    BOOST_REQUIRE(gate.Submit("report-b", "author-a", "domain-b", err));
    BOOST_CHECK(err.empty());

    err = "prior";
    BOOST_CHECK(!gate.Open(err));
    BOOST_CHECK_EQUAL(err, "QUORUM");
}

BOOST_AUTO_TEST_CASE(two_authors_in_one_domain_are_refused)
{
    modelnet::SwarmQuorumGate gate;
    std::string err = "prior";
    BOOST_REQUIRE(gate.Submit("report-a", "author-a", "domain-a", err));
    BOOST_CHECK(err.empty());
    err = "prior";
    BOOST_REQUIRE(gate.Submit("report-b", "author-b", "domain-a", err));
    BOOST_CHECK(err.empty());

    err = "prior";
    BOOST_CHECK(!gate.Open(err));
    BOOST_CHECK_EQUAL(err, "QUORUM");
}

BOOST_AUTO_TEST_CASE(two_authors_in_two_domains_are_accepted)
{
    modelnet::SwarmQuorumGate gate;
    std::string err = "prior";
    BOOST_REQUIRE(gate.Submit("report-a", "author-a", "domain-a", err));
    BOOST_CHECK(err.empty());
    err = "prior";
    BOOST_REQUIRE(gate.Submit("report-b", "author-b", "domain-b", err));
    BOOST_CHECK(err.empty());

    err = "prior";
    BOOST_CHECK(gate.Open(err));
    BOOST_CHECK(err.empty());

    err = "prior";
    BOOST_CHECK(gate.Open(err));
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
