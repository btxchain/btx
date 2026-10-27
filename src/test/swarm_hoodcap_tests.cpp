// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_hoodcap.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_hoodcap_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_is_node)
{
    modelnet::SwarmHoodCap cap;
    std::string err;
    const modelnet::Offer offer{"", "d1", 1, true};
    BOOST_CHECK(!cap.Admit(offer, err));
    BOOST_CHECK_EQUAL(err, "NODE");
    BOOST_CHECK_EQUAL(cap.known_count(), 0);
    BOOST_CHECK_EQUAL(cap.new_count(), 0);
    BOOST_CHECK(!cap.bytes_moved());
}

BOOST_AUTO_TEST_CASE(negative_rtt_is_rtt)
{
    modelnet::SwarmHoodCap cap;
    std::string err;
    const modelnet::Offer offer{"n1", "d1", -1, true};
    BOOST_CHECK(!cap.Admit(offer, err));
    BOOST_CHECK_EQUAL(err, "RTT");
    BOOST_CHECK_EQUAL(cap.known_count(), 0);
    BOOST_CHECK_EQUAL(cap.new_count(), 0);
    BOOST_CHECK(!cap.bytes_moved());
}

BOOST_AUTO_TEST_CASE(known_hood_cap)
{
    modelnet::SwarmHoodCap cap;
    std::string err = "stale";
    BOOST_CHECK(!cap.bytes_moved());
    const char* nodes[] = {"n1", "n2", "n3", "n4"};
    for (const char* node : nodes) {
        const modelnet::Offer offer{node, "d1", 1, true};
        BOOST_REQUIRE(cap.Admit(offer, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(!cap.bytes_moved());
    }
    BOOST_CHECK_EQUAL(cap.known_count(), 4);
    BOOST_CHECK_EQUAL(cap.new_count(), 0);
    const modelnet::Offer fifth{"n5", "d1", 1, true};
    BOOST_CHECK(!cap.Admit(fifth, err));
    BOOST_CHECK_EQUAL(err, "HOOD");
    BOOST_CHECK_EQUAL(cap.known_count(), 4);
    BOOST_CHECK_EQUAL(cap.new_count(), 0);
    BOOST_CHECK(!cap.bytes_moved());
}

BOOST_AUTO_TEST_CASE(new_hood_cap)
{
    modelnet::SwarmHoodCap cap;
    std::string err = "stale";
    BOOST_CHECK(!cap.bytes_moved());
    BOOST_REQUIRE(cap.Admit(modelnet::Offer{"n1", "d1", 0, false}, err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(cap.Admit(modelnet::Offer{"n2", "d1", 0, false}, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(cap.new_count(), 2);
    BOOST_CHECK_EQUAL(cap.known_count(), 0);
    BOOST_CHECK(!cap.Admit(modelnet::Offer{"n3", "d1", 0, false}, err));
    BOOST_CHECK_EQUAL(err, "HOOD");
    BOOST_CHECK_EQUAL(cap.new_count(), 2);
    BOOST_CHECK_EQUAL(cap.known_count(), 0);
    BOOST_CHECK(!cap.bytes_moved());
}

BOOST_AUTO_TEST_CASE(duplicate_node_is_replay)
{
    modelnet::SwarmHoodCap cap;
    std::string err;
    BOOST_REQUIRE(cap.Admit(modelnet::Offer{"n1", "d1", 5, true}, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!cap.Admit(modelnet::Offer{"n1", "d1", 5, false}, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(cap.known_count(), 1);
    BOOST_CHECK_EQUAL(cap.new_count(), 0);
    BOOST_CHECK(!cap.bytes_moved());
}

BOOST_AUTO_TEST_SUITE_END()
