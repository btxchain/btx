// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_routebook/swarm_routebook.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_routebook_claim_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_route_is_unqualified)
{
    modelnet::SwarmRouteBook book;
    std::string err = "prior";
    BOOST_CHECK(!book.Claim("missing", err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!book.Claim("", err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK(!book.qualified());
}

BOOST_AUTO_TEST_CASE(known_route_is_unqualified)
{
    modelnet::SwarmRouteBook book;
    std::string err = "prior";
    BOOST_CHECK(book.AddHop("route-a", "hop-a", 10, err));
    BOOST_CHECK(!book.Claim("route-a", err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(book.hop_count("route-a"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK(!book.qualified());
}

BOOST_AUTO_TEST_CASE(atoms_moved_stays_0_and_broadcast_stays_false)
{
    modelnet::SwarmRouteBook book;
    std::string err = "prior";
    BOOST_CHECK(book.AddHop("route-a", "hop-a", 10, err));
    BOOST_CHECK(book.AddHop("route-a", "hop-b", 20, err));
    BOOST_CHECK(book.AddHop("route-a", "hop-c", 30, err));
    BOOST_CHECK_EQUAL(book.required_slack("route-a"), static_cast<int64_t>(480));
    BOOST_CHECK(book.Bind("route-a", 480, err));
    BOOST_CHECK(book.Sighash("route-a", true, err));
    BOOST_CHECK(!book.Hashlock("route-a", 32, err));
    BOOST_CHECK_EQUAL(err, "NOT_ROUTE");
    BOOST_CHECK(!book.Claim("route-a", err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK(!book.qualified());
    BOOST_CHECK(!book.secp_penalty());
    BOOST_CHECK(!book.launched());
    BOOST_CHECK(!book.gpu());
    BOOST_CHECK(!book.signed_ok());
    BOOST_CHECK_EQUAL(book.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(book.bound_delta("route-a"), static_cast<int64_t>(480));
    BOOST_CHECK(book.outputs_covered("route-a"));
    BOOST_CHECK_EQUAL(book.hop_count("route-a"), static_cast<int64_t>(3));
}

BOOST_AUTO_TEST_SUITE_END()
