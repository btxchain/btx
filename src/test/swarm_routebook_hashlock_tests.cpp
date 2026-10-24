// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_routebook/swarm_routebook.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_routebook_hashlock_tests, BasicTestingSetup)

static void StoreOneHop(modelnet::SwarmRouteBook& book)
{
    std::string err;
    BOOST_CHECK(book.AddHop("route-a", "hop-a", 10, err));
}

BOOST_AUTO_TEST_CASE(unknown_route_is_route)
{
    modelnet::SwarmRouteBook book;
    std::string err = "prior";
    BOOST_CHECK(!book.Hashlock("missing", 31, err));
    BOOST_CHECK_EQUAL(err, "ROUTE");
    BOOST_CHECK(!book.Hashlock("missing", 32, err));
    BOOST_CHECK_EQUAL(err, "ROUTE");
    BOOST_CHECK(!book.qualified());
    BOOST_CHECK_EQUAL(book.hop_count("missing"), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(length_31_is_preimage)
{
    modelnet::SwarmRouteBook book;
    StoreOneHop(book);
    std::string err = "prior";
    BOOST_CHECK(!book.Hashlock("route-a", 31, err));
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
    BOOST_CHECK(!book.qualified());
    BOOST_CHECK_EQUAL(book.hop_count("route-a"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!book.broadcast());
}

BOOST_AUTO_TEST_CASE(length_32_is_not_route)
{
    modelnet::SwarmRouteBook book;
    StoreOneHop(book);
    std::string err = "prior";
    BOOST_CHECK(!book.Hashlock("route-a", 32, err));
    BOOST_CHECK_EQUAL(err, "NOT_ROUTE");
    BOOST_CHECK(!book.qualified());
    BOOST_CHECK(!book.signed_ok());
    BOOST_CHECK(!book.secp_penalty());
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK_EQUAL(book.bound_delta("route-a"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(book.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(other_lengths_are_preimage)
{
    modelnet::SwarmRouteBook book;
    StoreOneHop(book);
    std::string err = "prior";
    BOOST_CHECK(!book.Hashlock("route-a", 0, err));
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
    BOOST_CHECK(!book.Hashlock("route-a", 33, err));
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
    BOOST_CHECK(!book.Hashlock("route-a", -1, err));
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
    BOOST_CHECK(!book.qualified());
}

BOOST_AUTO_TEST_SUITE_END()
