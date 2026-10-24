// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_routebook/swarm_routebook.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_routebook_sighash_tests, BasicTestingSetup)

static void StoreOneHop(modelnet::SwarmRouteBook& book)
{
    std::string err;
    BOOST_CHECK(book.AddHop("route-a", "hop-a", 10, err));
}

BOOST_AUTO_TEST_CASE(unknown_route_is_route)
{
    modelnet::SwarmRouteBook book;
    std::string err = "prior";
    BOOST_CHECK(!book.Sighash("missing", true, err));
    BOOST_CHECK_EQUAL(err, "ROUTE");
    BOOST_CHECK(!book.Sighash("missing", false, err));
    BOOST_CHECK_EQUAL(err, "ROUTE");
    BOOST_CHECK(!book.outputs_covered("missing"));
    BOOST_CHECK(!book.signed_ok());
    BOOST_CHECK(!book.qualified());
}

BOOST_AUTO_TEST_CASE(covers_outputs_false_is_not_signed)
{
    modelnet::SwarmRouteBook book;
    StoreOneHop(book);
    std::string err = "prior";
    BOOST_CHECK(!book.Sighash("route-a", false, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK(!book.outputs_covered("route-a"));
    BOOST_CHECK(!book.signed_ok());
    BOOST_CHECK(!book.qualified());
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!book.broadcast());
}

BOOST_AUTO_TEST_CASE(covers_outputs_true_keeps_signed_ok_false)
{
    modelnet::SwarmRouteBook book;
    StoreOneHop(book);
    std::string err = "prior";
    BOOST_CHECK(book.Sighash("route-a", true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(book.outputs_covered("route-a"));
    BOOST_CHECK(!book.signed_ok());
    BOOST_CHECK(!book.qualified());
    BOOST_CHECK(!book.secp_penalty());
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK(!book.launched());
    BOOST_CHECK(!book.gpu());
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(book.automatic_spend(), "0");
    BOOST_CHECK(!book.Sighash("route-a", false, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK(book.outputs_covered("route-a"));
    BOOST_CHECK(!book.signed_ok());
}

BOOST_AUTO_TEST_SUITE_END()
