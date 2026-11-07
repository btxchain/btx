// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_preimage32.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_preimage32_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_invoice_is_invoice)
{
    modelnet::SwarmPreimage32 claims;
    const std::vector<unsigned char> preimage(32, 0x11);
    std::string err = "stale";

    BOOST_CHECK(!claims.Claim("", preimage, err));
    BOOST_CHECK_EQUAL(err, "INVOICE");
    BOOST_CHECK(!claims.Claimed(""));
}

BOOST_AUTO_TEST_CASE(thirty_one_byte_preimage_claims_nothing)
{
    modelnet::SwarmPreimage32 claims;
    const std::vector<unsigned char> preimage(31, 0x21);
    std::string err = "stale";

    BOOST_CHECK(!claims.Claim("inv-a", preimage, err));
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
    BOOST_CHECK(!claims.Claimed("inv-a"));
}

BOOST_AUTO_TEST_CASE(thirty_two_byte_preimage_is_claimed)
{
    modelnet::SwarmPreimage32 claims;
    const std::vector<unsigned char> preimage(32, 0x32);
    std::string err = "stale";

    BOOST_CHECK(!claims.Claimed("inv-a"));
    BOOST_REQUIRE(claims.Claim("inv-a", preimage, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(claims.Claimed("inv-a"));
    BOOST_CHECK(!claims.Claimed("inv-b"));
}

BOOST_AUTO_TEST_CASE(duplicate_invoice_is_replay)
{
    modelnet::SwarmPreimage32 claims;
    const std::vector<unsigned char> first(32, 0x11);
    const std::vector<unsigned char> again(32, 0x22);
    std::string err = "stale";

    BOOST_REQUIRE(claims.Claim("inv-a", first, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(claims.Claimed("inv-a"));

    BOOST_CHECK(!claims.Claim("inv-a", again, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(claims.Claimed("inv-a"));

    BOOST_REQUIRE(claims.Claim("inv-b", again, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(claims.Claimed("inv-a"));
    BOOST_CHECK(claims.Claimed("inv-b"));
}

BOOST_AUTO_TEST_SUITE_END()
