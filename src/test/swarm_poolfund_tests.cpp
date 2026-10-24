// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_poolfund.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_poolfund_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unfunded_pool_is_not_advertised)
{
    modelnet::SwarmPoolFund fund;
    std::string err = "stale";

    BOOST_CHECK(!fund.Advertised("pool-a"));
    BOOST_CHECK_EQUAL(fund.atoms("pool-a"), 0);

    BOOST_CHECK(!fund.Create("", err));
    BOOST_CHECK_EQUAL(err, "POOL");
    BOOST_CHECK(!fund.Advertised(""));
    BOOST_CHECK_EQUAL(fund.atoms(""), 0);

    BOOST_REQUIRE(fund.Create("pool-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!fund.Advertised("pool-a"));
    BOOST_CHECK_EQUAL(fund.atoms("pool-a"), 0);

    BOOST_CHECK(!fund.Create("pool-a", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!fund.Advertised("pool-a"));
    BOOST_CHECK_EQUAL(fund.atoms("pool-a"), 0);
}

BOOST_AUTO_TEST_CASE(fund_then_second_fund_refused)
{
    modelnet::SwarmPoolFund fund;
    std::string err = "stale";

    BOOST_REQUIRE(fund.Create("pool-a", err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(fund.Create("pool-b", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!fund.Advertised("pool-a"));
    BOOST_CHECK(!fund.Advertised("pool-b"));
    BOOST_CHECK_EQUAL(fund.atoms("pool-a"), 0);
    BOOST_CHECK_EQUAL(fund.atoms("pool-b"), 0);

    BOOST_CHECK(!fund.Fund("missing", 10, err));
    BOOST_CHECK_EQUAL(err, "POOL");
    BOOST_CHECK(!fund.Advertised("missing"));
    BOOST_CHECK_EQUAL(fund.atoms("missing"), 0);

    BOOST_CHECK(!fund.Fund("missing", 0, err));
    BOOST_CHECK_EQUAL(err, "POOL");

    BOOST_CHECK(!fund.Fund("pool-a", 0, err));
    BOOST_CHECK_EQUAL(err, "ATOMS");
    BOOST_CHECK(!fund.Advertised("pool-a"));
    BOOST_CHECK_EQUAL(fund.atoms("pool-a"), 0);

    BOOST_CHECK(!fund.Fund("pool-a", -3, err));
    BOOST_CHECK_EQUAL(err, "ATOMS");
    BOOST_CHECK(!fund.Advertised("pool-a"));
    BOOST_CHECK_EQUAL(fund.atoms("pool-a"), 0);

    BOOST_REQUIRE(fund.Fund("pool-a", 100, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(fund.Advertised("pool-a"));
    BOOST_CHECK_EQUAL(fund.atoms("pool-a"), 100);
    BOOST_CHECK(!fund.Advertised("pool-b"));
    BOOST_CHECK_EQUAL(fund.atoms("pool-b"), 0);

    BOOST_CHECK(!fund.Fund("pool-a", 50, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(fund.Advertised("pool-a"));
    BOOST_CHECK_EQUAL(fund.atoms("pool-a"), 100);

    BOOST_CHECK(!fund.Fund("pool-a", 0, err));
    BOOST_CHECK_EQUAL(err, "ATOMS");
    BOOST_CHECK_EQUAL(fund.atoms("pool-a"), 100);

    BOOST_CHECK(!fund.Create("pool-a", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(fund.atoms("pool-a"), 100);
    BOOST_CHECK(!fund.Advertised("pool-b"));
    BOOST_CHECK_EQUAL(fund.atoms("pool-b"), 0);
}

BOOST_AUTO_TEST_SUITE_END()
