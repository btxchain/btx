// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/jrn14/jrn14.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(jrn14_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pass)
{
    modelnet::Jrn14 eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Pass(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_SUITE_END()
