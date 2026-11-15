// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv05/liv05.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(liv05_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pass)
{
    modelnet::Liv05 eng;
    std::string err;
    BOOST_CHECK(eng.Pass(err));
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
}

BOOST_AUTO_TEST_SUITE_END()
