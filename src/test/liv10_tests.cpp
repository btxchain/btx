// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv10/liv10.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(liv10_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pass_spend)
{
    modelnet::Liv10 liv;
    std::string err;
    BOOST_CHECK(liv.Pass(err));
    BOOST_CHECK(!liv.release_qualified());
    BOOST_CHECK(!liv.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
}

BOOST_AUTO_TEST_SUITE_END()
