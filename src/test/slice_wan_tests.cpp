// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/slice_wan/slice_wan.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(slice_wan_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pass_one_host)
{
    modelnet::SliceWan wan;
    std::string err;
    BOOST_CHECK(wan.Pass(err));
    BOOST_CHECK_EQUAL(wan.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!wan.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
}

BOOST_AUTO_TEST_SUITE_END()
