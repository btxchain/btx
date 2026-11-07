// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/slice_views/slice_views.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::SliceViews& views)
{
    std::string err;
    BOOST_CHECK(!views.passed());
    BOOST_CHECK(!views.launched());
    BOOST_CHECK(!views.gpu());
    BOOST_CHECK(!views.broadcast());
    BOOST_CHECK(!views.qualified());
    BOOST_CHECK(!views.release_qualified());
    BOOST_CHECK_EQUAL(views.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(views.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(views.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!views.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(views.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(views.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(views.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!views.passed());
    BOOST_CHECK(!views.launched());
    BOOST_CHECK(!views.gpu());
    BOOST_CHECK(!views.broadcast());
    BOOST_CHECK(!views.qualified());
    BOOST_CHECK(!views.release_qualified());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(slice_views_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pass_returns_true_and_spend_err_is_zero)
{
    modelnet::SliceViews views;
    std::string err;
    BOOST_CHECK(views.Pass(err));
    BOOST_CHECK(!views.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    Idle(views);
}

BOOST_AUTO_TEST_SUITE_END()
