// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/slice_admit/slice_admit.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::SliceAdmit& gate)
{
    std::string err;
    BOOST_CHECK(!gate.passed());
    BOOST_CHECK(!gate.launched());
    BOOST_CHECK(!gate.gpu());
    BOOST_CHECK(!gate.broadcast());
    BOOST_CHECK(!gate.qualified());
    BOOST_CHECK(!gate.release_qualified());
    BOOST_CHECK_EQUAL(gate.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(gate.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(gate.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!gate.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!gate.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(slice_admit_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pass_returns_true_spend_err_is_zero)
{
    modelnet::SliceAdmit gate;
    std::string err = "stale";
    BOOST_CHECK(gate.Pass(err));
    BOOST_CHECK(!gate.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    Idle(gate);
}

BOOST_AUTO_TEST_SUITE_END()
