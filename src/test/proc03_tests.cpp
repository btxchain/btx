// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/proc03/proc03.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(proc03_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(recover_while_down)
{
    modelnet::Proc03 eng;
    std::string err = "stale";
    const std::string spend = eng.automatic_spend();

    BOOST_CHECK_EQUAL(eng.recovered(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.runtime_was_down());
    BOOST_CHECK(!eng.device_stopped());
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(spend, modelnet::NIFDT_AUTOMATIC_SPEND);

    BOOST_CHECK(!eng.Recover(static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.recovered(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.runtime_was_down());
    BOOST_CHECK(!eng.device_stopped());

    err = "stale";
    BOOST_CHECK(!eng.Recover(static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "EMPTY");
    BOOST_CHECK_EQUAL(eng.recovered(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.runtime_was_down());
    BOOST_CHECK(!eng.device_stopped());

    err = "stale";
    BOOST_CHECK(!eng.Recover(static_cast<int64_t>(1000), true, err));
    BOOST_CHECK_EQUAL(err, "RUNTIME");
    BOOST_CHECK_EQUAL(eng.recovered(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.runtime_was_down());
    BOOST_CHECK(!eng.device_stopped());

    err = "stale";
    BOOST_CHECK(eng.Recover(static_cast<int64_t>(1000), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.recovered(), static_cast<int64_t>(1000));
    BOOST_CHECK(eng.runtime_was_down());
    BOOST_CHECK(!eng.device_stopped());
    BOOST_CHECK_EQUAL(eng.automatic_spend(), spend);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());

    BOOST_CHECK(!eng.Recover(static_cast<int64_t>(-5), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.recovered(), static_cast<int64_t>(1000));
    BOOST_CHECK(eng.runtime_was_down());
    BOOST_CHECK(!eng.device_stopped());

    BOOST_CHECK(!eng.Recover(static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "EMPTY");
    BOOST_CHECK_EQUAL(eng.recovered(), static_cast<int64_t>(1000));

    BOOST_CHECK(!eng.Recover(static_cast<int64_t>(1000), true, err));
    BOOST_CHECK_EQUAL(err, "RUNTIME");
    BOOST_CHECK_EQUAL(eng.recovered(), static_cast<int64_t>(1000));
    BOOST_CHECK(eng.runtime_was_down());
    BOOST_CHECK(!eng.device_stopped());

    BOOST_CHECK(!eng.Recover(static_cast<int64_t>(2000), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(eng.recovered(), static_cast<int64_t>(1000));
    BOOST_CHECK(eng.runtime_was_down());
    BOOST_CHECK(!eng.device_stopped());
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());
}

BOOST_AUTO_TEST_SUITE_END()
