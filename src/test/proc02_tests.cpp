// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/proc02/proc02.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(proc02_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(two_cycles_then_latch)
{
    modelnet::Proc02 eng;
    std::string err = "stale";

    BOOST_CHECK_EQUAL(eng.cycles(), 0);
    BOOST_CHECK(eng.parent_after().empty());
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(eng.RunTwoCycles(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.cycles(), 2);
    BOOST_CHECK_EQUAL(eng.parent_after().size(), 64U);
    const std::string parent = eng.parent_after();

    err = "stale";
    BOOST_CHECK(eng.RunTwoCycles(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.cycles(), 2);
    BOOST_CHECK_EQUAL(eng.parent_after(), parent);
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_SUITE_END()
