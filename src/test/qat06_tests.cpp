// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/qat06/qat06.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(qat06_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pass_latches)
{
    modelnet::Qat06 eng;
    std::string err = "stale";

    // DT-Q16 simulation calibration. The trace argument is not read.
    BOOST_CHECK(!eng.Calibrate("hardware-trace", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.trace_read());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(eng.covers("DT-Q16"));

    // DT-Q17 repeated evolution. Generation stays 0 and passed() stays false.
    BOOST_CHECK(!eng.Generate(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(eng.generation(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(eng.covers("DT-Q17"));

    // DT-Q18 offline packaging and public release. No tag or archive.
    BOOST_CHECK(!eng.Release("v1", "pkg.tar", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.tag_created());
    BOOST_CHECK(!eng.archive_created());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(eng.covers("DT-Q18"));

    BOOST_CHECK(!eng.covers("DT-Q15"));
    BOOST_CHECK(!eng.covers("DT-Q19"));
    BOOST_CHECK(!eng.qualified());

    BOOST_CHECK(eng.Pass(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.Pass(err));
    BOOST_CHECK(err.empty());

    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.trace_read());
    BOOST_CHECK(!eng.tag_created());
    BOOST_CHECK(!eng.archive_created());
    BOOST_CHECK_EQUAL(eng.generation(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
}

BOOST_AUTO_TEST_SUITE_END()
