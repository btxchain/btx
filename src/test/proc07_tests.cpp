// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/proc07/proc07.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void ExpectQuiet(const modelnet::Proc07& eng)
{
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.cloud_used());
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.discover().connected());
    BOOST_CHECK(!eng.discover().launched());
    BOOST_CHECK(!eng.discover().gpu());
    BOOST_CHECK(!eng.discover().broadcast());
    BOOST_CHECK_EQUAL(eng.discover().bytes_moved(), static_cast<int64_t>(0));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(proc07_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cloud_on_writes_no_ok_flag)
{
    modelnet::Proc07 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.RunLocal(true, err));
    BOOST_CHECK_EQUAL(err, "CLOUD");
    BOOST_CHECK(!eng.discovery_ok());
    BOOST_CHECK(!eng.assignment_ok());
    BOOST_CHECK(!eng.inference_ok());
    BOOST_CHECK(!eng.discover().offered("local-worker"));
    BOOST_CHECK(!eng.discover().granted("local-worker"));
    BOOST_CHECK(eng.task_id().empty());
    BOOST_CHECK_EQUAL(eng.output(), static_cast<int64_t>(0));
    ExpectQuiet(eng);
}

BOOST_AUTO_TEST_CASE(cloud_off_discovers_assigns_and_infers)
{
    modelnet::Proc07 eng;
    std::string err = "stale";
    BOOST_CHECK(eng.RunLocal(false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.discovery_ok());
    BOOST_CHECK(eng.assignment_ok());
    BOOST_CHECK(eng.inference_ok());
    BOOST_CHECK(eng.discover().offered("local-worker"));
    BOOST_CHECK(eng.discover().granted("local-worker"));
    BOOST_CHECK_EQUAL(eng.discover().scope_of("local-worker"), "lan");
    BOOST_CHECK_EQUAL(eng.discover().endpoint_of("local-worker"), "local");
    BOOST_CHECK_EQUAL(eng.discover().until_ms_of("local-worker"), static_cast<int64_t>(100));
    BOOST_CHECK_EQUAL(eng.task_id(), "task-1");
    BOOST_CHECK_EQUAL(eng.output(), static_cast<int64_t>(7));
    ExpectQuiet(eng);

    err = "stale";
    BOOST_CHECK(eng.RunLocal(false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.discovery_ok());
    BOOST_CHECK(eng.assignment_ok());
    BOOST_CHECK(eng.inference_ok());
    BOOST_CHECK_EQUAL(eng.discover().endpoint_of("local-worker"), "local");
    BOOST_CHECK_EQUAL(eng.discover().until_ms_of("local-worker"), static_cast<int64_t>(100));
    BOOST_CHECK_EQUAL(eng.task_id(), "task-1");
    BOOST_CHECK_EQUAL(eng.output(), static_cast<int64_t>(7));
    ExpectQuiet(eng);

    BOOST_CHECK(!eng.RunLocal(true, err));
    BOOST_CHECK_EQUAL(err, "CLOUD");
    BOOST_CHECK(eng.discovery_ok());
    BOOST_CHECK(eng.assignment_ok());
    BOOST_CHECK(eng.inference_ok());
    BOOST_CHECK(eng.discover().granted("local-worker"));
    BOOST_CHECK_EQUAL(eng.output(), static_cast<int64_t>(7));
    ExpectQuiet(eng);
}

BOOST_AUTO_TEST_CASE(ask_cloud_refuses_and_keeps_ok_flags)
{
    modelnet::Proc07 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.AskCloud("", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.discovery_ok());
    BOOST_CHECK(!eng.assignment_ok());
    BOOST_CHECK(!eng.inference_ok());
    BOOST_CHECK(!eng.discover().offered("local-worker"));
    ExpectQuiet(eng);

    BOOST_CHECK(!eng.AskCloud("external", err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.discovery_ok());
    BOOST_CHECK(!eng.assignment_ok());
    BOOST_CHECK(!eng.inference_ok());
    ExpectQuiet(eng);

    BOOST_CHECK(eng.RunLocal(false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.AskCloud("external", err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(eng.discovery_ok());
    BOOST_CHECK(eng.assignment_ok());
    BOOST_CHECK(eng.inference_ok());
    BOOST_CHECK_EQUAL(eng.output(), static_cast<int64_t>(7));
    ExpectQuiet(eng);

    BOOST_CHECK(!eng.AskCloud("", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(eng.discovery_ok());
    BOOST_CHECK(eng.assignment_ok());
    BOOST_CHECK(eng.inference_ok());
    BOOST_CHECK(eng.discover().granted("local-worker"));
    BOOST_CHECK_EQUAL(eng.discover().endpoint_of("local-worker"), "local");
    ExpectQuiet(eng);
}

BOOST_AUTO_TEST_SUITE_END()
