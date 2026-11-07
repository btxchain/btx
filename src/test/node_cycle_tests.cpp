// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/node_cycle/node_cycle.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::NodeCycle& eng)
{
    std::string err;
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(node_cycle_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(idle_before_run_is_closed)
{
    modelnet::NodeCycle eng;
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK_EQUAL(eng.generation(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.stored(), static_cast<int64_t>(0));
    BOOST_CHECK(eng.monetary_ok());
    BOOST_CHECK(!eng.worker_failed());
    BOOST_CHECK(eng.steps().empty());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(run_reaches_failure_with_generation_zero)
{
    modelnet::NodeCycle eng;
    std::string err = "prior";
    BOOST_CHECK(eng.Run(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK_EQUAL(eng.generation(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.stored(), static_cast<int64_t>(40));
    BOOST_CHECK(eng.monetary_ok());
    BOOST_CHECK(eng.worker_failed());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    const char* names[] = {
        "form",
        "workload",
        "accelerate",
        "experience",
        "compare",
        "descendants",
        "measure",
        "graduate",
        "stage",
        "pay",
        "failure",
        "generation",
    };
    BOOST_CHECK_EQUAL(eng.steps().size(), static_cast<std::size_t>(12));
    for (std::size_t i = 0; i < static_cast<std::size_t>(12); ++i) {
        BOOST_CHECK_EQUAL(eng.steps().at(i), names[i]);
    }
    BOOST_CHECK_EQUAL(eng.steps().at(static_cast<std::size_t>(10)), "failure");
    BOOST_CHECK_EQUAL(eng.generation(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.passed());

    BOOST_CHECK(!eng.Run(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(eng.steps().size(), static_cast<std::size_t>(12));
    BOOST_CHECK_EQUAL(eng.generation(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.passed());
    Idle(eng);
    BOOST_CHECK_EQUAL(eng.stored(), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(eng.generation(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(accept_journal_advances_once)
{
    modelnet::NodeCycle cold;
    std::string err = "prior";
    BOOST_CHECK(!cold.AcceptJournal(err));
    BOOST_CHECK_EQUAL(err, modelnet::GRP29_ORDER);
    BOOST_CHECK_EQUAL(cold.generation(), static_cast<int64_t>(0));
    BOOST_CHECK(!cold.passed());
    BOOST_CHECK(cold.steps().empty());

    modelnet::NodeCycle eng;
    BOOST_CHECK(eng.Run(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.generation(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(eng.AcceptJournal(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.generation(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.stored(), static_cast<int64_t>(40));
    BOOST_CHECK(eng.monetary_ok());
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.steps().size(), static_cast<std::size_t>(12));

    BOOST_CHECK(!eng.AcceptJournal(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(eng.generation(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.stored(), static_cast<int64_t>(40));
    BOOST_CHECK(!eng.passed());
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
