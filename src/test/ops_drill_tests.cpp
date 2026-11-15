// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/ops_drill/ops_drill.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::OpsDrill& eng)
{
    std::string err;
    BOOST_CHECK(!eng.effect_sent());
    BOOST_CHECK(!eng.retaliation());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.effect_sent());
    BOOST_CHECK(!eng.retaliation());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(ops_drill_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(benign_triage)
{
    modelnet::OpsDrill eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Run("triage", "benign", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("triage"));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.effect_sent());
    BOOST_CHECK(!eng.retaliation());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(eng.Run("triage", "benign", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("triage"));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.effect_sent());

    BOOST_CHECK(!eng.Run("", "benign", err));
    BOOST_CHECK_EQUAL(err, modelnet::OPS_DRILL_FIELD);
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(eng.stored("triage"));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(non_benign_contain)
{
    modelnet::OpsDrill eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Contain("other", err));
    BOOST_CHECK_EQUAL(err, modelnet::OPS_DRILL_BLAST);
    BOOST_CHECK_EQUAL(err, "BLAST");
    BOOST_CHECK(!eng.stored("contain"));
    BOOST_CHECK(!eng.stored("other"));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.effect_sent());
    BOOST_CHECK(!eng.retaliation());

    BOOST_CHECK(!eng.Contain("", err));
    BOOST_CHECK_EQUAL(err, "BLAST");
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.stored("contain"));
    BOOST_CHECK(!eng.effect_sent());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(benign_contain_stores_name)
{
    modelnet::OpsDrill eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Contain("benign", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("contain"));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.effect_sent());
    BOOST_CHECK(!eng.retaliation());

    BOOST_CHECK(!eng.Contain("other", err));
    BOOST_CHECK_EQUAL(err, modelnet::OPS_DRILL_BLAST);
    BOOST_CHECK(eng.stored("contain"));
    BOOST_CHECK(!eng.stored("other"));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.effect_sent());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(field_drill_and_fixture_store_nothing)
{
    modelnet::OpsDrill eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Run("", "benign", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.Run("triage", "", err));
    BOOST_CHECK_EQUAL(err, modelnet::OPS_DRILL_FIELD);
    BOOST_CHECK(!eng.stored("triage"));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Run("unknown", "other", err));
    BOOST_CHECK_EQUAL(err, modelnet::OPS_DRILL_DRILL);
    BOOST_CHECK_EQUAL(err, "DRILL");
    BOOST_CHECK(!eng.stored("unknown"));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Run("patch", "other", err));
    BOOST_CHECK_EQUAL(err, modelnet::OPS_DRILL_FIXTURE);
    BOOST_CHECK_EQUAL(err, "FIXTURE");
    BOOST_CHECK(!eng.stored("patch"));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.effect_sent());
    BOOST_CHECK(!eng.retaliation());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(each_benign_drill_name)
{
    modelnet::OpsDrill eng;
    std::string err = "stale";
    const char* names[] = {"retainer", "triage", "contain", "mitigate", "patch", "federate"};
    for (const char* name : names) {
        BOOST_CHECK(eng.Run(name, "benign", err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(eng.stored(name));
        BOOST_CHECK(!eng.effect_sent());
        BOOST_CHECK(!eng.retaliation());
    }
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(6));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(eng.stored("triage"));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(6));
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
