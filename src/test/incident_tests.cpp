// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/incident/incident.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Incident& eng)
{
    std::string err;
    BOOST_CHECK(!eng.effect_sent());
    BOOST_CHECK(!eng.passed());
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
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.effect_sent());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(incident_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(one_stored_incident)
{
    modelnet::Incident eng;
    std::string err = "stale";
    BOOST_CHECK(eng.File("inc-a", "note-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("inc-a"));
    BOOST_CHECK_EQUAL(eng.text("inc-a"), "note-a");
    BOOST_CHECK(!eng.effect_sent());
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(eng.stored("inc-a"));
    BOOST_CHECK_EQUAL(eng.text("inc-a"), "note-a");

    modelnet::Incident blocked;
    err = "stale";
    BOOST_CHECK(!blocked.File("inc-a", "blocklist", err));
    BOOST_CHECK_EQUAL(err, "SCOPE");
    BOOST_CHECK(!blocked.stored("inc-a"));
    BOOST_CHECK(!blocked.effect_sent());
    BOOST_CHECK_EQUAL(blocked.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
