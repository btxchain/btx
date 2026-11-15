// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/proc01/proc01.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(proc01_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(observe_separates_advertised)
{
    modelnet::Proc01 fresh;
    std::string err = "stale";
    BOOST_CHECK(!fresh.passed());
    BOOST_CHECK(!fresh.release_qualified());
    BOOST_CHECK(!fresh.gpu_passed());
    BOOST_CHECK(!fresh.windows_passed());
    BOOST_CHECK(!fresh.hardware_qualified());
    BOOST_CHECK_EQUAL(fresh.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(fresh.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(fresh.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(fresh.count(), 0);

    // An empty id stores nothing.
    BOOST_CHECK(!fresh.Observe("", true, true, "evidence-1", err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!fresh.Observe("", true, false, "", err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(fresh.count(), 0);
    BOOST_CHECK(!fresh.advertised(""));
    BOOST_CHECK(!fresh.qualified(""));

    // Advertised without a measurement stays unqualified. Evidence is ignored.
    modelnet::Proc01 advertised_only;
    err = "stale";
    BOOST_CHECK(advertised_only.Observe("cap-advertised", true, false, "claim", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(advertised_only.advertised("cap-advertised"));
    BOOST_CHECK(!advertised_only.qualified("cap-advertised"));
    BOOST_CHECK_EQUAL(advertised_only.count(), 1);

    // Measured without advertised stays unqualified, even with real evidence.
    modelnet::Proc01 measured_only;
    err = "stale";
    BOOST_CHECK(measured_only.Observe("cap-measured", false, true, "evidence-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!measured_only.advertised("cap-measured"));
    BOOST_CHECK(!measured_only.qualified("cap-measured"));
    BOOST_CHECK_EQUAL(measured_only.count(), 1);

    // Evidence "claim" stores nothing, so a later real observation can record it.
    modelnet::Proc01 claim;
    err = "stale";
    BOOST_CHECK(!claim.Observe("cap-claim", true, true, "claim", err));
    BOOST_CHECK_EQUAL(err, "CLAIM");
    BOOST_CHECK(!claim.advertised("cap-claim"));
    BOOST_CHECK(!claim.qualified("cap-claim"));
    BOOST_CHECK_EQUAL(claim.count(), 0);
    BOOST_CHECK(claim.Observe("cap-claim", true, true, "evidence-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(claim.advertised("cap-claim"));
    BOOST_CHECK(claim.qualified("cap-claim"));
    BOOST_CHECK_EQUAL(claim.count(), 1);

    // Empty evidence stores nothing.
    modelnet::Proc01 missing_evidence;
    err = "stale";
    BOOST_CHECK(!missing_evidence.Observe("cap-field", true, true, "", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!missing_evidence.advertised("cap-field"));
    BOOST_CHECK(!missing_evidence.qualified("cap-field"));
    BOOST_CHECK_EQUAL(missing_evidence.count(), 0);

    // A real evidence value qualifies that id only.
    modelnet::Proc01 qualified_one;
    err = "stale";
    BOOST_CHECK(qualified_one.Observe("cap-open", true, false, "claim", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(qualified_one.Observe("cap-held", true, true, "evidence-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(qualified_one.advertised("cap-open"));
    BOOST_CHECK(!qualified_one.qualified("cap-open"));
    BOOST_CHECK(qualified_one.advertised("cap-held"));
    BOOST_CHECK(qualified_one.qualified("cap-held"));
    BOOST_CHECK(!qualified_one.advertised("cap-other"));
    BOOST_CHECK(!qualified_one.qualified("cap-other"));
    BOOST_CHECK_EQUAL(qualified_one.count(), 2);

    // Replay keeps the first record. A later qualify attempt does not upgrade it.
    BOOST_CHECK(!qualified_one.Observe("cap-open", true, true, "evidence-1", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(qualified_one.advertised("cap-open"));
    BOOST_CHECK(!qualified_one.qualified("cap-open"));
    BOOST_CHECK(qualified_one.qualified("cap-held"));
    BOOST_CHECK_EQUAL(qualified_one.count(), 2);

    // Neither advertised nor measured stores nothing.
    modelnet::Proc01 neither;
    err = "stale";
    BOOST_CHECK(!neither.Observe("cap-neither", false, false, "evidence-1", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(neither.count(), 0);
    BOOST_CHECK(!neither.advertised("cap-neither"));
    BOOST_CHECK(!neither.qualified("cap-neither"));

    // Qualifying one id does not set the qualification flags. Spend stays "0".
    BOOST_CHECK(!qualified_one.passed());
    BOOST_CHECK(!qualified_one.release_qualified());
    BOOST_CHECK(!qualified_one.gpu_passed());
    BOOST_CHECK(!qualified_one.windows_passed());
    BOOST_CHECK(!qualified_one.hardware_qualified());
    BOOST_CHECK_EQUAL(qualified_one.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(qualified_one.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(qualified_one.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
