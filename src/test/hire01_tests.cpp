// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/hire01/hire01.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(hire01_tests, BasicTestingSetup)

static void ExpectClosed(const modelnet::Hire01& hire)
{
    BOOST_CHECK(!hire.passed());
    BOOST_CHECK(!hire.gpu_passed());
    BOOST_CHECK(!hire.windows_passed());
    BOOST_CHECK(!hire.hardware_qualified());
    BOOST_CHECK(!hire.release_qualified());
    BOOST_CHECK(!hire.release_issued());
    BOOST_CHECK_EQUAL(hire.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(hire.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(qualify_modified_records_controls)
{
    modelnet::Hire01 hire;
    std::string err = "stale";

    BOOST_CHECK(hire.model_id().empty());
    BOOST_CHECK_EQUAL(hire.advertised_slots(), static_cast<int64_t>(0));
    ExpectClosed(hire);

    BOOST_CHECK(!hire.QualifyModified("", true, true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(hire.model_id().empty());
    ExpectClosed(hire);

    err = "stale";
    BOOST_CHECK(!hire.QualifyModified("", false, false, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(hire.model_id().empty());

    err = "stale";
    BOOST_CHECK(!hire.QualifyModified("model-a", false, true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(hire.model_id().empty());
    ExpectClosed(hire);

    err = "stale";
    BOOST_CHECK(!hire.QualifyModified("model-a", true, false, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(hire.model_id().empty());

    err = "stale";
    BOOST_CHECK(!hire.QualifyModified("model-a", false, false, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(hire.model_id().empty());
    ExpectClosed(hire);

    err = "stale";
    BOOST_CHECK(hire.QualifyModified("model-a", true, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(hire.model_id(), "model-a");
    ExpectClosed(hire);

    err = "stale";
    BOOST_CHECK(!hire.QualifyModified("", true, true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(hire.model_id(), "model-a");

    err = "stale";
    BOOST_CHECK(!hire.QualifyModified("model-b", false, true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(hire.model_id(), "model-a");
    ExpectClosed(hire);
}

BOOST_AUTO_TEST_CASE(unmeasured_warm_capacity_is_not_advertised)
{
    modelnet::Hire01 hire;
    std::string err = "stale";

    BOOST_CHECK_EQUAL(hire.advertised_slots(), static_cast<int64_t>(0));

    BOOST_CHECK(!hire.AdvertiseWarm("", static_cast<int64_t>(4), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(hire.advertised_slots(), static_cast<int64_t>(0));

    err = "stale";
    BOOST_CHECK(!hire.AdvertiseWarm("", static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(hire.advertised_slots(), static_cast<int64_t>(0));

    err = "stale";
    BOOST_CHECK(!hire.AdvertiseWarm("pool-a", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(hire.advertised_slots(), static_cast<int64_t>(0));

    err = "stale";
    BOOST_CHECK(!hire.AdvertiseWarm("pool-a", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(hire.advertised_slots(), static_cast<int64_t>(0));

    err = "stale";
    BOOST_CHECK(!hire.AdvertiseWarm("pool-a", static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(hire.advertised_slots(), static_cast<int64_t>(0));
    ExpectClosed(hire);

    err = "stale";
    BOOST_CHECK(!hire.AdvertiseWarm("pool-a", static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(hire.advertised_slots(), static_cast<int64_t>(0));

    err = "stale";
    BOOST_CHECK(hire.AdvertiseWarm("pool-a", static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(hire.advertised_slots(), static_cast<int64_t>(0));

    err = "stale";
    BOOST_CHECK(hire.AdvertiseWarm("pool-a", static_cast<int64_t>(4), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(hire.advertised_slots(), static_cast<int64_t>(4));
    ExpectClosed(hire);

    err = "stale";
    BOOST_CHECK(!hire.AdvertiseWarm("pool-a", static_cast<int64_t>(9), false, err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(hire.advertised_slots(), static_cast<int64_t>(4));

    err = "stale";
    BOOST_CHECK(!hire.AdvertiseWarm("", static_cast<int64_t>(9), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(hire.advertised_slots(), static_cast<int64_t>(4));
    ExpectClosed(hire);
}

BOOST_AUTO_TEST_CASE(issue_release_stays_unqualified)
{
    modelnet::Hire01 hire;
    std::string err = "stale";

    BOOST_CHECK(!hire.release_issued());
    ExpectClosed(hire);

    BOOST_CHECK(hire.QualifyModified("model-a", true, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(hire.AdvertiseWarm("pool-a", static_cast<int64_t>(4), true, err));
    BOOST_CHECK_EQUAL(hire.advertised_slots(), static_cast<int64_t>(4));

    err = "stale";
    BOOST_CHECK(!hire.IssueRelease("", true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!hire.release_issued());
    ExpectClosed(hire);

    err = "stale";
    BOOST_CHECK(!hire.IssueRelease("", false, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!hire.release_issued());

    err = "stale";
    BOOST_CHECK(!hire.IssueRelease("rel-1", false, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!hire.release_issued());
    ExpectClosed(hire);

    err = "stale";
    BOOST_CHECK(!hire.IssueRelease("rel-1", true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!hire.release_issued());
    BOOST_CHECK_EQUAL(hire.model_id(), "model-a");
    BOOST_CHECK_EQUAL(hire.advertised_slots(), static_cast<int64_t>(4));
    ExpectClosed(hire);
}

BOOST_AUTO_TEST_SUITE_END()
