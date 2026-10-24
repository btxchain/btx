// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_status/nif_status.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(nif_status_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(component_record_does_not_qualify_release)
{
    modelnet::NifStatus status;
    std::string err;

    BOOST_CHECK_EQUAL(status.component_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(status.native_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(status.hardware_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(status.release_count(), static_cast<int64_t>(0));
    BOOST_CHECK(!status.release_qualified());
    BOOST_CHECK(!status.hardware_qualified());
    BOOST_CHECK(!status.launched());
    BOOST_CHECK(!status.gpu());
    BOOST_CHECK(!status.broadcast());
    BOOST_CHECK_EQUAL(status.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(status.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);

    BOOST_CHECK(status.Record("component", "alpha", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(status.component_stored("alpha"));
    BOOST_CHECK_EQUAL(status.component_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(status.native_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(status.hardware_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(status.release_count(), static_cast<int64_t>(0));
    BOOST_CHECK(!status.release_qualified());
    BOOST_CHECK(!status.hardware_qualified());
    BOOST_CHECK(!status.launched());
    BOOST_CHECK(!status.gpu());
    BOOST_CHECK(!status.broadcast());
    BOOST_CHECK_EQUAL(status.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(hardware_record_leaves_hardware_unqualified)
{
    modelnet::NifStatus status;
    std::string err;

    BOOST_CHECK(status.Record("hardware", "meter", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(status.hardware_stored("meter"));
    BOOST_CHECK_EQUAL(status.hardware_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(status.component_count(), static_cast<int64_t>(0));
    BOOST_CHECK(!status.hardware_qualified());
    BOOST_CHECK(!status.release_qualified());
    BOOST_CHECK(!status.launched());
    BOOST_CHECK(!status.gpu());
    BOOST_CHECK(!status.broadcast());
    BOOST_CHECK_EQUAL(status.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
}

BOOST_AUTO_TEST_CASE(release_is_unqualified)
{
    modelnet::NifStatus status;
    std::string err;

    BOOST_CHECK(status.Record("component", "alpha", err));
    BOOST_CHECK_EQUAL(status.component_count(), static_cast<int64_t>(1));

    BOOST_CHECK(!status.Release("alpha", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!status.release_stored("alpha"));
    BOOST_CHECK_EQUAL(status.release_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(status.component_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!status.release_qualified());
    BOOST_CHECK(status.component_stored("alpha"));

    BOOST_CHECK(status.Record("release", "ship", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(status.release_stored("ship"));
    BOOST_CHECK_EQUAL(status.release_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!status.release_qualified());

    BOOST_CHECK(!status.Release("ship", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(status.release_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!status.release_qualified());
    BOOST_CHECK(status.release_stored("ship"));

    BOOST_CHECK(!status.Release("", err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(status.release_count(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_CASE(duplicate_component_name_does_not_double_the_count)
{
    modelnet::NifStatus status;
    std::string err;

    BOOST_CHECK(status.Record("component", "alpha", err));
    BOOST_CHECK_EQUAL(status.component_count(), static_cast<int64_t>(1));

    BOOST_CHECK(!status.Record("component", "alpha", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(status.component_count(), static_cast<int64_t>(1));
    BOOST_CHECK(status.component_stored("alpha"));

    BOOST_CHECK(status.Record("component", "beta", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(status.component_count(), static_cast<int64_t>(2));

    BOOST_CHECK(!status.Record("component", "beta", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(status.component_count(), static_cast<int64_t>(2));

    BOOST_CHECK(status.Record("native", "alpha", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(status.native_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(status.component_count(), static_cast<int64_t>(2));
    BOOST_CHECK(status.native_stored("alpha"));
    BOOST_CHECK(status.component_stored("alpha"));

    BOOST_CHECK(!status.Record("native", "alpha", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(status.native_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(status.component_count(), static_cast<int64_t>(2));
}

BOOST_AUTO_TEST_CASE(unknown_kind_is_class_and_empty_name_is_name)
{
    modelnet::NifStatus status;
    std::string err;

    BOOST_CHECK(!status.Record("widget", "alpha", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_STATUS_CLASS);
    BOOST_CHECK_EQUAL(err, "CLASS");
    BOOST_CHECK_EQUAL(status.component_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(status.native_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(status.hardware_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(status.release_count(), static_cast<int64_t>(0));
    BOOST_CHECK(!status.component_stored("alpha"));

    BOOST_CHECK(!status.Record("", "alpha", err));
    BOOST_CHECK_EQUAL(err, "CLASS");
    BOOST_CHECK_EQUAL(status.component_count(), static_cast<int64_t>(0));

    BOOST_CHECK(!status.Record("Component", "alpha", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_STATUS_CLASS);
    BOOST_CHECK(!status.component_stored("alpha"));

    BOOST_CHECK(!status.Record("component", "", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_STATUS_NAME);
    BOOST_CHECK_EQUAL(err, "NAME");
    BOOST_CHECK_EQUAL(status.component_count(), static_cast<int64_t>(0));

    BOOST_CHECK(!status.Record("hardware", "", err));
    BOOST_CHECK_EQUAL(err, "NAME");
    BOOST_CHECK_EQUAL(status.hardware_count(), static_cast<int64_t>(0));
    BOOST_CHECK(!status.hardware_qualified());

    BOOST_CHECK(status.Record("component", "alpha", err));
    BOOST_CHECK(!status.Record("other", "beta", err));
    BOOST_CHECK_EQUAL(err, "CLASS");
    BOOST_CHECK_EQUAL(status.component_count(), static_cast<int64_t>(1));
    BOOST_CHECK(status.component_stored("alpha"));
    BOOST_CHECK(!status.component_stored("beta"));
}

BOOST_AUTO_TEST_CASE(promote_is_unqualified)
{
    modelnet::NifStatus status;
    std::string err;

    BOOST_CHECK(status.Record("component", "alpha", err));
    BOOST_CHECK_EQUAL(status.component_count(), static_cast<int64_t>(1));

    BOOST_CHECK(!status.Promote("alpha", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!status.release_qualified());
    BOOST_CHECK(!status.release_stored("alpha"));
    BOOST_CHECK_EQUAL(status.release_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(status.component_count(), static_cast<int64_t>(1));
    BOOST_CHECK(status.component_stored("alpha"));
    BOOST_CHECK(!status.hardware_qualified());
    BOOST_CHECK(!status.launched());
    BOOST_CHECK(!status.gpu());
    BOOST_CHECK(!status.broadcast());
    BOOST_CHECK_EQUAL(status.automatic_spend(), "0");

    BOOST_CHECK(!status.Promote("missing", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(status.release_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(status.component_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!status.release_qualified());
}

BOOST_AUTO_TEST_CASE(classes_stay_separate)
{
    modelnet::NifStatus status;
    std::string err;

    BOOST_CHECK(status.Record("component", "same", err));
    BOOST_CHECK(status.Record("native", "same", err));
    BOOST_CHECK(status.Record("hardware", "same", err));
    BOOST_CHECK(status.Record("release", "same", err));

    BOOST_CHECK_EQUAL(status.component_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(status.native_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(status.hardware_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(status.release_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!status.hardware_qualified());
    BOOST_CHECK(!status.release_qualified());

    BOOST_CHECK(!status.Record("hardware", "same", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(status.hardware_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!status.hardware_qualified());

    BOOST_CHECK(!status.Record("release", "same", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(status.release_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!status.release_qualified());

    BOOST_CHECK(status.Record("hardware", "other", err));
    BOOST_CHECK_EQUAL(status.hardware_count(), static_cast<int64_t>(2));
    BOOST_CHECK(!status.hardware_qualified());
    BOOST_CHECK_EQUAL(status.component_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(status.native_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(status.release_count(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_SUITE_END()
