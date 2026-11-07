// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_memprof/nif_memprof.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>
#include <string>

BOOST_FIXTURE_TEST_SUITE(nif_memprof_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(reserve_60_model_10_transient_further_40_is_capacity)
{
    modelnet::NifMemProf prof;
    std::string err = "stale";
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(prof.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!prof.advertised());
    BOOST_CHECK(!prof.hardware_qualified());

    BOOST_CHECK(prof.Reserve("model", static_cast<int64_t>(60), static_cast<int64_t>(10), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(70));
    BOOST_CHECK_EQUAL(prof.model_bytes("model"), static_cast<int64_t>(60));
    BOOST_CHECK_EQUAL(prof.transient_bytes("model"), static_cast<int64_t>(10));

    BOOST_CHECK(!prof.Reserve("model", static_cast<int64_t>(40), static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(prof.model_bytes("model"), static_cast<int64_t>(60));
    BOOST_CHECK_EQUAL(prof.transient_bytes("model"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(70));

    BOOST_CHECK(!prof.Reserve("extra", static_cast<int64_t>(40), static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(70));
    BOOST_CHECK_EQUAL(prof.model_bytes("extra"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(prof.transient_bytes("extra"), static_cast<int64_t>(0));
    BOOST_CHECK(!prof.Cancel("extra", err));
    BOOST_CHECK_EQUAL(err, "PROFILE");
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(70));

    BOOST_CHECK(prof.Cancel("model", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(70));
    BOOST_CHECK_EQUAL(prof.model_bytes("model"), static_cast<int64_t>(60));
    BOOST_CHECK_EQUAL(prof.transient_bytes("model"), static_cast<int64_t>(10));

    BOOST_CHECK(!prof.Release("model", err));
    BOOST_CHECK_EQUAL(err, "PINNED");
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(70));

    BOOST_CHECK(prof.Quiesce("model", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(70));

    BOOST_CHECK(prof.Release("model", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(prof.model_bytes("model"), static_cast<int64_t>(60));
    BOOST_CHECK_EQUAL(prof.transient_bytes("model"), static_cast<int64_t>(10));

    BOOST_CHECK(!prof.Release("model", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(0));

    BOOST_CHECK(!prof.Reserve("model", static_cast<int64_t>(60), static_cast<int64_t>(10), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(prof.model_bytes("model"), static_cast<int64_t>(60));
    BOOST_CHECK_EQUAL(prof.transient_bytes("model"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(0));

    const int64_t physical = prof.physical_bytes();
    BOOST_CHECK(!prof.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(prof.physical_bytes(), physical);
    BOOST_CHECK(!prof.advertised());
    BOOST_CHECK(!prof.hardware_qualified());
    BOOST_CHECK(!prof.launched());
    BOOST_CHECK(!prof.gpu());
    BOOST_CHECK(!prof.broadcast());
    BOOST_CHECK_EQUAL(prof.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(prof.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(prof.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(empty_bytes_order_and_overflow_store_nothing)
{
    modelnet::NifMemProf prof;
    std::string err = "stale";

    BOOST_CHECK(!prof.Reserve("", static_cast<int64_t>(60), static_cast<int64_t>(10), err));
    BOOST_CHECK_EQUAL(err, "PROFILE");
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(prof.model_bytes(""), static_cast<int64_t>(0));

    BOOST_CHECK(!prof.Reserve("zero", static_cast<int64_t>(0), static_cast<int64_t>(10), err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(prof.model_bytes("zero"), static_cast<int64_t>(0));

    BOOST_CHECK(!prof.Reserve("neg", static_cast<int64_t>(60), static_cast<int64_t>(-1), err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK_EQUAL(prof.transient_bytes("neg"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(0));

    BOOST_CHECK(!prof.Cancel("missing", err));
    BOOST_CHECK_EQUAL(err, "PROFILE");
    BOOST_CHECK(!prof.Cancel("", err));
    BOOST_CHECK_EQUAL(err, "PROFILE");
    BOOST_CHECK(!prof.Quiesce("missing", err));
    BOOST_CHECK_EQUAL(err, "PROFILE");
    BOOST_CHECK(!prof.Release("missing", err));
    BOOST_CHECK_EQUAL(err, "PROFILE");
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(0));

    BOOST_CHECK(prof.Reserve("held", static_cast<int64_t>(10), static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(10));
    BOOST_CHECK(!prof.Quiesce("held", err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(10));
    BOOST_CHECK(!prof.Release("held", err));
    BOOST_CHECK_EQUAL(err, "PINNED");
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(10));

    BOOST_CHECK(!prof.Reserve("over", std::numeric_limits<int64_t>::max(), static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(prof.model_bytes("over"), static_cast<int64_t>(0));

    BOOST_CHECK(!prof.Reserve("wide", static_cast<int64_t>(91), static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(10));

    BOOST_CHECK(prof.Reserve("fill", static_cast<int64_t>(90), static_cast<int64_t>(0), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(100));
    BOOST_CHECK(!prof.Reserve("one", static_cast<int64_t>(1), static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(100));

    const int64_t physical = prof.physical_bytes();
    BOOST_CHECK(!prof.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(prof.physical_bytes(), physical);
    BOOST_CHECK(!prof.advertised());
    BOOST_CHECK(!prof.hardware_qualified());
    BOOST_CHECK_EQUAL(prof.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!prof.launched());
    BOOST_CHECK(!prof.gpu());
    BOOST_CHECK(!prof.broadcast());
    BOOST_CHECK_EQUAL(prof.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
}

BOOST_AUTO_TEST_CASE(release_subtracts_only_that_reservation)
{
    modelnet::NifMemProf prof;
    std::string err = "stale";

    BOOST_CHECK(prof.Reserve("a", static_cast<int64_t>(60), static_cast<int64_t>(10), err));
    BOOST_CHECK(prof.Reserve("b", static_cast<int64_t>(20), static_cast<int64_t>(5), err));
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(95));
    BOOST_CHECK_EQUAL(prof.model_bytes("a"), static_cast<int64_t>(60));
    BOOST_CHECK_EQUAL(prof.transient_bytes("b"), static_cast<int64_t>(5));

    BOOST_CHECK(prof.Cancel("a", err));
    BOOST_CHECK(!prof.Release("a", err));
    BOOST_CHECK_EQUAL(err, "PINNED");
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(95));

    BOOST_CHECK(prof.Quiesce("a", err));
    BOOST_CHECK(prof.Release("a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(25));
    BOOST_CHECK_EQUAL(prof.model_bytes("a"), static_cast<int64_t>(60));
    BOOST_CHECK_EQUAL(prof.transient_bytes("a"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(prof.model_bytes("b"), static_cast<int64_t>(20));
    BOOST_CHECK_EQUAL(prof.transient_bytes("b"), static_cast<int64_t>(5));

    BOOST_CHECK(!prof.Release("a", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(25));

    BOOST_CHECK(prof.Cancel("b", err));
    BOOST_CHECK(prof.Quiesce("b", err));
    BOOST_CHECK(prof.Release("b", err));
    BOOST_CHECK_EQUAL(prof.physical_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK(!prof.advertised());
    BOOST_CHECK(!prof.hardware_qualified());
    BOOST_CHECK_EQUAL(prof.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(prof.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
