// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp29/grp29.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp29& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(eng.monetary_ok());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(grp29_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(fail_after_store_keeps_amount)
{
    modelnet::Grp29 eng;
    std::string err = "stale";

    BOOST_CHECK_EQUAL(eng.stored(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.worker_failed());
    BOOST_CHECK(eng.monetary_ok());
    BOOST_CHECK_EQUAL(eng.generation(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Store(static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK_EQUAL(err, modelnet::GRP29_BYTES);
    BOOST_CHECK_EQUAL(eng.stored(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Store(static_cast<int64_t>(-1), err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK_EQUAL(eng.stored(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.worker_failed());

    BOOST_CHECK(eng.Store(static_cast<int64_t>(40), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored(), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(eng.generation(), static_cast<int64_t>(0));

    BOOST_CHECK(eng.FailWorker(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.worker_failed());
    BOOST_CHECK(eng.monetary_ok());
    BOOST_CHECK_EQUAL(eng.stored(), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(eng.generation(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Store(static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK(eng.worker_failed());
    BOOST_CHECK_EQUAL(eng.stored(), static_cast<int64_t>(40));
    BOOST_CHECK(eng.monetary_ok());
    Idle(eng);
    BOOST_CHECK_EQUAL(eng.stored(), static_cast<int64_t>(40));
    BOOST_CHECK(eng.worker_failed());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(advance_waits_until_journal_accepts)
{
    modelnet::Grp29 eng;
    std::string err = "stale";

    BOOST_CHECK_EQUAL(eng.generation(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Advance(false, err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK_EQUAL(err, modelnet::GRP29_ORDER);
    BOOST_CHECK_EQUAL(eng.generation(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.stored(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Advance(true, err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK_EQUAL(eng.generation(), static_cast<int64_t>(0));

    BOOST_CHECK(eng.Store(static_cast<int64_t>(40), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored(), static_cast<int64_t>(40));

    BOOST_CHECK(!eng.Advance(false, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK_EQUAL(err, modelnet::GRP29_JOURNAL);
    BOOST_CHECK_EQUAL(eng.generation(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.stored(), static_cast<int64_t>(40));
    BOOST_CHECK(!eng.worker_failed());
    BOOST_CHECK(eng.monetary_ok());

    BOOST_CHECK(eng.Advance(true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.generation(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.stored(), static_cast<int64_t>(40));

    BOOST_CHECK(!eng.Advance(true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.generation(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.stored(), static_cast<int64_t>(40));

    BOOST_CHECK(!eng.Advance(false, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK_EQUAL(eng.generation(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.stored(), static_cast<int64_t>(40));

    BOOST_CHECK(eng.FailWorker(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.worker_failed());
    BOOST_CHECK(eng.monetary_ok());
    BOOST_CHECK_EQUAL(eng.stored(), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(eng.generation(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
    BOOST_CHECK_EQUAL(eng.stored(), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(eng.generation(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_SUITE_END()
