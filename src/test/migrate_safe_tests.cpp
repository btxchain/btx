// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/migrate_safe/migrate_safe.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::MigrateSafe& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(migrate_safe_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(store_rejects_empty_and_negative)
{
    modelnet::MigrateSafe eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.present("case"));
    BOOST_CHECK(!eng.failed());
    BOOST_CHECK(!eng.Store("", "case-body", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(err, modelnet::MIGRATE_SAFE_FIELD);
    BOOST_CHECK(!eng.present(""));
    BOOST_CHECK(!eng.present("case"));

    BOOST_CHECK(!eng.Store("case", "", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.present("case"));

    BOOST_CHECK(!eng.Store("", "", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, "FIELD");

    BOOST_CHECK(!eng.Store("case", "case-body", static_cast<int64_t>(-1), err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(err, modelnet::MIGRATE_SAFE_BOUND);
    BOOST_CHECK(!eng.present("case"));
    BOOST_CHECK_EQUAL(eng.assurance("case"), static_cast<int64_t>(0));

    BOOST_CHECK(eng.Store("case", "case-body", static_cast<int64_t>(0), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.present("case"));
    BOOST_CHECK_EQUAL(eng.body("case"), "case-body");
    BOOST_CHECK_EQUAL(eng.assurance("case"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Store("case", "", static_cast<int64_t>(3), err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(eng.body("case"), "case-body");
    BOOST_CHECK_EQUAL(eng.assurance("case"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Store("case", "case-body", static_cast<int64_t>(-5), err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.body("case"), "case-body");
    BOOST_CHECK_EQUAL(eng.assurance("case"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
    BOOST_CHECK_EQUAL(eng.body("case"), "case-body");
    BOOST_CHECK_EQUAL(eng.assurance("case"), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(upgrade_refusal_keeps_body)
{
    modelnet::MigrateSafe eng;
    std::string err = "stale";

    BOOST_CHECK(eng.Store("pool", "pool-body", static_cast<int64_t>(2), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.body("pool"), "pool-body");
    BOOST_CHECK_EQUAL(eng.assurance("pool"), static_cast<int64_t>(2));

    BOOST_CHECK(!eng.Move("pool", static_cast<int64_t>(3), err));
    BOOST_CHECK_EQUAL(err, "UPGRADE");
    BOOST_CHECK_EQUAL(err, modelnet::MIGRATE_SAFE_UPGRADE);
    BOOST_CHECK_EQUAL(eng.body("pool"), "pool-body");
    BOOST_CHECK_EQUAL(eng.assurance("pool"), static_cast<int64_t>(2));
    BOOST_CHECK(!eng.failed());

    BOOST_CHECK(!eng.Move("missing", static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(err, modelnet::MIGRATE_SAFE_ID);
    BOOST_CHECK(!eng.present("missing"));
    BOOST_CHECK_EQUAL(eng.body("pool"), "pool-body");
    BOOST_CHECK_EQUAL(eng.assurance("pool"), static_cast<int64_t>(2));

    BOOST_CHECK(eng.Move("pool", static_cast<int64_t>(2), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.body("pool"), "pool-body");
    BOOST_CHECK_EQUAL(eng.assurance("pool"), static_cast<int64_t>(2));

    BOOST_CHECK(eng.Move("pool", static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.body("pool"), "pool-body");
    BOOST_CHECK_EQUAL(eng.assurance("pool"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
    BOOST_CHECK_EQUAL(eng.body("pool"), "pool-body");
    BOOST_CHECK_EQUAL(eng.assurance("pool"), static_cast<int64_t>(2));
}

BOOST_AUTO_TEST_CASE(failed_move_keeps_body)
{
    modelnet::MigrateSafe eng;
    std::string err = "stale";

    BOOST_CHECK(eng.Store("case", "case-body", static_cast<int64_t>(4), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.body("case"), "case-body");
    BOOST_CHECK_EQUAL(eng.assurance("case"), static_cast<int64_t>(4));

    eng.Fail();
    BOOST_CHECK(eng.failed());
    BOOST_CHECK_EQUAL(eng.body("case"), "case-body");
    BOOST_CHECK_EQUAL(eng.assurance("case"), static_cast<int64_t>(4));

    BOOST_CHECK(!eng.Move("case", static_cast<int64_t>(4), err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK_EQUAL(err, modelnet::MIGRATE_SAFE_JOURNAL);
    BOOST_CHECK_EQUAL(eng.body("case"), "case-body");
    BOOST_CHECK_EQUAL(eng.assurance("case"), static_cast<int64_t>(4));
    BOOST_CHECK(eng.failed());

    BOOST_CHECK(!eng.Move("case", static_cast<int64_t>(9), err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK_EQUAL(eng.body("case"), "case-body");
    BOOST_CHECK_EQUAL(eng.assurance("case"), static_cast<int64_t>(4));

    BOOST_CHECK(!eng.Move("other", static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK(!eng.present("other"));
    BOOST_CHECK_EQUAL(eng.body("case"), "case-body");

    Idle(eng);
    BOOST_CHECK(eng.failed());
    BOOST_CHECK_EQUAL(eng.body("case"), "case-body");
    BOOST_CHECK_EQUAL(eng.assurance("case"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    eng.Clear();
    BOOST_CHECK(!eng.failed());
    BOOST_CHECK_EQUAL(eng.body("case"), "case-body");
    BOOST_CHECK_EQUAL(eng.assurance("case"), static_cast<int64_t>(4));

    BOOST_CHECK(eng.Move("case", static_cast<int64_t>(4), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.body("case"), "case-body");
    BOOST_CHECK_EQUAL(eng.assurance("case"), static_cast<int64_t>(4));

    BOOST_CHECK(!eng.Move("case", static_cast<int64_t>(5), err));
    BOOST_CHECK_EQUAL(err, "UPGRADE");
    BOOST_CHECK_EQUAL(eng.body("case"), "case-body");
    BOOST_CHECK_EQUAL(eng.assurance("case"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
    BOOST_CHECK_EQUAL(eng.body("case"), "case-body");
    BOOST_CHECK(!eng.failed());
}

BOOST_AUTO_TEST_SUITE_END()
