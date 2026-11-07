// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/set01/set01.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(set01_tests, BasicTestingSetup)

static void ExpectUnsettled(const modelnet::Set01& eng)
{
    BOOST_CHECK(!eng.settled());
    BOOST_CHECK(eng.txid().empty());
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(unsigned_plan_is_not_settlement)
{
    modelnet::Set01 eng;
    std::string err = "stale";
    const std::string txid(64, 'b');

    BOOST_CHECK(!eng.NoteUnsignedPlan(false, false, "", err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    ExpectUnsettled(eng);

    err = "stale";
    BOOST_CHECK(!eng.NoteUnsignedPlan(false, true, txid, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    ExpectUnsettled(eng);

    err = "stale";
    BOOST_CHECK(!eng.NoteUnsignedPlan(true, false, "", err));
    BOOST_CHECK_EQUAL(err, "UNSIGNED");
    ExpectUnsettled(eng);

    err = "stale";
    BOOST_CHECK(!eng.NoteUnsignedPlan(true, false, txid, err));
    BOOST_CHECK_EQUAL(err, "UNSIGNED");
    ExpectUnsettled(eng);

    err = "stale";
    BOOST_CHECK(!eng.NoteUnsignedPlan(true, true, "", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    ExpectUnsettled(eng);

    err = "stale";
    BOOST_CHECK(eng.NoteUnsignedPlan(true, true, txid, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.settled());
    BOOST_CHECK_EQUAL(eng.txid(), txid);
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
