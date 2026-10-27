// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/set02/set02.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(set02_tests, BasicTestingSetup)

static void ExpectUnsettled(const modelnet::Set02& eng)
{
    BOOST_CHECK(!eng.settled());
    BOOST_CHECK(eng.txid().empty());
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.modes_settled()), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(funded_objective_needs_every_claimed_mode)
{
    modelnet::Set02 eng;
    std::string err = "stale";
    const std::string txid(64, 'c');

    BOOST_CHECK(!eng.Note(true, true, txid, 0, 0, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    ExpectUnsettled(eng);

    err = "stale";
    BOOST_CHECK(!eng.Note(false, true, txid, -1, -1, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    ExpectUnsettled(eng);

    err = "stale";
    BOOST_CHECK(!eng.Note(false, false, "", 2, 2, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    ExpectUnsettled(eng);

    err = "stale";
    BOOST_CHECK(!eng.Note(false, true, txid, 2, 2, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    ExpectUnsettled(eng);

    err = "stale";
    BOOST_CHECK(!eng.Note(true, false, "", 2, 2, err));
    BOOST_CHECK_EQUAL(err, "UNSIGNED");
    ExpectUnsettled(eng);

    err = "stale";
    BOOST_CHECK(!eng.Note(true, false, txid, 2, 2, err));
    BOOST_CHECK_EQUAL(err, "UNSIGNED");
    ExpectUnsettled(eng);

    err = "stale";
    BOOST_CHECK(!eng.Note(true, true, "", 2, 2, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    ExpectUnsettled(eng);

    // One settled mode does not cover two claimed modes.
    err = "stale";
    BOOST_CHECK(!eng.Note(true, true, txid, 2, 1, err));
    BOOST_CHECK_EQUAL(err, "MODE");
    ExpectUnsettled(eng);

    err = "stale";
    BOOST_CHECK(!eng.Note(true, true, txid, 1, -1, err));
    BOOST_CHECK_EQUAL(err, "MODE");
    ExpectUnsettled(eng);

    err = "stale";
    BOOST_CHECK(!eng.Note(true, true, txid, 1, 2, err));
    BOOST_CHECK_EQUAL(err, "MODE");
    ExpectUnsettled(eng);

    err = "stale";
    BOOST_CHECK(eng.Note(true, true, txid, 2, 2, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.settled());
    BOOST_CHECK_EQUAL(eng.txid(), txid);
    BOOST_CHECK_EQUAL(eng.modes_settled(), 2);
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
