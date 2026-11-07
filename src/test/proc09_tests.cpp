// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/proc09/proc09.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(proc09_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(deliver_exact)
{
    modelnet::Proc09 eng;
    std::string err = "stale";
    const std::vector<std::string> blockers{"gate-a", "gate-b"};

    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK(eng.fingerprint().empty());
    BOOST_CHECK(eng.log_digest().empty());
    BOOST_CHECK_EQUAL(eng.blocker_count(), 0);

    BOOST_CHECK(!eng.ClaimTaskCount(4, err));
    BOOST_CHECK_EQUAL(err, "CLAIM");
    BOOST_CHECK_EQUAL(eng.blocker_count(), 0);
    BOOST_CHECK(eng.fingerprint().empty());
    BOOST_CHECK(eng.log_digest().empty());

    BOOST_CHECK(!eng.Deliver("", "log-1", blockers, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.Deliver("fp-1", "", blockers, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.Deliver("fp-1", "log-1", {}, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.Deliver("fp-1", "log-1", {""}, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.Deliver("fp-1", "log-1", {"gate-a", ""}, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(eng.fingerprint().empty());
    BOOST_CHECK(eng.log_digest().empty());
    BOOST_CHECK_EQUAL(eng.blocker_count(), 0);

    BOOST_CHECK(eng.Deliver("fp-1", "log-1", blockers, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.fingerprint(), "fp-1");
    BOOST_CHECK_EQUAL(eng.log_digest(), "log-1");
    BOOST_CHECK_EQUAL(eng.blocker_count(), 2);
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());

    BOOST_CHECK(!eng.Deliver("fp-2", "log-2", {"other"}, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.fingerprint(), "fp-1");
    BOOST_CHECK_EQUAL(eng.log_digest(), "log-1");
    BOOST_CHECK_EQUAL(eng.blocker_count(), 2);

    BOOST_CHECK(!eng.Deliver("", "log-2", blockers, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(eng.fingerprint(), "fp-1");
    BOOST_CHECK_EQUAL(eng.log_digest(), "log-1");
    BOOST_CHECK_EQUAL(eng.blocker_count(), 2);

    BOOST_CHECK(!eng.ClaimTaskCount(9, err));
    BOOST_CHECK_EQUAL(err, "CLAIM");
    BOOST_CHECK_EQUAL(eng.blocker_count(), 2);
    BOOST_CHECK_EQUAL(eng.fingerprint(), "fp-1");
    BOOST_CHECK_EQUAL(eng.log_digest(), "log-1");
    BOOST_CHECK(!eng.ClaimTaskCount(0, err));
    BOOST_CHECK_EQUAL(err, "CLAIM");
    BOOST_CHECK_EQUAL(eng.blocker_count(), 2);
    BOOST_CHECK(!eng.ClaimTaskCount(-1, err));
    BOOST_CHECK_EQUAL(err, "CLAIM");
    BOOST_CHECK_EQUAL(eng.blocker_count(), 2);

    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
