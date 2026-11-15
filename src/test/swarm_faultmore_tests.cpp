// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultmore.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_faultmore_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(replacement_during_expiry)
{
    std::string err = "prior";
    const modelnet::SwarmLiveFaultOutcome expired = modelnet::SwarmLiveFaultCode(
        modelnet::SwarmLiveFault::ReplacementDuringExpiry, true, err);
    BOOST_CHECK(!expired.recovered);
    BOOST_CHECK(!expired.committed);
    BOOST_CHECK(!expired.bytes_moved);
    BOOST_CHECK_EQUAL(expired.code, "LEASE_EXPIRED");
    BOOST_CHECK_EQUAL(err, "LEASE_EXPIRED");
}

BOOST_AUTO_TEST_CASE(durable_worker_disconnect)
{
    std::string err = "prior";
    const modelnet::SwarmLiveFaultOutcome kept = modelnet::SwarmLiveFaultCode(
        modelnet::SwarmLiveFault::WorkerDisconnect, true, err);
    BOOST_CHECK(kept.recovered);
    BOOST_CHECK(!kept.committed);
    BOOST_CHECK(!kept.bytes_moved);
    BOOST_CHECK_EQUAL(kept.code, "DURABLE");
    BOOST_CHECK(err.empty());

    const modelnet::SwarmLiveFaultOutcome lost = modelnet::SwarmLiveFaultCode(
        modelnet::SwarmLiveFault::WorkerDisconnect, false, err);
    BOOST_CHECK(!lost.recovered);
    BOOST_CHECK(!lost.committed);
    BOOST_CHECK(!lost.bytes_moved);
    BOOST_CHECK_EQUAL(lost.code, "LOST");
    BOOST_CHECK_EQUAL(err, "LOST");
}

BOOST_AUTO_TEST_CASE(payment_crash_with_durable_earn)
{
    std::string err = "prior";
    const modelnet::SwarmLiveFaultOutcome earned = modelnet::SwarmLiveFaultCode(
        modelnet::SwarmLiveFault::PaymentCrashAfterEarn, true, err);
    BOOST_CHECK(earned.recovered);
    BOOST_CHECK(!earned.committed);
    BOOST_CHECK(!earned.bytes_moved);
    BOOST_CHECK_EQUAL(earned.code, "EARNED");
    BOOST_CHECK_EQUAL(err, "EARNED");

    const modelnet::SwarmLiveFaultOutcome lost = modelnet::SwarmLiveFaultCode(
        modelnet::SwarmLiveFault::PaymentCrashAfterEarn, false, err);
    BOOST_CHECK(!lost.recovered);
    BOOST_CHECK(!lost.committed);
    BOOST_CHECK(!lost.bytes_moved);
    BOOST_CHECK_EQUAL(lost.code, "LOST");
    BOOST_CHECK_EQUAL(err, "LOST");
}

BOOST_AUTO_TEST_CASE(mass_exit_reorg)
{
    std::string err = "prior";
    const modelnet::SwarmLiveFaultOutcome reorg = modelnet::SwarmLiveFaultCode(
        modelnet::SwarmLiveFault::MassExitReorg, true, err);
    BOOST_CHECK(!reorg.recovered);
    BOOST_CHECK(!reorg.committed);
    BOOST_CHECK(!reorg.bytes_moved);
    BOOST_CHECK_EQUAL(reorg.code, "REORG");
    BOOST_CHECK_EQUAL(err, "REORG");
}

BOOST_AUTO_TEST_SUITE_END()
