// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_fault_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(stale_epoch_commits_nothing)
{
    std::string err = "prior";
    const modelnet::SwarmFaultOutcome stale = modelnet::SwarmRecoverFault(
        modelnet::SwarmFaultKind::CoordinatorGone, true, true, err);
    BOOST_CHECK(!stale.recovered);
    BOOST_CHECK(!stale.stale_committed);
    BOOST_CHECK(!stale.bytes_moved);
    BOOST_CHECK_EQUAL(stale.code, "STALE_EPOCH");
    BOOST_CHECK_EQUAL(err, "STALE_EPOCH");

    const modelnet::SwarmFaultOutcome kind = modelnet::SwarmRecoverFault(
        modelnet::SwarmFaultKind::StaleEpoch, false, false, err);
    BOOST_CHECK(!kind.recovered);
    BOOST_CHECK(!kind.stale_committed);
    BOOST_CHECK(!kind.bytes_moved);
    BOOST_CHECK_EQUAL(kind.code, "STALE_EPOCH");
    BOOST_CHECK_EQUAL(err, "STALE_EPOCH");
}

BOOST_AUTO_TEST_CASE(coordinator_gone_with_and_without_a_durable_claim)
{
    std::string err = "prior";
    const modelnet::SwarmFaultOutcome kept = modelnet::SwarmRecoverFault(
        modelnet::SwarmFaultKind::CoordinatorGone, true, false, err);
    BOOST_CHECK(kept.recovered);
    BOOST_CHECK(!kept.stale_committed);
    BOOST_CHECK(!kept.bytes_moved);
    BOOST_CHECK_EQUAL(kept.code, "DURABLE");
    BOOST_CHECK(err.empty());

    const modelnet::SwarmFaultOutcome lost = modelnet::SwarmRecoverFault(
        modelnet::SwarmFaultKind::CoordinatorGone, false, false, err);
    BOOST_CHECK(!lost.recovered);
    BOOST_CHECK(!lost.stale_committed);
    BOOST_CHECK(!lost.bytes_moved);
    BOOST_CHECK_EQUAL(lost.code, "LOST");
    BOOST_CHECK_EQUAL(err, "LOST");
}

BOOST_AUTO_TEST_CASE(collateral_reuse_moves_no_bytes)
{
    std::string err;
    const modelnet::SwarmFaultOutcome reuse = modelnet::SwarmRecoverFault(
        modelnet::SwarmFaultKind::CollateralReuse, true, false, err);
    BOOST_CHECK(!reuse.recovered);
    BOOST_CHECK(!reuse.stale_committed);
    BOOST_CHECK(!reuse.bytes_moved);
    BOOST_CHECK_EQUAL(reuse.code, "COLLATERAL_REUSE");
    BOOST_CHECK_EQUAL(err, "COLLATERAL_REUSE");
}

BOOST_AUTO_TEST_SUITE_END()
