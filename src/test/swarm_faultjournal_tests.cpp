// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultjournal.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_faultjournal_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(twenty_faults_keep_earned_atoms_and_move_no_bytes)
{
    modelnet::SwarmFaultJournal journal;
    journal.Arm(5000, true, true, true);
    std::string err;
    BOOST_CHECK(!journal.Apply(0, err));
    BOOST_CHECK_EQUAL(err, "FAULT");

    const bool recovered_1 = journal.Apply(1, err);
    BOOST_CHECK(recovered_1);
    BOOST_CHECK_EQUAL(journal.code(), "DURABLE");
    BOOST_CHECK_EQUAL(journal.earned_atoms(), 5000);
    BOOST_CHECK_EQUAL(journal.bytes_moved(), 0);

    BOOST_CHECK(!journal.Apply(12, err));
    BOOST_CHECK(!journal.report_accepted());
    BOOST_CHECK_EQUAL(journal.code(), "CONFLICT");

    BOOST_CHECK(!journal.Apply(15, err));
    BOOST_CHECK(journal.frozen());
    BOOST_CHECK_EQUAL(journal.code(), "REORG");
    BOOST_CHECK_EQUAL(journal.earned_atoms(), 5000);

    BOOST_CHECK(!journal.Apply(16, err));
    BOOST_CHECK_EQUAL(err, "COLLATERAL_REUSE");

    BOOST_CHECK(!journal.Apply(18, err));
    BOOST_CHECK(!journal.training());
    BOOST_CHECK_EQUAL(err, "DATASET");

    for (int fault = 1; fault <= 20; ++fault) {
        journal.Arm(5000, true, true, true);
        journal.Apply(fault, err);
        BOOST_CHECK_EQUAL(journal.earned_atoms(), 5000);
        BOOST_CHECK_EQUAL(journal.bytes_moved(), 0);
    }
}

BOOST_AUTO_TEST_SUITE_END()
