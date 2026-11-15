// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_cohort/dt_cohort.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(dt_cohort_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(local_sgd_freezes_and_partition_blocks_commit)
{
    modelnet::DtCohort cohort;
    std::string err;
    BOOST_CHECK(cohort.Admit("a", "base", 1, err));
    BOOST_CHECK(cohort.Admit("b", "base", 1, err));
    BOOST_CHECK(cohort.Freeze(err));
    BOOST_CHECK(!cohort.Admit("c", "base", 1, err));
    BOOST_CHECK_EQUAL(err, "FROZEN");
    BOOST_CHECK(!cohort.OuterUpdate("a", "other", 10, err));
    BOOST_CHECK_EQUAL(err, "BASE");
    BOOST_CHECK(cohort.OuterUpdate("a", "base", 10, err));
    BOOST_CHECK(cohort.OuterUpdate("b", "base", 30, err));
    BOOST_CHECK(cohort.Commit(true, err));
    BOOST_CHECK_EQUAL(cohort.head(), static_cast<int64_t>(20));
    BOOST_CHECK_EQUAL(cohort.head_count(), 1);
    BOOST_CHECK(!cohort.diloco_complete());
    BOOST_CHECK(!cohort.permanent_leader());

    BOOST_CHECK(cohort.Partition(err));
    BOOST_CHECK(!cohort.quorum_available());
    BOOST_CHECK(!cohort.Commit(true, err));
    BOOST_CHECK_EQUAL(err, "PARTITION");
    BOOST_CHECK_EQUAL(cohort.head(), static_cast<int64_t>(20));
    BOOST_CHECK_EQUAL(cohort.head_count(), 1);
    BOOST_CHECK(!cohort.gpu());
    BOOST_CHECK_EQUAL(cohort.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
