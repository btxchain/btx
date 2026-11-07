// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_earnkeep.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_earnkeep_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_row_id_is_row)
{
    modelnet::SwarmEarnKeep row;
    row.atoms = 1000;
    row.coordinator_gone = true;
    row.want_drop = true;
    row.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmEarnKeepResult result = modelnet::SwarmKeepEarned(row, err);
    BOOST_CHECK(!result.dropped);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "ROW");
    BOOST_CHECK_EQUAL(err, "ROW");
}

BOOST_AUTO_TEST_CASE(negative_atoms_is_range)
{
    modelnet::SwarmEarnKeep row;
    row.row_id = "row-1";
    row.atoms = -1;
    row.coordinator_gone = false;
    row.want_drop = false;
    row.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmEarnKeepResult result = modelnet::SwarmKeepEarned(row, err);
    BOOST_CHECK(!result.dropped);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "RANGE");
    BOOST_CHECK_EQUAL(err, "RANGE");
}

BOOST_AUTO_TEST_CASE(coordinator_gone_is_stays)
{
    modelnet::SwarmEarnKeep row;
    row.row_id = "row-1";
    row.atoms = 1000;
    row.coordinator_gone = true;
    row.want_drop = false;
    row.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmEarnKeepResult result = modelnet::SwarmKeepEarned(row, err);
    BOOST_CHECK(!result.dropped);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, int64_t{1000});
    BOOST_CHECK_EQUAL(result.code, "STAYS");
    BOOST_CHECK_EQUAL(err, "STAYS");
}

BOOST_AUTO_TEST_CASE(want_spend_is_held)
{
    modelnet::SwarmEarnKeep row;
    row.row_id = "row-1";
    row.atoms = 1000;
    row.coordinator_gone = false;
    row.want_drop = false;
    row.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmEarnKeepResult result = modelnet::SwarmKeepEarned(row, err);
    BOOST_CHECK(!result.dropped);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, int64_t{1000});
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_row_is_noted)
{
    modelnet::SwarmEarnKeep row;
    row.row_id = "row-1";
    row.atoms = 1000;
    row.coordinator_gone = false;
    row.want_drop = false;
    row.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmEarnKeepResult result = modelnet::SwarmKeepEarned(row, err);
    BOOST_CHECK(!result.dropped);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, int64_t{1000});
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
