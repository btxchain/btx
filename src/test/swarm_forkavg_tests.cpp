// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_forkavg.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_forkavg_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_branch)
{
    modelnet::SwarmForkAvg branch;
    branch.branch_id.clear();
    branch.compatible = true;
    branch.want_average = false;
    std::string err;
    const modelnet::SwarmForkAvgResult result = modelnet::SwarmNoteForkAverage(branch, err);
    BOOST_CHECK_EQUAL(result.code, "BRANCH");
    BOOST_CHECK_EQUAL(err, "BRANCH");
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
}

BOOST_AUTO_TEST_CASE(incompatible_not_averaged)
{
    modelnet::SwarmForkAvg branch;
    branch.branch_id = "fork-1";
    branch.compatible = false;
    branch.want_average = false;
    std::string err;
    const modelnet::SwarmForkAvgResult result = modelnet::SwarmNoteForkAverage(branch, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_AVERAGED");
    BOOST_CHECK_EQUAL(err, "NOT_AVERAGED");
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
}

BOOST_AUTO_TEST_CASE(want_average_held)
{
    modelnet::SwarmForkAvg branch;
    branch.branch_id = "fork-2";
    branch.compatible = true;
    branch.want_average = true;
    std::string err;
    const modelnet::SwarmForkAvgResult result = modelnet::SwarmNoteForkAverage(branch, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmForkAvg branch;
    branch.branch_id = "fork-3";
    branch.compatible = true;
    branch.want_average = false;
    std::string err = "stale";
    const modelnet::SwarmForkAvgResult result = modelnet::SwarmNoteForkAverage(branch, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
}

BOOST_AUTO_TEST_SUITE_END()
