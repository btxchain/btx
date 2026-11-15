// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_scaleexec.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_scaleexec_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_scale_is_timescale)
{
    std::string err;
    const modelnet::SwarmScaleExecResult result = modelnet::SwarmExecuteTimescale("", true, err);
    BOOST_CHECK(!result.executed);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "TIMESCALE");
    BOOST_CHECK_EQUAL(err, "TIMESCALE");
}

BOOST_AUTO_TEST_CASE(unknown_scale_is_timescale)
{
    std::string err;
    const modelnet::SwarmScaleExecResult result = modelnet::SwarmExecuteTimescale("weekly", true, err);
    BOOST_CHECK(!result.executed);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "TIMESCALE");
    BOOST_CHECK_EQUAL(err, "TIMESCALE");
}

BOOST_AUTO_TEST_CASE(medium_with_record_is_train_absent)
{
    std::string err;
    const modelnet::SwarmScaleExecResult result = modelnet::SwarmExecuteTimescale("medium", true, err);
    BOOST_CHECK(!result.executed);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "TRAIN_ABSENT");
    BOOST_CHECK_EQUAL(err, "TRAIN_ABSENT");
}

BOOST_AUTO_TEST_CASE(long_with_record_is_train_absent)
{
    std::string err;
    const modelnet::SwarmScaleExecResult result = modelnet::SwarmExecuteTimescale("long", true, err);
    BOOST_CHECK(!result.executed);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "TRAIN_ABSENT");
    BOOST_CHECK_EQUAL(err, "TRAIN_ABSENT");
}

BOOST_AUTO_TEST_CASE(immediate_with_record_is_record_only)
{
    std::string err = "prior";
    const modelnet::SwarmScaleExecResult result = modelnet::SwarmExecuteTimescale("immediate", true, err);
    BOOST_CHECK(!result.executed);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "RECORD_ONLY");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(short_without_record_is_not_found)
{
    std::string err;
    const modelnet::SwarmScaleExecResult result = modelnet::SwarmExecuteTimescale("short", false, err);
    BOOST_CHECK(!result.executed);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_FOUND");
    BOOST_CHECK_EQUAL(err, "NOT_FOUND");
}

BOOST_AUTO_TEST_SUITE_END()
