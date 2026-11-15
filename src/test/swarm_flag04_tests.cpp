// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag04.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_flag04_tests, BasicTestingSetup)

static void CheckHeldFalse(const modelnet::SwarmFlag04Result& result)
{
    BOOST_CHECK_EQUAL(result.published, false);
    BOOST_CHECK_EQUAL(result.passed, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.gain, 0);
}

BOOST_AUTO_TEST_CASE(empty_cache_id_is_cache)
{
    modelnet::SwarmFlag04 in;
    in.baseline_measured = true;
    in.reuse_measured = true;
    in.want_publish = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag04Result result = modelnet::SwarmStageAccelerate(in, err);
    BOOST_CHECK_EQUAL(result.code, "CACHE");
    CheckHeldFalse(result);
    BOOST_CHECK_EQUAL(err, "CACHE");
}

BOOST_AUTO_TEST_CASE(missing_baseline_is_unmeasured)
{
    modelnet::SwarmFlag04 in;
    in.cache_id = "cache-1";
    in.baseline_measured = false;
    in.reuse_measured = true;
    in.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmFlag04Result result = modelnet::SwarmStageAccelerate(in, err);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    CheckHeldFalse(result);
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(missing_reuse_is_unmeasured)
{
    modelnet::SwarmFlag04 in;
    in.cache_id = "cache-1";
    in.baseline_measured = true;
    in.reuse_measured = false;
    in.want_publish = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag04Result result = modelnet::SwarmStageAccelerate(in, err);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    CheckHeldFalse(result);
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(neither_measured_is_unmeasured)
{
    modelnet::SwarmFlag04 in;
    in.cache_id = "cache-1";
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag04Result result = modelnet::SwarmStageAccelerate(in, err);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    CheckHeldFalse(result);
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(want_publish_is_held)
{
    modelnet::SwarmFlag04 in;
    in.cache_id = "cache-1";
    in.baseline_measured = true;
    in.reuse_measured = true;
    in.want_publish = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag04Result result = modelnet::SwarmStageAccelerate(in, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    CheckHeldFalse(result);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(want_pass_is_unqualified)
{
    modelnet::SwarmFlag04 in;
    in.cache_id = "cache-1";
    in.baseline_measured = true;
    in.reuse_measured = true;
    in.want_publish = false;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag04Result result = modelnet::SwarmStageAccelerate(in, err);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    CheckHeldFalse(result);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(measured_note_is_noted)
{
    modelnet::SwarmFlag04 in;
    in.cache_id = "cache-1";
    in.baseline_measured = true;
    in.reuse_measured = true;
    std::string err = "prior";
    const modelnet::SwarmFlag04Result result = modelnet::SwarmStageAccelerate(in, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    CheckHeldFalse(result);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
