// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_lmcacheops.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_lmcacheops_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_engine)
{
    modelnet::SwarmLmcacheOps engine;
    engine.engine_id.clear();
    engine.ops_absent = true;
    engine.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmLmcacheOpsResult result = modelnet::SwarmNoteLmcacheOps(engine, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "ENGINE");
    BOOST_CHECK_EQUAL(err, "ENGINE");
}

BOOST_AUTO_TEST_CASE(ops_absent_want_move_false)
{
    modelnet::SwarmLmcacheOps engine;
    engine.engine_id = "engine-1";
    engine.ops_absent = true;
    engine.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmLmcacheOpsResult result = modelnet::SwarmNoteLmcacheOps(engine, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(want_move_ops_present)
{
    modelnet::SwarmLmcacheOps engine;
    engine.engine_id = "engine-1";
    engine.ops_absent = false;
    engine.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmLmcacheOpsResult result = modelnet::SwarmNoteLmcacheOps(engine, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(ops_present_want_move_false)
{
    modelnet::SwarmLmcacheOps engine;
    engine.engine_id = "engine-1";
    engine.ops_absent = false;
    engine.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmLmcacheOpsResult result = modelnet::SwarmNoteLmcacheOps(engine, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
