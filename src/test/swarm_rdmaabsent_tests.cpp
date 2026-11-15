// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rdmaabsent.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_rdmaabsent_tests, BasicTestingSetup)

static modelnet::SwarmRdmaAbsent NotedEngine()
{
    modelnet::SwarmRdmaAbsent engine;
    engine.engine_id = "engine-1";
    engine.adapter_absent = false;
    engine.want_move = false;
    return engine;
}

BOOST_AUTO_TEST_CASE(empty_engine_is_engine)
{
    modelnet::SwarmRdmaAbsent engine = NotedEngine();
    engine.engine_id.clear();
    std::string err = "prior";
    const modelnet::SwarmRdmaAbsentResult result = modelnet::SwarmNoteRdmaAbsent(engine, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "ENGINE");
    BOOST_CHECK_EQUAL(err, "ENGINE");
}

BOOST_AUTO_TEST_CASE(adapter_absent_without_move_is_engine_absent)
{
    modelnet::SwarmRdmaAbsent engine = NotedEngine();
    engine.adapter_absent = true;
    engine.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmRdmaAbsentResult result = modelnet::SwarmNoteRdmaAbsent(engine, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(want_move_without_absent_is_held)
{
    modelnet::SwarmRdmaAbsent engine = NotedEngine();
    engine.want_move = true;
    engine.adapter_absent = false;
    std::string err = "prior";
    const modelnet::SwarmRdmaAbsentResult result = modelnet::SwarmNoteRdmaAbsent(engine, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(present_adapter_without_move_is_noted)
{
    modelnet::SwarmRdmaAbsent engine = NotedEngine();
    engine.adapter_absent = false;
    engine.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmRdmaAbsentResult result = modelnet::SwarmNoteRdmaAbsent(engine, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
