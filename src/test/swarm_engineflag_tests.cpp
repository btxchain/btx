// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_engineflag.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_engineflag_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_engine_is_engine)
{
    std::string err = "prior";
    modelnet::SwarmEngineFlag engine;
    engine.engine_flag = false;
    engine.want_move = true;
    const modelnet::SwarmEngineFlagResult result = modelnet::SwarmNoteEngineFlag(engine, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "ENGINE");
    BOOST_CHECK_EQUAL(err, "ENGINE");
}

BOOST_AUTO_TEST_CASE(engine_flag_is_not_transfer)
{
    std::string err = "prior";
    modelnet::SwarmEngineFlag engine;
    engine.engine_id = "engine-1";
    engine.engine_flag = true;
    engine.want_move = false;
    const modelnet::SwarmEngineFlagResult result = modelnet::SwarmNoteEngineFlag(engine, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_TRANSFER");
    BOOST_CHECK_EQUAL(err, "NOT_TRANSFER");
}

BOOST_AUTO_TEST_CASE(want_move_is_held)
{
    std::string err = "prior";
    modelnet::SwarmEngineFlag engine;
    engine.engine_id = "engine-1";
    engine.engine_flag = false;
    engine.want_move = true;
    const modelnet::SwarmEngineFlagResult result = modelnet::SwarmNoteEngineFlag(engine, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmEngineFlag engine;
    engine.engine_id = "engine-1";
    engine.engine_flag = false;
    engine.want_move = false;
    const modelnet::SwarmEngineFlagResult result = modelnet::SwarmNoteEngineFlag(engine, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
