// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnospawnside2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnospawnside2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_name_id_yields_name)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSpawnSide2 note;
    const modelnet::SwarmNotNoSpawnSide2Result result = modelnet::SwarmNoteNotNoSpawnSide2(note, err);
    BOOST_CHECK(!result.spawned);
    BOOST_CHECK_EQUAL(result.code, "NAME");
    BOOST_CHECK_EQUAL(err, "NAME");
}

BOOST_AUTO_TEST_CASE(want_spawn_true_yields_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSpawnSide2 note;
    note.name_id = "side-1";
    note.want_spawn = true;
    const modelnet::SwarmNotNoSpawnSide2Result result = modelnet::SwarmNoteNotNoSpawnSide2(note, err);
    BOOST_CHECK(!result.spawned);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(neither_yields_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSpawnSide2 note;
    note.name_id = "side-1";
    note.want_spawn = false;
    const modelnet::SwarmNotNoSpawnSide2Result result = modelnet::SwarmNoteNotNoSpawnSide2(note, err);
    BOOST_CHECK(!result.spawned);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
