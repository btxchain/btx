// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notseeder.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notseeder_tests, BasicTestingSetup)

static modelnet::SwarmNotSeeder NotedNote()
{
    modelnet::SwarmNotSeeder note;
    note.node_id = "node-1";
    note.device_present = true;
    note.want_train = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmNotSeeder note = NotedNote();
    note.node_id.clear();
    note.device_present = true;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotSeederResult result = modelnet::SwarmNoteNotSeeder(note, err);
    BOOST_CHECK(!result.seeding);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.slots, 0);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(absent_device_is_public_seed)
{
    modelnet::SwarmNotSeeder note = NotedNote();
    note.device_present = false;
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotSeederResult result = modelnet::SwarmNoteNotSeeder(note, err);
    BOOST_CHECK(!result.seeding);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.slots, 0);
    BOOST_CHECK_EQUAL(result.code, "PUBLIC_SEED");
    BOOST_CHECK_EQUAL(err, "PUBLIC_SEED");
}

BOOST_AUTO_TEST_CASE(present_device_want_train_is_cpu_only)
{
    modelnet::SwarmNotSeeder note = NotedNote();
    note.device_present = true;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotSeederResult result = modelnet::SwarmNoteNotSeeder(note, err);
    BOOST_CHECK(!result.seeding);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.slots, 0);
    BOOST_CHECK_EQUAL(result.code, "CPU_ONLY");
    BOOST_CHECK_EQUAL(err, "CPU_ONLY");
}

BOOST_AUTO_TEST_CASE(present_device_plain_is_noted)
{
    modelnet::SwarmNotSeeder note = NotedNote();
    note.device_present = true;
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotSeederResult result = modelnet::SwarmNoteNotSeeder(note, err);
    BOOST_CHECK(!result.seeding);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.slots, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
