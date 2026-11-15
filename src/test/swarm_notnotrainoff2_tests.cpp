// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotrainoff2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnotrainoff2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id)
{
    modelnet::SwarmNotNoTrainOff2 note;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoTrainOff2Result result = modelnet::SwarmNoteNotNoTrainOff2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK(!result.training);
    BOOST_CHECK(!result.gpu);
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_train)
{
    modelnet::SwarmNotNoTrainOff2 note;
    note.node_id = "node-1";
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoTrainOff2Result result = modelnet::SwarmNoteNotNoTrainOff2(note, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.training);
    BOOST_CHECK(!result.gpu);
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotNoTrainOff2 note;
    note.node_id = "node-1";
    std::string err = "prior";
    const modelnet::SwarmNotNoTrainOff2Result result = modelnet::SwarmNoteNotNoTrainOff2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.training);
    BOOST_CHECK(!result.gpu);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
