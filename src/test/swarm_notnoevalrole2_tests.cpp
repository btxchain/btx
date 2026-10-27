// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoevalrole2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoevalrole2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id)
{
    modelnet::SwarmNotNoEvalRole2 note;
    note.node_id.clear();
    note.no_device = true;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoEvalRole2Result result = modelnet::SwarmNoteNotNoEvalRole2(note, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(no_device_evaluator)
{
    modelnet::SwarmNotNoEvalRole2 note;
    note.node_id = "node-1";
    note.no_device = true;
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoEvalRole2Result result = modelnet::SwarmNoteNotNoEvalRole2(note, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "EVALUATOR");
    BOOST_CHECK_EQUAL(err, "EVALUATOR");
}

BOOST_AUTO_TEST_CASE(want_train_held)
{
    modelnet::SwarmNotNoEvalRole2 note;
    note.node_id = "node-1";
    note.no_device = false;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoEvalRole2Result result = modelnet::SwarmNoteNotNoEvalRole2(note, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotNoEvalRole2 note;
    note.node_id = "node-1";
    note.no_device = false;
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoEvalRole2Result result = modelnet::SwarmNoteNotNoEvalRole2(note, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
