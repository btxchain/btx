// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_vram.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_vram_tests, BasicTestingSetup)

static modelnet::SwarmVramTrain NotedTrain()
{
    modelnet::SwarmVramTrain train;
    train.node_id = "node-local";
    train.vram_mib = 16311;
    train.license_allows_training = true;
    train.want_train = false;
    return train;
}

static void ExpectTrainingStaysFalse(const modelnet::SwarmVramTrainResult& result)
{
    BOOST_CHECK(!result.training);
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_vram)
{
    modelnet::SwarmVramTrain train = NotedTrain();
    train.node_id.clear();
    std::string err = "prior";
    const modelnet::SwarmVramTrainResult result = modelnet::SwarmNoteVramTrain(train, err);
    ExpectTrainingStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "VRAM");
    BOOST_CHECK_EQUAL(err, "VRAM");
}

BOOST_AUTO_TEST_CASE(empty_node_id_wins_over_negative_vram_and_want_train)
{
    modelnet::SwarmVramTrain train = NotedTrain();
    train.node_id.clear();
    train.vram_mib = -1;
    train.license_allows_training = true;
    train.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmVramTrainResult result = modelnet::SwarmNoteVramTrain(train, err);
    ExpectTrainingStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "VRAM");
    BOOST_CHECK_EQUAL(err, "VRAM");
}

BOOST_AUTO_TEST_CASE(negative_vram_is_vram)
{
    modelnet::SwarmVramTrain train = NotedTrain();
    train.vram_mib = -1;
    train.license_allows_training = true;
    train.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmVramTrainResult result = modelnet::SwarmNoteVramTrain(train, err);
    ExpectTrainingStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "VRAM");
    BOOST_CHECK_EQUAL(err, "VRAM");
}

BOOST_AUTO_TEST_CASE(zero_vram_with_license_and_want_train_is_cpu_only)
{
    modelnet::SwarmVramTrain train = NotedTrain();
    train.vram_mib = 0;
    train.license_allows_training = true;
    train.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmVramTrainResult result = modelnet::SwarmNoteVramTrain(train, err);
    ExpectTrainingStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "CPU_ONLY");
    BOOST_CHECK_EQUAL(err, "CPU_ONLY");
}

BOOST_AUTO_TEST_CASE(missing_training_grant_with_want_train_is_cpu_only)
{
    modelnet::SwarmVramTrain train = NotedTrain();
    train.vram_mib = 16311;
    train.license_allows_training = false;
    train.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmVramTrainResult result = modelnet::SwarmNoteVramTrain(train, err);
    ExpectTrainingStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "CPU_ONLY");
    BOOST_CHECK_EQUAL(err, "CPU_ONLY");
}

BOOST_AUTO_TEST_CASE(zero_vram_and_missing_grant_with_want_train_is_cpu_only)
{
    modelnet::SwarmVramTrain train = NotedTrain();
    train.vram_mib = 0;
    train.license_allows_training = false;
    train.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmVramTrainResult result = modelnet::SwarmNoteVramTrain(train, err);
    ExpectTrainingStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "CPU_ONLY");
    BOOST_CHECK_EQUAL(err, "CPU_ONLY");
}

BOOST_AUTO_TEST_CASE(want_train_with_vram_and_license_is_held)
{
    modelnet::SwarmVramTrain train = NotedTrain();
    train.vram_mib = 16311;
    train.license_allows_training = true;
    train.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmVramTrainResult result = modelnet::SwarmNoteVramTrain(train, err);
    ExpectTrainingStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(vram_and_license_without_want_train_is_noted)
{
    modelnet::SwarmVramTrain train = NotedTrain();
    train.vram_mib = 16311;
    train.license_allows_training = true;
    train.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmVramTrainResult result = modelnet::SwarmNoteVramTrain(train, err);
    ExpectTrainingStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(zero_vram_without_want_train_is_noted)
{
    modelnet::SwarmVramTrain train = NotedTrain();
    train.vram_mib = 0;
    train.license_allows_training = false;
    train.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmVramTrainResult result = modelnet::SwarmNoteVramTrain(train, err);
    ExpectTrainingStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
