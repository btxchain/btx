// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_seqonce.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_seqonce_tests, BasicTestingSetup)

static modelnet::SwarmSequenceBatch NotedBatch()
{
    modelnet::SwarmSequenceBatch batch;
    batch.payments = 1000;
    batch.requested_sequence_steps = 1;
    return batch;
}

BOOST_AUTO_TEST_CASE(payments_below_one_are_sequence)
{
    modelnet::SwarmSequenceBatch batch = NotedBatch();
    batch.payments = 0;
    batch.requested_sequence_steps = 1;
    std::string err = "prior";
    const modelnet::SwarmSequenceBatchResult result = modelnet::SwarmNoteSequenceBatch(batch, err);
    BOOST_CHECK_EQUAL(result.advanced, false);
    BOOST_CHECK_EQUAL(result.code, "SEQUENCE");
    BOOST_CHECK_EQUAL(err, "SEQUENCE");
}

BOOST_AUTO_TEST_CASE(negative_payments_are_sequence)
{
    modelnet::SwarmSequenceBatch batch = NotedBatch();
    batch.payments = -1;
    batch.requested_sequence_steps = 1;
    std::string err = "prior";
    const modelnet::SwarmSequenceBatchResult result = modelnet::SwarmNoteSequenceBatch(batch, err);
    BOOST_CHECK_EQUAL(result.advanced, false);
    BOOST_CHECK_EQUAL(result.code, "SEQUENCE");
    BOOST_CHECK_EQUAL(err, "SEQUENCE");
}

BOOST_AUTO_TEST_CASE(requested_sequence_steps_below_one_are_sequence)
{
    modelnet::SwarmSequenceBatch batch = NotedBatch();
    batch.payments = 1;
    batch.requested_sequence_steps = 0;
    std::string err = "prior";
    const modelnet::SwarmSequenceBatchResult result = modelnet::SwarmNoteSequenceBatch(batch, err);
    BOOST_CHECK_EQUAL(result.advanced, false);
    BOOST_CHECK_EQUAL(result.code, "SEQUENCE");
    BOOST_CHECK_EQUAL(err, "SEQUENCE");
}

BOOST_AUTO_TEST_CASE(negative_requested_sequence_steps_are_sequence)
{
    modelnet::SwarmSequenceBatch batch = NotedBatch();
    batch.payments = 10;
    batch.requested_sequence_steps = -1;
    std::string err = "prior";
    const modelnet::SwarmSequenceBatchResult result = modelnet::SwarmNoteSequenceBatch(batch, err);
    BOOST_CHECK_EQUAL(result.advanced, false);
    BOOST_CHECK_EQUAL(result.code, "SEQUENCE");
    BOOST_CHECK_EQUAL(err, "SEQUENCE");
}

BOOST_AUTO_TEST_CASE(payments_below_one_win_over_once)
{
    modelnet::SwarmSequenceBatch batch = NotedBatch();
    batch.payments = 0;
    batch.requested_sequence_steps = 10;
    std::string err = "prior";
    const modelnet::SwarmSequenceBatchResult result = modelnet::SwarmNoteSequenceBatch(batch, err);
    BOOST_CHECK_EQUAL(result.advanced, false);
    BOOST_CHECK_EQUAL(result.code, "SEQUENCE");
    BOOST_CHECK_EQUAL(err, "SEQUENCE");
}

BOOST_AUTO_TEST_CASE(one_step_per_payment_is_once)
{
    modelnet::SwarmSequenceBatch batch = NotedBatch();
    batch.payments = 10;
    batch.requested_sequence_steps = 10;
    std::string err = "prior";
    const modelnet::SwarmSequenceBatchResult result = modelnet::SwarmNoteSequenceBatch(batch, err);
    BOOST_CHECK_EQUAL(result.advanced, false);
    BOOST_CHECK_EQUAL(result.code, "ONCE");
    BOOST_CHECK_EQUAL(err, "ONCE");
}

BOOST_AUTO_TEST_CASE(one_thousand_payments_with_one_step_are_noted)
{
    modelnet::SwarmSequenceBatch batch = NotedBatch();
    batch.payments = 1000;
    batch.requested_sequence_steps = 1;
    std::string err = "prior";
    const modelnet::SwarmSequenceBatchResult result = modelnet::SwarmNoteSequenceBatch(batch, err);
    BOOST_CHECK_EQUAL(result.advanced, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
