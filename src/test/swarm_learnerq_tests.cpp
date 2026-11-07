// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_learnerq.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_learnerq_tests, BasicTestingSetup)

static modelnet::SwarmLearnerItem ClearItem()
{
    modelnet::SwarmLearnerItem item;
    item.queue_id = "queue-1";
    item.policy_id = "policy-1";
    item.item_id = "item-1";
    item.credential = false;
    item.private_data = false;
    item.want_run = false;
    return item;
}

BOOST_AUTO_TEST_CASE(empty_queue_is_queue)
{
    modelnet::SwarmLearnerItem item = ClearItem();
    item.queue_id.clear();
    std::string err = "prior";
    const modelnet::SwarmLearnerResult result = modelnet::SwarmEnqueueLearner(item, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK(!result.queued);
    BOOST_CHECK_EQUAL(result.depth, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "QUEUE");
    BOOST_CHECK_EQUAL(err, "QUEUE");
}

BOOST_AUTO_TEST_CASE(empty_policy_is_policy)
{
    modelnet::SwarmLearnerItem item = ClearItem();
    item.policy_id.clear();
    std::string err = "prior";
    const modelnet::SwarmLearnerResult result = modelnet::SwarmEnqueueLearner(item, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK(!result.queued);
    BOOST_CHECK_EQUAL(result.depth, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "POLICY");
    BOOST_CHECK_EQUAL(err, "POLICY");
}

BOOST_AUTO_TEST_CASE(credential_is_credential)
{
    modelnet::SwarmLearnerItem item = ClearItem();
    item.credential = true;
    item.want_run = false;
    std::string err = "prior";
    const modelnet::SwarmLearnerResult result = modelnet::SwarmEnqueueLearner(item, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK(!result.queued);
    BOOST_CHECK_EQUAL(result.depth, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "CREDENTIAL");
    BOOST_CHECK_EQUAL(err, "CREDENTIAL");
}

BOOST_AUTO_TEST_CASE(private_data_is_private)
{
    modelnet::SwarmLearnerItem item = ClearItem();
    item.private_data = true;
    std::string err = "prior";
    const modelnet::SwarmLearnerResult result = modelnet::SwarmEnqueueLearner(item, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK(!result.queued);
    BOOST_CHECK_EQUAL(result.depth, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "PRIVATE");
    BOOST_CHECK_EQUAL(err, "PRIVATE");
}

BOOST_AUTO_TEST_CASE(empty_item_is_item)
{
    modelnet::SwarmLearnerItem item = ClearItem();
    item.item_id.clear();
    std::string err = "prior";
    const modelnet::SwarmLearnerResult result = modelnet::SwarmEnqueueLearner(item, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK(!result.queued);
    BOOST_CHECK_EQUAL(result.depth, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "ITEM");
    BOOST_CHECK_EQUAL(err, "ITEM");
}

BOOST_AUTO_TEST_CASE(want_run_true_is_held)
{
    modelnet::SwarmLearnerItem item = ClearItem();
    item.want_run = true;
    std::string err = "prior";
    const modelnet::SwarmLearnerResult result = modelnet::SwarmEnqueueLearner(item, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK(result.queued);
    BOOST_CHECK_EQUAL(result.depth, static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_run_false_is_noted)
{
    modelnet::SwarmLearnerItem item = ClearItem();
    item.want_run = false;
    std::string err = "prior";
    const modelnet::SwarmLearnerResult result = modelnet::SwarmEnqueueLearner(item, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK(result.queued);
    BOOST_CHECK_EQUAL(result.depth, static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
