// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_distill.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_distill_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_op_is_model_op)
{
    std::string err = "prior";
    modelnet::SwarmModelOpRequest request;
    request.op = "average";
    request.evidence_present = true;
    request.evaluated = true;
    const modelnet::SwarmModelOpResult result = modelnet::SwarmClassifyModelOp(request, err);
    BOOST_CHECK(!result.performed);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK_EQUAL(result.code, "MODEL_OP");
    BOOST_CHECK_EQUAL(err, "MODEL_OP");

    request.op = "";
    std::string err_empty = "prior";
    const modelnet::SwarmModelOpResult empty = modelnet::SwarmClassifyModelOp(request, err_empty);
    BOOST_CHECK(!empty.performed);
    BOOST_CHECK(!empty.averaged);
    BOOST_CHECK_EQUAL(empty.code, "MODEL_OP");
    BOOST_CHECK_EQUAL(err_empty, "MODEL_OP");
}

BOOST_AUTO_TEST_CASE(missing_evidence_is_evidence)
{
    std::string err = "prior";
    modelnet::SwarmModelOpRequest request;
    request.op = "merge";
    request.evidence_present = false;
    request.evaluated = true;
    const modelnet::SwarmModelOpResult result = modelnet::SwarmClassifyModelOp(request, err);
    BOOST_CHECK(!result.performed);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK_EQUAL(result.code, "EVIDENCE");
    BOOST_CHECK_EQUAL(err, "EVIDENCE");
}

BOOST_AUTO_TEST_CASE(unevaluated_merge_is_unevaluated)
{
    std::string err = "prior";
    modelnet::SwarmModelOpRequest request;
    request.op = "merge";
    request.evidence_present = true;
    request.evaluated = false;
    const modelnet::SwarmModelOpResult result = modelnet::SwarmClassifyModelOp(request, err);
    BOOST_CHECK(!result.performed);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK_EQUAL(result.code, "UNEVALUATED");
    BOOST_CHECK_EQUAL(err, "UNEVALUATED");
}

BOOST_AUTO_TEST_CASE(recorded_merge_is_not_performed)
{
    std::string err = "prior";
    modelnet::SwarmModelOpRequest request;
    request.op = "merge";
    request.evidence_present = true;
    request.evaluated = true;
    const modelnet::SwarmModelOpResult result = modelnet::SwarmClassifyModelOp(request, err);
    BOOST_CHECK(!result.performed);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK_EQUAL(result.code, "MERGE_RECORDED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(recorded_distill_is_not_performed)
{
    std::string err = "prior";
    modelnet::SwarmModelOpRequest request;
    request.op = "distill";
    request.evidence_present = true;
    request.evaluated = true;
    const modelnet::SwarmModelOpResult result = modelnet::SwarmClassifyModelOp(request, err);
    BOOST_CHECK(!result.performed);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK_EQUAL(result.code, "DISTILL_RECORDED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
