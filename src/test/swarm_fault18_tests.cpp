// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault18.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fault18_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_dataset_id_is_dataset)
{
    modelnet::SwarmFault18 in;
    in.job_id = "job-1";
    in.withdrawn = true;
    in.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmFault18Result result = modelnet::SwarmRecoverFault18(in, err);
    BOOST_CHECK_EQUAL(result.code, "DATASET");
    BOOST_CHECK(!result.training);
    BOOST_CHECK(!result.started);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(err, "DATASET");
}

BOOST_AUTO_TEST_CASE(empty_job_id_is_dataset)
{
    modelnet::SwarmFault18 in;
    in.dataset_id = "ds-1";
    in.withdrawn = true;
    in.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmFault18Result result = modelnet::SwarmRecoverFault18(in, err);
    BOOST_CHECK_EQUAL(result.code, "DATASET");
    BOOST_CHECK(!result.training);
    BOOST_CHECK(!result.started);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(err, "DATASET");
}

BOOST_AUTO_TEST_CASE(both_ids_empty_is_dataset)
{
    modelnet::SwarmFault18 in;
    in.withdrawn = true;
    in.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmFault18Result result = modelnet::SwarmRecoverFault18(in, err);
    BOOST_CHECK_EQUAL(result.code, "DATASET");
    BOOST_CHECK(!result.training);
    BOOST_CHECK(!result.started);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(err, "DATASET");
}

BOOST_AUTO_TEST_CASE(withdrawn_is_not_started_even_if_want_train)
{
    modelnet::SwarmFault18 in;
    in.dataset_id = "ds-1";
    in.job_id = "job-1";
    in.withdrawn = true;
    in.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmFault18Result result = modelnet::SwarmRecoverFault18(in, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_STARTED");
    BOOST_CHECK(!result.training);
    BOOST_CHECK(!result.started);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(err, "NOT_STARTED");
}

BOOST_AUTO_TEST_CASE(withdrawn_without_want_train_is_not_started)
{
    modelnet::SwarmFault18 in;
    in.dataset_id = "ds-1";
    in.job_id = "job-1";
    in.withdrawn = true;
    in.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmFault18Result result = modelnet::SwarmRecoverFault18(in, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_STARTED");
    BOOST_CHECK(!result.training);
    BOOST_CHECK(!result.started);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(err, "NOT_STARTED");
}

BOOST_AUTO_TEST_CASE(want_train_is_held)
{
    modelnet::SwarmFault18 in;
    in.dataset_id = "ds-1";
    in.job_id = "job-1";
    in.withdrawn = false;
    in.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmFault18Result result = modelnet::SwarmRecoverFault18(in, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.training);
    BOOST_CHECK(!result.started);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(otherwise_noted)
{
    modelnet::SwarmFault18 in;
    in.dataset_id = "ds-1";
    in.job_id = "job-1";
    std::string err = "prior";
    const modelnet::SwarmFault18Result result = modelnet::SwarmRecoverFault18(in, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.training);
    BOOST_CHECK(!result.started);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
