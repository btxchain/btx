// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_datasetgrant.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_datasetgrant_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_grant_id_is_grant)
{
    std::string err = "prior";
    modelnet::SwarmDatasetGrant grant;
    grant.grant_id.clear();
    grant.present = true;
    grant.withdrawn = false;
    grant.want_train = false;
    const modelnet::SwarmDatasetGrantResult result = modelnet::SwarmCheckDatasetGrant(grant, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "GRANT");
    BOOST_CHECK_EQUAL(err, "GRANT");
}

BOOST_AUTO_TEST_CASE(present_false_is_dataset)
{
    std::string err = "prior";
    modelnet::SwarmDatasetGrant grant;
    grant.grant_id = "grant-1";
    grant.present = false;
    grant.withdrawn = false;
    grant.want_train = false;
    const modelnet::SwarmDatasetGrantResult result = modelnet::SwarmCheckDatasetGrant(grant, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "DATASET");
    BOOST_CHECK_EQUAL(err, "DATASET");
}

BOOST_AUTO_TEST_CASE(withdrawn_true_is_dataset)
{
    std::string err = "prior";
    modelnet::SwarmDatasetGrant grant;
    grant.grant_id = "grant-1";
    grant.present = true;
    grant.withdrawn = true;
    grant.want_train = false;
    const modelnet::SwarmDatasetGrantResult result = modelnet::SwarmCheckDatasetGrant(grant, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "DATASET");
    BOOST_CHECK_EQUAL(err, "DATASET");
}

BOOST_AUTO_TEST_CASE(want_train_is_held)
{
    std::string err = "prior";
    modelnet::SwarmDatasetGrant grant;
    grant.grant_id = "grant-1";
    grant.present = true;
    grant.withdrawn = false;
    grant.want_train = true;
    const modelnet::SwarmDatasetGrantResult result = modelnet::SwarmCheckDatasetGrant(grant, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(without_want_train_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmDatasetGrant grant;
    grant.grant_id = "grant-1";
    grant.present = true;
    grant.withdrawn = false;
    grant.want_train = false;
    const modelnet::SwarmDatasetGrantResult result = modelnet::SwarmCheckDatasetGrant(grant, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
