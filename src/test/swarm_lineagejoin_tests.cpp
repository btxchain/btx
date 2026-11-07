// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_lineagejoin.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_lineagejoin_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_lineage)
{
    modelnet::SwarmLineageJoin join;
    join.lineage_id.clear();
    join.checkpoint_only = false;
    join.artifact = true;
    join.want_trust = false;
    std::string err = "prior";
    const modelnet::SwarmLineageJoinResult result = modelnet::SwarmJoinLineageLocal(join, err);
    BOOST_CHECK(!result.trusted);
    BOOST_CHECK(!result.joined);
    BOOST_CHECK_EQUAL(result.code, "LINEAGE");
    BOOST_CHECK_EQUAL(err, "LINEAGE");
}

BOOST_AUTO_TEST_CASE(checkpoint_only_not_trust)
{
    modelnet::SwarmLineageJoin join;
    join.lineage_id = "lineage-1";
    join.checkpoint_only = true;
    join.artifact = true;
    join.want_trust = false;
    std::string err = "prior";
    const modelnet::SwarmLineageJoinResult result = modelnet::SwarmJoinLineageLocal(join, err);
    BOOST_CHECK(!result.trusted);
    BOOST_CHECK(!result.joined);
    BOOST_CHECK_EQUAL(result.code, "NOT_TRUST");
    BOOST_CHECK_EQUAL(err, "NOT_TRUST");
}

BOOST_AUTO_TEST_CASE(missing_artifact)
{
    modelnet::SwarmLineageJoin join;
    join.lineage_id = "lineage-1";
    join.checkpoint_only = false;
    join.artifact = false;
    join.want_trust = false;
    std::string err = "prior";
    const modelnet::SwarmLineageJoinResult result = modelnet::SwarmJoinLineageLocal(join, err);
    BOOST_CHECK(!result.trusted);
    BOOST_CHECK(!result.joined);
    BOOST_CHECK_EQUAL(result.code, "ARTIFACT");
    BOOST_CHECK_EQUAL(err, "ARTIFACT");
}

BOOST_AUTO_TEST_CASE(want_trust_held)
{
    modelnet::SwarmLineageJoin join;
    join.lineage_id = "lineage-1";
    join.checkpoint_only = false;
    join.artifact = true;
    join.want_trust = true;
    std::string err = "prior";
    const modelnet::SwarmLineageJoinResult result = modelnet::SwarmJoinLineageLocal(join, err);
    BOOST_CHECK(!result.trusted);
    BOOST_CHECK(result.joined);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(artifact_noted)
{
    modelnet::SwarmLineageJoin join;
    join.lineage_id = "lineage-1";
    join.checkpoint_only = false;
    join.artifact = true;
    join.want_trust = false;
    std::string err = "prior";
    const modelnet::SwarmLineageJoinResult result = modelnet::SwarmJoinLineageLocal(join, err);
    BOOST_CHECK(!result.trusted);
    BOOST_CHECK(result.joined);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
