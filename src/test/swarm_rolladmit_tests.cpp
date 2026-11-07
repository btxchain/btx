// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rolladmit.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_rolladmit_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_id_is_example)
{
    std::string err = "prior";
    modelnet::SwarmRollAdmit example;
    example.example_id = "";
    example.private_data = false;
    example.rights_grant = false;
    example.credential = false;
    example.source_evidence = true;
    example.seen_before = false;
    example.want_train = false;
    const modelnet::SwarmRollAdmitResult result = modelnet::SwarmAdmitRolloutExample(example, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "EXAMPLE");
    BOOST_CHECK_EQUAL(err, "EXAMPLE");
}

BOOST_AUTO_TEST_CASE(credential_is_credential)
{
    std::string err = "prior";
    modelnet::SwarmRollAdmit example;
    example.example_id = "example";
    example.private_data = false;
    example.rights_grant = false;
    example.credential = true;
    example.source_evidence = true;
    example.seen_before = false;
    example.want_train = false;
    const modelnet::SwarmRollAdmitResult result = modelnet::SwarmAdmitRolloutExample(example, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "CREDENTIAL");
    BOOST_CHECK_EQUAL(err, "CREDENTIAL");
}

BOOST_AUTO_TEST_CASE(private_data_without_grant_is_private_data)
{
    std::string err = "prior";
    modelnet::SwarmRollAdmit example;
    example.example_id = "example";
    example.private_data = true;
    example.rights_grant = false;
    example.credential = false;
    example.source_evidence = true;
    example.seen_before = false;
    example.want_train = false;
    const modelnet::SwarmRollAdmitResult result = modelnet::SwarmAdmitRolloutExample(example, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
}

BOOST_AUTO_TEST_CASE(seen_before_is_replay)
{
    std::string err = "prior";
    modelnet::SwarmRollAdmit example;
    example.example_id = "example";
    example.private_data = false;
    example.rights_grant = false;
    example.credential = false;
    example.source_evidence = true;
    example.seen_before = true;
    example.want_train = false;
    const modelnet::SwarmRollAdmitResult result = modelnet::SwarmAdmitRolloutExample(example, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "REPLAY");
    BOOST_CHECK_EQUAL(err, "REPLAY");
}

BOOST_AUTO_TEST_CASE(missing_evidence_is_evidence)
{
    std::string err = "prior";
    modelnet::SwarmRollAdmit example;
    example.example_id = "example";
    example.private_data = false;
    example.rights_grant = false;
    example.credential = false;
    example.source_evidence = false;
    example.seen_before = false;
    example.want_train = false;
    const modelnet::SwarmRollAdmitResult result = modelnet::SwarmAdmitRolloutExample(example, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "EVIDENCE");
    BOOST_CHECK_EQUAL(err, "EVIDENCE");
}

BOOST_AUTO_TEST_CASE(want_train_is_held_and_admitted)
{
    std::string err = "prior";
    modelnet::SwarmRollAdmit example;
    example.example_id = "example";
    example.private_data = false;
    example.rights_grant = false;
    example.credential = false;
    example.source_evidence = true;
    example.seen_before = false;
    example.want_train = true;
    const modelnet::SwarmRollAdmitResult result = modelnet::SwarmAdmitRolloutExample(example, err);
    BOOST_CHECK(result.admitted);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(without_want_train_is_noted_and_admitted)
{
    std::string err = "prior";
    modelnet::SwarmRollAdmit example;
    example.example_id = "example";
    example.private_data = false;
    example.rights_grant = false;
    example.credential = false;
    example.source_evidence = true;
    example.seen_before = false;
    example.want_train = false;
    const modelnet::SwarmRollAdmitResult result = modelnet::SwarmAdmitRolloutExample(example, err);
    BOOST_CHECK(result.admitted);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
