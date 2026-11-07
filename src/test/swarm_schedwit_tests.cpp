// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_schedwit.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_schedwit_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_witness_id_is_witness)
{
    modelnet::SwarmSchedWit witness;
    witness.witness_id.clear();
    witness.scheduler = false;
    witness.want_sign = false;
    std::string err = "prior";
    const modelnet::SwarmSchedWitResult result = modelnet::SwarmNoteSchedWitness(witness, err);
    BOOST_CHECK(!result.signed_ok);
    BOOST_CHECK_EQUAL(result.code, "WITNESS");
    BOOST_CHECK_EQUAL(err, "WITNESS");
}

BOOST_AUTO_TEST_CASE(scheduler_true_want_sign_false_is_not_signed)
{
    modelnet::SwarmSchedWit witness;
    witness.witness_id = "wit-1";
    witness.scheduler = true;
    witness.want_sign = false;
    std::string err = "prior";
    const modelnet::SwarmSchedWitResult result = modelnet::SwarmNoteSchedWitness(witness, err);
    BOOST_CHECK(!result.signed_ok);
    BOOST_CHECK_EQUAL(result.code, "NOT_SIGNED");
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
}

BOOST_AUTO_TEST_CASE(want_sign_true_scheduler_false_is_held)
{
    modelnet::SwarmSchedWit witness;
    witness.witness_id = "wit-1";
    witness.scheduler = false;
    witness.want_sign = true;
    std::string err = "prior";
    const modelnet::SwarmSchedWitResult result = modelnet::SwarmNoteSchedWitness(witness, err);
    BOOST_CHECK(!result.signed_ok);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(neither_is_noted)
{
    modelnet::SwarmSchedWit witness;
    witness.witness_id = "wit-1";
    witness.scheduler = false;
    witness.want_sign = false;
    std::string err = "prior";
    const modelnet::SwarmSchedWitResult result = modelnet::SwarmNoteSchedWitness(witness, err);
    BOOST_CHECK(!result.signed_ok);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
