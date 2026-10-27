// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fundsign.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fundsign_tests, BasicTestingSetup)

static modelnet::SwarmFundingWitness NotedWitness()
{
    modelnet::SwarmFundingWitness witness;
    witness.scheduler_id = "scheduler-1";
    witness.scheduler_signs = false;
    witness.want_broadcast = false;
    return witness;
}

static void ExpectUnsignedUnbroadcast(const modelnet::SwarmFundingWitnessResult& result)
{
    BOOST_CHECK(!result.signed_witness);
    BOOST_CHECK(!result.broadcast);
}

BOOST_AUTO_TEST_CASE(empty_scheduler_id_is_witness)
{
    modelnet::SwarmFundingWitness witness = NotedWitness();
    witness.scheduler_id.clear();
    std::string err = "prior";
    const modelnet::SwarmFundingWitnessResult result = modelnet::SwarmNoteFundingWitness(witness, err);
    ExpectUnsignedUnbroadcast(result);
    BOOST_CHECK_EQUAL(result.code, "WITNESS");
    BOOST_CHECK_EQUAL(err, "WITNESS");
}

BOOST_AUTO_TEST_CASE(empty_scheduler_id_wins_over_sign_and_broadcast)
{
    modelnet::SwarmFundingWitness witness = NotedWitness();
    witness.scheduler_id.clear();
    witness.scheduler_signs = true;
    witness.want_broadcast = true;
    std::string err = "prior";
    const modelnet::SwarmFundingWitnessResult result = modelnet::SwarmNoteFundingWitness(witness, err);
    ExpectUnsignedUnbroadcast(result);
    BOOST_CHECK_EQUAL(result.code, "WITNESS");
    BOOST_CHECK_EQUAL(err, "WITNESS");
}

BOOST_AUTO_TEST_CASE(scheduler_signs_is_sign_refused)
{
    modelnet::SwarmFundingWitness witness = NotedWitness();
    witness.scheduler_signs = true;
    std::string err = "prior";
    const modelnet::SwarmFundingWitnessResult result = modelnet::SwarmNoteFundingWitness(witness, err);
    ExpectUnsignedUnbroadcast(result);
    BOOST_CHECK_EQUAL(result.code, "SIGN_REFUSED");
    BOOST_CHECK_EQUAL(err, "SIGN_REFUSED");
}

BOOST_AUTO_TEST_CASE(scheduler_signs_wins_over_want_broadcast)
{
    modelnet::SwarmFundingWitness witness = NotedWitness();
    witness.scheduler_signs = true;
    witness.want_broadcast = true;
    std::string err = "prior";
    const modelnet::SwarmFundingWitnessResult result = modelnet::SwarmNoteFundingWitness(witness, err);
    ExpectUnsignedUnbroadcast(result);
    BOOST_CHECK_EQUAL(result.code, "SIGN_REFUSED");
    BOOST_CHECK_EQUAL(err, "SIGN_REFUSED");
}

BOOST_AUTO_TEST_CASE(want_broadcast_is_broadcast_forbidden)
{
    modelnet::SwarmFundingWitness witness = NotedWitness();
    witness.want_broadcast = true;
    std::string err = "prior";
    const modelnet::SwarmFundingWitnessResult result = modelnet::SwarmNoteFundingWitness(witness, err);
    ExpectUnsignedUnbroadcast(result);
    BOOST_CHECK_EQUAL(result.code, "BROADCAST_FORBIDDEN");
    BOOST_CHECK_EQUAL(err, "BROADCAST_FORBIDDEN");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmFundingWitness witness = NotedWitness();
    std::string err = "prior";
    const modelnet::SwarmFundingWitnessResult result = modelnet::SwarmNoteFundingWitness(witness, err);
    ExpectUnsignedUnbroadcast(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
