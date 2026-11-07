// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notwitness.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notwitness_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_tx_id_is_tx)
{
    modelnet::SwarmNotWitness note;
    std::string err = "prior";
    const modelnet::SwarmNotWitnessResult result = modelnet::SwarmNoteNotWitness(note, err);
    BOOST_CHECK_EQUAL(result.verified, false);
    BOOST_CHECK_EQUAL(result.code, "TX");
    BOOST_CHECK_EQUAL(err, "TX");
}

BOOST_AUTO_TEST_CASE(want_verify_is_unverified)
{
    modelnet::SwarmNotWitness note;
    note.tx_id = "tx-1";
    note.want_verify = true;
    std::string err = "prior";
    const modelnet::SwarmNotWitnessResult result = modelnet::SwarmNoteNotWitness(note, err);
    BOOST_CHECK_EQUAL(result.verified, false);
    BOOST_CHECK_EQUAL(result.code, "UNVERIFIED");
    BOOST_CHECK_EQUAL(err, "UNVERIFIED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotWitness note;
    note.tx_id = "tx-1";
    note.want_verify = false;
    std::string err = "prior";
    const modelnet::SwarmNotWitnessResult result = modelnet::SwarmNoteNotWitness(note, err);
    BOOST_CHECK_EQUAL(result.verified, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
