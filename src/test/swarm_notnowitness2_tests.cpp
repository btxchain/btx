// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnowitness2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnowitness2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_tx_id)
{
    modelnet::SwarmNotNoWitness2 note;
    note.tx_id.clear();
    note.scheduler = true;
    note.want_sign = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoWitness2Result result = modelnet::SwarmNoteNotNoWitness2(note, err);
    BOOST_CHECK(!result.signed_witness);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.code, "TX");
    BOOST_CHECK_EQUAL(err, "TX");
}

BOOST_AUTO_TEST_CASE(scheduler_not_signed)
{
    modelnet::SwarmNotNoWitness2 note;
    note.tx_id = "tx-1";
    note.scheduler = true;
    note.want_sign = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoWitness2Result result = modelnet::SwarmNoteNotNoWitness2(note, err);
    BOOST_CHECK(!result.signed_witness);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.code, "NOT_SIGNED");
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
}

BOOST_AUTO_TEST_CASE(want_sign)
{
    modelnet::SwarmNotNoWitness2 note;
    note.tx_id = "tx-1";
    note.scheduler = false;
    note.want_sign = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoWitness2Result result = modelnet::SwarmNoteNotNoWitness2(note, err);
    BOOST_CHECK(!result.signed_witness);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    modelnet::SwarmNotNoWitness2 note;
    BOOST_CHECK(!note.scheduler);
    BOOST_CHECK(!note.want_sign);
    note.tx_id = "tx-1";
    std::string err = "prior";
    const modelnet::SwarmNotNoWitness2Result result = modelnet::SwarmNoteNotNoWitness2(note, err);
    BOOST_CHECK(!result.signed_witness);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
