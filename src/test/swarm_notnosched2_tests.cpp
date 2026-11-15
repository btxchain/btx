// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosched2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnosched2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_witness_id)
{
    modelnet::SwarmNotNoSched2 note;
    note.witness_id.clear();
    note.scheduler = true;
    note.want_sign = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSched2Result result = modelnet::SwarmNoteNotNoSched2(note, err);
    BOOST_CHECK(!result.signed_witness);
    BOOST_CHECK_EQUAL(result.code, "WITNESS");
    BOOST_CHECK_EQUAL(err, "WITNESS");
}

BOOST_AUTO_TEST_CASE(scheduler_not_signed)
{
    modelnet::SwarmNotNoSched2 note;
    note.witness_id = "witness-1";
    note.scheduler = true;
    note.want_sign = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSched2Result result = modelnet::SwarmNoteNotNoSched2(note, err);
    BOOST_CHECK(!result.signed_witness);
    BOOST_CHECK_EQUAL(result.code, "NOT_SIGNED");
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
}

BOOST_AUTO_TEST_CASE(want_sign)
{
    modelnet::SwarmNotNoSched2 note;
    note.witness_id = "witness-1";
    note.scheduler = false;
    note.want_sign = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSched2Result result = modelnet::SwarmNoteNotNoSched2(note, err);
    BOOST_CHECK(!result.signed_witness);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    modelnet::SwarmNotNoSched2 note;
    BOOST_CHECK(!note.scheduler);
    BOOST_CHECK(!note.want_sign);
    note.witness_id = "witness-1";
    std::string err = "prior";
    const modelnet::SwarmNotNoSched2Result result = modelnet::SwarmNoteNotNoSched2(note, err);
    BOOST_CHECK(!result.signed_witness);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
