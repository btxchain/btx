// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosighashout2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnosighashout2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_tx_id_is_tx)
{
    modelnet::SwarmNotNoSighashOut2 note;
    note.tx_id.clear();
    note.skip_outputs = false;
    note.want_sign = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSighashOut2Result result = modelnet::SwarmNoteNotNoSighashOut2(note, err);
    BOOST_CHECK(!result.signed_ok);
    BOOST_CHECK_EQUAL(result.code, "TX");
    BOOST_CHECK_EQUAL(err, "TX");
}

BOOST_AUTO_TEST_CASE(skip_outputs_is_not_signed)
{
    modelnet::SwarmNotNoSighashOut2 note;
    note.tx_id = "tx-1";
    note.skip_outputs = true;
    note.want_sign = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSighashOut2Result result = modelnet::SwarmNoteNotNoSighashOut2(note, err);
    BOOST_CHECK(!result.signed_ok);
    BOOST_CHECK_EQUAL(result.code, "NOT_SIGNED");
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
}

BOOST_AUTO_TEST_CASE(want_sign_is_held)
{
    modelnet::SwarmNotNoSighashOut2 note;
    note.tx_id = "tx-1";
    note.skip_outputs = false;
    note.want_sign = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSighashOut2Result result = modelnet::SwarmNoteNotNoSighashOut2(note, err);
    BOOST_CHECK(!result.signed_ok);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(neither_is_noted)
{
    modelnet::SwarmNotNoSighashOut2 note;
    note.tx_id = "tx-1";
    note.skip_outputs = false;
    note.want_sign = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSighashOut2Result result = modelnet::SwarmNoteNotNoSighashOut2(note, err);
    BOOST_CHECK(!result.signed_ok);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
