// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosighash2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnosighash2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_tx_id_is_tx)
{
    modelnet::SwarmNotNoSighash2 note;
    note.tx_id.clear();
    note.covers_outputs = false;
    note.want_accept = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSighash2Result result = modelnet::SwarmNoteNotNoSighash2(note, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.code, "TX");
    BOOST_CHECK_EQUAL(err, "TX");
}

BOOST_AUTO_TEST_CASE(uncovered_outputs_is_refused)
{
    modelnet::SwarmNotNoSighash2 note;
    note.tx_id = "tx-1";
    note.covers_outputs = false;
    note.want_accept = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSighash2Result result = modelnet::SwarmNoteNotNoSighash2(note, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.code, "REFUSED");
    BOOST_CHECK_EQUAL(err, "REFUSED");
}

BOOST_AUTO_TEST_CASE(want_accept_is_held)
{
    modelnet::SwarmNotNoSighash2 note;
    note.tx_id = "tx-1";
    note.covers_outputs = true;
    note.want_accept = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSighash2Result result = modelnet::SwarmNoteNotNoSighash2(note, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(covered_outputs_is_noted)
{
    modelnet::SwarmNotNoSighash2 note;
    note.tx_id = "tx-1";
    note.covers_outputs = true;
    note.want_accept = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSighash2Result result = modelnet::SwarmNoteNotNoSighash2(note, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
