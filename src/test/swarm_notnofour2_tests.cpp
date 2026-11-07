// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofour2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnofour2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_ledger_id_is_ledger)
{
    std::string err = "prior";
    modelnet::SwarmNotNoFour2 note;
    note.want_merge = true;
    const modelnet::SwarmNotNoFour2Result result = modelnet::SwarmNoteNotNoFour2(note, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "LEDGER");
    BOOST_CHECK_EQUAL(err, "LEDGER");
}

BOOST_AUTO_TEST_CASE(want_merge_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoFour2 note;
    note.ledger_id = "ledger-note";
    note.want_merge = true;
    const modelnet::SwarmNotNoFour2Result result = modelnet::SwarmNoteNotNoFour2(note, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoFour2 note;
    note.ledger_id = "ledger-note";
    note.want_merge = false;
    const modelnet::SwarmNotNoFour2Result result = modelnet::SwarmNoteNotNoFour2(note, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
