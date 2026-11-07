// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoautospent2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoautospent2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_spend_id_is_spend)
{
    modelnet::SwarmNotNoAutoSpent2 note;
    note.spend_id.clear();
    note.want_set = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAutoSpent2Result result = modelnet::SwarmNoteNotNoAutoSpent2(note, err);
    BOOST_CHECK(!result.armed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "SPEND");
    BOOST_CHECK_EQUAL(err, "SPEND");
}

BOOST_AUTO_TEST_CASE(want_set_is_held)
{
    modelnet::SwarmNotNoAutoSpent2 note;
    note.spend_id = "spend-1";
    note.want_set = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAutoSpent2Result result = modelnet::SwarmNoteNotNoAutoSpent2(note, err);
    BOOST_CHECK(!result.armed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoAutoSpent2 note;
    note.spend_id = "spend-1";
    note.want_set = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAutoSpent2Result result = modelnet::SwarmNoteNotNoAutoSpent2(note, err);
    BOOST_CHECK(!result.armed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
