// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoautospend.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoautospend_tests, BasicTestingSetup)

static modelnet::SwarmNotNoAutoSpend NotedNote()
{
    modelnet::SwarmNotNoAutoSpend note;
    note.mandate_id = "mandate-1";
    note.want_arm = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_mandate_id_is_mandate)
{
    modelnet::SwarmNotNoAutoSpend note = NotedNote();
    note.mandate_id.clear();
    note.want_arm = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAutoSpendResult result = modelnet::SwarmNoteNotNoAutoSpend(note, err);
    BOOST_CHECK(!result.armed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "MANDATE");
    BOOST_CHECK_EQUAL(err, "MANDATE");
}

BOOST_AUTO_TEST_CASE(want_arm_is_zero)
{
    modelnet::SwarmNotNoAutoSpend note = NotedNote();
    note.want_arm = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAutoSpendResult result = modelnet::SwarmNoteNotNoAutoSpend(note, err);
    BOOST_CHECK(!result.armed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "ZERO");
    BOOST_CHECK_EQUAL(err, "ZERO");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoAutoSpend note = NotedNote();
    note.want_arm = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAutoSpendResult result = modelnet::SwarmNoteNotNoAutoSpend(note, err);
    BOOST_CHECK(!result.armed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
