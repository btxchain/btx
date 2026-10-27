// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoprofit.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoprofit_tests, BasicTestingSetup)

static modelnet::SwarmNotNoProfit NotedNote()
{
    modelnet::SwarmNotNoProfit note;
    note.split_id = "split-1";
    note.want_share = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_split_id_is_split)
{
    modelnet::SwarmNotNoProfit note = NotedNote();
    note.split_id.clear();
    note.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoProfitResult result = modelnet::SwarmNoteNotNoProfit(note, err);
    BOOST_CHECK_EQUAL(result.code, "SPLIT");
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "SPLIT");
}

BOOST_AUTO_TEST_CASE(want_share_is_refused)
{
    modelnet::SwarmNotNoProfit note = NotedNote();
    note.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoProfitResult result = modelnet::SwarmNoteNotNoProfit(note, err);
    BOOST_CHECK_EQUAL(result.code, "REFUSED");
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "REFUSED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoProfit note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoProfitResult result = modelnet::SwarmNoteNotNoProfit(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
