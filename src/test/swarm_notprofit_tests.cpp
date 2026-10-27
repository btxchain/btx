// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notprofit.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notprofit_tests, BasicTestingSetup)

static modelnet::SwarmNotProfit NotedNote()
{
    modelnet::SwarmNotProfit note;
    note.share_id = "share-1";
    note.want_share = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_share_id_is_share)
{
    modelnet::SwarmNotProfit note = NotedNote();
    note.share_id.clear();
    note.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmNotProfitResult result = modelnet::SwarmNoteNotProfit(note, err);
    BOOST_CHECK_EQUAL(result.code, "SHARE");
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(err, "SHARE");
}

BOOST_AUTO_TEST_CASE(want_share_is_refused)
{
    modelnet::SwarmNotProfit note = NotedNote();
    note.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmNotProfitResult result = modelnet::SwarmNoteNotProfit(note, err);
    BOOST_CHECK_EQUAL(result.code, "REFUSED");
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(err, "REFUSED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotProfit note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotProfitResult result = modelnet::SwarmNoteNotProfit(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
