// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoprofitshare2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoprofitshare2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_share_id_is_share)
{
    std::string err = "prior";
    modelnet::SwarmNotNoProfitShare2 note;
    note.profit = true;
    note.want_pay = true;
    const modelnet::SwarmNotNoProfitShare2Result result = modelnet::SwarmNoteNotNoProfitShare2(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "SHARE");
    BOOST_CHECK_EQUAL(err, "SHARE");
}

BOOST_AUTO_TEST_CASE(profit_is_not_paid)
{
    std::string err = "prior";
    modelnet::SwarmNotNoProfitShare2 note;
    note.share_id = "share-1";
    note.profit = true;
    note.want_pay = false;
    const modelnet::SwarmNotNoProfitShare2Result result = modelnet::SwarmNoteNotNoProfitShare2(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_PAID");
    BOOST_CHECK_EQUAL(err, "NOT_PAID");
}

BOOST_AUTO_TEST_CASE(want_pay_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoProfitShare2 note;
    note.share_id = "share-1";
    note.profit = false;
    note.want_pay = true;
    const modelnet::SwarmNotNoProfitShare2Result result = modelnet::SwarmNoteNotNoProfitShare2(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoProfitShare2 note;
    note.share_id = "share-1";
    note.profit = false;
    note.want_pay = false;
    const modelnet::SwarmNotNoProfitShare2Result result = modelnet::SwarmNoteNotNoProfitShare2(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
