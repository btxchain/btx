// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_clearnote.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_clearnote_tests, BasicTestingSetup)

static modelnet::SwarmClearingNote NettedNote()
{
    modelnet::SwarmClearingNote note;
    note.payments = 1;
    note.want_l1_per_payment = false;
    return note;
}

BOOST_AUTO_TEST_CASE(payments_below_one_are_clear)
{
    modelnet::SwarmClearingNote note = NettedNote();
    note.payments = 0;
    std::string err = "prior";
    const modelnet::SwarmClearingNoteResult result = modelnet::SwarmNoteClearing(note, err);
    BOOST_CHECK_EQUAL(result.l1_transactions, 0);
    BOOST_CHECK_EQUAL(result.code, "CLEAR");
    BOOST_CHECK_EQUAL(err, "CLEAR");
}

BOOST_AUTO_TEST_CASE(negative_payments_are_clear)
{
    modelnet::SwarmClearingNote note = NettedNote();
    note.payments = -1;
    std::string err = "prior";
    const modelnet::SwarmClearingNoteResult result = modelnet::SwarmNoteClearing(note, err);
    BOOST_CHECK_EQUAL(result.l1_transactions, 0);
    BOOST_CHECK_EQUAL(result.code, "CLEAR");
    BOOST_CHECK_EQUAL(err, "CLEAR");
}

BOOST_AUTO_TEST_CASE(payments_below_one_wins_over_want_l1_per_payment)
{
    modelnet::SwarmClearingNote note = NettedNote();
    note.payments = 0;
    note.want_l1_per_payment = true;
    std::string err = "prior";
    const modelnet::SwarmClearingNoteResult result = modelnet::SwarmNoteClearing(note, err);
    BOOST_CHECK_EQUAL(result.l1_transactions, 0);
    BOOST_CHECK_EQUAL(result.code, "CLEAR");
    BOOST_CHECK_EQUAL(err, "CLEAR");
}

BOOST_AUTO_TEST_CASE(want_l1_per_payment_is_l1_refused)
{
    modelnet::SwarmClearingNote note = NettedNote();
    note.want_l1_per_payment = true;
    std::string err = "prior";
    const modelnet::SwarmClearingNoteResult result = modelnet::SwarmNoteClearing(note, err);
    BOOST_CHECK_EQUAL(result.l1_transactions, 0);
    BOOST_CHECK_EQUAL(result.code, "L1_REFUSED");
    BOOST_CHECK_EQUAL(err, "L1_REFUSED");
}

BOOST_AUTO_TEST_CASE(one_thousand_payments_wanting_l1_are_l1_refused)
{
    modelnet::SwarmClearingNote note = NettedNote();
    note.payments = 1000;
    note.want_l1_per_payment = true;
    std::string err = "prior";
    const modelnet::SwarmClearingNoteResult result = modelnet::SwarmNoteClearing(note, err);
    BOOST_CHECK_EQUAL(result.l1_transactions, 0);
    BOOST_CHECK_EQUAL(result.code, "L1_REFUSED");
    BOOST_CHECK_EQUAL(err, "L1_REFUSED");
}

BOOST_AUTO_TEST_CASE(one_payment_is_netted)
{
    modelnet::SwarmClearingNote note = NettedNote();
    std::string err = "prior";
    const modelnet::SwarmClearingNoteResult result = modelnet::SwarmNoteClearing(note, err);
    BOOST_CHECK_EQUAL(result.l1_transactions, 0);
    BOOST_CHECK_EQUAL(result.code, "NETTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(one_thousand_payments_are_netted)
{
    modelnet::SwarmClearingNote note = NettedNote();
    note.payments = 1000;
    std::string err = "prior";
    const modelnet::SwarmClearingNoteResult result = modelnet::SwarmNoteClearing(note, err);
    BOOST_CHECK_EQUAL(result.l1_transactions, 0);
    BOOST_CHECK_EQUAL(result.code, "NETTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
