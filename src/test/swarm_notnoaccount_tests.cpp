// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoaccount.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoaccount_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_ledger_id_is_ledger)
{
    modelnet::SwarmNotNoAccount note;
    note.real_money = true;
    note.want_pay = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAccountResult result = modelnet::SwarmNoteNotNoAccount(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "LEDGER");
    BOOST_CHECK_EQUAL(err, "LEDGER");
}

BOOST_AUTO_TEST_CASE(real_money_is_real_money_when_want_pay_is_false)
{
    modelnet::SwarmNotNoAccount note;
    note.ledger_id = "ledger-1";
    note.real_money = true;
    note.want_pay = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAccountResult result = modelnet::SwarmNoteNotNoAccount(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "REAL_MONEY");
    BOOST_CHECK_EQUAL(err, "REAL_MONEY");
}

BOOST_AUTO_TEST_CASE(want_pay_is_accounting_only)
{
    modelnet::SwarmNotNoAccount note;
    note.ledger_id = "ledger-1";
    note.real_money = false;
    note.want_pay = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAccountResult result = modelnet::SwarmNoteNotNoAccount(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "ACCOUNTING_ONLY");
    BOOST_CHECK_EQUAL(err, "ACCOUNTING_ONLY");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoAccount note;
    note.ledger_id = "ledger-1";
    note.real_money = false;
    note.want_pay = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAccountResult result = modelnet::SwarmNoteNotNoAccount(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
