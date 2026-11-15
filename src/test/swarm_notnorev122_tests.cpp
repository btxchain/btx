// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorev122.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnorev122_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_row_id_is_row)
{
    modelnet::SwarmNotNoRev122 note;
    note.want_pay = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoRev122Result result = modelnet::SwarmNoteNotNoRev122(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "ROW");
    BOOST_CHECK_EQUAL(err, "ROW");
}

BOOST_AUTO_TEST_CASE(want_pay_is_not_paid)
{
    modelnet::SwarmNotNoRev122 note;
    note.row_id = "row-1";
    note.want_pay = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoRev122Result result = modelnet::SwarmNoteNotNoRev122(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_PAID");
    BOOST_CHECK_EQUAL(err, "NOT_PAID");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoRev122 note;
    note.row_id = "row-1";
    note.want_pay = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoRev122Result result = modelnet::SwarmNoteNotNoRev122(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
