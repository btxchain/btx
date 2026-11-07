// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notmandate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notmandate_tests, BasicTestingSetup)

static modelnet::SwarmNotMandate NotedNote()
{
    modelnet::SwarmNotMandate note;
    note.mandate_id = "mandate-1";
    note.operator_signed = true;
    note.want_spend = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_mandate_id_is_mandate)
{
    modelnet::SwarmNotMandate note = NotedNote();
    note.mandate_id.clear();
    note.operator_signed = true;
    note.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmNotMandateResult result = modelnet::SwarmNoteNotMandate(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "MANDATE");
    BOOST_CHECK_EQUAL(err, "MANDATE");
}

BOOST_AUTO_TEST_CASE(unsigned_is_unsigned)
{
    modelnet::SwarmNotMandate note = NotedNote();
    note.operator_signed = false;
    note.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmNotMandateResult result = modelnet::SwarmNoteNotMandate(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "UNSIGNED");
    BOOST_CHECK_EQUAL(err, "UNSIGNED");
}

BOOST_AUTO_TEST_CASE(want_spend_is_held)
{
    modelnet::SwarmNotMandate note = NotedNote();
    note.operator_signed = true;
    note.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmNotMandateResult result = modelnet::SwarmNoteNotMandate(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_signed_note_is_noted)
{
    modelnet::SwarmNotMandate note = NotedNote();
    note.operator_signed = true;
    note.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmNotMandateResult result = modelnet::SwarmNoteNotMandate(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
