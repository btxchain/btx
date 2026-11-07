// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notreport.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notreport_tests, BasicTestingSetup)

static modelnet::SwarmNotReport NotedNote()
{
    modelnet::SwarmNotReport note;
    note.eval_id = "eval-1";
    note.want_attach = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_eval_id_is_eval)
{
    modelnet::SwarmNotReport note = NotedNote();
    note.eval_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotReportResult result = modelnet::SwarmNoteNotReport(note, err);
    BOOST_CHECK(!result.attached);
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK_EQUAL(result.code, "EVAL");
    BOOST_CHECK_EQUAL(err, "EVAL");
}

BOOST_AUTO_TEST_CASE(want_attach_is_not_attached)
{
    modelnet::SwarmNotReport note = NotedNote();
    note.want_attach = true;
    std::string err = "prior";
    const modelnet::SwarmNotReportResult result = modelnet::SwarmNoteNotReport(note, err);
    BOOST_CHECK(!result.attached);
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK_EQUAL(result.code, "NOT_ATTACHED");
    BOOST_CHECK_EQUAL(err, "NOT_ATTACHED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotReport note = NotedNote();
    note.want_attach = false;
    std::string err = "prior";
    const modelnet::SwarmNotReportResult result = modelnet::SwarmNoteNotReport(note, err);
    BOOST_CHECK(!result.attached);
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
