// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoquorum2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoquorum2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoQuorum2 NotedNote()
{
    modelnet::SwarmNotNoQuorum2 note;
    note.quorum_id = "quorum-1";
    note.same_evaluator = false;
    note.same_domain = false;
    note.want_settle = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_quorum_id_is_quorum)
{
    modelnet::SwarmNotNoQuorum2 note = NotedNote();
    note.quorum_id.clear();
    note.same_evaluator = true;
    note.same_domain = true;
    note.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoQuorum2Result result = modelnet::SwarmNoteNotNoQuorum2(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "QUORUM");
    BOOST_CHECK_EQUAL(err, "QUORUM");
}

BOOST_AUTO_TEST_CASE(same_evaluator_is_not_settled)
{
    modelnet::SwarmNotNoQuorum2 note = NotedNote();
    note.same_evaluator = true;
    note.same_domain = false;
    note.want_settle = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoQuorum2Result result = modelnet::SwarmNoteNotNoQuorum2(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_SETTLED");
    BOOST_CHECK_EQUAL(err, "NOT_SETTLED");
}

BOOST_AUTO_TEST_CASE(want_settle_both_flags_false_is_held)
{
    modelnet::SwarmNotNoQuorum2 note = NotedNote();
    note.same_evaluator = false;
    note.same_domain = false;
    note.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoQuorum2Result result = modelnet::SwarmNoteNotNoQuorum2(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(both_flags_false_want_settle_false_is_noted)
{
    modelnet::SwarmNotNoQuorum2 note = NotedNote();
    note.same_evaluator = false;
    note.same_domain = false;
    note.want_settle = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoQuorum2Result result = modelnet::SwarmNoteNotNoQuorum2(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
