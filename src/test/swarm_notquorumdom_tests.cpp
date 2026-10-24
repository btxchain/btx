// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notquorumdom.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notquorumdom_tests, BasicTestingSetup)

static modelnet::SwarmNotQuorumDom NotedNote()
{
    modelnet::SwarmNotQuorumDom note;
    note.quorum_id = "quorum-1";
    note.distinct_evaluators = true;
    note.distinct_domains = true;
    note.want_settle = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_quorum_id_is_quorum)
{
    modelnet::SwarmNotQuorumDom note = NotedNote();
    note.quorum_id.clear();
    note.distinct_evaluators = false;
    note.distinct_domains = false;
    note.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmNotQuorumDomResult result = modelnet::SwarmNoteNotQuorumDom(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "QUORUM");
    BOOST_CHECK_EQUAL(err, "QUORUM");
}

BOOST_AUTO_TEST_CASE(same_evaluator_is_same_evaluator)
{
    modelnet::SwarmNotQuorumDom note = NotedNote();
    note.distinct_evaluators = false;
    note.distinct_domains = true;
    note.want_settle = false;
    std::string err = "prior";
    const modelnet::SwarmNotQuorumDomResult result = modelnet::SwarmNoteNotQuorumDom(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "SAME_EVALUATOR");
    BOOST_CHECK_EQUAL(err, "SAME_EVALUATOR");
}

BOOST_AUTO_TEST_CASE(same_domain_is_same_domain)
{
    modelnet::SwarmNotQuorumDom note = NotedNote();
    note.distinct_evaluators = true;
    note.distinct_domains = false;
    note.want_settle = false;
    std::string err = "prior";
    const modelnet::SwarmNotQuorumDomResult result = modelnet::SwarmNoteNotQuorumDom(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "SAME_DOMAIN");
    BOOST_CHECK_EQUAL(err, "SAME_DOMAIN");
}

BOOST_AUTO_TEST_CASE(want_settle_both_distinct_is_held)
{
    modelnet::SwarmNotQuorumDom note = NotedNote();
    note.distinct_evaluators = true;
    note.distinct_domains = true;
    note.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmNotQuorumDomResult result = modelnet::SwarmNoteNotQuorumDom(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(both_distinct_plain_is_noted)
{
    modelnet::SwarmNotQuorumDom note = NotedNote();
    note.distinct_evaluators = true;
    note.distinct_domains = true;
    note.want_settle = false;
    std::string err = "prior";
    const modelnet::SwarmNotQuorumDomResult result = modelnet::SwarmNoteNotQuorumDom(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
