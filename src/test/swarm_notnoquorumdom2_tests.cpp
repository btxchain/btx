// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoquorumdom2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoquorumdom2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoQuorumDom2 NotedNote()
{
    modelnet::SwarmNotNoQuorumDom2 note;
    note.quorum_id = "quorum-1";
    note.same_domain = false;
    note.want_count = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_quorum_id)
{
    modelnet::SwarmNotNoQuorumDom2 note = NotedNote();
    note.quorum_id.clear();
    note.same_domain = true;
    note.want_count = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoQuorumDom2Result result = modelnet::SwarmNoteNotNoQuorumDom2(note, err);
    BOOST_CHECK(!result.counted);
    BOOST_CHECK_EQUAL(result.code, "QUORUM");
    BOOST_CHECK_EQUAL(err, "QUORUM");
}

BOOST_AUTO_TEST_CASE(same_domain_true_want_count_false)
{
    modelnet::SwarmNotNoQuorumDom2 note = NotedNote();
    note.same_domain = true;
    note.want_count = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoQuorumDom2Result result = modelnet::SwarmNoteNotNoQuorumDom2(note, err);
    BOOST_CHECK(!result.counted);
    BOOST_CHECK_EQUAL(result.code, "NOT_QUORUM");
    BOOST_CHECK_EQUAL(err, "NOT_QUORUM");
}

BOOST_AUTO_TEST_CASE(want_count_true_same_domain_false)
{
    modelnet::SwarmNotNoQuorumDom2 note = NotedNote();
    note.quorum_id = "quorum-2";
    note.same_domain = false;
    note.want_count = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoQuorumDom2Result result = modelnet::SwarmNoteNotNoQuorumDom2(note, err);
    BOOST_CHECK(!result.counted);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(neither_noted)
{
    modelnet::SwarmNotNoQuorumDom2 note = NotedNote();
    note.quorum_id = "quorum-2";
    note.same_domain = false;
    note.want_count = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoQuorumDom2Result result = modelnet::SwarmNoteNotNoQuorumDom2(note, err);
    BOOST_CHECK(!result.counted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
