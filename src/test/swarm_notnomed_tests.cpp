// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomed.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnomed_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_context_id_is_context)
{
    std::string err = "prior";
    modelnet::SwarmNotNoMed note;
    note.tokens = 128;
    note.want_promote = true;
    const modelnet::SwarmNotNoMedResult result = modelnet::SwarmNoteNotNoMed(note, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "CONTEXT");
    BOOST_CHECK_EQUAL(err, "CONTEXT");
}

BOOST_AUTO_TEST_CASE(nonzero_tokens_is_not_promoted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoMed note;
    note.context_id = "context-1";
    note.tokens = 128;
    note.want_promote = false;
    const modelnet::SwarmNotNoMedResult result = modelnet::SwarmNoteNotNoMed(note, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "NOT_PROMOTED");
    BOOST_CHECK_EQUAL(err, "NOT_PROMOTED");
}

BOOST_AUTO_TEST_CASE(want_promote_at_zero_is_not_promoted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoMed note;
    note.context_id = "context-1";
    note.tokens = 0;
    note.want_promote = true;
    const modelnet::SwarmNotNoMedResult result = modelnet::SwarmNoteNotNoMed(note, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "NOT_PROMOTED");
    BOOST_CHECK_EQUAL(err, "NOT_PROMOTED");
}

BOOST_AUTO_TEST_CASE(plain_zero_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoMed note;
    note.context_id = "context-1";
    note.tokens = 0;
    note.want_promote = false;
    const modelnet::SwarmNotNoMedResult result = modelnet::SwarmNoteNotNoMed(note, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
