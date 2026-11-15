// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notpromo.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notpromo_tests, BasicTestingSetup)

static modelnet::SwarmNotPromo NotedNote()
{
    modelnet::SwarmNotPromo note;
    note.candidate_id = "candidate-1";
    note.want_promote = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_candidate_id_is_candidate)
{
    modelnet::SwarmNotPromo note = NotedNote();
    note.candidate_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotPromoResult result = modelnet::SwarmNoteNotPromo(note, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK_EQUAL(result.code, "CANDIDATE");
    BOOST_CHECK_EQUAL(err, "CANDIDATE");
}

BOOST_AUTO_TEST_CASE(want_promote_is_not_promoted)
{
    modelnet::SwarmNotPromo note = NotedNote();
    note.want_promote = true;
    std::string err = "prior";
    const modelnet::SwarmNotPromoResult result = modelnet::SwarmNoteNotPromo(note, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK_EQUAL(result.code, "NOT_PROMOTED");
    BOOST_CHECK_EQUAL(err, "NOT_PROMOTED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotPromo note = NotedNote();
    note.want_promote = false;
    std::string err = "prior";
    const modelnet::SwarmNotPromoResult result = modelnet::SwarmNoteNotPromo(note, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
