// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoniche.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoniche_tests, BasicTestingSetup)

static modelnet::SwarmNotNoNiche NotedNote()
{
    modelnet::SwarmNotNoNiche note;
    note.niche_id = "niche-1";
    note.same_niche = true;
    note.want_merge = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_niche_id_is_niche)
{
    modelnet::SwarmNotNoNiche note = NotedNote();
    note.niche_id.clear();
    note.same_niche = true;
    note.want_merge = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoNicheResult result = modelnet::SwarmNoteNotNoNiche(note, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.code, "NICHE");
    BOOST_CHECK_EQUAL(err, "NICHE");
}

BOOST_AUTO_TEST_CASE(different_niche_is_separate)
{
    modelnet::SwarmNotNoNiche note = NotedNote();
    note.same_niche = false;
    note.want_merge = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoNicheResult result = modelnet::SwarmNoteNotNoNiche(note, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.code, "SEPARATE");
    BOOST_CHECK_EQUAL(err, "SEPARATE");
}

BOOST_AUTO_TEST_CASE(want_merge_on_same_niche_is_separate)
{
    modelnet::SwarmNotNoNiche note = NotedNote();
    note.same_niche = true;
    note.want_merge = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoNicheResult result = modelnet::SwarmNoteNotNoNiche(note, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.code, "SEPARATE");
    BOOST_CHECK_EQUAL(err, "SEPARATE");
}

BOOST_AUTO_TEST_CASE(same_niche_plain_is_noted)
{
    modelnet::SwarmNotNoNiche note = NotedNote();
    note.same_niche = true;
    note.want_merge = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoNicheResult result = modelnet::SwarmNoteNotNoNiche(note, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
