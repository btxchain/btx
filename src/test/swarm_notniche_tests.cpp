// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notniche.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notniche_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_niche_id_is_niche)
{
    modelnet::SwarmNotNiche note;
    note.niche_id.clear();
    note.want_merge = false;
    std::string err = "prior";
    const modelnet::SwarmNotNicheResult result = modelnet::SwarmNoteNotNiche(note, err);
    BOOST_CHECK_EQUAL(result.code, "NICHE");
    BOOST_CHECK_EQUAL(err, "NICHE");
    BOOST_CHECK(!result.merged);
}

BOOST_AUTO_TEST_CASE(want_merge_is_separate)
{
    modelnet::SwarmNotNiche note;
    note.niche_id = "niche-1";
    note.want_merge = true;
    std::string err = "prior";
    const modelnet::SwarmNotNicheResult result = modelnet::SwarmNoteNotNiche(note, err);
    BOOST_CHECK_EQUAL(result.code, "SEPARATE");
    BOOST_CHECK_EQUAL(err, "SEPARATE");
    BOOST_CHECK(!result.merged);
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNiche note;
    note.niche_id = "niche-1";
    note.want_merge = false;
    std::string err = "prior";
    const modelnet::SwarmNotNicheResult result = modelnet::SwarmNoteNotNiche(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.merged);
}

BOOST_AUTO_TEST_SUITE_END()
