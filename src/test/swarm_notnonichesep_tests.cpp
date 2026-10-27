// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnonichesep.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnonichesep_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_niche_id_is_niche)
{
    modelnet::SwarmNotNoNicheSep note;
    note.niche_id.clear();
    note.same_niche = false;
    note.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoNicheSepResult result = modelnet::SwarmNoteNotNoNicheSep(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NICHE");
    BOOST_CHECK_EQUAL(err, "NICHE");
}

BOOST_AUTO_TEST_CASE(different_niche_is_separate)
{
    modelnet::SwarmNotNoNicheSep note;
    note.niche_id = "niche-1";
    note.same_niche = false;
    note.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoNicheSepResult result = modelnet::SwarmNoteNotNoNicheSep(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "SEPARATE");
    BOOST_CHECK_EQUAL(err, "SEPARATE");
}

BOOST_AUTO_TEST_CASE(want_share_is_not_shared)
{
    modelnet::SwarmNotNoNicheSep note;
    note.niche_id = "niche-1";
    note.same_niche = true;
    note.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoNicheSepResult result = modelnet::SwarmNoteNotNoNicheSep(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_SHARED");
    BOOST_CHECK_EQUAL(err, "NOT_SHARED");
}

BOOST_AUTO_TEST_CASE(same_niche_without_share_is_noted)
{
    modelnet::SwarmNotNoNicheSep note;
    note.niche_id = "niche-1";
    note.same_niche = true;
    note.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoNicheSepResult result = modelnet::SwarmNoteNotNoNicheSep(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
