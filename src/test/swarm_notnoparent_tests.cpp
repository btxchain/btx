// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoparent.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoparent_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_candidate_id_is_candidate)
{
    std::string err = "prior";
    modelnet::SwarmNotNoParent note;
    note.qualified = false;
    note.want_replace = true;
    const modelnet::SwarmNotNoParentResult result = modelnet::SwarmNoteNotNoParent(note, err);
    BOOST_CHECK(!result.replaced);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "CANDIDATE");
    BOOST_CHECK_EQUAL(err, "CANDIDATE");
}

BOOST_AUTO_TEST_CASE(unqualified_is_kept)
{
    std::string err = "prior";
    modelnet::SwarmNotNoParent note;
    note.candidate_id = "candidate-note";
    note.qualified = false;
    note.want_replace = false;
    const modelnet::SwarmNotNoParentResult result = modelnet::SwarmNoteNotNoParent(note, err);
    BOOST_CHECK(!result.replaced);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "KEPT");
    BOOST_CHECK_EQUAL(err, "KEPT");
}

BOOST_AUTO_TEST_CASE(want_replace_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoParent note;
    note.candidate_id = "candidate-note";
    note.qualified = true;
    note.want_replace = true;
    const modelnet::SwarmNotNoParentResult result = modelnet::SwarmNoteNotNoParent(note, err);
    BOOST_CHECK(!result.replaced);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_qualified_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoParent note;
    note.candidate_id = "candidate-note";
    note.qualified = true;
    note.want_replace = false;
    const modelnet::SwarmNotNoParentResult result = modelnet::SwarmNoteNotNoParent(note, err);
    BOOST_CHECK(!result.replaced);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
