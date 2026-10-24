// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocompatfam2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocompatfam2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_family_id)
{
    std::string err = "prior";
    modelnet::SwarmNotNoCompatFam2 note;
    note.membership = true;
    note.want_share = true;
    const modelnet::SwarmNotNoCompatFam2Result result = modelnet::SwarmNoteNotNoCompatFam2(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.code, "FAMILY");
    BOOST_CHECK_EQUAL(err, "FAMILY");
}

BOOST_AUTO_TEST_CASE(membership_without_want_share)
{
    std::string err = "prior";
    modelnet::SwarmNotNoCompatFam2 note;
    note.family_id = "family-1";
    note.membership = true;
    note.want_share = false;
    const modelnet::SwarmNotNoCompatFam2Result result = modelnet::SwarmNoteNotNoCompatFam2(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.code, "NOT_COMPAT");
    BOOST_CHECK_EQUAL(err, "NOT_COMPAT");
}

BOOST_AUTO_TEST_CASE(want_share_without_membership)
{
    std::string err = "prior";
    modelnet::SwarmNotNoCompatFam2 note;
    note.family_id = "family-1";
    note.membership = false;
    note.want_share = true;
    const modelnet::SwarmNotNoCompatFam2Result result = modelnet::SwarmNoteNotNoCompatFam2(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    std::string err = "prior";
    modelnet::SwarmNotNoCompatFam2 note;
    note.family_id = "family-1";
    note.membership = false;
    note.want_share = false;
    const modelnet::SwarmNotNoCompatFam2Result result = modelnet::SwarmNoteNotNoCompatFam2(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
