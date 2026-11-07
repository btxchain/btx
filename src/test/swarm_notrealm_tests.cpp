// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notrealm.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notrealm_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_candidate_id_is_realm)
{
    std::string err = "prior";
    modelnet::SwarmNotRealm note;
    note.quality_passed = true;
    note.want_realm_promote = true;
    const modelnet::SwarmNotRealmResult result = modelnet::SwarmNoteNotRealm(note, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK_EQUAL(result.code, "REALM");
    BOOST_CHECK_EQUAL(err, "REALM");
}

BOOST_AUTO_TEST_CASE(want_realm_promote_with_quality_passed_is_not_realm)
{
    std::string err = "prior";
    modelnet::SwarmNotRealm note;
    note.candidate_id = "cand-a";
    note.quality_passed = true;
    note.want_realm_promote = true;
    const modelnet::SwarmNotRealmResult result = modelnet::SwarmNoteNotRealm(note, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK_EQUAL(result.code, "NOT_REALM");
    BOOST_CHECK_EQUAL(err, "NOT_REALM");
}

BOOST_AUTO_TEST_CASE(quality_passed_without_realm_promote_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotRealm note;
    note.candidate_id = "cand-a";
    note.quality_passed = true;
    note.want_realm_promote = false;
    const modelnet::SwarmNotRealmResult result = modelnet::SwarmNoteNotRealm(note, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotRealm note;
    note.candidate_id = "cand-a";
    note.quality_passed = false;
    note.want_realm_promote = false;
    const modelnet::SwarmNotRealmResult result = modelnet::SwarmNoteNotRealm(note, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
