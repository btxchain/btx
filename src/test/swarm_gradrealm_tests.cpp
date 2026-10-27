// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_gradrealm.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_gradrealm_tests, BasicTestingSetup)

static modelnet::SwarmGradRealm NotedRealm()
{
    modelnet::SwarmGradRealm note;
    note.candidate_id = "cand-1";
    note.quality_passed = false;
    note.want_realm_promotion = false;
    note.want_exact_replay = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_candidate_id_is_graduate)
{
    modelnet::SwarmGradRealm note = NotedRealm();
    note.candidate_id.clear();
    std::string err = "prior";
    const modelnet::SwarmGradRealmResult result = modelnet::SwarmNoteGraduationRealm(note, err);
    BOOST_CHECK(!result.realm_promoted);
    BOOST_CHECK(!result.exact_replay_admitted);
    BOOST_CHECK_EQUAL(result.code, "GRADUATE");
    BOOST_CHECK_EQUAL(err, "GRADUATE");
}

BOOST_AUTO_TEST_CASE(empty_candidate_id_wins_over_quality_realm_and_replay)
{
    modelnet::SwarmGradRealm note = NotedRealm();
    note.candidate_id.clear();
    note.quality_passed = true;
    note.want_realm_promotion = true;
    note.want_exact_replay = true;
    std::string err = "prior";
    const modelnet::SwarmGradRealmResult result = modelnet::SwarmNoteGraduationRealm(note, err);
    BOOST_CHECK(!result.realm_promoted);
    BOOST_CHECK(!result.exact_replay_admitted);
    BOOST_CHECK_EQUAL(result.code, "GRADUATE");
    BOOST_CHECK_EQUAL(err, "GRADUATE");
}

BOOST_AUTO_TEST_CASE(want_realm_promotion_is_realm_refused)
{
    modelnet::SwarmGradRealm note = NotedRealm();
    note.want_realm_promotion = true;
    std::string err = "prior";
    const modelnet::SwarmGradRealmResult result = modelnet::SwarmNoteGraduationRealm(note, err);
    BOOST_CHECK(!result.realm_promoted);
    BOOST_CHECK(!result.exact_replay_admitted);
    BOOST_CHECK_EQUAL(result.code, "REALM_REFUSED");
    BOOST_CHECK_EQUAL(err, "REALM_REFUSED");
}

BOOST_AUTO_TEST_CASE(want_realm_promotion_wins_when_quality_passed_and_exact_replay)
{
    modelnet::SwarmGradRealm note = NotedRealm();
    note.quality_passed = true;
    note.want_realm_promotion = true;
    note.want_exact_replay = true;
    std::string err = "prior";
    const modelnet::SwarmGradRealmResult result = modelnet::SwarmNoteGraduationRealm(note, err);
    BOOST_CHECK(!result.realm_promoted);
    BOOST_CHECK(!result.exact_replay_admitted);
    BOOST_CHECK_EQUAL(result.code, "REALM_REFUSED");
    BOOST_CHECK_EQUAL(err, "REALM_REFUSED");
}

BOOST_AUTO_TEST_CASE(want_exact_replay_is_replay_refused)
{
    modelnet::SwarmGradRealm note = NotedRealm();
    note.want_exact_replay = true;
    std::string err = "prior";
    const modelnet::SwarmGradRealmResult result = modelnet::SwarmNoteGraduationRealm(note, err);
    BOOST_CHECK(!result.realm_promoted);
    BOOST_CHECK(!result.exact_replay_admitted);
    BOOST_CHECK_EQUAL(result.code, "REPLAY_REFUSED");
    BOOST_CHECK_EQUAL(err, "REPLAY_REFUSED");
}

BOOST_AUTO_TEST_CASE(want_exact_replay_wins_when_quality_passed)
{
    modelnet::SwarmGradRealm note = NotedRealm();
    note.quality_passed = true;
    note.want_exact_replay = true;
    std::string err = "prior";
    const modelnet::SwarmGradRealmResult result = modelnet::SwarmNoteGraduationRealm(note, err);
    BOOST_CHECK(!result.realm_promoted);
    BOOST_CHECK(!result.exact_replay_admitted);
    BOOST_CHECK_EQUAL(result.code, "REPLAY_REFUSED");
    BOOST_CHECK_EQUAL(err, "REPLAY_REFUSED");
}

BOOST_AUTO_TEST_CASE(quality_passed_is_held_and_does_not_promote_or_admit)
{
    modelnet::SwarmGradRealm note = NotedRealm();
    note.quality_passed = true;
    std::string err = "prior";
    const modelnet::SwarmGradRealmResult result = modelnet::SwarmNoteGraduationRealm(note, err);
    BOOST_CHECK(!result.realm_promoted);
    BOOST_CHECK(!result.exact_replay_admitted);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(otherwise_noted_and_flags_stay_false)
{
    modelnet::SwarmGradRealm note = NotedRealm();
    std::string err = "prior";
    const modelnet::SwarmGradRealmResult result = modelnet::SwarmNoteGraduationRealm(note, err);
    BOOST_CHECK(!result.realm_promoted);
    BOOST_CHECK(!result.exact_replay_admitted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
