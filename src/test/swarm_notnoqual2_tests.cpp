// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoqual2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoqual2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_realm_id_is_realm)
{
    std::string err = "prior";
    modelnet::SwarmNotNoQual2 note;
    note.graduated = true;
    note.want_promote = true;
    const modelnet::SwarmNotNoQual2Result result = modelnet::SwarmNoteNotNoQual2(note, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "REALM");
    BOOST_CHECK_EQUAL(err, "REALM");
}

BOOST_AUTO_TEST_CASE(graduated_without_want_promote_is_not_promoted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoQual2 note;
    note.realm_id = "realm-a";
    note.graduated = true;
    note.want_promote = false;
    const modelnet::SwarmNotNoQual2Result result = modelnet::SwarmNoteNotNoQual2(note, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "NOT_PROMOTED");
    BOOST_CHECK_EQUAL(err, "NOT_PROMOTED");
}

BOOST_AUTO_TEST_CASE(want_promote_without_graduation_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoQual2 note;
    note.realm_id = "realm-a";
    note.graduated = false;
    note.want_promote = true;
    const modelnet::SwarmNotNoQual2Result result = modelnet::SwarmNoteNotNoQual2(note, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_without_graduation_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoQual2 note;
    note.realm_id = "realm-a";
    note.graduated = false;
    note.want_promote = false;
    const modelnet::SwarmNotNoQual2Result result = modelnet::SwarmNoteNotNoQual2(note, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
