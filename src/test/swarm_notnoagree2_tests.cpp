// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoagree2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoagree2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty)
{
    modelnet::SwarmNotNoAgree2 note;
    note.quorum_id.clear();
    note.agreed = true;
    note.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAgree2Result result = modelnet::SwarmNoteNotNoAgree2(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "QUORUM");
    BOOST_CHECK_EQUAL(err, "QUORUM");
}

BOOST_AUTO_TEST_CASE(agreed)
{
    modelnet::SwarmNotNoAgree2 note;
    note.quorum_id = "quorum-1";
    note.agreed = true;
    note.want_settle = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAgree2Result result = modelnet::SwarmNoteNotNoAgree2(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_SETTLED");
    BOOST_CHECK_EQUAL(err, "NOT_SETTLED");
}

BOOST_AUTO_TEST_CASE(want_settle_without_agreement)
{
    modelnet::SwarmNotNoAgree2 note;
    note.quorum_id = "quorum-1";
    note.agreed = false;
    note.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAgree2Result result = modelnet::SwarmNoteNotNoAgree2(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_without_agreement)
{
    modelnet::SwarmNotNoAgree2 note;
    note.quorum_id = "quorum-1";
    note.agreed = false;
    note.want_settle = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAgree2Result result = modelnet::SwarmNoteNotNoAgree2(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
