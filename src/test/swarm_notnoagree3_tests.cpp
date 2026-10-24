// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoagree3.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoagree3_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty)
{
    modelnet::SwarmNotNoAgree3 note;
    note.agreement_id.clear();
    note.agreement = true;
    note.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAgree3Result result = modelnet::SwarmNoteNotNoAgree3(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "AGREEMENT");
    BOOST_CHECK_EQUAL(err, "AGREEMENT");
}

BOOST_AUTO_TEST_CASE(agreement)
{
    modelnet::SwarmNotNoAgree3 note;
    note.agreement_id = "agreement-1";
    note.agreement = true;
    note.want_settle = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAgree3Result result = modelnet::SwarmNoteNotNoAgree3(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_SETTLED");
    BOOST_CHECK_EQUAL(err, "NOT_SETTLED");
}

BOOST_AUTO_TEST_CASE(want_settle_without_agreement)
{
    modelnet::SwarmNotNoAgree3 note;
    note.agreement_id = "agreement-1";
    note.agreement = false;
    note.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAgree3Result result = modelnet::SwarmNoteNotNoAgree3(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_without_agreement)
{
    modelnet::SwarmNotNoAgree3 note;
    note.agreement_id = "agreement-1";
    note.agreement = false;
    note.want_settle = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAgree3Result result = modelnet::SwarmNoteNotNoAgree3(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
