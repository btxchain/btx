// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoassurance.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoassurance_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_route_id_is_route)
{
    std::string err = "prior";
    modelnet::SwarmNotNoAssurance note;
    note.want_proof = true;
    const modelnet::SwarmNotNoAssuranceResult result = modelnet::SwarmNoteNotNoAssurance(note, err);
    BOOST_CHECK(!result.proved);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "ROUTE");
    BOOST_CHECK_EQUAL(err, "ROUTE");
}

BOOST_AUTO_TEST_CASE(want_proof_is_not_work_proof)
{
    std::string err = "prior";
    modelnet::SwarmNotNoAssurance note;
    note.route_id = "route-1";
    note.want_proof = true;
    const modelnet::SwarmNotNoAssuranceResult result = modelnet::SwarmNoteNotNoAssurance(note, err);
    BOOST_CHECK(!result.proved);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "NOT_WORK_PROOF");
    BOOST_CHECK_EQUAL(err, "NOT_WORK_PROOF");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoAssurance note;
    note.route_id = "route-1";
    note.want_proof = false;
    const modelnet::SwarmNotNoAssuranceResult result = modelnet::SwarmNoteNotNoAssurance(note, err);
    BOOST_CHECK(!result.proved);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
