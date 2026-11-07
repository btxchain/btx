// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohflineage2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnohflineage2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_model_id)
{
    modelnet::SwarmNotNoHfLineage2 note;
    note.hub_card = true;
    note.want_trust = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoHfLineage2Result result = modelnet::SwarmNoteNotNoHfLineage2(note, err);
    BOOST_CHECK_EQUAL(result.code, "MODEL");
    BOOST_CHECK(!result.trusted);
    BOOST_CHECK_EQUAL(err, "MODEL");
}

BOOST_AUTO_TEST_CASE(hub_card)
{
    modelnet::SwarmNotNoHfLineage2 note;
    note.model_id = "model-1";
    note.hub_card = true;
    note.want_trust = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoHfLineage2Result result = modelnet::SwarmNoteNotNoHfLineage2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_LINEAGE");
    BOOST_CHECK(!result.trusted);
    BOOST_CHECK_EQUAL(err, "NOT_LINEAGE");
}

BOOST_AUTO_TEST_CASE(want_trust)
{
    modelnet::SwarmNotNoHfLineage2 note;
    note.model_id = "model-1";
    note.hub_card = false;
    note.want_trust = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoHfLineage2Result result = modelnet::SwarmNoteNotNoHfLineage2(note, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.trusted);
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotNoHfLineage2 note;
    note.model_id = "model-1";
    std::string err = "prior";
    const modelnet::SwarmNotNoHfLineage2Result result = modelnet::SwarmNoteNotNoHfLineage2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.trusted);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
