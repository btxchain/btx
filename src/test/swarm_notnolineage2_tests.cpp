// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnolineage2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnolineage2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_model_id)
{
    modelnet::SwarmNotNoLineage2 note;
    note.hub_listing = true;
    note.want_authority = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoLineage2Result result = modelnet::SwarmNoteNotNoLineage2(note, err);
    BOOST_CHECK_EQUAL(result.code, "MODEL");
    BOOST_CHECK(!result.authority);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(err, "MODEL");
}

BOOST_AUTO_TEST_CASE(hub_listing)
{
    modelnet::SwarmNotNoLineage2 note;
    note.model_id = "model-1";
    note.hub_listing = true;
    note.want_authority = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoLineage2Result result = modelnet::SwarmNoteNotNoLineage2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_AUTHORITY");
    BOOST_CHECK(!result.authority);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(err, "NOT_AUTHORITY");
}

BOOST_AUTO_TEST_CASE(want_authority)
{
    modelnet::SwarmNotNoLineage2 note;
    note.model_id = "model-1";
    note.hub_listing = false;
    note.want_authority = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoLineage2Result result = modelnet::SwarmNoteNotNoLineage2(note, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.authority);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotNoLineage2 note;
    note.model_id = "model-1";
    std::string err = "prior";
    const modelnet::SwarmNotNoLineage2Result result = modelnet::SwarmNoteNotNoLineage2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.authority);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
