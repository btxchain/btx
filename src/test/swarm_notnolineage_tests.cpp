// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnolineage.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnolineage_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_model_id)
{
    modelnet::SwarmNotNoLineage note;
    note.want_authority = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoLineageResult result = modelnet::SwarmNoteNotNoLineage(note, err);
    BOOST_CHECK_EQUAL(result.code, "MODEL");
    BOOST_CHECK(!result.authority);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(err, "MODEL");
}

BOOST_AUTO_TEST_CASE(want_authority)
{
    modelnet::SwarmNotNoLineage note;
    note.model_id = "model-1";
    note.want_authority = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoLineageResult result = modelnet::SwarmNoteNotNoLineage(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_AUTHORITY");
    BOOST_CHECK(!result.authority);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(err, "NOT_AUTHORITY");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotNoLineage note;
    note.model_id = "model-1";
    std::string err = "prior";
    const modelnet::SwarmNotNoLineageResult result = modelnet::SwarmNoteNotNoLineage(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.authority);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
