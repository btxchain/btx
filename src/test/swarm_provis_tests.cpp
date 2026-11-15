// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_provis.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_provis_tests, BasicTestingSetup)

static modelnet::SwarmProvisionalNote NotedLineage()
{
    modelnet::SwarmProvisionalNote note;
    note.lineage_id = "lineage-a";
    note.provisional = false;
    note.want_public = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_lineage_id_is_lineage)
{
    modelnet::SwarmProvisionalNote note = NotedLineage();
    note.lineage_id.clear();
    std::string err = "prior";
    const modelnet::SwarmProvisionalResult result = modelnet::SwarmNoteProvisional(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "LINEAGE");
    BOOST_CHECK_EQUAL(err, "LINEAGE");
}

BOOST_AUTO_TEST_CASE(empty_lineage_wins_over_provisional_and_want_public)
{
    modelnet::SwarmProvisionalNote note = NotedLineage();
    note.lineage_id.clear();
    note.provisional = true;
    note.want_public = true;
    std::string err = "prior";
    const modelnet::SwarmProvisionalResult result = modelnet::SwarmNoteProvisional(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "LINEAGE");
    BOOST_CHECK_EQUAL(err, "LINEAGE");
}

BOOST_AUTO_TEST_CASE(provisional_want_public_stays_private)
{
    modelnet::SwarmProvisionalNote note = NotedLineage();
    note.provisional = true;
    note.want_public = true;
    std::string err = "prior";
    const modelnet::SwarmProvisionalResult result = modelnet::SwarmNoteProvisional(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "PRIVATE");
    BOOST_CHECK_EQUAL(err, "PRIVATE");
}

BOOST_AUTO_TEST_CASE(provisional_without_want_public_is_private)
{
    modelnet::SwarmProvisionalNote note = NotedLineage();
    note.provisional = true;
    note.want_public = false;
    std::string err = "prior";
    const modelnet::SwarmProvisionalResult result = modelnet::SwarmNoteProvisional(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "PRIVATE");
    BOOST_CHECK_EQUAL(err, "PRIVATE");
}

BOOST_AUTO_TEST_CASE(want_public_is_held)
{
    modelnet::SwarmProvisionalNote note = NotedLineage();
    note.want_public = true;
    std::string err = "prior";
    const modelnet::SwarmProvisionalResult result = modelnet::SwarmNoteProvisional(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(noted_is_not_published)
{
    modelnet::SwarmProvisionalNote note = NotedLineage();
    std::string err = "prior";
    const modelnet::SwarmProvisionalResult result = modelnet::SwarmNoteProvisional(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
