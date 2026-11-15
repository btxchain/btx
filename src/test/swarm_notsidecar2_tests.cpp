// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notsidecar2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notsidecar2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    std::string err = "prior";
    modelnet::SwarmNotSidecar2 note;
    note.want_external = true;
    const modelnet::SwarmNotSidecar2Result result = modelnet::SwarmNoteNotSidecar2(note, err);
    BOOST_CHECK(!result.external);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_external_stays_inside)
{
    std::string err = "prior";
    modelnet::SwarmNotSidecar2 note;
    note.node_id = "node-a";
    note.want_external = true;
    const modelnet::SwarmNotSidecar2Result result = modelnet::SwarmNoteNotSidecar2(note, err);
    BOOST_CHECK(!result.external);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "INSIDE");
    BOOST_CHECK_EQUAL(err, "INSIDE");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotSidecar2 note;
    note.node_id = "node-a";
    note.want_external = false;
    const modelnet::SwarmNotSidecar2Result result = modelnet::SwarmNoteNotSidecar2(note, err);
    BOOST_CHECK(!result.external);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
