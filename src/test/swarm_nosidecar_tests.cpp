// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nosidecar.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_nosidecar_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_is_sidecar)
{
    std::string err = "prior";
    modelnet::SwarmNoSidecar note;
    note.want_exec = true;
    const modelnet::SwarmNoSidecarResult result = modelnet::SwarmNoteNoSidecar(note, err);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "SIDECAR");
    BOOST_CHECK_EQUAL(err, "SIDECAR");
}

BOOST_AUTO_TEST_CASE(want_exec_is_not_launched)
{
    std::string err = "prior";
    modelnet::SwarmNoSidecar note;
    note.node_id = "node-a";
    note.want_exec = true;
    const modelnet::SwarmNoSidecarResult result = modelnet::SwarmNoteNoSidecar(note, err);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "NOT_LAUNCHED");
    BOOST_CHECK_EQUAL(err, "NOT_LAUNCHED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNoSidecar note;
    note.node_id = "node-a";
    note.want_exec = false;
    const modelnet::SwarmNoSidecarResult result = modelnet::SwarmNoteNoSidecar(note, err);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
