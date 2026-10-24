// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnovram0.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnovram0_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id)
{
    modelnet::SwarmNotNoVram0 note;
    note.no_device = true;
    note.want_vram = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoVram0Result result = modelnet::SwarmNoteNotNoVram0(note, err);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK(!result.granted);
    BOOST_CHECK_EQUAL(result.bytes, 0);
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(no_device)
{
    modelnet::SwarmNotNoVram0 note;
    note.node_id = "node-1";
    note.no_device = true;
    note.want_vram = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoVram0Result result = modelnet::SwarmNoteNotNoVram0(note, err);
    BOOST_CHECK_EQUAL(result.code, "ZERO");
    BOOST_CHECK(!result.granted);
    BOOST_CHECK_EQUAL(result.bytes, 0);
    BOOST_CHECK_EQUAL(err, "ZERO");
}

BOOST_AUTO_TEST_CASE(want_vram)
{
    modelnet::SwarmNotNoVram0 note;
    note.node_id = "node-1";
    note.no_device = false;
    note.want_vram = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoVram0Result result = modelnet::SwarmNoteNotNoVram0(note, err);
    BOOST_CHECK_EQUAL(result.code, "ZERO");
    BOOST_CHECK(!result.granted);
    BOOST_CHECK_EQUAL(result.bytes, 0);
    BOOST_CHECK_EQUAL(err, "ZERO");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotNoVram0 note;
    note.node_id = "node-1";
    note.no_device = false;
    note.want_vram = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoVram0Result result = modelnet::SwarmNoteNotNoVram0(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.granted);
    BOOST_CHECK_EQUAL(result.bytes, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
