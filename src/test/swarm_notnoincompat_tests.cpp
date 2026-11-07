// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoincompat.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoincompat_tests, BasicTestingSetup)

static modelnet::SwarmNotNoIncompat NotedNote()
{
    modelnet::SwarmNotNoIncompat note;
    note.tensor_id = "tensor-1";
    note.compatible = true;
    note.want_share = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_tensor_id_is_tensor)
{
    modelnet::SwarmNotNoIncompat note = NotedNote();
    note.tensor_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotNoIncompatResult result = modelnet::SwarmNoteNotNoIncompat(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "TENSOR");
    BOOST_CHECK_EQUAL(err, "TENSOR");
}

BOOST_AUTO_TEST_CASE(incompatible_without_want_share_is_not_shared)
{
    modelnet::SwarmNotNoIncompat note = NotedNote();
    note.compatible = false;
    note.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoIncompatResult result = modelnet::SwarmNoteNotNoIncompat(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_SHARED");
    BOOST_CHECK_EQUAL(err, "NOT_SHARED");
}

BOOST_AUTO_TEST_CASE(want_share_with_compatible_is_not_shared)
{
    modelnet::SwarmNotNoIncompat note = NotedNote();
    note.compatible = true;
    note.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoIncompatResult result = modelnet::SwarmNoteNotNoIncompat(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_SHARED");
    BOOST_CHECK_EQUAL(err, "NOT_SHARED");
}

BOOST_AUTO_TEST_CASE(plain_compatible_note_is_noted)
{
    modelnet::SwarmNotNoIncompat note = NotedNote();
    note.compatible = true;
    note.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoIncompatResult result = modelnet::SwarmNoteNotNoIncompat(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
