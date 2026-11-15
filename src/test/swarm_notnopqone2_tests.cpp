// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopqone2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnopqone2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_mesh_id_is_mesh)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPqOne2 note;
    note.want_add = true;
    const modelnet::SwarmNotNoPqOne2Result result = modelnet::SwarmNoteNotNoPqOne2(note, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.code, "MESH");
    BOOST_CHECK_EQUAL(err, "MESH");
}

BOOST_AUTO_TEST_CASE(want_add_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPqOne2 note;
    note.mesh_id = "pq-mesh";
    note.want_add = true;
    const modelnet::SwarmNotNoPqOne2Result result = modelnet::SwarmNoteNotNoPqOne2(note, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(one_mesh_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPqOne2 note;
    note.mesh_id = "pq-mesh";
    note.want_add = false;
    const modelnet::SwarmNotNoPqOne2Result result = modelnet::SwarmNoteNotNoPqOne2(note, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
