// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoacctonly.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <cstdint>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoacctonly_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_mesh_id_is_mesh)
{
    modelnet::SwarmNotNoAcctOnly note;
    note.want_pay = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAcctOnlyResult result = modelnet::SwarmNoteNotNoAcctOnly(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "MESH");
    BOOST_CHECK_EQUAL(err, "MESH");
}

BOOST_AUTO_TEST_CASE(want_pay_is_accounting)
{
    modelnet::SwarmNotNoAcctOnly note;
    note.mesh_id = "mesh-1";
    note.want_pay = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAcctOnlyResult result = modelnet::SwarmNoteNotNoAcctOnly(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "ACCOUNTING");
    BOOST_CHECK_EQUAL(err, "ACCOUNTING");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoAcctOnly note;
    note.mesh_id = "mesh-1";
    note.want_pay = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAcctOnlyResult result = modelnet::SwarmNoteNotNoAcctOnly(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
